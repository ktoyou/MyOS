"""Проверка профиля официального Chrome на MyFS после двух загрузок QEMU."""

import argparse
import hashlib
import http.server
import pathlib
import re
import secrets
import sys
import tempfile
import threading
import time

import disk_install_smoke
from kernel_x64_chrome_smoke import firmware_args
from kernel_x64_wayland_smoke import read_frame
from uefi_x64_smoke import VM, clean

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'tools'))
import make_uefi
from chrome_x64_live import PROFILE_TOKEN_GUEST, URL_GUEST, chrome_files, make_image, prepare_profile, profile_drive_args, qemu_path


ORIGIN = '10.44.0.81:18080'
LOCAL_LEASE = 'DHCP address=10.44.0.20 mask=255.255.255.0'
TARGET = '/myos-chrome/persistent-profile'
STORED = 'MyOS Chrome profile stored'
RESTORED = 'MyOS Chrome profile restored'
STORE_COLOR = bytes.fromhex('341d71')
RESTORE_COLOR = bytes.fromhex('146544')
EXIT = 'Linux x86-64 exit status=0x00'
PROFILE_TEST_BYTES = 128 * 1024 * 1024


def page(nonce):
    return f'''<!doctype html><meta charset="utf-8"><title>MyOS Chrome profile</title>
<style>body{{margin:0;padding:30px;color:white;font:32px sans-serif}}</style><h1></h1>
<script>
const key = 'myos-profile-smoke';
let result;
try {{
  const value = localStorage.getItem(key);
  if (value === null) {{
    localStorage.setItem(key, '{nonce}');
    if (localStorage.getItem(key) !== '{nonce}') throw new Error('read after write');
    result = '{STORED}';
    document.body.style.background = '#{STORE_COLOR.hex()}';
  }} else if (value === '{nonce}') {{
    result = '{RESTORED}';
    document.body.style.background = '#{RESTORE_COLOR.hex()}';
  }} else {{
    result = 'MyOS Chrome profile mismatch';
  }}
}} catch (error) {{ result = 'MyOS Chrome profile storage error: ' + error.name; }}
document.querySelector('h1').textContent = document.title = result;
</script>'''.encode()


class ProfileHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        host, agent = self.headers.get('Host'), self.headers.get('User-Agent', '')
        if self.path != TARGET or host != ORIGIN or 'Chrome/' not in agent:
            self.send_error(404)
            return
        self.server.requests.append((self.path, host, agent))
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(self.server.page)))
        self.end_headers()
        self.wfile.write(self.server.page)

    def log_message(self, *_args):
        pass


def sha256(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.digest()


def has_background(shot, color):
    width, height, pixels = read_frame(shot)
    for y in (height // 2, 3 * height // 4):
        for x in (width // 4, 3 * width // 4):
            offset = (width * y + x) * 3
            if pixels[offset:offset + 3] != color:
                return False
    return True


def wait_for_page(vm, server, requests_before, expected, color, shot, timeout):
    deadline = time.monotonic() + timeout
    saw_page = False
    keyboard = re.compile(r'wl_keyboard#\d+\.enter\(')
    while time.monotonic() < deadline:
        serial = clean(vm.log)
        if vm.p.poll() is not None or 'exception halted' in serial or 'Linux x86-64 exit status=' in serial:
            break
        if (LOCAL_LEASE in serial and len(server.requests) > requests_before and
                f'{expected} - Google Chrome' in serial):
            if not saw_page:
                vm.qmp('screendump', {'filename': str(shot)})
                saw_page = has_background(shot, color)
            if saw_page and keyboard.search(serial):
                return
        time.sleep(.2)
    if vm.p.poll() is None:
        vm.qmp('screendump', {'filename': str(shot.with_stem(shot.stem + '-failure'))})
    raise AssertionError(f'Chrome не показал страницу «{expected}» или не получил фокус:\n' +
                         '\n'.join(clean(vm.log).splitlines()[-50:]))


def browser_vm(directory, name, disk, server, volume=None):
    directory.mkdir()
    relay = f'python3 tests/kernel_x64_tcp_smoke.py --relay {server.server_port}'
    network = ('user,id=wire,restrict=on,ipv6=off,net=10.44.0.0/24,host=10.44.0.5,'
               f'dhcpstart=10.44.0.20,dns=10.44.0.53,guestfwd=tcp:{ORIGIN}-cmd:{relay}')
    profile = profile_drive_args(volume) if volume is not None else ()
    return VM(name, firmware_args(directory) + [
        '-drive', f'if=none,id=root,format=raw,snapshot=on,file={qemu_path(disk)}',
        '-device', 'nvme,drive=root,serial=MYOSCHROME,bootindex=1',
        *profile, '-netdev', network, '-device', 'e1000,netdev=wire',
    ], memory='1024M', binary='qemu-system-x86_64', cpu='max')


def run_browser(directory, artifacts, disk, volume, server, phase, title, color, timeout):
    name = f'x64-chrome-profile-{phase}'
    requests_before = len(server.requests)
    vm = browser_vm(directory, name, disk, server, volume)
    try:
        vm.wait('UEFI video: V=mode menu', timeout=20)
        vm.key('s')
        wait_for_page(vm, server, requests_before, title, color, artifacts / f'{name}.ppm', timeout)
        if phase == 1:
            # Blink возвращает результат setItem раньше отложенной записи в LevelDB.
            time.sleep(7)
        offset = len(clean(vm.log))
        keys = [{'type': 'qcode', 'data': key} for key in ('ctrl', 'shift', 'w')]
        vm.qmp('send-key', {'keys': keys, 'hold-time': 75})
        vm.wait(EXIT, offset, timeout=25)
        assert 'x86-64 exception' not in clean(vm.log)
    finally:
        vm.stop()


def check_missing_profile(directory, disk, server):
    requests_before = len(server.requests)
    vm = browser_vm(directory, 'x64-chrome-profile-missing', disk, server)
    try:
        vm.wait('UEFI video: V=mode menu', timeout=20)
        vm.key('s')
        vm.wait('Chrome profile:', timeout=30)
        vm.wait('Linux x86-64 exit status=0x01', timeout=5)
        assert 'xdg_toplevel' not in clean(vm.log), 'Chrome открыл окно без запрошенного тома'
        assert len(server.requests) == requests_before, 'Chrome загрузил страницу без запрошенного тома'
    finally:
        vm.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('chrome', 'compositor', 'kernel', 'launcher', 'myfs'):
        parser.add_argument(f'--{name}', type=pathlib.Path, required=True)
    parser.add_argument('--artifacts', type=pathlib.Path, default=pathlib.Path('build/x86_64/chrome-profile-smoke'))
    parser.add_argument('--timeout', type=int, default=120)
    args = parser.parse_args()
    args.artifacts = args.artifacts.resolve()
    args.artifacts.mkdir(parents=True, exist_ok=True)
    disk_install_smoke.B = args.artifacts

    with tempfile.TemporaryDirectory(prefix='myos-chrome-profile-') as temp, \
         http.server.ThreadingHTTPServer(('127.0.0.1', 0), ProfileHandler) as server:
        directory = pathlib.Path(temp)
        disk, volume = directory / 'chrome.img', directory / 'profile.img'
        token = prepare_profile(volume, args.myfs.resolve(), size=PROFILE_TEST_BYTES)
        virgin_profile = sha256(volume)
        files = chrome_files(args.chrome.resolve(), args.compositor.resolve(), args.launcher.resolve())
        files.update({PROFILE_TOKEN_GUEST: token, URL_GUEST: f'http://{ORIGIN}{TARGET}\n'.encode(),
                      '/myos/chrome-debug': b''})
        make_uefi.DIRECTORY = directory / 'firmware'
        make_image(disk, args.kernel, args.launcher, files)
        del files
        boot_digest = sha256(disk)
        server.page, server.requests = page(secrets.token_hex(16)), []
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            run_browser(directory / 'first', args.artifacts, disk, volume, server, 1, STORED, STORE_COLOR, args.timeout)
            assert sha256(disk) == boot_digest, 'Chrome изменил загрузочный образ'
            written_profile = sha256(volume)
            assert written_profile != virgin_profile, 'Chrome не записал профиль MyFS'
            assert prepare_profile(volume, args.myfs.resolve()) == token, 'Токен профиля изменился'
            assert sha256(volume) == written_profile, 'Подготовка заменила или изменила существующий профиль'

            run_browser(directory / 'second', args.artifacts, disk, volume, server, 2, RESTORED, RESTORE_COLOR, args.timeout)
            assert sha256(disk) == boot_digest, 'Chrome изменил загрузочный образ'
            assert prepare_profile(volume, args.myfs.resolve()) == token, 'Токен профиля изменился после второй загрузки'

            check_missing_profile(directory / 'missing', disk, server)
            assert sha256(disk) == boot_digest, 'Chrome изменил загрузочный образ'
        finally:
            server.shutdown()
            worker.join()
            (args.artifacts / 'x64-chrome-profile-http.log').write_text(
                '\n'.join(map(repr, server.requests)) + '\n', encoding='utf-8')
    print('OVMF Linux x86-64: Chrome сохранил localStorage после перезагрузки и потребовал том профиля: PASS', flush=True)


if __name__ == '__main__':
    main()
