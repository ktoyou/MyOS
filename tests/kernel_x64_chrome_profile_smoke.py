"""Проверка профиля официального Chrome на MyFS после двух загрузок QEMU."""

import argparse
import hashlib
import http.server
import json
import pathlib
import re
import secrets
import shutil
import subprocess
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
TARGET_URL = f'http://{ORIGIN}{TARGET}'
BOOKMARK_FILE = '/chrome/Default/Bookmarks'
LANDING = '/myos-chrome/profile-home'
LANDING_TITLE = 'MyOS Chrome profile start'
LANDING_COLOR = bytes.fromhex('174780')
RENAMED_BOOKMARK = 'myos saved bookmark'
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
        self.server.requests.append((self.path, host, agent))
        if self.path not in (TARGET, LANDING) or host != ORIGIN or 'Chrome/' not in agent:
            self.send_error(404)
            return
        if self.path == TARGET and self.server.redirect_to_landing:
            self.send_response(302)
            self.send_header('Location', LANDING)
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            return
        page = self.server.page if self.path == TARGET else self.server.landing
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def log_message(self, *_args):
        pass


def sha256(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.digest()


def bookmark_entries(folder):
    for item in folder.get('children', ()):
        if item['type'] == 'url':
            yield item
        elif item['type'] == 'folder':
            yield from bookmark_entries(item)


def read_bookmark(directory, volume, myfs):
    # Чтение через myfs открывает журнал, поэтому исходный том не используем.
    with tempfile.TemporaryDirectory(prefix='bookmark-', dir=directory) as temp:
        copy = pathlib.Path(temp) / 'profile-copy.img'
        exported = pathlib.Path(temp) / 'Bookmarks'
        shutil.copyfile(volume, copy)
        subprocess.run([myfs, copy, 'get', BOOKMARK_FILE, exported], check=True)
        roots = json.loads(exported.read_text(encoding='utf-8'))['roots']
    matches = [(folder, item) for folder, root in roots.items()
               for item in bookmark_entries(root) if item['url'] == TARGET_URL]
    assert len(matches) == 1 and matches[0][1]['guid'], matches
    return matches[0]


def key_chord(vm, *keys):
    vm.qmp('send-key', {'keys': [{'type': 'qcode', 'data': key} for key in keys], 'hold-time': 75})
    time.sleep(.1)


def pixel(vm, shot, x, y):
    vm.qmp('screendump', {'filename': str(shot)})
    width, height, pixels = read_frame(shot)
    assert (width, height) == (1024, 768), (width, height)
    offset = (y * width + x) * 3
    return pixels[offset:offset + 3]


def wait_pixel(vm, shot, point, background, visible, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and vm.p.poll() is None:
        if (pixel(vm, shot, *point) != background) == visible:
            return
        time.sleep(.2)
    raise AssertionError(f'Chrome не показал ожидаемое состояние интерфейса: {shot}')


def click(vm, start, end):
    x, y = start
    while (x, y) != end:
        dx = max(-100, min(100, end[0] - x))
        dy = max(-100, min(100, end[1] - y))
        vm.qmp('input-send-event', {'events': [
            {'type': 'rel', 'data': {'axis': 'x', 'value': dx}},
            {'type': 'rel', 'data': {'axis': 'y', 'value': dy}},
        ]})
        x, y = x + dx, y + dy
        time.sleep(.1)
    for down in (True, False):
        vm.qmp('input-send-event', {'events': [{'type': 'btn', 'data': {'button': 'left', 'down': down}}]})


def edit_bookmark(vm, shot, background, timeout, name=None):
    # Диалог Chrome перекрывает содержимое страницы в этой точке при обоих положениях звезды.
    anchor = (650, 242)
    key_chord(vm, 'ctrl', 'd')
    wait_pixel(vm, shot, anchor, background, True, timeout)
    if name is not None:
        key_chord(vm, 'ctrl', 'a')
        for char in name:
            key_chord(vm, 'spc' if char == ' ' else char)
    key_chord(vm, 'ret')
    wait_pixel(vm, shot, anchor, background, False, timeout)


def open_bookmark(vm, server, folder, artifacts, timeout):
    # В тестовом разрешении 1024x768 панель занимает место ниже адресной строки.
    shot = artifacts / 'x64-chrome-profile-bookmark-menu.ppm'
    bar = (500, 110)
    if pixel(vm, shot, *bar) == LANDING_COLOR:
        key_chord(vm, 'ctrl', 'shift', 'b')
        wait_pixel(vm, shot, bar, LANDING_COLOR, True, timeout)

    assert folder in ('bookmark_bar', 'other'), folder
    cursor = (512, 384)
    bookmark = (125, 109)
    if folder == 'other':
        cursor = (960, 109)
        click(vm, (512, 384), cursor)
        wait_pixel(vm, shot, (900, 190), LANDING_COLOR, True, timeout)
        bookmark = (825, 195)

    before = len(server.requests)
    server.redirect_to_landing = False
    click(vm, cursor, bookmark)
    restored = artifacts / 'x64-chrome-profile-bookmark-opened.ppm'
    wait_for_page(vm, server, before, RESTORED, RESTORE_COLOR, restored, timeout)
    assert any(path == TARGET and host == ORIGIN and 'Chrome/' in agent
               for path, host, agent in server.requests[before:]), server.requests[before:]


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


def run_browser(directory, artifacts, disk, volume, server, phase, title, color, timeout, bookmark_folder=None):
    name = f'x64-chrome-profile-{phase}'
    requests_before = len(server.requests)
    vm = browser_vm(directory, name, disk, server, volume)
    try:
        vm.wait('UEFI video: V=mode menu', timeout=20)
        vm.key('s')
        wait_for_page(vm, server, requests_before, title, color, artifacts / f'{name}.ppm', timeout)
        bookmark_shot = artifacts / f'{name}-bookmark.ppm'
        if bookmark_folder is None:
            edit_bookmark(vm, bookmark_shot, STORE_COLOR, timeout)
            # Blink возвращает результат setItem раньше отложенной записи в LevelDB.
            time.sleep(7)
        else:
            open_bookmark(vm, server, bookmark_folder, artifacts, timeout)
            edit_bookmark(vm, bookmark_shot, RESTORE_COLOR, timeout, RENAMED_BOOKMARK)
        offset = len(clean(vm.log))
        key_chord(vm, 'ctrl', 'shift', 'w')
        vm.wait(EXIT, offset, timeout=25)
        assert 'x86-64 exception' not in clean(vm.log)
    finally:
        vm.stop()


def check_missing_profile(directory, disk, server, volume=None):
    requests_before = len(server.requests)
    vm = browser_vm(directory, f'x64-chrome-profile-{directory.name}', disk, server, volume)
    try:
        vm.wait('UEFI video: V=mode menu', timeout=20)
        vm.key('s')
        vm.wait('Chrome profile:', timeout=30)
        vm.wait('Linux x86-64 exit status=0x01', timeout=5)
        serial = clean(vm.log)
        assert not re.search(r'\b(?:wl_surface|xdg_surface|xdg_toplevel)\b', serial), (
            'Chrome открыл окно без запрошенного тома')
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
        files.update({PROFILE_TOKEN_GUEST: token, URL_GUEST: (TARGET_URL + '\n').encode(),
                      '/myos/chrome-debug': b''})
        make_uefi.DIRECTORY = directory / 'firmware'
        make_image(disk, args.kernel, args.launcher, files)
        del files
        boot_digest = sha256(disk)
        server.page, server.requests = page(secrets.token_hex(16)), []
        server.redirect_to_landing = False
        server.landing = (f'<!doctype html><title>{LANDING_TITLE}</title>'
                          f'<style>body{{background:#{LANDING_COLOR.hex()}}}</style>').encode()
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            run_browser(directory / 'first', args.artifacts, disk, volume, server, 1, STORED, STORE_COLOR, args.timeout)
            assert sha256(disk) == boot_digest, 'Chrome изменил загрузочный образ'
            written_profile = sha256(volume)
            assert written_profile != virgin_profile, 'Chrome не записал профиль MyFS'
            assert prepare_profile(volume, args.myfs.resolve()) == token, 'Токен профиля изменился'
            assert sha256(volume) == written_profile, 'Подготовка заменила или изменила существующий профиль'

            folder, bookmark = read_bookmark(directory, volume, args.myfs.resolve())
            assert bookmark['name'] == STORED, bookmark
            server.redirect_to_landing = True
            run_browser(directory / 'second', args.artifacts, disk, volume, server, 2,
                        LANDING_TITLE, LANDING_COLOR, args.timeout, bookmark_folder=folder)
            assert sha256(disk) == boot_digest, 'Chrome изменил загрузочный образ'
            assert prepare_profile(volume, args.myfs.resolve()) == token, 'Токен профиля изменился после второй загрузки'
            updated_folder, updated = read_bookmark(directory, volume, args.myfs.resolve())
            assert updated_folder == folder and updated['guid'] == bookmark['guid'], updated
            assert updated['name'] == RENAMED_BOOKMARK, updated

            check_missing_profile(directory / 'missing', disk, server)
            assert sha256(disk) == boot_digest, 'Chrome изменил загрузочный образ'

            wrong_volume = directory / 'wrong-profile.img'
            wrong_token = prepare_profile(wrong_volume, args.myfs.resolve(), size=PROFILE_TEST_BYTES)
            assert wrong_token != token, 'Тестовые тома профиля получили одинаковый токен'
            wrong_digest = sha256(wrong_volume)
            check_missing_profile(directory / 'wrong-token', disk, server, volume=wrong_volume)
            assert sha256(wrong_volume) == wrong_digest, 'Лаунчер изменил том с чужим токеном'
            assert sha256(disk) == boot_digest, 'Лаунчер изменил загрузочный образ'
        finally:
            server.shutdown()
            worker.join()
            (args.artifacts / 'x64-chrome-profile-http.log').write_text(
                '\n'.join(map(repr, server.requests)) + '\n', encoding='utf-8')
    print('OVMF Linux x86-64: Chrome восстановил localStorage и закладку, сохранил новое имя '
          'и потребовал правильный том профиля: PASS', flush=True)


if __name__ == '__main__':
    main()
