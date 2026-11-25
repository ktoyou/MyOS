"""Проверка HTTPS в официальном Chrome для Linux x86-64 под MyOS и QEMU."""
import argparse
import http.server
import os
import pathlib
import queue
import shlex
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import ExitStack

import disk_install_smoke
from kernel_x64_dhcp_smoke import LEASE
from kernel_x64_dns_smoke import connect, dns_name, dns_query, dns_question, dns_reply, network_args, receive_frame
from kernel_x64_ethernet_smoke import pcap_frames
from kernel_x64_udp_smoke import send_frames
from kernel_x64_wayland_smoke import read_frame
from uefi_x64_smoke import VM, clean

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'tools'))
import make_uefi
from chrome_x64_live import CHROME_ML_LIBRARY, CHROME_VM_MEMORY, chrome_files, firmware, make_image, qemu_path


HOST = 'chrome-https.test'
PORT = 18080
SERVER = bytes((10, 44, 0, 81))
ORIGIN = f'{HOST}:{PORT}'
TARGET = '/myos-chrome/verified-https'
TITLE = 'MyOS Chrome verified HTTPS'
COLOR = bytes.fromhex('168052')
NSS_PATH = '/tmp/.local/share/pki/nssdb'
DB_FILES = ('cert9.db', 'key4.db', 'pkcs11.txt')
CA_LABEL = 'MyOS Chrome HTTPS test CA'
PAGE = f'''<!doctype html><html><meta charset="utf-8"><title>{TITLE}</title>
<style>body{{margin:0;background:#168052;color:white;font:32px sans-serif}}main{{padding:48px}}</style>
<main><h1>Chrome on MyOS</h1><p>HTTPS with a locally trusted certificate.</p></main></html>'''.encode()


def generate_certificates(directory):
    ca, ca_key = directory / 'ca.pem', directory / 'ca.key'
    leaf, key, request = (directory / name for name in ('leaf.pem', 'leaf.key', 'leaf.csr'))
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-sha256',
                    '-subj', f'/CN={CA_LABEL}', '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
                    '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', ca_key, '-out', ca],
                   check=True, capture_output=True)
    subprocess.run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', f'/CN={HOST}',
                    '-keyout', key, '-out', request], check=True, capture_output=True)
    extensions = directory / 'leaf.ext'
    extensions.write_text(f'basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:{HOST}\n'
                          'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
    subprocess.run(['openssl', 'x509', '-req', '-in', request, '-CA', ca, '-CAkey', ca_key, '-CAcreateserial',
                    '-days', '2', '-sha256', '-extfile', extensions, '-out', leaf], check=True, capture_output=True)
    subprocess.run(['openssl', 'verify', '-CAfile', ca, '-purpose', 'sslserver', '-verify_hostname', HOST, leaf],
                   check=True, capture_output=True)
    return leaf, key, ca


def nss_files(directory, ca, certutil, trusted):
    db = directory / 'nssdb'
    db.mkdir()
    database = f'sql:{db}'
    subprocess.run([certutil, '-N', '-d', database, '--empty-password'], check=True)
    if trusted:
        subprocess.run([certutil, '-A', '-d', database, '-t', 'C,,', '-n', CA_LABEL, '-i', ca], check=True)
    modules = db / 'pkcs11.txt'
    modules.write_text(modules.read_text().replace(str(db), NSS_PATH))
    return {f'/myos/chrome-test-nss/{name}': (db / name).read_bytes() for name in DB_FILES}


class TlsServer(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        error = sys.exc_info()[1]
        if isinstance(error, ssl.SSLError):
            self.alerts.append(str(error))
        else:
            super().handle_error(request, client_address)


class PageHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        host = self.headers.get('Host')
        agent = self.headers.get('User-Agent', '')
        self.server.requests.append((self.path, host, agent, self.connection.version()))
        if self.path == TARGET and host == ORIGIN and 'Chrome/' in agent:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(PAGE)))
            self.end_headers()
            self.wfile.write(PAGE)
            self.server.loaded.set()
        else:
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.end_headers()

    def log_message(self, fmt, *args):
        pass


def forwards(frame):
    ethertype = frame[12:14]
    if ethertype == b'\x08\x06':
        return True
    if ethertype != b'\x08\x00' or len(frame) < 42:
        return False
    ports = 14 + (frame[14] & 15) * 4
    if ports + 4 > len(frame):
        return False
    source, destination = struct.unpack_from('!HH', frame, ports)
    return ((frame[23] == 17 and (source, destination) == (68, 67)) or
            (frame[23] == 6 and frame[30:34] == SERVER and destination == PORT))


def serve_wire(egress, forward, injector, replies, errors, deadline):
    # slirp обслуживает DHCP, ARP и тестовый TCP. Остальной трафик не передаётся хосту.
    try:
        while True:
            frame = receive_frame(egress, deadline)
            if forwards(frame):
                send_frames(forward, frame)
            elif query := dns_query(frame):
                name, kind, _ = dns_question(query[2])
                if name.lower() == dns_name(HOST):
                    reply = dns_reply(query, SERVER)
                    send_frames(injector, reply)
                    if kind == 1:
                        replies.add(reply)
    except (AssertionError, OSError, EOFError) as error:
        errors.put(error)


def wait_for_page(vm, server, trusted, shot, deadline, errors):
    serial = ''
    while time.monotonic() < deadline:
        if not errors.empty():
            raise RuntimeError('Ошибка контролируемой сети QEMU') from errors.get()
        serial = clean(vm.log)
        if 'exception halted' in serial or 'Linux x86-64 exit status=' in serial:
            break
        if LEASE in serial:
            success = server.loaded.is_set() and f'{TITLE} - Google Chrome' in serial
            rejected = ('Privacy error - Google Chrome' in serial and 'net_error -202' in serial and
                        any('CERTIFICATE_UNKNOWN' in alert for alert in server.alerts))
            if (trusted and success) or (not trusted and rejected):
                vm.qmp('screendump', {'filename': str(shot)})
                if not trusted or read_frame(shot)[2].count(COLOR) > 100000:
                    return serial
        time.sleep(.2)
    raise AssertionError('Нет ожидаемого результата Chrome:\n' + '\n'.join(serial.splitlines()[-45:]))


def check_wire_capture(pcap, replies):
    frames = set(pcap_frames(pcap))
    assert replies and replies <= frames, 'В PCAP отсутствует DNS-ответ для тестового имени'
    queries = (dns_question(query[2]) for frame in frames if (query := dns_query(frame)))
    assert any(name.lower() == dns_name(HOST) and kind == 1 for name, kind, _ in queries)


def firmware_args(directory):
    code, template = firmware()
    variables = directory / 'vars.fd'
    shutil.copyfile(template, variables)
    return ['-machine', 'q35', '-fw_cfg', 'name=opt/ovmf/X-PciMmio64Mb,string=0',
            '-drive', f'if=pflash,format=raw,unit=0,readonly=on,file={qemu_path(code)}',
            '-drive', f'if=pflash,format=raw,unit=1,file={qemu_path(variables)}']


def examine_browser(directory, run_name, disk, certificate, key, trusted, artifacts, timeout, *, chrome_ml):
    egress, forward, injector, pcap = (directory / name for name in ('egress', 'forward', 'inject', 'wire.pcap'))
    shot = artifacts / f'{run_name}.ppm'
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, key)
    names, replies, errors = [], set(), queue.SimpleQueue()

    def record_sni(_socket, name, _context):
        names.append(name)

    context.sni_callback = record_sni
    with TlsServer(('127.0.0.1', 0), PageHandler) as server:
        server.requests, server.alerts, server.loaded = [], [], threading.Event()
        server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        args = network_args(egress, forward, injector, pcap)
        relay = f'python3 tests/kernel_x64_tcp_smoke.py --relay {server.server_port}'
        args[1] += f',guestfwd=tcp:{socket.inet_ntoa(SERVER)}:{PORT}-cmd:{relay}'
        try:
            vm = VM(run_name, firmware_args(directory) + [
                '-S', '-drive', f'if=none,id=root,format=raw,file={qemu_path(disk)}',
                '-device', 'nvme,drive=root,serial=UEFIX64,bootindex=1', *args,
            ], memory=CHROME_VM_MEMORY, binary='qemu-system-x86_64', cpu='max')
            try:
                with ExitStack() as stack:
                    peers = [connect(stack, path) for path in (egress, forward, injector)]
                    deadline = time.monotonic() + timeout
                    wire = threading.Thread(target=serve_wire, args=(*peers, replies, errors, deadline), daemon=True)
                    wire.start()
                    vm.qmp('cont')
                    vm.wait('UEFI video: V=mode menu', timeout=20)
                    vm.key('s')
                    wait_for_page(vm, server, trusted, shot, deadline, errors)
                    if chrome_ml:
                        assert 'ChromeML library loaded' in clean(vm.log), 'Гость не подтвердил загрузку ChromeML'
            finally:
                vm.stop()
                if pcap.exists():
                    shutil.copyfile(pcap, artifacts / f'{run_name}.pcap')
        finally:
            server.shutdown()
            worker.join()

        assert HOST in names, names
        if trusted:
            assert any(path == TARGET and host == ORIGIN and 'Chrome/' in agent and tls in ('TLSv1.2', 'TLSv1.3')
                       for path, host, agent, tls in server.requests), server.requests
        else:
            assert not server.requests, server.requests
            assert any('CERTIFICATE_UNKNOWN' in alert for alert in server.alerts), server.alerts
        (artifacts / f'{run_name}-https.log').write_text('\n'.join(map(str, server.requests + server.alerts)) + '\n')
        check_wire_capture(pcap, replies)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('chrome', 'compositor', 'kernel', 'launcher'):
        parser.add_argument(f'--{name}', type=pathlib.Path, required=True)
    parser.add_argument('--certutil', default='certutil')
    parser.add_argument('--cc', default=os.environ.get('CC', 'cc'))
    parser.add_argument('--artifacts', type=pathlib.Path, default=pathlib.Path('build'))
    parser.add_argument('--timeout', type=int, default=120)
    args = parser.parse_args()
    certutil = shutil.which(args.certutil)
    if certutil is None:
        parser.error('Укажите certutil из NSS через --certutil или PATH')
    args.artifacts = args.artifacts.resolve()
    args.artifacts.mkdir(parents=True, exist_ok=True)
    disk_install_smoke.B = args.artifacts

    with tempfile.TemporaryDirectory(prefix='myos-chrome-https-') as temp:
        directory = pathlib.Path(temp)
        wrapper = directory / 'chrome-test-launch'
        source = pathlib.Path(__file__).with_name('kernel_x64_chrome_launch.c')
        subprocess.run([*shlex.split(args.cc), '-O2', '-Wall', '-Wextra', source, '-o', wrapper, '-ldl'], check=True)
        chrome = args.chrome.resolve()
        base = chrome_files(chrome, args.compositor.resolve(), wrapper)
        chrome_ml = chrome.with_name(CHROME_ML_LIBRARY).is_file()
        if chrome_ml:
            base['/myos/chrome-test-ml'] = b''
        base.update({'/myos/chrome-launch-real': args.launcher.read_bytes(),
                     '/myos/chrome-url': f'https://{ORIGIN}{TARGET}\n'.encode(), '/myos/chrome-debug': b''})
        certificate, key, root = generate_certificates(directory)
        for trusted, suffix in ((True, ''), (False, '-untrusted')):
            name = f'x64-chrome-https{suffix}'
            case = directory / ('trusted' if trusted else 'untrusted')
            case.mkdir()
            make_uefi.DIRECTORY = case / 'firmware'
            disk = case / 'chrome.img'
            make_image(disk, args.kernel, wrapper, base | nss_files(case, root, certutil, trusted))
            examine_browser(case, name, disk, certificate, key, trusted, args.artifacts, args.timeout,
                            chrome_ml=chrome_ml)
    print('OVMF Linux x86-64 Chrome: DHCP DNS, trusted HTTPS rendering and untrusted certificate rejection: PASS', flush=True)


if __name__ == '__main__':
    main()
