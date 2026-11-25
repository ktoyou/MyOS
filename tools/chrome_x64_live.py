"""Собрать Live-образ MyOS x86-64 для уже распакованного официального Chrome."""

import argparse
import os
from pathlib import Path, PurePosixPath
import shutil
import struct
import subprocess
import tempfile
from urllib.parse import urlsplit

if __package__:
    from . import make_uefi
else:
    import make_uefi


REPO = Path(__file__).resolve().parents[1]
CHROME_GUEST = '/opt/google/chrome'
LAUNCHER_GUEST = '/myos/chrome-launch'
URL_GUEST = '/myos/chrome-url'
DEFAULT_URL = 'https://www.kernel.org/'
PAGE_SIZE = 4096
URL_LIMIT = PAGE_SIZE - 2  # fgets должен уместить также перевод строки и NUL.
ROOT_MAX = 512 * 1024 * 1024
MAX_FILES = 1024
DISK_ID = 0x23456789

FONT_CONFIG = b'''<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd">
<fontconfig>
  <dir>/usr/share/fonts/myos</dir>
  <cachedir>/tmp</cachedir>
  <alias><family>sans-serif</family><prefer><family>Ubuntu</family></prefer></alias>
</fontconfig>
'''


def dependencies(binary: Path) -> dict[str, Path]:
    result = subprocess.run(('ldd', str(binary.resolve(strict=True))), capture_output=True, text=True,
                            env={**os.environ, 'LC_ALL': 'C'})
    if result.returncode:
        message = (result.stdout + result.stderr).strip()
        if message == 'not a dynamic executable' or message == 'statically linked':
            return {}
        raise ValueError(f'{binary}: ldd: {message}')

    files = {}
    for line in result.stdout.splitlines():
        name, arrow, target = line.strip().partition(' => ')
        if arrow and target == 'not found':
            raise ValueError(f'{binary}: библиотека {name} не найдена')
        location = (target if arrow else name).split(' (0x', 1)[0]
        if location.startswith('/'):
            host = Path(location)
            files[name if arrow else str(host)] = host
    return files


def merge_dependencies(existing: dict[str, Path], additions: dict[str, Path]) -> None:
    for name, host in additions.items():
        previous = existing.get(name)
        if previous is not None and not previous.samefile(host):
            raise ValueError(f'Несовместимые файлы библиотеки {name}: {previous} и {host}')
        existing[name] = host


def chrome_files(chrome: Path, compositor: Path, launcher: Path) -> dict[str, bytes]:
    """Прочитать файлы доверенного дистрибутива Chrome и локальные Linux-библиотеки."""
    directory = chrome.parent
    crashpad = directory / 'chrome_crashpad_handler'
    libs = {}
    for executable in (chrome, crashpad, compositor, launcher):
        merge_dependencies(libs, dependencies(executable))

    if 'libc.so.6' not in libs or 'libnss3.so' not in libs:
        raise ValueError(f'{chrome}: требуются glibc и NSS для x86-64 Linux')
    libdir = PurePosixPath(str(libs['libc.so.6'].parent))
    nss_dir = libs['libnss3.so'].parent
    for name in ('libsoftokn3.so', 'libfreeblpriv3.so', 'libnssckbi.so'):
        # NSS загружает эти модули во время запуска, поэтому их нет в ldd Chrome.
        module = nss_dir / name
        merge_dependencies(libs, dependencies(module))
        merge_dependencies(libs, {name: module})

    library_paths = {}
    for name, host in libs.items():
        if '/' in name and not name.startswith('/'):
            raise ValueError(f'{chrome}: неожиданный путь библиотеки {name}')
        guest = name if name.startswith('/') else str(libdir / name)
        merge_dependencies(library_paths, {guest: host})

    files = {guest: host.read_bytes() for guest, host in library_paths.items()}
    files[f'{CHROME_GUEST}/chrome'] = chrome.read_bytes()
    required = ('chrome_crashpad_handler', 'icudtl.dat', 'resources.pak', 'chrome_100_percent.pak',
                'chrome_200_percent.pak', 'v8_context_snapshot.bin')
    optional = ('CHROME_VERSION_EXTRA', 'libvk_swiftshader.so', 'libvulkan.so.1', 'vk_swiftshader_icd.json')
    for name in required:
        files[f'{CHROME_GUEST}/{name}'] = (directory / name).read_bytes()
    for name in optional:
        asset = directory / name
        if asset.is_file():
            files[f'{CHROME_GUEST}/{name}'] = asset.read_bytes()
    locales = sorted(asset for asset in (directory / 'locales').glob('en-US*') if asset.is_file())
    if not locales:
        raise ValueError(f'{chrome}: файлы локали en-US не найдены')
    for locale in locales:
        files[f'{CHROME_GUEST}/locales/{locale.name}'] = locale.read_bytes()

    files['/myos/wayland-compositor'] = compositor.read_bytes()
    files['/myos/keyboard.xkb'] = (compositor.parent / 'keyboard.xkb').read_bytes()
    files['/etc/fonts/fonts.conf'] = FONT_CONFIG
    files['/usr/share/fonts/myos/Ubuntu-R.ttf'] = (REPO / 'fonts/Ubuntu-R.ttf').read_bytes()
    return files


def align_page(position: int) -> int:
    return (position + PAGE_SIZE - 1) // PAGE_SIZE * PAGE_SIZE


def live_path(path: str) -> bytes:
    encoded = path.encode('utf-8') + b'\0'
    if (not path.startswith('/') or len(encoded) > PAGE_SIZE or '\0' in path or
            any(not part or part in ('.', '..') or len(part.encode('utf-8')) > 255
                for part in path[1:].split('/'))):
        raise ValueError(f'Недопустимый путь в Live-образе: {path!r}')
    return encoded


def make_image(path: Path, kernel: Path, launcher: Path, files: dict[str, bytes]) -> None:
    """Записать разреженный образ с ESP и выровненными записями Live-корня."""
    executable = launcher.read_bytes()
    entry = live_path(LAUNCHER_GUEST)
    if len(files) > MAX_FILES or LAUNCHER_GUEST in files:
        raise ValueError('Превышен предел файлов Live-корня или путь запуска задан повторно')

    records = [(live_path(name), data) for name, data in files.items()]
    root_size = align_page(32 + len(entry)) + len(executable)
    for name, data in records:
        root_size = align_page(root_size + 16 + len(name)) + len(data)
    root_size = align_page(root_size)
    if root_size > ROOT_MAX:
        raise ValueError('Размер Live-корня превышает 512 МиБ')
    root_sectors = root_size // 512

    payload = kernel.with_suffix('.bin').read_bytes()
    symbols = subprocess.check_output(('nm', str(kernel.with_suffix('.elf'))), text=True)
    end = next((int(line.split()[0], 16) for line in symbols.splitlines()
                if line.endswith(' __kernel_end')), None)
    if end is None:
        raise ValueError(f'{kernel.with_suffix(".elf")}: отсутствует __kernel_end')
    efi, _ = make_uefi.esp(payload, end, mode=1, disk_id=DISK_ID, root_sectors=root_sectors, arch='x86_64')

    mbr = bytearray(512)
    struct.pack_into('<I', mbr, 440, DISK_ID)
    struct.pack_into('<B3xB3xII', mbr, 446, 0, 0x83, make_uefi.ROOT_START, root_sectors)
    struct.pack_into('<B3xB3xII', mbr, 462, 0, 0xef, make_uefi.ESP_START, make_uefi.ESP_SECTORS)
    mbr[510:] = b'\x55\xaa'

    path.parent.mkdir(parents=True, exist_ok=True)
    disk = tempfile.NamedTemporaryFile(dir=path.parent, prefix=f'.{path.name}.', delete=False)
    temporary = Path(disk.name)
    try:
        with disk:
            disk.write(mbr)
            disk.seek(make_uefi.ESP_START * 512)
            disk.write(efi)
            root = make_uefi.ROOT_START * 512
            disk.seek(root)
            disk.write(struct.pack('<8s3Q', b'MYOSLX66', len(executable), len(records), len(entry)))
            disk.write(entry)
            disk.seek(root + align_page(disk.tell() - root))
            disk.write(executable)
            for name, data in records:
                disk.write(struct.pack('<2Q', len(name), len(data)))
                disk.write(name)
                disk.seek(root + align_page(disk.tell() - root))
                disk.write(data)
            disk.truncate(root + root_size)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def firmware() -> tuple[Path, Path]:
    override_code, override_vars = os.environ.get('OVMF_CODE'), os.environ.get('OVMF_VARS')
    if override_code or override_vars:
        if not (override_code and override_vars):
            raise ValueError('Задайте OVMF_CODE и OVMF_VARS вместе')
        return Path(override_code).resolve(strict=True), Path(override_vars).resolve(strict=True)
    for directory, suffix in (('/usr/share/OVMF', '_4M'), ('/usr/share/OVMF', ''),
                              ('/usr/share/edk2/ovmf', '')):
        code = Path(directory) / f'OVMF_CODE{suffix}.fd'
        variables = Path(directory) / f'OVMF_VARS{suffix}.fd'
        if code.is_file() and variables.is_file():
            return code, variables
    raise ValueError('OVMF не найден. Укажите файлы прошивки в OVMF_CODE и OVMF_VARS')


def qemu_path(path: Path) -> str:
    return str(path.resolve()).replace(',', ',,')


def run_image(image: Path, headless: bool) -> None:
    code, variables = firmware()
    with tempfile.TemporaryDirectory(prefix='myos-chrome-ovmf-') as directory:
        copy = Path(directory) / 'vars.fd'
        shutil.copyfile(variables, copy)
        subprocess.run((
            'qemu-system-x86_64', '-machine', 'q35', '-cpu', 'max', '-m', '1024M', '-no-reboot',
            '-display', 'none' if headless else 'gtk', '-serial', 'stdio', '-monitor', 'none',
            '-fw_cfg', 'name=opt/ovmf/X-PciMmio64Mb,string=0',
            '-drive', f'if=pflash,format=raw,unit=0,readonly=on,file={qemu_path(code)}',
            '-drive', f'if=pflash,format=raw,unit=1,file={qemu_path(copy)}',
            '-drive', f'if=none,id=root,format=raw,snapshot=on,file={qemu_path(image)}',
            '-device', 'nvme,drive=root,serial=MYOSCHROME,bootindex=1',
            '-nic', 'none', '-netdev', 'user,id=wire,ipv6=off', '-device', 'e1000,netdev=wire',
        ), check=True)


def navigation_url(text: str) -> str:
    try:
        url = urlsplit(text)
        if (0 < len(text.encode('utf-8')) <= URL_LIMIT and all(ord(char) > 32 and ord(char) != 127 for char in text)
                and (text == 'about:blank' or (url.scheme in ('http', 'https') and url.hostname))):
            return url.scheme + text[len(url.scheme):]
    except ValueError:
        pass
    raise argparse.ArgumentTypeError('Ожидается URL http://, https:// или about:blank')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True, help='путь к ядру без суффикса .bin или .elf')
    parser.add_argument('--compositor', type=Path, required=True)
    parser.add_argument('--launcher', type=Path, required=True)
    parser.add_argument('--chrome', type=Path, required=True, help='исполняемый файл доверенного Chrome')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--url', type=navigation_url, default=DEFAULT_URL)
    parser.add_argument('--run', action='store_true', help='запустить образ в QEMU после сборки')
    parser.add_argument('--headless', action='store_true', help='запустить QEMU без графического окна')
    args = parser.parse_args()
    if args.headless and not args.run:
        parser.error('--headless требует --run')

    try:
        inputs = (args.chrome, args.compositor, args.launcher, args.kernel.with_suffix('.bin'),
                  args.kernel.with_suffix('.elf'))
        if args.output.resolve() in (source.resolve() for source in inputs):
            raise ValueError('Путь выходного образа совпадает с входным файлом')
        files = chrome_files(args.chrome, args.compositor, args.launcher)
        files[URL_GUEST] = args.url.encode('utf-8') + b'\n'
        make_image(args.output, args.kernel, args.launcher, files)
        print(args.output.resolve(), flush=True)
        if args.run:
            run_image(args.output, args.headless)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'{parser.prog}: {error}\n')
    except KeyboardInterrupt:
        parser.exit(130)


if __name__ == '__main__':
    main()
