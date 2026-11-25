"""Собрать Live-образ MyOS x86-64 для уже распакованного официального Chrome."""

import argparse
import os
import secrets
import stat
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
CHROME_ML_LIBRARY = 'liboptimization_guide_internal.so'
CHROME_ML_ASSETS = (CHROME_ML_LIBRARY, 'libLiteRtWebGpuAccelerator.so')
CHROME_VM_MEMORY = '1280M'
LAUNCHER_GUEST = '/myos/chrome-launch'
URL_GUEST = '/myos/chrome-url'
PROFILE_TOKEN_GUEST = '/myos/myfs-volume'
PROFILE_MAGIC = b'MYOSPROF'
PROFILE_TOKEN_BYTES = 16
PROFILE_SECTOR = 512
PROFILE_BYTES = 1024 * 1024 * 1024
MYFS_MAX_SECTORS = 128 * 1024 * 1024
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
    # Вспомогательные процессы загружают эти модули через dlopen.
    modules = tuple(directory / name for name in CHROME_ML_ASSETS if (directory / name).is_file())
    for executable in (chrome, crashpad, compositor, launcher, *modules):
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
    optional = ('CHROME_VERSION_EXTRA', 'libvk_swiftshader.so', 'libvulkan.so.1', 'vk_swiftshader_icd.json',
                *CHROME_ML_ASSETS)
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


def read_profile_token(path: Path) -> bytes:
    # O_NONBLOCK позволяет отклонить FIFO, не дожидаясь писателя.
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK), 'rb') as disk:
        info = os.fstat(disk.fileno())
        sectors, remainder = divmod(info.st_size, PROFILE_SECTOR)
        if not stat.S_ISREG(info.st_mode) or remainder or not 1 < sectors <= MYFS_MAX_SECTORS + 1:
            raise ValueError(f'{path}: ожидается файл-образ профиля MyFS')
        magic, version, blocks = struct.unpack('<4sII', disk.read(12))
        if magic != b'MYFS' or version not in (5, 6) or blocks != sectors - 1:
            raise ValueError(f'{path}: неверный заголовок тома профиля MyFS')
        disk.seek(-PROFILE_SECTOR, os.SEEK_END)
        record = disk.read(len(PROFILE_MAGIC) + PROFILE_TOKEN_BYTES)
        token = record[len(PROFILE_MAGIC):]
        if not record.startswith(PROFILE_MAGIC) or len(token) != PROFILE_TOKEN_BYTES or not any(token):
            raise ValueError(f'{path}: отсутствует идентификатор профиля MyOS')
        return token


def prepare_profile(path: Path, myfs: Path, *, size: int = PROFILE_BYTES) -> bytes:
    try:
        return read_profile_token(path)
    except FileNotFoundError:
        if path.is_symlink():
            raise
    if size < 16 * 1024 * 1024 or size % PROFILE_SECTOR or size > MYFS_MAX_SECTORS * PROFILE_SECTOR:
        raise ValueError('Недопустимый размер тома для профиля MyFS')
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.myos-chrome-profile-', dir=path.parent) as directory:
        candidate = Path(directory) / 'profile.img'
        fd = os.open(candidate, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w+b') as disk:
            disk.truncate(size)
        for args in (('mkdir', '/chrome'), ('chmod', '0700', '/chrome'), ('chown', '1000', '1000', '/chrome')):
            subprocess.run((str(myfs.resolve()), str(candidate), *args), check=True, stdout=subprocess.DEVNULL)

        token = secrets.token_bytes(PROFILE_TOKEN_BYTES)
        with candidate.open('ab') as disk:
            disk.write((PROFILE_MAGIC + token).ljust(PROFILE_SECTOR, b'\0'))
            disk.flush()
            os.fsync(disk.fileno())
        token = read_profile_token(candidate)
        try:
            # Публикация готового тома не заменяет файл параллельного запуска.
            os.link(candidate, path)
        except FileExistsError:
            return read_profile_token(path)
        return token


def profile_drive_args(path: Path) -> tuple[str, ...]:
    return (
        '-drive', f'if=none,id=chrome-profile,format=raw,snapshot=off,file={qemu_path(path)}',
        '-device', 'nvme,drive=chrome-profile,serial=MYOSPROFILE',
    )


def run_image(image: Path, headless: bool, profile: Path | None = None) -> None:
    code, variables = firmware()
    with tempfile.TemporaryDirectory(prefix='myos-chrome-ovmf-') as directory:
        copy = Path(directory) / 'vars.fd'
        shutil.copyfile(variables, copy)
        subprocess.run((
            'qemu-system-x86_64', '-machine', 'q35', '-cpu', 'max', '-m', CHROME_VM_MEMORY, '-no-reboot',
            '-display', 'none' if headless else 'gtk', '-serial', 'stdio', '-monitor', 'none',
            '-fw_cfg', 'name=opt/ovmf/X-PciMmio64Mb,string=0',
            '-drive', f'if=pflash,format=raw,unit=0,readonly=on,file={qemu_path(code)}',
            '-drive', f'if=pflash,format=raw,unit=1,file={qemu_path(copy)}',
            '-drive', f'if=none,id=root,format=raw,snapshot=on,file={qemu_path(image)}',
            '-device', 'nvme,drive=root,serial=MYOSCHROME,bootindex=1',
            *(profile_drive_args(profile) if profile is not None else ()),
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


def same_path(first: Path, second: Path) -> bool:
    if first.resolve() == second.resolve():
        return True
    try:
        return first.samefile(second)
    except FileNotFoundError:
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True, help='путь к ядру без суффикса .bin или .elf')
    parser.add_argument('--compositor', type=Path, required=True)
    parser.add_argument('--launcher', type=Path, required=True)
    parser.add_argument('--chrome', type=Path, required=True, help='исполняемый файл доверенного Chrome')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--url', type=navigation_url, default=DEFAULT_URL)
    parser.add_argument('--profile', help='отдельный образ MyFS для постоянного профиля')
    parser.add_argument('--myfs', type=Path, default=REPO / 'build/myfs')
    parser.add_argument('--run', action='store_true', help='запустить образ в QEMU после сборки')
    parser.add_argument('--headless', action='store_true', help='запустить QEMU без графического окна')
    args = parser.parse_args()
    if args.headless and not args.run:
        parser.error('--headless требует --run')

    try:
        inputs = (args.chrome, args.compositor, args.launcher, args.kernel.with_suffix('.bin'),
                  args.kernel.with_suffix('.elf'), *(args.chrome.with_name(name) for name in CHROME_ML_ASSETS))
        profile = Path(args.profile) if args.profile else None
        if profile is not None:
            inputs = (*inputs, args.myfs)
        if any(same_path(args.output, source) for source in inputs):
            raise ValueError('Путь выходного образа совпадает с входным файлом')
        if profile is not None and any(same_path(profile, source) for source in (*inputs, args.output)):
            raise ValueError('Образ профиля совпадает с входным файлом или Live-образом')
        files = chrome_files(args.chrome, args.compositor, args.launcher)
        files[URL_GUEST] = args.url.encode('utf-8') + b'\n'
        if profile is not None:
            files[PROFILE_TOKEN_GUEST] = prepare_profile(profile, args.myfs)
        make_image(args.output, args.kernel, args.launcher, files)
        print(args.output.resolve(), flush=True)
        if args.run:
            run_image(args.output, args.headless, profile)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'{parser.prog}: {error}\n')
    except KeyboardInterrupt:
        parser.exit(130)


if __name__ == '__main__':
    main()
