"""Проверка кадра отдельного Wayland-клиента по снимку QEMU."""
import pathlib
import subprocess
import sys
import tempfile

from kernel_x64_linux_smoke import linux_root
from kernel_x64_smoke import image
from uefi_x64_smoke import boot_x64


def dependencies(binary):
    files = {}
    for line in subprocess.check_output(('ldd', str(binary.resolve())), text=True).splitlines():
        name, separator, library = line.strip().partition(' => ')
        if separator:
            if library == 'not found':
                raise RuntimeError(f'{binary}: {name}: {library}')
            path = pathlib.Path(library.split()[0])
            guest = f'/lib/x86_64-linux-gnu/{name}'
        elif name.startswith('/'):
            path = pathlib.Path(name.split()[0])
            guest = str(path)
        else:
            continue
        files[guest] = path.read_bytes()
    return files


def check_pixels(shot):
    magic, width, height, maxval, pixels = shot.read_bytes().split(maxsplit=4)
    w, h = int(width), int(height)
    assert magic == b'P6' and maxval == b'255' and len(pixels) == w * h * 3
    colors = (('f14c88', '13c5a2'), ('8254ec', 'd49d12'))
    for y in (0, h // 2 - 1, h // 2, h - 1):
        for x in (0, w // 2 - 1, w // 2, w - 1):
            offset = (y * w + x) * 3
            actual = pixels[offset:offset + 3].hex()
            assert actual == colors[y >= h // 2][x >= w // 2], (x, y, w, h, actual)


def main():
    build = pathlib.Path(sys.argv[1])
    client = build / 'wayland-client'
    compositor = build / 'wayland-compositor'
    files = dependencies(client) | dependencies(compositor)
    files['/myos/wayland-compositor'] = compositor.read_bytes()
    root = linux_root(client.read_bytes(), files, '/myos/wayland-client')
    payload, kernel_end = image('kernel-linux')
    with tempfile.TemporaryDirectory(prefix='myos-wayland-x64-') as temp:
        directory = pathlib.Path(temp)
        shot = directory / 'wayland.ppm'
        serial = boot_x64(directory, 'x64-linux-wayland', payload, kernel_end,
                          ['Wayland shared memory frame presented', 'Linux x86-64 exit status=0x00'],
                          live_root_header=root, screenshot=shot)
        assert 'x86-64 exception' not in serial, serial
        check_pixels(shot)
    print('OVMF: Wayland xdg-shell, shared memory, frame callback and framebuffer pixels: PASS', flush=True)


if __name__ == '__main__':
    main()
