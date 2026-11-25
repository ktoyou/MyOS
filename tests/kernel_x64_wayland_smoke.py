"""Проверка кадра и ввода отдельного Wayland-клиента в QEMU."""
import pathlib
import subprocess
import sys
import tempfile

from kernel_x64_linux_smoke import linux_root
from kernel_x64_smoke import image
from uefi_x64_smoke import boot_x64


POINTER_DX, POINTER_DY = 48, 36
CURSOR_DX, CURSOR_DY = 5, 3
CURSOR_HOTSPOT_X, CURSOR_HOTSPOT_Y = 2, 1
CURSOR_COLOR = bytes.fromhex('ed117a')
COLORS = ((bytes.fromhex('f14c88'), bytes.fromhex('13c5a2')),
          (bytes.fromhex('8254ec'), bytes.fromhex('d49d12')))


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


def read_frame(shot):
    magic, width, height, maxval, pixels = shot.read_bytes().split(maxsplit=4)
    w, h = int(width), int(height)
    assert magic == b'P6' and maxval == b'255' and len(pixels) == w * h * 3
    return w, h, pixels


def different_pixel(w, h, pixels, x, y):
    offset = (y * w + x) * 3
    return pixels[offset:offset + 3] != COLORS[y >= h // 2][x >= w // 2]


def check_pixels(shot):
    w, h, pixels = read_frame(shot)
    for y in (0, h // 2 - 1, h // 2, h - 1):
        for x in (0, w // 2 - 1, w // 2, w - 1):
            assert not different_pixel(w, h, pixels, x, y), (x, y, w, h)


def overlay_pixels(w, h, pixels, cx, cy):
    return [(x, y) for y in range(max(0, cy - 16), min(h, cy + 17))
            for x in range(max(0, cx - 16), min(w, cx + 17))
            if different_pixel(w, h, pixels, x, y)]


def check_fallback_cursor(shot, dx=0, dy=0):
    w, h, pixels = read_frame(shot)
    center_x, center_y = w // 2, h // 2
    assert len(overlay_pixels(w, h, pixels, center_x + dx, center_y + dy)) > 1, 'missing fallback cursor'
    if dx or dy:
        assert not overlay_pixels(w, h, pixels, center_x, center_y), 'cursor trail at the old position'


def check_client_cursor(shot):
    w, h, pixels = read_frame(shot)
    x, y = w // 2 + POINTER_DX + CURSOR_DX, h // 2 + POINTER_DY + CURSOR_DY
    image_x, image_y = x - CURSOR_HOTSPOT_X, y - CURSOR_HOTSPOT_Y
    offset = (image_y * w + image_x) * 3
    assert pixels[offset:offset + 3] == CURSOR_COLOR, 'client cursor color or hotspot'
    assert overlay_pixels(w, h, pixels, x, y) == [(image_x, image_y)], 'cursor transparency or fallback trail'


def main():
    build = pathlib.Path(sys.argv[1])
    client = build / 'wayland-client'
    compositor = build / 'wayland-compositor'
    files = dependencies(client) | dependencies(compositor)
    files['/myos/wayland-compositor'] = compositor.read_bytes()
    files['/myos/keyboard.xkb'] = (build / 'keyboard.xkb').read_bytes()
    root = linux_root(client.read_bytes(), files, '/myos/wayland-client')
    payload, kernel_end = image('kernel-linux')

    with tempfile.TemporaryDirectory(prefix='myos-wayland-x64-') as temp:
        directory = pathlib.Path(temp)
        shot = directory / 'wayland.ppm'

        def input_events(vm):
            vm.wait('Wayland keyboard focused')
            events = [{'type': 'key', 'data': {'down': down, 'key': {'type': 'qcode', 'data': key}}}
                      for key, down in (('shift', True), ('a', True), ('a', False), ('shift', False))]
            vm.qmp('input-send-event', {'events': events})

            vm.wait('Wayland pointer focused')
            initial = directory / 'cursor-initial.ppm'
            vm.qmp('screendump', {'filename': str(initial)})
            check_fallback_cursor(initial)

            def move(dx, dy):
                vm.qmp('input-send-event', {'events': [
                    {'type': 'rel', 'data': {'axis': 'x', 'value': dx}},
                    {'type': 'rel', 'data': {'axis': 'y', 'value': dy}},
                ]})

            move(POINTER_DX, POINTER_DY)
            vm.wait('Wayland pointer moved')
            moved = directory / 'cursor-moved.ppm'
            vm.qmp('screendump', {'filename': str(moved)})
            check_fallback_cursor(moved, POINTER_DX, POINTER_DY)

            move(CURSOR_DX, CURSOR_DY)
            vm.wait('Wayland client cursor presented')
            client_cursor = directory / 'cursor-client.ppm'
            vm.qmp('screendump', {'filename': str(client_cursor)})
            check_client_cursor(client_cursor)
            for button, states, marker in (('left', (True,), 'Wayland left button down'),
                                           ('left', (False,), 'Wayland left button up'),
                                           ('wheel-up', (True, False), 'Wayland wheel up')):
                vm.qmp('input-send-event', {'events': [
                    {'type': 'btn', 'data': {'button': button, 'down': down}} for down in states
                ]})
                vm.wait(marker)

        serial = boot_x64(directory, 'x64-linux-wayland', payload, kernel_end,
                          ['Wayland shared memory frame presented', 'Linux x86-64 exit status=0x00'],
                          live_root_header=root, screenshot=shot, interact=input_events)
        assert 'x86-64 exception' not in serial, serial
        check_pixels(shot)
        check_fallback_cursor(shot, POINTER_DX + CURSOR_DX, POINTER_DY + CURSOR_DY)
    print('OVMF: Wayland xdg-shell, shared memory, framebuffer, keyboard and pointer: PASS', flush=True)


if __name__ == '__main__':
    main()
