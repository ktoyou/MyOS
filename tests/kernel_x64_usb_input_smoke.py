"""Проверить ввод USB HID через xHCI и Linux evdev в MyOS x86-64."""
import argparse
from pathlib import Path
import tempfile

from kernel_x64_linux_smoke import image, linux_root
from uefi_x64_smoke import boot_x64


TOPOLOGIES = {'usb': b'u', 'keyboard-only': b'k', 'ps2-mouse': b'm'}


def key(down):
    return {'type': 'key', 'data': {'down': down, 'key': {'type': 'qcode', 'data': 'a'}}}


def button(name, down):
    return {'type': 'btn', 'data': {'down': down, 'button': name}}


def movement(axis, value):
    return {'type': 'rel', 'data': {'axis': axis, 'value': value}}


def verify_unplug(vm, offset, device, event, held, removed):
    vm.qmp('input-send-event', {'events': [event]})
    offset = vm.wait(held, after=offset, timeout=12)
    vm.qmp('device_del', {'id': device})
    return vm.wait(removed, after=offset, timeout=12)


def exercise_input(vm, topology):
    sequence = [
        ('USB KEY_A down', [key(True)]),
        ('USB KEY_A up', [key(False)]),
    ]
    if topology != 'keyboard-only':
        sequence.extend([
            ('Input mouse moved', [movement('x', -19), movement('y', 13)]),
            ('Input BTN_LEFT down', [button('left', True)]),
            ('Input BTN_LEFT up', [button('left', False)]),
            ('Input REL_WHEEL up', [button('wheel-up', True), button('wheel-up', False)]),
            ('Input REL_WHEEL down', [button('wheel-down', True), button('wheel-down', False)]),
        ])
    offset = vm.wait('USB input ready')
    for marker, events in sequence:
        vm.qmp('input-send-event', {'events': events})
        offset = vm.wait(marker, after=offset, timeout=12)

    if topology == 'usb':
        offset = verify_unplug(vm, offset, 'mouse', button('left', True),
                               'USB mouse held', 'USB mouse removed')
        verify_unplug(vm, offset, 'keyboard', key(True),
                      'USB key held', 'USB keyboard removed')


def check_topology(payload, kernel_end, elf, topology):
    qemu = ['-device', 'qemu-xhci,id=xhci', '-device', 'usb-kbd,bus=xhci.0,id=keyboard']
    if topology != 'ps2-mouse':
        qemu.extend(['-machine', 'q35,i8042=off'])
    if topology == 'usb':
        qemu.extend(['-device', 'usb-mouse,bus=xhci.0,id=mouse'])

    root = linux_root(elf, {'/myos/usb-input-mode': TOPOLOGIES[topology]})
    with tempfile.TemporaryDirectory(prefix='myos-x64-usb-input-') as temp:
        serial = boot_x64(Path(temp), f'x64-usb-input-{topology}', payload, kernel_end,
                          ['Linux x86-64 USB input PASS', 'Linux x86-64 exit status=0x00'],
                          live_root_header=root, extra=qemu,
                          interact=lambda vm: exercise_input(vm, topology))
    assert 'x86-64 exception' not in serial, serial
    print(f'OVMF Linux x86-64 USB input ({topology}): PASS', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--topology', choices=TOPOLOGIES)
    args = parser.parse_args()
    payload, kernel_end = image('kernel-linux')
    elf = Path('build/x86_64/linux-usb-input.elf').read_bytes()
    for topology in (args.topology,) if args.topology else TOPOLOGIES:
        check_topology(payload, kernel_end, elf, topology)


if __name__ == '__main__':
    main()
