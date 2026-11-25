"""Проверить ввод USB HID через xHCI и Linux evdev в MyOS x86-64."""
import argparse
from pathlib import Path
import re
import tempfile
import time

from kernel_x64_linux_smoke import image, linux_root
from uefi_x64_smoke import boot_x64, clean


TOPOLOGIES = {'usb': b'u', 'keyboard-only': b'k', 'ps2-mouse': b'm', 'hotplug': b'h'}


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


def add_hub_devices(vm, identifier):
    vm.qmp('device_add', {'driver': 'usb-hub', 'id': identifier, 'bus': 'xhci.0',
                          'port': '3', 'ports': 4, 'port-power': True})
    for device, port in (('kbd', '3.1'), ('mouse', '3.2')):
        vm.qmp('device_add', {'driver': f'usb-{device}', 'id': f'{identifier}-{device}',
                              'bus': 'xhci.0', 'port': port})


def wait_hub_devices(vm, offset):
    deadline = time.monotonic() + 18
    serial = ''
    while time.monotonic() < deadline and vm.p.poll() is None:
        serial = clean(vm.log)[offset:]
        hids = re.findall(r'USB HID (keyboard|mouse): port (\d+), slot (\d+), endpoint \d+', serial)
        attached = set(re.findall(r'USB attached: root (\d+) route ([12]) slot (\d+),', serial))
        if all(any(kind == device and (port, route, slot) in attached for kind, port, slot in hids)
               for device, route in (('keyboard', '1'), ('mouse', '2'))):
            return len(clean(vm.log))
        if 'Linux x86-64 exit status=' in serial:
            break
        time.sleep(.05)
    raise AssertionError('No guest publication of both hub HID devices:\n' + serial[-3000:])


def send_events(vm, sequence, offset):
    for marker, events in sequence:
        vm.qmp('input-send-event', {'events': events})
        offset = vm.wait(marker, after=offset, timeout=12)
    return offset


def exercise_hotplug(vm):
    offset = vm.wait('USB hotplug empty controller')
    add_hub_devices(vm, 'hub-first')
    offset = vm.wait('USB hotplug opened both devices', after=offset, timeout=18)
    offset = send_events(vm, [
        ('USB hotplug key held', [key(True)]),
        ('USB hotplug button held', [button('left', True)]),
    ], offset)
    vm.qmp('device_del', {'id': 'hub-first'})
    offset = vm.wait('USB hotplug hub removal released key and button', after=offset, timeout=18)

    add_hub_devices(vm, 'hub-again')
    offset = wait_hub_devices(vm, offset)
    offset = send_events(vm, [
        ('USB hotplug key reconnected', [key(True)]),
        ('USB hotplug key up after reconnect', [key(False)]),
        ('USB hotplug mouse reconnected', [movement('x', -19), movement('y', 13)]),
        ('USB hotplug button down after reconnect', [button('left', True)]),
        ('USB hotplug mouse up after reconnect', [button('left', False)]),
    ], offset)
    vm.qmp('device_del', {'id': 'hub-again'})
    vm.wait('USB hotplug DMA pages reclaimed', after=offset, timeout=12)


def exercise_input(vm, topology):
    if topology == 'hotplug':
        exercise_hotplug(vm)
        return
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
    offset = send_events(vm, sequence, vm.wait('USB input ready'))

    if topology == 'usb':
        offset = verify_unplug(vm, offset, 'mouse', button('left', True),
                               'USB mouse held', 'USB mouse removed')
        verify_unplug(vm, offset, 'keyboard', key(True),
                      'USB key held', 'USB keyboard removed')


def check_topology(payload, kernel_end, elf, topology):
    qemu = ['-device', 'qemu-xhci,id=xhci']
    if topology != 'hotplug':
        qemu.extend(['-device', 'usb-kbd,bus=xhci.0,id=keyboard'])
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
