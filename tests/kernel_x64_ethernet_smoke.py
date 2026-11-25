"""Проверка PCI e1000 и обмена ARP поверх QEMU user networking."""
import pathlib
import struct
import tempfile

from kernel_x64_smoke import image
from kernel_x64_linux_smoke import linux_root
from uefi_x64_smoke import boot_x64


MAC = bytes.fromhex('52 54 00 19 01 ab')
ARP_HEADER = bytes.fromhex('08 06 00 01 08 00 06 04 00')
NETWORK = bytes((10, 0, 2))
GATEWAY = NETWORK + b'\x02'
FIRST_HOST, DOWN_HOST, RECOVERY_HOST = 100, 140, 141
NETWORK_ARGS = (
    '-netdev', 'user,id=wire,restrict=on,ipv6=off',
    '-device', f'e1000,netdev=wire,id=eth0,mac={MAC.hex(":")}',
)


def set_link(vm, up):
    vm.qmp('set_link', {'name': 'eth0', 'up': up})


def exercise_link(vm):
    for marker, up in (
        ('e1000 test: initial link down', True),
        ('e1000 test: exchanged 40 ARP replies', False),
        ('e1000 test: traffic blocked with link down', True),
    ):
        vm.wait(marker, timeout=20)
        set_link(vm, up)


def pcap_frames(path):
    with path.open('rb') as pcap:
        header = pcap.read(24)
        endian = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>'}.get(header[:4])
        assert endian and len(header) == 24, header
        assert struct.unpack_from(endian + 'I', header, 20)[0] == 1, 'expected Ethernet PCAP'
        record = struct.Struct(endian + 'IIII')
        while info := pcap.read(record.size):
            assert len(info) == record.size, 'truncated PCAP record'
            _, _, captured, length = record.unpack(info)
            assert captured <= length, (captured, length)
            frame = pcap.read(captured)
            assert len(frame) == captured, 'truncated PCAP frame'
            yield frame


def check_capture(path):
    observed = []
    for frame in pcap_frames(path):
        if len(frame) < 42 or frame[12:21] != ARP_HEADER:
            continue
        if frame[6:12] == MAC and frame[21] == 1 and frame[28:31] == NETWORK:
            host = frame[31]
            if FIRST_HOST <= host <= RECOVERY_HOST:
                assert frame[:6] == b'\xff' * 6 and frame[22:28] == MAC, frame.hex()
                assert frame[32:38] == bytes(6) and frame[38:42] == GATEWAY, frame.hex()
                observed.append((host, 1))
        if frame[:6] == MAC and frame[21] == 2 and frame[38:41] == NETWORK:
            host = frame[41]
            if FIRST_HOST <= host <= RECOVERY_HOST:
                assert frame[6:12] == frame[22:28] and frame[6:12] != MAC and not frame[6] & 1, frame.hex()
                assert frame[28:32] == GATEWAY and frame[32:38] == MAC, frame.hex()
                observed.append((host, 2))
    # У каждой пары свой адрес отправителя. Повторный или устаревший ответ не засчитывается.
    hosts = (*range(FIRST_HOST, DOWN_HOST), RECOVERY_HOST)
    assert observed == [(host, op) for host in hosts for op in (1, 2)], observed


def main():
    payload, kernel_end = image('kernel-ethernet')
    with tempfile.TemporaryDirectory(prefix='myos-ethernet-x64-') as temp:
        directory = pathlib.Path(temp)
        pcap = directory / 'ethernet.pcap'
        serial = boot_x64(directory, 'x64-kernel-ethernet', payload, kernel_end,
                          ['x86-64 e1000 ARP PASS'], before_boot=lambda vm: set_link(vm, False),
                          interact=exercise_link, extra=[
                              *NETWORK_ARGS,
                              '-object', f'filter-dump,id=arp-dump,netdev=wire,file={pcap}',
                          ])
        assert 'x86-64 e1000 ARP FAIL' not in serial and 'x86-64 exception' not in serial, serial
        check_capture(pcap)
    print('OVMF x86-64 e1000: link transitions, 40 ARP exchanges across both rings, recovery: PASS', flush=True)

    payload, kernel_end = image('kernel-linux')
    elf = pathlib.Path('build/x86_64/linux-probe.elf').read_bytes()
    with tempfile.TemporaryDirectory(prefix='myos-linux-e1000-') as temp:
        serial = boot_x64(pathlib.Path(temp), 'x64-linux-e1000', payload, kernel_end,
                          ['MyOS x86-64: e1000 Ethernet ready', 'Linux x86-64 exit status=0x2a'],
                          live_root_header=linux_root(elf, {}), extra=NETWORK_ARGS)
        assert 'x86-64 exception' not in serial, serial
    print('OVMF Linux x86-64: e1000 initialization before ring 3: PASS', flush=True)


if __name__ == '__main__':
    main()
