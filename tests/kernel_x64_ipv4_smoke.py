"""Проверка IPv4, выбора следующего узла и ICMP через изолированный QEMU slirp."""
import pathlib
import struct
import tempfile

from kernel_x64_ethernet_smoke import ARP_HEADER, GATEWAY, MAC, NETWORK, NETWORK_ARGS, pcap_frames, set_link
from kernel_x64_smoke import image
from uefi_x64_smoke import boot_x64


ADDRESS = NETWORK + b'\x0f'
ON_LINK = NETWORK + b'\x03'
OFF_LINK = bytes((192, 0, 2, 7))
NO_ROUTE = bytes((192, 0, 2, 8))
ROUTE_PAYLOAD = bytes.fromhex('4d 79 4f 53 93 a7')
ECHO_FIELDS = bytes.fromhex('39 17 a2 65 f2 44 12 84 bb de 51')


def bring_link_up(vm):
    vm.wait('IPv4 test: waiting for link')
    set_link(vm, True)


def checksum_valid(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return total == 0xffff


def ipv4_data(frame):
    packet = frame[14:]
    header_size = (packet[0] & 15) * 4
    total_size, = struct.unpack_from('!H', packet, 2)
    fragment, = struct.unpack_from('!H', packet, 6)
    assert packet[0] >> 4 == 4 and 20 <= header_size <= total_size <= len(packet), packet.hex()
    assert not fragment & 0x3fff and checksum_valid(packet[:header_size]), packet.hex()
    return packet[header_size:total_size]


def check_capture(path):
    neighbors = {}
    events = []
    for frame in pcap_frames(path):
        if len(frame) >= 42 and frame[12:21] == ARP_HEADER:
            if frame[6:12] == MAC and frame[21] == 1 and frame[28:32] == ADDRESS:
                target = frame[38:42]
                assert target in (GATEWAY, ON_LINK), ('unexpected ARP target', target)
                assert frame[:6] == b'\xff' * 6 and frame[22:28] == MAC and frame[32:38] == bytes(6), frame.hex()
                events.append(('arp request', target))
            elif frame[:6] == MAC and frame[21] == 2 and frame[38:42] == ADDRESS:
                sender = frame[28:32]
                assert sender in (GATEWAY, ON_LINK) and frame[32:38] == MAC, frame.hex()
                assert frame[6:12] == frame[22:28] and frame[6:12] != MAC and not frame[6] & 1, frame.hex()
                neighbors[sender] = frame[6:12]
                events.append(('arp reply', sender))
        if len(frame) < 34 or frame[12:14] != b'\x08\x00':
            continue
        source, dest, protocol = frame[26:30], frame[30:34], frame[23]
        assert frame[6:12] != MAC or dest != NO_ROUTE, ('packet escaped without a gateway', frame.hex())
        if frame[6:12] == MAC and source == ADDRESS:
            if protocol == 253 and dest in (OFF_LINK, ON_LINK):
                hop = GATEWAY if dest == OFF_LINK else ON_LINK
                assert frame[:6] == neighbors.get(hop) and ipv4_data(frame) == ROUTE_PAYLOAD, frame.hex()
                events.append(('ipv4 transmit', dest))
            elif protocol == 1 and dest == GATEWAY:
                echo = ipv4_data(frame)
                assert frame[:6] == neighbors.get(GATEWAY), frame.hex()
                assert echo[:2] == b'\x08\x00' and echo[4:] == ECHO_FIELDS and checksum_valid(echo), echo.hex()
                events.append(('echo request', dest))
        elif frame[:6] == MAC and source == GATEWAY and dest == ADDRESS and protocol == 1:
            echo = ipv4_data(frame)
            if echo[:1] != b'\x00':
                continue
            assert frame[6:12] == neighbors.get(GATEWAY), frame.hex()
            assert echo[:2] == b'\x00\x00' and echo[4:] == ECHO_FIELDS and checksum_valid(echo), echo.hex()
            events.append(('echo reply', source))

    assert events == [
        ('arp request', GATEWAY), ('arp reply', GATEWAY), ('ipv4 transmit', OFF_LINK),
        ('echo request', GATEWAY), ('echo reply', GATEWAY),
        ('arp request', ON_LINK), ('arp reply', ON_LINK), ('ipv4 transmit', ON_LINK),
    ], events


def main():
    payload, kernel_end = image('kernel-ipv4')
    with tempfile.TemporaryDirectory(prefix='myos-ipv4-x64-') as temp:
        directory = pathlib.Path(temp)
        pcap = directory / 'ipv4.pcap'
        serial = boot_x64(directory, 'x64-kernel-ipv4', payload, kernel_end,
                          ['x86-64 IPv4 PASS'], before_boot=lambda vm: set_link(vm, False),
                          interact=bring_link_up, extra=[
                              *NETWORK_ARGS,
                              '-object', f'filter-dump,id=ipv4-dump,netdev=wire,file={pcap}',
                          ])
        assert 'x86-64 IPv4 FAIL' not in serial and 'x86-64 exception' not in serial, serial
        check_capture(pcap)
    print('OVMF x86-64 IPv4: next-hop routing, gateway ICMP echo and missing default route: PASS', flush=True)


if __name__ == '__main__':
    main()
