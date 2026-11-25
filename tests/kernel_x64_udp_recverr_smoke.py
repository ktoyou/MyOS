"""Проверка Linux IP_RECVERR на реальных UDP и ICMP кадрах QEMU e1000."""
import pathlib
import socket
import struct
import tempfile
import time

from kernel_x64_dhcp_smoke import ADDRESS, MAC, NETWORK_ARGS, PEERS, checksum
from kernel_x64_ethernet_smoke import pcap_frames, set_link
from kernel_x64_ipv4_smoke import ipv4_data
from kernel_x64_linux_smoke import linux_root
from kernel_x64_smoke import image
from kernel_x64_udp_smoke import arp_query, arp_reply, pseudo_header, send_frames, wait_frame
from uefi_x64_smoke import boot_x64


PEER, PEER_MAC = PEERS[0]
OFFENDER, OFFENDER_MAC = PEERS[1]
WRONG_OFFENDER = bytes((10, 44, 0, 83))
ENABLED_PORT, DISABLED_PORT, REMOTE_PORT = 42003, 42004, 42005
ENABLED_DATA = b'myos-recverr:enabled\xd1'
DISABLED_DATA = b'myos-recverr:disabled\xd2'
PURGE_DATA = b'myos-recverr:purge\xd3'
PAYLOADS = {ENABLED_DATA: ENABLED_PORT, DISABLED_DATA: DISABLED_PORT, PURGE_DATA: ENABLED_PORT}
LEASE = 'MyOS x86-64: DHCP address=10.44.0.20 mask=255.255.255.0'


def sent_datagrams(pcap):
    for frame in pcap_frames(pcap):
        if (len(frame) < 42 or frame[:14] != PEER_MAC + MAC + b'\x08\x00' or frame[23] != 17 or
                frame[26:34] != ADDRESS + PEER):
            continue
        udp = ipv4_data(frame)
        source, dest, length, value = struct.unpack_from('!HHHH', udp)
        data = udp[8:]
        assert PAYLOADS.get(data) == source and dest == REMOTE_PORT and length == len(udp), udp.hex()
        assert not value or checksum(pseudo_header(ADDRESS, PEER, length) + udp) == 0, udp.hex()
        ip_size, = struct.unpack_from('!H', frame, 16)
        yield data, frame[14:14 + ip_size]


def other_remote_port(quote):
    header_size = (quote[0] & 15) * 4
    udp = quote[header_size:]
    udp = udp[:2] + struct.pack('!H', REMOTE_PORT + 1) + udp[4:6] + b'\x00\x00' + udp[8:]
    value = checksum(pseudo_header(ADDRESS, PEER, len(udp)) + udp) or 0xffff
    return quote[:header_size] + udp[:6] + struct.pack('!H', value) + udp[8:]


def icmp_unreachable(quote, source, identification):
    icmp = b'\x03\x03' + bytes(6) + quote
    icmp = icmp[:2] + struct.pack('!H', checksum(icmp)) + icmp[4:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(icmp), identification, 0, 64, 1, 0, source, ADDRESS)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return MAC + OFFENDER_MAC + b'\x08\x00' + ip + icmp


def wait_datagrams(pcap, *payloads):
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        quotes = dict(sent_datagrams(pcap))
        if quotes.keys() >= set(payloads):
            return quotes
        time.sleep(.05)
    raise AssertionError(f'missing UDP datagrams for ICMP quotation: {payloads!r}')


def exercise(vm, pcap, injector):
    vm.wait('UDP RECVERR guest ready')
    assert LEASE not in vm.log.read_text(errors='replace'), 'lease before link up'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(3)
        peer.connect(str(injector))
        set_link(vm, True)
        vm.wait(LEASE, timeout=10)
        wait_frame(pcap, lambda frame: frame.startswith(arp_query()), 'ARP request for UDP peer')
        send_frames(peer, arp_reply())
        vm.wait('UDP RECVERR probes sent', timeout=6)
        quotes = wait_datagrams(pcap, DISABLED_DATA, ENABLED_DATA)
        # Сначала кадры, которые не должны попасть в очередь включённого сокета.
        send_frames(peer, icmp_unreachable(quotes[DISABLED_DATA], OFFENDER, 0x204),
                    icmp_unreachable(other_remote_port(quotes[ENABLED_DATA]), WRONG_OFFENDER, 0x205),
                    icmp_unreachable(quotes[ENABLED_DATA], OFFENDER, 0x206))
        vm.wait('UDP RECVERR purge probe sent', timeout=6)
        quote = wait_datagrams(pcap, PURGE_DATA)[PURGE_DATA]
        send_frames(peer, icmp_unreachable(quote, OFFENDER, 0x207))


def check_capture(pcap):
    quotes = dict(sent_datagrams(pcap))
    assert quotes.keys() == PAYLOADS.keys(), quotes
    errors = []
    for frame in pcap_frames(pcap):
        if len(frame) < 70 or frame[:14] != MAC + OFFENDER_MAC + b'\x08\x00' or frame[23] != 1:
            continue
        assert frame[30:34] == ADDRESS, frame.hex()
        icmp = ipv4_data(frame)
        assert icmp[:2] == b'\x03\x03' and not checksum(icmp), icmp.hex()
        errors.append((frame[26:30], icmp[8:]))
    assert errors == [(OFFENDER, quotes[DISABLED_DATA]),
                      (WRONG_OFFENDER, other_remote_port(quotes[ENABLED_DATA])),
                      (OFFENDER, quotes[ENABLED_DATA]),
                      (OFFENDER, quotes[PURGE_DATA])], errors


def main():
    payload, kernel_end = image('kernel-linux')
    elf = pathlib.Path('build/x86_64/linux-udp-recverr-probe.elf').read_bytes()
    with tempfile.TemporaryDirectory(prefix='myos-udp-recverr-x64-') as temp:
        directory = pathlib.Path(temp)
        pcap, injector = directory / 'recverr.pcap', directory / 'inject'
        serial = boot_x64(directory, 'x64-kernel-udp-recverr', payload, kernel_end,
                          ['UDP RECVERR guest PASS', 'Linux x86-64 exit status=0x00'],
                          live_root_header=linux_root(elf, {}), before_boot=lambda vm: set_link(vm, False),
                          interact=lambda vm: exercise(vm, pcap, injector), extra=[
                              '-netdev', 'user,id=wire,restrict=on,ipv6=off,net=10.44.0.0/24,host=10.44.0.5,'
                                         'dhcpstart=10.44.0.20',
                              *NETWORK_ARGS[2:],
                              '-chardev', f'socket,id=recverr-peer,path={injector},server=on,wait=off',
                              '-object', 'filter-redirector,id=recverr-inject,netdev=wire,queue=tx,indev=recverr-peer',
                              '-object', f'filter-dump,id=recverr-wire,netdev=wire,file={pcap}',
                          ])
        assert 'x86-64 exception' not in serial, serial
        check_capture(pcap)
    print('OVMF Linux x86-64: UDP IP_RECVERR, ICMP quotation, readiness and socket isolation: PASS', flush=True)


if __name__ == '__main__':
    main()
