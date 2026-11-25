"""Проверка Linux UDP ABI и датаграмм на реальном кольце e1000 в QEMU."""
import pathlib
import socket
import struct
import tempfile
import time

from kernel_x64_dhcp_smoke import ADDRESS, ARP_HEADER, BROADCAST_MAC, LEASE, MAC, NETWORK_ARGS, PEERS, checksum
from kernel_x64_ethernet_smoke import pcap_frames, set_link
from kernel_x64_ipv4_smoke import ipv4_data
from kernel_x64_linux_smoke import linux_root
from kernel_x64_smoke import image
from uefi_x64_smoke import boot_x64


PEER, PEER_MAC = PEERS[0]
CLOSE_PEER, CLOSE_PEER_MAC = PEERS[1]
LOCAL_PORT, PEER_PORT, CLOSE_PORT = 41993, 41994, 41996
REQUESTS = (b'myos-udp:sendto\x91', b'myos-udp:sendmsg\x96')
REPLIES = (b'myos-udp:peek\x94', b'myos-udp:next\x95', b'myos-udp:recvmsg\x97')
CLOSE_PAYLOAD = b'myos-udp:closed\x98'


def send_frames(peer, *frames):
    peer.sendall(b''.join(struct.pack('!I', len(frame)) + frame for frame in frames))


def arp_query(ip=PEER):
    return BROADCAST_MAC + MAC + ARP_HEADER + b'\x01' + MAC + ADDRESS + bytes(6) + ip


def arp_reply(ip=PEER, mac=PEER_MAC):
    frame = MAC + mac + ARP_HEADER + b'\x02' + mac + ip + MAC + ADDRESS
    return frame.ljust(60, b'\0')


def pseudo_header(source, destination, length):
    return source + destination + struct.pack('!BBH', 0, 17, length)


def udp_reply(data, packet_id):
    udp = struct.pack('!HHHH', PEER_PORT, LOCAL_PORT, 8 + len(data), 0) + data
    udp_checksum = checksum(pseudo_header(PEER, ADDRESS, len(udp)) + udp) or 0xffff
    udp = udp[:6] + struct.pack('!H', udp_checksum) + udp[8:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), packet_id, 0, 64, 17, 0, PEER, ADDRESS)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return (MAC + PEER_MAC + b'\x08\x00' + ip + udp).ljust(60, b'\0')


def udp_data(frame, incoming=False, *, peer=PEERS[0], local_port=LOCAL_PORT):
    ip, mac = peer
    source, destination = (ip, ADDRESS) if incoming else (ADDRESS, ip)
    addresses = (MAC + mac) if incoming else (mac + MAC)
    if (len(frame) < 42 or frame[:14] != addresses + b'\x08\x00' or frame[23] != 17 or
            frame[26:34] != source + destination):
        return None
    udp = ipv4_data(frame)
    expected_ports = (PEER_PORT, local_port) if incoming else (local_port, PEER_PORT)
    ports = struct.unpack_from('!HH', udp)
    assert ports == expected_ports, (ports, expected_ports)
    length, value = struct.unpack_from('!HH', udp, 4)
    assert length == len(udp) and (not value or checksum(pseudo_header(source, destination, length) + udp) == 0), udp.hex()
    return udp[8:]


def closed_socket_data(frame):
    return udp_data(frame, peer=PEERS[1], local_port=CLOSE_PORT)


def wait_frame(pcap, predicate, description):
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        if any(predicate(frame) for frame in pcap_frames(pcap)):
            return
        time.sleep(.05)
    raise AssertionError(f'missing {description} on the wire')


def exercise_udp(vm, pcap, injector):
    vm.wait('UDP guest ready')
    assert LEASE not in vm.log.read_text(errors='replace'), 'lease before link up'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(3)
        peer.connect(str(injector))
        set_link(vm, True)
        vm.wait(LEASE, timeout=10)
        wait_frame(pcap, lambda frame: frame.startswith(arp_query()), 'ARP request for UDP peer')
        send_frames(peer, arp_reply())
        wait_frame(pcap, lambda frame: udp_data(frame) == REQUESTS[0], 'sendto datagram')
        send_frames(peer, udp_reply(REPLIES[0], 0x199), udp_reply(REPLIES[1], 0x19a))
        wait_frame(pcap, lambda frame: udp_data(frame) == REQUESTS[1], 'connected sendmsg datagram')
        send_frames(peer, udp_reply(REPLIES[2], 0x19b))
        vm.wait('UDP close queued', timeout=5)
        wait_frame(pcap, lambda frame: frame.startswith(arp_query(CLOSE_PEER)), 'ARP request for closed socket')
        assert all(closed_socket_data(frame) is None for frame in pcap_frames(pcap)), 'UDP sent before ARP resolution'
        send_frames(peer, arp_reply(CLOSE_PEER, CLOSE_PEER_MAC))
        wait_frame(pcap, lambda frame: closed_socket_data(frame) == CLOSE_PAYLOAD, 'UDP datagram after close')


def check_capture(pcap):
    events = []
    close_request = ('queued ARP', 'request')
    for frame in pcap_frames(pcap):
        if frame.startswith(arp_query()):
            events.append(('ARP', 'request'))
        elif frame.startswith(arp_reply()[:42]):
            events.append(('ARP', 'reply'))
        elif frame.startswith(arp_query(CLOSE_PEER)):
            if events[-1:] != [close_request]:
                events.append(close_request)
        elif frame.startswith(arp_reply(CLOSE_PEER, CLOSE_PEER_MAC)[:42]):
            events.append(('queued ARP', 'reply'))
        outgoing = udp_data(frame)
        incoming = udp_data(frame, incoming=True)
        if outgoing is not None:
            events.append(('TX', outgoing))
        if incoming is not None:
            events.append(('RX', incoming))
        queued = closed_socket_data(frame)
        if queued is not None:
            events.append(('TX after close', queued))
        if len(frame) >= 34 and frame[6:14] == MAC + b'\x08\x00':
            loopback = bytes((127, 0, 0, 1))
            assert loopback not in (frame[26:30], frame[30:34]), 'loopback packet reached Ethernet'

    while events and events[0] == ('ARP', 'request'):
        events.pop(0)
    assert events == [('ARP', 'reply'), ('TX', REQUESTS[0]), ('RX', REPLIES[0]), ('RX', REPLIES[1]),
                      ('TX', REQUESTS[1]), ('RX', REPLIES[2]), close_request, ('queued ARP', 'reply'),
                      ('TX after close', CLOSE_PAYLOAD)], events


def main():
    payload, kernel_end = image('kernel-linux')
    elf = pathlib.Path('build/x86_64/linux-udp-probe.elf').read_bytes()
    with tempfile.TemporaryDirectory(prefix='myos-udp-x64-') as temp:
        directory = pathlib.Path(temp)
        pcap, injector = directory / 'udp.pcap', directory / 'inject'
        serial = boot_x64(directory, 'x64-kernel-udp', payload, kernel_end,
                          ['UDP guest PASS', 'Linux x86-64 exit status=0x00'],
                          live_root_header=linux_root(elf, {}), before_boot=lambda vm: set_link(vm, False),
                          interact=lambda vm: exercise_udp(vm, pcap, injector), extra=[
                              '-netdev', 'user,id=wire,ipv6=off,net=10.44.0.0/24,host=10.44.0.5,'
                                         'dhcpstart=10.44.0.20,dns=10.44.0.53',
                              *NETWORK_ARGS[2:],
                              '-chardev', f'socket,id=udp-peer,path={injector},server=on,wait=off',
                              '-object', 'filter-redirector,id=udp-inject,netdev=wire,queue=tx,indev=udp-peer',
                              '-object', f'filter-dump,id=udp-wire,netdev=wire,file={pcap}',
                          ])
        assert 'x86-64 exception' not in serial, serial
        check_capture(pcap)
    print('OVMF Linux x86-64: UDP over e1000, epoll, loopback and queued send after close: PASS', flush=True)


if __name__ == '__main__':
    main()
