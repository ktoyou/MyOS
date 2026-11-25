"""Проверка TCP Linux ABI через e1000, slirp и TCP-сервер на хосте."""
import pathlib
import select
import socket
import struct
import sys
import tempfile
from typing import NamedTuple

from kernel_x64_dhcp_smoke import ADDRESS, LEASE, MAC, NETWORK_ARGS, PEERS, checksum
from kernel_x64_ethernet_smoke import pcap_frames, set_link
from kernel_x64_ipv4_smoke import ipv4_data
from kernel_x64_linux_smoke import linux_root
from kernel_x64_smoke import image
from uefi_x64_smoke import boot_x64


SERVER = PEERS[0][0]
CLIENT_PORT, SERVER_PORT = 41997, 41998
REQUEST = bytes((i * 17 + 0x39) & 255 for i in range(5003))
RESPONSE = bytes((i * 29 + 0x71) & 255 for i in range(7001))
TRAILER = b'myos-tcp:after-peer-fin\xa1'
FIN, SYN, ACK = 1, 2, 16
SEQ_MASK = 0xffffffff


class Segment(NamedTuple):
    outgoing: bool
    sequence: int
    acknowledgement: int
    flags: int
    data: bytes


def relay(port):
    # guestfwd cmd передаёт двунаправленный сокет. FIN закрывает только направление записи.
    with socket.socket(fileno=0) as guest, socket.create_connection(('127.0.0.1', port), timeout=8) as host:
        guest.settimeout(8)
        receivers = {guest: host, host: guest}
        while receivers:
            readable, _, _ = select.select(list(receivers), [], [], 8)
            if not readable:
                raise TimeoutError('guestfwd TCP relay idle')
            for source in readable:
                data = source.recv(16384)
                if data:
                    receivers[source].sendall(data)
                else:
                    receivers.pop(source).shutdown(socket.SHUT_WR)


def read_exact(stream, length):
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise AssertionError(f'TCP EOF after {len(data)} of {length} bytes')
        data.extend(chunk)
    return bytes(data)


def exercise_tcp(vm, listener):
    vm.wait('TCP guest ready')
    assert LEASE not in vm.log.read_text(errors='replace'), 'lease before link up'
    set_link(vm, True)
    vm.wait(LEASE, timeout=10)
    stream, remote = listener.accept()
    assert remote[0] == '127.0.0.1', remote
    with stream:
        stream.settimeout(8)
        vm.wait('TCP guest connected', timeout=6)
        assert read_exact(stream, len(REQUEST)) == REQUEST, 'wrong request stream'
        stream.sendall(RESPONSE)
        stream.shutdown(socket.SHUT_WR)
        assert read_exact(stream, len(TRAILER)) == TRAILER, 'wrong stream after remote FIN'
        assert stream.recv(1) == b'', 'host did not observe EOF'


def tcp_segments(pcap):
    for frame in pcap_frames(pcap):
        if len(frame) < 54 or frame[12:14] != b'\x08\x00' or frame[23] != 6:
            continue
        source, dest = frame[26:30], frame[30:34]
        if (source, dest) == (ADDRESS, SERVER):
            assert frame[6:12] == MAC, frame.hex()
            outgoing, ports = True, (CLIENT_PORT, SERVER_PORT)
        elif (source, dest) == (SERVER, ADDRESS):
            assert frame[:6] == MAC, frame.hex()
            outgoing, ports = False, (SERVER_PORT, CLIENT_PORT)
        else:
            continue
        tcp = ipv4_data(frame)
        assert len(tcp) >= 20, tcp.hex()
        assert struct.unpack_from('!HH', tcp) == ports, tcp.hex()
        sequence, acknowledgement = struct.unpack_from('!II', tcp, 4)
        header_size = (tcp[12] >> 4) * 4
        assert 20 <= header_size <= len(tcp), tcp.hex()
        assert checksum(source + dest + struct.pack('!BBH', 0, 6, len(tcp)) + tcp) == 0, tcp.hex()
        yield Segment(outgoing, sequence, acknowledgement, tcp[13], tcp[header_size:])


def assert_stream(segments, start, expected):
    covered = bytearray(len(expected))
    for segment in segments:
        if segment.data:
            offset = (segment.sequence - start) & SEQ_MASK
            end = offset + len(segment.data)
            assert len(segment.data) <= 1460 and end <= len(expected), (offset, len(segment.data))
            assert segment.data == expected[offset:end], (offset, segment.data.hex())
            covered[offset:end] = b'\x01' * len(segment.data)
    assert all(covered), ('bytes absent from PCAP', covered.count(0))


def fin_offset(segment, start):
    return (segment.sequence + len(segment.data) - start) & SEQ_MASK


def check_capture(pcap):
    segments = list(tcp_segments(pcap))
    syn_index = next(i for i, packet in enumerate(segments)
                     if packet.outgoing and packet.flags & (SYN | ACK) == SYN)
    guest_start = (segments[syn_index].sequence + 1) & SEQ_MASK
    syn_ack_index = next(i for i, packet in enumerate(segments[syn_index + 1:], syn_index + 1)
                         if not packet.outgoing and packet.flags & (SYN | ACK) == (SYN | ACK))
    syn_ack = segments[syn_ack_index]
    host_start = (syn_ack.sequence + 1) & SEQ_MASK
    assert syn_ack.acknowledgement == guest_start, syn_ack
    established = segments[syn_ack_index + 1:]
    assert any(packet.outgoing and packet.flags & ACK and packet.sequence == guest_start and
               packet.acknowledgement == host_start for packet in established), 'missing handshake ACK'

    assert_stream((packet for packet in established if packet.outgoing), guest_start, REQUEST + TRAILER)
    assert_stream((packet for packet in established if not packet.outgoing), host_start, RESPONSE)
    remote_fin = next(i for i, packet in enumerate(established)
                      if not packet.outgoing and packet.flags & FIN and fin_offset(packet, host_start) == len(RESPONSE))
    assert_stream((packet for packet in established[remote_fin + 1:] if packet.outgoing and
                   (packet.sequence - guest_start) & SEQ_MASK >= len(REQUEST)),
                  (guest_start + len(REQUEST)) & SEQ_MASK, TRAILER)
    assert any(packet.outgoing and packet.flags & FIN and fin_offset(packet, guest_start) == len(REQUEST + TRAILER)
               for packet in established[remote_fin + 1:]), 'missing local FIN after the reply trailer'


def main():
    payload, kernel_end = image('kernel-linux')
    elf = pathlib.Path('build/x86_64/linux-tcp-probe.elf').read_bytes()
    with tempfile.TemporaryDirectory(prefix='myos-tcp-x64-') as temp, socket.socket() as listener:
        directory = pathlib.Path(temp)
        pcap = directory / 'tcp.pcap'
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(8)
        # Старые версии slirp делят команду guestfwd по пробелам без обработки кавычек.
        command = f'python3 tests/kernel_x64_tcp_smoke.py --relay {listener.getsockname()[1]}'
        forwarded = f'guestfwd=tcp:{socket.inet_ntoa(SERVER)}:{SERVER_PORT}-cmd:{command}'
        serial = boot_x64(directory, 'x64-kernel-tcp', payload, kernel_end,
                          ['TCP guest received EOF', 'TCP guest PASS'],
                          live_root_header=linux_root(elf, {}), before_boot=lambda vm: set_link(vm, False),
                          interact=lambda vm: exercise_tcp(vm, listener), extra=[
                              '-netdev', 'user,id=wire,ipv6=off,net=10.44.0.0/24,host=10.44.0.5,'
                                         'dhcpstart=10.44.0.20,dns=10.44.0.53,' + forwarded,
                              *NETWORK_ARGS[2:],
                              '-object', f'filter-dump,id=tcp-wire,netdev=wire,file={pcap}',
                          ])
        assert 'x86-64 exception' not in serial, serial
        check_capture(pcap)
    print('OVMF Linux x86-64: TCP connect, streaming, epoll and bidirectional FIN: PASS', flush=True)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--relay':
        relay(int(sys.argv[2]))
    else:
        main()
