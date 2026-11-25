"""Проверка DHCP-конфигурации и glibc getaddrinfo через e1000 в QEMU."""
import pathlib
import socket
import struct
import sys
import tempfile
import time
from contextlib import ExitStack

from kernel_x64_dhcp_smoke import ADDRESS, DNS, LEASE, LEASE_LOST, MAC, NETWORK_ARGS, checksum, dhcp_options
from kernel_x64_ethernet_smoke import pcap_frames, set_link
from kernel_x64_ipv4_smoke import ipv4_data
from kernel_x64_linux_smoke import linux_root
from kernel_x64_smoke import image
from kernel_x64_tcp_smoke import read_exact
from kernel_x64_udp_smoke import pseudo_header, send_frames
from kernel_x64_wayland_smoke import dependencies
from uefi_x64_smoke import boot_x64


ANSWER = bytes((10, 44, 0, 100))
NETDEV = 'user,id=wire,ipv6=off,net=10.44.0.0/24,host=10.44.0.5,dhcpstart=10.44.0.20,dns=10.44.0.53'
OVERRIDE = b'nameserver 10.44.0.54\n'
NEW_DNS = bytes((10, 44, 0, 54))
NEW_LEASE = LEASE.replace('dns=10.44.0.53', 'dns=10.44.0.54')


def dns_name(name):
    return b''.join(bytes((len(label),)) + label.encode('ascii')
                    for label in name.rstrip('.').split('.')) + b'\0'


def dns_query(frame):
    if len(frame) < 42 or frame[6:14] != MAC + b'\x08\x00' or frame[23] != 17:
        return None
    udp = ipv4_data(frame)
    source, dest, length, value = struct.unpack_from('!HHHH', udp)
    if dest != 53:
        return None
    assert frame[26:34] == ADDRESS + DNS, ('DNS sent to the wrong address', frame[26:34].hex())
    assert length == len(udp), udp.hex()
    assert not value or checksum(pseudo_header(ADDRESS, DNS, length) + udp) == 0, udp.hex()
    return frame[:6], source, udp[8:]


def dns_question(request):
    assert len(request) > 16 and not request[2] & 0x80, request.hex()
    assert struct.unpack_from('!H', request, 4)[0] == 1, request.hex()
    end = 12
    while end < len(request) and request[end]:
        assert request[end] <= 63, request.hex()
        end += 1 + request[end]
    end += 1
    assert end + 4 <= len(request), request.hex()
    kind, question_class = struct.unpack_from('!HH', request, end)
    assert question_class == 1, request.hex()
    return request[12:end], kind, request[12:end + 4]


def dns_reply(query, address=ANSWER):
    remote_mac, source_port, request = query
    _, kind, question = dns_question(request)
    answers = b''
    if kind == 1:
        answers = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 30, len(address)) + address
    flags = 0x8080 | (struct.unpack_from('!H', request, 2)[0] & 0x0100)
    dns = request[:2] + struct.pack('!HHHHH', flags, 1, int(bool(answers)), 0, 0) + question + answers
    udp = struct.pack('!HHHH', 53, source_port, 8 + len(dns), 0) + dns
    value = checksum(pseudo_header(DNS, ADDRESS, len(udp)) + udp) or 0xffff
    udp = udp[:6] + struct.pack('!H', value) + udp[8:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0x203, 0, 64, 17, 0, DNS, ADDRESS)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return (MAC + remote_mac + b'\x08\x00' + ip + udp).ljust(60, b'\0')


def network_args(egress, forward, injector, pcap):
    return [
        '-netdev', NETDEV, *NETWORK_ARGS[2:],
        '-chardev', f'socket,id=dns-egress,path={egress},server=on,wait=off',
        '-chardev', f'socket,id=dns-forward,path={forward},server=on,wait=off',
        '-chardev', f'socket,id=dns-inject,path={injector},server=on,wait=off',
        '-object', 'filter-redirector,id=dns-tx,netdev=wire,queue=tx,indev=dns-inject',
        '-object', 'filter-redirector,id=dns-rx,netdev=wire,queue=rx,indev=dns-forward,outdev=dns-egress',
        '-object', f'filter-dump,id=dns-wire,netdev=wire,file={pcap}',
    ]


def connect(stack, path):
    peer = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
    peer.settimeout(4)
    peer.connect(str(path))
    return peer


def receive_frame(egress, deadline):
    remaining = deadline - time.monotonic()
    assert remaining > 0, 'waiting for guest Ethernet frame'
    egress.settimeout(remaining)
    size, = struct.unpack('!I', read_exact(egress, 4))
    assert 14 <= size <= 1518, size
    return read_exact(egress, size)


def serve_dns(egress, forward, injector):
    deadline = time.monotonic() + 12
    expected = {1, 28}
    replies = set()
    # slirp завершает DHCP/ARP. DNS остаётся внутри теста и не доходит до резолвера хоста.
    while expected:
        frame = receive_frame(egress, deadline)
        query = dns_query(frame)
        if query is None:
            send_frames(forward, frame)
            continue
        name, kind, _ = dns_question(query[2])
        assert name == dns_name('myos-dns.test') and kind in (1, 28), (name, kind)
        response = dns_reply(query)
        send_frames(injector, response)
        replies.add(response)
        expected.discard(kind)
    return replies


def dhcp_packet(frame, ports):
    if len(frame) < 42 or frame[12:14] != b'\x08\x00' or frame[23] != 17:
        return None
    offset = 14 + (frame[14] & 15) * 4
    if struct.unpack_from('!HH', frame, offset) != ports:
        return None
    packet = ipv4_data(frame)[8:]
    if packet[28:34] != MAC:
        return None
    return offset, packet, dhcp_options(packet[236:])


def replace_lease_reply(frame, offset, packet, xid):
    marker = b'\x06\x04' + DNS
    position = packet.index(marker, 240) + 2
    packet = packet[:4] + xid + packet[8:position] + NEW_DNS + packet[position + len(NEW_DNS):]
    udp = frame[offset:offset + 6] + b'\0\0' + packet
    value = checksum(pseudo_header(frame[26:30], frame[30:34], len(udp)) + udp) or 0xffff
    return frame[:offset + 6] + struct.pack('!H', value) + packet


def lease_templates(pcap):
    templates = {}
    for frame in pcap_frames(pcap):
        if offer := dhcp_packet(frame, (67, 68)):
            offset, packet, options = offer
            assert options[6] == DNS, options
            templates[options[53]] = frame, offset, packet
    assert {b'\x02', b'\x05'} <= templates.keys(), 'missing slirp OFFER/ACK template'
    return templates


def serve_changed_lease(egress, forward, injector, templates):
    deadline = time.monotonic() + 10
    while True:
        frame = receive_frame(egress, deadline)
        request = dhcp_packet(frame, (68, 67))
        if request is None:
            send_frames(forward, frame)
            continue
        _, packet, options = request
        kind = options[53]
        assert kind in (b'\x01', b'\x03'), options
        reply = templates[b'\x02' if kind == b'\x01' else b'\x05']
        send_frames(injector, replace_lease_reply(*reply, packet[4:8]))
        if kind == b'\x03':
            return


def main():
    binary = pathlib.Path(sys.argv[1])
    elf = binary.read_bytes()
    files = dependencies(binary)
    payload, kernel_end = image('kernel-linux')
    with tempfile.TemporaryDirectory(prefix='myos-dns-x64-') as temp:
        directory = pathlib.Path(temp)
        egress, forward, injector, pcap = (directory / name for name in ('egress', 'forward', 'inject', 'dns.pcap'))
        replies = set()

        def resolve(vm):
            vm.wait('DNS guest ready')
            assert LEASE not in vm.log.read_text(errors='replace'), 'lease before link up'
            with ExitStack() as stack:
                peers = [connect(stack, path) for path in (egress, forward, injector)]
                set_link(vm, True)
                replies.update(serve_dns(*peers))
                vm.wait(LEASE, timeout=5)
                resolved = vm.wait('DNS guest resolved', timeout=5)
                set_link(vm, False)
                vm.wait(LEASE_LOST, after=resolved, timeout=5)
                vm.wait('DNS guest lease absent', timeout=5)
                templates = lease_templates(pcap)
                set_link(vm, True)
                serve_changed_lease(*peers, templates)
                vm.wait(NEW_LEASE, timeout=5)

        serial = boot_x64(directory, 'x64-kernel-dns', payload, kernel_end,
                          ['DNS guest PASS', 'Linux x86-64 exit status=0x00'],
                          live_root_header=linux_root(elf, files), before_boot=lambda vm: set_link(vm, False),
                          interact=resolve, extra=network_args(egress, forward, injector, pcap))
        assert 'x86-64 exception' not in serial, serial
        frames = list(pcap_frames(pcap))
        assert {dns_question(query[2])[1] for frame in frames if (query := dns_query(frame))} == {1, 28}
        assert replies <= set(frames), 'missing injected DNS responses in PCAP'

        def lease_for_override(vm):
            vm.wait('DNS override ready')
            set_link(vm, True)
            vm.wait(LEASE, timeout=10)

        serial = boot_x64(directory, 'x64-kernel-dns-override', payload, kernel_end,
                          ['DNS override PASS', 'Linux x86-64 exit status=0x00'],
                          live_root_header=linux_root(elf, files | {'/etc/resolv.conf': OVERRIDE}),
                          before_boot=lambda vm: set_link(vm, False), interact=lease_for_override,
                          extra=['-netdev', NETDEV, *NETWORK_ARGS[2:]])
        assert 'x86-64 exception' not in serial, serial
    print('OVMF Linux x86-64: DHCP resolver, glibc UDP DNS, lease loss and Live override: PASS', flush=True)


if __name__ == '__main__':
    main()
