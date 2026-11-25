"""Проверка получения DHCP-аренды и ответа ARP под обычным ядром x86-64."""
import pathlib
import socket
import struct
import tempfile
import time

from kernel_x64_ethernet_smoke import ARP_HEADER, MAC, NETWORK_ARGS, pcap_frames, set_link
from kernel_x64_ipv4_smoke import ipv4_data
from kernel_x64_linux_smoke import linux_root
from kernel_x64_smoke import image
from uefi_x64_smoke import boot_x64


ADDRESS = bytes((10, 44, 0, 20))
GATEWAY = bytes((10, 44, 0, 5))
DNS = bytes((10, 44, 0, 53))
MASK = bytes((255, 255, 255, 0))
PEERS = ((bytes((10, 44, 0, 81)), bytes.fromhex('52 54 00 91 97 a1')),
         (bytes((10, 44, 0, 82)), bytes.fromhex('52 54 00 91 97 a2')))
BROADCAST = b'\xff' * 4
BROADCAST_MAC = b'\xff' * 6
ECHO_FIELDS = bytes.fromhex('df 97 00 01 44 48 43 50 20 19 97')
LEASE = 'MyOS x86-64: DHCP address=10.44.0.20 mask=255.255.255.0 gateway=10.44.0.5 dns=10.44.0.53'
LEASE_LOST = 'MyOS x86-64: DHCP lease lost'


def dhcp_options(data):
    assert data[:4] == bytes.fromhex('63 82 53 63'), data.hex()
    options = {}
    offset = 4
    while offset < len(data):
        number = data[offset]
        offset += 1
        if number == 0:
            continue
        if number == 255:
            return options
        assert offset < len(data), ('missing DHCP option length', number)
        end = offset + 1 + data[offset]
        assert end <= len(data), ('truncated DHCP option', number)
        options[number] = options.get(number, b'') + data[offset + 1:end]
        offset = end
    raise AssertionError('missing DHCP end option')


def dhcp_messages(frames):
    for frame in frames:
        if len(frame) < 42 or frame[12:14] != b'\x08\x00' or frame[23] != 17:
            continue
        header_size = (frame[14] & 15) * 4
        ports = frame[14 + header_size:18 + header_size]
        if ports not in (b'\x00\x44\x00\x43', b'\x00\x43\x00\x44'):
            continue
        udp = ipv4_data(frame)
        length, = struct.unpack_from('!H', udp, 4)
        assert length == len(udp), ('invalid DHCP UDP length', length, len(udp))
        bootp = udp[8:]
        if bootp[28:34] != MAC:
            continue
        assert len(bootp) > 240 and bootp[1:3] == b'\x01\x06', bootp.hex()
        assert bootp[12:16] == bytes(4), ('unexpected BOOTP ciaddr', bootp.hex())
        opts = dhcp_options(bootp[236:])
        kind = opts.get(53, b'')
        assert kind in (b'\x01', b'\x02', b'\x03', b'\x05'), opts
        if kind in (b'\x01', b'\x03'):
            assert ports == b'\x00\x44\x00\x43' and bootp[0] == 1, (ports, bootp[0])
            assert frame[:6] == BROADCAST_MAC and frame[6:12] == MAC, frame.hex()
            assert frame[26:30] == bytes(4) and frame[30:34] == BROADCAST, frame.hex()
            assert bootp[16:20] == bytes(4), bootp.hex()
            if kind == b'\x03':
                assert opts.get(50) == ADDRESS and opts.get(54) == GATEWAY, opts
        else:
            assert ports == b'\x00\x43\x00\x44' and bootp[0] == 2, (ports, bootp[0])
            assert frame[:6] in (MAC, BROADCAST_MAC) and frame[6:12] != MAC and not frame[6] & 1, frame.hex()
            assert frame[26:30] == GATEWAY and frame[30:34] in (ADDRESS, BROADCAST), frame.hex()
            assert bootp[16:20] == ADDRESS and opts.get(54) == GATEWAY, opts
            assert opts.get(1) == MASK and opts.get(3) == GATEWAY and opts.get(6) == DNS, opts
            lease = opts.get(51, b'')
            assert len(lease) == 4 and int.from_bytes(lease, 'big') > 0, opts
        yield kind[0], bootp[4:8]


def check_transaction(frames):
    messages = list(dhcp_messages(frames))
    assert messages and len({xid for _, xid in messages}) == 1, messages
    # Повтор DHCP-пакета допустим, но обмен одним XID должен завершить все стадии.
    stages = iter(kind for kind, _ in messages)
    assert all(stage in stages for stage in (1, 2, 3, 5)), messages
    return messages[0][1]


def arp_probe(ip, mac):
    return (BROADCAST_MAC + mac + ARP_HEADER + b'\x01' + mac + ip + bytes(6) + ADDRESS).ljust(60, b'\0')


def arp_response(ip, mac):
    return mac + MAC + ARP_HEADER + b'\x02' + MAC + ADDRESS + mac + ip


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return total ^ 0xffff


def echo_probe():
    echo = b'\x08\x00\x00\x00' + ECHO_FIELDS
    echo = echo[:2] + struct.pack('!H', checksum(echo)) + echo[4:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(echo), 0x197, 0, 64, 1, 0, GATEWAY, ADDRESS)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return MAC + PEERS[0][1] + b'\x08\x00' + ip + echo


def is_echo_reply(frame):
    if (len(frame) < 42 or frame[6:14] != MAC + b'\x08\x00' or frame[23] != 1 or
            frame[26:34] != ADDRESS + GATEWAY):
        return False
    echo = ipv4_data(frame)
    return echo[:2] == b'\x00\x00' and echo[4:] == ECHO_FIELDS and checksum(echo) == 0


def check_echo_route(frames):
    request = echo_probe()
    arp = BROADCAST_MAC + MAC + ARP_HEADER + b'\x01' + MAC + ADDRESS + bytes(6) + GATEWAY
    started = asked = False
    gateway_mac = None
    for frame in frames:
        if frame.startswith(request):
            started = True
        elif started and frame.startswith(arp):
            asked = True
        elif asked and frame[:42] == (MAC + frame[6:12] + ARP_HEADER + b'\x02' + frame[6:12] +
                                      GATEWAY + MAC + ADDRESS):
            gateway_mac = frame[6:12]
        elif gateway_mac and is_echo_reply(frame):
            assert frame[:6] == gateway_mac and gateway_mac != PEERS[0][1], frame.hex()
            return
    raise AssertionError('missing ordered ICMP echo and gateway ARP exchange')


def check_capture(path):
    frames = list(pcap_frames(path))
    headers = [frame[:42] for frame in frames]
    transactions = []
    start = 0
    for round_number, (ip, mac) in enumerate(PEERS):
        request = headers.index(arp_probe(ip, mac)[:42], start)
        reply = headers.index(arp_response(ip, mac), request + 1)
        if round_number == 1:
            check_echo_route(frames[start:request])
        transactions.append(check_transaction(frames[start:request]))
        start = reply + 1
    assert len(set(transactions)) == len(PEERS), ('DHCP XID reused after link reset', transactions)


def probe_bound_address(peer, pcap, ip, mac, test_end):
    # DHCP уже занёс клиента в ARP-кэш slirp. Отдельный сосед проверяет ответ на новый запрос.
    frame = arp_probe(ip, mac)
    peer.sendall(struct.pack('!I', len(frame)) + frame)
    expected = arp_response(ip, mac)
    deadline = min(test_end, time.monotonic() + 4)
    while time.monotonic() < deadline:
        if any(packet[:42] == expected for packet in pcap_frames(pcap)):
            return
        time.sleep(.05)
    raise AssertionError(f'missing ARP reply for peer {socket.inet_ntoa(ip)}')


def probe_echo(peer, pcap, test_end):
    frame = echo_probe().ljust(60, b'\0')
    # Первый и единственный Echo должен дождаться разрешения шлюза через ARP.
    peer.sendall(struct.pack('!I', len(frame)) + frame)
    deadline = min(test_end, time.monotonic() + 4)
    while time.monotonic() < deadline:
        if any(is_echo_reply(packet) for packet in pcap_frames(pcap)):
            return
        time.sleep(.05)
    raise AssertionError('missing ICMP echo reply from the leased address')


def exercise_link(vm, pcap, injector):
    vm.wait('DHCP guest ready')
    assert LEASE not in vm.log.read_text(errors='replace'), 'lease before link up'
    test_end = time.monotonic() + 23
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(3)
        peer.connect(str(injector))
        set_link(vm, True)
        first_lease = vm.wait(LEASE, timeout=10)
        probe_bound_address(peer, pcap, *PEERS[0], test_end)
        probe_echo(peer, pcap, test_end)
        set_link(vm, False)
        lease_lost = vm.wait(LEASE_LOST, after=first_lease, timeout=min(5, test_end - time.monotonic()))
        set_link(vm, True)
        vm.wait(LEASE, after=lease_lost, timeout=min(10, test_end - time.monotonic()))
        probe_bound_address(peer, pcap, *PEERS[1], test_end)


def main():
    payload, kernel_end = image('kernel-linux')
    elf = pathlib.Path('build/x86_64/linux-dhcp-probe.elf').read_bytes()
    with tempfile.TemporaryDirectory(prefix='myos-dhcp-x64-') as temp:
        directory = pathlib.Path(temp)
        pcap, injector = directory / 'dhcp.pcap', directory / 'inject'
        serial = boot_x64(directory, 'x64-kernel-dhcp', payload, kernel_end,
                          [LEASE], live_root_header=linux_root(elf, {}),
                          before_boot=lambda vm: set_link(vm, False),
                          interact=lambda vm: exercise_link(vm, pcap, injector), extra=[
                              '-netdev', 'user,id=wire,ipv6=off,net=10.44.0.0/24,host=10.44.0.5,'
                                         'dhcpstart=10.44.0.20,dns=10.44.0.53',
                              *NETWORK_ARGS[2:],
                              '-chardev', f'socket,id=arp-peer,path={injector},server=on,wait=off',
                              '-object', 'filter-redirector,id=arp-inject,netdev=wire,queue=tx,indev=arp-peer',
                              '-object', f'filter-dump,id=dhcp-wire,netdev=wire,file={pcap}',
                          ])
        assert 'x86-64 exception' not in serial, serial
        assert serial.count(LEASE) == 2 and serial.count(LEASE_LOST) == 1, serial
        check_capture(pcap)
    print('OVMF Linux x86-64: DHCP DORA, ARP, ICMP echo and link recovery: PASS', flush=True)


if __name__ == '__main__':
    main()
