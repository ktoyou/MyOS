"""Run the same static Linux ELF64 on the host and in the MyOS guest."""
import pathlib
import struct
import subprocess
import tempfile

from kernel_x64_smoke import image
from uefi_x64_smoke import boot_x64


def check_guest(name, elf, marker, *, fault=False):
    payload, kernel_end = image('kernel-linux')
    root_header = b'MYOSLX64' + struct.pack('<Q', len(elf)) + elf
    with tempfile.TemporaryDirectory(prefix='myos-linux-x64-') as temp:
        serial = boot_x64(pathlib.Path(temp), 'x64-linux-' + name, payload,
                          kernel_end, [marker], live_root_header=root_header)
    if not fault:
        assert 'x86-64 exception' not in serial, serial
    return serial


def main():
    build = pathlib.Path('build/x86_64')
    probe = build / 'linux-probe.elf'
    host = subprocess.run([str(probe.resolve())], env={}, capture_output=True, timeout=5)
    assert (host.returncode, host.stdout, host.stderr) == (42, b'OK', b' Linux ELF64 syscall probe\n'), host
    elf = probe.read_bytes()
    serial = check_guest('probe', elf, 'Linux x86-64 exit status=0x2a')
    assert 'OK Linux ELF64 syscall probe' in serial and 'Linux x86-64 ELF rejected' not in serial, serial
    print('OVMF: same Linux ELF64, same output and exit status: PASS', flush=True)

    phoff = struct.unpack_from('<Q', elf, 32)[0]
    phentsize, phnum = struct.unpack_from('<HH', elf, 54)
    executable = next(phoff + i * phentsize for i in range(phnum)
                      if struct.unpack_from('<II', elf, phoff + i * phentsize) == (1, 5))
    for name, offset, value in (('wx', executable + 4, struct.pack('<I', 7)),
                                ('entry', 24, struct.pack('<Q', 0x100000)),
                                ('phoff', 32, struct.pack('<Q', len(elf)))):
        broken = bytearray(elf)
        broken[offset:offset + len(value)] = value
        check_guest(name, broken, 'Linux x86-64 ELF rejected')
    check_guest('bad-stack', (build / 'linux-bad-stack.elf').read_bytes(),
                'Linux x86-64 invalid syscall return')
    symbols = subprocess.check_output(['nm', str(probe)], text=True)
    entry = next(int(line.split()[0], 16) for line in symbols.splitlines()
                 if line.endswith(' guard_probe'))
    guard = bytearray(elf)
    struct.pack_into('<Q', guard, 24, entry)
    serial = check_guest('guard', guard, 'x86-64 exception halted', fault=True)
    assert ('vector=0x000000000000000e error=0x0000000000000004' in serial and
            'cr2=0x00007fffffefb000 cpl=3' in serial), serial
    print('OVMF: malformed ELF, noncanonical stack and stack guard: PASS', flush=True)


if __name__ == '__main__':
    main()
