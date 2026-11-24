"""Run the same Linux ELF64 files on the host and in the MyOS guest."""
import os
import pathlib
import resource
import signal
import struct
import subprocess
import tempfile

from kernel_x64_smoke import image
from uefi_x64_smoke import boot_x64


def linux_root(elf, files):
    root = bytearray(b'MYOSLX63' + struct.pack('<QQ', len(elf), len(files)))
    root.extend(elf)
    for path, contents in files.items():
        encoded = os.fsencode(path) + b'\0'
        root.extend(struct.pack('<QQ', len(encoded), len(contents)))
        root.extend(encoded)
        root.extend(contents)
    return root


def check_guest(name, elf, marker, *, fault=False, files=None, cpu='max'):
    payload, kernel_end = image('kernel-linux')
    root_header = linux_root(elf, files or {})
    with tempfile.TemporaryDirectory(prefix='myos-linux-x64-') as temp:
        serial = boot_x64(pathlib.Path(temp), 'x64-linux-' + name, payload,
                          kernel_end, [marker], live_root_header=root_header, cpu=cpu)
    if not fault:
        assert 'x86-64 exception' not in serial, serial
    return serial


def program_headers(elf):
    phoff = struct.unpack_from('<Q', elf, 32)[0]
    phentsize, phnum = struct.unpack_from('<HH', elf, 54)
    for i in range(phnum):
        yield phoff + i * phentsize


def check_interpreter(build):
    pie = (build / 'linux-pie.elf').resolve()
    linker = (build / 'linux-interp.elf').resolve()
    elf, interp = pie.read_bytes(), linker.read_bytes()
    path_header = next(p for p in program_headers(elf) if struct.unpack_from('<I', elf, p)[0] == 3)
    path_offset = struct.unpack_from('<Q', elf, path_header + 8)[0]
    path_length = struct.unpack_from('<Q', elf, path_header + 32)[0]
    path_bytes = elf[path_offset:path_offset + path_length]
    assert path_bytes.endswith(b'\0')
    path = os.fsdecode(path_bytes[:-1])
    assert pathlib.Path(path).resolve() == linker

    host = subprocess.run([str(pie)], env={}, capture_output=True, timeout=5)
    marker = b'Linux ELF64 interpreter\n'
    assert (host.returncode, host.stdout, host.stderr) == (
        42, marker + b'OK', b' Linux ELF64 syscall probe\n'), host
    serial = check_guest('interp', elf, 'Linux x86-64 exit status=0x2a',
                         files={path: interp})
    assert 'Linux ELF64 interpreter\nOK Linux ELF64 syscall probe' in serial, serial
    print('OVMF: same PIE and interpreter as Linux: PASS', flush=True)

    rejected = 'Linux x86-64 ELF rejected'
    check_guest('interp-missing', elf, rejected)
    check_guest('interp-wrong-path', elf, rejected, files={'/missing/loader': interp})
    check_guest('interp-nested', elf, rejected, files={path: elf})

    broken = bytearray(elf)
    broken[path_offset + path_length - 1] = ord('x')
    check_guest('interp-unterminated', broken, rejected, files={path: interp})

    # Переносим интерпретатор ET_EXEC туда, где MyOS размещает основной PIE.
    collision = bytearray(interp)
    bias = 0x100000000
    struct.pack_into('<H', collision, 16, 2)
    struct.pack_into('<Q', collision, 24, struct.unpack_from('<Q', interp, 24)[0] + bias)
    for p in program_headers(interp):
        if struct.unpack_from('<I', interp, p)[0] == 1:
            address = struct.unpack_from('<Q', interp, p + 16)[0]
            struct.pack_into('<Q', collision, p + 16, address + bias)
    check_guest('interp-overlap', elf, rejected, files={path: collision})
    print('OVMF: invalid interpreter paths, nesting and overlap: PASS', flush=True)


def check_files(build):
    probe = build / 'linux-files.elf'
    data = (build / 'linux-interp.elf').absolute()
    host = subprocess.run([str(probe.resolve())], env={}, capture_output=True, timeout=5)
    assert (host.returncode, host.stdout, host.stderr) == (0, b'Linux ELF64 files probe\n', b''), host
    serial = check_guest('files', probe.read_bytes(), 'Linux x86-64 exit status=0x00',
                         files={data: data.read_bytes()})
    assert 'Linux ELF64 files probe' in serial, serial
    print('OVMF: Linux ELF64 file reads, metadata and descriptor errors: PASS', flush=True)


def check_mmap(build):
    probe = (build / 'linux-mmap.elf').absolute()
    data = (build / 'linux-mmap-data.bin').absolute()
    # mov eax,42; ret. Маркер во второй странице позволяет проверить смещение.
    data.write_bytes(b'\xb8\x2a\0\0\0\xc3'.ljust(4096, b'\0') + b'\x5a')
    files = {data: data.read_bytes()}
    host = subprocess.run([str(probe)], env={}, capture_output=True, timeout=5)
    marker = 'Linux ELF64 mmap and mprotect probe'
    assert (host.returncode, host.stdout, host.stderr) == (0, (marker + '\n').encode(), b''), host
    elf = probe.read_bytes()
    serial = check_guest('mmap', elf, 'Linux x86-64 exit status=0x00', files=files)
    assert marker in serial, serial
    symbols = {line.split()[-1]: int(line.split()[0], 16)
               for line in subprocess.check_output(['nm', str(probe)], text=True).splitlines()}
    protected = bytearray(elf)
    struct.pack_into('<Q', protected, 24, symbols['mmap_protection'])
    check_guest('mmap-protection', protected, 'Linux x86-64 exit status=0x00', files=files)

    past_eof = bytearray(elf)
    struct.pack_into('<Q', past_eof, 24, symbols['mmap_past_eof'])
    host_past_eof = build / 'linux-mmap-past-eof.elf'
    host_past_eof.write_bytes(past_eof)
    host_past_eof.chmod(0o755)
    host = subprocess.run([str(host_past_eof.resolve())], env={}, timeout=5,
                          preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
    assert host.returncode == -signal.SIGBUS, host
    serial = check_guest('mmap-past-eof', past_eof, 'x86-64 exception halted',
                         fault=True, files=files)
    assert ('vector=0x000000000000000e error=0x0000000000000004' in serial and
            'cr2=0x0000001000002000 cpl=3' in serial), serial

    relro = bytearray(elf)
    struct.pack_into('<Q', relro, 24, symbols['mprotect_relro_fault'])
    serial = check_guest('mprotect-relro', relro, 'x86-64 exception halted', fault=True, files=files)
    assert ('vector=0x000000000000000e error=0x0000000000000007' in serial and
            f'cr2=0x{symbols["relro"]:016x} cpl=3' in serial), serial
    sparse_oom = bytearray(elf)
    struct.pack_into('<Q', sparse_oom, 24, symbols['mprotect_sparse_oom'])
    check_guest('mprotect-sparse-oom', sparse_oom, 'Linux x86-64 exit status=0x00', files=files)
    print('OVMF: mmap, mprotect, RELRO and Linux futex wake with no waiters: PASS', flush=True)


def main():
    build = pathlib.Path('build/x86_64')
    probe = build / 'linux-probe.elf'
    host = subprocess.run([str(probe.resolve())], env={}, capture_output=True, timeout=5)
    assert (host.returncode, host.stdout, host.stderr) == (42, b'OK', b' Linux ELF64 syscall probe\n'), host
    elf = probe.read_bytes()
    serial = check_guest('probe', elf, 'Linux x86-64 exit status=0x2a')
    assert 'OK Linux ELF64 syscall probe' in serial and 'Linux x86-64 ELF rejected' not in serial, serial
    print('OVMF: same Linux ELF64, same output and exit status: PASS', flush=True)
    serial = check_guest('no-rdrand', elf, 'Linux x86-64 ELF rejected', cpu='max,-rdrand')
    assert 'AT_RANDOM entropy unavailable' in serial and 'Linux x86-64 exit status' not in serial, serial
    print('OVMF: Linux ELF64 rejects CPU without RDRAND: PASS', flush=True)

    executable = next(p for p in program_headers(elf) if struct.unpack_from('<II', elf, p) == (1, 5))
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
    check_interpreter(build)
    check_files(build)
    check_mmap(build)


if __name__ == '__main__':
    main()
