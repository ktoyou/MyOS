"""Run the same Linux ELF64 files on the host and in the MyOS guest."""
import datetime
import os
import pathlib
import resource
import signal
import struct
import subprocess
import tempfile

from kernel_x64_smoke import image
from uefi_x64_smoke import boot_x64


def linux_root(elf, files, exec_path='/myos/test.elf', *, aligned=True):
    executable = os.fsencode(exec_path) + b'\0'
    tag = b'MYOSLX66' if aligned else b'MYOSLX65'
    root = bytearray(tag + struct.pack('<QQQ', len(elf), len(files), len(executable)))

    def append_payload(contents):
        if aligned:
            root.extend(b'\0' * (-len(root) % 4096))
        root.extend(contents)

    root.extend(executable)
    append_payload(elf)
    for path, contents in files.items():
        encoded = os.fsencode(path) + b'\0'
        root.extend(struct.pack('<QQ', len(encoded), len(contents)))
        root.extend(encoded)
        append_payload(contents)
    return root


def check_guest(name, elf, marker, *, fault=False, files=None, cpu='max', exec_path='/myos/test.elf',
                rtc=None, aligned=True):
    payload, kernel_end = image('kernel-linux')
    root_header = linux_root(elf, files or {}, exec_path, aligned=aligned)
    with tempfile.TemporaryDirectory(prefix='myos-linux-x64-') as temp:
        serial = boot_x64(pathlib.Path(temp), 'x64-linux-' + name, payload,
                          kernel_end, [marker], live_root_header=root_header, cpu=cpu, rtc=rtc)
    if not fault:
        assert 'x86-64 exception' not in serial, serial
    return serial


def program_headers(elf):
    phoff = struct.unpack_from('<Q', elf, 32)[0]
    phentsize, phnum = struct.unpack_from('<HH', elf, 54)
    for i in range(phnum):
        yield phoff + i * phentsize


def check_shared_elf(build):
    probe = build / 'linux-exec.elf'
    elf = bytearray(probe.read_bytes())
    symbols = subprocess.check_output(['nm', str(probe)], text=True).splitlines()
    entry = next(int(line.split()[0], 16) for line in symbols if line.endswith(' exec_shared_entry'))
    struct.pack_into('<Q', elf, 24, entry)
    header = next(offset for offset in program_headers(elf)
                  if struct.unpack_from('<I', elf, offset)[0] == 0x6474e551)
    elf.extend(b'\0' * (-len(elf) % 4096))
    length = 52 * 1024 * 1024 + 1
    struct.pack_into('<II6Q', elf, header, 1, 4, len(elf), 0x50000000, 0, length, length + 4096, 4096)
    elf.extend(bytearray(length))
    elf[-length], elf[-1] = 0x29, 0x63
    # В госте с 256 МиБ четыре копии сегмента плюс Live-образ не помещаются в RAM.
    check_guest('elf-shared', elf, 'Linux x86-64 exit status=0x00')
    print('OVMF: concurrent execve shares read-only ELF pages and keeps writes private: PASS', flush=True)


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
                         files={path: interp}, exec_path=pie)
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
    assert (host.returncode, host.stderr) == (0, b''), host
    host_uname, host_time, host_marker = host.stdout.decode().splitlines()
    assert host_uname == 'Linux uname: Linux' and host_marker == 'Linux ELF64 files probe', host
    assert int(host_time.removeprefix('Linux UTC seconds: ')) > 0, host
    rtc_date = datetime.datetime(2040, 2, 29, 12, 34, 56, tzinfo=datetime.timezone.utc)
    serial = check_guest('files', probe.read_bytes(), 'Linux x86-64 exit status=0x00',
                         files={data: data.read_bytes()},
                         rtc=f'base={rtc_date.replace(tzinfo=None).isoformat()},clock=vm')
    assert 'Linux uname: MyOS' in serial and 'Linux ELF64 files probe' in serial, serial
    timestamp = int(serial.split('Linux UTC seconds: ', 1)[1].splitlines()[0])
    assert rtc_date.timestamp() <= timestamp <= rtc_date.timestamp() + 30, serial
    print('OVMF: Linux ELF64 files, directories, symlinks, descriptors, signals, IDs and UTC clocks: PASS', flush=True)


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

    for entry, fault_page in (('mmap_past_eof', 2), ('mmap_shared_past_eof', 1)):
        name = entry.replace('_', '-')
        past_eof = bytearray(elf)
        struct.pack_into('<Q', past_eof, 24, symbols[entry])
        host_past_eof = build / f'linux-{name}.elf'
        host_past_eof.write_bytes(past_eof)
        host_past_eof.chmod(0o755)
        host = subprocess.run([str(host_past_eof.resolve())], env={}, timeout=5,
                              preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
        assert host.returncode == -signal.SIGBUS, host
        serial = check_guest(name, past_eof, 'x86-64 exception halted', fault=True, files=files)
        assert ('vector=0x000000000000000e error=0x0000000000000004' in serial and
                f'cr2=0x{0x1000000000 + fault_page * 4096:016x} cpl=3' in serial), serial

    relro = bytearray(elf)
    struct.pack_into('<Q', relro, 24, symbols['mprotect_relro_fault'])
    serial = check_guest('mprotect-relro', relro, 'x86-64 exception halted', fault=True, files=files)
    assert ('vector=0x000000000000000e error=0x0000000000000007' in serial and
            f'cr2=0x{symbols["relro"]:016x} cpl=3' in serial), serial
    sparse_oom = bytearray(elf)
    struct.pack_into('<Q', sparse_oom, 24, symbols['mprotect_sparse_oom'])
    check_guest('mprotect-sparse-oom', sparse_oom, 'Linux x86-64 exit status=0x00', files=files)
    memfd_nx = bytearray(elf)
    struct.pack_into('<Q', memfd_nx, 24, symbols['mmap_memfd_nx'])
    serial = check_guest('mmap-memfd-nx', memfd_nx, 'x86-64 exception halted', fault=True)
    assert ('vector=0x000000000000000e error=0x0000000000000015' in serial and
            'cr2=0x0000001000000000 cpl=3' in serial), serial
    print('OVMF: mmap, memfd, mprotect, MADV_DONTNEED, RELRO and Linux futex wake: PASS', flush=True)
    sysinfo = bytearray(elf)
    struct.pack_into('<Q', sysinfo, 24, symbols['check_sysinfo'])
    check_guest('sysinfo', sysinfo, 'Linux x86-64 exit status=0x00')
    print('OVMF: Linux x86-64 sysinfo ABI, page accounting and task count: PASS', flush=True)


def check_socket(build):
    probe = (build / 'linux-socket.elf').resolve()
    marker = 'Linux ELF64 socket probe'
    host = subprocess.run([str(probe)], env={}, capture_output=True, timeout=5,
                          preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32)))
    assert (host.returncode, host.stdout, host.stderr) == (0, (marker + '\n').encode(), b''), host
    serial = check_guest('socket', probe.read_bytes(), 'Linux x86-64 exit status=0x00')
    assert marker in serial, serial
    print('OVMF: AF_UNIX pathname streams, blocking stream and seqpacket I/O, descriptor cleanup: PASS', flush=True)


def check_pipe(build):
    probe = (build / 'linux-pipe.elf').resolve()
    marker = 'Linux ELF64 pipe probe'
    host = subprocess.run([str(probe)], env={}, capture_output=True, timeout=5)
    assert (host.returncode, host.stdout, host.stderr) == (0, (marker + '\n').encode(), b''), host
    serial = check_guest('pipe', probe.read_bytes(), 'Linux x86-64 exit status=0x00')
    assert marker in serial, serial
    print('OVMF: Linux pipes, FIFO, descriptor cleanup and blocking I/O: PASS', flush=True)


def check_poll(build):
    probe = (build / 'linux-poll.elf').resolve()
    marker = 'Linux ELF64 poll probe'
    host = subprocess.run([str(probe)], env={}, capture_output=True, timeout=5,
                          preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32)))
    assert (host.returncode, host.stdout, host.stderr) == (0, (marker + '\n').encode(), b''), host
    serial = check_guest('poll', probe.read_bytes(), 'Linux x86-64 exit status=0x00')
    assert marker in serial, serial
    print('OVMF: Linux poll, ppoll, and eventfd readiness and blocking wakeup: PASS', flush=True)


def check_pthread(build):
    probe = (build / 'linux-pthread.elf').resolve()
    marker = 'Linux ELF64 pthread probe'
    host = subprocess.run([str(probe)], env={}, capture_output=True, timeout=5)
    assert (host.returncode, host.stdout, host.stderr) == (0, (marker + '\n').encode(), b''), host
    serial = check_guest('pthread', probe.read_bytes(), 'Linux x86-64 exit status=0x00')
    assert marker in serial, serial
    print('OVMF: Linux pthread TLS, shared process state, futex and group exit: PASS', flush=True)


def drop_root():
    if os.geteuid() == 0:
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)


def check_userns(build):
    probe = (build / 'linux-userns.elf').resolve()
    marker = 'Linux ELF64 user namespace probe'
    host = subprocess.run([str(probe)], env={}, capture_output=True, timeout=5, preexec_fn=drop_root)
    if host.returncode == 77:
        print('Linux: unprivileged user namespaces denied by host policy: SKIP', flush=True)
    else:
        assert (host.returncode, host.stdout, host.stderr) == (0, (marker + '\n').encode(), b''), host
    serial = check_guest('userns', probe.read_bytes(), 'Linux x86-64 exit status=0x00')
    assert marker in serial, serial
    print('OVMF: Linux user namespace, ID mappings, scoped caps and nested unshare: PASS', flush=True)


def check_pidns(build):
    probe = (build / 'linux-pidns.elf').resolve()
    marker = 'Linux ELF64 PID namespace probe'
    host = subprocess.run([str(probe)], env={}, capture_output=True, timeout=15, preexec_fn=drop_root)
    if host.returncode == 77:
        print('Linux: unprivileged PID namespaces denied by host policy: SKIP', flush=True)
    else:
        assert (host.returncode, host.stdout, host.stderr) == (0, (marker + '\n').encode(), b''), host
    serial = check_guest('pidns', probe.read_bytes(), 'Linux x86-64 exit status=0x00')
    assert marker in serial, serial
    print('OVMF: PID namespaces, translated waits and credentials, and subtree teardown: PASS', flush=True)


def check_fork(build):
    probe = (build / 'linux-fork.elf').resolve()
    marker = 'Linux ELF64 fork probe'
    host = subprocess.run([str(probe)], env={}, capture_output=True, timeout=5,
                          preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
    assert (host.returncode, host.stdout, host.stderr) == (0, (marker + '\n').encode(), b''), host
    serial = check_guest('fork', probe.read_bytes(), 'Linux x86-64 exit status=0x00')
    assert marker in serial, serial
    symbols = subprocess.check_output(['nm', str(probe)], text=True)
    entry = next(int(line.split()[0], 16) for line in symbols.splitlines() if line.endswith(' fork_oom'))
    oom = bytearray(probe.read_bytes())
    struct.pack_into('<Q', oom, 24, entry)
    check_guest('fork-oom', oom, 'Linux x86-64 exit status=0x00')
    print('OVMF: Linux fork, wait4, address spaces and shared file descriptions: PASS', flush=True)


def check_vfork(build):
    probe = (build / 'linux-vfork.elf').resolve()
    marker = 'Linux ELF64 vfork probe'
    host = subprocess.run([str(probe)], env={}, capture_output=True, timeout=5,
                          preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
    assert (host.returncode, host.stdout, host.stderr) == (0, (marker + '\n').encode(), b''), host
    serial = check_guest('vfork', probe.read_bytes(), 'Linux x86-64 exit status=0x00')
    assert marker in serial, serial
    print('OVMF: Linux vfork, shared address space and waitid: PASS', flush=True)


def check_shared_fs(build):
    probe = (build / 'linux-shared-fs.elf').read_bytes()
    elf = bytearray((build / 'linux-pie.elf').read_bytes())
    header = next(p for p in program_headers(elf) if struct.unpack_from('<I', elf, p)[0] == 3)
    path = b'/lib/test-ld.so\0'
    offset = struct.unpack_from('<Q', elf, header + 8)[0]
    elf[offset:offset + len(path)] = path
    struct.pack_into('<QQ', elf, header + 32, len(path), len(path))

    loader = bytearray((build / 'linux-interp.elf').read_bytes())
    entry = struct.unpack_from('<Q', loader, 24)[0]
    for p in program_headers(loader):
        kind, _, offset, address, _, size = struct.unpack_from('<II4Q', loader, p)
        if kind == 1 and address <= entry < address + size:
            pos = offset + entry - address
            # mov eax,60; mov edi,42; syscall
            loader[pos:pos + 12] = b'\xb8\x3c\0\0\0\xbf\x2a\0\0\0\x0f\x05'
            break
    else:
        raise AssertionError('ELF interpreter entry has no file bytes')

    files = {'/sandbox/sub/probe': elf, '/outside.elf': elf}
    for suffix, extra in (
        ('missing', {'/lib/test-ld.so': loader, '/loader-missing': b'1'}),
        ('present', {'/lib/test-ld.so': b'not an ELF', '/sandbox/lib/test-ld.so': loader}),
    ):
        serial = check_guest('shared-fs-' + suffix, probe, 'Linux x86-64 exit status=0x00',
                             files={**files, **extra})
        assert 'Linux ELF64 shared filesystem probe' in serial, serial
    print('OVMF: shared filesystem, chroot, Unix paths and rooted ELF interpreter: PASS', flush=True)


def check_exec(build):
    probe = (build / 'linux-exec.elf').resolve()
    target = build / 'linux-exec-target.elf'
    malformed = build / 'linux-exec-bad.elf'
    malformed.write_bytes(b'not an ELF image\n')
    malformed.chmod(0o755)
    marker = 'Linux ELF64 execve probe'
    host = subprocess.run([str(probe)], cwd=probe.parent, env={}, capture_output=True, timeout=5)
    assert (host.returncode, host.stdout, host.stderr) == (0, (marker + '\n').encode(), b''), host
    files = {pathlib.Path('/') / path.name: path.read_bytes() for path in (target, malformed)}
    serial = check_guest('execve', probe.read_bytes(), 'Linux x86-64 exit status=0x00', files=files)
    assert marker in serial, serial
    symbols = subprocess.check_output(['nm', str(probe)], text=True)
    entry = next(int(line.split()[0], 16) for line in symbols.splitlines() if line.endswith(' exec_oom'))
    oom = bytearray(probe.read_bytes())
    struct.pack_into('<Q', oom, 24, entry)
    large = bytearray(target.read_bytes())
    loads = [offset for offset in program_headers(large) if struct.unpack_from('<I', large, offset)[0] == 1]
    last = max(loads, key=lambda offset: struct.unpack_from('<Q', large, offset + 16)[0])
    struct.pack_into('<Q', large, last + 40, 0x9000000)
    check_guest('execve-oom', oom, 'Linux x86-64 exit status=0x00',
                files={pathlib.Path('/linux-exec-oom.elf'): large})
    print('OVMF: execve, new ELF stack, CLOEXEC, vfork resume and rollback: PASS', flush=True)


def main():
    build = pathlib.Path('build/x86_64')
    probe = build / 'linux-probe.elf'
    host = subprocess.run([str(probe.resolve())], env={}, capture_output=True, timeout=5)
    assert (host.returncode, host.stdout, host.stderr) == (42, b'OK', b' Linux ELF64 syscall probe\n'), host
    elf = probe.read_bytes()
    serial = check_guest('probe', elf, 'Linux x86-64 exit status=0x2a', exec_path=probe.resolve())
    assert 'OK Linux ELF64 syscall probe' in serial and 'Linux x86-64 ELF rejected' not in serial, serial
    print('OVMF: same Linux ELF64, same output and exit status: PASS', flush=True)
    longest_path = '/' + 'bin/' * 1023 + 'el'
    check_guest('long-exe', elf, 'Linux x86-64 exit status=0x2a', exec_path=longest_path, aligned=False)
    check_guest('bad-exe', elf, 'Linux x86-64 ELF rejected', exec_path='relative.elf')
    print('OVMF: executable path, AT_EXECFN and readlink: PASS', flush=True)
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
    for name, address, error in (('guard', 0x7fffff6ff000, 4),
                                 ('stack_noaccess', 0x7fffffee0000, 4),
                                 ('stack_nx', 0x7fffffedf000, 20)):
        entry = next(int(line.split()[0], 16) for line in symbols.splitlines()
                     if line.endswith(f' {name}_probe'))
        faulting = bytearray(elf)
        struct.pack_into('<Q', faulting, 24, entry)
        serial = check_guest(name, faulting, 'x86-64 exception halted', fault=True)
        assert (f'vector=0x000000000000000e error=0x{error:016x}' in serial and
                f'cr2=0x{address:016x} cpl=3' in serial), serial
    print('OVMF: lazy stack growth, guard, PROT_NONE and NX: PASS', flush=True)
    check_interpreter(build)
    check_files(build)
    check_mmap(build)
    check_socket(build)
    check_pipe(build)
    check_poll(build)
    check_fork(build)
    check_pthread(build)
    check_userns(build)
    check_pidns(build)
    check_shared_fs(build)
    check_vfork(build)
    check_exec(build)
    check_shared_elf(build)


if __name__ == '__main__':
    main()
