"""Boot the normal and exception-test x86-64 kernels under OVMF."""
import pathlib
import re
import subprocess
import tempfile

from uefi_x64_smoke import boot_x64


def main():
    build = pathlib.Path('build/x86_64')
    for suffix, vector, error in (('', None, None), ('-6', 6, 0), ('-13', 13, 0x28)):
        name = 'kernel' + suffix
        payload = (build / (name + '.bin')).read_bytes()
        symbols = subprocess.check_output(['nm', str(build / (name + '.elf'))], text=True)
        kernel_end = next(int(line.split()[0], 16) for line in symbols.splitlines()
                          if line.endswith(' __kernel_end'))
        markers = ['MyOS x86-64: UEFI memory map verified, IDT active']
        if vector is not None:
            prefix = f'x86-64 exception vector={vector:#018x} error={error:#018x} rip='
            markers.extend((prefix, 'x86-64 exception halted'))
        with tempfile.TemporaryDirectory(prefix='myos-kernel-x64-') as temp:
            serial = boot_x64(pathlib.Path(temp), 'x64-' + name, payload, kernel_end, markers)
        if vector is not None:
            match = re.search(re.escape(prefix) + r'(0x[0-9a-f]{16})', serial)
            assert match and 0x100000 <= int(match[1], 16) < 0x100000 + len(payload), serial
        else:
            assert 'x86-64 exception' not in serial, serial
        print(f'OVMF x86-64 {name}: PASS', flush=True)


if __name__ == '__main__':
    main()
