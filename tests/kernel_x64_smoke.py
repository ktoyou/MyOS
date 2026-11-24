"""Boot the normal and exception-test x86-64 kernels under OVMF."""
import pathlib
import re
import subprocess
import sys
import tempfile

from uefi_x64_smoke import boot_x64


def image(name):
    build = pathlib.Path('build/x86_64')
    payload = (build / (name + '.bin')).read_bytes()
    symbols = subprocess.check_output(['nm', str(build / (name + '.elf'))], text=True)
    kernel_end = next(int(line.split()[0], 16) for line in symbols.splitlines()
                      if line.endswith(' __kernel_end'))
    return payload, kernel_end


def check_pmm():
    payload, kernel_end = image('kernel-pmm')
    for mode in ('disk', 'live'):
        with tempfile.TemporaryDirectory(prefix='myos-pmm-x64-') as temp:
            marker = f'x86-64 PMM {mode} PASS'
            boot_x64(pathlib.Path(temp), f'x64-pmm-{mode}', payload, kernel_end, [marker],
                     live_root_header=b'MYOSPMM!' if mode == 'live' else None)
        print(f'OVMF x86-64 PMM {mode}: PASS', flush=True)


def check_paging():
    for mode, error in enumerate((None, 3, 0x11, 0)):
        name = f'kernel-paging-{mode}'
        payload, kernel_end = image(name)
        markers = ['MyOS x86-64: kernel CR3 active', 'x86-64 paging access PASS']
        if error is not None:
            fault = f'x86-64 exception vector=0x000000000000000e error={error:#018x} rip='
            markers.extend((fault, 'x86-64 exception halted'))
        with tempfile.TemporaryDirectory(prefix='myos-paging-x64-') as temp:
            serial = boot_x64(pathlib.Path(temp), f'x64-{name}', payload, kernel_end, markers)
        assert 'x86-64 paging check FAIL' not in serial, serial
        if error is not None:
            expected = re.search(r'x86-64 expected fault address=(0x[0-9a-f]{16})', serial)
            actual = re.search(re.escape(fault) + r'(0x[0-9a-f]{16}) cr2=(0x[0-9a-f]{16})', serial)
            assert expected and actual and expected[1] == actual[2], serial
            if mode == 2:
                assert actual[1] == actual[2], serial
            else:
                assert 0x100000 <= int(actual[1], 16) < 0x100000 + len(payload), serial
        else:
            assert 'x86-64 exception' not in serial, serial
        print(f'OVMF x86-64 paging {mode}: PASS', flush=True)

    payload, kernel_end = image('kernel-paging-0')
    with tempfile.TemporaryDirectory(prefix='myos-paging-x64-live-') as temp:
        boot_x64(pathlib.Path(temp), 'x64-kernel-paging-live', payload, kernel_end,
                 ['x86-64 paging live root PASS', 'x86-64 paging access PASS'],
                 live_root_header=b'MYOSPG!')
    print('OVMF x86-64 paging live root: PASS', flush=True)


def main():
    for suffix, vector, error in (('', None, None), ('-6', 6, 0), ('-13', 13, 0x28)):
        name = 'kernel' + suffix
        payload, kernel_end = image(name)
        markers = ['MyOS x86-64: UEFI memory map verified, IDT active',
                   'MyOS x86-64: kernel CR3 active']
        if vector is not None:
            prefix = f'x86-64 exception vector={vector:#018x} error={error:#018x} rip='
            markers.extend((prefix, 'x86-64 exception halted'))
        else:
            markers.append('MyOS x86-64: physical pages ready')
        with tempfile.TemporaryDirectory(prefix='myos-kernel-x64-') as temp:
            serial = boot_x64(pathlib.Path(temp), 'x64-' + name, payload, kernel_end, markers)
        if vector is not None:
            match = re.search(re.escape(prefix) + r'(0x[0-9a-f]{16})', serial)
            assert match and 0x100000 <= int(match[1], 16) < 0x100000 + len(payload), serial
        else:
            assert 'x86-64 exception' not in serial, serial
        print(f'OVMF x86-64 {name}: PASS', flush=True)


if __name__ == '__main__':
    if sys.argv[1:] == ['--pmm']:
        check_pmm()
    elif sys.argv[1:] == ['--paging']:
        check_paging()
    else:
        main()
