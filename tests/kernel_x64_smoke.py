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


def check_ring3():
    cases = ((6, 0, None), (14, 5, 0x100000), (14, 0x15, 0x800ff8), (14, 7, 0x400000))
    for mode, (vector, error, cr2) in enumerate(cases):
        name = f'kernel-ring3-{mode}'
        payload, kernel_end = image(name)
        prefix = f'x86-64 exception vector={vector:#018x} error={error:#018x} rip='
        markers = [prefix, 'x86-64 TSS entry stack active', 'x86-64 exception halted']
        with tempfile.TemporaryDirectory(prefix='myos-ring3-x64-') as temp:
            serial = boot_x64(pathlib.Path(temp), f'x64-{name}', payload, kernel_end, markers)
        match = re.search(re.escape(prefix) + r'(0x[0-9a-f]{16})'
                          r'(?: cr2=(0x[0-9a-f]{16}))? cpl=3 user_rsp=(0x[0-9a-f]{16})',
                          serial)
        assert match and 'x86-64 ring3 FAIL' not in serial, serial
        assert (int(match[2], 16) if match[2] else None) == cr2, serial
        assert int(match[3], 16) == (0x800ff8 if mode == 2 else 0x801000), serial
        if mode == 2:
            assert match[1] == match[2], serial
        else:
            assert 0x400000 <= int(match[1], 16) < 0x401000, serial
        print(f'OVMF x86-64 ring3 {mode}: PASS', flush=True)


def check_gop():
    payload, kernel_end = image('kernel-gop')
    markers = ['x86-64 GOP frame PASS', 'x86-64 exception vector=0x000000000000000e',
               'cr2=0xffffc00000000000 cpl=3', 'x86-64 exception halted']
    with tempfile.TemporaryDirectory(prefix='myos-gop-x64-') as temp:
        directory = pathlib.Path(temp)
        shot = directory / 'gop.ppm'
        serial = boot_x64(directory, 'x64-kernel-gop', payload, kernel_end, markers, screenshot=shot)
        assert 'error=0x0000000000000005' in serial and 'x86-64 ring3 FAIL' not in serial, serial
        magic, width, height, maxval, pixels = shot.read_bytes().split(maxsplit=4)
        w, h = int(width), int(height)
        assert magic == b'P6' and maxval == b'255' and w >= 640 and h >= 480 and len(pixels) == w * h * 3
        for y in (0, h // 2 - 1, h // 2, h - 1):
            for x in (0, w // 2 - 1, w // 2, w - 1):
                colors = ('de292f', '23b471') if y < h // 2 else ('365ed6', 'efd487')
                offset = (y * w + x) * 3
                assert pixels[offset:offset + 3] == bytes.fromhex(colors[x >= w // 2]), (x, y, w, h)
    print('OVMF x86-64 GOP output and supervisor access: PASS', flush=True)


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
    elif sys.argv[1:] == ['--ring3']:
        check_ring3()
    elif sys.argv[1:] == ['--gop']:
        check_gop()
    else:
        main()
