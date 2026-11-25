"""Проверить общий объект /dev/shm и изоляцию путей в Linux ABI MyOS."""

import pathlib

from kernel_x64_linux_smoke import check_guest


def main():
    probe = pathlib.Path('build/x86_64/linux-shm-probe.elf').read_bytes()
    files = {'/dev/shm/myos-shm-live-marker': b'live'}
    serial = check_guest('shm', probe, 'Linux x86-64 exit status=', files=files)
    assert 'SHM guest PASS' in serial and 'Linux x86-64 exit status=0x00' in serial, serial
    print('OVMF Linux x86-64: /dev/shm mode, listing, fork, unlink lifetime and chroot: PASS', flush=True)


if __name__ == '__main__':
    main()
