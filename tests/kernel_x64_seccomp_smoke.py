"""Проверить установку, исполнение и наследование seccomp в Linux ABI MyOS."""

import pathlib

from kernel_x64_linux_smoke import check_guest


def main():
    probe = pathlib.Path('build/x86_64/linux-seccomp-probe.elf').read_bytes()
    serial = check_guest('seccomp', probe, 'Linux x86-64 exit status=')
    assert 'Seccomp guest PASS' in serial and 'Linux x86-64 exit status=0x00' in serial, serial
    print('OVMF Linux x86-64: seccomp validation, stacking, fork/exec inheritance, TSYNC and SIGSYS: PASS', flush=True)


if __name__ == '__main__':
    main()
