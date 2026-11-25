"""Проверка диагностики PCI без сетевой карты и с e1000 в OVMF."""

import argparse
import pathlib
import re
import subprocess
import tempfile
import time

from disk_install_smoke import uefi_firmware
from hardware_smoke import clean


START = 'RTL8125 PCI probe start'
COMPLETE = re.compile(r'^RTL8125 PCI probe complete: PCI=(\d+) RTL8125=(\d+) XID=(\d+) E1000=(\d+)$',
                      re.MULTILINE)
INTEL = re.compile(r'^PCI [0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7] 8086:100e$', re.MULTILINE | re.IGNORECASE)
INTEL_BAR = re.compile(r"^BAR0 MEM base=([0-9a-f]+) length=([0-9a-f]+)$", re.MULTILINE | re.IGNORECASE)


def make_esp(path, application):
    with path.open('xb') as image:
        image.truncate(64 * 1024 * 1024)
    subprocess.run(['mformat', '-i', path, '-F', '::'], check=True)
    subprocess.run(['mmd', '-i', path, '::/EFI', '::/EFI/BOOT'], check=True)
    subprocess.run(['mcopy', '-i', path, application, '::/EFI/BOOT/BOOTX64.EFI'], check=True)


def wait_for_probe(vm, serial):
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        output = clean(serial)
        result = COMPLETE.search(output)
        # После возврата из EFI-приложения OVMF выбирает следующую загрузочную запись.
        if result and 'BdsDxe: loading Boot' in output[result.end():]:
            return output, result
        status = vm.poll()
        if status is not None:
            raise RuntimeError(f'QEMU завершился с кодом {status}')
        time.sleep(0.1)
    raise RuntimeError('OVMF не завершил запуск диагностики за 40 секунд')


def boot(work, esp, nic):
    name = 'e1000' if nic else 'no-nic'
    serial = work / f'{name}.log'
    stderr = work / f'{name}.stderr'
    serial.touch()
    args = ['qemu-system-x86_64', '-m', '256M', '-display', 'none', '-monitor', 'none',
            '-serial', f'file:{serial}', '-no-reboot', '-nic', 'none', *uefi_firmware(work, name),
            '-drive', f'if=none,id=esp,format=raw,readonly=on,file={esp}',
            '-device', 'qemu-xhci,id=xhci', '-device', 'usb-storage,bus=xhci.0,drive=esp,bootindex=1']
    if nic:
        args += ['-netdev', 'user,id=wire,restrict=on', '-device', 'e1000,netdev=wire,romfile=']

    try:
        with stderr.open('wb') as errors, subprocess.Popen(
            args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=errors,
        ) as vm:
            try:
                output, result = wait_for_probe(vm, serial)
            finally:
                if vm.poll() is None:
                    vm.terminate()
                    try:
                        vm.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        vm.kill()
                        vm.wait()
        scanned, realtek, xid, intel = map(int, result.groups())
        if (START not in output[:result.start()] or scanned < 1 or realtek or xid or intel != int(nic) or
                bool(INTEL.search(output[:result.start()])) != nic):
            raise RuntimeError('Неожиданный результат перечисления PCI')
        if nic:
            bar = INTEL_BAR.search(output[:result.start()])
            if not bar or int(bar[1], 16) == 0 or int(bar[2], 16) != 0x20000:
                raise RuntimeError('Не удалось проверить дескриптор области памяти e1000')
    except (OSError, RuntimeError) as error:
        raise SystemExit(f'{name}: {error}\n--- serial ---\n{clean(serial)}\n'
                         f'--- QEMU stderr ---\n{stderr.read_text(errors="replace")}') from error

    print(f'OVMF RTL8125 probe ({name}): PCI={scanned}, RTL8125={realtek}, XID={xid}, E1000={intel}: PASS', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('application', type=pathlib.Path, metavar='PATH_TO_EFI')
    args = parser.parse_args()
    if not args.application.is_file():
        parser.error(f'EFI-приложение не найдено: {args.application}')
    with tempfile.TemporaryDirectory(prefix='myos-rtl8125-probe-') as temporary:
        work = pathlib.Path(temporary)
        esp = work / 'esp.img'
        make_esp(esp, args.application)
        boot(work, esp, nic=False)
        boot(work, esp, nic=True)


if __name__ == '__main__':
    main()
