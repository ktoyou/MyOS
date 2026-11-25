"""Два запуска Live с одним временным NVMe-диском данных."""

import pathlib
import tempfile

from hardware_smoke import digest
from kernel_x64_smoke import image
from uefi_x64_smoke import boot_x64


SECTOR = 512
DATA_SECTORS = 8192
FIRST = 32
COUNT = 19
SEEDS = (0x37, 0x58, 0xa9)


def set_payload(data, seed):
    data[FIRST * SECTOR:(FIRST + COUNT) * SECTOR] = bytes(
        (seed + index * 13 + (index // 256) * 29) & 0xff for index in range(COUNT * SECTOR)
    )


def initial_disk():
    data = bytearray(DATA_SECTORS * SECTOR)
    data[:8] = b'MYOSDATA'
    data[440:444] = (0x51da7a09).to_bytes(4, 'little')
    data[510:512] = b'\x55\xaa'
    for lba, value in ((FIRST - 1, 0x19), (FIRST + COUNT, 0x32), (DATA_SECTORS - 1, 0xc7)):
        data[lba * SECTOR:(lba + 1) * SECTOR] = bytes([value]) * SECTOR
    set_payload(data, SEEDS[0])
    return data


def main():
    payload, kernel_end = image('kernel-nvme')
    with tempfile.TemporaryDirectory(prefix='myos-nvme-data-x64-') as temp:
        directory = pathlib.Path(temp)
        data_disk = directory / 'data.img'
        expected = initial_disk()
        data_disk.write_bytes(expected)
        for phase in range(2):
            boot_directory = directory / f'boot-{phase}'
            boot_directory.mkdir()
            boot_disk = boot_directory / 'disk.img'
            boot_digest = None

            def record_boot_disk(_vm):
                nonlocal boot_digest
                boot_digest = digest(boot_disk)

            # При второй загрузке диск данных предшествует диску Live в порядке PCI.
            root_slot, data_slot = (8, 9) if phase == 0 else (9, 8)
            serial = boot_x64(boot_directory, f'x64-nvme-data-{phase}', payload, kernel_end,
                              ['x86-64 NVMe data PASS'], live_root_header=b'MYOSNVME' + bytes([phase]),
                              before_boot=record_boot_disk, root_pci_address=root_slot, extra=[
                                  '-drive', f'if=none,id=data,format=raw,snapshot=off,file={data_disk}',
                                  '-device', f'nvme,drive=data,serial=MYOSDATA,addr={data_slot:#x}',
                              ])
            assert 'x86-64 NVMe data FAIL' not in serial and 'x86-64 exception' not in serial, serial
            assert digest(boot_disk) == boot_digest, 'Live boot disk was modified'
            set_payload(expected, SEEDS[phase + 1])
            assert data_disk.read_bytes() == expected, f'Unexpected raw NVMe contents after boot {phase + 1}'
    print('OVMF x86-64: secondary NVMe selection, bounded I/O and data across two boots: PASS', flush=True)


if __name__ == '__main__':
    main()
