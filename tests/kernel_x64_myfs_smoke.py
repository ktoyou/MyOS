"""Проверка записи MyFS v5 на отдельном NVMe и чтения после новой загрузки."""

import pathlib
import shutil
import struct
import subprocess
import tempfile

from hardware_smoke import digest
from kernel_x64_smoke import image
from uefi_x64_smoke import boot_x64


SECTOR = 512
VOLUME_SECTORS = 32768
VOLUME_BYTES = VOLUME_SECTORS * SECTOR
PAYLOAD_BYTES = 19 * SECTOR
SEEDS = (0x39, 0x91)
MARKER = b'MYOSX64MYFSDATA!'.ljust(SECTOR, b'\xa5')
MYFS = pathlib.Path('build/myfs')


def pattern(seed):
    return bytes((seed + index * 13 + (index // 256) * 29) & 0xff for index in range(PAYLOAD_BYTES))


def make_volume(path):
    with path.open('xb') as disk:
        disk.truncate(VOLUME_BYTES)
    subprocess.run([MYFS, path, 'fsck'], check=True)
    with path.open('r+b') as disk:
        assert struct.unpack('<4sII', disk.read(12)) == (b'MYFS', 5, VOLUME_SECTORS)
        # Маркер лежит за пределами тома и доступен до его монтирования.
        disk.seek(VOLUME_BYTES)
        disk.write(MARKER)


def inspect_volume(path, directory, seed):
    with path.open('rb') as disk:
        assert struct.unpack('<4sII', disk.read(12)) == (b'MYFS', 5, VOLUME_SECTORS)
        disk.seek(VOLUME_BYTES)
        assert disk.read() == MARKER, 'MyFS wrote outside the volume'
    # Утилита может записывать при открытии. Оригинальный диск снова подключит QEMU.
    copy = directory / 'inspection.img'
    shutil.copyfile(path, copy)
    output = directory / 'persisted.bin'
    subprocess.run([MYFS, copy, 'get', '/persisted', output], check=True)
    assert output.read_bytes() == pattern(seed), 'Unexpected persisted MyFS file contents'


def run_boot(directory, image_data, phase, volume, *, fault_config=None, readonly=False, markers=()):
    directory.mkdir()
    boot_disk = directory / 'disk.img'
    boot_digest = None

    def record_boot_disk(_vm):
        nonlocal boot_digest
        boot_digest = digest(boot_disk)

    payload, kernel_end = image_data
    root_slot, data_slot = (8, 9) if phase % 2 == 0 else (9, 8)
    source = f'blkdebug:{fault_config}:{volume}' if fault_config else str(volume)
    mode = 'on' if readonly else 'off'
    serial = boot_x64(directory, f'x64-myfs-data-{phase}', payload, kernel_end,
                      [*markers, 'x86-64 MyFS data PASS'], live_root_header=b'MYOSMYFS' + bytes([phase]),
                      before_boot=record_boot_disk, root_pci_address=root_slot, extra=[
                          '-drive', f'if=none,id=data,format=raw,snapshot=off,readonly={mode},werror=report,file={source}',
                          '-device', f'nvme,drive=data,serial=MYOSMYFS,addr={data_slot:#x}',
                      ])
    assert 'x86-64 MyFS data FAIL' not in serial and 'x86-64 exception' not in serial, serial
    assert digest(boot_disk) == boot_digest, 'Live boot disk was modified'


def check_failed_commit(directory, image_data):
    directory.mkdir()
    volume = directory / 'data.img'
    make_volume(volume)
    initial = directory / 'initial.bin'
    initial.write_bytes(pattern(SEEDS[0]))
    subprocess.run([MYFS, volume, 'put', initial, '/persisted'], check=True)

    before = volume.read_bytes()
    journal_lba, journal_blocks = struct.unpack_from('<II', before, 44)
    header = journal_lba * SECTOR
    end = (journal_lba + journal_blocks) * SECTOR
    assert 0 < header < end == VOLUME_BYTES and before[header:header + SECTOR] == bytes(SECTOR)
    config = directory / 'journal-write-error.cfg'
    config.write_text('[inject-error]\nevent = "write_aio"\nerrno = "5"\n'
                      f'sector = "{journal_lba}"\nonce = "on"\nimmediately = "on"\n', encoding='ascii')
    run_boot(directory / 'fault', image_data, 2, volume, fault_config=config,
             markers=('journal commit returned FS_EIO and disabled volume',))
    after = volume.read_bytes()
    assert after[:header + SECTOR] == before[:header + SECTOR], 'Failed commit changed the header or home sectors'
    assert after[header + SECTOR:end] != before[header + SECTOR:end], 'Redo payload never reached the disk'
    assert after[end:] == before[end:] == MARKER, 'Failed commit wrote outside the volume'

    run_boot(directory / 'recovery', image_data, 3, volume, readonly=True,
             markers=('old file readable after failed commit',))
    assert volume.read_bytes() == after, 'Read-only verification changed the data disk'


def main():
    image_data = image('kernel-myfs')
    with tempfile.TemporaryDirectory(prefix='myos-myfs-data-x64-') as temp:
        directory = pathlib.Path(temp)
        volume = directory / 'data.img'
        make_volume(volume)
        for phase, seed in enumerate(SEEDS):
            boot_directory = directory / f'boot-{phase}'
            run_boot(boot_directory, image_data, phase, volume)
            inspect_volume(volume, boot_directory, seed)
        check_failed_commit(directory / 'journal-error', image_data)
    print('OVMF x86-64: MyFS v5 write, rename, rollback, persistence and failed commit: PASS', flush=True)


if __name__ == '__main__':
    main()
