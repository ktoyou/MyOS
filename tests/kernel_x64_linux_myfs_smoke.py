"""Проверка Linux ABI на MyFS-профиле после двух независимых загрузок."""

import pathlib
import secrets
import shutil
import subprocess
import tempfile

from hardware_smoke import digest
from kernel_x64_linux_smoke import linux_root
from kernel_x64_myfs_smoke import MYFS, SECTOR, VOLUME_BYTES, make_volume
from kernel_x64_smoke import image
from uefi_x64_smoke import boot_x64


def prepare_volume(directory, volume, marker):
    make_volume(volume)
    seed = directory / 'seed.txt'
    seed.write_bytes(b'group can read\n')
    for name in ('group', 'private', 'sealed/inside'):
        subprocess.run([MYFS, volume, 'put', seed, f'/owned/{name}'], check=True)
    for name, mode, uid, gid in (('/owned', '0700', '1000', '1000'),
                                 ('/owned/group', '0640', '1001', '1000'),
                                 ('/owned/private', '0600', '1001', '1001'),
                                 ('/owned/sealed', '0700', '1001', '1001')):
        subprocess.run([MYFS, volume, 'chmod', mode, name], check=True)
        subprocess.run([MYFS, volume, 'chown', uid, gid, name], check=True)
    with volume.open('r+b') as disk:
        disk.seek(VOLUME_BYTES)
        disk.write(marker)


def verify_disk(directory, volume):
    # Утилита MyFS может записывать при открытии, поэтому читаем копию.
    copy = directory / 'inspection.img'
    shutil.copyfile(volume, copy)
    result = directory / 'preferences.bin'
    subprocess.run([MYFS, copy, 'get', '/owned/Default/Preferences', result], check=True)
    assert result.read_bytes() == bytes((0xa7 + i * 13 + (i // 256) * 29) & 0xff for i in range(9728))


def main():
    elf = pathlib.Path('build/x86_64/linux-myfs-files.elf').read_bytes()
    payload, kernel_end = image('kernel-linux')
    token = secrets.token_hex(8).encode('ascii')
    marker = (b'MYOSPROF' + token).ljust(SECTOR, b'\0')
    with tempfile.TemporaryDirectory(prefix='myos-linux-myfs-x64-') as temp:
        directory = pathlib.Path(temp)
        volume = directory / 'profile.img'
        prepare_volume(directory, volume, marker)
        for phase, check, access, data_slot, root_slot in (
            (b'1', 'wrote profile', 'off', 9, 8),
            (b'2', 'reopened profile', 'on', 8, 9),
        ):
            boot_directory = directory / f'boot-{phase.decode()}'
            boot_directory.mkdir()
            boot_disk = boot_directory / 'disk.img'
            boot_digest = None
            volume_digest = digest(volume)

            def record_boot_disk(_vm):
                nonlocal boot_digest
                boot_digest = digest(boot_disk)

            root = linux_root(elf, {'/myos/myfs-volume': token, '/myos/myfs-test-phase': phase})
            serial = boot_x64(boot_directory, f'x64-linux-myfs-{phase.decode()}', payload, kernel_end,
                              ['Linux x86-64 exit status='], live_root_header=root,
                              before_boot=record_boot_disk, root_pci_address=root_slot, extra=[
                                  '-drive', f'if=none,id=profile,format=raw,snapshot=off,readonly={access},file={volume}',
                                  '-device', f'nvme,drive=profile,serial=MYOSPROFILE,addr={data_slot:#x}',
                              ])
            assert f'Linux MyFS guest {check} PASS' in serial and 'Linux x86-64 exit status=0x00' in serial, serial
            assert 'x86-64 exception' not in serial, serial
            assert digest(boot_disk) == boot_digest, 'Live boot disk was modified'
            with volume.open('rb') as disk:
                disk.seek(VOLUME_BYTES)
                assert disk.read() == marker, 'MyFS wrote beyond the volume'
            if phase == b'2':
                assert digest(volume) == volume_digest, 'Read-only boot modified the profile disk'
        verify_disk(directory, volume)
    print('OVMF Linux x86-64: MyFS profile, open FDs, rename, symlinks, permissions and persistence: PASS', flush=True)


if __name__ == '__main__':
    main()
