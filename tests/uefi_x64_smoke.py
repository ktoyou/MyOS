"""Boot a freestanding x86-64 payload after leaving OVMF boot services."""
import pathlib
import struct
import sys
import tempfile

from disk_install_smoke import VM, run, uefi_firmware
from hardware_smoke import clean

sys.path.insert(0, str(pathlib.Path('tools').resolve()))
from make_uefi import ESP_START, ESP_SECTORS, ROOT_START, esp


def test_disk(image, payload, kernel_end, live_root_header):
    disk_id = 0x23456789
    root_sectors = 131072
    efi, _ = esp(payload, kernel_end, mode=1 if live_root_header is not None else 2, disk_id=disk_id,
                 root_sectors=root_sectors, arch='x86_64')
    mbr = bytearray(512)
    struct.pack_into('<I', mbr, 440, disk_id)
    struct.pack_into('<B3xB3xII', mbr, 446, 0, 0x83, ROOT_START, root_sectors)
    struct.pack_into('<B3xB3xII', mbr, 462, 0, 0xef, ESP_START, ESP_SECTORS)
    mbr[510:] = b'\x55\xaa'
    with image.open('wb') as disk:
        disk.write(mbr)
        disk.seek(512 * ESP_START)
        disk.write(efi)
        if live_root_header is not None:
            disk.seek(512 * ROOT_START)
            disk.write(live_root_header)
        disk.truncate(512 * (ROOT_START + root_sectors))


def boot_x64(directory, name, payload, kernel_end, markers, *, live_root_header=None, cpu='max', rtc=None):
    image = directory / 'disk.img'
    test_disk(image, payload, kernel_end, live_root_header)
    args = uefi_firmware(directory, name) + [
        '-drive', f'if=none,id=root,format=raw,file={image}',
        '-device', 'nvme,drive=root,serial=UEFIX64,bootindex=1',
    ]
    if rtc is not None:
        args += ['-rtc', rtc]
    vm = VM(name, args, binary='qemu-system-x86_64', cpu=cpu)
    vm.boot_timeout = 45
    try:
        vm.wait('UEFI: leaving boot services, entering x86-64 kernel')
        for marker in markers:
            vm.wait(marker)
        return clean(vm.log)
    finally:
        vm.stop()


def main():
    with tempfile.TemporaryDirectory(prefix='myos-uefi-x64-') as temp:
        directory = pathlib.Path(temp)
        binary = directory / 'kernel.bin'
        run('nasm', '-f', 'bin', 'tests/uefi_x64_handoff.asm', '-o', binary)
        payload = binary.read_bytes()
        boot_x64(directory, 'uefi-x64-handoff', payload, 0x100000 + len(payload) + 256,
                 ['UEFI X64 HANDOFF PASS'])
    print('OVMF x86-64 handoff, private paging and boot info: PASS')


if __name__ == '__main__':
    main()
