"""Boot the real VBE loader, inject choices through BIOS keyboard, inspect scanout."""
import pathlib
import time
import shutil
import tempfile
import hardware_smoke
from hardware_smoke import VM, clean, digest, IMAGE, B

def bios_wait(vm, marker):
    path=pathlib.Path(vm.temp.name)/'bios-text.bin'
    end=time.monotonic()+120
    while time.monotonic()<end:
        vm.qmp('pmemsave',{'val':0xb8000,'size':4000,'filename':str(path)})
        text=path.read_bytes()[::2].decode('ascii',errors='replace')
        if marker in text:return
        time.sleep(.05)
    raise AssertionError('BIOS prompt missing: '+marker+' '+text+' '+clean(vm.log)[-1000:])

def run(name,choice,expected,extra=None):
    vm=VM(name,usb=False,extra=extra)
    try:
        bios_wait(vm,'Press V for resolution menu')
        vm.key('v')
        bios_wait(vm,'Choose 0-9')
        vm.key(choice)
        vm.wait('New password:')
        log=clean(vm.log)
        assert f'{expected[0]}x{expected[1]}, 32 bpp' in log,log[-3500:]
        path=pathlib.Path(vm.temp.name)/'screen.ppm'
        vm.qmp('screendump',{'filename':str(path)})
        assert tuple(map(int,path.read_bytes().split(b'\n',3)[1].split()))==expected
        assert 'EXCEPTION' not in log
        print(name,expected,'OK',flush=True)
    finally:vm.stop()

def check():
    before=digest(hardware_smoke.IMAGE)
    run('video-menu-fullhd','7',(1920,1080))
    run('video-menu-safe','3',(1024,768))
    # EDID advertises a native mode, which must win over the fallback list.
    run('video-edid-native','0',(1280,720),['-global','VGA.xres=1280','-global','VGA.yres=720'])
    run('video-menu-1440p','9',(2560,1440))
    # 8 MiB VRAM fits Full HD but cannot hold a 2560x1440 32-bit scanout.
    run('video-menu-fallback','9',(1280,800),['-global','VGA.vgamem_mb=8'])
    assert digest(hardware_smoke.IMAGE)==before
    print('VBE loader: BIOS menu + Full HD + safe mode + EDID + unavailable mode fallback: OK')

def main():
    # DrvFS медленно обслуживает тысячи мелких BIOS-чтений: тестируем копию на ext4.
    with tempfile.TemporaryDirectory(prefix='myos-video-image-') as directory:
        copy=pathlib.Path(directory)/'live.img';shutil.copyfile(IMAGE,copy)
        hardware_smoke.IMAGE=copy
        try:check()
        finally:hardware_smoke.IMAGE=IMAGE

if __name__=='__main__':main()
