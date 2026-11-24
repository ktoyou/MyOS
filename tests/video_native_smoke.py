"""Реальные BIOS/UEFI, EDID, безопасный fallback и большие оконные буферы."""
import argparse
import pathlib
import sys
import tempfile
import time
from disk_install_smoke import VM,run,uefi_firmware
from hardware_inventory_smoke import live_image,login
import hardware_smoke as hardware
B=pathlib.Path('build')

def dimensions(vm):
    p=pathlib.Path(vm.temp.name)/'native.ppm'
    vm.qmp('screendump',{'filename':str(p)})
    return tuple(map(int,p.read_bytes().split(b'\n',3)[1].split()))

def window_check(vm,name):
    vm.send("echo 'desktop &' > /tmp/native.sh",'root:/')
    vm.send("echo 'sleep 3' >> /tmp/native.sh",'root:/')
    vm.send("echo 'nativewindowcheck' >> /tmp/native.sh",'root:/')
    vm.send('sh /tmp/native.sh','NATIVE WINDOW PASS')
    time.sleep(1)
    shot=B/(name+'.ppm');vm.qmp('screendump',{'filename':str(shot.resolve())})
    pixels=shot.read_bytes().split(b'\n',3)[3]
    for color in [(220,40,60),(40,220,60),(40,60,220)]:
        assert pixels.count(bytes(color))>=3000,('Missing window corner',color)
    hardware.save_png(shot,shot.with_suffix('.png'))
    assert 'NATIVE WINDOW FAIL' not in hardware.clean(vm.log)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--quick',action='store_true')
    parser.add_argument('--firmware',choices=['bios','uefi'])
    parser.add_argument('--width',type=int)
    parser.add_argument('--vram',type=int)
    parser.add_argument('--virtual-only',action='store_true')
    args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='myos-video-native-') as directory:
        temp=pathlib.Path(directory);root=temp/'root.img'
        with root.open('wb') as out:out.truncate(64*1048576)
        for d in ['/bin','/lib','/etc','/root','/home','/tmp','/lib/fonts']:run(B/'myfs',root,'mkdir',d)
        for name in ['sh','mode','cat','stat','poweroff','sleep','desktop','display','nativewindowcheck']:
            run(B/'myfs',root,'put',B/'user'/name,'/bin/'+name)
        for name,source in [('ld.so',B/'ld.so'),('libc.so',B/'user/libc.so'),('libgfx.so',B/'user/libgfx.so')]:
            run(B/'myfs',root,'put',source,'/lib/'+name)
        for font in pathlib.Path('fonts').glob('*.ttf'):run(B/'myfs',root,'put',font,'/lib/fonts/'+font.name)
        for firmware in ['bios','uefi']:
            if args.virtual_only:continue
            if args.firmware and firmware!=args.firmware:continue
            image=temp/(firmware+'.img');live_image(root,image,temp,uefi=firmware=='uefi')
            cases=[(3440,1440,64,'1024M')]
            if not args.quick:cases += [(3840,2160,64,'1024M'),(5120,2160,64,'1024M'),(3440,1440,8,'256M'),(1280,720,64,'256M')]
            if not args.quick and firmware=='bios':cases += [(1280,720,16,'256M')]
            for w,h,vram,ram in cases:
                if args.width and w!=args.width:continue
                if args.vram and vram!=args.vram:continue
                name=f'video-native-{firmware}-{w}-{vram}'
                extra=uefi_firmware(temp,name) if firmware=='uefi' else []
                extra+=['-drive',f'format=raw,file={image},snapshot=on,index=0','-device',f'VGA,vgamem_mb={vram},xres={w},yres={h}','-vga','none']
                vm=VM(name,extra,memory=ram,binary='qemu-system-x86_64' if firmware=='uefi' else 'qemu-system-i386')
                try:
                    login(vm)
                    actual=dimensions(vm)
                    if firmware=='bios':
                        import struct
                        vm.qmp('pmemsave',{'val':0x1400,'size':1024,'filename':str((B/(name+'-edid.bin')).resolve())})
                        contract=pathlib.Path(vm.temp.name)/'boot-info.bin'
                        vm.qmp('pmemsave',{'val':0x6000,'size':100,'filename':str(contract)})
                        fields=struct.unpack('<25I',contract.read_bytes())
                        assert fields[1]==5 and fields[13:22]==(0,)*9,('Uninitialized BIOS boot contract',fields)
                    print(name,'selected',actual,flush=True)
                    # SeaBIOS не предлагает 3440 и обрезает EDID до 256 байт:
                    # DisplayID расширения 4K недоступны. OVMF здесь без EDID.
                    expected=(4096,2160) if firmware=='uefi' else (2560,1440) if w==3440 else (1280,720) if w==1280 else (5120,2160)
                    if w==1280 and firmware=='uefi':expected=(2800,2100)
                    if vram>=16:assert actual==expected,hardware.clean(vm.log)[-10000:]
                    else:assert actual[0]*actual[1]*4<=8*1048576
                    vm.send('mode','Usage: mode auto')
                    if firmware=='bios' and vram>=16:
                        vm.send('mode 1024x768','Switched to 1024x768')
                        vm.send('mode auto',f'Switched to {expected[0]}x{expected[1]}')
                        assert dimensions(vm)==expected
                        vm.send('cat /etc/display','cursor=')
                        if w in (3440,3840):vm.send('mode 3840x2160','Switched to 3840x2160')
                    if vram>=16:
                        window_check(vm,name)
                    text=hardware.clean(vm.log)
                    assert 'EXCEPTION' not in text and 'PANIC' not in text,text[-5000:]
                finally:vm.stop()
        if not args.firmware:
            for backend in ['std','virtio']:
                name='video-native-'+backend
                video=['-vga','none','-device','VGA,vgamem_mb=64'] if backend=='std' else ['-vga','virtio']
                vm=VM(name,['-smp','2','-drive',f'format=raw,file={B}/os.img,snapshot=on,index=0',
                    '-drive',f'format=raw,file={root},snapshot=on,index=1',*video],memory='1024M')
                try:
                    login(vm)
                    vm.send('mode auto','Switched to 5120x2880')
                    assert dimensions(vm)==(5120,2880)
                    vm.send('mode 3440x1440','Switched to 3440x1440')
                    assert dimensions(vm)==(3440,1440)
                    window_check(vm,name)
                    text=hardware.clean(vm.log)
                    assert 'EXCEPTION' not in text and 'PANIC' not in text and 'NATIVE WINDOW FAIL' not in text,text[-5000:]
                    print(name,'5K Auto, 3440x1440 and full-size window: PASS',flush=True)
                finally:vm.stop()
    print('Selected native display scenarios: PASS',flush=True)

if __name__=='__main__':main()
