"""Проверка вывода пикселей libnsfb в окно рабочего стола MyOS."""
import pathlib,tempfile,time
from disk_install_smoke import VM,run
from hardware_inventory_smoke import live_image,login

B=pathlib.Path('build')

def main():
    with tempfile.TemporaryDirectory(prefix='myos-display-trial-') as directory:
        temp=pathlib.Path(directory);root=temp/'root.img'
        with root.open('wb') as f:f.truncate(64*1048576)
        for d in ['/bin','/lib','/lib/fonts','/etc','/root','/tmp']:run(B/'myfs',root,'mkdir',d)
        for name in ['sh','desktop','netsurf-surface-check','sleep']:
            run(B/'myfs',root,'put',B/'user'/name,'/bin/'+name)
        for name,source in [('ld.so',B/'ld.so'),('libc.so',B/'user/libc.so'),('libgfx.so',B/'user/libgfx.so')]:
            run(B/'myfs',root,'put',source,'/lib/'+name)
        for font in pathlib.Path('fonts').glob('*.ttf'):run(B/'myfs',root,'put',font,'/lib/fonts/'+font.name)
        preference=temp/'display';preference.write_text('1024x768\ncursor=sw\n')
        run(B/'myfs',root,'put',preference,'/etc/display')
        image=temp/'usb.img';live_image(root,image,temp)
        vm=VM('netsurf-window',['-smp','2','-device','qemu-xhci,id=xhci',
            '-drive',f'if=none,id=stick,format=raw,file={image}',
            '-device','usb-storage,bus=xhci.0,drive=stick,bootindex=1'],memory='512M')
        try:
            login(vm)
            for i, line in enumerate(['desktop &','sleep 2','netsurf-surface-check']):
                vm.send("echo '"+line+"' "+('>' if not i else '>>')+' /tmp/ns.sh','root:/')
            vm.send('sh /tmp/ns.sh','NetSurf: frame submitted')
            for attempt in range(8):
                shot=temp/'window.ppm'
                vm.qmp('screendump',{'filename':str(shot)})
                if bytes([0x44,0x88,0xff])*400 in shot.read_bytes():
                    print('NetSurf surface visible in MyOS: PASS')
                    return
                time.sleep(.3)
            raise AssertionError('window pixels missing')
        finally:
            vm.stop()
main()