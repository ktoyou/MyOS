"""Preview, подтверждение и откат с настоящим VBE и персистентным тестовым USB."""
import pathlib,re,subprocess,tempfile,time
from disk_install_smoke import VM,run
from hardware_inventory_smoke import live_image,login
import hardware_smoke as hw
B=pathlib.Path('build')

def main():
    with tempfile.TemporaryDirectory(prefix='myos-display-trial-') as directory:
        temp=pathlib.Path(directory);root=temp/'root.img'
        with root.open('wb') as f:f.truncate(64*1048576)
        for d in ['/bin','/lib','/lib/fonts','/etc','/root','/tmp']:run(B/'myfs',root,'mkdir',d)
        for name in ['sh','desktop','display-ui-check','sleep','mode','cat','poweroff']:
            run(B/'myfs',root,'put',B/'user'/name,'/bin/'+name)
        for name,source in [('ld.so',B/'ld.so'),('libc.so',B/'user/libc.so'),('libgfx.so',B/'user/libgfx.so')]:
            run(B/'myfs',root,'put',source,'/lib/'+name)
        for font in pathlib.Path('fonts').glob('*.ttf'):run(B/'myfs',root,'put',font,'/lib/fonts/'+font.name)
        preference=temp/'display';preference.write_text('1024x768\ncursor=sw\n')
        run(B/'myfs',root,'put',preference,'/etc/display')
        image=temp/'usb.img';live_image(root,image,temp)
        vm=VM('display-preview',['-smp','2','-device','qemu-xhci,id=xhci',
            '-drive',f'if=none,id=stick,format=raw,file={image}',
            '-device','usb-storage,bus=xhci.0,drive=stick,bootindex=1'],memory='512M')
        def text():return hw.clean(vm.log)
        def preference_is(expected):
            vm.qmp('stop')
            try:actual=subprocess.check_output([str(B/'myfs'),str(image),'cat','/etc/display'])
            finally:vm.qmp('cont')
            assert actual==expected,('Unexpected saved display setting',actual,expected)
        def shot(name):
            p=B/('display-preview-'+name+'.ppm');vm.qmp('screendump',{'filename':str(p.resolve())})
            hw.save_png(p,p.with_suffix('.png'))
            return tuple(map(int,p.read_bytes().split(b'\n',3)[1].split()))
        def start(w,h):
            offset=len(text());vm.key('home');vm.key('right');vm.key('right');vm.key('ret')
            vm.wait(f'screen={w}x{h} seconds=15',offset)
            assert re.search(r'DISPLAY UI: token=[1-9][0-9]* screen='+str(w)+'x'+str(h),text()[offset:])
            return offset
        def restored(w,h,offset):
            vm.wait(f'Display: restored {w}x{h}',offset,timeout=25)
            vm.wait(f'token=0 screen={w}x{h}',offset)
            assert shot('restored')==(w,h)
        try:
            login(vm)
            lines=['desktop &','sleep 3','display-ui-check','sleep 1','display-ui-check','mode','cat /etc/display','poweroff']
            for i,line in enumerate(lines):vm.send("echo '"+line+"' "+('>' if not i else '>>')+' /tmp/display.sh','root:/')
            vm.send('sh /tmp/display.sh','DISPLAY UI: token=0 screen=1024x768')
            saved=b'1024x768\ncursor=sw\n'
            offset=start(800,600);preference_is(saved);assert shot('confirm')==(800,600)
            restored(1024,768,offset);preference_is(saved)
            offset=start(800,600);vm.key('tab');vm.key('ret')
            vm.wait('DISPLAY SAVE: 800x600 result=0',offset);vm.wait('token=0 screen=800x600',offset)
            saved=b'800x600\ncursor=sw\n';preference_is(saved)
            offset=start(1024,768);vm.key('esc');restored(800,600,offset);preference_is(saved)
            offset=start(1024,768);vm.key('ret');restored(800,600,offset);preference_is(saved)
            offset=start(1024,768);vm.key('z');vm.wait('blocked for 20 seconds',offset)
            vm.wait('Display: restored 800x600',offset,timeout=18)
            assert shot('blocked')==(800,600);restored(800,600,offset);preference_is(saved)
            offset=start(1024,768);vm.key('k');vm.wait('DISPLAY UI: abrupt exit',offset)
            restored(800,600,offset);preference_is(saved)
            offset=start(1024,768)
            vm.key('q')  # Контрольный клиент передаёт обычный EV_CLOSE.
            vm.wait('Display: restored 800x600',offset);vm.wait('Powering off...',offset);vm.p.wait(timeout=25)
            assert text().count('DISPLAY SAVE:')==1,text()[-7000:]
            assert 'EXCEPTION' not in text() and 'PANIC' not in text(),text()[-7000:]
        finally:vm.stop()
        assert subprocess.check_output([str(B/'myfs'),str(image),'cat','/etc/display'])==saved
        print('Display native UI: timeout, explicit keep, Escape, safe Enter, blocked UI, abrupt exit and close; durable settings: PASS',flush=True)

if __name__=='__main__':main()
