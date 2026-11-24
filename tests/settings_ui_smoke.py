"""Клавиатурный ввод и фокус в настоящем окне настроек на временном Live-образе."""
import pathlib,re,tempfile,time
from disk_install_smoke import VM,run,uefi_firmware
from hardware_inventory_smoke import live_image,login
import hardware_smoke as hw
B=pathlib.Path('build')

def main():
    with tempfile.TemporaryDirectory(prefix='myos-settings-ui-') as directory:
        temp=pathlib.Path(directory);root=temp/'root.img'
        with root.open('wb') as f:f.truncate(64*1048576)
        for d in ['/bin','/lib','/lib/fonts','/etc','/root','/tmp']:
            run(B/'myfs',root,'mkdir',d)
        for name in ['sh','desktop','settings-ui-check','sleep','poweroff']:
            run(B/'myfs',root,'put',B/'user'/name,'/bin/'+name)
        for name,source in [('ld.so',B/'ld.so'),('libc.so',B/'user/libc.so'),('libgfx.so',B/'user/libgfx.so')]:
            run(B/'myfs',root,'put',source,'/lib/'+name)
        for font in pathlib.Path('fonts').glob('*.ttf'):run(B/'myfs',root,'put',font,'/lib/fonts/'+font.name)
        saved_wallpaper=temp/'wallpaper';saved_wallpaper.write_text('/usr/share/wallpapers/comet.jpg')
        run(B/'myfs',root,'put',saved_wallpaper,'/etc/wallpaper')
        source=temp/'usb.img';live_image(root,source,temp,uefi=True)
        before=hw.digest(source)
        vm=VM('settings-ui',uefi_firmware(temp,'live')+['-device','qemu-xhci,id=xhci',
            '-drive',f'if=none,id=stick,format=raw,file={source},snapshot=on',
            '-device','usb-storage,bus=xhci.0,drive=stick,bootindex=1'],memory='512M',binary='qemu-system-x86_64')
        def type_text(text):
            for char in text:vm.key({' ':'spc','/':'slash','.':'dot','-':'minus'}.get(char,char))
        def control_u():
            vm.qmp('send-key',{'keys':[{'type':'qcode','data':'ctrl'},{'type':'qcode','data':'u'}],'hold-time':35});time.sleep(.15)
        def state(key,page,focus):
            offset=len(hw.clean(vm.log));vm.key(key)
            vm.wait(f'SETTINGS UI: page={page} focus={focus} ',offset)
            return [line for line in hw.clean(vm.log)[offset:].splitlines() if line.startswith('SETTINGS UI:')][-1]
        try:
            login(vm)
            for i,line in enumerate(['desktop &','sleep 3','settings-ui-check','poweroff']):
                vm.send("echo '"+line+"' "+('>' if not i else '>>')+' /tmp/ui.sh','root:/')
            vm.send('sh /tmp/ui.sh','SETTINGS UI: page=0 focus=1 ')
            state('tab',0,2);control_u();type_text('1.2.3.4')
            vm.key('home');vm.key('delete');type_text('8');vm.key('end');vm.key('left');vm.key('backspace');type_text('.')
            line=state('ret',0,2)
            assert 'dns=[8.2.3.4]' in line and 'applies=0' in line,'Field Enter applied DNS or editing failed: '+line
            state('tab',0,3);line=state('ret',0,3)
            assert 'applies=1' in line,'Focused button did not activate'
            state('tab',0,1);state('down',1,1);line=state('tab',1,2)
            assert 'gallery=3' in line,'Gallery focus did not follow saved wallpaper'
            line=state('right',1,2)
            assert 'gallery=4' in line and 'path=[/usr/share/wallpapers/comet.jpg]' in line and 'status=[]' in line,'Gallery navigation applied wallpaper'
            state('tab',1,3);control_u()
            long_path='/root/'+('long-wallpaper-name-'*4)+'image.png';type_text(long_path)
            line=state('end',1,3)
            assert int(re.search(r'scroll=(\d+)',line)[1])>0,'Long field did not scroll'
            line=state('home',1,3);assert 'cursor=0 scroll=0' in line,'Home did not reveal beginning'
            line=state('ret',1,3);assert 'status=[]' in line,'Enter in path field applied settings'
            ppm=B/'settings-ui.ppm';vm.qmp('screendump',{'filename':str(ppm.resolve())});hw.save_png(ppm,B/'settings-ui.png')
            state('tab',1,4);line=state('ret',1,4)
            assert 'status=[]' not in line,'Focused wallpaper button did not run'
            state('tab',1,5);state('tab',1,1);state('down',2,1);state('tab',2,2)
            vm.key('esc');vm.wait('Powering off...');vm.p.wait(timeout=25)
        finally:vm.stop()
        assert hw.digest(source)==before,'Live source changed'
        print('Settings native UI: middle editing, Tab focus, guarded Enter, gallery, scrolling and keyboard buttons: PASS')

if __name__=='__main__':main()
