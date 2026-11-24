"""Native threads on disposable disks: oversubscription, SMP, lifetime and TLB."""
import argparse,pathlib,re,shutil,subprocess,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parent.parent
B=ROOT/'build'
def run(cpus,extra=(),tls_only=False):
    suffix=f'{cpus}'+('-fallback' if extra else '')
    mode='tls' if tls_only else 'thread'
    with tempfile.TemporaryDirectory(prefix='myos-threads-') as temp:
        temp=pathlib.Path(temp); image=temp/'disk.img'
        shutil.copyfile(B/f'{mode}-base.img',image)
        log=temp/'serial.log';log.touch()
        with (B/f'{mode}-{suffix}.stderr').open('w') as err:
            p=subprocess.Popen(['qemu-system-i386','-smp',str(cpus),'-m','256M','-display','none',
                '-drive','format=raw,file=build/os.img,index=0,snapshot=on',
                '-drive',f'format=raw,file={image},index=1','-nic','none',
                '-serial',f'file:{log}','-monitor','stdio','-no-reboot',*extra],
                cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=err,text=True)
            def text(): return re.sub(r'\x1b\[[0-9;?]*[A-Za-z]','',log.read_text(errors='replace')).replace('\r','')
            def wait(marker,after=0,timeout=100):
                end=time.monotonic()+timeout
                while time.monotonic()<end:
                    s=text()
                    if any(x in s for x in ('PANIC','THREAD FAIL','SMP FAIL','TLS FAIL','Segmentation fault')): raise AssertionError(s[-5000:])
                    if marker in s[after:]:return
                    if p.poll() is not None:raise AssertionError('QEMU exited: '+s[-4000:])
                    time.sleep(.05)
                raise AssertionError(marker+' missing: '+text()[-5000:])
            def send(s,marker):
                start=len(text())
                for c in s+'\n':
                    key={'\n':'ret',' ':'spc','/':'slash','-':'minus'}.get(c,c)
                    p.stdin.write('sendkey '+key+' 10\n');p.stdin.flush();time.sleep(.04)
                wait(marker,start)
            try:
                wait('New password:');send('smp123','Confirm password:')
                send('smp123','Login [root]:');send('','Password:');send('smp123','root:/')
                if tls_only:
                    send('tlscheck','TLS PASS static image, threads, fork and exec')
                    print(f'Static TLS {suffix} CPUs: PASS',flush=True)
                else:
                    expected=1 if extra else cpus
                    send(f'threadcheck {expected}',f'THREAD PASS count=100 cpus={expected}')
                    send('smpcheck '+str(expected),f'SMP PASS online={expected} executed={expected}')
                    print(f'Threads {suffix} CPUs: PASS',flush=True)
            finally:
                p.terminate()
                try:p.wait(timeout=5)
                except subprocess.TimeoutExpired:p.kill();p.wait()
                (B/f'{mode}-{suffix}.log').write_text(text())
if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--tls-only',action='store_true')
    args=parser.parse_args()
    B.mkdir(exist_ok=True)
    if args.tls_only:
        tls_image=B/'tls-base.img'
        with tls_image.open('wb') as image:
            image.truncate(8 * 1024 * 1024)
        subprocess.run(['make','-j4','build/os.img','build/myfs','build/user/sh','build/user/tlscheck'],cwd=ROOT,check=True,stdout=subprocess.DEVNULL)
        for name in ('sh','tlscheck'):
            subprocess.run(['build/myfs',str(tls_image),'put','build/user/'+name,'/bin/'+name],cwd=ROOT,check=True)
        for cpus in (1,4):
            run(cpus,tls_only=True)
        raise SystemExit(0)
    # Recreate only this disposable fixture; a full install exceeds 64 MiB.
    with (B/'thread-base.img').open('wb') as image:
        image.truncate(128 * 1024 * 1024)
    subprocess.run(['make','-j4','build/os.img','build/user/threadcheck','build/user/smpcheck','install','DISK=build/thread-base.img'],cwd=ROOT,check=True,stdout=subprocess.DEVNULL)
    for name in ('threadcheck','smpcheck'):
        subprocess.run(['build/myfs','build/thread-base.img','put','build/user/'+name,'/bin/'+name],cwd=ROOT,check=True)
    subprocess.run(['build/myfs','build/thread-base.img','rm','/etc/accounts'],cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    for cpus in (1,2,4,8):run(cpus)
    run(4,('-machine','pc,acpi=off'))
