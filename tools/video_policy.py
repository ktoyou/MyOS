"""Общие пределы графики и небольшой C-модуль BIOS stage2."""
import pathlib,re,subprocess
def limits():
    header=pathlib.Path('user/lib/video_mode.h').read_text()
    return tuple(int(re.search(r'^#define '+name+r' (0x[0-9a-fA-F]+|[0-9]+)u?$',header,re.M)[1],0)
                 for name in ['VIDEO_MAX_WIDTH','VIDEO_MAX_HEIGHT','VIDEO_BUFFER_BYTES'])
def bios_policy():
    import fcntl
    directory=pathlib.Path('build/video-policy');directory.mkdir(parents=True,exist_ok=True)
    output=directory/'policy.bin'
    with (directory/'lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        sources=[pathlib.Path(p) for p in ['boot/video-policy.c','boot/video-policy.ld','user/lib/video_mode.h']]
        if not output.exists() or any(p.stat().st_mtime_ns>output.stat().st_mtime_ns for p in sources):
            subprocess.run(['gcc','-m32','-Os','-ffreestanding','-fno-pie','-fno-pic','-fno-stack-protector','-fno-builtin','-nostdlib','-nostdinc','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-mno-sse','-mno-mmx','-c',sources[0],'-o',directory/'policy.o'],check=True)
            subprocess.run(['ld','-m','elf_i386','-T','boot/video-policy.ld','--oformat','binary',directory/'policy.o','-o',output],check=True)
            if not output.stat().st_size or output.stat().st_size>4096:raise ValueError('BIOS video policy exceeds reserved stage2 area')
        w,h,size=limits();include=directory/'limits.inc'
        contents=f'%define VIDEO_MAX_W {w}\n%define VIDEO_MAX_H {h}\n%define VIDEO_BYTES {size}\n'
        if not include.exists() or include.read_text()!=contents:include.write_text(contents)
    return output
