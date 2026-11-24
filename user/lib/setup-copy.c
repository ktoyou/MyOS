/* Общая процедура для консольного и графического установщиков. */
#include "myos.h"
#include "setup-copy.h"
#include "sys/stat.h"
#include "unistd.h"
#include "utime.h"
#include "errno.h"
#include "stdio.h"
#include "string.h"

#define TARGET "/mnt/install"
#define PATH_CAP 1024
static unsigned source_dev, files;
static unsigned long long bytes;
static char data[32768];
static char last_error[1400];
static setup_copy_progress progress_hook;
static void *progress_arg;

static void progress(const char *phase,const char *path) {
    if(progress_hook)progress_hook(phase,path,files,bytes,progress_arg);
}

static int failure(const char *operation,const char *path,int error) {
    snprintf(last_error,sizeof(last_error),"%s %s: %s",operation,path,strerror(error));
    dprintf(STDERR,"setup: %s %s: %s\n",operation,path,strerror(error));return -1;
}
static int join(char *out,const char *parent,const char *name) {
    if(snprintf(out,PATH_CAP,"%s%s%s",parent,!strcmp(parent,"/")?"":"/",name)>=PATH_CAP)
        return failure("path too long:",parent,ENAMETOOLONG);
    return 0;
}
static int copy_tree(const char *source,const char *dest,unsigned depth) {
    progress("copy",source);
    struct stat st;
    if(depth>64)return failure("directory depth:",source,ELOOP);
    if(lstat(source,&st))return failure("stat",source,errno);
    if(st.st_dev!=source_dev)return 0; /* /dev и другие смонтированные тома не переносятся. */
    if(depth==1 && S_ISDIR(st.st_mode))printf("Copying %s...\n",source);
    if(S_ISLNK(st.st_mode)) {
        char link[PATH_CAP];int n=readlink(source,link,sizeof(link)-1);
        if(n<0)return failure("readlink",source,errno);
        if(n>=(int)sizeof(link)-1)return failure("symlink too long:",source,ENAMETOOLONG);
        link[n]=0;
        if(symlink(link,dest) || lchown(dest,st.st_uid,st.st_gid))return failure("symlink",dest,errno);
        files++;progress("copy",source);return 0;
    }
    if(S_ISDIR(st.st_mode)) {
        if(mkdir(dest,0700) && errno!=EEXIST)return failure("mkdir",dest,errno);
        struct dirent_info entry;
        for(int i=0;;i++) {
            int r=dirread(source,i,&entry);if(r<0)return failure("readdir",source,-r);if(!r)break;
            if(!strcmp(entry.name,".") || !strcmp(entry.name,".."))continue;
            char from[PATH_CAP],to[PATH_CAP];
            if(join(from,source,entry.name) || join(to,dest,entry.name))return -1;
            /* Закрытую базу учётных записей переносит ядро при commit. */
            if(!strcmp(from,"/etc/accounts"))continue;
            /* Точки монтирования сохраняются пустыми, без содержимого чужого тома. */
            struct stat child;if(lstat(from,&child))return failure("stat",from,errno);
            if(child.st_dev!=source_dev) {
                if(S_ISDIR(child.st_mode) && mkdir(to,0755) && errno!=EEXIST)return failure("mkdir",to,errno);
                continue;
            }
            if(copy_tree(from,to,depth+1))return -1;
        }
    } else if(S_ISREG(st.st_mode)) {
        int in=open(source,O_RDONLY);if(in<0)return failure("open",source,errno);
        int out=open(dest,O_WRONLY|O_CREAT|O_TRUNC,0600);
        if(out<0){close(in);return failure("create",dest,errno);}
        unsigned copied=0;int error=0;
        for(;;) {
            int n=read(in,data,sizeof(data));if(n<0){error=errno;break;}if(!n)break;
            for(int off=0;off<n;) {int w=write(out,data+off,n-off);if(w<=0){error=w<0?errno:EIO;break;}off+=w;}
            if(error)break;
            copied+=n;
        }
        if(close(out) && !error)error=errno;
        close(in);
        if(!error && copied!=st.st_size)error=EIO;
        if(error)return failure("copy",source,error);
        bytes+=copied;files++;
        progress("copy",source);
        if(!(files%100))printf("Copied %u files (%u MiB)\n",files,(unsigned)(bytes/1048576));
    } else return failure("unsupported file:",source,EINVAL);
    if(chown(dest,st.st_uid,st.st_gid) || chmod(dest,st.st_mode&01777))return failure("metadata",dest,errno);
    struct utimbuf times={st.st_atime,st.st_mtime};
    if(utime(dest,&times))return failure("timestamp",dest,errno);
    return 0;
}
static int install_execute(unsigned index,struct disk_install_info *info) {
    int r;files=0;bytes=0;last_error[0]=0;
    progress("prepare",info->device);
    struct stat root;if(stat("/",&root)){failure("stat","/",errno);goto abort;}
    source_dev=root.st_dev;
    struct stat config;
    if(lstat("/etc",&config) || !S_ISDIR(config.st_mode) || config.st_dev!=source_dev) {
        failure("requires a directory on the root filesystem:","/etc",EINVAL);goto abort;
    }
    if(mkdir("/mnt",0755) && errno!=EEXIST){failure("mkdir","/mnt",errno);goto abort;}
    if(mkdir(TARGET,0700) && errno!=EEXIST){failure("mkdir",TARGET,errno);goto abort;}
    r=disk_install(INSTALL_PREPARE,index,info);
    if(r<0){failure("prepare",info->device,-r);goto abort;}
    char partition[16];snprintf(partition,sizeof(partition),"%s%s1",info->device,!strncmp(info->device,"/dev/nvme",9)?"p":"");
    r=mount(partition,TARGET);if(r<0){failure("mount",partition,-r);goto abort;}
    puts("Copying the Live root filesystem...");
    int failed=copy_tree("/",TARGET,0);
    if(!failed) {
        /* Записи Live fstab могут выбрать посторонние физические диски. */
        if(remove(TARGET "/etc/fstab") && errno!=ENOENT)failed=failure("unlink","fstab",errno);
    }
    if(!failed) {
        int fd=open(TARGET "/etc/fstab",O_WRONLY|O_CREAT|O_TRUNC,0644);
        const char text[]="# Installed MyOS: root is selected by the boot disk ID.\n";
        if(fd<0)failed=failure("create","fstab",errno);
        else {if(write(fd,text,sizeof(text)-1)!=sizeof(text)-1)failed=failure("write","fstab",EIO);if(close(fd))failed=-1;}
    }
    r=umount(TARGET);if(r<0){failure("unmount",TARGET,-r);failed=-1;}
    if(failed)goto abort;
    puts("Checking filesystem and committing the boot loader...");
    progress("commit",info->device);
    r=disk_install(INSTALL_COMMIT,index,info);
    if(r<0){failure("commit",info->device,-r);goto abort;}
    printf("Installation complete: %u files, %u MiB.\nShut down, remove Live USB and boot the disk in BIOS/CSM or UEFI x64 mode.\n",files,(unsigned)(bytes/1048576));
    return 0;
abort:
    disk_install(INSTALL_ABORT,index,info);
    dprintf(STDERR,"setup: installation failed; the selected disk may contain an incomplete installation.\n");return 1;
}

int setup_copy(unsigned index,struct disk_install_info *info,struct setup_copy_result *result,setup_copy_progress hook,void *arg) {
    progress_hook=hook;progress_arg=arg;
    int code=install_execute(index,info);
    result->files=files;result->bytes=bytes;
    snprintf(result->error,sizeof(result->error),"%s",last_error);
    progress_hook=NULL;progress_arg=NULL;
    return code;
}
