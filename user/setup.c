/* Консольный интерфейс сохраняет точное подтверждение стирания выбранного диска. */
#include "myos.h"
#include "setup-copy.h"
#include "unistd.h"
#include "stdio.h"
#include "string.h"
static int failure(const char *operation,const char *path,int error) {
    dprintf(STDERR,"setup: %s %s: %s\n",operation,path,strerror(error));return -1;
}
static int list(void) {
    int count=0;
    for(unsigned i=0;i<INSTALL_TARGETS;i++) {
        struct disk_install_info info;int r=disk_install(INSTALL_LIST,i,&info);if(r<0)continue;
        printf("%s  %u MiB  %s\n",info.device,info.sectors/2048,info.model);count++;
    }
    if(!count)puts("No unmounted SATA/AHCI or NVMe installation targets found.");
    return count;
}
int main(int argc,char **argv) {
    if(geteuid()){dprintf(STDERR,"setup: root login required\n");return 1;}
    if(argc!=2) {
        puts("Usage: setup --list | setup DEVICE | setup --gui\nExamples: /dev/sdc (SATA), /dev/nvme0 (NVMe namespace)\nBIOS/CSM and UEFI x64 (Secure Boot off). Erases the entire selected disk/namespace.");return 2;
    }
    if(!strcmp(argv[1],"--gui")){char *av[]={"setup-gui",NULL};exec("/bin/setup-gui",av);perror("setup-gui");return 1;}
    if(service_register("disk-setup")<0){dprintf(STDERR,"setup: another installer is running\n");return 1;}
    int r=disk_install(INSTALL_PROBE,0,NULL);
    if(r<0){failure("probe","SATA/AHCI or NVMe targets (boot from Live USB)",-r);return 1;}
    if(!strcmp(argv[1],"--list"))return list()?0:1;
    unsigned index=INSTALL_TARGETS;
    for(unsigned i=0;i<INSTALL_TARGETS;i++){struct disk_install_info info;if(!disk_install(INSTALL_LIST,i,&info) && !strcmp(info.device,argv[1]))index=i;}
    if(index==INSTALL_TARGETS){list();failure("invalid target:",argv[1],ENODEV);return 1;}
    struct disk_install_info info;
    r=disk_install(INSTALL_PLAN,index,&info);
    if(r<0){failure("plan",argv[1],-r);return 1;}
    printf("\nDisk: %s (%s), %u MiB\nMyFS root: %u MiB\n",info.device,info.model,info.sectors/2048,info.root_sectors/2048);
    puts("ALL DATA AND PARTITIONS ON THIS DISK WILL BE ERASED.\nOther operating systems will not be preserved.");
    char expected[40],answer[80];snprintf(expected,sizeof(expected),"erase %s",info.device);
    printf("Type exactly '%s' to install: ",expected);
    if(!fgets(answer,sizeof(answer),stdin)){disk_install(INSTALL_ABORT,index,&info);return 1;}
    answer[strcspn(answer,"\r\n")]=0;
    if(strcmp(answer,expected)){puts("Installation cancelled. Disk unchanged.");disk_install(INSTALL_ABORT,index,&info);return 1;}
    struct setup_copy_result result;return setup_copy(index,&info,&result,NULL,NULL);
}
