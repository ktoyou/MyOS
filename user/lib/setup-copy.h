#ifndef SETUP_COPY_H
#define SETUP_COPY_H
#include "installer.h"
struct setup_copy_result {
    unsigned files;
    unsigned long long bytes;
    char error[1400];
};
typedef void (*setup_copy_progress)(const char *phase,const char *path,unsigned files,unsigned long long bytes,void *arg);
int setup_copy(unsigned index,struct disk_install_info *info,struct setup_copy_result *result,setup_copy_progress progress,void *arg);
#endif
