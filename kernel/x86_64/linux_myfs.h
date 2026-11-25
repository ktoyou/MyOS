#ifndef MYOS_LINUX64_MYFS_H
#define MYOS_LINUX64_MYFS_H

#include "linux.h"

struct boot_info;
#define LINUX64_MYFS_MOUNT "/profile"
#define LINUX64_MYFS_ROOT 1u

void linux64_myfs_mount(const struct boot_info *boot, const struct linux64_file_source *source);
bool linux64_myfs_mounted(void);
long linux64_myfs_stat(u32 ino, struct linux64_file *file);
long linux64_myfs_lookup(u32 parent, const char *name, struct linux64_file *file);
long linux64_myfs_next(u32 ino, uptr *position, char name[256], struct linux64_file *file);
long linux64_myfs_create(u32 parent, const char *name, const struct linux64_file *requested,
                         struct linux64_file *file);
long linux64_myfs_remove(u32 parent, const char *name, u32 ino);
long linux64_myfs_rename(u32 old_parent, const char *old_name, u32 new_parent, const char *new_name,
                         u32 victim);
long linux64_myfs_path(u32 ino, char *path);
long linux64_myfs_read(u32 ino, uptr offset, void *buffer, uptr length);
long linux64_myfs_write(u32 ino, uptr offset, const void *buffer, uptr length);
long linux64_myfs_truncate(u32 ino, uptr size);
long linux64_myfs_sync(void);
long linux64_myfs_retain(u32 ino);
void linux64_myfs_release(u32 ino);

#endif
