#ifndef X86_64_PAGING_H
#define X86_64_PAGING_H

#include "pmm.h"

#define X64_USER_TOP 0x0000800000000000ul

bool paging64_init(const struct boot_info *boot);
uptr paging64_active_root(void);
void paging64_switch_root(uptr root);
uptr paging64_fork_root(void);
uptr paging64_exec_root(void);
void paging64_drop_root(uptr root);
void *paging64_user_page(uptr address);
bool paging64_reserve_stack(uptr start, uptr end);
bool paging64_zero_fault(uptr address, u64 error);
bool paging64_user_code(uptr address, const u8 *code, uptr length);
bool paging64_user_load(uptr address, const u8 *source, uptr offset, uptr length,
                        bool writable, bool executable);
const u8 *paging64_user_read(uptr address);
uptr paging64_copy_from_user(void *destination, uptr address, uptr length);
bool paging64_shared_futex_address(uptr address);
uptr paging64_copy_to_user(uptr address, const void *source, uptr length);
bool paging64_put_user_u16(uptr address, u16 value);
bool paging64_put_user_u32(uptr address, u32 value);
bool paging64_put_user_u64(uptr address, u64 value);
bool paging64_range_free(uptr start, uptr end);
enum paging64_protect_result {
    PAGING64_PROTECT_OK,
    PAGING64_PROTECT_UNMAPPED,
    PAGING64_PROTECT_DENIED,
};
enum paging64_protect_result paging64_protect(uptr start, uptr end, bool accessible,
                                             bool writable, bool executable,
                                             uptr (*reserved_end)(uptr));
uptr paging64_first_mapped(uptr start, uptr end);
bool paging64_remove_mmap(uptr start, uptr end);
enum paging64_discard_result {
    PAGING64_DISCARD_OK,
    PAGING64_DISCARD_HOLE,
    PAGING64_DISCARD_UNSUPPORTED,
};
enum paging64_discard_result paging64_discard_anon(uptr start, uptr end, uptr (*reserved_end)(uptr));
struct paging64_mmap_file {
    const u8 *bytes;
    uptr length, offset;
    uptr (*frame)(const void *object, uptr offset);
    const void *object;
};
bool paging64_map_mmap(uptr start, uptr end, const struct paging64_mmap_file *file,
                       bool accessible, bool writable, bool executable,
                       bool shared, bool no_write);

#endif
