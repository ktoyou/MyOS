#ifndef X86_64_PAGING_H
#define X86_64_PAGING_H

#include "pmm.h"

#define X64_USER_TOP 0x0000800000000000ul

bool paging64_init(const struct boot_info *boot);
void *paging64_user_page(uptr address);
bool paging64_user_code(uptr address, const u8 *code, uptr length);
bool paging64_user_load(uptr address, const u8 *source, uptr offset, uptr length,
                        bool writable, bool executable);
const u8 *paging64_user_read(uptr address);
uptr paging64_copy_from_user(void *destination, uptr address, uptr length);
bool paging64_shared_futex_address(uptr address);
uptr paging64_copy_to_user(uptr address, const void *source, uptr length);
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
bool paging64_map_mmap(uptr start, uptr end, const u8 *source, uptr file_bytes,
                       bool anonymous, bool accessible, bool writable, bool executable,
                       bool immutable_shared);

#endif
