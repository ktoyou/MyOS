#include "../kernel/x86_64/paging.h"
#include "../kernel/x86_64/segments.h"

#define USER_CODE       0x400000u
#define USER_STACK      0x800000u

extern const u8 ring3_stack_start[], ring3_stack_end[];
extern const u8 ring3_kernel_start[], ring3_kernel_end[];
extern const u8 ring3_nx_start[], ring3_nx_end[];
extern const u8 ring3_write_start[], ring3_write_end[];

bool ring3_check(unsigned mode) {
    const u8 *start, *end;
    if (mode == 0) {
        start = ring3_stack_start;
        end = ring3_stack_end;
    } else if (mode == 1) {
        start = ring3_kernel_start;
        end = ring3_kernel_end;
    } else if (mode == 2) {
        start = ring3_nx_start;
        end = ring3_nx_end;
    } else {
        start = ring3_write_start;
        end = ring3_write_end;
    }
    uptr length = (uptr)end - (uptr)start;
    if (paging64_user_code(0x100000, start, length) ||
        paging64_user_page(X64_DIRECT_BASE))
        return false;

    if (!paging64_user_code(USER_CODE, start, length) || !paging64_user_page(USER_STACK) ||
        paging64_user_page(USER_CODE))
        return false;
    segments64_enter_user(USER_CODE, USER_STACK + PMM_PAGE_SIZE);
}
