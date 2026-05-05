// Used to interact with https://github.com/nyx-fuzz/nyx-lite
// Breakpoint hypercalls have been left out.

#ifndef NYX_LITE_H
#define NYX_LITE_H

#include <stdint.h>
#include <assert.h>

#define HYPERCALL_MAGIC     0x6574696c2d78796e

#define HYPERCALL_EXECDONE  0x656e6f6463657865
#define HYPERCALL_SNAPSHOT  0x746f687370616e73
#define HYPERCALL_SHAREMEM  0x6d656d6572616873
#define HYPERCALL_DBGPRINT  0x746e697270676264

// TODO: Experimental
#define HYPERCALL_FUZZABORT 0x7777777777777777

static inline void nyx_lite_hypercall(uint64_t hypercall_num, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4) {
    uint64_t rax = HYPERCALL_MAGIC;
    asm volatile(
        "int 3;"
        : "=r" (rax)
        : "0" (rax), "r" (hypercall_num), "r" (arg1), "r" (arg2), "r" (arg3), "r" (arg4)
        : "cc", "memory"
    );
    assert(rax == 0);
}

static inline void nyx_lite_register_region(char* name, unsigned char* mem, uint64_t mem_size) {
    nyx_lite_hypercall(HYPERCALL_SHAREMEM, (uintptr_t)name, (uintptr_t)mem, mem_size, 0);
}

static inline void nyx_lite_snapshot() {
    nyx_lite_hypercall(HYPERCALL_SNAPSHOT, 0, 0, 0, 0);
}

static inline void nyx_lite_execdone(uint64_t exit_code) {
    nyx_lite_hypercall(HYPERCALL_EXECDONE, exit_code, 0, 0, 0);
}

static inline void nyx_lite_debugprint(char* msg) {
    nyx_lite_hypercall(HYPERCALL_DBGPRINT, (uintptr_t)msg, 0, 0, 0);
}

static inline void nyx_lite_abort(char* msg) {
    nyx_lite_hypercall(HYPERCALL_FUZZABORT, (uintptr_t)msg, 0, 0, 0);
}

#endif
