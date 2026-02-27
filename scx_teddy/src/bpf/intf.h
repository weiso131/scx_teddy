#include <limits.h>
#include <stdbool.h>

/* Type defs for BPF/userspace compat - defined when vmlinux.h is not included */
#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;
#endif

#define MODE_TID    0  
#define MODE_TGID   1

#define NORMAL_TASK_DSQ 200
#define TARGET_CRITICAL_DSQ 201
#define TARGET_INTERACTIVE_DSQ 202
#define TARGET_NORMAL_DSQ 203

#define DSQ_NUM 5

#define NORMAL_TASK_SLICE 100 * 1000

#define TIER_CRITICAL 0
#define TIER_INTERACTIVE 1
#define TIER_NORMAL 2

typedef struct target_ctx {
    s32 prio; // 0, 1, 2
    u64 slice; // ns
    u8 on_ecore;
} target_ctx_t;
