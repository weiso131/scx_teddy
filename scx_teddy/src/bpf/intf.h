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

#define OTHER_DSQ 200
#define CRITICAL_DSQ 201
#define INTERACTIVE_DSQ 202
#define NORMAL_DSQ 203
#define CRITICAL_WAKEUP_DSQ 204
#define INTERACTIVE_WAKEUP_DSQ 205

#define DSQ_NUM 6

#define DEFAULT_SLICE 100 * 1000

#define TIER_CRITICAL 0
#define TIER_INTERACTIVE 1
#define TIER_NORMAL 2
#define TIER_OTHER 3

typedef struct target_ctx {
    s32 prio; // 0, 1, 2
    u64 slice; // ns
    u8 config;
    /* | 7 bits NOP | 1 bits ecore |*/
    u64 runtime_ns;
    u64 start_running;
    u64 sleep_start;
    u64 sleep_end;
} target_ctx_t;

typedef struct task_event {
    int tid;  // Thread ID (statistics are per-TID)
    int parent;
    unsigned long long sleep_start;
    unsigned long long sleep_end;
    unsigned long long runtime_ns;
} task_event_t;

#define CONFIG_STOP_RINGBUF 0
