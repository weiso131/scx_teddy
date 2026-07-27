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

#define DSQ_BASE 200
/* Experimental vtime DSQ block, kept in a low id range that never overlaps
 * DSQ_BASE. One slot per (1 + cpu_kind_num): slot 0 = shared, slot k = kind k.
 * A task with target_ctx->wait != 0 is inserted here with vtime = now + wait,
 * meaning it may not run until that deadline passes. */
#define EXP_DSQ_BASE 100
#define PRIORITY_NUM 12
#define CRITICAL_PRIO 4 // prio < 4 is critical
#define DEFAULT_PRIO 11 // use lowest priority as default

/* Marks an update_map entry whose settings `stopping` has already applied. Out
 * of the valid priority range, so it can never be mistaken for a real setting.
 *
 * The entry itself tracks task liveness instead: init_task creates it and
 * exit_task deletes it, so a write with BPF_EXIST fails exactly when the task is
 * gone. That is what keeps a dead task's entry from being recreated by a writer
 * that has not noticed the exit yet. */
#define PRIO_CONSUMED PRIORITY_NUM

#define DEFAULT_SLICE 100 * 1000

/* Scheduling-delay EWMA weight: new = (old + sample * (N-1)) / N, with
 * N = 1 << EWMA_SHIFT. The sample carries the (N-1)/N weight, so the average
 * tracks the current delay quickly. The old 1/N sample weight made the value
 * climb far too slowly for tasks that wake infrequently: the experiment injects
 * a delay and only gets a handful of samples before measuring, so a slow EWMA
 * still reads mostly pre-injection delay. Plain integer mul/div for now;
 * fixed-point later. */
#define EWMA_SHIFT 3

/* Upper bound on logical CPUs for the topology arrays below. */
#define MAX_CPU 255

/* Upper bound on distinct CPU kinds (freq tiers). A compile-time cap is needed
 * to bound the DSQ-creation loop for the verifier; real hardware has 1-3. */
#define MAX_CPU_KIND 8

#define CPU_NO_PREFER 0
#define CPU_FAST_PREFER 1
#define CPU_SLOW_PREFER 2

/* Per-CPU topology */
typedef struct cpu_info {
    u8 cpu_kind;  // 1 = fastest kind
    u32 freq_n;   // numerator   = this CPU's max_freq (kHz)
    u32 freq_d;   // denominator = fastest CPU's max_freq (kHz)
} cpu_info_t;

/* Value of sched_delay_map: the published delay EWMA plus the time its last
 * sample was taken. The stamp lets userspace require a *newer* sample than one
 * it saw earlier, instead of re-reading an average that has not moved because
 * the task never woke. */
typedef struct sched_delay {
    u64 ewma;   // ns
    u64 stamp;  // scx_bpf_now when the EWMA last took a sample (ns)
} sched_delay_t;

typedef struct task_info {
    s32 prio;
    u8 kind;  // DSQ slot: 0 = shared (any kind), 1..cpu_kind_num = kind-only
    u8 cpu_prefer;
    u64 slice; // ns
    u64 expt_wait;  // experimental vtime DSQ deadline (ns); 0 = disabled
} sched_info_t;

typedef struct target_ctx {
    s32 prio;
    u64 slice; // ns
    u8 config;
    /* | 7 bits NOP | 1 bits ecore |*/
    u8 kind;  // DSQ slot: 0 = shared (any kind), 1..cpu_kind_num = kind-only
    u8 cpu_prefer;
    u64 expt_wait;  // experimental vtime DSQ deadline (ns); 0 = disabled

    u64 start_running;
    u64 sleep_start;
    u64 sleep_end;
    u64 runtime_ns;

    /* Scheduling delay: set when the task becomes runnable (wakeup) or is
     * preempted while still runnable (slice used up); consumed in running to
     * feed the EWMA below. */
    u64 wait_start;
    u64 sched_delay_ewma; // ns
    /* When sched_delay_ewma last took a sample (scx_bpf_now, ns). Lets a reader
     * tell a fresh average from one a sleeping task left behind. */
    u64 sched_delay_stamp;

    u64 last_send_time;

    u32 event_cnt;
    u64 sleep_sum; // use 1e-6 sec
    u64 sleep_sq_sum;
    u64 runtime_sum;
    u64 runtime_sq_sum;
    u32 sleep_cnt; // 1 ns add 1 still not overflow
    u32 in_iowait_cnt;
    u32 futex_wait_cnt;
    u32 ntsync_wait_cnt;
    u8 audio_producer;
} target_ctx_t;

typedef struct task_event {
    s32 tid;  // Thread ID (statistics are per-TID)
    s32 parent;
    u32 event_cnt;
    u64 sleep_sum; // use 1e-6 sec
    u64 sleep_sq_sum;
    u64 runtime_sum;
    u64 runtime_sq_sum;
    u32 sleep_cnt;
    u32 in_iowait_cnt;
    u32 futex_wait_cnt;
    u32 ntsync_wait_cnt;
    u8 audio_producer; // sticky: 1 if this task ever produced audio (see target_ctx)
} task_event_t;

#define CONFIG_STOP_RINGBUF 0

#define RUNTIME_MAX_TIME 100000000

/* ntsync wait ioctl command numbers (the _IOC nr field), from
 * uapi/linux/ntsync.h's NTSYNC_IOC_WAIT_ANY / NTSYNC_IOC_WAIT_ALL. The kprobe
 * hooks ntsync_char_ioctl directly, so every cmd it sees already belongs to
 * ntsync; masking cmd down to its 8-bit nr and matching these is enough to pick
 * out the two wait ioctls without depending on the ioctl's encoded size. */
#define NTSYNC_WAIT_ANY_NR 0x82
#define NTSYNC_WAIT_ALL_NR 0x83
