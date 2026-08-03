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

/* Marks an update_map entry whose settings `runnable` has already applied. Out
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

/* Value of sched_delay_map: the published delay EWMA plus the epoch of the
 * settings it was measured under. Requiring a matching epoch is strictly
 * stronger than requiring a recent sample: the delay is measured in `running`
 * but only published in `stopping`, so a sample can arrive well after the write
 * that superseded it and still describe the old settings. */
typedef struct sched_delay {
    u64 ewma;   // ns
    u64 epoch;  // the epoch in force when the EWMA last took a sample
} sched_delay_t;

/* Audio-throughput measurement window, driven by userspace over
 * audio_expt_map. Distinct from target_ctx's audio_rate_max: that is a per-task
 * classification feature (peak demand, never reset), this is a workload-wide
 * count of writes over one experiment window.
 *
 * `state` carries the whole handshake. Userspace stores RUN to open a window,
 * then STOP to close it; the probe sees STOP on its next call and answers IDLE,
 * which tells userspace no probe will touch `count` again and it may read it.
 * Having the probe rather than userspace write IDLE is what makes the count
 * settled at that point — the probe cannot be mid-increment.
 *
 * The probe may never run again (silence, or an audio thread starved by the
 * injected delay), so userspace also gives up after a timeout and takes the
 * count as it stands; only the window's end boundary is fuzzy then. */
#define AUDIO_EXPT_IDLE 0  // no window open; count is settled and readable
#define AUDIO_EXPT_RUN  1  // window open, probe counting
#define AUDIO_EXPT_STOP 2  // close requested; probe acknowledges by storing IDLE

typedef struct audio_expt {
    u32 state;
    u32 count;  // pa_stream_write calls counted in the current window
} audio_expt_t;

typedef struct task_info {
    s32 prio;
    u8 kind;  // DSQ slot: 0 = shared (any kind), 1..cpu_kind_num = kind-only
    u8 cpu_prefer;
    u64 slice; // ns
    u64 expt_wait;  // experimental vtime DSQ deadline (ns); 0 = disabled
    /* Identifies which write these settings came from, so a published delay can
     * be tied back to the settings it ran under. Only the experiment reads it,
     * and it drives a whole cluster with one set of params, so a single counter
     * shared by every task is enough. */
    u64 epoch;
} sched_info_t;

typedef struct target_ctx {
    s32 prio;
    u64 slice; // ns
    u8 config;
    /* | 7 bits NOP | 1 bits ecore |*/
    u8 kind;  // DSQ slot: 0 = shared (any kind), 1..cpu_kind_num = kind-only
    u8 cpu_prefer;
    u64 expt_wait;  // experimental vtime DSQ deadline (ns); 0 = disabled
    u64 epoch;      // epoch of the settings above (see sched_info_t)

    u64 start_running;
    u64 sleep_start;
    u64 sleep_end;
    u64 runtime_ns;

    /* Scheduling delay: set when the task becomes runnable (wakeup) or is
     * preempted while still runnable (slice used up); consumed in running to
     * feed the EWMA below. */
    u64 wait_start;
    u64 sched_delay_ewma; // ns
    /* The epoch in force when sched_delay_ewma last took a sample. Captured at
     * sample time rather than at publish time: publishing happens in `stopping`,
     * by which point the task may already have picked up newer settings. */
    u64 sched_delay_epoch;

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
    /* Audio production rate, in pa_stream_write calls per second. The peak is
     * kept rather than the mean: a thread held off the CPU writes less audio
     * per second than it wants to, so the largest rate it ever reached is the
     * one that reflects its actual demand. Window state below feeds it. */
    u32 audio_rate_max;
    u32 audio_win_cnt;
    u64 audio_win_start;
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
    u32 audio_rate_max; // peak pa_stream_write calls/sec (see target_ctx)
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
