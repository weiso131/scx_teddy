// SPDX-License-Identifier: GPL-2.0
/* scx_teddy - A BPF scheduler based on task runtime characteristics */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/* CPU topology, filled by userspace (topology.rs) into rodata before load. */
const volatile u8 cpu_num;       // number of online logical CPUs in use
const volatile u8 cpu_kind_num;  // number of distinct freq kinds (>= 1)
/* CPUs sorted by speed. cpus_fast_to_slow[0] is the fastest CPU id;
 * cpus_slow_to_fast is the reverse. Only the first `cpu_num` entries are set. */
const volatile u8 cpus_fast_to_slow[MAX_CPU];
const volatile u8 cpus_slow_to_fast[MAX_CPU];
/* Indexed by logical CPU id. */
const volatile cpu_info_t cpu_info[MAX_CPU];

/* Fastest / slowest CPU kind. Kinds are 1-based with kind 1 = fastest (see
 * topology.rs CpuInfo::cpu_kind), so the fastest kind is always 1 and the
 * slowest is the highest kind id, cpu_kind_num. Used to honour CPU_FAST_PREFER
 * / CPU_SLOW_PREFER in select_cpu. */
#define FASTEST_KIND 1
#define SLOWEST_KIND cpu_kind_num

/* DSQ layout
 * ----------
 * Each priority owns a contiguous block of (1 + cpu_kind_num) DSQs starting at
 * DSQ_BASE, in priority order (prio 0 first). Within a priority block the slot
 * is the CPU kind:
 *   slot 0          = the shared DSQ — any CPU kind may pull from it.
 *   slot 1..kind_num = the kind-only DSQ for that CPU kind (kinds are 1-based,
 *                      kind 1 = fastest; see topology.rs CpuInfo::cpu_kind).
 * Total DSQ count is PRIORITY_NUM * (1 + cpu_kind_num).
 *
 * dispatch pulls slot 0 (shared, "runs anywhere") before the running CPU's own
 * kind slot within a priority, and walks priorities 0 -> PRIORITY_NUM-1.
 */

/* Number of DSQs in one priority block. */
static __always_inline u32 dsq_per_prio(void)
{
    return 1 + cpu_kind_num;
}

/* DSQ id for a priority and slot. slot 0 = shared, slot k = CPU kind k. */
static __always_inline u64 dsq_id(s32 prio, u32 kind)
{
    return DSQ_BASE + (u64)prio * dsq_per_prio() + kind;
}

/* P-core deadline. The fastest-kind DSQs (kind == FASTEST_KIND) are vtime DSQs,
 * not FIFO: every task is inserted with vtime = now + this deadline. Once that
 * deadline passes, an E-core may pull the task instead of letting it keep
 * waiting behind a P-core hog (e.g. a game busy-waiting that pins the P-cores).
 * 10 ms for now; the same deadline notion is later meant to feed the cpu_prefer
 * mechanism. */
#define P_CORE_DEADLINE_NS (10 * 1000 * 1000ULL)

/* The fastest CPU kind's DSQs are run as vtime DSQs (deadline ordering) so that
 * stalled P-core tasks can be rescued by E-cores. Every other kind stays FIFO.
 * Keep this the single source of truth: a DSQ must be inserted into with vtime
 * IFF this returns true, never mixing FIFO and vtime in the same DSQ. */
static __always_inline bool kind_is_vtime(u32 kind)
{
    return kind == FASTEST_KIND;
}

/* Insert p into the per-(prio,kind) DSQ, choosing FIFO vs vtime by kind. The
 * fastest kind goes into its vtime DSQ with a deadline of now + P_CORE_DEADLINE_NS;
 * all other kinds use plain FIFO insertion. */
static __always_inline void insert_kind_dsq(struct task_struct *p, s32 prio,
                                            u32 kind, u64 slice, u64 enq_flags)
{
    if (kind_is_vtime(kind)) {
        u64 vtime = scx_bpf_now() + P_CORE_DEADLINE_NS;
        scx_bpf_dsq_insert_vtime(p, dsq_id(prio, kind), slice, vtime, enq_flags);
    } else {
        scx_bpf_dsq_insert(p, dsq_id(prio, kind), slice, enq_flags);
    }
}

/* Experimental DSQ id for a kind slot. slot 0 = shared, slot k = CPU kind k. */
static __always_inline u64 exp_dsq_id(u32 kind)
{
    return EXP_DSQ_BASE + kind;
}

/* Insert p into the experimental vtime DSQ for its kind, with a deadline of
 * now + target_ctx->expt_wait. The task may not run until that deadline passes
 * (dispatch pulls it only once now >= vtime). */
static __always_inline void insert_exp_dsq(struct task_struct *p,
                                           target_ctx_t *target_ctx, u64 enq_flags)
{
    u64 vtime = scx_bpf_now() + target_ctx->expt_wait;
    scx_bpf_dsq_insert_vtime(p, exp_dsq_id(target_ctx->kind), target_ctx->slice,
                             vtime, enq_flags);
}

static __always_inline u64 ewma_decay(u64 old, u64 sample)
{
    if (unlikely(old == 0))
        return sample;
    return (old * ((1ULL << EWMA_SHIFT) - 1) + sample) >> EWMA_SHIFT;
}

static __always_inline void update_sched_delay(target_ctx_t *target_ctx, u64 now)
{
    if (unlikely(target_ctx->wait_start == 0))
        return;
    u64 sample = now - target_ctx->wait_start;
    if (unlikely(sample == 0))
        sample = 1;
    target_ctx->sched_delay_ewma = ewma_decay(target_ctx->sched_delay_ewma, sample);
    target_ctx->wait_start = 0;
}

#define MIN_SEND_INTERVAL 100000000

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, target_ctx_t);
} task_ctx SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} scheduler_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256 * 1024);
    __type(key, s32);
    __type(value, sched_info_t);
} update_map SEC(".maps");

/* Per-tid scheduling-delay EWMA, exposed to userspace off the ringbuf hot path.
 * key = tid, value = sched_delay_ewma (ns). Written under the same throttle as
 * the ringbuf event (see try_data_to_user); the value is a single aligned u64,
 * so a userspace lookup copies it out without tearing — no lock needed. Lets the
 * expt_tolerance experiment loop read a task's real delay directly instead of
 * waiting for a ringbuf event. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256 * 1024);
    __type(key, s32);
    __type(value, u64);
} sched_delay_map SEC(".maps");

static void try_data_to_user(struct task_struct *p, target_ctx_t *target_ctx)
{
    u32 key = CONFIG_STOP_RINGBUF;
    u32 *pause_ringbuf = bpf_map_lookup_elem(&scheduler_config, &key);

    if (*pause_ringbuf) {
        return; // don't clear the data
    }
    
    u64 now = scx_bpf_now();

    if (now - target_ctx->last_send_time < MIN_SEND_INTERVAL)
        return;
    target_ctx->last_send_time = now;

    /* Publish the current delay EWMA for userspace to read directly (off the
     * ringbuf path). Same throttle as the event below. */
    s32 delay_key = p->pid;
    u64 delay = target_ctx->sched_delay_ewma;
    bpf_map_update_elem(&sched_delay_map, &delay_key, &delay, BPF_ANY);

    task_event_t *e = bpf_ringbuf_reserve(&events, sizeof(task_event_t), 0);
    if (!e) {
        //bpf_printk("RINGBUF_FULL");
        return; // Ring buffer full, drop event
    }

    // Fill event data
    e->tid = p->pid;
    e->parent = p->real_parent->pid;
    e->event_cnt = target_ctx->event_cnt;
    e->sleep_sum = target_ctx->sleep_sum;
    e->sleep_sq_sum = target_ctx->sleep_sq_sum;
    e->runtime_sum = target_ctx->runtime_sum;
    e->runtime_sq_sum = target_ctx->runtime_sq_sum;
    e->sleep_cnt = target_ctx->sleep_cnt;
    e->in_iowait_cnt = target_ctx->in_iowait_cnt;
    e->futex_wait_cnt = target_ctx->futex_wait_cnt;

    // Submit to ring buffer
    bpf_ringbuf_submit(e, 0);

    target_ctx->event_cnt = 0;
    target_ctx->sleep_sum = 0;
    target_ctx->sleep_sq_sum = 0;
    target_ctx->runtime_sum = 0;
    target_ctx->runtime_sq_sum = 0;
    target_ctx->sleep_cnt = 0;
    target_ctx->in_iowait_cnt = 0;
    target_ctx->futex_wait_cnt = 0;
}

static target_ctx_t *get_target_storage(struct task_struct *p)
{
    target_ctx_t *target_ctx;
    target_ctx = bpf_task_storage_get(&task_ctx, p, 0, 0);

    if (unlikely(!target_ctx)) {
        target_ctx = bpf_task_storage_get(&task_ctx, p, 0,
                               BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (unlikely(!target_ctx))
            return NULL;
        s32 key = p->pid;
        target_ctx->slice = DEFAULT_SLICE;
        target_ctx->prio = DEFAULT_PRIO;
        target_ctx->config = 1;
        target_ctx->kind = 0; // default: shared DSQ (no kind restriction)
        target_ctx->expt_wait = 0; // experimental vtime DSQ disabled by default
        target_ctx->last_send_time = bpf_ktime_get_ns();

        target_ctx->start_running = target_ctx->sleep_start = target_ctx->sleep_end = target_ctx->runtime_ns = 0;
        target_ctx->wait_start = target_ctx->sched_delay_ewma = 0;
    }

    return target_ctx;
}

/* Does a CPU satisfy this task's kind restriction? kind 0 = no restriction. */
static __always_inline bool cpu_kind_ok(s32 cpu, target_ctx_t *target_ctx)
{
    return target_ctx->kind == 0 || cpu_info[cpu].cpu_kind == target_ctx->kind;
}

/* Does a CPU satisfy this task's fast/slow preference? */
static __always_inline bool cpu_prefer_ok(s32 cpu, target_ctx_t *target_ctx)
{
    switch (target_ctx->cpu_prefer) {
    case CPU_FAST_PREFER:
        return cpu_info[cpu].cpu_kind == FASTEST_KIND;
    case CPU_SLOW_PREFER:
        return cpu_info[cpu].cpu_kind == SLOWEST_KIND;
    default: // CPU_NO_PREFER
        return true;
    }
}

/* Walk CPUs in the given speed order and claim the first idle one that
 * satisfies the task's affinity and kind. Returns the claimed CPU (already
 * marked non-idle via test_and_clear) or -1 if none. `order` is one of
 * cpus_fast_to_slow / cpus_slow_to_fast. */
static __always_inline s32 pick_idle_in_order(struct task_struct *p,
                                              target_ctx_t *target_ctx,
                                              const volatile u8 *order)
{
    for (u32 i = 0; i < MAX_CPU; i++) {
        if (i >= cpu_num)
            break;
        s32 cpu = order[i];
        if (!cpu_kind_ok(cpu, target_ctx))
            continue;
        if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
            continue;
        /* test_and_clear atomically claims the idle CPU: once it returns true
         * we own it and must dispatch to it. */
        if (scx_bpf_test_and_clear_cpu_idle(cpu))
            return cpu;
    }
    return -1;
}

s32 BPF_STRUCT_OPS(teddy_select_cpu, struct task_struct *p, s32 prev_cpu,
                   u64 wake_flags)
{
    target_ctx_t *target_ctx = get_target_storage(p);
    if (!target_ctx) {
        scx_bpf_dsq_insert(p, dsq_id(DEFAULT_PRIO, 0), DEFAULT_SLICE, wake_flags);
        return prev_cpu;
    }

    /* Experimental: a task with expt_wait set goes straight into the experimental
     * vtime DSQ and skips the rest of select_cpu (and enqueue). */
    if (target_ctx->expt_wait != 0) {
        insert_exp_dsq(p, target_ctx, wake_flags);
        return prev_cpu;
    }

    if (target_ctx->prio >= CRITICAL_PRIO) {
        insert_kind_dsq(p, target_ctx->prio, target_ctx->kind, DEFAULT_SLICE, wake_flags);
        return prev_cpu;
    }

    if (wake_flags & SCX_WAKE_SYNC) {
        s32 sync_cpu = bpf_get_smp_processor_id();
        if (bpf_cpumask_test_cpu(sync_cpu, p->cpus_ptr) &&
            cpu_kind_ok(sync_cpu, target_ctx) &&
            cpu_prefer_ok(sync_cpu, target_ctx) &&
            scx_bpf_test_and_clear_cpu_idle(sync_cpu)) {
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u64)sync_cpu, target_ctx->slice, wake_flags);
            return sync_cpu;
        }
    }

    s32 cpu = -1;

    /* No fast/slow preference: let the default picker find an idle CPU. */
    if (target_ctx->cpu_prefer == CPU_NO_PREFER && target_ctx->kind == 0) {
        bool is_idle;
        cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
        if (!is_idle)
            cpu = -1;
    } else {
        /* Fast/slow preference: scan CPUs in the preferred speed order and claim
        * the first idle one that fits kind + affinity. */
        const volatile u8 *order = (target_ctx->cpu_prefer == CPU_FAST_PREFER)
                                ? cpus_fast_to_slow : cpus_slow_to_fast;
        cpu = pick_idle_in_order(p, target_ctx, order);
    }

    if (cpu >= 0) {
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u64)cpu, target_ctx->slice, wake_flags);
        return cpu;
    }

    return prev_cpu;
}

void BPF_STRUCT_OPS(teddy_enqueue, struct task_struct *p, u64 enq_flags)
{
    target_ctx_t *target_ctx = get_target_storage(p);
    if (!target_ctx) {
        /* No ctx: fall back to the lowest-priority shared DSQ (batch). */
        scx_bpf_dsq_insert(p, dsq_id(DEFAULT_PRIO, 0), DEFAULT_SLICE, enq_flags);
        return;
    }

    /* Experimental: expt_wait set -> experimental vtime DSQ (same as select_cpu). */
    if (target_ctx->expt_wait != 0) {
        insert_exp_dsq(p, target_ctx, enq_flags);
        return;
    }

    insert_kind_dsq(p, target_ctx->prio, target_ctx->kind,
                    target_ctx->slice, enq_flags);
}

void BPF_STRUCT_OPS(teddy_dispatch, s32 cpu, struct task_struct *prev)
{
    /* cpu is the running CPU id, always in [0, cpu_num) — but the verifier
     * treats the s32 arg as possibly negative, so cpu_info[cpu] would read
     * out of bounds in its eyes. Clamp explicitly so the index is provably
     * within [0, MAX_CPU). */
    if (cpu < 0 || cpu >= MAX_CPU)
        return;
    /* This CPU's kind selects which kind-only DSQ this CPU may pull from. */
    u32 kind = cpu_info[cpu].cpu_kind;

    /* Experimental: highest priority of all. Pull from the experimental vtime
     * DSQ (shared slot then this CPU's kind slot) only when the head task's
     * deadline has passed — a task waits there until now >= its vtime. */
    {
        u64 now_exp = scx_bpf_now();
        struct task_struct *head = scx_bpf_dsq_peek(exp_dsq_id(0));
        if (head && now_exp >= head->scx.dsq_vtime) {
            if (scx_bpf_dsq_move_to_local(exp_dsq_id(0)))
                return;
        }
        head = scx_bpf_dsq_peek(exp_dsq_id(kind));
        if (head && now_exp >= head->scx.dsq_vtime) {
            if (scx_bpf_dsq_move_to_local(exp_dsq_id(kind)))
                return;
        }
    }

    /* A non-fastest CPU (e.g. an E-core) may also rescue tasks stranded on the
     * fastest-kind (P-core) vtime DSQ once their deadline has passed — see
     * P_CORE_DEADLINE_NS. This keeps a P-core hog (a busy-waiting game) from
     * starving P-core-bound work indefinitely. */
    bool is_e_core = !kind_is_vtime(kind);
    u64 now = scx_bpf_now();

    /* Walk priorities high -> low. Within each priority, pull the shared
     * (any-kind) DSQ before this CPU's own kind DSQ — "runs anywhere" wins. */
    for (s32 prio = 0; prio < PRIORITY_NUM; prio++) {
        if (scx_bpf_dsq_move_to_local(dsq_id(prio, 0)))
            return;
        if (scx_bpf_dsq_move_to_local(dsq_id(prio, kind)))
            return;
        if (is_e_core) {
            struct task_struct *head = scx_bpf_dsq_peek(dsq_id(prio, FASTEST_KIND));
            if (head && now > head->scx.dsq_vtime) {
                if (scx_bpf_dsq_move_to_local(dsq_id(prio, FASTEST_KIND)))
                    return;
            }
        }
    }
}

void BPF_STRUCT_OPS(teddy_tick, struct task_struct *p)
{
}

/* Initialize the scheduler */
s32 BPF_STRUCT_OPS_SLEEPABLE(teddy_init)
{
    /* Dump the topology rodata filled by userspace (topology.rs), visible via
     * `cat /sys/kernel/debug/tracing/trace_pipe`. Loops are bounded by MAX_CPU
     * (compile-time) for the verifier and broken early at cpu_num. */
    bpf_printk("teddy topo: cpu_num=%u cpu_kind_num=%u", cpu_num, cpu_kind_num);
    for (u32 i = 0; i < MAX_CPU; i++) {
        if (i >= cpu_num)
            break;
        bpf_printk("teddy topo: cpu%u kind=%u freq=%u/%u",
                   i, cpu_info[i].cpu_kind, cpu_info[i].freq_n, cpu_info[i].freq_d);
    }
    for (u32 i = 0; i < MAX_CPU; i++) {
        if (i >= cpu_num)
            break;
        bpf_printk("teddy topo: order[%u] fast_to_slow=%u slow_to_fast=%u",
                   i, cpus_fast_to_slow[i], cpus_slow_to_fast[i]);
    }

    /* Create the DSQs now that the topology is known: PRIORITY_NUM priority
     * blocks of (1 + cpu_kind_num) DSQs each (slot 0 shared + one per kind).
     * The loop is bounded by the compile-time max (PRIORITY_NUM * (1 +
     * MAX_CPU_KIND)) for the verifier and broken early at the real count. */
    u32 dsq_total = (u32)PRIORITY_NUM * dsq_per_prio();
    for (u32 i = 0; i < PRIORITY_NUM * (1 + MAX_CPU_KIND); i++) {
        if (i >= dsq_total)
            break;
        s32 ret = scx_bpf_create_dsq(DSQ_BASE + i, -1);
        if (ret < 0)
            return ret;
    }

    /* Experimental vtime DSQ block: 1 + cpu_kind_num slots (shared + per kind),
     * not split by priority. Bounded by the compile-time max for the verifier. */
    for (u32 i = 0; i < 1 + MAX_CPU_KIND; i++) {
        if (i >= dsq_per_prio())
            break;
        s32 ret = scx_bpf_create_dsq(EXP_DSQ_BASE + i, -1);
        if (ret < 0)
            return ret;
    }

    return 0;
}

void BPF_STRUCT_OPS(teddy_runnable, struct task_struct *p, u64 enq_flags)
{
    target_ctx_t *target_ctx = get_target_storage(p);
    if (!target_ctx)
        return;
    u64 now = scx_bpf_now();
    /* Scheduling delay starts counting the moment the task becomes runnable. */
    target_ctx->wait_start = now;
    if (enq_flags & SCX_ENQ_WAKEUP)
        target_ctx->sleep_end = now;
}

void BPF_STRUCT_OPS(teddy_running, struct task_struct *p)
{
    target_ctx_t *target_ctx = get_target_storage(p);
    if (!target_ctx)
        return;
    u64 now = scx_bpf_now();
    update_sched_delay(target_ctx, now);
    target_ctx->start_running = now;
}

static void update_event_data(target_ctx_t *target_ctx)
{
    target_ctx->event_cnt++;
    u64 sleep_mus;
    if (target_ctx->sleep_end > target_ctx->sleep_start) 
        sleep_mus = (target_ctx->sleep_end - target_ctx->sleep_start) >> 10;
    else
        sleep_mus = 0;
    if (sleep_mus > (1ULL << 31)) 
        sleep_mus = 1ULL << 31;
    target_ctx->sleep_sum += sleep_mus;
    target_ctx->sleep_sq_sum += sleep_mus * sleep_mus;

    // runtime have upper bound RUNTIME_MAX_TIME, won't overflow directly
    target_ctx->runtime_sum += target_ctx->runtime_ns;
    target_ctx->runtime_sq_sum += target_ctx->runtime_ns * target_ctx->runtime_ns;

    target_ctx->runtime_ns = 0;
    target_ctx->sleep_end = 0;
}

void BPF_STRUCT_OPS(teddy_stopping, struct task_struct *p, bool runnable)
{
    u64 now = scx_bpf_now();
    target_ctx_t *target_ctx = get_target_storage(p);
    if (!target_ctx)
        return;
    
    u64 now_runtime = now - target_ctx->start_running;
    /* Normalize CPU frequency differences between big and little cores 
     * to avoid overestimating task load when tasks are executed on little 
     * cores.*/
    {
        u32 cpu = bpf_get_smp_processor_id();
        u64 freq_n = cpu_info[cpu].freq_n;
        u64 freq_d = cpu_info[cpu].freq_d;
        if (freq_n != freq_d) {
            now_runtime *= freq_n;
            now_runtime /= freq_d;
        }
    }

    target_ctx->runtime_ns += now_runtime;
    target_ctx->in_iowait_cnt += BPF_CORE_READ_BITFIELD_PROBED(p, in_iowait);

    if (!runnable) {
        target_ctx->sleep_cnt++;
        if (target_ctx->sleep_start != 0) {
            update_event_data(target_ctx);
            try_data_to_user(p, target_ctx);
        }
        target_ctx->sleep_start = now;
    } else {
        /* Still runnable (slice used up): it goes back to the queue, so the
         * scheduling delay starts counting again from here. */
        target_ctx->wait_start = now;
        if (target_ctx->runtime_ns >= RUNTIME_MAX_TIME) {
            update_event_data(target_ctx);
            try_data_to_user(p, target_ctx);
        }
    }

    s32 key = p->pid;
    sched_info_t *update_info = bpf_map_lookup_elem(&update_map, &key);
    if (unlikely(update_info)) {
        target_ctx->prio = update_info->prio;
        target_ctx->slice = update_info->slice;
        target_ctx->expt_wait = update_info->expt_wait;

        /* Only apply the cpu_kind setting when the task is not bound
         * to a specific CPU. */
        if (BPF_CORE_READ(p, nr_cpus_allowed) == (s32)cpu_num)
            target_ctx->kind = update_info->kind;

        target_ctx->cpu_prefer = update_info->cpu_prefer;
        if (target_ctx->cpu_prefer == CPU_NO_PREFER) {
            if (target_ctx->kind == FASTEST_KIND)
                target_ctx->cpu_prefer = CPU_FAST_PREFER;
            else if (target_ctx->kind == SLOWEST_KIND)
                target_ctx->cpu_prefer = CPU_SLOW_PREFER;
        }

        bpf_map_delete_elem(&update_map, &key);
    }

}

void BPF_STRUCT_OPS(teddy_exit_task, struct task_struct *p, struct scx_exit_task_args *args)
{
    u32 key = CONFIG_STOP_RINGBUF;
    u32 *pause_ringbuf = bpf_map_lookup_elem(&scheduler_config, &key);

    if (*pause_ringbuf)
        goto clear_tracing_data;

    task_event_t *e = bpf_ringbuf_reserve(&events, sizeof(task_event_t), 0);
    if (!e)
        return;

    e->tid = p->pid;
    e->parent = -1;

    bpf_ringbuf_submit(e, 0);
clear_tracing_data:
    /* Drop the task's delay entry so a recycled tid never reads a stale value. */
    pid_t delay_key = p->pid;
    bpf_map_delete_elem(&sched_delay_map, &delay_key);
}

/* Scheduler exit - record exit info */
void BPF_STRUCT_OPS(teddy_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}

void BPF_STRUCT_OPS(teddy_dump_task, struct scx_dump_ctx *dctx, struct task_struct *p)
{
    target_ctx_t *target_ctx = get_target_storage(p);
    if (!target_ctx)
        return;

    if (target_ctx->runtime_ns > 10000000) {
        scx_bpf_dump("===\n%s tid: %d run for %llu ns prio: %d, cpu: %d, slice: %d\n===\n",
            p->comm, p->pid, target_ctx->runtime_ns, target_ctx->prio, target_ctx->kind, 
            target_ctx->slice);
    } else { // stall task
        u64 wait_ns = dctx->at_ns - target_ctx->sleep_end;
        if (wait_ns > 1000000000ULL)
            scx_bpf_dump("%s tid: %d stall for %llu ns  prio: %d, cpu: %d, slice: %d\n", 
                p->comm, p->pid, wait_ns, target_ctx->prio, target_ctx->kind, 
                target_ctx->slice);

    }
}

SCX_OPS_DEFINE(teddy_ops,
               .select_cpu     = (void *)teddy_select_cpu,
               .enqueue        = (void *)teddy_enqueue,
               .dispatch       = (void *)teddy_dispatch,
               .tick           = (void *)teddy_tick,
               .runnable       = (void *)teddy_runnable,
               .running        = (void *)teddy_running,
               .stopping       = (void *)teddy_stopping,
               .exit_task      = (void *)teddy_exit_task,
               .init           = (void *)teddy_init,
               .exit           = (void *)teddy_exit,
               .dump_task      = (void *)teddy_dump_task,
               .flags          = SCX_OPS_KEEP_BUILTIN_IDLE,
               .name           = "teddy");

SEC("kprobe/futex_wait")
int BPF_KPROBE(trace_futex_wait)
{
    struct task_struct *p = bpf_get_current_task_btf();
    target_ctx_t *target_ctx = get_target_storage(p);
    if (target_ctx)
        target_ctx->futex_wait_cnt++;
    return 0;
}
