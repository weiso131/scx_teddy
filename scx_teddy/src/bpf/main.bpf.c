// SPDX-License-Identifier: GPL-2.0
/* scx_teddy - A BPF scheduler based on task runtime characteristics */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, int);
    __type(value, target_ctx_t);
} target_tids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, target_ctx_t);
} task_ctx SEC(".maps");

s32 target_mode = 0;
s32 target_single_tid = 0;
s32 target_single_tgid = 0;

u64 normal_task_cpu = 0;

target_ctx_t *get_target_storage(struct task_struct *p)
{
    target_ctx_t *target_ctx;
    target_ctx = bpf_task_storage_get(&task_ctx, p, 0, 0);

    if (unlikely(!target_ctx)) {
        target_ctx = bpf_task_storage_get(&task_ctx, p, 0,
                               BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (unlikely(!target_ctx))
            return NULL;
        s32 key = p->pid;
        target_ctx_t *tmp = bpf_map_lookup_elem(&target_tids, &key);
        if (!tmp)
            return NULL;
        target_ctx->slice = tmp->slice;
        target_ctx->prio = tmp->prio;
        target_ctx->on_ecore = tmp->on_ecore;
    }

    return target_ctx;
}

// Check if task should be traced
static __always_inline bool is_target(struct task_struct *task)
{
    int tid = task->pid;
    int tgid = task->tgid;

    switch (target_mode) {
    case MODE_TID:
        if (target_single_tid)
            return tid == target_single_tid;

    case MODE_TGID:
        if (target_single_tgid)
            return tgid == target_single_tgid;
    }

    return false;
}

static __always_inline s32 dispatch_sync_cold(struct task_struct *p, u64 wake_flags)
{
    u32 cpu = bpf_get_smp_processor_id();
    if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
        return -1;

    target_ctx_t *target_ctx = get_target_storage(p);
    if (!target_ctx)
        return -1;
    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u64)cpu, target_ctx->slice, wake_flags);
    return (s32)cpu;
}

s32 BPF_STRUCT_OPS(teddy_select_cpu, struct task_struct *p, s32 prev_cpu,
                   u64 wake_flags)
{
    if (!is_target(p)) {
        scx_bpf_dsq_insert(p, NORMAL_TASK_DSQ, NORMAL_TASK_SLICE, wake_flags);
        return prev_cpu;
    }
    // p is woken by this cpu
    if (wake_flags & SCX_WAKE_SYNC) {
        s32 sync_cpu = dispatch_sync_cold(p, wake_flags);
        if (sync_cpu >= 0)
            return sync_cpu;
    }
    bool is_idle;
    s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

    if (is_idle) {
        target_ctx_t *target_ctx = get_target_storage(p);
        if (!target_ctx)
            return prev_cpu;
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u64)cpu, target_ctx->slice, wake_flags);
        return cpu;
    }

    return prev_cpu;
}

void BPF_STRUCT_OPS(teddy_enqueue, struct task_struct *p, u64 enq_flags)
{
    // Todo: use storage is NULL or not as filter
    if (unlikely(!is_target(p))) {
        scx_bpf_dsq_insert(p, NORMAL_TASK_DSQ, NORMAL_TASK_SLICE, enq_flags);
        return;
    }
    target_ctx_t *target_ctx = get_target_storage(p);
    if (!target_ctx)
        return;
    if ((enq_flags & SCX_ENQ_WAKEUP) && target_ctx->prio != TIER_NORMAL) {
        // Todo: use cpu mask find NORMAL_TASK (not target) and preempt

        // Todo: use cpu mask find TIER_TARGET_NORMAL and preempt

    }

    scx_bpf_dsq_insert(p, TARGET_CRITICAL_DSQ + target_ctx->prio, target_ctx->slice, enq_flags);
}

void BPF_STRUCT_OPS(teddy_dispatch, s32 raw_cpu, struct task_struct *prev)
{
    if (scx_bpf_dsq_move_to_local(TARGET_CRITICAL_DSQ))
        return;
    else if (scx_bpf_dsq_move_to_local(TARGET_INTERACTIVE_DSQ))
        return;
    else if (scx_bpf_dsq_move_to_local(TARGET_NORMAL_DSQ))
        return;
    else if (scx_bpf_dsq_move_to_local(NORMAL_TASK_DSQ))
        return;
}

void BPF_STRUCT_OPS(teddy_tick, struct task_struct *p)
{
}

/* Initialize the scheduler */
s32 BPF_STRUCT_OPS_SLEEPABLE(teddy_init)
{
    for (s32 i = 0;i < DSQ_NUM;i++) {
        s32 ret = scx_bpf_create_dsq(NORMAL_TASK_DSQ + i, -1);
        if (ret < 0)
            return ret;
    }

    return 0;
}

/* Scheduler exit - record exit info */
void BPF_STRUCT_OPS(teddy_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(teddy_ops,
               .select_cpu     = (void *)teddy_select_cpu,
               .enqueue        = (void *)teddy_enqueue,
               .dispatch       = (void *)teddy_dispatch,
               .tick           = (void *)teddy_tick,
               .init           = (void *)teddy_init,
               .exit           = (void *)teddy_exit,
               .flags          = SCX_OPS_KEEP_BUILTIN_IDLE,
               .name           = "teddy");
