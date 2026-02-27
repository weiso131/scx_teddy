// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Facebook

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tracer.h"

char _license[] SEC("license") = "GPL";

// Configuration variables (set by userspace)
int target_mode = MODE_TID;        // Tracing mode: TID/TGID
int target_single_tid = 0;        // TID mode: single target (optimization, 0=use map)
int target_single_tgid = 0;       // TGID mode: single target (optimization, 0=use map)

// Ring Buffer - for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB
} events SEC(".maps");

// HashMap - stores per-task tracing data (key is TID)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240); // Support more threads
    __type(key, int);
    __type(value, trace_data_t);
} task_traces SEC(".maps");

// HashMap - used for multi-TID mode (when target_single_tid == 0)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, int);
    __type(value, unsigned char);
} tracked_tids SEC(".maps");

// HashMap - used for multi-TGID mode (when target_single_tgid == 0)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, int);
    __type(value, unsigned char);
} tracked_tgids SEC(".maps");

// Check if task should be traced
static inline bool is_target(struct task_struct *task)
{
    int tid = task->pid;
    int tgid = task->tgid;

    switch (target_mode) {
    case MODE_TID:
        // Optimization: direct comparison for single TID
        if (target_single_tid)
            return tid == target_single_tid;
        // Otherwise lookup in hash map
        return bpf_map_lookup_elem(&tracked_tids, &tid) != NULL;

    case MODE_TGID:
        // Optimization: direct comparison for single TGID
        if (target_single_tgid)
            return tgid == target_single_tgid;
        // Otherwise lookup in hash map
        return bpf_map_lookup_elem(&tracked_tgids, &tgid) != NULL;
    }

    return false;
}

// Send data to userspace
static inline void data_to_user(int tid, trace_data_t *trace_data)
{
    sleeptime_t *e;

    // Reserve space in ring buffer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return; // Ring buffer full, drop event

    // Fill event data
    e->tid = tid;
    e->sleep_start = trace_data->sleep_start;
    e->sleep_end = trace_data->sleep_end;
    e->runtime_ns = trace_data->runtime_ns;

    // Submit to ring buffer
    bpf_ringbuf_submit(e, 0);

    // Clear tracing data
    trace_data->runtime_ns = 0;
    trace_data->sleep_end = 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev,
             struct task_struct *next)
{
    u64 now = bpf_ktime_get_ns();
    s32 prev_tid = prev->pid;
    s32 next_tid = next->pid;

    // Handle task being switched out
    if (is_target(prev)) {
        trace_data_t *trace_data = bpf_map_lookup_elem(&task_traces, &prev_tid);
        if (trace_data) {
            // Accumulate runtime
            trace_data->runtime_ns += now - trace_data->start_running;

            // Check if voluntarily sleeping
            if (prev->__state != 0) {
                if (trace_data->sleep_start != 0)
                    data_to_user(prev_tid, trace_data);
                trace_data->sleep_start = now;
                // Update map
                bpf_map_update_elem(&task_traces, &prev_tid, trace_data, BPF_ANY);
            }
            // Check if running too long (>= 1 second)
            else if (trace_data->runtime_ns >= 1000000000) {
                data_to_user(prev_tid, trace_data);
                // Update map
                bpf_map_update_elem(&task_traces, &prev_tid, trace_data, BPF_ANY);
            }
        }
    }

    // Handle task being switched in
    if (is_target(next)) {
        trace_data_t *trace_data = bpf_map_lookup_elem(&task_traces, &next_tid);
        if (trace_data) {
            trace_data->start_running = now;
            bpf_map_update_elem(&task_traces, &next_tid, trace_data, BPF_ANY);
        } else {
            // First time seeing this task, initialize
            trace_data_t new_trace = {
                .start_running = now,
                .runtime_ns = 0,
                .sleep_start = 0,
                .sleep_end = 0,
            };
            bpf_map_update_elem(&task_traces, &next_tid, &new_trace, BPF_ANY);
        }
    }

    return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
    int tid = p->pid;

    if (is_target(p)) {
        trace_data_t *trace_data = bpf_map_lookup_elem(&task_traces, &tid);
        if (trace_data) {
            trace_data->sleep_end = bpf_ktime_get_ns();
            bpf_map_update_elem(&task_traces, &tid, trace_data, BPF_ANY);
        }
    }

    return 0;
}
