// SPDX-License-Identifier: GPL-2.0

#ifndef __TRACER_H
#define __TRACER_H

// Tracing modes
#define MODE_TID    0  // Track specific TIDs
#define MODE_TGID   1  // Track entire process (all threads of a TGID)

// Per-task tracing data structure
typedef struct trace_data {
    unsigned long long runtime_ns;
    unsigned long long start_running;
    unsigned long long sleep_start;
    unsigned long long sleep_end;
} trace_data_t;

// Event structure sent to userspace
typedef struct sleeptime {
    int tid;  // Thread ID (statistics are per-TID)
    unsigned long long sleep_start;
    unsigned long long sleep_end;
    unsigned long long runtime_ns;
} sleeptime_t;

#endif /* __TRACER_H */
