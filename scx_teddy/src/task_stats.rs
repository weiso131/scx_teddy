#[repr(C)]
pub struct TaskEvent {
    pub tid: i32,
    pub parent: i32,
    pub event_cnt: u32,
    pub sleep_sum: u64,
    pub sleep_sq_sum: u64,
    pub runtime_sum: u64,
    pub runtime_sq_sum: u64,
    pub sleep_cnt: u32,
    pub in_iowait_cnt: u32,
    pub futex_wait_cnt: u32
}

#[derive(Debug, Clone)]
pub struct TaskStats {
    // Runtime statistics
    pub runtime_sum: u64,
    pub runtime_sq_sum: f64,  // Sum of squares for variance calculation

    // Sleep statistics
    pub sleep_sum: u64,
    pub sleep_sq_sum: f64,
    pub sleep_count: u64,  // Number of events with sleep (used internally for avg/cv)

    pub in_iowait_cnt: u64,
    pub futex_wait_cnt: u64,

    pub event_count: u64,
    /// Union-Find ancestor pointer toward the specialization root.
    /// Initialised from the task's real parent (carried in TaskEvent.parent
    /// at first-seen time), then advanced toward 1 (init, "not a target
    /// descendant") or `target_ppid` by `climb_one_step` in main.rs. Once it
    /// lands on either, the task is classified and the field stops moving —
    /// until the target changes (see `last_target`). NOT the real parent
    /// after the first climb — use `real_ppid` for the raw kernel value.
    pub ancestor: i32,
    /// The task's real parent pid, captured once at first-seen time and never
    /// touched by the climb. When the specialization target changes, `ancestor`
    /// is reset to this so the climb can restart from the true tree instead of
    /// staying stuck at a root it converged to under the *old* target.
    pub real_ppid: i32,
    /// The `target_ppid` value the last climb of this task used. When it no
    /// longer matches the current target, this task's `ancestor` is stale
    /// (converged under a different target) and must be re-climbed from
    /// `real_ppid`. 0 means "never climbed under any target yet".
    pub last_target: i32,
    pub exit: u8,
    /// Set to 1 whenever new events arrive; cleared after the task is reclassified.
    /// Lets the classify loop skip tasks whose features haven't changed since last predict.
    pub need_update: u8,
    /// The cluster this task was last classified into, or -1 if it has never
    /// been classified. Lets a predictor detect that a task's cluster is
    /// unchanged and skip the work that only matters on a transition. -1 rather
    /// than 0 because 0 is a valid cluster id.
    pub last_cluster: i32,
}

/// Hand-written so `last_cluster` starts at -1 ("never classified"); a derived
/// `Default` would give 0, which is a valid cluster id.
impl Default for TaskStats {
    fn default() -> Self {
        Self::new(0)
    }
}

impl TaskStats {
    /// Construct a fresh TaskStats. `ancestor` is seeded with the task's
    /// real parent (from TaskEvent.parent on the first enqueue) and will
    /// then be collapsed toward `1` or `target_ppid` by `climb_one_step`.
    /// The same value is kept verbatim in `real_ppid` so the climb can be
    /// restarted from the true parent when the target changes.
    pub fn new(ancestor: i32) -> Self {
        Self {
            runtime_sum: 0,
            runtime_sq_sum: 0.0,

            sleep_sum: 0,
            sleep_sq_sum: 0.0,
            sleep_count: 0,

            in_iowait_cnt: 0,
            futex_wait_cnt: 0,

            event_count: 0,
            ancestor,
            real_ppid: ancestor,
            last_target: 0,
            exit: 0,
            need_update: 0,
            last_cluster: -1,
        }
    }

    pub fn update(&mut self, event: &TaskEvent) {
        self.need_update = 1;
        self.event_count += event.event_cnt as u64;

        // Update runtime statistics
        self.runtime_sum += event.runtime_sum;
        self.runtime_sq_sum += event.runtime_sq_sum as f64;

        // Update sleep statistics
        self.sleep_count += event.sleep_cnt as u64;
        self.sleep_sum += event.sleep_sum;
        self.sleep_sq_sum += event.sleep_sq_sum as f64;
        
        self.in_iowait_cnt += event.in_iowait_cnt as u64;
        self.futex_wait_cnt += event.futex_wait_cnt as u64;
    }

    pub fn avg_runtime_ms(&self) -> f64 {
        if self.event_count > 0 {
            (self.runtime_sum as f64 / self.event_count as f64) / 1_000_000.0
        } else {
            0.0
        }
    }

    pub fn stddev_runtime_ms(&self) -> f64 {
        if self.event_count > 1 {
            let mean = self.runtime_sum as f64 / self.event_count as f64;
            let variance = (self.runtime_sq_sum / self.event_count as f64) - (mean * mean);
            (variance.max(0.0).sqrt()) / 1_000_000.0
        } else {
            0.0
        }
    }

    /// Coefficient of variation for runtime (stddev / avg). 0 if avg is 0.
    pub fn runtime_cv(&self) -> f64 {
        let avg = self.avg_runtime_ms();
        if avg > 0.0 { self.stddev_runtime_ms() / avg } else { 0.0 }
    }

    pub fn avg_sleep_ms(&self) -> f64 {
        if self.sleep_count > 0 {
            (self.sleep_sum as f64 / self.sleep_count as f64) / 1_000.0
        } else {
            0.0
        }
    }

    pub fn stddev_sleep_ms(&self) -> f64 {
        if self.sleep_count > 1 {
            let mean = self.sleep_sum as f64 / self.sleep_count as f64;
            let variance = (self.sleep_sq_sum / self.sleep_count as f64) - (mean * mean);
            (variance.max(0.0).sqrt()) / 1_000.0
        } else {
            0.0
        }
    }

    /// Coefficient of variation for sleep (stddev / avg). 0 if avg is 0.
    pub fn sleep_cv(&self) -> f64 {
        let avg = self.avg_sleep_ms();
        if avg > 0.0 { self.stddev_sleep_ms() / avg } else { 0.0 }
    }

    pub fn sleep_base_ratio(&self, cnt: u64) -> f64 {
        if self.sleep_count == 0 {
            return 0 as f64;
        }
        (cnt as f64) / (self.sleep_count as f64)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_stats() {
        let stats = TaskStats::new(1);
        assert_eq!(stats.event_count, 0);
        assert_eq!(stats.avg_runtime_ms(), 0.0);
        assert_eq!(stats.stddev_runtime_ms(), 0.0);
        assert_eq!(stats.runtime_cv(), 0.0);
    }

    #[test]
    fn test_single_event() {
        let mut stats = TaskStats::new(1);
        let event = TaskEvent {
            tid: 100,
            parent: 1,
            event_cnt: 1,
            runtime_sum: 10_000_000,    // 10ms
            runtime_sq_sum: 100_000_000_000_000, // (10^7)^2
            sleep_cnt: 0,
            sleep_sum: 0,
            sleep_sq_sum: 0,
            in_iowait_cnt: 0,
            futex_wait_cnt: 0,
        };
        stats.update(&event);
        
        assert_eq!(stats.event_count, 1);
        assert_eq!(stats.avg_runtime_ms(), 10.0);
        // Stddev for single event should be 0
        assert_eq!(stats.stddev_runtime_ms(), 0.0);
    }

    #[test]
    fn test_multiple_events_calculation() {
        let mut stats = TaskStats::new(1);
        
        // Data: 10ms, 20ms, 30ms
        // Mean = 20ms
        // Variance = ((10^2 + 20^2 + 30^2)/3) - 20^2 = (1400/3) - 400 = 466.67 - 400 = 66.67
        // Stddev = sqrt(66.67) = 8.165
        
        let events = vec![
            10_000_000,
            20_000_000,
            30_000_000,
        ];

        for r in events {
            stats.update(&TaskEvent {
                tid: 100,
                parent: 1,
                event_cnt: 1,
                runtime_sum: r,
                runtime_sq_sum: r * r,
                sleep_cnt: 0,
                sleep_sum: 0,
                sleep_sq_sum: 0,
                in_iowait_cnt: 0,
                futex_wait_cnt: 0,
            });
        }

        assert_eq!(stats.event_count, 3);
        assert_eq!(stats.avg_runtime_ms(), 20.0);
        
        let stddev = stats.stddev_runtime_ms();
        assert!((stddev - 8.1649).abs() < 0.001);
        
        let cv = stats.runtime_cv();
        assert!((cv - (8.1649 / 20.0)).abs() < 0.001);
    }

    #[test]
    fn test_sleep_stats() {
        let mut stats = TaskStats::new(1);
        let event = TaskEvent {
            tid: 100,
            parent: 1,
            event_cnt: 1,
            runtime_sum: 0,
            runtime_sq_sum: 0,
            sleep_cnt: 2,
            sleep_sum: 5000, // 5ms in total
            sleep_sq_sum: 12_500_000, // (2.5^2 + 2.5^2) in us? 
                                      // Wait, the code says sleep_sum is in us (>> 10 approx)
                                      // Let's re-check the update_event_data in BPF
            in_iowait_cnt: 0,
            futex_wait_cnt: 0,
        };
        // In BPF: sleep_mus = (target_ctx->sleep_end - target_ctx->sleep_start) >> 10;
        // target_ctx->sleep_sum += sleep_mus;
        // In Rust: (self.sleep_sum as f64 / self.sleep_count as f64) / 1_000.0 (to ms)
        
        stats.update(&event);
        assert_eq!(stats.sleep_count, 2);
        assert_eq!(stats.avg_sleep_ms(), 2.5);
    }

    #[test]
    fn test_interface_layout() {
        // This test prevents out-of-sync issues between C (intf.h) and Rust (task_stats.rs)
        use crate::bpf_intf::task_event_t;
        
        // Ensure the sizes are exactly the same
        assert_eq!(
            std::mem::size_of::<TaskEvent>(),
            std::mem::size_of::<task_event_t>(),
            "Size of manually defined TaskEvent does not match the C definition in intf.h!"
        );

        // Ensure the memory alignment is the same
        assert_eq!(
            std::mem::align_of::<TaskEvent>(),
            std::mem::align_of::<task_event_t>(),
            "Alignment of manually defined TaskEvent does not match the C definition in intf.h!"
        );
    }
}
