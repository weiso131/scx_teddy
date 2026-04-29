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

#[derive(Debug, Clone, Default)]
pub struct TaskStats {
    // Runtime statistics
    runtime_sum: u64,
    runtime_sq_sum: f64,  // Sum of squares for variance calculation

    // Sleep statistics
    sleep_sum: u64,
    sleep_sq_sum: f64,
    sleep_count: u64,  // Number of events with sleep (used internally for avg/cv)

    in_iowait_cnt: u64,
    futex_wait_cnt: u64,

    pub event_count: u64,
    parent: i32,
    pub exit: u8,
    /// Set to 1 whenever new events arrive; cleared after the task is reclassified.
    /// Lets the classify loop skip tasks whose features haven't changed since last predict.
    pub need_update: u8,
}

impl TaskStats {
    pub fn new(parent: i32) -> Self {
        Self {
            runtime_sum: 0,
            runtime_sq_sum: 0.0,

            sleep_sum: 0,
            sleep_sq_sum: 0.0,
            sleep_count: 0,

            in_iowait_cnt: 0,
            futex_wait_cnt: 0,

            event_count: 0,
            parent,
            exit: 0,
            need_update: 0,
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

    fn avg_runtime_ms(&self) -> f64 {
        if self.event_count > 0 {
            (self.runtime_sum as f64 / self.event_count as f64) / 1_000_000.0
        } else {
            0.0
        }
    }

    fn stddev_runtime_ms(&self) -> f64 {
        if self.event_count > 1 {
            let mean = self.runtime_sum as f64 / self.event_count as f64;
            let variance = (self.runtime_sq_sum / self.event_count as f64) - (mean * mean);
            (variance.max(0.0).sqrt()) / 1_000_000.0
        } else {
            0.0
        }
    }

    /// Coefficient of variation for runtime (stddev / avg). 0 if avg is 0.
    fn runtime_cv(&self) -> f64 {
        let avg = self.avg_runtime_ms();
        if avg > 0.0 { self.stddev_runtime_ms() / avg } else { 0.0 }
    }

    fn avg_sleep_ms(&self) -> f64 {
        if self.sleep_count > 0 {
            (self.sleep_sum as f64 / self.sleep_count as f64) / 1_000.0
        } else {
            0.0
        }
    }

    fn stddev_sleep_ms(&self) -> f64 {
        if self.sleep_count > 1 {
            let mean = self.sleep_sum as f64 / self.sleep_count as f64;
            let variance = (self.sleep_sq_sum / self.sleep_count as f64) - (mean * mean);
            (variance.max(0.0).sqrt()) / 1_000.0
        } else {
            0.0
        }
    }

    /// Coefficient of variation for sleep (stddev / avg). 0 if avg is 0.
    fn sleep_cv(&self) -> f64 {
        let avg = self.avg_sleep_ms();
        if avg > 0.0 { self.stddev_sleep_ms() / avg } else { 0.0 }
    }

    fn sleep_base_ratio(&self, cnt: u64) -> f64 {
        if (self.sleep_count == 0) {
            return 0 as f64;
        }
        (cnt as f64) / (self.sleep_count as f64)
    }

    /// Returns (name, value) pairs for all features.
    /// The order here defines the CSV column order and feature vector order.
    pub fn get_named_stats(&self) -> Vec<(&'static str, f64)> {
        vec![
            ("runtime_ms", self.avg_runtime_ms()),
            ("runtime_cv", self.runtime_cv()),
            ("avg_sleep_ms", self.avg_sleep_ms()),
            ("sleep_cv", self.sleep_cv()),
            ("iowait_ratio", self.sleep_base_ratio(self.in_iowait_cnt)),
            ("futex_wait_ratio", self.sleep_base_ratio(self.futex_wait_cnt)),
            ("runtime_ratio", self.avg_runtime_ms() / (self.avg_runtime_ms() + self.avg_sleep_ms())),
        ]
    }

    /// Returns feature values as a Vec (order matches get_named_stats).
    pub fn get_stats(&self) -> Vec<f64> {
        self.get_named_stats().into_iter().map(|(_, v)| v).collect()
    }

    /// If `need_update` is set, clear it and return both the feature vector and
    /// the named stats (named stats are needed by adaptive slice computation).
    /// Returns None when the task hasn't received new events since last predict.
    pub fn take_features_if_needed(&mut self) -> Option<(Vec<f64>, Vec<(&'static str, f64)>)> {
        if self.need_update == 0 {
            return None;
        }
        self.need_update = 0;
        let named = self.get_named_stats();
        let features = named.iter().map(|(_, v)| *v).collect();
        Some((features, named))
    }

    /// Returns feature names (order matches get_stats).
    pub fn get_feature_names() -> Vec<&'static str> {
        Self::default().get_named_stats().into_iter().map(|(n, _)| n).collect()
    }
}
