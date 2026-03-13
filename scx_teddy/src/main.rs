// SPDX-License-Identifier: GPL-2.0
//! scx_teddy - A BPF scheduler based on task runtime characteristics

use std::mem::MaybeUninit;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use plain::Plain;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;

mod bpf_skel {
    include!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
}

mod bpf_intf {
    include!(concat!(env!("OUT_DIR"), "/intf.rs"));
}

#[allow(clippy::wildcard_imports)]
use bpf_skel::*;

#[derive(Debug, Deserialize, Serialize)]
struct TaskConfig {
    tid: i32,
    prio: i32,
    slice: u64,
    on_ecore: u8,
}

#[derive(Debug, Deserialize, Serialize)]
struct Config {
    target_mode: i32,
    tgid: Option<i32>,
    tasks: Vec<TaskConfig>,
}

#[derive(Parser, Debug)]
#[command(name = "scx_teddy")]
#[command(about = "scx_teddy - A BPF scheduler based on task runtime characteristics", long_about = None)]
struct Args {
    /// Verbose output
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
    #[arg(short, long, default_value_t = 600)]
    collect_duration: u64,
}

#[derive(Debug, Clone, Default)]
struct TaskStats {
    // Runtime statistics
    runtime_sum: u64,
    runtime_sum_sq: f64,  // Sum of squares for variance calculation
    runtime_min: u64,
    runtime_max: u64,

    // Sleep statistics
    sleep_sum: u64,
    sleep_sum_sq: f64,
    sleep_min: u64,
    sleep_max: u64,
    sleep_count: u64,  // Number of events with sleep

    // Sleep interval statistics (time between sleeps)
    last_sleep_end: u64,
    sleep_interval_sum: u64,
    sleep_interval_sum_sq: f64,
    sleep_interval_min: u64,
    sleep_interval_max: u64,
    sleep_interval_count: u64,

    event_count: u64,
}

impl TaskStats {
    fn new() -> Self {
        Self {
            runtime_sum: 0,
            runtime_sum_sq: 0.0,
            runtime_min: u64::MAX,
            runtime_max: 0,

            sleep_sum: 0,
            sleep_sum_sq: 0.0,
            sleep_min: u64::MAX,
            sleep_max: 0,
            sleep_count: 0,

            last_sleep_end: 0,
            sleep_interval_sum: 0,
            sleep_interval_sum_sq: 0.0,
            sleep_interval_min: u64::MAX,
            sleep_interval_max: 0,
            sleep_interval_count: 0,

            event_count: 0,
        }
    }

    fn update(&mut self, runtime_ns: u64, sleep_ns: u64, sleep_end: u64) {
        self.event_count += 1;

        // Update runtime statistics
        self.runtime_sum += runtime_ns;
        self.runtime_sum_sq += (runtime_ns as f64) * (runtime_ns as f64);
        self.runtime_min = self.runtime_min.min(runtime_ns);
        self.runtime_max = self.runtime_max.max(runtime_ns);

        // Update sleep statistics
        if sleep_ns > 0 {
            self.sleep_count += 1;
            self.sleep_sum += sleep_ns;
            self.sleep_sum_sq += (sleep_ns as f64) * (sleep_ns as f64);
            self.sleep_min = self.sleep_min.min(sleep_ns);
            self.sleep_max = self.sleep_max.max(sleep_ns);

            // Update sleep interval statistics
            if self.last_sleep_end > 0 && sleep_end > self.last_sleep_end {
                let interval = sleep_end - self.last_sleep_end;
                self.sleep_interval_count += 1;
                self.sleep_interval_sum += interval;
                self.sleep_interval_sum_sq += (interval as f64) * (interval as f64);
                self.sleep_interval_min = self.sleep_interval_min.min(interval);
                self.sleep_interval_max = self.sleep_interval_max.max(interval);
            }
            self.last_sleep_end = sleep_end;
        }
    }
}

struct TaskEvent {
    tid: i32,
    sleep_start: u64,
    sleep_end: u64,
    runtime_ns: u64
}

unsafe impl Plain for TaskEvent {}

// Process event received from ring buffer
fn process_event(data: &[u8], stats: &Arc<Mutex<std::collections::HashMap<i32, TaskStats>>>) -> i32 {
    let event = plain::from_bytes::<TaskEvent>(data).unwrap();

    let sleep_duration = if event.sleep_end > event.sleep_start {
        event.sleep_end - event.sleep_start
    } else {
        0
    };

    // Update statistics
    let mut stats = stats.lock().unwrap();
    let task_stats = stats.entry(event.tid).or_insert_with(TaskStats::new);
    task_stats.update(event.runtime_ns, sleep_duration, event.sleep_end);

    0
}

fn main() -> Result<()> {
    let args = Args::parse();
    println!("scx_teddy scheduler starting...");

    // Build and load eBPF skeleton
    let skel_builder = BpfSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = skel_builder.open(&mut open_object).context("Failed to open BPF object")?;

    // Initialize SCX enums from kernel BTF (SCX_DSQ_LOCAL_ON, etc.)
    scx_utils::import_enums!(open_skel);

    let mut skel = open_skel.load().context("Failed to load BPF object")?;

    // Load and attach the scheduler struct_ops
    let _struct_ops = skel
        .maps
        .teddy_ops
        .attach_struct_ops()
        .context("Failed to attach struct_ops")?;

    // Statistics storage
    let stats: Arc<Mutex<std::collections::HashMap<i32, TaskStats>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));
    let stats_clone = Arc::clone(&stats);

    let mut builder = libbpf_rs::RingBufferBuilder::new();
    builder
        .add(&skel.maps.events, move |data| process_event(data, &stats_clone))
        .context("Failed to add ringbuf")?;
    let ringbuf = builder.build().context("Failed to build ringbuf")?;

    let scheduler_config = &skel.maps.scheduler_config;

    println!("scx_teddy scheduler loaded successfully!");
    println!("Press Ctrl+C to exit...\n");

    // Setup Ctrl+C handler
    let running = Arc::new(Mutex::new(true));
    let running_clone = Arc::clone(&running);
    ctrlc::set_handler(move || {
        println!("\nReceived Ctrl+C, shutting down...");
        *running_clone.lock().unwrap() = false;
    })
    .expect("Error setting Ctrl+C handler");

    let mut start_time = Instant::now();
    let duration = Duration::from_secs(args.collect_duration);

    // Main loop - keep scheduler running
    while *running.lock().unwrap() {
        if start_time.elapsed() >= duration {
            let key = 0u32.to_ne_bytes();
            let mut val = 1u32.to_ne_bytes();
            scheduler_config.update(&key, &val, MapFlags::ANY)?;
            let mut stats_map = stats.lock().unwrap();
            for (&tid, task_stats) in stats_map.iter() {
                println!("TID: {}, Event cnt: {}", tid, task_stats.event_count);
            }
            stats_map.clear();
            start_time = Instant::now();
            val = 0u32.to_ne_bytes();
            scheduler_config.update(&key, &val, MapFlags::ANY)?;
        }
        ringbuf.poll(Duration::from_millis(1000))?;
    }

    println!("scx_teddy scheduler exiting...");

    Ok(())
}
