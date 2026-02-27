// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

//! Task sleep/runtime tracer using eBPF

use core::time::Duration;
use std::mem::MaybeUninit;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use plain::Plain;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;

mod bpf_skel {
    include!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
}

#[allow(clippy::wildcard_imports)]
use bpf_skel::*;

// Trace modes
#[derive(Debug, Clone, Copy, PartialEq)]
enum TraceMode {
    Tid = 0,
    Tgid = 1,
}

// Command-line arguments
#[derive(Parser, Debug)]
#[command(name = "tracer")]
#[command(about = "Task sleep/runtime tracer using eBPF", long_about = None)]
struct Args {
    /// Tracing mode: tid or tgid (default: tid)
    #[arg(short, long, default_value = "tid")]
    mode: String,

    /// Tracing target(s): TID or TGID (can specify multiple)
    /// If not specified, tid mode traces current thread, tgid mode traces current process
    #[arg(short = 't', long, value_name = "TARGET")]
    target: Vec<i32>,

    /// Duration in seconds, 0 for unlimited
    #[arg(short, long, default_value = "10")]
    duration: u64,
}

// Structure matching eBPF-side sleeptime_t (defined in tracer.h)
#[derive(Debug, Copy, Clone)]
#[repr(C)]
struct Sleeptime {
    tid: i32,
    sleep_start: u64,
    sleep_end: u64,
    runtime_ns: u64,
}

// Mark structure as safe to convert from raw bytes
unsafe impl Plain for Sleeptime {}

// Task statistics
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
            let variance = (self.runtime_sum_sq / self.event_count as f64) - (mean * mean);
            (variance.max(0.0).sqrt()) / 1_000_000.0
        } else {
            0.0
        }
    }

    fn avg_sleep_ms(&self) -> f64 {
        if self.sleep_count > 0 {
            (self.sleep_sum as f64 / self.sleep_count as f64) / 1_000_000.0
        } else {
            0.0
        }
    }

    fn stddev_sleep_ms(&self) -> f64 {
        if self.sleep_count > 1 {
            let mean = self.sleep_sum as f64 / self.sleep_count as f64;
            let variance = (self.sleep_sum_sq / self.sleep_count as f64) - (mean * mean);
            (variance.max(0.0).sqrt()) / 1_000_000.0
        } else {
            0.0
        }
    }

    fn avg_sleep_interval_ms(&self) -> f64 {
        if self.sleep_interval_count > 0 {
            (self.sleep_interval_sum as f64 / self.sleep_interval_count as f64) / 1_000_000.0
        } else {
            0.0
        }
    }

    fn stddev_sleep_interval_ms(&self) -> f64 {
        if self.sleep_interval_count > 1 {
            let mean = self.sleep_interval_sum as f64 / self.sleep_interval_count as f64;
            let variance = (self.sleep_interval_sum_sq / self.sleep_interval_count as f64) - (mean * mean);
            (variance.max(0.0).sqrt()) / 1_000_000.0
        } else {
            0.0
        }
    }
}

// Process event received from ring buffer
fn process_event(data: &[u8], stats: &Arc<Mutex<std::collections::HashMap<i32, TaskStats>>>) -> i32 {
    let event = plain::from_bytes::<Sleeptime>(data).unwrap();

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

    // Parse trace mode
    let mode = match args.mode.as_str() {
        "tid" => TraceMode::Tid,
        "tgid" => TraceMode::Tgid,
        _ => anyhow::bail!("Invalid mode: {}. Use 'tid' or 'tgid'", args.mode),
    };

    // Build and load eBPF skeleton
    let skel_builder = BpfSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object).context("Failed to open BPF object")?;
    let mut skel = open_skel.load().context("Failed to load BPF object")?;

    // Set trace mode
    if let Some(bss) = skel.maps.bss_data.as_deref_mut() {
        bss.target_mode = mode as i32;
    }

    // Get target list
    let targets = if args.target.is_empty() {
        // No targets specified, use current process/thread
        match mode {
            TraceMode::Tid => vec![unsafe { libc::gettid() }],
            TraceMode::Tgid => vec![unsafe { libc::getpid() }],
        }
    } else {
        args.target.clone()
    };

    // Configure targets based on mode
    let tracked: u8 = 1;
    match mode {
        TraceMode::Tid => {
            println!("Trace mode: TID");

            // Single target optimization
            if targets.len() == 1 {
                let tid = targets[0];
                if let Some(bss) = skel.maps.bss_data.as_deref_mut() {
                    bss.target_single_tid = tid;
                }
                println!("Target TID: {} (single target optimization)", tid);
            } else {
                // Multi-target mode
                println!("Target TIDs: {:?} (multi-target mode)", targets);
                for &tid in &targets {
                    skel.maps
                        .tracked_tids
                        .update(&tid.to_ne_bytes(), &tracked.to_ne_bytes(), MapFlags::ANY)
                        .context(format!("Failed to add TID {} to tracked list", tid))?;
                }
            }
        }
        TraceMode::Tgid => {
            println!("Trace mode: TGID (entire process)");

            // Single target optimization
            if targets.len() == 1 {
                let tgid = targets[0];
                if let Some(bss) = skel.maps.bss_data.as_deref_mut() {
                    bss.target_single_tgid = tgid;
                }
                println!("Target TGID: {} (single target optimization)", tgid);
            } else {
                // Multi-target mode
                println!("Target TGIDs: {:?} (multi-target mode)", targets);
                for &tgid in &targets {
                    skel.maps
                        .tracked_tgids
                        .update(&tgid.to_ne_bytes(), &tracked.to_ne_bytes(), MapFlags::ANY)
                        .context(format!("Failed to add TGID {} to tracked list", tgid))?;
                }
            }
        }
    }

    // Attach eBPF programs to tracepoints
    let _links = skel.attach().context("Failed to attach BPF programs")?;

    if args.duration > 0 {
        println!("\nDuration: {} seconds\n", args.duration);
    } else {
        println!("\nDuration: unlimited (press Ctrl+C to stop)\n");
    }

    // Statistics storage
    let stats: Arc<Mutex<std::collections::HashMap<i32, TaskStats>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));
    let stats_clone = Arc::clone(&stats);

    // Build ring buffer with callback
    let mut builder = libbpf_rs::RingBufferBuilder::new();
    builder
        .add(&skel.maps.events, move |data| process_event(data, &stats_clone))
        .context("Failed to add ringbuf")?;
    let ringbuf = builder.build().context("Failed to build ringbuf")?;

    // Record start time
    let start_time = Instant::now();
    let duration = Duration::from_secs(args.duration);

    // Setup Ctrl+C handler
    let running = Arc::new(Mutex::new(true));
    let running_clone = Arc::clone(&running);
    ctrlc::set_handler(move || {
        *running_clone.lock().unwrap() = false;
    }).expect("Error setting Ctrl+C handler");

    // Poll ring buffer continuously
    while *running.lock().unwrap() {
        // Check timeout
        if args.duration > 0 && start_time.elapsed() >= duration {
            break;
        }

        // poll() processes events
        ringbuf.poll(Duration::from_millis(100))?;
    }

    // Display statistics report
    println!("\n========== Statistics Report ==========\n");

    let stats = stats.lock().unwrap();
    for (&tid, task_stats) in stats.iter() {
        if task_stats.event_count == 0 {
            continue;
        }

        println!("Task TID: {}", tid);
        println!("  Event count: {}", task_stats.event_count);

        println!("\n  Runtime:");
        println!("    Average: {:.2} ms", task_stats.avg_runtime_ms());
        println!("    Std dev: {:.2} ms", task_stats.stddev_runtime_ms());
        println!("    Min: {:.2} ms", task_stats.runtime_min as f64 / 1_000_000.0);
        println!("    Max: {:.2} ms", task_stats.runtime_max as f64 / 1_000_000.0);

        if task_stats.sleep_count > 0 {
            println!("\n  Sleep Duration:");
            println!("    Count: {}", task_stats.sleep_count);
            println!("    Average: {:.2} ms", task_stats.avg_sleep_ms());
            println!("    Std dev: {:.2} ms", task_stats.stddev_sleep_ms());
            println!("    Min: {:.2} ms", task_stats.sleep_min as f64 / 1_000_000.0);
            println!("    Max: {:.2} ms", task_stats.sleep_max as f64 / 1_000_000.0);
        }

        if task_stats.sleep_interval_count > 0 {
            println!("\n  Sleep Interval (time between sleeps):");
            println!("    Count: {}", task_stats.sleep_interval_count);
            println!("    Average: {:.2} ms", task_stats.avg_sleep_interval_ms());
            println!("    Std dev: {:.2} ms", task_stats.stddev_sleep_interval_ms());
            println!("    Min: {:.2} ms", task_stats.sleep_interval_min as f64 / 1_000_000.0);
            println!("    Max: {:.2} ms", task_stats.sleep_interval_max as f64 / 1_000_000.0);
        }

        println!();
    }

    Ok(())
}
