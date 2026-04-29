// SPDX-License-Identifier: GPL-2.0
//! scx_teddy - A BPF scheduler based on task runtime characteristics

use std::collections::HashMap;
use std::io::Write;
use std::io::BufRead;
use std::mem::MaybeUninit;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;
use plain::Plain;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;

mod classifier;
mod task_stats;

use task_stats::TaskStats;
use crate::task_stats::TaskEvent;

mod bpf_skel {
    include!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
}

mod bpf_intf {
    include!(concat!(env!("OUT_DIR"), "/intf.rs"));
}

#[allow(clippy::wildcard_imports)]
use bpf_skel::*;

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "slice_mode")]
enum SliceConfig {
    /// slice = avg_runtime_ns + sigma * stddev_runtime_ns
    #[serde(rename = "adaptive")]
    Adaptive { slice_sigma: f64 },
    /// slice = fixed value in ns
    #[serde(rename = "fixed")]
    Fixed { slice_ns: u64 },
}

#[derive(Debug, Deserialize, Clone)]
struct ClusterSchedConfig {
    prio: i32,
    #[serde(flatten)]
    slice: SliceConfig,
}

#[derive(Debug, Deserialize)]
struct SchedConfig {
    clusters: HashMap<String, ClusterSchedConfig>,
    default: ClusterSchedConfig,
}

impl ClusterSchedConfig {
    /// Compute the slice in ns for a task given its named runtime stats.
    fn compute_slice_ns(&self, named_stats: &[(&str, f64)]) -> u64 {
        match &self.slice {
            SliceConfig::Adaptive { slice_sigma } => {
                let lookup = |name: &str| -> f64 {
                    named_stats.iter()
                        .find(|(n, _)| *n == name)
                        .map(|(_, v)| *v)
                        .unwrap_or(0.0)
                };
                let avg_ms = lookup("avg_runtime_ms");
                let cv = lookup("runtime_cv");
                let avg_ns = avg_ms * 1_000_000.0;
                let std_ns = avg_ms * cv * 1_000_000.0;
                let slice = avg_ns + slice_sigma * std_ns;
                (slice.max(1000.0)) as u64 // at least 1us
            }
            SliceConfig::Fixed { slice_ns } => *slice_ns,
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "scx_teddy")]
#[command(about = "scx_teddy - A BPF scheduler based on task runtime characteristics", long_about = None)]
struct Args {
    /// Verbose output
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Data collection interval in seconds
    #[arg(short, long, default_value_t = 600)]
    collect_duration: u64,

    /// Mode: "collect" to generate event.csv, "classify" to use a trained model,
    /// "debug_classify" to print cluster assignments for selected comms without
    /// modifying scheduling.
    #[arg(short, long, default_value = "collect")]
    mode: String,

    /// Minimum event count to include a task in event.csv (filter inactive tasks)
    #[arg(long, default_value_t = 2)]
    min_events: u64,

    /// Output CSV file path (collect mode)
    #[arg(short, long, default_value = "event.csv")]
    output: String,

    /// Path to trained model JSON (classify mode)
    #[arg(long)]
    model: Option<String>,

    /// Path to scheduling config JSON (classify mode)
    #[arg(long)]
    config: Option<String>,

    /// Path to debug config file (debug_classify mode). One comm name per line;
    /// lines starting with '#' are comments. Matching is by prefix.
    #[arg(long)]
    debug_config: Option<String>,
}

/// Load a debug config file: one comm prefix per line, '#' starts comments.
fn load_debug_config(path: &str) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read debug config: {}", path))?;
    let mut patterns = Vec::new();
    for line in content.lines() {
        let s = line.split('#').next().unwrap_or("").trim();
        if !s.is_empty() {
            patterns.push(s.to_string());
        }
    }
    Ok(patterns)
}

unsafe impl Plain for TaskEvent {}

fn thread_cpu_time() -> Duration {
    #[repr(C)]
    struct Timespec { tv_sec: i64, tv_nsec: i64 }
    const CLOCK_THREAD_CPUTIME_ID: i32 = 3;
    extern "C" {
        fn clock_gettime(clk_id: i32, tp: *mut Timespec) -> i32;
    }
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { clock_gettime(CLOCK_THREAD_CPUTIME_ID, &mut ts); }
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

// Process event received from ring buffer
fn process_event(data: &[u8], stats: &Arc<Mutex<std::collections::HashMap<i32, TaskStats>>>) -> i32 {
    let event = plain::from_bytes::<TaskEvent>(data).unwrap();

    // Update statistics
    let mut stats = stats.lock().unwrap();

    if event.parent > 0 {
        let task_stats = stats.entry(event.tid).or_insert(TaskStats::new(event.parent));
        task_stats.update(event);
    } else if event.parent == -1 {
        if let Some(task_stats) = stats.get_mut(&event.tid) {
            task_stats.exit = 1;
        }
    }

    0
}

fn csv_header() -> String {
    let feature_names = TaskStats::get_feature_names();
    let mut header = String::from("tid,tgid,ppid,comm");
    for name in &feature_names {
        header.push(',');
        header.push_str(name);
    }
    header
}

/// Read a field (e.g. "Tgid", "PPid") from /proc/<tid>/status.
fn read_proc_field(tid: i32, field: &str) -> Option<i32> {
    let path = format!("/proc/{}/status", tid);
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            if let Some(val) = rest.strip_prefix(':') {
                return val.trim().parse().ok();
            }
        }
    }
    None
}

/// Read command name from /proc/<tid>/comm.
fn read_proc_comm(tid: i32) -> String {
    let path = format!("/proc/{}/comm", tid);
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.mode.as_str() {
        "collect" | "classify" | "debug_classify" => {}
        _ => anyhow::bail!(
            "Invalid mode '{}'. Use 'collect', 'classify', or 'debug_classify'.",
            args.mode
        ),
    }

    // Load model and config for classify mode
    let (model, sched_config) = if args.mode == "classify" {
        let model_path = args.model.as_deref()
            .context("Classify mode requires --model <path>")?;
        let m = classifier::load_model(model_path)?;
        println!("Loaded model from {} ({} clusters)", model_path, m.n_clusters());

        let config_path = args.config.as_deref()
            .context("Classify mode requires --config <path>")?;
        let content = std::fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read config: {}", config_path))?;
        let cfg: SchedConfig = serde_json::from_str(&content)
            .context("Failed to parse scheduling config")?;
        println!("Loaded scheduling config from {}", config_path);

        (Some(m), Some(cfg))
    } else {
        (None, None)
    };

    // Load model and debug patterns for debug_classify mode
    let (debug_model, debug_patterns) = if args.mode == "debug_classify" {
        let model_path = args.model.as_deref()
            .context("debug_classify mode requires --model <path>")?;
        let m = classifier::load_model(model_path)?;
        println!("Loaded model from {} ({} clusters)", model_path, m.n_clusters());

        let debug_path = args.debug_config.as_deref()
            .context("debug_classify mode requires --debug-config <path>")?;
        let patterns = load_debug_config(debug_path)?;
        println!("Loaded debug config from {} ({} comm patterns): {:?}",
            debug_path, patterns.len(), patterns);

        (Some(m), Some(patterns))
    } else {
        (None, None)
    };

    println!("scx_teddy scheduler starting...");

    // Build and load eBPF skeleton
    let skel_builder = BpfSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = skel_builder.open(&mut open_object).context("Failed to open BPF object")?;

    // Initialize SCX enums from kernel BTF (SCX_DSQ_LOCAL_ON, etc.)
    scx_utils::import_enums!(open_skel);

    let mut skel = open_skel.load().context("Failed to load BPF object")?;

    let _futex_wait = skel.progs.trace_futex_wait.attach()?;

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
    while *running.lock().unwrap() && !scx_utils::uei_exited!(&skel, uei) {
        if start_time.elapsed() >= duration {
            let key = 0u32.to_ne_bytes();
            let mut val = 1u32.to_ne_bytes();
            scheduler_config.update(&key, &val, MapFlags::ANY)?;
            let mut stats_map = stats.lock().unwrap();

            if let (Some(ref classifier), Some(ref patterns)) = (&debug_model, &debug_patterns) {
                // Debug classify mode: print predicted cluster for matched comms,
                // do NOT update scheduler_config or update_map.
                let n = classifier.n_clusters();
                let mut cluster_tasks: Vec<Vec<(i32, String)>> = vec![Vec::new(); n];

                for (&tid, task_stats) in stats_map.iter() {
                    if task_stats.exit != 0 || task_stats.event_count < args.min_events {
                        continue;
                    }
                    let comm = read_proc_comm(tid);
                    let matched = patterns.iter().any(|p| comm == *p || comm.starts_with(p));
                    if !matched {
                        continue;
                    }
                    let named_stats = task_stats.get_named_stats();
                    let features: Vec<f64> = named_stats.iter().map(|(_, v)| *v).collect();
                    let cluster = classifier.predict(&features);
                    cluster_tasks[cluster].push((tid, comm));
                }

                // Build per-comm → cluster count map
                let mut comm_clusters: std::collections::BTreeMap<String, Vec<usize>> =
                    std::collections::BTreeMap::new();
                for (cluster_id, tasks) in cluster_tasks.iter().enumerate() {
                    for (_tid, comm) in tasks {
                        comm_clusters.entry(comm.clone()).or_default().push(cluster_id);
                    }
                }

                print!("\x1b[H\x1b[2J\x1b[3J");
                println!("[debug_classify]");
                for (comm, clusters) in &comm_clusters {
                    // Count occurrences per cluster
                    let mut counts: std::collections::BTreeMap<usize, usize> =
                        std::collections::BTreeMap::new();
                    for &c in clusters {
                        *counts.entry(c).or_insert(0) += 1;
                    }
                    let summary: Vec<String> = counts.iter()
                        .map(|(c, cnt)| format!("cluster{}: {}", c, cnt))
                        .collect();
                    println!("  {}: [{}]", comm, summary.join(", "));
                }
                std::io::stdout().flush().ok();
            } else if let (Some(ref classifier), Some(ref cfg)) = (&model, &sched_config) {
                // Classify mode: predict cluster and update BPF map
                let n = classifier.n_clusters();
                let mut cluster_tids: Vec<Vec<i32>> = vec![Vec::new(); n];
                let update_map = &skel.maps.update_map;

                let wall_start = Instant::now();
                let cpu_start = thread_cpu_time();
                let mut predict_count: usize = 0;

                for (&tid, task_stats) in stats_map.iter() {
                    if task_stats.exit != 0 || task_stats.event_count < args.min_events{
                        continue;
                    }
                    let named_stats = task_stats.get_named_stats();
                    let features: Vec<f64> = named_stats.iter().map(|(_, v)| *v).collect();
                    let cluster = classifier.predict(&features);
                    predict_count += 1;
                    cluster_tids[cluster].push(tid);

                    let cluster_cfg = cfg.clusters
                        .get(&cluster.to_string())
                        .unwrap_or(&cfg.default);

                    let prio = cluster_cfg.prio;
                    let slice_ns = cluster_cfg.compute_slice_ns(&named_stats);

                    // Write sched_info_t {prio: s32, slice: u64} to update_map
                    // Layout: 4 bytes prio + 4 bytes padding + 8 bytes slice
                    let tid_key = tid.to_ne_bytes();
                    let mut val_buf = [0u8; 16];
                    val_buf[0..4].copy_from_slice(&prio.to_ne_bytes());
                    val_buf[8..16].copy_from_slice(&slice_ns.to_ne_bytes());
                    update_map.update(&tid_key, &val_buf, MapFlags::ANY)?;
                }

                let batch_wall_us = wall_start.elapsed().as_micros();
                let batch_cpu_us  = (thread_cpu_time() - cpu_start).as_micros();
                let avg_per_task_ns = if predict_count > 0 {
                    (batch_cpu_us * 1000) / predict_count as u128
                } else { 0 };

                println!("Classification results (updated {} tasks):",
                    cluster_tids.iter().map(|v| v.len()).sum::<usize>());
                println!("  [timing] batch wall={}us cpu={}us avg={}ns/task over {} tasks (incl. feature build + map update)",
                    batch_wall_us, batch_cpu_us, avg_per_task_ns, predict_count);
                for (i, tids) in cluster_tids.iter().enumerate() {
                    let cluster_cfg = cfg.clusters
                        .get(&i.to_string())
                        .unwrap_or(&cfg.default);
                    println!("  Cluster {} (prio={}, {} tasks)",
                        i, cluster_cfg.prio, tids.len());
                }
            } else {
                // Collect mode: write stats to CSV
                // Read existing CSV rows into an ordered map (tid -> row string)
                let mut existing_rows: Vec<(i32, String)> = Vec::new();
                let mut existing_tids: HashMap<i32, usize> = HashMap::new();

                if std::path::Path::new(&args.output).exists() {
                    let reader = std::io::BufReader::new(
                        std::fs::File::open(&args.output)
                            .context("Failed to open existing CSV for reading")?
                    );
                    for (i, line) in reader.lines().enumerate() {
                        let line = line.context("Failed to read CSV line")?;
                        if i == 0 {
                            continue; // skip header
                        }
                        if let Some(tid_str) = line.split(',').next() {
                            if let Ok(tid) = tid_str.trim().parse::<i32>() {
                                existing_tids.insert(tid, existing_rows.len());
                                existing_rows.push((tid, line));
                            }
                        }
                    }
                }

                let mut new_count = 0u64;
                let mut update_count = 0u64;
                for (&tid, task_stats) in stats_map.iter() {
                    if task_stats.exit != 0 || task_stats.event_count < args.min_events{
                        continue;
                    }
                    let tgid = read_proc_field(tid, "Tgid")
                        .map(|v| v.to_string()).unwrap_or_default();
                    let ppid = read_proc_field(tid, "PPid")
                        .map(|v| v.to_string()).unwrap_or_default();
                    let comm = read_proc_comm(tid);
                    let stats_arr = task_stats.get_stats();
                    let values: Vec<String> = stats_arr.iter().map(|v| format!("{}", v)).collect();
                    let row = format!("{},{},{},{},{}", tid, tgid, ppid, comm, values.join(","));

                    if let Some(&idx) = existing_tids.get(&tid) {
                        existing_rows[idx].1 = row;
                        update_count += 1;
                    } else {
                        existing_tids.insert(tid, existing_rows.len());
                        existing_rows.push((tid, row));
                        new_count += 1;
                    }
                }

                // Write everything back
                let mut file = std::fs::File::create(&args.output)
                    .context("Failed to create output CSV")?;
                writeln!(file, "{}", csv_header())
                    .context("Failed to write CSV header")?;
                for (_, row) in &existing_rows {
                    writeln!(file, "{}", row)
                        .context("Failed to write CSV row")?;
                }
                println!("CSV updated: {} new, {} updated, {} total rows",
                    new_count, update_count, existing_rows.len());
            }

            start_time = Instant::now();
            val = 0u32.to_ne_bytes();
            scheduler_config.update(&key, &val, MapFlags::ANY)?;
        }
        ringbuf.poll(Duration::from_millis(1000))?;
    }

    println!("scx_teddy scheduler exiting...");
    scx_utils::uei_report!(&skel, uei)
        .context("UEI report")?;

    Ok(())
}
