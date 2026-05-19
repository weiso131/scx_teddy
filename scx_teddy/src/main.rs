// SPDX-License-Identifier: GPL-2.0
//! scx_teddy - A BPF scheduler based on task runtime characteristics

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Write;
use std::io::BufRead;
use std::mem::MaybeUninit;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;
use std::cmp::max;

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

    /// Mode: "collect" to generate event.csv, "classify" to use a trained model.
    #[arg(short, long, default_value = "collect")]
    mode: String,

    /// Minimum event count to include a task in event.csv (filter inactive tasks)
    #[arg(long, default_value_t = 2)]
    min_events: u64,

    /// Output CSV file path (collect mode)
    #[arg(short, long, default_value = "event.csv")]
    output: String,

    /// Write the CSV every collect cycle (collect mode). By default the CSV is
    /// only written once on shutdown; enable this to checkpoint each cycle so a
    /// crash or `kill -9` does not lose the run's data.
    #[arg(long, default_value_t = false)]
    csv_checkpoint: bool,

    /// Maximum total run time in seconds (collect mode). Once reached, the
    /// in-memory CSV is written out and the scheduler exits. 0 means no limit.
    #[arg(long, default_value_t = 0)]
    max_runtime: u64,

    /// Path to trained model JSON (classify mode)
    #[arg(long)]
    model: Option<String>,

    /// Path to scheduling config JSON (classify mode)
    #[arg(long)]
    config: Option<String>,
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

/// Shared task statistics. The ring-buffer callback writes into it and the
/// main loop reads from it; both run on the same thread, so RefCell (not a
/// mutex) is enough — the borrows never overlap.
type StatsMap = Rc<RefCell<HashMap<i32, TaskStats>>>;

// Process event received from ring buffer
fn process_event(data: &[u8], stats: &StatsMap) -> i32 {
    let event = plain::from_bytes::<TaskEvent>(data).unwrap();

    // Update statistics
    let mut stats = stats.borrow_mut();

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

/// Format one task's stats into a CSV row, reading tgid/ppid/comm from /proc.
fn task_csv_row(tid: i32, task_stats: &TaskStats) -> String {
    let tgid = read_proc_field(tid, "Tgid")
        .map(|v| v.to_string()).unwrap_or_default();
    let ppid = read_proc_field(tid, "PPid")
        .map(|v| v.to_string()).unwrap_or_default();
    let comm = read_proc_comm(tid);
    let values: Vec<String> = task_stats.get_stats().iter()
        .map(|v| format!("{}", v)).collect();
    format!("{},{},{},{},{}", tid, tgid, ppid, comm, values.join(","))
}

/// Write `rows` to a fresh CSV at `path`, header first. The output path is
/// checked for non-existence at startup, so this is a plain write — no merge
/// with any prior file.
fn write_csv(path: &str, rows: &[(i32, String)]) -> Result<()> {
    let mut file = std::fs::File::create(path)
        .context("Failed to create output CSV")?;
    writeln!(file, "{}", csv_header())
        .context("Failed to write CSV header")?;
    for (_, row) in rows {
        writeln!(file, "{}", row)
            .context("Failed to write CSV row")?;
    }
    println!("CSV written: {} rows", rows.len());
    Ok(())
}

/// Pack every eligible task in `stats_map` into CSV rows and write them out via
/// `write_csv`. `stats_map` is the single source of truth — no buffer is kept
/// between cycles.
fn collect_data(
    stats_map: &HashMap<i32, TaskStats>,
    output: &str,
    min_events: u64,
) -> Result<()> {
    let rows: Vec<(i32, String)> = stats_map.iter()
        .filter(|(_, ts)| ts.exit == 0 && ts.event_count >= min_events)
        .map(|(&tid, ts)| (tid, task_csv_row(tid, ts)))
        .collect();
    write_csv(output, &rows)
}

/// Run one classify cycle: predict each eligible task's cluster and write the
/// resulting {prio, slice} into `update_map`. Only tasks with new data since
/// the last cycle are processed (`take_features_if_needed`).
fn run_classify_cycle(
    stats_map: &mut HashMap<i32, TaskStats>,
    update_map: &libbpf_rs::Map,
    classifier: &dyn classifier::Classifier,
    cfg: &SchedConfig,
    min_events: u64,
) -> Result<()> {
    let n = classifier.n_clusters();
    let mut cluster_tids: Vec<Vec<i32>> = vec![Vec::new(); n];

    let wall_start = Instant::now();
    let cpu_start = thread_cpu_time();
    let mut predict_count: usize = 0;
    let mut update_count: usize = 0;

    for (&tid, task_stats) in stats_map.iter_mut() {
        if task_stats.exit != 0 || task_stats.event_count < min_events {
            continue;
        }

        // Only classify the synthetic benchmark workloads (stress-ng, schbench);
        // every other task is left alone — no prediction, no BPF map write.
        let comm = read_proc_comm(tid);
        if !(comm.contains("stress-ng") || comm.contains("schbench")) {
            continue;
        }

        let Some((features, named_stats)) = task_stats.take_features_if_needed() else {
            continue;
        };
        let cluster = classifier.predict(&features);
        predict_count += 1;
        cluster_tids[cluster].push(tid);

        if comm.contains("schbench-msg") && cluster != 1 {
            println!("schbench-msg wrong predict");
        }

        // Skip the BPF map update when the cluster is unchanged: writing the
        // same assignment is wasteful and the update is costly on the BPF side.
        if task_stats.last_cluster == cluster {
            continue;
        }
        task_stats.last_cluster = cluster;

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
        update_count += 1;
    }

    let batch_wall_us = wall_start.elapsed().as_micros();
    let batch_cpu_us  = (thread_cpu_time() - cpu_start).as_micros();
    let avg_per_task_ns = if predict_count > 0 {
        (batch_cpu_us * 1000) / predict_count as u128
    } else { 0 };

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.mode.as_str() {
        "collect" | "classify" => {}
        _ => anyhow::bail!(
            "Invalid mode '{}'. Use 'collect' or 'classify'.",
            args.mode
        ),
    }

    // Collect mode refuses to overwrite an existing CSV: bail early so a run
    // never destroys prior data. Pick a new path or remove the old file.
    if args.mode == "collect" && std::path::Path::new(&args.output).exists() {
        anyhow::bail!(
            "Output file '{}' already exists; choose a different --output path.",
            args.output
        );
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
    let stats: StatsMap = Rc::new(RefCell::new(HashMap::new()));
    let stats_clone = Rc::clone(&stats);

    let mut builder = libbpf_rs::RingBufferBuilder::new();
    builder
        .add(&skel.maps.events, move |data| process_event(data, &stats_clone))
        .context("Failed to add ringbuf")?;
    let ringbuf = builder.build().context("Failed to build ringbuf")?;

    let scheduler_config = &skel.maps.scheduler_config;
    let update_map = &skel.maps.update_map;

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
    let collect_mode = model.is_none();

    // Overall run-time limit (collect mode only): once this deadline passes the
    // loop stops and the CSV is flushed. None means no limit.
    let run_deadline = if collect_mode && args.max_runtime > 0 {
        Some(start_time + Duration::from_secs(args.max_runtime))
    } else {
        None
    };

    // Main loop - keep scheduler running
    while *running.lock().unwrap()
        && !scx_utils::uei_exited!(&skel, uei)
        && run_deadline.is_none_or(|d| Instant::now() < d)
    {
        if start_time.elapsed() >= duration {
            // Pause pushing events into the ring buffer while this cycle runs,
            // so the buffer cannot overflow during prediction / CSV work.
            let key = 0u32.to_ne_bytes();
            scheduler_config.update(&key, &1u32.to_ne_bytes(), MapFlags::ANY)?;

            if let (Some(classifier), Some(cfg)) = (&model, &sched_config) {
                run_classify_cycle(&mut stats.borrow_mut(), update_map,
                    classifier.as_ref(), cfg, args.min_events)?;
            } else if args.csv_checkpoint {
                // Collect mode writes the CSV every cycle only with this flag;
                // otherwise it is flushed once on shutdown.
                collect_data(&stats.borrow(), &args.output, args.min_events)?;
            }

            start_time = Instant::now();
            scheduler_config.update(&key, &0u32.to_ne_bytes(), MapFlags::ANY)?;
        }
        ringbuf.poll(Duration::from_millis(1000))?;
    }

    println!("scx_teddy scheduler exiting...");

    // Flush the CSV on shutdown (collect mode).
    if collect_mode {
        collect_data(&stats.borrow(), &args.output, args.min_events)?;
    }

    scx_utils::uei_report!(&skel, uei)
        .context("UEI report")?;

    Ok(())
}
