// SPDX-License-Identifier: GPL-2.0
//! scx_teddy - A BPF scheduler based on task runtime characteristics

use std::mem::MaybeUninit;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::fs;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;

mod bpf_skel {
    include!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
}

mod bpf_intf {
    #[allow(dead_code)]
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
    #[arg(short, long)]
    verbose: bool,

    /// Path to JSON configuration file
    #[arg(short, long)]
    config: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("scx_teddy scheduler starting...");

    // Load configuration from JSON file
    let config_content = fs::read_to_string(&args.config)
        .context(format!("Failed to read config file: {}", args.config))?;
    let config: Config = serde_json::from_str(&config_content)
        .context("Failed to parse JSON config")?;

    println!("Loaded config: target_mode={}, tgid={:?}, tasks count={}",
             config.target_mode, config.tgid, config.tasks.len());

    // Build and load eBPF skeleton
    let skel_builder = BpfSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = skel_builder.open(&mut open_object).context("Failed to open BPF object")?;

    // Initialize SCX enums from kernel BTF (SCX_DSQ_LOCAL_ON, etc.)
    scx_utils::import_enums!(open_skel);

    // Configure BPF based on config file
    if let Some(bss) = open_skel.maps.bss_data.as_mut() {
        bss.target_mode = config.target_mode;

        // Set target_single_tgid if tgid is provided
        if let Some(tgid) = config.tgid {
            bss.target_single_tgid = tgid;
            println!("Set target_single_tgid to {}", tgid);
        }

        // Set target_single_tid to the first task's tid if available
        if let Some(first_task) = config.tasks.first() {
            bss.target_single_tid = first_task.tid;
        }
    }

    let mut skel = open_skel.load().context("Failed to load BPF object")?;

    // Update target_tids map with all tasks from config
    let target_tids = skel.maps.target_tids;

    for task in &config.tasks {
        let key = task.tid;
        let val = bpf_intf::target_ctx_t {
            prio: task.prio,
            slice: task.slice,
            on_ecore: task.on_ecore,
        };

        let key_bytes = unsafe {
            std::slice::from_raw_parts(
                &key as *const _ as *const u8,
                std::mem::size_of_val(&key),
            )
        };
        let val_bytes = unsafe {
            std::slice::from_raw_parts(
                &val as *const _ as *const u8,
                std::mem::size_of_val(&val),
            )
        };

        target_tids.update(key_bytes, val_bytes, MapFlags::ANY)?;
        println!("Configured task: tid={}, prio={}, slice={}, on_ecore={}",
                 task.tid, task.prio, task.slice, task.on_ecore);
    }

    // Load and attach the scheduler struct_ops
    let _struct_ops = skel
        .maps
        .teddy_ops
        .attach_struct_ops()
        .context("Failed to attach struct_ops")?;

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

    // Main loop - keep scheduler running
    while *running.lock().unwrap() {
        std::thread::sleep(Duration::from_millis(1000));

        if args.verbose {
            println!("Scheduler running...");
        }
    }

    println!("scx_teddy scheduler exiting...");

    Ok(())
}
