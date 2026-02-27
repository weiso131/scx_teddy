// SPDX-License-Identifier: GPL-2.0
//! scx_teddy - A BPF scheduler based on task runtime characteristics

use std::mem::MaybeUninit;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;

mod bpf_skel {
    include!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
}

mod bpf_intf {
    #[allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/intf.rs"));
}

#[allow(clippy::wildcard_imports)]
use bpf_skel::*;

#[derive(Parser, Debug)]
#[command(name = "scx_teddy")]
#[command(about = "scx_teddy - A BPF scheduler based on task runtime characteristics", long_about = None)]
struct Args {
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("scx_teddy scheduler starting...");

    // Build and load eBPF skeleton
    let skel_builder = BpfSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object).context("Failed to open BPF object")?;
    let mut skel = open_skel.load().context("Failed to load BPF object")?;

    // Load and attach the scheduler struct_ops
    let _struct_ops = skel
        .maps
        .teddy_ops
        .attach_struct_ops()
        .context("Failed to attach struct_ops")?;

    println!("scx_teddy scheduler loaded successfully!");
    println!("All tasks scheduled as NORMAL");
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
