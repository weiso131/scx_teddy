# scx_teddy

An experimental sched-ext scheduler with profiling-guided optimization.

## Overview

scx_teddy is a sched-ext based experimental scheduler that provides a tracer to profile and record multi-threaded task behavior. By analyzing the collected runtime characteristics along with domain knowledge about the workload, scheduling parameters can be fine-tuned either manually or with assistance from LLMs to optimize performance for specific applications.

## Components

### 1. scx_teddy - Main Scheduler

The main scheduler component that loads and runs the BPF-based scheduling policy.

#### Building

```bash
cd scx_teddy
cargo build --release
```

#### Usage

```bash
sudo ./target/release/scx_teddy --config <CONFIG_FILE>
```

**Options:**
- `-c, --config <CONFIG_FILE>` - Path to JSON configuration file (required)
- `-v, --verbose` - Enable verbose output

#### Configuration Format

The scheduler uses JSON configuration files to specify scheduling parameters:

```json
{
  "target_mode": 0,
  "tgid": 12345,
  "tasks": [
    {
      "tid": 28182,
      "prio": 2,
      "slice": 100000000000,
      "on_ecore": 1
    }
  ]
}
```

**Configuration Fields:**
- `target_mode` (required): Target mode for the scheduler
- `tgid` (optional): Thread group ID. If specified, sets `target_single_tgid`
- `tasks` (required): Array of task configurations
  - `tid`: Thread ID
  - `prio`: Priority level (valid range: 0-2)
  - `slice`: Time slice in nanoseconds
  - `on_ecore`: Whether to run on E-core (1) or not (0)

**Example Configuration Files:**
- `config.example.json` - Basic configuration without TGID
- `config.with-tgid.example.json` - Configuration with TGID specified

### 2. Tracer - Task Runtime and Sleep Tracer

An eBPF-based tool for monitoring task execution time, sleep duration, and scheduling behavior.

#### Building

```bash
cd tracer
cargo build --release
```

#### Usage

```bash
sudo ./target/release/tracer [OPTIONS]
```

**Options:**
- `-m, --mode <MODE>` - Tracing mode (default: tid)
  - `tid`: Trace specific threads (Thread ID)
  - `tgid`: Trace entire process (Process ID)
- `-t, --target <TARGET>` - Specify trace target(s) (can be used multiple times)
  - If not specified:
    - `tid` mode: traces current thread
    - `tgid` mode: traces current process
- `-d, --duration <DURATION>` - Trace duration in seconds (default: 10)
  - Set to 0 for unlimited duration (until Ctrl+C)

#### Examples

1. **Trace a specific TID for 10 seconds**
   ```bash
   sudo ./tracer -m tid -t 12345
   ```

2. **Trace a specific TGID (entire process) for 30 seconds**
   ```bash
   sudo ./tracer -m tgid -t 5678 -d 30
   ```

3. **Trace multiple TIDs**
   ```bash
   sudo ./tracer -m tid -t 100 -t 200 -t 300 -d 60
   ```

4. **Trace current thread indefinitely**
   ```bash
   sudo ./tracer -m tid -d 0
   ```

5. **Trace multiple TGIDs**
   ```bash
   sudo ./tracer -m tgid -t 1000 -t 2000 -d 20
   ```

#### Output Statistics

The tracer provides comprehensive statistics including:

- **Event count**: Total number of events captured
- **Runtime**: Execution time statistics
  - Average: Mean execution time
  - Std dev: Standard deviation
  - Min/Max: Minimum and maximum values
- **Sleep Duration**: Sleep time statistics (if sleep events occur)
  - Count: Number of sleep events
  - Average, Std dev, Min, Max
- **Sleep Interval**: Time between consecutive sleeps
  - Count, Average, Std dev, Min, Max

All time values are reported in milliseconds (ms).

## Requirements

- Linux kernel with sched_ext support
- Root privileges (required for eBPF operations)
- Rust toolchain
- libbpf

## Recent Changes

- Implemented user-space target specification with JSON configuration support
- Added tracer for monitoring task runtime and sleep behavior
- Implemented eBPF-based scheduling framework

---

[中文版說明文件](README.zh-TW.md)
