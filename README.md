# scx_teddy

An eBPF-based experimental scheduler that collects task runtime data online and exposes it to userspace. This provides a foundation for future scheduling optimizations using ML models or agents.

## Building

```bash
cargo build --release
```

## Usage

```bash
sudo ./target/release/scx_teddy [OPTIONS]
```

**Options:**
- `-v, --verbose` - Enable verbose output
- `-c, --collect-duration <SECONDS>` - Data collection interval in seconds (default: 600)

**Example:**

```bash
# Collect and report statistics every 60 seconds
sudo ./target/release/scx_teddy -c 60
```

After each interval, the scheduler prints event counts per TID and resets counters for the next collection period.

## Requirements

- Linux kernel with sched_ext support
- Root privileges (required for eBPF operations)
- Rust toolchain
- libbpf

---

[中文版說明文件](README.zh-TW.md)
