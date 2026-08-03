# scx_teddy

An eBPF-based (sched_ext) experimental scheduler and **framework** for studying
per-task scheduling. It collects each task's runtime behaviour online, clusters
tasks with an ML model (K-means), and applies a per-cluster scheduling policy —
priority, time slice, and CPU-kind placement on hybrid (big.LITTLE) machines.

The design goal is to make it *easy to collect data and easy to change the
scheduling policy*: train a model on your own workload, write a small JSON
policy, and run it — no recompilation. A Streamlit GUI wraps the whole loop (see
[`gui/`](gui/README.md)).

## Requirements

- Linux kernel with sched_ext support
- Root privileges (eBPF)
- Rust toolchain, libbpf
- Python 3 with `numpy`, `pandas`, `scikit-learn` (training + GUI)

## Building

```bash
cargo build --release
pip install -r requirements.txt
```

## Modes

scx_teddy runs in two modes: **collect** (gather task data into a CSV) and
**classify** (apply a trained model to schedule tasks live).

### Step 1: Collect task data

```bash
sudo ./target/release/scx_teddy -m collect -c 60 -o event.csv
```

**Options:**
- `-m, --mode <MODE>` — `collect` or `classify` (default: `collect`)
- `-c, --collect-duration <SECONDS>` — collect interval (default: 600)
- `-o, --output <PATH>` — output CSV (default: `event.csv`)
- `--min-events <N>` — minimum event count to include a task (default: 2)
- `--csv-checkpoint` — write the CSV every cycle. By default it is kept in memory
  and written once on shutdown; enable this so a crash / `kill -9` doesn't lose
  the run.
- `--max-runtime <SECONDS>` — stop after this long (writes the CSV and exits).
  `0` = no limit (default: `0`).
- `-v, --verbose` — verbose log to `teddy.log`

### Step 2: Train a K-means model

```bash
python3 train.py event.csv -o model.json
```

To restrict training to specific workloads, pass a `--train-config` file with
one `comm` prefix per line (lines starting with `#` and blanks are ignored):

```bash
python3 train.py event.csv -o model.json --train-config train_config.config
```

This selects the cluster count via the elbow method (or `-k`), writes the model
(centroids + scaler) to JSON, and writes `<model>_result.json` with per-cluster
task membership (tid, tgid, ppid, command).

**Options:**
- `-o, --output <PATH>` — output model JSON (default: `model.json`)
- `-k, --clusters <N>` — number of clusters (auto if omitted)
- `--train-config <PATH>` — comm-prefix filter list (default: all tasks)
- `--filter-tid / --filter-tgid / --filter-cmd <…>` — filter the training set
- `--exclude-feature <NAME…>` — train without these feature columns

Training ends with a set of diagnostics on the features themselves —
near-constant and binary columns, rank correlation between features, effective
dimensionality, silhouette against other cluster counts, and how far the split
departs from grouping by command name. To act on what they report, drop a
column and retrain:

```bash
python3 train.py event.csv -o model.json --exclude-feature iowait_ratio avg_sleep_ms
```

Excluding a column changes the model's feature list, so a model trained this
way expects the same CSV as any other — scx_teddy reads the feature names from
the model JSON and uses only those. An unknown name is rejected rather than
ignored.

### Step 3: Write a scheduling policy

A `config.json` maps each cluster id to a scheduling entry, plus a `default`
entry for clusters not listed (and for tasks scx_teddy can't place):

```json
{
  "clusters": {
    "0": { "prio": 0,  "slice_ns": 1500000, "cpu_kind": 1, "cpu_prefer": 1 },
    "1": { "prio": 2,  "slice_ns": 3000000 },
    "6": { "prio": 11, "slice_ns": 100000,  "cpu_prefer": 2 }
  },
  "default": { "prio": 11, "slice_ns": 100000 }
}
```

- **prio** — priority tier, `0` = highest, `11` = lowest (12 tiers). Tasks are
  dispatched from `prio 0` down. `prio < 4` is treated as *critical*: those tasks
  get an active idle-CPU search on wakeup (lowest latency); `prio >= 4` are just
  enqueued.
- **slice_ns** — time slice in nanoseconds, floored at 100000.
- **cpu_kind** *(hybrid machines)* — `0` (default) = shared, runnable on any CPU
  kind; otherwise 1-based, `1` = fastest tier (P-core), higher = slower (E-core /
  tier-N). scx_teddy discovers the kinds from cpufreq at startup and prints the
  valid range.
- **cpu_prefer** — `select_cpu` speed preference: `0` = none (auto-derived from
  `cpu_kind`), `1` = prefer fastest, `2` = prefer slowest.

### Step 4: Run with classification

```bash
sudo ./target/release/scx_teddy -m classify -c 1 --model model.json --config config.json
```

**classify options:**
- `--model <PATH>` / `--config <PATH>` — trained model + policy (both required)
- `-c, --collect-duration <SECONDS>` — re-classify period (default: 600; the GUI
  uses 1s for responsiveness)
- `--target-model <PATH>` / `--target-config <PATH>` — an optional *second*
  model + policy for the specialization target family (see below)
- `--control-interval <SECONDS>` — how often to re-read the control files
  (default: 5)

## Measuring what a policy should be: `expt_tolerance`

Writing a policy by hand means guessing which clusters actually need low latency.
`expt_tolerance` measures it instead: it injects a scheduling delay into one
cluster at a time, watches whether the game degrades, and derives the priorities
from what it found.

Select it by setting `algorithm` in the model JSON — the model itself is an
ordinary K-means model, so train it exactly as above and edit the one field
(`train.py` always writes `kmeans`):

```json
{
  "algorithm": "expt_tolerance",
  "n_clusters": 10,
  ...
}
```

The search runs per cluster, after a 30-second warm-up:

1. Measure the game undelayed, inject `expt_wait` into every task of the cluster,
   measure again, remove it, and measure a third time. The undelayed state is
   measured on **both** sides so the game's own fluctuation is not read as an
   effect of the delay.
2. Repeat for several rounds and sum how much each round cost. A delay counts as
   bad once the total crosses a threshold — summing rather than counting bad
   rounds lets one ruinous round and a run of mild ones both reach a verdict.
3. If the delay was tolerable, double it and go again; otherwise this cluster is
   done and its tolerance is the largest delay that survived.

Clusters are then ranked by measured tolerance — least tolerant gets `prio 0` —
and the result is written as a new config for you to inspect. **The input config
is never modified**: the calibration is a proposal, not something applied behind
your back. Name the destination with `calibrated_output`, or nothing is written:

```json
{
  "clusters": { "0": { "prio": 4, "slice_ns": 100000 } },
  "default":  { "prio": 4, "slice_ns": 100000 },
  "calibrated_output": "/path/to/config_calibrated.json"
}
```

It is printed at startup too, so a config you forgot to edit shows up
immediately rather than after a run that takes hours.

### What it measures the game with

Two signals over one shared window, either of which counts as a failure on its
own — stuttering video and broken audio are each unacceptable, and scoring them
apart keeps one from being averaged away by the other holding up:

| signal | source | needs |
|---|---|---|
| framerate | `vkQueuePresentKHR` in a Vulkan layer, over POSIX shared memory | the layer installed |
| audio rate | `pa_stream_write` uprobe, over a BPF map | the game to use PulseAudio |

The Vulkan layer is **not** part of this repository — it lives in the
[`latency_creater`](https://github.com/weiso131/latency_creater) project, under
its `game_fps/` directory. Without it there is no framerate to read and the
experiment cannot run. The audio side needs nothing extra, and a silent game
simply scores 0 there, leaving the framerate to decide.

⚠️ This mode **deliberately makes the game stutter** while it searches: injecting
delay is how it finds the limit. Run it to calibrate a policy, then run normally
with the config it produced.

⚠️ The GUI does not fully support this mode yet — it rebuilds the config from its
own editor and does not carry `calibrated_output` through, so the calibration
ends up somewhere disposable. **Run `expt_tolerance` from the command line** until
that is wired up.

## Specialization: optimizing one process family

scx_teddy can give one process and all its descendants their own scheduling,
distinct from the rest of the system — e.g. to prioritize a game's threads. The
target family is chosen *outside* scx_teddy by writing single values into control
files under `/tmp/scx_teddy/`, re-read every `--control-interval` seconds:

- `control_ppid` — the target ppid (`0` = none)
- `control_model` / `control_config` — an optional model + policy applied only to
  the target family (empty = use the default policy for it too)

Any program that can write a file can drive this. `target_finder_helper/` ships
an example scanner that detects a running Steam game and publishes its ppid; see
[`target_finder_helper/README.md`](target_finder_helper/README.md) for the
protocol and how to write your own.

## GUI

[`gui/`](gui/README.md) is a Streamlit dashboard over this whole loop: Collect,
Train, t-SNE visualization, Classify (with a live config editor + target
selection), and an htop-style Overall view. See [`gui/README.md`](gui/README.md).

---

[中文版說明文件](README.zh-TW.md)
