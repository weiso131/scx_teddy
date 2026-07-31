"""Subprocess wrappers around scx_teddy and train.py.

Design constraints (from demo.md):
  - No IPC layer. Control flows to scx_teddy by writing single values into the
    /tmp/scx_teddy/control_* files (an external scanner / the GUI / a manual
    `echo`); data flows back by reading files under /tmp. The GUI can die and
    scx_teddy keeps running; scx_teddy runs fine with no GUI at all.
  - Everything here just shells out — the GUI stays a thin shell over the
    same commands a user could type by hand.

scx_teddy needs root for BPF, so the collect command is wrapped in `sudo`.
The caller is responsible for the machine being able to sudo (cached creds
or a terminal askpass); we surface failures rather than prompt.
"""

from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path

# Repo root = parent of this gui/ directory.
REPO_ROOT = Path(__file__).resolve().parent.parent
TRAIN_PY = REPO_ROOT / "train.py"

# Optional repo-root stash dirs for hand-placed models / configs. The Classify
# pickers scan these in addition to the tmpfs data dir, so a user can drop a
# curated model or config here and have it show up in the dropdowns. Missing
# dirs are simply ignored.
MODEL_DIR = REPO_ROOT / "model"
CONFIG_DIR = REPO_ROOT / "config"

# Built binary location (cargo workspace target). Allow override via env so a
# release build or a custom path can be pointed at without code changes.
DEFAULT_BIN = REPO_ROOT / "target" / "release" / "scx_teddy"
SCX_TEDDY_BIN = Path(os.environ.get("SCX_TEDDY_BIN", DEFAULT_BIN))

# Default scratch location for collected data, per demo.md ("/tmp"). /tmp is
# tmpfs (RAM) here, so this is disk-free. gui.sh creates and exports this; the
# fallback keeps a bare `python3 gui/app.py` working too.
DEFAULT_DATA_DIR = Path(os.environ.get("SCX_TEDDY_DATA_DIR", "/tmp/scx_teddy_gui"))


class ProcessHandle:
    """A running child process whose stdout/stderr are pumped to a callback.

    `on_line(text)` is invoked from a reader thread for every output line
    (stdout and stderr merged). `on_exit(returncode)` fires once when the
    process ends. Both callbacks run off the Tk main thread, so the GUI must
    marshal back via `widget.after(...)`.
    """

    def __init__(self, argv, on_line, on_exit, label="proc"):
        self.label = label
        self._on_exit = on_exit
        # Line-buffered text pipes; merge stderr into stdout so ordering is
        # preserved in the log view. stdin kept open as a pipe so control
        # lines can be written later (the stdin command protocol on the
        # scx_teddy side is still TODO — see demo.md).
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self._reader = threading.Thread(
            target=self._pump, args=(on_line,), daemon=True
        )
        self._reader.start()

    def _pump(self, on_line):
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            on_line(line.rstrip("\n"))
        rc = self.proc.wait()
        self._on_exit(rc)

    def send_line(self, text: str) -> bool:
        """Write one line to the child's stdin.

        Returns False if the pipe is already closed/dead. Legacy channel from
        the old stdin-control design; scx_teddy is now driven by the /tmp
        control files (see write_control), so nothing here uses this anymore.
        Kept because an open stdin pipe is harmless.
        """
        if self.proc.stdin is None or self.proc.poll() is not None:
            return False
        try:
            self.proc.stdin.write(text + "\n")
            self.proc.stdin.flush()
            return True
        except (BrokenPipeError, ValueError):
            return False

    def is_running(self) -> bool:
        return self.proc.poll() is None

    def stop(self):
        """Ask the process to shut down (SIGINT, mirroring a terminal Ctrl-C).

        scx_teddy's Ctrl-C handler flushes the CSV and tears down the
        scheduler, so SIGINT (not SIGKILL) is the clean stop.
        """
        if self.is_running():
            self.proc.send_signal(signal.SIGINT)


def build_collect_argv(
    output: Path,
    duration: int | None = None,
    max_runtime: int | None = None,
    checkpoint: bool = False,
    use_sudo: bool = True,
) -> list[str]:
    """Build the argv for a `scx_teddy --mode collect` run.

    scx_teddy refuses to overwrite an existing --output file, so the caller
    must pick a fresh path (or delete the old one) before starting.
    """
    argv: list[str] = []
    if use_sudo:
        # -E preserves env (e.g. SCX_TEDDY_BIN) for the child; harmless if unset.
        argv += ["sudo", "-E"]
    argv += [str(SCX_TEDDY_BIN), "--mode", "collect", "--output", str(output)]
    if duration is not None:
        argv += ["--collect-duration", str(duration)]
    if max_runtime is not None and max_runtime > 0:
        argv += ["--max-runtime", str(max_runtime)]
    if checkpoint:
        argv += ["--csv-checkpoint"]
    return argv


def build_classify_argv(
    model: Path,
    config: Path,
    duration: int | None = None,
    target_model: Path | None = None,
    target_config: Path | None = None,
    use_sudo: bool = True,
) -> list[str]:
    """Build the argv for a `scx_teddy --mode classify` run.

    classify loads a trained model + scheduling config and runs until SIGINT
    (no max-runtime — that deadline is collect-only). Like collect it needs
    root for BPF, so it is wrapped in `sudo -E`.

    `duration` is `-c/--collect-duration`: in classify mode it is the predict
    *period* — the main loop re-classifies every `duration` seconds. scx_teddy's
    built-in default (600s) is far too slow to feel interactive, so the GUI
    passes an explicit value (defaulting to 1s).

    `target_model`/`target_config` (both or neither) seed the specialization
    target set at startup via --target-model/--target-config. This is the only
    way to set a target set *before* the scheduler runs: scx_teddy rebuilds the
    /tmp control files on init, so writing them before launch would be wiped.
    Once running, control_model/control_config (set_target_set) hot-swaps it.
    """
    argv: list[str] = []
    if use_sudo:
        argv += ["sudo", "-E"]
    argv += [str(SCX_TEDDY_BIN), "--mode", "classify",
             "--model", str(model), "--config", str(config)]
    if duration is not None:
        argv += ["--collect-duration", str(duration)]
    if target_model is not None and target_config is not None:
        argv += ["--target-model", str(target_model),
                 "--target-config", str(target_config)]
    return argv


# --- Specialization control files -------------------------------------------
# scx_teddy specializes a task family by reading three single-value files (see
# init_control_files / CONTROL_*_PATH in main.rs, and target_finder_helper/
# README.md). The scheduler creates them root-owned (it runs under sudo for
# BPF), so the GUI writes them via `sudo tee` — same cached-creds assumption as
# every other command here. control_ppid picks the family; control_model /
# control_config (classify only) give that family its own model + config (empty
# = fall back to the default set).
CONTROL_DIR = Path("/tmp/scx_teddy")
CONTROL_PPID_PATH = CONTROL_DIR / "control_ppid"
CONTROL_MODEL_PATH = CONTROL_DIR / "control_model"
CONTROL_CONFIG_PATH = CONTROL_DIR / "control_config"

# Directory of example scanners shipped in the repo. A scanner is any program
# that writes control_ppid; they run under sudo so they can write that
# root-owned file (the README documents this requirement). Discovered at
# runtime so adding a new scanner there shows up in the GUI dropdown with no
# code change here.
SCANNER_DIR = REPO_ROOT / "target_finder_helper"


def list_scanners() -> list[Path]:
    """Executable scanner scripts under SCANNER_DIR (newest-name first is not
    meaningful here, so sort by name). Currently just the .py examples; the
    dropdown is populated from this so future scanners need no code change."""
    if not SCANNER_DIR.is_dir():
        return []
    return sorted(p for p in SCANNER_DIR.glob("*.py") if p.is_file())


def write_control(path: Path, value: str, use_sudo: bool = True) -> None:
    """Write a single value into a (root-owned) control file via `sudo tee`.

    The one place the GUI writes a control file. Value goes in on stdin so it
    never lands in the process table. `tee`'s stdout is discarded. Raises
    CalledProcessError on failure (e.g. sudo creds expired) for the caller to
    surface; mirrors the "surface, don't prompt" stance of the run commands.
    """
    argv = (["sudo", "tee", str(path)] if use_sudo else ["tee", str(path)])
    subprocess.run(argv, input=value, text=True, check=True,
                   stdout=subprocess.DEVNULL)


def set_target_ppid(ppid: int) -> None:
    """Point the specialization target at `ppid` (0 clears it)."""
    write_control(CONTROL_PPID_PATH, str(int(ppid)))


def clear_target_ppid() -> None:
    """Clear the specialization target (control_ppid = 0)."""
    set_target_ppid(0)


def set_target_set(model: Path | None, config: Path | None) -> None:
    """Set (or clear) the target family's own model + config.

    Written as a pair: both paths together, or both empty to fall back to the
    default set. scx_teddy treats either one empty as "use default", so passing
    only one is pointless — callers should always supply both or neither.

    TODO: validate the model↔config cluster-count pairing here (separate TODO);
    scx_teddy doesn't enforce it (an unknown cluster falls back to default).
    """
    write_control(CONTROL_MODEL_PATH, str(model) if model else "")
    write_control(CONTROL_CONFIG_PATH, str(config) if config else "")


def clear_target_set() -> None:
    """Clear control_model / control_config (target family uses the default)."""
    set_target_set(None, None)


def read_control_ppid() -> int | None:
    """Read back the current control_ppid for display. Plain read (no sudo —
    the file is world-readable); malformed/missing → None."""
    try:
        return int(CONTROL_PPID_PATH.read_text().strip())
    except (OSError, ValueError):
        return None


def build_scanner_argv(scanner: Path, interval: int = 5,
                       use_sudo: bool = True) -> list[str]:
    """Build the argv to run a chosen scanner script. It writes control_ppid
    itself, so it needs sudo (root-owned file); -E preserves env. The scanner
    takes the scan interval (s) as its one positional arg (the example honours
    it; a custom scanner may ignore it)."""
    argv = ["sudo", "-E"] if use_sudo else []
    argv += [sys.executable, str(scanner), str(int(interval))]
    return argv


def build_train_argv(
    csv: Path,
    model_out: Path,
    k: int | None = None,
    train_config: Path | None = None,
) -> list[str]:
    """Build the argv for a `train.py` run. Produces model_out and, alongside
    it, <model_out stem>_result.json with per-task cluster membership."""
    argv = [sys.executable, str(TRAIN_PY), str(csv), "-o", str(model_out)]
    if k is not None:
        argv += ["-k", str(k)]
    if train_config is not None:
        argv += ["--train-config", str(train_config)]
    return argv


def model_n_clusters(model: Path) -> int | None:
    """Read `n_clusters` out of a trained model JSON, or None if unreadable.

    The Classify config editor uses this to show exactly one row per cluster
    (cluster ids 0..n-1) plus the `default` row. Best-effort: a malformed or
    missing file just yields None and the caller falls back to a manual count.
    """
    try:
        import json
        with open(model) as f:
            n = json.load(f).get("n_clusters")
        return int(n) if n is not None else None
    except (OSError, ValueError, TypeError):
        return None


# Defaults for a freshly-built cluster scheduling entry (see ClusterSchedConfig
# in main.rs). prio 11 = lowest priority, a 100us fixed slice, cpu_kind 0 =
# shared DSQ (runnable on any CPU kind). The editor seeds every row with these.
CONFIG_DEFAULT_PRIO = 11
CONFIG_DEFAULT_SLICE_NS = 100_000
CONFIG_DEFAULT_CPU_KIND = 0
CONFIG_DEFAULT_CPU_PREFER = 0

# cpu_prefer encodes a select_cpu speed preference; the editor shows the labels
# and writes the int. 0 = no preference (let the BPF side auto-derive from
# cpu_kind), 1 = prefer the fastest CPUs, 2 = prefer the slowest.
CPU_PREFER_LABELS = {0: "no preference", 1: "prefer fast", 2: "prefer slow"}
CPU_PREFER_BY_LABEL = {v: k for k, v in CPU_PREFER_LABELS.items()}


def make_cluster_entry(prio: int = CONFIG_DEFAULT_PRIO,
                       slice_ns: int = CONFIG_DEFAULT_SLICE_NS,
                       cpu_kind: int = CONFIG_DEFAULT_CPU_KIND,
                       cpu_prefer: int = CONFIG_DEFAULT_CPU_PREFER) -> dict:
    """One cluster's scheduling entry in the shape scx_teddy reads:
    {"prio", "slice_ns", "cpu_kind", "cpu_prefer"}.

    slice_ns is floored at CONFIG_DEFAULT_SLICE_NS (100us): anything smaller is
    not what the scheduler actually grants in practice, so a smaller value would
    silently mislead. We clamp at the single point every saved config flows
    through rather than only in the editor widget."""
    return {"prio": int(prio),
            "slice_ns": max(int(slice_ns), CONFIG_DEFAULT_SLICE_NS),
            "cpu_kind": int(cpu_kind),
            "cpu_prefer": int(cpu_prefer)}


# Where classify mode publishes its per-cycle snapshot (see write_snapshot in
# main.rs). Fixed path under tmpfs, independent of DEFAULT_DATA_DIR. The Overall
# tab reads it to fill the tier/slice/cluster columns; absent = scx_teddy isn't
# classifying, and those columns stay blank.
SNAPSHOT_PATH = Path("/tmp/scx_teddy/snapshot.json")


def read_snapshot() -> dict[int, dict] | None:
    """Read the classify snapshot, keyed by tid for an O(1) join against the
    /proc task list. Each value is {cluster, prio, slice_ns, cpu_kind,
    cpu_prefer, is_target}.

    Returns None when there's nothing to show (file missing — no classify run —
    or a transient read that lost the rename race / malformed). The caller
    treats None and a tid-miss identically: leave the columns blank. Best-effort
    by design; this is a live feed, a skipped frame just means stale-by-1s.
    """
    try:
        import json
        with open(SNAPSHOT_PATH) as f:
            tasks = json.load(f)
        return {int(t["tid"]): t for t in tasks}
    except (OSError, ValueError, KeyError, TypeError):
        return None


def read_config(path: Path) -> tuple[dict, dict] | None:
    """Parse an existing scheduling config JSON into ({clusters}, default).

    Best-effort: returns None if the file is missing or malformed. Used by the
    Classify editor's "Existing file" mode to seed the table from a config on
    disk, which the user can then re-shape (clusters added/dropped) before it
    is re-serialized to /tmp.
    """
    try:
        import json
        with open(path) as f:
            obj = json.load(f)
        clusters = obj.get("clusters", {})
        default = obj.get("default", {})
        if not isinstance(clusters, dict) or not isinstance(default, dict):
            return None
        return clusters, default
    except (OSError, ValueError):
        return None


def _config_json(clusters: dict[str, dict], default: dict) -> str:
    import json
    return json.dumps({"clusters": clusters, "default": default}, indent=2)


def write_config(clusters: dict[str, dict], default: dict,
                 directory: Path | None = None, prefix: str = "config") -> Path:
    """Serialize a {clusters, default} scheduling config to a fresh timestamped
    JSON under the data dir (tmpfs by default) and return its path.

    Writing to /tmp keeps the GUI-built config out of the repo and means the
    "edit in the GUI" path is just "write a file, then `--config` it" — no new
    channel, same thin-shell model as everything else here.

    `prefix` distinguishes configs written back-to-back: classify Start writes
    the default config and the target config in the same call. The timestamp is
    second-resolution, so without distinct prefixes they'd collide on the same
    name and the second write would clobber the first — both --config and
    --target-config ending up at one file with the target's contents. Pass
    "target_config" for the target so the two paths never alias.
    """
    out = timestamped_path(prefix, "json", directory=directory)
    out.write_text(_config_json(clusters, default))
    return out


def save_config_to(path: Path, clusters: dict[str, dict], default: dict) -> Path:
    """Write a {clusters, default} config to an explicit path, overwriting it.

    This is the deliberate "save back to the original file" action (the Classify
    editor's Save button) — distinct from `write_config`, which always picks a
    fresh /tmp path. Kept separate so an overwrite only ever happens on an
    explicit user click, never as a side effect of starting a run.
    """
    path.write_text(_config_json(clusters, default))
    return path


def ensure_data_dir() -> Path:
    DEFAULT_DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DEFAULT_DATA_DIR


def timestamped_path(prefix: str, ext: str, directory: Path | None = None) -> Path:
    """A fresh path named by wall-clock time so it never collides with a
    previous run. Used for both collected CSVs (scx_teddy refuses to overwrite
    an existing --output) and trained models (so a new train run doesn't
    silently clobber the last model). `ext` without dot.

    `directory` defaults to the tmpfs data dir; pass a user-chosen directory
    to write straight to persistent storage (SSD) instead of /tmp — the
    filename is still auto-generated, only the location changes.
    """
    if directory is None:
        directory = ensure_data_dir()
    else:
        directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return directory / f"{prefix}_{stamp}.{ext}"


# Path of the most recently produced output, regardless of where it landed
# (/tmp or a custom SSD dir). The tabs default their dropdown to this so a
# just-collected CSV / just-trained model is immediately the selection for the
# next step — the intuitive "I made a CSV, now I train/visualize it" flow.
# None until something is produced this session (then the dropdown has no
# default, which is fine: nothing exists to act on yet).
last_csv: Path | None = None
last_model: Path | None = None


def note_csv(path: Path) -> None:
    global last_csv
    last_csv = path


def note_model(path: Path) -> None:
    global last_model
    last_model = path


def list_files(pattern: str, directory: Path | None = None) -> list[Path]:
    """List files matching `pattern` under the data dir (newest first by
    mtime). This is the tmpfs /tmp menu of items that exist this boot — used
    to populate dropdowns so the user can also reach back to earlier files.
    The *default* selection, however, is driven by last_csv/last_model, which
    may point outside this dir (a custom SSD output)."""
    directory = directory or ensure_data_dir()
    if not directory.is_dir():
        return []
    files = [p for p in directory.glob(pattern) if p.is_file()]
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files


def list_models(directory: Path | None = None) -> list[Path]:
    """List model JSONs reachable in the Classify picker, newest first within
    each source: the tmpfs data dir (train.py output, `model_*.json`) plus any
    hand-placed models in the repo-root `model/` dir (any `*.json`). Both
    exclude `*_result.json` siblings so a model appears once.

    `directory` overrides only the tmpfs source (used by tests); MODEL_DIR is
    always added when it exists.
    """
    tmp = [p for p in list_files("model_*.json", directory)
           if not p.name.endswith("_result.json")]
    stash = []
    if MODEL_DIR.is_dir():
        stash = sorted(
            (p for p in MODEL_DIR.glob("*.json")
             if p.is_file() and not p.name.endswith("_result.json")),
            key=lambda p: p.stat().st_mtime, reverse=True)
    return tmp + stash


def list_configs(directory: Path | None = None) -> list[Path]:
    """List scheduling-config JSONs for the Classify 'Existing file' dropdown:
    the tmpfs data dir (GUI-written `config_*.json`) plus any hand-placed
    configs in the repo-root `config/` dir (any `*.json`). Newest first within
    each source. Missing CONFIG_DIR is ignored."""
    tmp = list_files("config_*.json", directory)
    stash = []
    if CONFIG_DIR.is_dir():
        stash = sorted((p for p in CONFIG_DIR.glob("*.json") if p.is_file()),
                       key=lambda p: p.stat().st_mtime, reverse=True)
    return tmp + stash


def copy_to(src: Path, dest_dir: Path, with_result: bool = False) -> list[Path]:
    """Copy a file out of tmpfs onto persistent storage (SSD). Returns the
    list of destination paths actually written.

    Uses copy (not move): the source in /tmp is often root-owned (collect runs
    under sudo) but world-readable, so a copy by the normal-user GUI works,
    whereas deleting the root-owned source would need privileges. /tmp clears
    on reboot anyway, so leaving the original is harmless.

    `with_result=True` (for models): if a sibling `<stem>_result.json` exists,
    copy it too, so the model and its cluster-membership file stay together.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    written = [Path(shutil.copy2(src, dest_dir / src.name))]
    if with_result:
        sibling = result_path_for(src)
        if sibling.exists():
            written.append(Path(shutil.copy2(sibling, dest_dir / sibling.name)))
    return written


# Back-compat aliases (CSV-specific names used by the Collect tab).
def timestamped_csv(prefix: str = "event", directory: Path | None = None) -> Path:
    return timestamped_path(prefix, "csv", directory)


def list_csvs(directory: Path | None = None) -> list[Path]:
    return list_files("*.csv", directory)


def clear_data(pattern: str) -> int:
    """Delete files matching `pattern` from the tmpfs data dir ONLY (not any
    SSD copy target — those are deliberate user backups). Returns how many
    were removed.

    No sudo needed: the data dir is owned by the normal user, and Unix
    deletion is governed by the directory's write permission, not the files'
    owner (they are root-owned because collect runs under sudo). /tmp is RAM
    anyway, so this just reclaims what would vanish on reboot.
    """
    removed = 0
    for p in DEFAULT_DATA_DIR.glob(pattern):
        if p.is_file():
            try:
                p.unlink()
                removed += 1
            except OSError:
                pass
    return removed


def result_path_for(model_out: Path) -> Path:
    """train.py writes <model>_result.json next to the model (it does
    output_path.replace('.json', '_result.json'))."""
    return model_out.with_name(model_out.stem + "_result.json")


def pretty_argv(argv: list[str]) -> str:
    return " ".join(shlex.quote(a) for a in argv)
