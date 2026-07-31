//! The `expt_tolerance` predictor: searches for how much scheduling delay each
//! cluster can tolerate before the user-visible metric degrades. Its metric
//! machinery is private to this module — nothing else in the crate uses it.
//!
//! It classifies exactly like the `kmeans` predictor (a self-contained copy, so
//! the two can diverge), then layers an experiment on top: after a warm-up it
//! picks one cluster and searches for how much scheduling delay that cluster's
//! tasks tolerate.
//!
//! Threading. `predict` runs on the main classify thread. Once the warm-up has
//! elapsed it spawns a single, detached experiment thread. The two share
//! `ExptState` behind a mutex: `predict` records each cluster's membership and
//! leaves the schedule of the cluster under test to the experiment thread,
//! which drives that cluster's tids. The experiment thread only touches
//! `ExptState` and its own owned `MapHandle` — never the classify thread's
//! stats map.
//! `expt_wait` stays 0 until the experiment sets a delay, so before then tasks
//! are scheduled purely by priority.

mod metric;
mod metrics;

use anyhow::{Context, Result};
use libbpf_rs::{MapCore, MapFlags, MapHandle};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use crate::predictor::{Collector, Predictor, SchedDecision, write_sched_info};
use crate::predictors::helper::{ClusterSchedConfig, KMeansCore, SchedConfig};
use crate::predictors::expt_tolerance::metric::Metric;
use crate::predictors::expt_tolerance::metrics::game_fps::GameFps;
use crate::task_stats::TaskStats;

/// Warm-up before the experiment starts: classify without touching `expt_wait`
/// for this long so the classification has settled. Constant for now.
const WARMUP: Duration = Duration::from_secs(30);

/// First injected delay of an experiment; it doubles from here.
const EXPT_WAIT_START: u64 = 1000; // ns
const MAX_WAIT_MULTIPLE: i32 = 21; // 1000 << 20 ≈ 1.049s
/// How many before/delayed/after rounds to run per `expt_wait` value.
const EXPT_ROUNDS: u32 = 5;
/// Total percentage of the metric an `expt_wait` may cost across its rounds
/// before it counts as "bad". Summing the drops rather than counting bad rounds
/// lets one ruinous round and a run of mild ones both add up to a verdict.
const DROP_SUM_THRESHOLD: f64 = 20.0;
/// Window length (seconds) a cluster's measurements start at.
const MEASURE_SEC_START: u32 = 1;
/// Longest window to grow to while chasing a fresh delay sample. Bounds how long
/// a round can stretch when a cluster's tasks wake infrequently.
const MEASURE_SEC_MAX: u32 = 20;
/// Least urgent priority the calibration will assign. Mirrors `DEFAULT_PRIO` in
/// intf.h (`PRIORITY_NUM - 1`); a prio past the BPF side's range would land
/// tasks in a DSQ that does not exist.
const MAX_PRIO: i32 = 11;

/// Per-cluster experiment progress. Index into `ExptState::clusters` is the
/// cluster id.
struct ClusterExpt {
    /// Running sum of `ln(runtime_ratio)` and its count. Their quotient is the
    /// log-domain mean of runtime_ratio; since `exp` is monotonic we compare
    /// clusters on the quotient directly and never convert back. Accumulated
    /// across cycles (not reset) for now.
    ln_sum: f64,
    count: u64,
    /// Every tid classified into this cluster so far. Accumulated across cycles
    /// and never cleared, so when the experiment thread reaches this cluster it
    /// gets the full membership instead of only the tasks that happened to wake
    /// since the switch — long-period tasks used to be missing from a cluster's
    /// early rounds. `predict` only touches this on a cluster transition (see
    /// `TaskStats::last_cluster`).
    tids: HashSet<i32>,
    /// The largest `expt_wait` that still measured OK; the tolerable delay found
    /// so far. 0 until the first good value.
    good_expt_wait: u64,
    /// The largest *measured* delay (ns) seen across the rounds of a good
    /// `expt_wait` — the tolerance this cluster demonstrated. Injecting a delay
    /// does not produce exactly that delay (queueing can push the real one
    /// higher), so this, not `good_expt_wait`, is what the priority assignment
    /// is derived from. 0 until a good value produced a usable reading.
    good_real_delay: u64,
    /// Whether this cluster's search has finished.
    done: bool,
}

impl ClusterExpt {
    fn new() -> Self {
        Self {
            ln_sum: 0.0,
            count: 0,
            tids: HashSet::new(),
            good_expt_wait: 0,
            good_real_delay: 0,
            done: false,
        }
    }

    /// Ordering key for cluster selection: the log-domain mean of runtime_ratio.
    /// Monotonic in the geometric mean, so it ranks clusters without the `exp`.
    /// `NEG_INFINITY` when there are no samples, so such clusters sort last.
    fn ratio_rank(&self) -> f64 {
        if self.count == 0 { f64::NEG_INFINITY } else { self.ln_sum / self.count as f64 }
    }
}

/// The scheduling parameters the experiment thread writes for the tids under
/// test — a snapshot of the cluster-under-test's config, minus `expt_wait`
/// (which the experiment sets/clears itself)
#[derive(Clone)]
struct ExptParams {
    prio: i32,
    cpu_kind: u8,
    cpu_prefer: u8,
    slice_ns: u64,
}

/// State shared between the classify thread (`predict`) and the experiment
/// thread. The experiment thread owns the search; `predict` only feeds it tids
/// and accumulates the runtime_ratio stats.
struct ExptState {
    /// The cluster currently under experiment. `None` before one is picked.
    expt_cluster: Option<usize>,
    /// Config snapshot of the cluster under test, for the experiment thread to
    /// write. Set together with `expt_cluster`.
    cur_params: Option<ExptParams>,
    /// Per-cluster experiment progress and membership, indexed by cluster id.
    clusters: Vec<ClusterExpt>,
    /// Per-cluster scheduling params, snapshotted from config at startup. The
    /// experiment thread reads these when it picks a cluster (config lives on
    /// the classify thread, so it is copied here once).
    cluster_params: Vec<ExptParams>,
}

impl ExptState {
    fn new(cluster_params: Vec<ExptParams>) -> Self {
        let n_clusters = cluster_params.len();
        Self {
            expt_cluster: None,
            cur_params: None,
            clusters: (0..n_clusters).map(|_| ClusterExpt::new()).collect(),
            cluster_params,
        }
    }

    /// Snapshot of the tids in the cluster currently under test. Empty when no
    /// cluster is under test.
    fn expt_tids(&self) -> Vec<i32> {
        self.expt_cluster
            .and_then(|c| self.clusters.get(c))
            .map(|c| c.tids.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Pick the not-yet-done cluster with the highest runtime_ratio rank.
    /// Returns None when every remaining cluster is done, unsampled, or empty.
    ///
    /// Classification is chaotic during warm-up, so a cluster can hold stats
    /// from tasks since classified elsewhere while holding no members at all.
    /// Those stats still rank it, which is how an empty cluster got picked and
    /// then measured no delay at all.
    fn pick_cluster(&self) -> Option<usize> {
        self.clusters
            .iter()
            .enumerate()
            .filter(|(_, c)| !c.done && c.count > 0 && !c.tids.is_empty())
            .max_by(|(_, a), (_, b)| {
                a.ratio_rank().partial_cmp(&b.ratio_rank())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(i, _)| i)
    }

    /// The scheduling params to drive `cluster` with during its experiment.
    fn cur_params_for(&self, cluster: usize) -> ExptParams {
        self.cluster_params[cluster].clone()
    }
}

/// Write `expt_wait` (with the cluster-under-test's params) to every tid in the
/// cluster under test, tagging the write with `epoch`. Snapshots the tid set
/// under the lock, then writes without it held so `predict` is not blocked
/// during the map updates.
fn drive_tids(state: &Arc<Mutex<ExptState>>, map: &MapHandle, expt_wait: u64, epoch: u64) {
    let (tids, params) = {
        let st = state.lock().unwrap();
        match &st.cur_params {
            Some(p) => (st.expt_tids(), p.clone()),
            None => return,
        }
    };
    for tid in tids {
        let decision = SchedDecision {
            cluster: 0, // unused by write_sched_info
            prio: params.prio,
            cpu_kind: params.cpu_kind,
            cpu_prefer: params.cpu_prefer,
            slice_ns: params.slice_ns,
            expt_wait,
            epoch,
        };
        // A tid that has exited is simply skipped: the cluster's roster keeps
        // dead tids (nothing prunes it), and they must not be waited on.
        if let Err(e) = write_sched_info(map, tid, &decision) {
            eprintln!("[expt] write_sched_info(tid={tid}) failed: {e}");
        }
    }
}

/// The experiment thread. Picks one cluster at a time (highest runtime_ratio
/// rank), then grows `expt_wait` from `EXPT_WAIT_START`, doubling each step,
/// until a value looks bad — that ends the cluster's search. Each value is
/// judged over `EXPT_ROUNDS` before/delayed/after rounds. `measure` blocks
/// (~1s) inside the layer, which paces the loop; it runs without the lock held
/// so `predict` can keep feeding tids meanwhile.
/// Size of the BPF `sched_delay_t` value: the EWMA followed by its epoch.
const DELAY_VALUE_SIZE: usize = 16;

/// Read one tid's published (ewma, epoch). None when the tid has no entry yet
/// (never published, or exited and `teddy_exit` deleted it).
fn read_delay(delay_map: &MapHandle, tid: i32) -> Option<(u64, u64)> {
    let key = tid.to_ne_bytes();
    // The lookup goes through the syscall, which copies the value out, so this
    // is a snapshot of the last publish rather than a live view of the entry.
    match delay_map.lookup(&key, MapFlags::ANY) {
        Ok(Some(val)) if val.len() == DELAY_VALUE_SIZE => Some((
            u64::from_ne_bytes(val[..8].try_into().unwrap()),
            u64::from_ne_bytes(val[8..16].try_into().unwrap()),
        )),
        Ok(Some(val)) => {
            eprintln!("[expt] delay lookup(tid={tid}): unexpected value len {}", val.len());
            None
        }
        Ok(None) => None,
        Err(e) => {
            eprintln!("[expt] delay lookup(tid={tid}) failed: {e}");
            None
        }
    }
}

/// Mean sched-delay EWMA (ns) over the current cluster's tids, counting only
/// samples taken under `epoch` — that is, measured while the params this round
/// wrote were the ones in force.
fn cluster_mean_delay(
    state: &Arc<Mutex<ExptState>>,
    delay_map: &MapHandle,
    epoch: u64,
) -> Option<u64> {
    let tids: Vec<i32> = state.lock().unwrap().expt_tids();
    let mut sum: u128 = 0;
    let mut n: u64 = 0;
    for tid in tids {
        let Some((ewma, sample_epoch)) = read_delay(delay_map, tid) else {
            continue;
        };
        if ewma > 0 && sample_epoch == epoch {
            sum += ewma as u128;
            n += 1;
        }
    }
    if n == 0 { None } else { Some((sum / n as u128) as u64) }
}

/// Measure one window that the cluster demonstrably lived through under
/// `epoch`'s params: a delay sample carrying that epoch proves its tasks both
/// picked the params up and ran while we were watching. When none appears the
/// window was shorter than their wake period, so it grows (up to
/// `MEASURE_SEC_MAX`) and measures again — `measure_sec` is `&mut` so that
/// growth carries to every later call instead of being re-paid each time.
///
/// Returns the fps sample and the cluster's mean delay over the window, the
/// latter `None` if the cluster stayed silent even at the longest window.
fn measure_window(
    state: &Arc<Mutex<ExptState>>,
    delay_map: &MapHandle,
    measure_sec: &mut u32,
    epoch: u64,
    phase: &str,
    cluster: usize,
) -> (GameFps, Option<u64>) {
    loop {
        // `measure` only errors while first mapping the shm; once that succeeds
        // it always returns `Ok`
        let sample = GameFps::measure(*measure_sec)
            .unwrap_or_else(|e| panic!("measure ({phase}) failed after warm-up: {e}"));
        let delay = cluster_mean_delay(state, delay_map, epoch);
        if delay.is_some() || *measure_sec >= MEASURE_SEC_MAX {
            return (sample, delay);
        }
        *measure_sec += 1;
        eprintln!("[expt] cluster {cluster}: no sample for epoch {epoch}, window -> {measure_sec}s");
    }
}

fn experiment_loop(
    state: Arc<Mutex<ExptState>>,
    map: MapHandle,
    delay_map: MapHandle,
    config: SchedConfig,
    config_path: String,
) {
    eprintln!("[expt] experiment thread started");
    loop {
        let cluster = {
            let mut st = state.lock().unwrap();
            let Some(cluster) = st.pick_cluster() else {
                eprintln!("[expt] all clusters done, calibrating");
                // finish_calibration takes the lock itself.
                drop(st);
                finish_calibration(&state, &config, &config_path);
                return;
            };
            let params = st.cur_params_for(cluster);
            st.expt_cluster = Some(cluster);
            st.cur_params = Some(params);
            cluster
        };
        eprintln!("[expt] start cluster {cluster}");

        // Restarts per cluster: a cluster's tasks have never been driven when it
        // is picked, so they carry epoch 0, and the first `before` has to ask for
        // the epoch they actually hold. Only the cluster under test is read, so
        // the numbers never have to be unique across clusters.
        let mut epoch: u64 = 0;

        // Grow expt_wait until a value looks bad, or until we hit the cap. The
        // cap bounds the injected delay so a task with no tolerable limit never
        // gets so much delay that sched-ext tears the scheduler down.
        let mut expt_wait = EXPT_WAIT_START;
        // Only ever grows: a bigger injected delay never needs a shorter window
        // than the one that already worked, so restarting at the minimum each
        // round would re-pay the same lengthening.
        let mut measure_sec = MEASURE_SEC_START;
        for _ in 0..MAX_WAIT_MULTIPLE {
            let mut drop_sum = 0.0;
            // Largest delay actually measured across this value's rounds.
            let mut max_real_delay = 0u64;
            for _ in 0..EXPT_ROUNDS {
                // Matches the epoch the previous round's restore wrote, or 0 on
                // the first round — which the cluster's tasks still carry, and
                // which means the same thing here: no delay injected.
                let (before, _) =
                    measure_window(&state, &delay_map, &mut measure_sec, epoch, "before", cluster);

                epoch += 1;
                drive_tids(&state, &map, expt_wait, epoch);
                let (delayed, real_delay) =
                    measure_window(&state, &delay_map, &mut measure_sec, epoch, "delayed", cluster);

                epoch += 1;
                drive_tids(&state, &map, 0, epoch);
                let (after, _) =
                    measure_window(&state, &delay_map, &mut measure_sec, epoch, "after", cluster);

                if let Some(d) = real_delay {
                    max_real_delay = max_real_delay.max(d);
                }

                let drop = delayed.regression(&before, &after);
                // Negative drops are kept so the round-to-round noise cancels in
                // the sum instead of only ever accumulating upwards.
                drop_sum += drop;

                eprintln!(
                    "[expt] cluster {cluster}: expt_wait={expt_wait} epoch={epoch} real_delay={} ns \
                     drop={drop:.1}% (before_fps={:.1} delayed_fps={:.1} after_fps={:.1})",
                    real_delay.map_or("n/a".to_string(), |d| d.to_string()),
                    before.fps, delayed.fps, after.fps
                );
            }

            // A bad value ends the search: good_expt_wait already holds the last
            // OK value. Otherwise record this value as good and double it.
            if drop_sum >= DROP_SUM_THRESHOLD {
                eprintln!(
                    "[expt] cluster {cluster}: expt_wait={expt_wait} bad \
                     (drop_sum={drop_sum:.1}%) -> done"
                );
                break;
            }

            eprintln!(
                "[expt] cluster {cluster}: expt_wait={expt_wait} ok \
                 (max real_delay={max_real_delay} ns), doubling"
            );
            if let Some(c) = state.lock().unwrap().clusters.get_mut(cluster) {
                c.good_expt_wait = expt_wait;
                // Keep the largest measured delay this cluster tolerated
                c.good_real_delay = c.good_real_delay.max(max_real_delay);
            }
            expt_wait = expt_wait.saturating_mul(2);
        }

        // The cluster's search is over whether it ended on a bad value or ran
        // out of room at the cap — either way mark it done and stop claiming the
        // cluster, so its tasks go back to being scheduled by `predict`. The
        // membership set stays: it is the cluster's roster, not a hand-off queue.
        let mut st = state.lock().unwrap();
        if let Some(c) = st.clusters.get_mut(cluster) {
            c.done = true; // good_expt_wait holds the last OK value (0 if none)
        }
        st.expt_cluster = None;
        st.cur_params = None;
    }
}

/// How many times the smallest tolerance in a group may be multiplied before a
/// cluster is considered too far apart to share a priority. Delays within a
/// factor of `TOLERANCE_GROUP_K` of the group's smallest are treated as
/// indistinguishable, since the search itself only doubles `expt_wait`.
const TOLERANCE_GROUP_K: u64 = 2;

/// Group clusters by tolerance, ordered ascending — the least tolerant group
/// first. Walking the sorted delays, the smallest ungrouped delay anchors a
/// group and everything up to `anchor * TOLERANCE_GROUP_K` joins it; the first
/// delay past that bound anchors the next group. Groups are relative to each
/// anchor rather than fixed decade boundaries, so nearby tolerances stay
/// together regardless of where they fall on a log scale.
fn tolerance_groups(clusters: &[ClusterExpt]) -> Vec<Vec<usize>> {
    let mut measured: Vec<(usize, u64)> = clusters
        .iter()
        .enumerate()
        .filter(|(_, c)| c.good_real_delay > 0)
        .map(|(i, c)| (i, c.good_real_delay))
        .collect();
    measured.sort_by_key(|&(_, delay)| delay);

    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut anchor: Option<u64> = None;
    for (cluster, delay) in measured {
        match anchor {
            // saturating_mul so a huge anchor never overflows the bound.
            Some(a) if delay <= a.saturating_mul(TOLERANCE_GROUP_K) => {
                groups.last_mut().expect("anchor set implies a group exists").push(cluster);
            }
            _ => {
                groups.push(vec![cluster]);
                anchor = Some(delay);
            }
        }
    }
    groups
}

/// Build a config with priorities derived from the measured tolerances
fn calibrated_config(base: &SchedConfig, clusters: &[ClusterExpt]) -> SchedConfig {
    let mut out = base.clone();
    for (rank, group) in tolerance_groups(clusters).iter().enumerate() {
        let prio = (rank as i32).min(MAX_PRIO);
        for &cluster in group {
            let entry = out
                .clusters
                .entry(cluster.to_string())
                .or_insert_with(|| base.cluster_or_default(cluster).clone());
            entry.prio = prio;
        }
    }
    out
}

/// Write `config` next to `base_path` as `<stem>_calibrated.json`. Returns the
/// path written. The original is never modified: the calibration is a proposal
/// to inspect, not something to apply behind the user's back.
fn write_calibrated_config(base_path: &str, config: &SchedConfig) -> Result<PathBuf> {
    let base = Path::new(base_path);
    let stem = base.file_stem().and_then(|s| s.to_str()).unwrap_or("config");
    let out_path = base.with_file_name(format!("{stem}_calibrated.json"));
    let json = serde_json::to_string_pretty(config)
        .context("Failed to serialize the calibrated config")?;
    std::fs::write(&out_path, json)
        .with_context(|| format!("Failed to write calibrated config: {}", out_path.display()))?;
    Ok(out_path)
}

/// Report the measured tolerances and emit the calibrated config. Called once,
/// when every cluster's search has finished.
fn finish_calibration(state: &Arc<Mutex<ExptState>>, config: &SchedConfig, config_path: &str) {
    let st = state.lock().unwrap();

    for (rank, group) in tolerance_groups(&st.clusters).iter().enumerate() {
        let prio = (rank as i32).min(MAX_PRIO);
        for &cluster in group {
            eprintln!(
                "[expt] cluster {cluster}: tolerance={} ns -> prio {prio}",
                st.clusters[cluster].good_real_delay
            );
        }
    }
    for (i, c) in st.clusters.iter().enumerate() {
        if c.good_real_delay == 0 {
            eprintln!("[expt] cluster {i}: no measured tolerance, priority left as configured");
        }
    }

    match write_calibrated_config(config_path, &calibrated_config(config, &st.clusters)) {
        Ok(path) => eprintln!("[expt] calibrated config written to {}", path.display()),
        Err(e) => eprintln!("[expt] failed to write calibrated config: {e:#}"),
    }
}

/// Snapshot a cluster's config as `ExptParams` for the experiment thread.
fn to_expt_params(cfg: &ClusterSchedConfig) -> ExptParams {
    ExptParams {
        prio: cfg.prio,
        cpu_kind: cfg.cpu_kind,
        cpu_prefer: cfg.cpu_prefer,
        slice_ns: cfg.slice_ns,
    }
}

/// Feature extraction for this predictor. Same feature set as the kmeans
/// predictor, kept as its own copy so the two can diverge.
pub struct ExptToleranceCollector;

impl ExptToleranceCollector {
    /// Returns (name, value) pairs for all features.
    /// The order here defines the CSV column order and feature vector order.
    pub fn named_stats(stats: &TaskStats) -> Vec<(&'static str, f64)> {
        vec![
            ("runtime_ms", stats.avg_runtime_ms()),
            ("runtime_cv", stats.runtime_cv()),
            ("avg_sleep_ms", stats.avg_sleep_ms()),
            ("sleep_cv", stats.sleep_cv()),
            ("iowait_ratio", stats.sleep_base_ratio(stats.in_iowait_cnt)),
            ("futex_wait_ratio", stats.sleep_base_ratio(stats.futex_wait_cnt)),
            ("ntsync_wait_ratio", stats.sleep_base_ratio(stats.ntsync_wait_cnt)),
            ("audio_rate", stats.audio_rate_max as f64),
            ("present_rate", stats.present_rate_max as f64),
            ("submit_rate", stats.submit_rate_max as f64),
            ("runtime_ratio", stats.avg_runtime_ms() / (stats.avg_runtime_ms() + stats.avg_sleep_ms())),
        ]
    }

    /// Returns feature values as a Vec (order matches named_stats).
    pub fn feature_values(stats: &TaskStats) -> Vec<f64> {
        Self::named_stats(stats).into_iter().map(|(_, v)| v).collect()
    }

    /// Returns feature names (order matches feature_values).
    pub fn feature_names() -> Vec<&'static str> {
        Self::named_stats(&TaskStats::default()).into_iter().map(|(n, _)| n).collect()
    }
}

impl Collector for ExptToleranceCollector {
    fn named_stats(&self, stats: &TaskStats) -> Vec<(&'static str, f64)> {
        Self::named_stats(stats)
    }

    fn feature_values(&self, stats: &TaskStats) -> Vec<f64> {
        Self::feature_values(stats)
    }

    fn feature_names(&self) -> Vec<&'static str> {
        Self::feature_names()
    }
}

#[derive(Deserialize)]
struct KMeansScaler {
    mean: Vec<f64>,
    std: Vec<f64>,
}

#[derive(Deserialize)]
pub struct ExptToleranceModel {
    n_clusters: usize,
    features: Vec<String>,
    centroids: Vec<Vec<f64>>,
    scaler: KMeansScaler,
}

pub struct ExptTolerancePredictor {
    n_clusters: usize,
    /// Nearest-centroid classifier (feature selection + scaler + centroids).
    core: KMeansCore,
    /// Maps a cluster to its scheduling parameters. An unknown cluster falls
    /// back to the config's `default` entry.
    config: SchedConfig,
    /// Where `config` was loaded from; the calibrated config is written beside
    /// it when the experiment finishes.
    config_path: String,
    /// When this predictor was created, for measuring the warm-up.
    start: Instant,
    /// Set once the experiment thread has been spawned, so it happens only once.
    spawned: AtomicBool,
    /// Shared with the experiment thread (see `ExptState`).
    state: Arc<Mutex<ExptState>>,
    /// Owned handle to the BPF per-tid delay-EWMA map, set by
    /// `attach_sched_delay_map` after the skeleton loads and handed to the
    /// experiment thread when it spawns. `None` until then.
    sched_delay_map: Mutex<Option<MapHandle>>,
}

impl ExptTolerancePredictor {
    pub fn from_model(model: ExptToleranceModel, config_path: &str) -> Result<Self> {
        let core = KMeansCore::from_model_parts(
            model.n_clusters,
            &model.features,
            model.centroids,
            model.scaler.mean,
            model.scaler.std,
            &ExptToleranceCollector::feature_names(),
        )?;
        let config = SchedConfig::from_path(config_path)?;

        // Snapshot each cluster's params for the experiment thread (config lives
        // on the classify thread). An unknown cluster falls back to `default`.
        let cluster_params: Vec<ExptParams> = (0..model.n_clusters)
            .map(|c| to_expt_params(config.cluster_or_default(c)))
            .collect();

        Ok(Self {
            n_clusters: model.n_clusters,
            core,
            config,
            config_path: config_path.to_string(),
            start: Instant::now(),
            spawned: AtomicBool::new(false),
            state: Arc::new(Mutex::new(ExptState::new(cluster_params))),
            sched_delay_map: Mutex::new(None),
        })
    }

    /// After the warm-up, spawn the experiment thread exactly once. Called from
    /// `predict`, where `update_map` is available to clone into an owned handle
    /// the thread can keep. The thread picks which cluster to experiment on.
    fn maybe_spawn_experiment(&self, update_map: &libbpf_rs::Map) -> Result<()> {
        if self.start.elapsed() < WARMUP {
            return Ok(());
        }
        // Claim the spawn: only the thread that flips false->true proceeds.
        if self.spawned.swap(true, Ordering::AcqRel) {
            return Ok(());
        }

        let map = MapHandle::try_from(update_map)
            .context("Failed to clone update_map for the experiment thread")?;
        // Take the delay-map handle attached after load. It must be present by
        // now: attach_sched_delay_map runs right after the skeleton loads, long
        // before the warm-up that gates this spawn elapses.
        let delay_map = self.sched_delay_map.lock().unwrap().take()
            .context("sched_delay_map was never attached before the experiment spawned")?;
        let state = Arc::clone(&self.state);
        // The thread outlives this borrow, so it gets its own copy of the config
        // to build the calibrated one from.
        let config = self.config.clone();
        let config_path = self.config_path.clone();
        eprintln!("[expt] warm-up done, spawning experiment thread");
        std::thread::spawn(move || {
            experiment_loop(state, map, delay_map, config, config_path)
        });
        Ok(())
    }
}

impl Predictor for ExptTolerancePredictor {
    fn predict(
        &self,
        tid: i32,
        stats: &mut TaskStats,
        update_map: &libbpf_rs::Map,
    ) -> Result<Option<SchedDecision>> {
        // Spawn the experiment thread once the warm-up has elapsed.
        self.maybe_spawn_experiment(update_map)?;

        if stats.need_update == 0 {
            return Ok(None);
        }
        stats.need_update = 0;

        let named_stats = ExptToleranceCollector::named_stats(stats);
        let raw_features: Vec<f64> = named_stats.iter().map(|(_, v)| *v).collect();
        let cluster = self.core.nearest_cluster(&raw_features);

        let cluster_cfg = self.config.cluster_or_default(cluster);

        let decision = SchedDecision {
            cluster,
            prio: cluster_cfg.prio,
            cpu_kind: cluster_cfg.cpu_kind,
            cpu_prefer: cluster_cfg.cpu_prefer,
            slice_ns: cluster_cfg.slice_ns,
            expt_wait: 0,
            epoch: 0,
        };

        let runtime_ratio = named_stats
            .iter()
            .find(|(n, _)| *n == "runtime_ratio")
            .map(|(_, v)| *v)
            .unwrap_or(0.0);

        // Accumulate the cluster's runtime_ratio (for cluster selection), keep
        // the cluster membership sets current, and decide whether the experiment
        // thread owns this tid's schedule. The lock is held only long enough to
        // update the shared state.
        let handed_off = {
            let mut st = self.state.lock().unwrap();
            if let Some(c) = st.clusters.get_mut(cluster) {
                // ln(0) would poison the mean, so only count positive ratios.
                if runtime_ratio > 0.0 {
                    c.ln_sum += runtime_ratio.ln();
                    c.count += 1;
                }
            }

            // Membership only changes when the task's cluster does, which is
            // rare once classification settles — so in the steady state this
            // costs one comparison rather than a set update every cycle.
            if stats.last_cluster != cluster as i32 {
                if let Ok(prev) = usize::try_from(stats.last_cluster) {
                    if let Some(c) = st.clusters.get_mut(prev) {
                        c.tids.remove(&tid);
                    }
                }
                if let Some(c) = st.clusters.get_mut(cluster) {
                    c.tids.insert(tid);
                }
                stats.last_cluster = cluster as i32;
            }

            // Checked every cycle, not just on a transition: a task whose
            // cluster never changes still has to be handed off once the
            // experiment reaches its cluster.
            st.expt_cluster == Some(cluster)
        };

        if !handed_off {
            let _ = write_sched_info(update_map, tid, &decision)?;
        }
        Ok(Some(decision))
    }

    fn attach_sched_delay_map(&self, map: &libbpf_rs::Map) {
        match MapHandle::try_from(map) {
            Ok(handle) => *self.sched_delay_map.lock().unwrap() = Some(handle),
            // Only logged: the experiment thread's take() will surface a hard
            // error if it spawns without a handle, so a failure here isn't silent.
            Err(e) => eprintln!("[expt] failed to clone sched_delay_map: {e}"),
        }
    }

    fn n_outputs(&self) -> usize {
        self.n_clusters
    }

    fn validate(&self, cpu_kind_num: u8) -> Result<()> {
        self.config.validate_cpu_kind(cpu_kind_num)
    }
}
