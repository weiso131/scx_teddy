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
//! `ExptState` behind a mutex: `predict` routes tasks of the cluster under test
//! into `expt_tids` instead of writing their schedule itself, and the experiment
//! thread drives those tids. The experiment thread only ever touches `ExptState`
//! and its own owned `MapHandle` — never the classify thread's stats map.
//! `expt_wait` stays 0 until the experiment sets a delay, so before then tasks
//! are scheduled purely by priority.

mod metric;
mod metrics;

use anyhow::{Context, Result};
use libbpf_rs::MapHandle;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use crate::predictor::{Collector, Predictor, SchedDecision, write_sched_info};
use crate::predictors::helper::{ClusterSchedConfig, KMeansCore, SchedConfig, SliceConfig};
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
/// How many of those rounds must look worse for the value to count as "bad".
const EXPT_BAD_THRESHOLD: u32 = 3;
/// Fixed slice used while experimenting when the cluster's config is adaptive:
/// the experiment thread has no per-task stats to compute an adaptive slice.
const EXPT_FIXED_SLICE_NS: u64 = 100 * 1000; // 100us, mirrors DEFAULT_SLICE

/// Per-cluster experiment progress. Index into `ExptState::clusters` is the
/// cluster id.
#[derive(Clone)]
struct ClusterExpt {
    /// Running sum of `ln(runtime_ratio)` and its count. Their quotient is the
    /// log-domain mean of runtime_ratio; since `exp` is monotonic we compare
    /// clusters on the quotient directly and never convert back. Accumulated
    /// across cycles (not reset) for now.
    ln_sum: f64,
    count: u64,
    /// The largest `expt_wait` that still measured OK; the tolerable delay found
    /// so far. 0 until the first good value.
    good_expt_wait: u64,
    /// Whether this cluster's search has finished.
    done: bool,
}

impl ClusterExpt {
    fn new() -> Self {
        Self { ln_sum: 0.0, count: 0, good_expt_wait: 0, done: false }
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
/// (which the experiment sets/clears itself). Slice is fixed here: the
/// experiment thread has no per-task stats to recompute an adaptive slice.
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
    /// Tids classified into `expt_cluster`, handed to the experiment thread.
    /// `predict` inserts; the experiment thread reads (and clears when it moves
    /// on to the next cluster).
    expt_tids: HashSet<i32>,
    /// Per-cluster experiment progress, indexed by cluster id.
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
            expt_tids: HashSet::new(),
            clusters: vec![ClusterExpt::new(); n_clusters],
            cluster_params,
        }
    }

    /// Pick the not-yet-done cluster with the highest runtime_ratio rank.
    /// Returns None when every remaining cluster is done or unsampled.
    fn pick_cluster(&self) -> Option<usize> {
        self.clusters
            .iter()
            .enumerate()
            .filter(|(_, c)| !c.done && c.count > 0)
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

/// Write `expt_wait` (with the cluster-under-test's params) to every tid in
/// `expt_tids`. Snapshots the tid set under the lock, then writes without it
/// held so `predict` is not blocked during the map updates.
fn drive_tids(state: &Arc<Mutex<ExptState>>, map: &MapHandle, expt_wait: u64) {
    let (tids, params) = {
        let st = state.lock().unwrap();
        match &st.cur_params {
            Some(p) => (st.expt_tids.iter().copied().collect::<Vec<_>>(), p.clone()),
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
        };
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
fn experiment_loop(state: Arc<Mutex<ExptState>>, map: MapHandle) {
    eprintln!("[expt] experiment thread started");
    loop {
        // Pick the next cluster to experiment on. When every cluster is done
        // there is nothing left to drive, so the thread just exits.
        let cluster = {
            let mut st = state.lock().unwrap();
            let Some(cluster) = st.pick_cluster() else {
                eprintln!("[expt] all clusters done, experiment thread exiting");
                return;
            };
            let params = st.cur_params_for(cluster);
            st.expt_cluster = Some(cluster);
            st.cur_params = Some(params);
            st.expt_tids.clear();
            cluster
        };
        eprintln!("[expt] start cluster {cluster}");

        // Grow expt_wait until a value looks bad, or until we hit the cap. The
        // cap bounds the injected delay so a task with no tolerable limit never
        // gets so much delay that sched-ext tears the scheduler down.
        let mut expt_wait = EXPT_WAIT_START;
        for _ in 0..MAX_WAIT_MULTIPLE {
            let mut bad = 0;
            for _ in 0..EXPT_ROUNDS {
                // `measure` only errors while first mapping the shm; once that
                // succeeds it always returns `Ok`
                let before = GameFps::measure().expect("measure (before) failed after warm-up");
                drive_tids(&state, &map, expt_wait);
                let delayed = GameFps::measure().expect("measure (delayed) failed after warm-up");
                drive_tids(&state, &map, 0);
                let after = GameFps::measure().expect("measure (after) failed after warm-up");

                // Bad if the delayed sample is worse than both undelayed ones.
                if delayed.compare(&before) == std::cmp::Ordering::Less
                    && delayed.compare(&after) == std::cmp::Ordering::Less
                {
                    bad += 1;
                    // `compare` ranks purely on fps, so print all three fps to
                    // see whether delayed really dropped or the game just jittered.
                    eprintln!(
                        "[expt] cluster {cluster}: expt_wait={expt_wait} bad round: \
                         before_fps={:.1} delayed_fps={:.1} after_fps={:.1}",
                        before.fps, delayed.fps, after.fps
                    );
                }
            }

            // A bad value ends the search: good_expt_wait already holds the last
            // OK value. Otherwise record this value as good and double it.
            if bad >= EXPT_BAD_THRESHOLD {
                eprintln!("[expt] cluster {cluster}: expt_wait={expt_wait} bad ({bad}/{EXPT_ROUNDS}) -> done");
                break;
            }

            eprintln!("[expt] cluster {cluster}: expt_wait={expt_wait} ok, doubling");
            if let Some(c) = state.lock().unwrap().clusters.get_mut(cluster) {
                c.good_expt_wait = expt_wait;
            }
            expt_wait = expt_wait.saturating_mul(2);
        }

        // The cluster's search is over whether it ended on a bad value or ran
        // out of room at the cap — either way mark it done and release the tids
        // so they go back to being scheduled by `predict`.
        let mut st = state.lock().unwrap();
        if let Some(c) = st.clusters.get_mut(cluster) {
            c.done = true; // good_expt_wait holds the last OK value (0 if none)
        }
        st.expt_cluster = None;
        st.cur_params = None;
        st.expt_tids.clear();
    }
}

/// Snapshot a cluster's config as `ExptParams` for the experiment thread. An
/// adaptive slice has no per-task stats here, so it falls back to a fixed slice.
fn to_expt_params(cfg: &ClusterSchedConfig) -> ExptParams {
    let slice_ns = match &cfg.slice {
        SliceConfig::Adaptive { .. } => EXPT_FIXED_SLICE_NS,
        SliceConfig::Fixed { slice_ns } => *slice_ns,
    };
    ExptParams {
        prio: cfg.prio,
        cpu_kind: cfg.cpu_kind,
        cpu_prefer: cfg.cpu_prefer,
        slice_ns,
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
    /// When this predictor was created, for measuring the warm-up.
    start: Instant,
    /// Set once the experiment thread has been spawned, so it happens only once.
    spawned: AtomicBool,
    /// Shared with the experiment thread (see `ExptState`).
    state: Arc<Mutex<ExptState>>,
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
            start: Instant::now(),
            spawned: AtomicBool::new(false),
            state: Arc::new(Mutex::new(ExptState::new(cluster_params))),
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
        let state = Arc::clone(&self.state);
        eprintln!("[expt] warm-up done, spawning experiment thread");
        std::thread::spawn(move || experiment_loop(state, map));
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
            slice_ns: cluster_cfg.compute_slice_ns(&named_stats),
            expt_wait: 0,
        };

        let runtime_ratio = named_stats
            .iter()
            .find(|(n, _)| *n == "runtime_ratio")
            .map(|(_, v)| *v)
            .unwrap_or(0.0);

        // Accumulate the cluster's runtime_ratio (for cluster selection) and, if
        // this is the cluster under experiment, hand the tid to the experiment
        // thread instead of writing it here. The lock is held only long enough
        // to update the shared state.
        let handed_off = {
            let mut st = self.state.lock().unwrap();
            if let Some(c) = st.clusters.get_mut(cluster) {
                // ln(0) would poison the mean, so only count positive ratios.
                if runtime_ratio > 0.0 {
                    c.ln_sum += runtime_ratio.ln();
                    c.count += 1;
                }
            }
            if st.expt_cluster == Some(cluster) {
                st.expt_tids.insert(tid);
                true
            } else {
                false
            }
        };

        if !handed_off {
            write_sched_info(update_map, tid, &decision)?;
        }
        Ok(Some(decision))
    }

    fn n_outputs(&self) -> usize {
        self.n_clusters
    }

    fn validate(&self, cpu_kind_num: u8) -> Result<()> {
        self.config.validate_cpu_kind(cpu_kind_num)
    }
}
