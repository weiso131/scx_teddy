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

use anyhow::{Context, Result, bail};
use libbpf_rs::MapHandle;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use crate::predictor::{Collector, Predictor, SchedDecision, write_sched_info};
use crate::predictors::expt_tolerance::metric::Metric;
use crate::predictors::expt_tolerance::metrics::game_fps::GameFps;
use crate::task_stats::TaskStats;

/// Warm-up before the experiment starts: classify without touching `expt_wait`
/// for this long so the classification has settled. Constant for now.
const WARMUP: Duration = Duration::from_secs(30);

/// State shared between the classify thread (`predict`) and the experiment
/// thread. The experiment thread owns the search; `predict` only feeds it tids.
struct ExptState {
    /// The cluster currently under experiment. `None` before one is picked.
    expt_cluster: Option<usize>,
    /// Tids classified into `expt_cluster`, handed to the experiment thread.
    /// `predict` inserts; the experiment thread reads (and clears when it moves
    /// on to the next cluster).
    expt_tids: HashSet<i32>,
}

impl ExptState {
    fn new() -> Self {
        Self { expt_cluster: None, expt_tids: HashSet::new() }
    }
}

/// The experiment thread. Skeleton for now: each round just measures one metric
/// window. `measure` blocks (~1s) inside the layer, which paces the loop — no
/// sleep needed — and it runs without the lock held so `predict` can keep
/// feeding tids meanwhile. Later this will drive the tids in `expt_tids` with
/// `write_sched_info` using the current `expt_wait`, compare metric samples,
/// grow `expt_wait`, and advance to the next cluster.
fn experiment_loop(state: Arc<Mutex<ExptState>>, _map: MapHandle) {
    eprintln!("[expt] experiment thread started");
    loop {
        match GameFps::measure() {
            Ok(s) => eprintln!("[expt] fps={:.1} (frames={})", s.fps, s.frame_count),
            Err(e) => eprintln!("[expt] measure failed: {e}"),
        }

        let _guard = state.lock().unwrap();
        // TODO: pick expt_cluster by highest avg runtime_ratio, drive expt_tids,
        // compare samples, grow expt_wait, advance to the next cluster.
    }
}

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
    /// DSQ slot / CPU-kind binding (1-based; 1 = fastest kind). 0 (the default
    /// when omitted) means the shared DSQ — runnable on any CPU kind. A value
    /// of `k` pins the cluster's tasks to the kind-only DSQ for kind `k`.
    #[serde(default)]
    cpu_kind: u8,
    /// CPU speed preference for select_cpu: 0 = none, 1 = prefer fastest,
    /// 2 = prefer slowest. Omitted (0) lets the BPF side auto-derive it from
    /// cpu_kind when the kind is the fastest/slowest tier.
    #[serde(default)]
    cpu_prefer: u8,
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
                let avg_ms = lookup("runtime_ms");
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
    /// Indices of features in the raw feature vector.
    feature_indices: Vec<usize>,
    centroids: Vec<Vec<f64>>,
    mean: Vec<f64>,
    std: Vec<f64>,
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
        if model.centroids.len() != model.n_clusters {
            bail!(
                "Centroid count ({}) does not match n_clusters ({})",
                model.centroids.len(),
                model.n_clusters
            );
        }
        if model.scaler.mean.len() != model.scaler.std.len() {
            bail!("Scaler mean/std length mismatch");
        }
        if model.scaler.mean.len() != model.features.len() {
            bail!("Scaler length does not match feature count");
        }

        // Map feature names to indices
        let available_features = ExptToleranceCollector::feature_names();
        let mut feature_indices = Vec::new();
        for f_name in &model.features {
            let idx = available_features
                .iter()
                .position(|&name| name == f_name)
                .with_context(|| format!("Model requires feature '{}' which is not available", f_name))?;
            feature_indices.push(idx);
        }

        let content = std::fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read config: {}", config_path))?;
        let config: SchedConfig = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse config: {}", config_path))?;

        Ok(Self {
            n_clusters: model.n_clusters,
            feature_indices,
            centroids: model.centroids,
            mean: model.scaler.mean,
            std: model.scaler.std,
            config,
            start: Instant::now(),
            spawned: AtomicBool::new(false),
            state: Arc::new(Mutex::new(ExptState::new())),
        })
    }

    /// After the warm-up, spawn the experiment thread exactly once. Called from
    /// `predict`, where `update_map` is available to clone into an owned handle
    /// the thread can keep. `expt_cluster` is hardcoded to 0 for now.
    fn maybe_spawn_experiment(&self, update_map: &libbpf_rs::Map) -> Result<()> {
        if self.start.elapsed() < WARMUP {
            return Ok(());
        }
        // Claim the spawn: only the thread that flips false->true proceeds.
        if self.spawned.swap(true, Ordering::AcqRel) {
            return Ok(());
        }

        self.state.lock().unwrap().expt_cluster = Some(0);

        let map = MapHandle::try_from(update_map)
            .context("Failed to clone update_map for the experiment thread")?;
        let state = Arc::clone(&self.state);
        eprintln!("[expt] warm-up done, spawning experiment thread (expt_cluster=0)");
        std::thread::spawn(move || experiment_loop(state, map));
        Ok(())
    }

    fn standardize(&self, selected_features: &[f64]) -> Vec<f64> {
        selected_features
            .iter()
            .zip(self.mean.iter().zip(self.std.iter()))
            .map(|(&x, (&m, &s))| if s != 0.0 { (x - m) / s } else { 0.0 })
            .collect()
    }

    /// Nearest centroid for a task's features.
    fn nearest_cluster(&self, raw_features: &[f64]) -> usize {
        // 1. Extract only the features this model was trained on
        let selected: Vec<f64> = self.feature_indices
            .iter()
            .map(|&i| raw_features[i])
            .collect();

        // 2. Standardize
        let scaled = self.standardize(&selected);

        // 3. Find nearest centroid
        let mut best_cluster = 0;
        let mut best_dist = f64::MAX;

        for (i, centroid) in self.centroids.iter().enumerate() {
            let dist: f64 = scaled
                .iter()
                .zip(centroid.iter())
                .map(|(&a, &b)| (a - b) * (a - b))
                .sum();
            if dist < best_dist {
                best_dist = dist;
                best_cluster = i;
            }
        }
        best_cluster
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
        let cluster = self.nearest_cluster(&raw_features);

        let cluster_cfg = self.config.clusters
            .get(&cluster.to_string())
            .unwrap_or(&self.config.default);

        let decision = SchedDecision {
            cluster,
            prio: cluster_cfg.prio,
            cpu_kind: cluster_cfg.cpu_kind,
            cpu_prefer: cluster_cfg.cpu_prefer,
            slice_ns: cluster_cfg.compute_slice_ns(&named_stats),
            expt_wait: 0,
        };

        // Tasks of the cluster under experiment are handed to the experiment
        // thread instead of being written here. The lock is held only long
        // enough to check the cluster and record the tid.
        let handed_off = {
            let mut st = self.state.lock().unwrap();
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

    /// Reject any cluster (or the default) whose `cpu_kind` exceeds the machine's
    /// kind count. Valid range is `0..=cpu_kind_num` (0 = shared / any kind, 1 =
    /// fastest kind). A binding to a non-existent kind would put tasks in a DSQ no
    /// CPU pulls from, starving them — so fail loudly at startup instead.
    fn validate(&self, cpu_kind_num: u8) -> Result<()> {
        let check = |name: &str, c: &ClusterSchedConfig| -> Result<()> {
            if c.cpu_kind > cpu_kind_num {
                anyhow::bail!(
                    "config {}: cpu_kind={} exceeds this machine's {} kind(s) \
                     (valid: 0=shared, 1..={})",
                    name, c.cpu_kind, cpu_kind_num, cpu_kind_num
                );
            }
            Ok(())
        };
        check("default", &self.config.default)?;
        for (k, c) in &self.config.clusters {
            check(&format!("cluster {k}"), c)?;
        }
        Ok(())
    }
}
