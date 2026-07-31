//! Shared building blocks for the k-means-based predictors (`kmeans`,
//! `expt_tolerance`): the feature set, the scheduling config format, and the
//! "nearest centroid" classifier, each defined once.
//!
//! The two predictors used to carry a copy of the feature list each, on the
//! theory that they would diverge. They never did — every feature added had to
//! be written twice, and a model naming one the other lacked would only fail at
//! load time.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::task_stats::TaskStats;

/// Every feature a model may train on, in the order they appear as CSV columns.
///
/// The single definition of the feature set: adding one here is all it takes for
/// both predictors and the collect-mode CSV to carry it. A model selects the
/// subset it was trained on by name (see `KMeansCore::from_model_parts`), so
/// this list may grow without invalidating models that do not mention the new
/// column.
const FEATURES: &[(&str, fn(&TaskStats) -> f64)] = &[
    ("runtime_ms", |s| s.avg_runtime_ms()),
    ("runtime_cv", |s| s.runtime_cv()),
    ("avg_sleep_ms", |s| s.avg_sleep_ms()),
    ("sleep_cv", |s| s.sleep_cv()),
    ("iowait_ratio", |s| s.sleep_base_ratio(s.in_iowait_cnt)),
    ("futex_wait_ratio", |s| s.sleep_base_ratio(s.futex_wait_cnt)),
    ("ntsync_wait_ratio", |s| s.sleep_base_ratio(s.ntsync_wait_cnt)),
    ("audio_rate", |s| s.audio_rate_max as f64),
    ("present_rate", |s| s.present_rate_max as f64),
    ("submit_rate", |s| s.submit_rate_max as f64),
    ("runtime_ratio", |s| {
        s.avg_runtime_ms() / (s.avg_runtime_ms() + s.avg_sleep_ms())
    }),
];

/// Feature names, in the order `feature_values` returns them.
pub fn feature_names() -> Vec<&'static str> {
    FEATURES.iter().map(|(n, _)| *n).collect()
}

/// Every feature's value for one task, in `feature_names` order.
pub fn feature_values(stats: &TaskStats) -> Vec<f64> {
    FEATURES.iter().map(|(_, f)| f(stats)).collect()
}

/// One feature by name, or 0.0 if there is no such feature. For the few callers
/// that want a single named value rather than the whole vector.
pub fn feature_value(stats: &TaskStats, name: &str) -> f64 {
    FEATURES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, f)| f(stats))
        .unwrap_or(0.0)
}

/// Per-cluster scheduling parameters, as read from the config JSON.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ClusterSchedConfig {
    pub prio: i32,
    /// DSQ slot / CPU-kind binding (1-based; 1 = fastest kind). 0 (the default
    /// when omitted) means the shared DSQ — runnable on any CPU kind. A value
    /// of `k` pins the cluster's tasks to the kind-only DSQ for kind `k`.
    #[serde(default)]
    pub cpu_kind: u8,
    /// CPU speed preference for select_cpu: 0 = none, 1 = prefer fastest,
    /// 2 = prefer slowest. Omitted (0) lets the BPF side auto-derive it from
    /// cpu_kind when the kind is the fastest/slowest tier.
    #[serde(default)]
    pub cpu_prefer: u8,
    /// Time slice in ns.
    pub slice_ns: u64,
}

/// The whole scheduling config: per-cluster entries keyed by cluster id (as a
/// string), plus a `default` used for any cluster not listed.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SchedConfig {
    pub clusters: HashMap<String, ClusterSchedConfig>,
    pub default: ClusterSchedConfig,
}

impl SchedConfig {
    /// The config entry for `cluster`, falling back to `default` when the cluster
    /// is not listed.
    pub fn cluster_or_default(&self, cluster: usize) -> &ClusterSchedConfig {
        self.clusters.get(&cluster.to_string()).unwrap_or(&self.default)
    }

    /// Read and parse a `SchedConfig` from a JSON file.
    pub fn from_path(config_path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read config: {}", config_path))?;
        serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse config: {}", config_path))
    }

    /// Reject any cluster (or the default) whose `cpu_kind` exceeds the machine's
    /// kind count. Valid range is `0..=cpu_kind_num` (0 = shared / any kind, 1 =
    /// fastest kind). A binding to a non-existent kind would put tasks in a DSQ no
    /// CPU pulls from, starving them — so fail loudly at startup instead.
    pub fn validate_cpu_kind(&self, cpu_kind_num: u8) -> Result<()> {
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
        check("default", &self.default)?;
        for (k, c) in &self.clusters {
            check(&format!("cluster {k}"), c)?;
        }
        Ok(())
    }
}

/// The nearest-centroid classifier shared by the k-means predictors: it selects
/// the model's trained features from a raw feature vector, standardizes them
/// with the scaler, and returns the closest centroid. Each predictor keeps its
/// own model/scaler structs and builds a `KMeansCore` from their parts.
pub struct KMeansCore {
    /// Indices of the model's features within the collector's raw feature vector.
    feature_indices: Vec<usize>,
    centroids: Vec<Vec<f64>>,
    mean: Vec<f64>,
    std: Vec<f64>,
}

impl KMeansCore {
    /// Build the classifier from a model's parts. Validates the centroid count,
    /// scaler lengths, and maps each requested feature name to its index in the
    /// collector's feature list (`available_features`).
    pub fn from_model_parts(
        n_clusters: usize,
        features: &[String],
        centroids: Vec<Vec<f64>>,
        mean: Vec<f64>,
        std: Vec<f64>,
        available_features: &[&str],
    ) -> Result<Self> {
        if centroids.len() != n_clusters {
            anyhow::bail!(
                "Centroid count ({}) does not match n_clusters ({})",
                centroids.len(),
                n_clusters
            );
        }
        if mean.len() != std.len() {
            anyhow::bail!("Scaler mean/std length mismatch");
        }
        if mean.len() != features.len() {
            anyhow::bail!("Scaler length does not match feature count");
        }

        let mut feature_indices = Vec::with_capacity(features.len());
        for f_name in features {
            let idx = available_features
                .iter()
                .position(|&name| name == f_name)
                .with_context(|| format!("Model requires feature '{}' which is not available", f_name))?;
            feature_indices.push(idx);
        }

        Ok(Self { feature_indices, centroids, mean, std })
    }

    fn standardize(&self, selected_features: &[f64]) -> Vec<f64> {
        selected_features
            .iter()
            .zip(self.mean.iter().zip(self.std.iter()))
            .map(|(&x, (&m, &s))| if s != 0.0 { (x - m) / s } else { 0.0 })
            .collect()
    }

    /// Nearest centroid for a task's raw feature vector.
    pub fn nearest_cluster(&self, raw_features: &[f64]) -> usize {
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
