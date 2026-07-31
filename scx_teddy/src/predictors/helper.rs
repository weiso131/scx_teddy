//! Shared building blocks for the k-means-based predictors (`kmeans`,
//! `expt_tolerance`). The two predictors keep their own `Collector` (the feature
//! set is expected to diverge) and their own model/scaler structs, but the parts
//! that are genuinely k-means — the scheduling config format and the "nearest
//! centroid" classifier — live here so they are defined once.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
