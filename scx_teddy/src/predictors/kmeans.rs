use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::HashMap;
use crate::predictor::{Collector, Predictor, SchedDecision};
use crate::task_stats::TaskStats;

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

pub struct KMeansCollector;

impl KMeansCollector {
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

impl Collector for KMeansCollector {
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
pub struct KMeansModel {
    n_clusters: usize,
    features: Vec<String>,
    centroids: Vec<Vec<f64>>,
    scaler: KMeansScaler,
}

pub struct KMeansPredictor {
    n_clusters: usize,
    /// Indices of features in the raw feature vector.
    feature_indices: Vec<usize>,
    centroids: Vec<Vec<f64>>,
    mean: Vec<f64>,
    std: Vec<f64>,
    /// Maps a cluster to its scheduling parameters. An unknown cluster falls
    /// back to the config's `default` entry.
    config: SchedConfig,
}

impl KMeansPredictor {
    pub fn from_model(model: KMeansModel, config_path: &str) -> Result<Self> {
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
        let available_features = KMeansCollector::feature_names();
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
        })
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

impl Predictor for KMeansPredictor {
    fn predict(&self, stats: &mut TaskStats) -> Option<SchedDecision> {
        if stats.need_update == 0 {
            return None;
        }
        stats.need_update = 0;

        let named_stats = KMeansCollector::named_stats(stats);
        let raw_features: Vec<f64> = named_stats.iter().map(|(_, v)| *v).collect();
        let cluster = self.nearest_cluster(&raw_features);

        let cluster_cfg = self.config.clusters
            .get(&cluster.to_string())
            .unwrap_or(&self.config.default);

        Some(SchedDecision {
            cluster,
            prio: cluster_cfg.prio,
            cpu_kind: cluster_cfg.cpu_kind,
            cpu_prefer: cluster_cfg.cpu_prefer,
            slice_ns: cluster_cfg.compute_slice_ns(&named_stats),
            expt_wait: 0,
        })
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
