use anyhow::{Context, Result, bail};
use serde::Deserialize;
use crate::predictor::{Collector, Predictor};
use crate::task_stats::TaskStats;

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
}

impl KMeansPredictor {
    pub fn from_model(model: KMeansModel) -> Result<Self> {
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

        Ok(Self {
            n_clusters: model.n_clusters,
            feature_indices,
            centroids: model.centroids,
            mean: model.scaler.mean,
            std: model.scaler.std,
        })
    }

    fn standardize(&self, selected_features: &[f64]) -> Vec<f64> {
        selected_features
            .iter()
            .zip(self.mean.iter().zip(self.std.iter()))
            .map(|(&x, (&m, &s))| if s != 0.0 { (x - m) / s } else { 0.0 })
            .collect()
    }
}

impl Predictor for KMeansPredictor {
    fn predict(&self, stats: &mut TaskStats) -> Option<usize> {
        if stats.need_update == 0 {
            return None;
        }
        stats.need_update = 0;

        let raw_features = KMeansCollector::feature_values(stats);

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
        Some(best_cluster)
    }

    fn n_outputs(&self) -> usize {
        self.n_clusters
    }
}
