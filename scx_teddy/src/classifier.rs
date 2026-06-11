use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::fs;
use crate::task_stats::TaskStats;

pub trait Predictor: Send + Sync {
    /// Predict cluster/class index for a feature vector.
    /// `raw_features` should match the order from `TaskStats::get_feature_names()`.
    fn predict(&self, raw_features: &[f64]) -> usize;

    /// Number of output categories (clusters or classes).
    fn n_outputs(&self) -> usize;
}

/// Load a predictor from a JSON model file.
/// Dispatches to the correct implementation based on the "algorithm" field.
pub fn load_predictor(path: &str) -> Result<Box<dyn Predictor>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read model file: {}", path))?;
    let raw: serde_json::Value = serde_json::from_str(&content)
        .context("Failed to parse model JSON")?;

    let algorithm = raw["algorithm"]
        .as_str()
        .context("Missing 'algorithm' field in model JSON")?;

    match algorithm {
        "kmeans" => {
            let model: KMeansModel = serde_json::from_value(raw)
                .context("Failed to parse KMeans model")?;
            Ok(Box::new(KMeansPredictor::from_model(model)?))
        }
        _ => bail!("Unsupported algorithm: {}", algorithm),
    }
}

// --- KMeans ---

#[derive(Deserialize)]
struct KMeansScaler {
    mean: Vec<f64>,
    std: Vec<f64>,
}

#[derive(Deserialize)]
struct KMeansModel {
    n_clusters: usize,
    features: Vec<String>,
    centroids: Vec<Vec<f64>>,
    scaler: KMeansScaler,
}

struct KMeansPredictor {
    n_clusters: usize,
    /// Indices of features in the raw feature vector.
    feature_indices: Vec<usize>,
    centroids: Vec<Vec<f64>>,
    mean: Vec<f64>,
    std: Vec<f64>,
}

impl KMeansPredictor {
    fn from_model(model: KMeansModel) -> Result<Self> {
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
        let available_features = TaskStats::get_feature_names();
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
    fn predict(&self, raw_features: &[f64]) -> usize {
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

    fn n_outputs(&self) -> usize {
        self.n_clusters
    }
}
