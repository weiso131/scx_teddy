use anyhow::{Context, Result, bail};
use std::fs;
use crate::predictors::kmeans::{KMeansModel, KMeansPredictor};

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
