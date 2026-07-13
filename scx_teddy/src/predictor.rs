use anyhow::{Context, Result, bail};
use std::fs;
use crate::predictors::kmeans::{KMeansCollector, KMeansModel, KMeansPredictor};
use crate::task_stats::TaskStats;

/// The scheduling parameters a predictor decides for one task. Mirrors the BPF
/// `sched_info_t` (bpf/intf.h) plus the class id the task was assigned to.
/// A predictor that has no notion of a given field leaves it at its default
/// (e.g. kmeans has no `expt_wait` and always reports 0).
#[derive(Debug, Clone, Default)]
pub struct SchedDecision {
    /// The class/cluster the task was assigned to. Reported to the GUI snapshot.
    pub cluster: usize,
    pub prio: i32,
    pub cpu_kind: u8,
    pub cpu_prefer: u8,
    pub slice_ns: u64,
    pub expt_wait: u64,
}

pub trait Predictor: Send + Sync {
    /// Decide the scheduling parameters for a task. The predictor owns its
    /// config, so it maps the task's stats all the way to a `SchedDecision`.
    /// It decides which fields it reads and whether to consume `need_update`.
    /// Returns None when there is nothing to do this cycle.
    fn predict(&self, stats: &mut TaskStats) -> Option<SchedDecision>;

    /// Number of output categories (clusters or classes).
    fn n_outputs(&self) -> usize;

    /// Check the predictor's config against the machine topology. Called once
    /// the CPU topology is known (which is after loading).
    fn validate(&self, cpu_kind_num: u8) -> Result<()>;
}

pub trait Collector: Send + Sync {
    /// Returns (name, value) pairs for all features.
    /// The order here defines the CSV column order and feature vector order.
    #[allow(dead_code)]
    fn named_stats(&self, stats: &TaskStats) -> Vec<(&'static str, f64)>;

    /// Returns feature values as a Vec (order matches named_stats).
    fn feature_values(&self, stats: &TaskStats) -> Vec<f64>;

    /// Returns feature names (order matches feature_values).
    fn feature_names(&self) -> Vec<&'static str>;
}

/// Load a collector by algorithm name. Mirrors `load_predictor` so the feature
/// set used for collection can be switched the same way the predictor is.
pub fn load_collector(algorithm: &str) -> Result<Box<dyn Collector>> {
    match algorithm {
        "kmeans" => Ok(Box::new(KMeansCollector)),
        _ => bail!("Unsupported algorithm: {}", algorithm),
    }
}

/// Load a predictor from a JSON model file plus the config that interprets its
/// output. Dispatches to the correct implementation based on the "algorithm"
/// field; each implementation parses the config in its own format.
pub fn load_predictor(model_path: &str, config_path: &str) -> Result<Box<dyn Predictor>> {
    let content = fs::read_to_string(model_path)
        .with_context(|| format!("Failed to read model file: {}", model_path))?;
    let raw: serde_json::Value = serde_json::from_str(&content)
        .context("Failed to parse model JSON")?;

    let algorithm = raw["algorithm"]
        .as_str()
        .context("Missing 'algorithm' field in model JSON")?;

    match algorithm {
        "kmeans" => {
            let model: KMeansModel = serde_json::from_value(raw)
                .context("Failed to parse KMeans model")?;
            Ok(Box::new(KMeansPredictor::from_model(model, config_path)?))
        }
        _ => bail!("Unsupported algorithm: {}", algorithm),
    }
}
