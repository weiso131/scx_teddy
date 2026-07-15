use anyhow::{Context, Result, bail};
use std::fs;
use libbpf_rs::{MapCore, MapFlags};
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

/// Pack a `sched_info_t {prio: s32, kind: u8, cpu_prefer: u8, slice: u64,
/// expt_wait: u64}` and write it into `update_map` for `tid`. Predictors call
/// this from `predict` to push a decision down to BPF.
pub fn write_sched_info(
    update_map: &libbpf_rs::Map,
    tid: i32,
    d: &SchedDecision,
) -> Result<()> {
    let tid_key = tid.to_ne_bytes();
    let mut val_buf = [0u8; 24];
    val_buf[0..4].copy_from_slice(&d.prio.to_ne_bytes());
    val_buf[4] = d.cpu_kind;
    val_buf[5] = d.cpu_prefer;
    val_buf[8..16].copy_from_slice(&d.slice_ns.to_ne_bytes());
    val_buf[16..24].copy_from_slice(&d.expt_wait.to_ne_bytes());
    update_map.update(&tid_key, &val_buf, MapFlags::ANY)?;
    Ok(())
}

pub trait Predictor: Send + Sync {
    /// Decide the scheduling parameters for `tid` and push them to BPF. The
    /// predictor owns its config, so it maps the task's stats all the way to a
    /// `SchedDecision` and writes it into `update_map` itself (via
    /// `write_sched_info`) — this lets an experiment-driven predictor control
    /// exactly what and when it writes. It decides which fields it reads and
    /// whether to consume `need_update`. The returned decision is what was
    /// written, for the caller's snapshot; `None` means nothing to do this cycle.
    fn predict(
        &self,
        tid: i32,
        stats: &mut TaskStats,
        update_map: &libbpf_rs::Map,
    ) -> Result<Option<SchedDecision>>;

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
