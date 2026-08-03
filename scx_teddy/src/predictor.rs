use anyhow::{Context, Result, bail};
use std::fs;
use libbpf_rs::{MapCore, MapFlags};
use crate::predictors::kmeans::{KMeansModel, KMeansPredictor};
use crate::predictors::expt_tolerance::{ExptToleranceModel, ExptTolerancePredictor};
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
    /// Tags this write so a delay sample published later can be matched back to
    /// it. Only the experiment reads it back; predictors that do not care leave
    /// it at 0.
    pub epoch: u64,
}

/// Pack a `sched_info_t {prio: s32, kind: u8, cpu_prefer: u8, slice: u64,
/// expt_wait: u64, epoch: u64}` and write it into `update_map` for `tid`.
/// Predictors call this from `predict` to push a decision down to BPF. Generic
/// over the map so both a borrowed `Map` (main thread) and an owned `MapHandle`
/// (an experiment thread) can write through it.
///
/// Returns whether the write landed. BPF keeps an entry for exactly as long as
/// the task lives (created in `init_task`, deleted in `exit_task`), so writing
/// with `EXIST` both refuses to resurrect a dead task's entry and reports the
/// exit — in one map operation, with no window between checking and writing.
/// `Ok(false)` is that ordinary outcome; `Err` stays reserved for a real map
/// failure.
pub fn write_sched_info(
    update_map: &impl MapCore,
    tid: i32,
    d: &SchedDecision,
) -> Result<bool> {
    let tid_key = tid.to_ne_bytes();
    let mut val_buf = [0u8; 32];
    val_buf[0..4].copy_from_slice(&d.prio.to_ne_bytes());
    val_buf[4] = d.cpu_kind;
    val_buf[5] = d.cpu_prefer;
    val_buf[8..16].copy_from_slice(&d.slice_ns.to_ne_bytes());
    val_buf[16..24].copy_from_slice(&d.expt_wait.to_ne_bytes());
    val_buf[24..32].copy_from_slice(&d.epoch.to_ne_bytes());
    match update_map.update(&tid_key, &val_buf, MapFlags::EXIST) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == libbpf_rs::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).context("Failed to write sched info"),
    }
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

    /// Hand the predictor the BPF maps its own threads read directly, once the
    /// skeleton is loaded: the per-tid delay-EWMA map (tid -> ns) and the audio
    /// measurement window. Called once per set right after load, and again for a
    /// target set reloaded live. Most predictors don't need them (default no-op);
    /// `expt_tolerance` clones them into owned handles so its experiment thread
    /// can read a task's real scheduling delay off the ringbuf path and measure
    /// audio throughput over its windows.
    fn attach_expt_maps(&self, _sched_delay: &libbpf_rs::Map, _audio_expt: &libbpf_rs::Map) {}

    /// Number of output categories (clusters or classes).
    fn n_outputs(&self) -> usize;

    /// Check the predictor's config against the machine topology. Called once
    /// the CPU topology is known (which is after loading).
    fn validate(&self, cpu_kind_num: u8) -> Result<()>;
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
        "expt_tolerance" => {
            let model: ExptToleranceModel = serde_json::from_value(raw)
                .context("Failed to parse expt_tolerance model")?;
            Ok(Box::new(ExptTolerancePredictor::from_model(model, config_path)?))
        }
        _ => bail!("Unsupported algorithm: {}", algorithm),
    }
}
