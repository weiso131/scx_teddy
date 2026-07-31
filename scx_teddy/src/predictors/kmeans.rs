use anyhow::Result;
use serde::Deserialize;
use crate::predictor::{Collector, Predictor, SchedDecision, write_sched_info};
use crate::predictors::helper::{KMeansCore, SchedConfig};
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
            ("ntsync_wait_ratio", stats.sleep_base_ratio(stats.ntsync_wait_cnt)),
            ("audio_rate", stats.audio_rate_max as f64),
            ("present_rate", stats.present_rate_max as f64),
            ("submit_rate", stats.submit_rate_max as f64),
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
    /// Nearest-centroid classifier (feature selection + scaler + centroids).
    core: KMeansCore,
    /// Maps a cluster to its scheduling parameters. An unknown cluster falls
    /// back to the config's `default` entry.
    config: SchedConfig,
}

impl KMeansPredictor {
    pub fn from_model(model: KMeansModel, config_path: &str) -> Result<Self> {
        let core = KMeansCore::from_model_parts(
            model.n_clusters,
            &model.features,
            model.centroids,
            model.scaler.mean,
            model.scaler.std,
            &KMeansCollector::feature_names(),
        )?;
        let config = SchedConfig::from_path(config_path)?;

        Ok(Self {
            n_clusters: model.n_clusters,
            core,
            config,
        })
    }
}

impl Predictor for KMeansPredictor {
    fn predict(
        &self,
        tid: i32,
        stats: &mut TaskStats,
        update_map: &libbpf_rs::Map,
    ) -> Result<Option<SchedDecision>> {
        if stats.need_update == 0 {
            return Ok(None);
        }
        stats.need_update = 0;

        let named_stats = KMeansCollector::named_stats(stats);
        let raw_features: Vec<f64> = named_stats.iter().map(|(_, v)| *v).collect();
        let cluster = self.core.nearest_cluster(&raw_features);

        let cluster_cfg = self.config.cluster_or_default(cluster);

        let decision = SchedDecision {
            cluster,
            prio: cluster_cfg.prio,
            cpu_kind: cluster_cfg.cpu_kind,
            cpu_prefer: cluster_cfg.cpu_prefer,
            slice_ns: cluster_cfg.compute_slice_ns(&named_stats),
            expt_wait: 0,
            epoch: 0,
        };
        let _ = write_sched_info(update_map, tid, &decision)?;
        Ok(Some(decision))
    }

    fn n_outputs(&self) -> usize {
        self.n_clusters
    }

    fn validate(&self, cpu_kind_num: u8) -> Result<()> {
        self.config.validate_cpu_kind(cpu_kind_num)
    }
}
