use serde::{Deserialize, Serialize};

use crate::corpus::{CrashEntry, Seed};
use crate::node::{NodeInfo, Priority};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CampaignLifecycle {
    #[default]
    Running,
    Paused,
    Draining,
    Completed,
}

impl std::fmt::Display for CampaignLifecycle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CampaignLifecycle::Running => write!(f, "running"),
            CampaignLifecycle::Paused => write!(f, "paused"),
            CampaignLifecycle::Draining => write!(f, "draining"),
            CampaignLifecycle::Completed => write!(f, "completed"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub hostname: String,
    pub campaign: String,
    pub fuzzer: String,
    pub priority: Priority,
    /// A stable id the node persists across restarts. When present and valid the
    /// coordinator reuses it, so a restarted node keeps its seed-distribution
    /// history instead of re-pulling the whole corpus.
    #[serde(default)]
    pub requested_id: Option<String>,
    /// True when the fuzzer command has an overall time or run limit (so the
    /// node is expected to finish on its own and then suspend).
    #[serde(default)]
    pub time_limited: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub node_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PushSeedRequest {
    pub node_id: String,
    pub seed: Seed,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PushSeedBatchRequest {
    pub node_id: String,
    pub seeds: Vec<Seed>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PullSeedsRequest {
    pub node_id: String,
    // the node sends its own campaign so the coordinator does not have to scan
    // the whole nodes table to find it on every pull
    pub campaign: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PullSeedsResponse {
    pub seeds: Vec<Seed>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportCrashRequest {
    pub node_id: String,
    pub crash: CrashEntry,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub node_id: String,
    pub execs_per_sec: u64,
    pub corpus_size: u64,
    pub crashes_found: u64,
    #[serde(default)]
    pub edges_found: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScryResponse {
    pub nodes: Vec<NodeInfo>,
    pub campaign: CampaignStatus,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CampaignStatus {
    pub name: String,
    pub total_corpus: u64,
    pub total_crashes: u64,
    /// Distinct bugs by stack hash. Below total_crashes once traces dedup them.
    #[serde(default)]
    pub unique_bugs: u64,
    pub total_execs_per_sec: u64,
    #[serde(default)]
    pub total_edges: u64,
    pub nodes_online: u64,
    #[serde(default)]
    pub lifecycle: CampaignLifecycle,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeregisterRequest {
    pub node_id: String,
    pub drain: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateCampaignRequest {
    pub name: String,
    pub fuzzer_name: String,
    pub fuzzer_command: Vec<String>,
    #[serde(default)]
    pub triage_cmd: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignInfo {
    pub name: String,
    pub fuzzer_name: String,
    pub fuzzer_command: Vec<String>,
    #[serde(default)]
    pub triage_cmd: Option<Vec<String>>,
    pub harness_len: u64,
    pub created_at: i64,
    #[serde(default)]
    pub lifecycle: CampaignLifecycle,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateCampaignLifecycleRequest {
    pub lifecycle: CampaignLifecycle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub ts: i64,
    pub total_execs_per_sec: u64,
    pub corpus_size: u64,
    pub crashes: u64,
    pub unique_bugs: u64,
    pub edges: u64,
    pub nodes_online: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsResponse {
    pub campaign: String,
    pub snapshots: Vec<MetricsSnapshot>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CorpusListResponse {
    pub campaign: String,
    pub hashes: Vec<String>,
    pub total: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InjectSeedsRequest {
    pub seeds: Vec<Seed>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PullCrashesRequest {
    pub campaign: String,
    #[serde(default)]
    pub limit: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PullCrashesResponse {
    pub crashes: Vec<CrashEntry>,
}
