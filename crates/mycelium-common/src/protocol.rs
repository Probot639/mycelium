use serde::{Deserialize, Serialize};

use crate::corpus::{CrashEntry, Seed};
use crate::node::{NodeInfo, NodeStatus, Priority};

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub hostname: String,
    pub campaign: String,
    pub fuzzer: String,
    pub priority: Priority,
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
pub struct PullSeedsRequest {
    pub node_id: String,
    // not used yet, but the circle could send these to avoid re-downloading
    pub known_hashes: Vec<String>,
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
    pub total_execs_per_sec: u64,
    pub nodes_online: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeregisterRequest {
    pub node_id: String,
    pub drain: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusUpdate {
    pub node_id: String,
    pub status: NodeStatus,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateCampaignRequest {
    pub name: String,
    pub fuzzer_name: String,
    pub fuzzer_command: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignInfo {
    pub name: String,
    pub fuzzer_name: String,
    pub fuzzer_command: Vec<String>,
    pub harness_len: u64,
    pub created_at: i64,
}
