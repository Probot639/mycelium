use anyhow::Result;

use mycelium_common::corpus::{CrashEntry, Seed};
use mycelium_common::node::{NodeInfo, NodeStatus};
use mycelium_common::protocol::{CampaignInfo, CampaignLifecycle, MetricsSnapshot};

pub trait Storage: Send {
    fn register_node(&self, info: &NodeInfo) -> Result<()>;
    fn deregister_node(&self, node_id: &str) -> Result<()>;
    fn update_node_status(&self, node_id: &str, status: NodeStatus) -> Result<()>;
    fn mark_stale_offline(&self, timeout_secs: i64) -> Result<usize>;
    fn store_seed(&self, seed: &Seed) -> Result<bool>;
    fn delete_seed(&self, hash: &str, campaign: &str) -> Result<()>;
    fn node_campaign(&self, node_id: &str) -> Result<Option<String>>;
    fn get_campaign(&self, name: &str) -> Result<Option<CampaignInfo>>;
    fn get_unseen_seeds(&self, node_id: &str, campaign: &str) -> Result<Vec<Seed>>;
    fn mark_seed_sent(&self, seed_hash: &str, node_id: &str) -> Result<()>;
    fn store_crash(&self, crash: &CrashEntry) -> Result<bool>;
    fn delete_crash(&self, input_hash: &str, campaign: &str) -> Result<()>;
    fn update_heartbeat(
        &self,
        node_id: &str,
        execs_per_sec: u64,
        corpus_size: u64,
        crashes_found: u64,
        edges_found: u64,
    ) -> Result<()>;
    fn list_nodes(&self, campaign: Option<&str>) -> Result<Vec<NodeInfo>>;
    fn count_seeds(&self, campaign: &str) -> Result<u64>;
    fn count_crashes(&self, campaign: &str) -> Result<u64>;
    fn count_unique_bugs(&self, campaign: &str) -> Result<u64>;
    fn sum_execs_per_sec(&self, campaign: &str) -> Result<u64>;
    fn sum_edges(&self, campaign: &str) -> Result<u64>;
    fn get_campaign_lifecycle(&self, name: &str) -> Result<Option<CampaignLifecycle>>;
    fn create_campaign(
        &self,
        name: &str,
        fuzzer_name: &str,
        fuzzer_command: &[String],
        triage_cmd: Option<&[String]>,
    ) -> Result<()>;
    fn set_harness_len(&self, campaign: &str, len: u64) -> Result<()>;
    fn list_campaign_names(&self) -> Result<Vec<String>>;
    fn snapshot_metrics(&self, campaign: &str) -> Result<()>;
    fn get_metrics(&self, campaign: &str, limit: u64) -> Result<Vec<MetricsSnapshot>>;
    fn list_seed_hashes(&self, campaign: &str) -> Result<Vec<String>>;
    fn list_crashes(&self, campaign: &str, limit: u64) -> Result<Vec<CrashEntry>>;
    fn update_campaign_lifecycle(
        &self,
        name: &str,
        lifecycle: CampaignLifecycle,
    ) -> Result<bool>;
}
