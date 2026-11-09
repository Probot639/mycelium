use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::Result;

use mycelium_common::corpus::{CrashEntry, Seed};
use mycelium_common::node::{NodeInfo, NodeStatus};
use mycelium_common::protocol::{
    CampaignInfo, CampaignLifecycle, CampaignStatus, MetricsSnapshot,
};

use crate::storage::Storage;

pub struct CoordinatorState {
    db: Mutex<Box<dyn Storage>>,
    pub corpus_dir: PathBuf,
    pub auth_token: Option<String>,
}

fn init_corpus_dirs(corpus_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(corpus_dir)?;
    std::fs::create_dir_all(corpus_dir.join("blobs"))?;
    std::fs::create_dir_all(corpus_dir.join("crashes"))?;
    std::fs::create_dir_all(corpus_dir.join("harnesses"))?;
    Ok(())
}

impl CoordinatorState {
    #[cfg(feature = "sqlite")]
    pub fn new(db_path: &Path, corpus_dir: &Path) -> Result<Self> {
        init_corpus_dirs(corpus_dir)?;
        Ok(Self {
            db: Mutex::new(Box::new(crate::db::Db::open(db_path)?)),
            corpus_dir: corpus_dir.to_path_buf(),
            auth_token: None,
        })
    }

    #[cfg(feature = "sqlite")]
    pub fn new_in_memory(corpus_dir: &Path) -> Result<Self> {
        init_corpus_dirs(corpus_dir)?;
        Ok(Self {
            db: Mutex::new(Box::new(crate::db::Db::open_in_memory()?)),
            corpus_dir: corpus_dir.to_path_buf(),
            auth_token: None,
        })
    }

    #[cfg(feature = "postgres")]
    pub fn new_pg(pool: sqlx::PgPool, corpus_dir: &Path) -> Result<Self> {
        init_corpus_dirs(corpus_dir)?;
        let pg = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(crate::pg::PgDb::connect_with_pool(pool))
        })?;
        Ok(Self {
            db: Mutex::new(Box::new(pg)),
            corpus_dir: corpus_dir.to_path_buf(),
            auth_token: None,
        })
    }

    pub fn with_auth_token(mut self, token: Option<String>) -> Self {
        self.auth_token = token;
        self
    }

    pub fn register_node(&self, info: &NodeInfo) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.register_node(info)
    }

    pub fn deregister_node(&self, node_id: &str) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.deregister_node(node_id)
    }

    pub fn set_node_status(&self, node_id: &str, status: NodeStatus) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.update_node_status(node_id, status)
    }

    pub fn reap_stale(&self, timeout_secs: i64) -> Result<usize> {
        let db = self.db.lock().unwrap();
        db.mark_stale_offline(timeout_secs)
    }

    pub fn ingest_seed(&self, seed: &Seed) -> Result<bool> {
        anyhow::ensure!(
            mycelium_common::validate::is_valid_hash(&seed.hash),
            "refusing seed with non-hash name"
        );
        let db = self.db.lock().unwrap();
        let is_new = db.store_seed(seed)?;
        if is_new {
            let blob_path = self.corpus_dir.join("blobs").join(&seed.hash);
            if let Err(e) = std::fs::write(&blob_path, &seed.data) {
                let _ = db.delete_seed(&seed.hash, &seed.campaign);
                return Err(e.into());
            }
        }
        Ok(is_new)
    }

    pub fn node_campaign(&self, node_id: &str) -> Result<Option<String>> {
        let db = self.db.lock().unwrap();
        db.node_campaign(node_id)
    }

    pub fn get_seeds_for_node(&self, node_id: &str, campaign: &str) -> Result<Vec<Seed>> {
        let db = self.db.lock().unwrap();
        if let Ok(Some(info)) = db.get_campaign(campaign) {
            if matches!(info.lifecycle, CampaignLifecycle::Paused | CampaignLifecycle::Completed) {
                return Ok(vec![]);
            }
        }
        let seeds = db.get_unseen_seeds(node_id, campaign)?;
        for seed in &seeds {
            db.mark_seed_sent(&seed.hash, node_id)?;
        }
        Ok(seeds)
    }

    pub fn ingest_crash(&self, crash: &CrashEntry) -> Result<bool> {
        anyhow::ensure!(
            mycelium_common::validate::is_valid_hash(&crash.stack_hash)
                && mycelium_common::validate::is_valid_hash(&crash.input_hash),
            "refusing crash with non-hash name"
        );
        let db = self.db.lock().unwrap();
        let is_new = db.store_crash(crash)?;
        if is_new {
            let write = || -> std::io::Result<()> {
                let crash_dir = self.corpus_dir.join("crashes").join(&crash.stack_hash);
                std::fs::create_dir_all(&crash_dir)?;
                std::fs::write(crash_dir.join(format!("{}.bin", crash.input_hash)), &crash.data)?;
                std::fs::write(
                    crash_dir.join(format!("{}.txt", crash.input_hash)),
                    &crash.sanitizer_output,
                )?;
                Ok(())
            };
            if let Err(e) = write() {
                let _ = db.delete_crash(&crash.input_hash, &crash.campaign);
                return Err(e.into());
            }
        }
        Ok(is_new)
    }

    pub fn heartbeat(
        &self,
        node_id: &str,
        execs_per_sec: u64,
        corpus_size: u64,
        crashes_found: u64,
        edges_found: u64,
    ) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.update_heartbeat(node_id, execs_per_sec, corpus_size, crashes_found, edges_found)
    }

    pub fn list_nodes(&self, campaign: Option<&str>) -> Result<Vec<NodeInfo>> {
        let db = self.db.lock().unwrap();
        db.list_nodes(campaign)
    }

    pub fn campaign_status(&self, campaign: &str) -> Result<CampaignStatus> {
        let db = self.db.lock().unwrap();
        let nodes = db.list_nodes(Some(campaign))?;
        let lifecycle = db
            .get_campaign_lifecycle(campaign)?
            .unwrap_or(CampaignLifecycle::Running);
        Ok(CampaignStatus {
            name: campaign.to_string(),
            total_corpus: db.count_seeds(campaign)?,
            total_crashes: db.count_crashes(campaign)?,
            unique_bugs: db.count_unique_bugs(campaign)?,
            total_execs_per_sec: db.sum_execs_per_sec(campaign)?,
            total_edges: db.sum_edges(campaign)?,
            nodes_online: nodes
                .iter()
                .filter(|n| n.status == NodeStatus::Online)
                .count() as u64,
            lifecycle,
        })
    }

    pub fn create_campaign(
        &self,
        name: &str,
        fuzzer_name: &str,
        fuzzer_command: &[String],
        triage_cmd: Option<&[String]>,
    ) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.create_campaign(name, fuzzer_name, fuzzer_command, triage_cmd)
    }

    pub fn get_campaign(&self, name: &str) -> Result<Option<CampaignInfo>> {
        let db = self.db.lock().unwrap();
        db.get_campaign(name)
    }

    pub fn update_campaign_lifecycle(
        &self,
        name: &str,
        lifecycle: CampaignLifecycle,
    ) -> Result<bool> {
        let db = self.db.lock().unwrap();
        db.update_campaign_lifecycle(name, lifecycle)
    }

    pub fn store_harness(&self, campaign: &str, data: &[u8]) -> Result<()> {
        anyhow::ensure!(
            mycelium_common::validate::is_valid_campaign(campaign),
            "refusing harness for invalid campaign name"
        );
        let path = self.corpus_dir.join("harnesses").join(campaign);
        std::fs::write(&path, data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
        }
        let db = self.db.lock().unwrap();
        db.set_harness_len(campaign, data.len() as u64)?;
        Ok(())
    }

    pub fn get_harness(&self, campaign: &str) -> Result<Option<Vec<u8>>> {
        anyhow::ensure!(
            mycelium_common::validate::is_valid_campaign(campaign),
            "refusing harness lookup for invalid campaign name"
        );
        let path = self.corpus_dir.join("harnesses").join(campaign);
        if path.exists() {
            Ok(Some(std::fs::read(&path)?))
        } else {
            Ok(None)
        }
    }

    pub fn snapshot_metrics(&self) -> Result<()> {
        let db = self.db.lock().unwrap();
        for name in db.list_campaign_names()? {
            if let Err(e) = db.snapshot_metrics(&name) {
                tracing::warn!(campaign = %name, error = %e, "metrics snapshot failed");
            }
        }
        Ok(())
    }

    pub fn get_metrics(&self, campaign: &str, limit: u64) -> Result<Vec<MetricsSnapshot>> {
        let db = self.db.lock().unwrap();
        db.get_metrics(campaign, limit)
    }

    pub fn list_seed_hashes(&self, campaign: &str) -> Result<Vec<String>> {
        let db = self.db.lock().unwrap();
        db.list_seed_hashes(campaign)
    }

    pub fn list_crashes(
        &self,
        campaign: &str,
        limit: u64,
    ) -> Result<Vec<CrashEntry>> {
        let db = self.db.lock().unwrap();
        db.list_crashes(campaign, limit)
    }
}
