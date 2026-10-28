use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::Result;

use mycelium_common::corpus::{CrashEntry, Seed};
use mycelium_common::node::{NodeInfo, NodeStatus};
use mycelium_common::protocol::{CampaignInfo, CampaignStatus};

use crate::db::Db;

pub struct CoordinatorState {
    pub db: Mutex<Db>,
    pub corpus_dir: PathBuf,
}

impl CoordinatorState {
    pub fn new(db_path: &Path, corpus_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(corpus_dir)?;
        std::fs::create_dir_all(corpus_dir.join("blobs"))?;
        std::fs::create_dir_all(corpus_dir.join("crashes"))?;
        std::fs::create_dir_all(corpus_dir.join("harnesses"))?;

        Ok(Self {
            db: Mutex::new(Db::open(db_path)?),
            corpus_dir: corpus_dir.to_path_buf(),
        })
    }

    pub fn new_in_memory(corpus_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(corpus_dir)?;
        std::fs::create_dir_all(corpus_dir.join("blobs"))?;
        std::fs::create_dir_all(corpus_dir.join("crashes"))?;
        std::fs::create_dir_all(corpus_dir.join("harnesses"))?;
        Ok(Self {
            db: Mutex::new(Db::open_in_memory()?),
            corpus_dir: corpus_dir.to_path_buf(),
        })
    }

    pub fn register_node(&self, info: &NodeInfo) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.register_node(info)
    }

    pub fn deregister_node(&self, node_id: &str) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.deregister_node(node_id)
    }

    pub fn ingest_seed(&self, seed: &Seed) -> Result<bool> {
        let db = self.db.lock().unwrap();
        let is_new = db.store_seed(seed)?;
        if is_new {
            let blob_path = self.corpus_dir.join("blobs").join(&seed.hash);
            std::fs::write(&blob_path, &seed.data)?;
        }
        Ok(is_new)
    }

    pub fn get_seeds_for_node(&self, node_id: &str, campaign: &str) -> Result<Vec<Seed>> {
        let db = self.db.lock().unwrap();
        let seeds = db.get_unseen_seeds(node_id, campaign)?;
        for seed in &seeds {
            db.mark_seed_sent(&seed.hash, node_id)?;
        }
        Ok(seeds)
    }

    pub fn ingest_crash(&self, crash: &CrashEntry) -> Result<bool> {
        let db = self.db.lock().unwrap();
        let is_new = db.store_crash(crash)?;
        if is_new {
            let crash_dir = self.corpus_dir.join("crashes").join(&crash.stack_hash);
            std::fs::create_dir_all(&crash_dir)?;
            std::fs::write(crash_dir.join("input.bin"), &crash.data)?;
            std::fs::write(crash_dir.join("trace.txt"), &crash.sanitizer_output)?;
        }
        Ok(is_new)
    }

    pub fn heartbeat(
        &self,
        node_id: &str,
        execs_per_sec: u64,
        corpus_size: u64,
        crashes_found: u64,
    ) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.update_heartbeat(node_id, execs_per_sec, corpus_size, crashes_found)
    }

    pub fn list_nodes(&self, campaign: Option<&str>) -> Result<Vec<NodeInfo>> {
        let db = self.db.lock().unwrap();
        db.list_nodes(campaign)
    }

    pub fn campaign_status(&self, campaign: &str) -> Result<CampaignStatus> {
        let db = self.db.lock().unwrap();
        let nodes = db.list_nodes(Some(campaign))?;
        // TODO: execs_per_sec lives in the nodes table but NodeInfo doesn't
        // carry it yet, so this is always zero. fix when we add the stats column
        // to the select in list_nodes
        let total_execs_per_sec = 0u64;
        Ok(CampaignStatus {
            name: campaign.to_string(),
            total_corpus: db.count_seeds(campaign)?,
            total_crashes: db.count_crashes(campaign)?,
            total_execs_per_sec,
            nodes_online: nodes
                .iter()
                .filter(|n| n.status == NodeStatus::Online)
                .count() as u64,
        })
    }

    pub fn create_campaign(
        &self,
        name: &str,
        fuzzer_name: &str,
        fuzzer_command: &[String],
    ) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.create_campaign(name, fuzzer_name, fuzzer_command)
    }

    pub fn get_campaign(&self, name: &str) -> Result<Option<CampaignInfo>> {
        let db = self.db.lock().unwrap();
        db.get_campaign(name)
    }

    pub fn store_harness(&self, campaign: &str, data: &[u8]) -> Result<()> {
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
        let path = self.corpus_dir.join("harnesses").join(campaign);
        if path.exists() {
            Ok(Some(std::fs::read(&path)?))
        } else {
            Ok(None)
        }
    }
}
