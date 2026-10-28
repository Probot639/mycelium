use std::path::Path;
use std::time::Duration;

use anyhow::Result;

use mycelium_common::corpus::{hash_bytes, CrashEntry, Seed};
use mycelium_common::protocol::*;

pub struct SyncClient {
    client: reqwest::Client,
    coordinator_url: String,
    node_id: String,
    campaign: String,
}

impl SyncClient {
    pub fn new(coordinator_url: &str, node_id: &str, campaign: &str) -> Self {
        let base = if coordinator_url.starts_with("http") {
            coordinator_url.to_string()
        } else {
            format!("http://{coordinator_url}")
        };
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("failed to build http client"),
            coordinator_url: base,
            node_id: node_id.to_string(),
            campaign: campaign.to_string(),
        }
    }

    // register is static because the node_id doesn't exist yet, we get it back
    pub async fn register(
        coordinator_url: &str,
        hostname: &str,
        campaign: &str,
        fuzzer: &str,
        priority: mycelium_common::node::Priority,
    ) -> Result<String> {
        let base = if coordinator_url.starts_with("http") {
            coordinator_url.to_string()
        } else {
            format!("http://{coordinator_url}")
        };
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base}/register"))
            .json(&RegisterRequest {
                hostname: hostname.into(),
                campaign: campaign.into(),
                fuzzer: fuzzer.into(),
                priority,
            })
            .send()
            .await?
            .error_for_status()?
            .json::<RegisterResponse>()
            .await?;
        Ok(resp.node_id)
    }

    pub async fn push_seed(&self, hash: String, data: Vec<u8>) -> Result<()> {
        let seed = Seed {
            hash,
            data,
            source_node: self.node_id.clone(),
            campaign: self.campaign.clone(),
            found_at: chrono::Utc::now(),
        };
        self.client
            .post(format!("{}/seed/push", self.coordinator_url))
            .json(&PushSeedRequest {
                node_id: self.node_id.clone(),
                seed,
            })
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn pull_seeds(&self) -> Result<Vec<Seed>> {
        let resp = self
            .client
            .post(format!("{}/seed/pull", self.coordinator_url))
            .json(&PullSeedsRequest {
                node_id: self.node_id.clone(),
                known_hashes: vec![],
            })
            .send()
            .await?
            .error_for_status()?
            .json::<PullSeedsResponse>()
            .await?;
        Ok(resp.seeds)
    }

    pub async fn report_crash(&self, data: Vec<u8>, sanitizer_output: &str) -> Result<()> {
        let input_hash = hash_bytes(&data);
        // Simple stack hash: hash the first 3 non-empty lines of sanitizer output
        let stack_hash = {
            let lines: Vec<&str> = sanitizer_output
                .lines()
                .filter(|l| !l.trim().is_empty())
                .take(3)
                .collect();
            hash_bytes(lines.join("\n").as_bytes())
        };
        let crash = CrashEntry {
            stack_hash,
            input_hash,
            data,
            sanitizer_output: sanitizer_output.to_string(),
            source_node: self.node_id.clone(),
            campaign: self.campaign.clone(),
            found_at: chrono::Utc::now(),
        };
        self.client
            .post(format!("{}/crash", self.coordinator_url))
            .json(&ReportCrashRequest {
                node_id: self.node_id.clone(),
                crash,
            })
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn heartbeat(&self, execs_per_sec: u64, corpus_size: u64, crashes_found: u64) -> Result<()> {
        self.client
            .post(format!("{}/heartbeat", self.coordinator_url))
            .json(&HeartbeatRequest {
                node_id: self.node_id.clone(),
                execs_per_sec,
                corpus_size,
                crashes_found,
            })
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn deregister(&self, drain: bool) -> Result<()> {
        self.client
            .post(format!("{}/deregister", self.coordinator_url))
            .json(&DeregisterRequest {
                node_id: self.node_id.clone(),
                drain,
            })
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub fn inject_seed(&self, inject_dir: &Path, seed: &Seed) -> Result<()> {
        let path = inject_dir.join(&seed.hash);
        if !path.exists() {
            std::fs::write(&path, &seed.data)?;
        }
        Ok(())
    }
}
