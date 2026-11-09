use std::path::Path;
use std::time::Duration;

use anyhow::Result;

use mycelium_common::corpus::{hash_bytes, CrashEntry, Seed};
use mycelium_common::protocol::*;

#[derive(Clone)]
pub struct SyncClient {
    client: reqwest::Client,
    coordinator_url: String,
    node_id: String,
    campaign: String,
}

// The sync-loop client's request timeout. Kept short on purpose: pull, push and
// heartbeat all run from the one select! loop, so a request that hangs on a slow
// or dead coordinator stalls the whole loop (lapsing the heartbeat, letting the
// watcher's unbounded channel grow). Failing fast lets the loop keep draining
// and keep heartbeating; a dropped seed batch is recovered on the next tick.
const LOOP_TIMEOUT_SECS: u64 = 20;
// Base-corpus and harness uploads can be large (tens of MB) and run once, off
// the loop, so they get a generous timeout instead.
const UPLOAD_TIMEOUT_SECS: u64 = 300;

// Build an HTTP client that carries the coordinator bearer token from
// MYCELIUM_TOKEN, if set. Symmetric with the coordinator: both read the same
// env var, so a node on a secured coordinator just needs that var exported.
fn client_with_auth() -> reqwest::Client {
    client_with_timeout(LOOP_TIMEOUT_SECS)
}

fn client_with_timeout(timeout_secs: u64) -> reqwest::Client {
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(timeout_secs));
    if let Some(token) = std::env::var("MYCELIUM_TOKEN").ok().filter(|s| !s.is_empty())
        && let Ok(val) = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
    {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::AUTHORIZATION, val);
        builder = builder.default_headers(headers);
    }
    builder.build().expect("failed to build http client")
}

impl SyncClient {
    pub fn new(coordinator_url: &str, node_id: &str, campaign: &str) -> Self {
        let base = if coordinator_url.starts_with("http") {
            coordinator_url.to_string()
        } else {
            format!("http://{coordinator_url}")
        };
        Self {
            client: client_with_auth(),
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
        requested_id: Option<String>,
        time_limited: bool,
    ) -> Result<String> {
        let base = if coordinator_url.starts_with("http") {
            coordinator_url.to_string()
        } else {
            format!("http://{coordinator_url}")
        };
        let client = client_with_auth();
        let resp = client
            .post(format!("{base}/register"))
            .json(&RegisterRequest {
                hostname: hostname.into(),
                campaign: campaign.into(),
                fuzzer: fuzzer.into(),
                priority,
                requested_id,
                time_limited,
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

    // Push a burst of seeds in one request, so a fast fuzzer is not bottlenecked
    // on one HTTP round-trip per seed.
    pub async fn push_seeds_batch(&self, items: Vec<(String, Vec<u8>)>) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        let seeds: Vec<Seed> = items
            .into_iter()
            .map(|(hash, data)| Seed {
                hash,
                data,
                source_node: self.node_id.clone(),
                campaign: self.campaign.clone(),
                found_at: chrono::Utc::now(),
            })
            .collect();
        self.client
            .post(format!("{}/seed/push/batch", self.coordinator_url))
            .json(&PushSeedBatchRequest {
                node_id: self.node_id.clone(),
                seeds,
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
                campaign: self.campaign.clone(),
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
        // Per-bug hash from the trace's error class and top frames. With no
        // usable trace, fall back to the input hash so traceless crashes stay
        // distinct instead of all collapsing onto one value.
        let stack_hash = mycelium_common::triage::stack_hash(sanitizer_output)
            .unwrap_or_else(|| input_hash.clone());
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

    pub async fn heartbeat(
        &self,
        execs_per_sec: u64,
        corpus_size: u64,
        crashes_found: u64,
        edges_found: u64,
    ) -> Result<()> {
        self.client
            .post(format!("{}/heartbeat", self.coordinator_url))
            .json(&HeartbeatRequest {
                node_id: self.node_id.clone(),
                execs_per_sec,
                corpus_size,
                crashes_found,
                edges_found,
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
        // The hash becomes a path component, and it arrives from the coordinator,
        // so re-validate it node-side before the join: a value like
        // "../../.ssh/authorized_keys" would otherwise write attacker bytes
        // outside inject_dir. The coordinator validates on ingest too, but the
        // node does not get to assume that.
        anyhow::ensure!(
            mycelium_common::validate::is_valid_hash(&seed.hash),
            "refusing to inject seed with non-hash name"
        );
        let path = inject_dir.join(&seed.hash);
        if !path.exists() {
            std::fs::write(&path, &seed.data)?;
        }
        Ok(())
    }

    pub async fn create_campaign(
        coordinator_url: &str,
        name: &str,
        fuzzer_name: &str,
        fuzzer_command: &[String],
        triage_cmd: Option<&[String]>,
    ) -> Result<()> {
        let base = if coordinator_url.starts_with("http") {
            coordinator_url.to_string()
        } else {
            format!("http://{coordinator_url}")
        };
        client_with_auth()
            .post(format!("{base}/campaign"))
            .json(&mycelium_common::protocol::CreateCampaignRequest {
                name: name.into(),
                fuzzer_name: fuzzer_name.into(),
                fuzzer_command: fuzzer_command.to_vec(),
                triage_cmd: triage_cmd.map(|c| c.to_vec()),
            })
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    // Upload base-corpus seeds for a campaign before any node joins. They are
    // tagged with a synthetic source so every real node receives them.
    pub async fn upload_seeds(
        coordinator_url: &str,
        campaign: &str,
        seeds: Vec<(String, Vec<u8>)>,
    ) -> Result<usize> {
        let base = if coordinator_url.starts_with("http") {
            coordinator_url.to_string()
        } else {
            format!("http://{coordinator_url}")
        };
        let seed_structs: Vec<Seed> = seeds
            .into_iter()
            .map(|(hash, data)| Seed {
                hash,
                data,
                source_node: "campaign-seed".into(),
                campaign: campaign.into(),
                found_at: chrono::Utc::now(),
            })
            .collect();
        let n = seed_structs.len();
        client_with_timeout(UPLOAD_TIMEOUT_SECS)
            .post(format!("{base}/seed/push/batch"))
            .json(&PushSeedBatchRequest {
                node_id: "campaign-seed".into(),
                seeds: seed_structs,
            })
            .send()
            .await?
            .error_for_status()?;
        Ok(n)
    }

    pub async fn upload_harness(
        coordinator_url: &str,
        campaign: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        let base = if coordinator_url.starts_with("http") {
            coordinator_url.to_string()
        } else {
            format!("http://{coordinator_url}")
        };
        client_with_timeout(UPLOAD_TIMEOUT_SECS)
            .put(format!("{base}/campaign/{campaign}/harness"))
            .body(data)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn download_harness(
        coordinator_url: &str,
        campaign: &str,
    ) -> Result<Vec<u8>> {
        let base = if coordinator_url.starts_with("http") {
            coordinator_url.to_string()
        } else {
            format!("http://{coordinator_url}")
        };
        let bytes = client_with_timeout(UPLOAD_TIMEOUT_SECS)
            .get(format!("{base}/campaign/{campaign}/harness"))
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        Ok(bytes.to_vec())
    }

    pub async fn get_campaign_info(
        coordinator_url: &str,
        campaign: &str,
    ) -> Result<mycelium_common::protocol::CampaignInfo> {
        let base = if coordinator_url.starts_with("http") {
            coordinator_url.to_string()
        } else {
            format!("http://{coordinator_url}")
        };
        let info = client_with_auth()
            .get(format!("{base}/campaign/{campaign}"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_with_hash(hash: &str) -> Seed {
        Seed {
            hash: hash.into(),
            data: b"payload".to_vec(),
            source_node: "n".into(),
            campaign: "c".into(),
            found_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn inject_rejects_traversal_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let client = SyncClient::new("http://127.0.0.1:1", "n", "c");
        // a coordinator-supplied hash that is really a path must be refused
        let bad = seed_with_hash("../../escape");
        assert!(client.inject_seed(tmp.path(), &bad).is_err());
        assert!(!tmp.path().parent().unwrap().join("escape").exists());
        // a real content hash is written as a plain file under inject_dir
        let good = seed_with_hash(&"a".repeat(64));
        assert!(client.inject_seed(tmp.path(), &good).is_ok());
        assert!(tmp.path().join("a".repeat(64)).exists());
    }
}
