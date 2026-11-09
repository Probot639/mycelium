use anyhow::Result;
use sqlx::{PgPool, Row};

use mycelium_common::corpus::{CrashEntry, Seed};
use mycelium_common::node::{NodeInfo, NodeStatus, Priority};
use mycelium_common::protocol::{CampaignInfo, CampaignLifecycle, MetricsSnapshot};

use crate::storage::Storage;

pub struct PgDb {
    pool: PgPool,
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
}

impl PgDb {
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(url)
            .await?;
        Self::connect_with_pool(pool).await
    }

    pub async fn connect_with_pool(pool: PgPool) -> Result<Self> {
        let db = Self { pool };
        db.run_migrations().await?;
        Ok(db)
    }

    async fn run_migrations(&self) -> Result<()> {
        sqlx::query(include_str!("../../../migrations/001_init.sql"))
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

impl Storage for PgDb {
    fn register_node(&self, info: &NodeInfo) -> Result<()> {
        block_on(async {
            sqlx::query(
                "INSERT INTO nodes (id, hostname, campaign, fuzzer, priority, status, last_sync, time_limited)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (id) DO UPDATE SET
                    hostname = EXCLUDED.hostname,
                    campaign = EXCLUDED.campaign,
                    fuzzer = EXCLUDED.fuzzer,
                    priority = EXCLUDED.priority,
                    status = EXCLUDED.status,
                    last_sync = EXCLUDED.last_sync,
                    time_limited = EXCLUDED.time_limited",
            )
            .bind(&info.id)
            .bind(&info.hostname)
            .bind(&info.campaign)
            .bind(&info.fuzzer)
            .bind(serde_json::to_string(&info.priority)?.trim_matches('"'))
            .bind(serde_json::to_string(&info.status)?.trim_matches('"'))
            .bind(info.last_sync.timestamp())
            .bind(info.time_limited)
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    fn deregister_node(&self, node_id: &str) -> Result<()> {
        block_on(async {
            sqlx::query("DELETE FROM nodes WHERE id = $1")
                .bind(node_id)
                .execute(&self.pool)
                .await?;
            sqlx::query("DELETE FROM seed_distribution WHERE node_id = $1")
                .bind(node_id)
                .execute(&self.pool)
                .await?;
            Ok(())
        })
    }

    fn update_node_status(&self, node_id: &str, status: NodeStatus) -> Result<()> {
        let status_str = serde_json::to_string(&status)?;
        block_on(async {
            sqlx::query("UPDATE nodes SET status = $1 WHERE id = $2")
                .bind(status_str.trim_matches('"'))
                .bind(node_id)
                .execute(&self.pool)
                .await?;
            Ok(())
        })
    }

    fn mark_stale_offline(&self, timeout_secs: i64) -> Result<usize> {
        let cutoff = chrono::Utc::now().timestamp() - timeout_secs;
        block_on(async {
            let r = sqlx::query(
                "UPDATE nodes SET status = 'unreachable' WHERE status = 'online' AND last_sync < $1",
            )
            .bind(cutoff)
            .execute(&self.pool)
            .await?;
            Ok(r.rows_affected() as usize)
        })
    }

    fn store_seed(&self, seed: &Seed) -> Result<bool> {
        block_on(async {
            let r = sqlx::query(
                "INSERT INTO seeds (hash, data, source_node, campaign, found_at)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (hash, campaign) DO NOTHING",
            )
            .bind(&seed.hash)
            .bind(&seed.data)
            .bind(&seed.source_node)
            .bind(&seed.campaign)
            .bind(seed.found_at.timestamp())
            .execute(&self.pool)
            .await?;
            Ok(r.rows_affected() > 0)
        })
    }

    fn delete_seed(&self, hash: &str, campaign: &str) -> Result<()> {
        block_on(async {
            sqlx::query("DELETE FROM seeds WHERE hash = $1 AND campaign = $2")
                .bind(hash)
                .bind(campaign)
                .execute(&self.pool)
                .await?;
            Ok(())
        })
    }

    fn node_campaign(&self, node_id: &str) -> Result<Option<String>> {
        block_on(async {
            let row = sqlx::query("SELECT campaign FROM nodes WHERE id = $1")
                .bind(node_id)
                .fetch_optional(&self.pool)
                .await?;
            Ok(row.map(|r| r.get("campaign")))
        })
    }

    fn get_campaign(&self, name: &str) -> Result<Option<CampaignInfo>> {
        block_on(async {
            let row = sqlx::query(
                "SELECT name, fuzzer_name, fuzzer_command, harness_len, created_at, triage_cmd, lifecycle
                 FROM campaigns WHERE name = $1",
            )
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
            match row {
                Some(r) => {
                    let cmd_json: serde_json::Value = r.get("fuzzer_command");
                    let triage_json: Option<serde_json::Value> = r.get("triage_cmd");
                    let lifecycle_str: String = r.get("lifecycle");
                    Ok(Some(CampaignInfo {
                        name: r.get("name"),
                        fuzzer_name: r.get("fuzzer_name"),
                        fuzzer_command: serde_json::from_value(cmd_json).unwrap_or_default(),
                        triage_cmd: triage_json.and_then(|j| serde_json::from_value(j).ok()),
                        harness_len: r.get::<i64, _>("harness_len") as u64,
                        created_at: r.get("created_at"),
                        lifecycle: serde_json::from_str(&format!("\"{lifecycle_str}\""))
                            .unwrap_or(CampaignLifecycle::Running),
                    }))
                }
                None => Ok(None),
            }
        })
    }

    fn get_unseen_seeds(&self, node_id: &str, campaign: &str) -> Result<Vec<Seed>> {
        block_on(async {
            let rows = sqlx::query(
                "SELECT s.hash, s.data, s.source_node, s.campaign, s.found_at
                 FROM seeds s
                 WHERE s.campaign = $1
                   AND s.source_node != $2
                   AND s.hash NOT IN (SELECT seed_hash FROM seed_distribution WHERE node_id = $2)",
            )
            .bind(campaign)
            .bind(node_id)
            .fetch_all(&self.pool)
            .await?;
            let mut seeds = Vec::new();
            for r in &rows {
                let ts: i64 = r.get("found_at");
                seeds.push(Seed {
                    hash: r.get("hash"),
                    data: r.get("data"),
                    source_node: r.get("source_node"),
                    campaign: r.get("campaign"),
                    found_at: chrono::DateTime::from_timestamp(ts, 0).unwrap_or_default(),
                });
            }
            Ok(seeds)
        })
    }

    fn mark_seed_sent(&self, seed_hash: &str, node_id: &str) -> Result<()> {
        block_on(async {
            sqlx::query(
                "INSERT INTO seed_distribution (seed_hash, node_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(seed_hash)
            .bind(node_id)
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    fn store_crash(&self, crash: &CrashEntry) -> Result<bool> {
        block_on(async {
            let r = sqlx::query(
                "INSERT INTO crashes (stack_hash, input_hash, data, sanitizer_output, source_node, campaign, found_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (input_hash, campaign) DO NOTHING",
            )
            .bind(&crash.stack_hash)
            .bind(&crash.input_hash)
            .bind(&crash.data)
            .bind(&crash.sanitizer_output)
            .bind(&crash.source_node)
            .bind(&crash.campaign)
            .bind(crash.found_at.timestamp())
            .execute(&self.pool)
            .await?;
            Ok(r.rows_affected() > 0)
        })
    }

    fn delete_crash(&self, input_hash: &str, campaign: &str) -> Result<()> {
        block_on(async {
            sqlx::query("DELETE FROM crashes WHERE input_hash = $1 AND campaign = $2")
                .bind(input_hash)
                .bind(campaign)
                .execute(&self.pool)
                .await?;
            Ok(())
        })
    }

    fn update_heartbeat(
        &self,
        node_id: &str,
        execs_per_sec: u64,
        corpus_size: u64,
        crashes_found: u64,
        edges_found: u64,
    ) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        let clamp = |v: u64| v.min(i64::MAX as u64) as i64;
        block_on(async {
            sqlx::query(
                "UPDATE nodes SET last_sync = $1, execs_per_sec = $2, corpus_size = $3, crashes_found = $4,
                    edges_found = $5,
                    status = CASE WHEN status = 'suspended' THEN 'suspended' ELSE 'online' END
                 WHERE id = $6",
            )
            .bind(now)
            .bind(clamp(execs_per_sec))
            .bind(clamp(corpus_size))
            .bind(clamp(crashes_found))
            .bind(clamp(edges_found))
            .bind(node_id)
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    fn list_nodes(&self, campaign: Option<&str>) -> Result<Vec<NodeInfo>> {
        block_on(async {
            let rows = if let Some(campaign) = campaign {
                sqlx::query(
                    "SELECT id, hostname, campaign, fuzzer, priority, status, last_sync, time_limited
                     FROM nodes WHERE campaign = $1",
                )
                .bind(campaign)
                .fetch_all(&self.pool)
                .await?
            } else {
                sqlx::query(
                    "SELECT id, hostname, campaign, fuzzer, priority, status, last_sync, time_limited
                     FROM nodes",
                )
                .fetch_all(&self.pool)
                .await?
            };
            let mut nodes = Vec::new();
            for r in &rows {
                let priority_str: String = r.get("priority");
                let status_str: String = r.get("status");
                let ts: i64 = r.get("last_sync");
                let time_limited: bool = r.get("time_limited");
                nodes.push(NodeInfo {
                    id: r.get("id"),
                    hostname: r.get("hostname"),
                    campaign: r.get("campaign"),
                    fuzzer: r.get("fuzzer"),
                    priority: serde_json::from_str(&format!("\"{priority_str}\""))
                        .unwrap_or(Priority::Shared),
                    status: serde_json::from_str(&format!("\"{status_str}\""))
                        .unwrap_or(NodeStatus::Offline),
                    time_limited,
                    last_sync: chrono::DateTime::from_timestamp(ts, 0).unwrap_or_default(),
                });
            }
            Ok(nodes)
        })
    }

    fn count_seeds(&self, campaign: &str) -> Result<u64> {
        block_on(async {
            let row = sqlx::query("SELECT COUNT(*) as cnt FROM seeds WHERE campaign = $1")
                .bind(campaign)
                .fetch_one(&self.pool)
                .await?;
            Ok(row.get::<i64, _>("cnt") as u64)
        })
    }

    fn count_crashes(&self, campaign: &str) -> Result<u64> {
        block_on(async {
            let row = sqlx::query("SELECT COUNT(*) as cnt FROM crashes WHERE campaign = $1")
                .bind(campaign)
                .fetch_one(&self.pool)
                .await?;
            Ok(row.get::<i64, _>("cnt") as u64)
        })
    }

    fn count_unique_bugs(&self, campaign: &str) -> Result<u64> {
        block_on(async {
            let row = sqlx::query(
                "SELECT COUNT(DISTINCT stack_hash) as cnt FROM crashes WHERE campaign = $1",
            )
            .bind(campaign)
            .fetch_one(&self.pool)
            .await?;
            Ok(row.get::<i64, _>("cnt") as u64)
        })
    }

    fn sum_execs_per_sec(&self, campaign: &str) -> Result<u64> {
        block_on(async {
            let row = sqlx::query(
                "SELECT COALESCE(SUM(execs_per_sec), 0) as total FROM nodes WHERE campaign = $1 AND status = 'online'",
            )
            .bind(campaign)
            .fetch_one(&self.pool)
            .await?;
            Ok(row.get::<i64, _>("total") as u64)
        })
    }

    fn sum_edges(&self, campaign: &str) -> Result<u64> {
        block_on(async {
            let row = sqlx::query(
                "SELECT COALESCE(SUM(edges_found), 0) as total FROM nodes WHERE campaign = $1 AND status = 'online'",
            )
            .bind(campaign)
            .fetch_one(&self.pool)
            .await?;
            Ok(row.get::<i64, _>("total") as u64)
        })
    }

    fn get_campaign_lifecycle(&self, name: &str) -> Result<Option<CampaignLifecycle>> {
        block_on(async {
            let row = sqlx::query("SELECT lifecycle FROM campaigns WHERE name = $1")
                .bind(name)
                .fetch_optional(&self.pool)
                .await?;
            match row {
                Some(r) => {
                    let s: String = r.get("lifecycle");
                    Ok(Some(
                        serde_json::from_str(&format!("\"{s}\""))
                            .unwrap_or(CampaignLifecycle::Running),
                    ))
                }
                None => Ok(None),
            }
        })
    }

    fn create_campaign(
        &self,
        name: &str,
        fuzzer_name: &str,
        fuzzer_command: &[String],
        triage_cmd: Option<&[String]>,
    ) -> Result<()> {
        let cmd_json = serde_json::to_value(fuzzer_command)?;
        let triage_json = triage_cmd.map(serde_json::to_value).transpose()?;
        let now = chrono::Utc::now().timestamp();
        block_on(async {
            sqlx::query(
                "INSERT INTO campaigns (name, fuzzer_name, fuzzer_command, triage_cmd, created_at)
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(name)
            .bind(fuzzer_name)
            .bind(&cmd_json)
            .bind(&triage_json)
            .bind(now)
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    fn set_harness_len(&self, campaign: &str, len: u64) -> Result<()> {
        block_on(async {
            sqlx::query("UPDATE campaigns SET harness_len = $1 WHERE name = $2")
                .bind(len as i64)
                .bind(campaign)
                .execute(&self.pool)
                .await?;
            Ok(())
        })
    }

    fn list_campaign_names(&self) -> Result<Vec<String>> {
        block_on(async {
            let rows = sqlx::query("SELECT name FROM campaigns ORDER BY created_at")
                .fetch_all(&self.pool)
                .await?;
            Ok(rows.iter().map(|r| r.get("name")).collect())
        })
    }

    fn snapshot_metrics(&self, campaign: &str) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        block_on(async {
            sqlx::query(
                "INSERT INTO metrics (campaign, ts, total_execs_per_sec, corpus_size, crashes, unique_bugs, edges, nodes_online)
                 SELECT $1, $2,
                    COALESCE((SELECT SUM(execs_per_sec) FROM nodes WHERE campaign = $1 AND status = 'online'), 0),
                    COALESCE((SELECT COUNT(*) FROM seeds WHERE campaign = $1), 0),
                    COALESCE((SELECT COUNT(*) FROM crashes WHERE campaign = $1), 0),
                    COALESCE((SELECT COUNT(DISTINCT stack_hash) FROM crashes WHERE campaign = $1), 0),
                    COALESCE((SELECT SUM(edges_found) FROM nodes WHERE campaign = $1 AND status = 'online'), 0),
                    COALESCE((SELECT COUNT(*) FROM nodes WHERE campaign = $1 AND status = 'online'), 0)
                 ON CONFLICT (campaign, ts) DO UPDATE SET
                    total_execs_per_sec = EXCLUDED.total_execs_per_sec,
                    corpus_size = EXCLUDED.corpus_size,
                    crashes = EXCLUDED.crashes,
                    unique_bugs = EXCLUDED.unique_bugs,
                    edges = EXCLUDED.edges,
                    nodes_online = EXCLUDED.nodes_online",
            )
            .bind(campaign)
            .bind(now)
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    fn get_metrics(&self, campaign: &str, limit: u64) -> Result<Vec<MetricsSnapshot>> {
        block_on(async {
            let rows = sqlx::query(
                "SELECT ts, total_execs_per_sec, corpus_size, crashes, unique_bugs, edges, nodes_online
                 FROM metrics WHERE campaign = $1 ORDER BY ts DESC LIMIT $2",
            )
            .bind(campaign)
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await?;
            let mut out: Vec<MetricsSnapshot> = rows
                .iter()
                .map(|r| MetricsSnapshot {
                    ts: r.get("ts"),
                    total_execs_per_sec: r.get::<i64, _>("total_execs_per_sec") as u64,
                    corpus_size: r.get::<i64, _>("corpus_size") as u64,
                    crashes: r.get::<i64, _>("crashes") as u64,
                    unique_bugs: r.get::<i64, _>("unique_bugs") as u64,
                    edges: r.get::<i64, _>("edges") as u64,
                    nodes_online: r.get::<i64, _>("nodes_online") as u64,
                })
                .collect();
            out.reverse();
            Ok(out)
        })
    }

    fn list_seed_hashes(&self, campaign: &str) -> Result<Vec<String>> {
        block_on(async {
            let rows =
                sqlx::query("SELECT hash FROM seeds WHERE campaign = $1 ORDER BY found_at")
                    .bind(campaign)
                    .fetch_all(&self.pool)
                    .await?;
            Ok(rows.iter().map(|r| r.get("hash")).collect())
        })
    }

    fn list_crashes(&self, campaign: &str, limit: u64) -> Result<Vec<CrashEntry>> {
        block_on(async {
            let rows = sqlx::query(
                "SELECT stack_hash, input_hash, data, sanitizer_output, source_node, campaign, found_at
                 FROM crashes WHERE campaign = $1 ORDER BY found_at DESC LIMIT $2",
            )
            .bind(campaign)
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await?;
            Ok(rows
                .iter()
                .map(|r| {
                    let ts: i64 = r.get("found_at");
                    CrashEntry {
                        stack_hash: r.get("stack_hash"),
                        input_hash: r.get("input_hash"),
                        data: r.get("data"),
                        sanitizer_output: r.get("sanitizer_output"),
                        source_node: r.get("source_node"),
                        campaign: r.get("campaign"),
                        found_at: chrono::DateTime::from_timestamp(ts, 0).unwrap_or_default(),
                    }
                })
                .collect())
        })
    }

    fn update_campaign_lifecycle(
        &self,
        name: &str,
        lifecycle: CampaignLifecycle,
    ) -> Result<bool> {
        let status_str = serde_json::to_string(&lifecycle)?;
        block_on(async {
            let r = sqlx::query("UPDATE campaigns SET lifecycle = $1 WHERE name = $2")
                .bind(status_str.trim_matches('"'))
                .bind(name)
                .execute(&self.pool)
                .await?;
            Ok(r.rows_affected() > 0)
        })
    }
}
