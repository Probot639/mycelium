use std::path::Path;

use anyhow::Result;
use rusqlite::Connection;

use mycelium_common::corpus::{CrashEntry, Seed};
use mycelium_common::node::{NodeInfo, NodeStatus, Priority};
use mycelium_common::protocol::{CampaignLifecycle, MetricsSnapshot};

pub struct Db {
    conn: Connection,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.init_tables()?;
        Ok(db)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.init_tables()?;
        Ok(db)
    }

    fn init_tables(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                campaign TEXT NOT NULL,
                fuzzer TEXT NOT NULL,
                priority TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'online',
                last_sync INTEGER NOT NULL,
                execs_per_sec INTEGER NOT NULL DEFAULT 0,
                corpus_size INTEGER NOT NULL DEFAULT 0,
                crashes_found INTEGER NOT NULL DEFAULT 0,
                time_limited INTEGER NOT NULL DEFAULT 0,
                edges_found INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS seeds (
                hash TEXT NOT NULL,
                data BLOB NOT NULL,
                source_node TEXT NOT NULL,
                campaign TEXT NOT NULL,
                found_at INTEGER NOT NULL,
                PRIMARY KEY (hash, campaign)
            );

            CREATE TABLE IF NOT EXISTS crashes (
                stack_hash TEXT NOT NULL,
                input_hash TEXT NOT NULL,
                data BLOB NOT NULL,
                sanitizer_output TEXT NOT NULL,
                source_node TEXT NOT NULL,
                campaign TEXT NOT NULL,
                found_at INTEGER NOT NULL,
                PRIMARY KEY (input_hash, campaign)
            );

            CREATE TABLE IF NOT EXISTS seed_distribution (
                seed_hash TEXT NOT NULL,
                node_id TEXT NOT NULL,
                PRIMARY KEY (seed_hash, node_id)
            );

            CREATE TABLE IF NOT EXISTS campaigns (
                name TEXT PRIMARY KEY,
                fuzzer_name TEXT NOT NULL,
                fuzzer_command TEXT NOT NULL,
                harness_len INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                triage_cmd TEXT,
                lifecycle TEXT NOT NULL DEFAULT 'running'
            );

            CREATE TABLE IF NOT EXISTS metrics (
                campaign TEXT NOT NULL,
                ts INTEGER NOT NULL,
                total_execs_per_sec INTEGER NOT NULL DEFAULT 0,
                corpus_size INTEGER NOT NULL DEFAULT 0,
                crashes INTEGER NOT NULL DEFAULT 0,
                unique_bugs INTEGER NOT NULL DEFAULT 0,
                edges INTEGER NOT NULL DEFAULT 0,
                nodes_online INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (campaign, ts)
            );",
        )?;
        // Add columns introduced after the first schema. ADD COLUMN errors if
        // the column already exists, so ignore that one case.
        let _ = self.conn.execute("ALTER TABLE nodes ADD COLUMN time_limited INTEGER NOT NULL DEFAULT 0", []);
        let _ = self.conn.execute("ALTER TABLE nodes ADD COLUMN edges_found INTEGER NOT NULL DEFAULT 0", []);
        let _ = self.conn.execute("ALTER TABLE campaigns ADD COLUMN triage_cmd TEXT", []);
        let _ = self.conn.execute("ALTER TABLE campaigns ADD COLUMN lifecycle TEXT NOT NULL DEFAULT 'running'", []);
        Ok(())
    }

    pub fn register_node(&self, info: &NodeInfo) -> Result<()> {
        // serde_json wraps enum values in quotes ("shared"), trim them for sqlite.
        // On re-register (a restart reusing a stable id) update the descriptive
        // columns but leave execs_per_sec/corpus_size/crashes_found alone, so a
        // restart does not zero out the node's accumulated stats. A plain
        // INSERT OR REPLACE would delete the row and reset those to their default.
        self.conn.execute(
            "INSERT INTO nodes (id, hostname, campaign, fuzzer, priority, status, last_sync, time_limited)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
                hostname = excluded.hostname,
                campaign = excluded.campaign,
                fuzzer = excluded.fuzzer,
                priority = excluded.priority,
                status = excluded.status,
                last_sync = excluded.last_sync,
                time_limited = excluded.time_limited",
            (
                &info.id,
                &info.hostname,
                &info.campaign,
                &info.fuzzer,
                serde_json::to_string(&info.priority)?.trim_matches('"'),
                serde_json::to_string(&info.status)?.trim_matches('"'),
                info.last_sync.timestamp(),
                info.time_limited as i64,
            ),
        )?;
        Ok(())
    }

    pub fn deregister_node(&self, node_id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM nodes WHERE id = ?1", [node_id])?;
        self.conn
            .execute("DELETE FROM seed_distribution WHERE node_id = ?1", [node_id])?;
        Ok(())
    }

    // Mark online nodes whose last heartbeat is older than the timeout as
    // unreachable, so they stop counting toward nodes_online and the execs/sec
    // total. Returns how many were reaped.
    pub fn mark_stale_offline(&self, timeout_secs: i64) -> Result<usize> {
        let cutoff = chrono::Utc::now().timestamp() - timeout_secs;
        let n = self.conn.execute(
            "UPDATE nodes SET status = 'unreachable' WHERE status = 'online' AND last_sync < ?1",
            [cutoff],
        )?;
        Ok(n)
    }

    pub fn update_node_status(&self, node_id: &str, status: NodeStatus) -> Result<()> {
        let status_str = serde_json::to_string(&status)?;
        self.conn.execute(
            "UPDATE nodes SET status = ?1 WHERE id = ?2",
            [status_str.trim_matches('"'), node_id],
        )?;
        Ok(())
    }

    pub fn update_heartbeat(
        &self,
        node_id: &str,
        execs_per_sec: u64,
        corpus_size: u64,
        crashes_found: u64,
        edges_found: u64,
    ) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        let clamp = |v: u64| v.min(i64::MAX as u64) as i64;
        self.conn.execute(
            "UPDATE nodes SET last_sync = ?1, execs_per_sec = ?2, corpus_size = ?3, crashes_found = ?4,
                edges_found = ?5,
                status = CASE WHEN status = 'suspended' THEN 'suspended' ELSE 'online' END
             WHERE id = ?6",
            (now, clamp(execs_per_sec), clamp(corpus_size), clamp(crashes_found), clamp(edges_found), node_id),
        )?;
        Ok(())
    }

    // TODO: these two branches are almost identical, could build the query
    // string dynamically but rusqlite makes that annoying with the param types
    pub fn list_nodes(&self, campaign: Option<&str>) -> Result<Vec<NodeInfo>> {
        let mut nodes = Vec::new();
        if let Some(campaign) = campaign {
            let mut stmt = self
                .conn
                .prepare("SELECT id, hostname, campaign, fuzzer, priority, status, last_sync, time_limited FROM nodes WHERE campaign = ?1")?;
            let rows = stmt.query_map([campaign], |row| {
                Ok(Self::node_from_row(row))
            })?;
            for row in rows {
                nodes.push(row??);
            }
        } else {
            let mut stmt = self
                .conn
                .prepare("SELECT id, hostname, campaign, fuzzer, priority, status, last_sync, time_limited FROM nodes")?;
            let rows = stmt.query_map([], |row| {
                Ok(Self::node_from_row(row))
            })?;
            for row in rows {
                nodes.push(row??);
            }
        }
        Ok(nodes)
    }

    fn node_from_row(row: &rusqlite::Row<'_>) -> Result<NodeInfo> {
        let priority_str: String = row.get(4)?;
        let status_str: String = row.get(5)?;
        let ts: i64 = row.get(6)?;
        let time_limited: i64 = row.get(7)?;
        Ok(NodeInfo {
            id: row.get(0)?,
            hostname: row.get(1)?,
            campaign: row.get(2)?,
            fuzzer: row.get(3)?,
            priority: serde_json::from_str(&format!("\"{priority_str}\""))
                .unwrap_or(Priority::Shared),
            status: serde_json::from_str(&format!("\"{status_str}\""))
                .unwrap_or(NodeStatus::Offline),
            time_limited: time_limited != 0,
            last_sync: chrono::DateTime::from_timestamp(ts, 0)
                .unwrap_or_default(),
        })
    }

    pub fn store_seed(&self, seed: &Seed) -> Result<bool> {
        let result = self.conn.execute(
            "INSERT OR IGNORE INTO seeds (hash, data, source_node, campaign, found_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                &seed.hash,
                &seed.data,
                &seed.source_node,
                &seed.campaign,
                seed.found_at.timestamp(),
            ),
        )?;
        Ok(result > 0)
    }

    // Remove a just-stored row when its on-disk artifact failed to write, so the
    // row and the file stay consistent and a retry re-does both (otherwise the
    // committed row makes the retry short-circuit on is_new=false, leaving a
    // crash/seed with no reproducer on disk).
    pub fn delete_seed(&self, hash: &str, campaign: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM seeds WHERE hash = ?1 AND campaign = ?2",
            [hash, campaign],
        )?;
        Ok(())
    }

    pub fn delete_crash(&self, input_hash: &str, campaign: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM crashes WHERE input_hash = ?1 AND campaign = ?2",
            [input_hash, campaign],
        )?;
        Ok(())
    }

    pub fn mark_seed_sent(&self, seed_hash: &str, node_id: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO seed_distribution (seed_hash, node_id) VALUES (?1, ?2)",
            [seed_hash, node_id],
        )?;
        Ok(())
    }

    // The campaign a node registered for, by primary key. Used to bind a pull to
    // the node's own campaign so it cannot read another campaign's corpus.
    pub fn node_campaign(&self, node_id: &str) -> Result<Option<String>> {
        match self.conn.query_row(
            "SELECT campaign FROM nodes WHERE id = ?1",
            [node_id],
            |row| row.get::<_, String>(0),
        ) {
            Ok(c) => Ok(Some(c)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn get_unseen_seeds(&self, node_id: &str, campaign: &str) -> Result<Vec<Seed>> {
        let mut stmt = self.conn.prepare(
            "SELECT s.hash, s.data, s.source_node, s.campaign, s.found_at
             FROM seeds s
             WHERE s.campaign = ?1
               AND s.source_node != ?2
               AND s.hash NOT IN (SELECT seed_hash FROM seed_distribution WHERE node_id = ?2)",
        )?;
        let rows = stmt.query_map([campaign, node_id], |row| {
            let ts: i64 = row.get(4)?;
            Ok(Seed {
                hash: row.get(0)?,
                data: row.get(1)?,
                source_node: row.get(2)?,
                campaign: row.get(3)?,
                found_at: chrono::DateTime::from_timestamp(ts, 0).unwrap_or_default(),
            })
        })?;
        let mut seeds = Vec::new();
        for row in rows {
            seeds.push(row?);
        }
        Ok(seeds)
    }

    pub fn store_crash(&self, crash: &CrashEntry) -> Result<bool> {
        let result = self.conn.execute(
            "INSERT OR IGNORE INTO crashes (stack_hash, input_hash, data, sanitizer_output, source_node, campaign, found_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (
                &crash.stack_hash,
                &crash.input_hash,
                &crash.data,
                &crash.sanitizer_output,
                &crash.source_node,
                &crash.campaign,
                crash.found_at.timestamp(),
            ),
        )?;
        Ok(result > 0)
    }

    pub fn count_seeds(&self, campaign: &str) -> Result<u64> {
        let count: u64 = self.conn.query_row(
            "SELECT COUNT(*) FROM seeds WHERE campaign = ?1",
            [campaign],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    pub fn count_crashes(&self, campaign: &str) -> Result<u64> {
        let count: u64 = self.conn.query_row(
            "SELECT COUNT(*) FROM crashes WHERE campaign = ?1",
            [campaign],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    // Distinct bugs, by stack hash. With real traces this is far below the raw
    // crash count, which is the whole point of dedup by stack.
    pub fn count_unique_bugs(&self, campaign: &str) -> Result<u64> {
        let count: u64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT stack_hash) FROM crashes WHERE campaign = ?1",
            [campaign],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    // Live throughput across the campaign's online nodes. The per-node value is
    // written by the heartbeat; summing it here is what the dashboard shows.
    pub fn sum_execs_per_sec(&self, campaign: &str) -> Result<u64> {
        let total: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(execs_per_sec), 0) FROM nodes WHERE campaign = ?1 AND status = 'online'",
            [campaign],
            |row| row.get(0),
        )?;
        Ok(total as u64)
    }

    pub fn create_campaign(
        &self,
        name: &str,
        fuzzer_name: &str,
        fuzzer_command: &[String],
        triage_cmd: Option<&[String]>,
    ) -> Result<()> {
        let cmd_json = serde_json::to_string(fuzzer_command)?;
        let triage_json = triage_cmd.map(|c| serde_json::to_string(c)).transpose()?;
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "INSERT INTO campaigns (name, fuzzer_name, fuzzer_command, triage_cmd, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            (name, fuzzer_name, &cmd_json, &triage_json, now),
        )?;
        Ok(())
    }

    pub fn get_campaign(&self, name: &str) -> Result<Option<mycelium_common::protocol::CampaignInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, fuzzer_name, fuzzer_command, harness_len, created_at, triage_cmd, lifecycle FROM campaigns WHERE name = ?1",
        )?;
        let mut rows = stmt.query_map([name], |row| {
            let cmd_json: String = row.get(2)?;
            let harness_len: i64 = row.get(3)?;
            let triage_json: Option<String> = row.get(5)?;
            let lifecycle_str: String = row.get::<_, String>(6).unwrap_or_else(|_| "running".into());
            Ok(mycelium_common::protocol::CampaignInfo {
                name: row.get(0)?,
                fuzzer_name: row.get(1)?,
                fuzzer_command: serde_json::from_str(&cmd_json).unwrap_or_default(),
                triage_cmd: triage_json.and_then(|j| serde_json::from_str(&j).ok()),
                harness_len: harness_len as u64,
                created_at: row.get(4)?,
                lifecycle: serde_json::from_str(&format!("\"{lifecycle_str}\""))
                    .unwrap_or(CampaignLifecycle::Running),
            })
        })?;
        match rows.next() {
            Some(Ok(info)) => Ok(Some(info)),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    pub fn set_harness_len(&self, campaign: &str, len: u64) -> Result<()> {
        self.conn.execute(
            "UPDATE campaigns SET harness_len = ?1 WHERE name = ?2",
            (len as i64, campaign),
        )?;
        Ok(())
    }

    pub fn sum_edges(&self, campaign: &str) -> Result<u64> {
        let total: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(edges_found), 0) FROM nodes WHERE campaign = ?1 AND status = 'online'",
            [campaign],
            |row| row.get(0),
        )?;
        Ok(total as u64)
    }

    pub fn update_campaign_lifecycle(&self, name: &str, lifecycle: CampaignLifecycle) -> Result<bool> {
        let status_str = serde_json::to_string(&lifecycle)?;
        let n = self.conn.execute(
            "UPDATE campaigns SET lifecycle = ?1 WHERE name = ?2",
            [status_str.trim_matches('"'), name],
        )?;
        Ok(n > 0)
    }

    pub fn get_campaign_lifecycle(&self, name: &str) -> Result<Option<CampaignLifecycle>> {
        match self.conn.query_row(
            "SELECT lifecycle FROM campaigns WHERE name = ?1",
            [name],
            |row| row.get::<_, String>(0),
        ) {
            Ok(s) => Ok(Some(
                serde_json::from_str(&format!("\"{s}\"")).unwrap_or(CampaignLifecycle::Running),
            )),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn snapshot_metrics(&self, campaign: &str) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        let corpus = self.count_seeds(campaign)? as i64;
        let crashes = self.count_crashes(campaign)? as i64;
        let bugs = self.count_unique_bugs(campaign)? as i64;
        let execs: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(execs_per_sec), 0) FROM nodes WHERE campaign = ?1 AND status = 'online'",
            [campaign],
            |row| row.get(0),
        )?;
        let edges: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(edges_found), 0) FROM nodes WHERE campaign = ?1 AND status = 'online'",
            [campaign],
            |row| row.get(0),
        )?;
        let nodes: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM nodes WHERE campaign = ?1 AND status = 'online'",
            [campaign],
            |row| row.get(0),
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO metrics (campaign, ts, total_execs_per_sec, corpus_size, crashes, unique_bugs, edges, nodes_online)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            (campaign, now, execs, corpus, crashes, bugs, edges, nodes),
        )?;
        Ok(())
    }

    pub fn get_metrics(&self, campaign: &str, limit: u64) -> Result<Vec<MetricsSnapshot>> {
        let mut stmt = self.conn.prepare(
            "SELECT ts, total_execs_per_sec, corpus_size, crashes, unique_bugs, edges, nodes_online
             FROM metrics WHERE campaign = ?1 ORDER BY ts DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![campaign, limit as i64], |row| {
            Ok(MetricsSnapshot {
                ts: row.get(0)?,
                total_execs_per_sec: row.get::<_, i64>(1)? as u64,
                corpus_size: row.get::<_, i64>(2)? as u64,
                crashes: row.get::<_, i64>(3)? as u64,
                unique_bugs: row.get::<_, i64>(4)? as u64,
                edges: row.get::<_, i64>(5)? as u64,
                nodes_online: row.get::<_, i64>(6)? as u64,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        out.reverse();
        Ok(out)
    }

    pub fn list_seed_hashes(&self, campaign: &str) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT hash FROM seeds WHERE campaign = ?1 ORDER BY found_at",
        )?;
        let rows = stmt.query_map([campaign], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn list_crashes(&self, campaign: &str, limit: u64) -> Result<Vec<CrashEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT stack_hash, input_hash, data, sanitizer_output, source_node, campaign, found_at
             FROM crashes WHERE campaign = ?1 ORDER BY found_at DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![campaign, limit as i64], |row| {
            let ts: i64 = row.get(6)?;
            Ok(CrashEntry {
                stack_hash: row.get(0)?,
                input_hash: row.get(1)?,
                data: row.get(2)?,
                sanitizer_output: row.get(3)?,
                source_node: row.get(4)?,
                campaign: row.get(5)?,
                found_at: chrono::DateTime::from_timestamp(ts, 0).unwrap_or_default(),
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn list_campaign_names(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT name FROM campaigns ORDER BY created_at")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }
}

impl crate::storage::Storage for Db {
    fn register_node(&self, info: &NodeInfo) -> Result<()> { self.register_node(info) }
    fn deregister_node(&self, node_id: &str) -> Result<()> { self.deregister_node(node_id) }
    fn update_node_status(&self, node_id: &str, status: NodeStatus) -> Result<()> { self.update_node_status(node_id, status) }
    fn mark_stale_offline(&self, timeout_secs: i64) -> Result<usize> { self.mark_stale_offline(timeout_secs) }
    fn store_seed(&self, seed: &Seed) -> Result<bool> { self.store_seed(seed) }
    fn delete_seed(&self, hash: &str, campaign: &str) -> Result<()> { self.delete_seed(hash, campaign) }
    fn node_campaign(&self, node_id: &str) -> Result<Option<String>> { self.node_campaign(node_id) }
    fn get_campaign(&self, name: &str) -> Result<Option<mycelium_common::protocol::CampaignInfo>> { self.get_campaign(name) }
    fn get_unseen_seeds(&self, node_id: &str, campaign: &str) -> Result<Vec<Seed>> { self.get_unseen_seeds(node_id, campaign) }
    fn mark_seed_sent(&self, seed_hash: &str, node_id: &str) -> Result<()> { self.mark_seed_sent(seed_hash, node_id) }
    fn store_crash(&self, crash: &CrashEntry) -> Result<bool> { self.store_crash(crash) }
    fn delete_crash(&self, input_hash: &str, campaign: &str) -> Result<()> { self.delete_crash(input_hash, campaign) }
    fn update_heartbeat(&self, node_id: &str, execs_per_sec: u64, corpus_size: u64, crashes_found: u64, edges_found: u64) -> Result<()> {
        self.update_heartbeat(node_id, execs_per_sec, corpus_size, crashes_found, edges_found)
    }
    fn list_nodes(&self, campaign: Option<&str>) -> Result<Vec<NodeInfo>> { self.list_nodes(campaign) }
    fn count_seeds(&self, campaign: &str) -> Result<u64> { self.count_seeds(campaign) }
    fn count_crashes(&self, campaign: &str) -> Result<u64> { self.count_crashes(campaign) }
    fn count_unique_bugs(&self, campaign: &str) -> Result<u64> { self.count_unique_bugs(campaign) }
    fn sum_execs_per_sec(&self, campaign: &str) -> Result<u64> { self.sum_execs_per_sec(campaign) }
    fn sum_edges(&self, campaign: &str) -> Result<u64> { self.sum_edges(campaign) }
    fn get_campaign_lifecycle(&self, name: &str) -> Result<Option<CampaignLifecycle>> { self.get_campaign_lifecycle(name) }
    fn create_campaign(&self, name: &str, fuzzer_name: &str, fuzzer_command: &[String], triage_cmd: Option<&[String]>) -> Result<()> {
        self.create_campaign(name, fuzzer_name, fuzzer_command, triage_cmd)
    }
    fn set_harness_len(&self, campaign: &str, len: u64) -> Result<()> { self.set_harness_len(campaign, len) }
    fn list_campaign_names(&self) -> Result<Vec<String>> { self.list_campaign_names() }
    fn snapshot_metrics(&self, campaign: &str) -> Result<()> { self.snapshot_metrics(campaign) }
    fn get_metrics(&self, campaign: &str, limit: u64) -> Result<Vec<MetricsSnapshot>> { self.get_metrics(campaign, limit) }
    fn list_seed_hashes(&self, campaign: &str) -> Result<Vec<String>> { self.list_seed_hashes(campaign) }
    fn list_crashes(&self, campaign: &str, limit: u64) -> Result<Vec<CrashEntry>> { self.list_crashes(campaign, limit) }
    fn update_campaign_lifecycle(&self, name: &str, lifecycle: CampaignLifecycle) -> Result<bool> {
        self.update_campaign_lifecycle(name, lifecycle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Db {
        Db::open_in_memory().unwrap()
    }

    fn test_node(id: &str) -> NodeInfo {
        NodeInfo {
            id: id.to_string(),
            hostname: "testhost".into(),
            campaign: "test-campaign".into(),
            fuzzer: "aflpp".into(),
            priority: Priority::Dedicated,
            status: NodeStatus::Online,
            time_limited: false,
            last_sync: chrono::Utc::now(),
        }
    }

    #[test]
    fn register_and_list() {
        let db = test_db();
        db.register_node(&test_node("node-1")).unwrap();
        db.register_node(&test_node("node-2")).unwrap();
        let nodes = db.list_nodes(Some("test-campaign")).unwrap();
        assert_eq!(nodes.len(), 2);
    }

    #[test]
    fn reaper_marks_stale_offline() {
        let db = test_db();
        db.register_node(&test_node("n1")).unwrap();
        // a fresh node is not stale under a normal timeout
        assert_eq!(db.mark_stale_offline(60).unwrap(), 0);
        // a cutoff in the future reaps every online node
        assert_eq!(db.mark_stale_offline(-1_000_000).unwrap(), 1);
        let nodes = db.list_nodes(None).unwrap();
        assert_eq!(nodes[0].status, NodeStatus::Unreachable);
        // already reaped, so a second pass does nothing
        assert_eq!(db.mark_stale_offline(-1_000_000).unwrap(), 0);
    }

    #[test]
    fn reregister_preserves_stats() {
        let db = test_db();
        db.register_node(&test_node("worker-7")).unwrap();
        db.update_heartbeat("worker-7", 90_000, 5000, 42, 0).unwrap();
        // a restart re-registers with the same id; stats must survive
        db.register_node(&test_node("worker-7")).unwrap();
        let n = db.sum_execs_per_sec("test-campaign").unwrap();
        assert_eq!(n, 90_000, "execs/sec reset on re-register");
    }

    #[test]
    fn heartbeat_does_not_resurrect_suspended() {
        let db = test_db();
        db.register_node(&test_node("drained")).unwrap();
        db.update_node_status("drained", NodeStatus::Suspended).unwrap();
        // a still-running drained node keeps heartbeating; it must stay suspended
        db.update_heartbeat("drained", 1000, 10, 0, 0).unwrap();
        let nodes = db.list_nodes(None).unwrap();
        assert_eq!(nodes[0].status, NodeStatus::Suspended);
    }

    #[test]
    fn same_seed_hash_distinct_campaigns() {
        let db = test_db();
        let mk = |campaign: &str| Seed {
            hash: "deadbeef".into(),
            data: b"same bytes".to_vec(),
            source_node: "n".into(),
            campaign: campaign.into(),
            found_at: chrono::Utc::now(),
        };
        // identical bytes in two campaigns must both store, not collide
        assert!(db.store_seed(&mk("camp-a")).unwrap());
        assert!(db.store_seed(&mk("camp-b")).unwrap());
        assert_eq!(db.count_seeds("camp-a").unwrap(), 1);
        assert_eq!(db.count_seeds("camp-b").unwrap(), 1);
    }

    #[test]
    fn deregister() {
        let db = test_db();
        db.register_node(&test_node("node-1")).unwrap();
        db.deregister_node("node-1").unwrap();
        let nodes = db.list_nodes(None).unwrap();
        assert_eq!(nodes.len(), 0);
    }

    #[test]
    fn seed_store_and_dedup() {
        let db = test_db();
        let seed = Seed {
            hash: "abc123".into(),
            data: b"test data".to_vec(),
            source_node: "node-1".into(),
            campaign: "test-campaign".into(),
            found_at: chrono::Utc::now(),
        };
        assert!(db.store_seed(&seed).unwrap());
        assert!(!db.store_seed(&seed).unwrap());
    }

    #[test]
    fn unseen_seeds() {
        let db = test_db();
        let seed = Seed {
            hash: "abc123".into(),
            data: b"test data".to_vec(),
            source_node: "node-1".into(),
            campaign: "camp".into(),
            found_at: chrono::Utc::now(),
        };
        db.store_seed(&seed).unwrap();

        let unseen = db.get_unseen_seeds("node-2", "camp").unwrap();
        assert_eq!(unseen.len(), 1);

        db.mark_seed_sent("abc123", "node-2").unwrap();
        let unseen = db.get_unseen_seeds("node-2", "camp").unwrap();
        assert_eq!(unseen.len(), 0);
    }

    #[test]
    fn crash_store_and_dedup() {
        let db = test_db();
        let crash = CrashEntry {
            stack_hash: "stack1".into(),
            input_hash: "input1".into(),
            data: b"crash input".to_vec(),
            sanitizer_output: "ASAN error".into(),
            source_node: "node-1".into(),
            campaign: "camp".into(),
            found_at: chrono::Utc::now(),
        };
        assert!(db.store_crash(&crash).unwrap());
        assert!(!db.store_crash(&crash).unwrap());
    }

    #[test]
    fn source_node_excluded_from_unseen() {
        let db = test_db();
        let seed = Seed {
            hash: "abc123".into(),
            data: b"test".to_vec(),
            source_node: "node-1".into(),
            campaign: "camp".into(),
            found_at: chrono::Utc::now(),
        };
        db.store_seed(&seed).unwrap();
        let unseen = db.get_unseen_seeds("node-1", "camp").unwrap();
        assert_eq!(unseen.len(), 0);
    }
}
