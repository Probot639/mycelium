use std::path::Path;

use anyhow::Result;
use rusqlite::Connection;

use mycelium_common::corpus::{CrashEntry, Seed};
use mycelium_common::node::{NodeInfo, NodeStatus, Priority};

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
                crashes_found INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS seeds (
                hash TEXT PRIMARY KEY,
                data BLOB NOT NULL,
                source_node TEXT NOT NULL,
                campaign TEXT NOT NULL,
                found_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS crashes (
                stack_hash TEXT NOT NULL,
                input_hash TEXT PRIMARY KEY,
                data BLOB NOT NULL,
                sanitizer_output TEXT NOT NULL,
                source_node TEXT NOT NULL,
                campaign TEXT NOT NULL,
                found_at INTEGER NOT NULL
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
                created_at INTEGER NOT NULL
            );",
        )?;
        Ok(())
    }

    pub fn register_node(&self, info: &NodeInfo) -> Result<()> {
        // serde_json wraps enum values in quotes ("shared"), trim them for sqlite
        self.conn.execute(
            "INSERT OR REPLACE INTO nodes (id, hostname, campaign, fuzzer, priority, status, last_sync)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (
                &info.id,
                &info.hostname,
                &info.campaign,
                &info.fuzzer,
                serde_json::to_string(&info.priority)?.trim_matches('"'),
                serde_json::to_string(&info.status)?.trim_matches('"'),
                info.last_sync.timestamp(),
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
    ) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "UPDATE nodes SET last_sync = ?1, execs_per_sec = ?2, corpus_size = ?3, crashes_found = ?4, status = 'online' WHERE id = ?5",
            (now, execs_per_sec, corpus_size, crashes_found, node_id),
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
                .prepare("SELECT id, hostname, campaign, fuzzer, priority, status, last_sync FROM nodes WHERE campaign = ?1")?;
            let rows = stmt.query_map([campaign], |row| {
                Ok(Self::node_from_row(row))
            })?;
            for row in rows {
                nodes.push(row??);
            }
        } else {
            let mut stmt = self
                .conn
                .prepare("SELECT id, hostname, campaign, fuzzer, priority, status, last_sync FROM nodes")?;
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
        Ok(NodeInfo {
            id: row.get(0)?,
            hostname: row.get(1)?,
            campaign: row.get(2)?,
            fuzzer: row.get(3)?,
            priority: serde_json::from_str(&format!("\"{priority_str}\""))
                .unwrap_or(Priority::Shared),
            status: serde_json::from_str(&format!("\"{status_str}\""))
                .unwrap_or(NodeStatus::Offline),
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

    pub fn mark_seed_sent(&self, seed_hash: &str, node_id: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO seed_distribution (seed_hash, node_id) VALUES (?1, ?2)",
            [seed_hash, node_id],
        )?;
        Ok(())
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

    pub fn create_campaign(
        &self,
        name: &str,
        fuzzer_name: &str,
        fuzzer_command: &[String],
    ) -> Result<()> {
        let cmd_json = serde_json::to_string(fuzzer_command)?;
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "INSERT INTO campaigns (name, fuzzer_name, fuzzer_command, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            (name, fuzzer_name, &cmd_json, now),
        )?;
        Ok(())
    }

    pub fn get_campaign(&self, name: &str) -> Result<Option<mycelium_common::protocol::CampaignInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, fuzzer_name, fuzzer_command, harness_len, created_at FROM campaigns WHERE name = ?1",
        )?;
        let mut rows = stmt.query_map([name], |row| {
            let cmd_json: String = row.get(2)?;
            let harness_len: i64 = row.get(3)?;
            Ok(mycelium_common::protocol::CampaignInfo {
                name: row.get(0)?,
                fuzzer_name: row.get(1)?,
                fuzzer_command: serde_json::from_str(&cmd_json).unwrap_or_default(),
                harness_len: harness_len as u64,
                created_at: row.get(4)?,
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
