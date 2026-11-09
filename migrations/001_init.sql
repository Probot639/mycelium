-- Mycelium coordinator Postgres schema.
-- Mirrors the SQLite schema in db.rs but uses Postgres types and adds
-- time-series partitioning on the metrics table.

CREATE TABLE IF NOT EXISTS nodes (
    id          TEXT PRIMARY KEY,
    hostname    TEXT NOT NULL,
    campaign    TEXT NOT NULL,
    fuzzer      TEXT NOT NULL,
    priority    TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'online',
    last_sync   BIGINT NOT NULL,
    execs_per_sec BIGINT NOT NULL DEFAULT 0,
    corpus_size BIGINT NOT NULL DEFAULT 0,
    crashes_found BIGINT NOT NULL DEFAULT 0,
    edges_found BIGINT NOT NULL DEFAULT 0,
    time_limited BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_nodes_campaign ON nodes(campaign);
CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status);

CREATE TABLE IF NOT EXISTS seeds (
    hash        TEXT NOT NULL,
    data        BYTEA NOT NULL,
    source_node TEXT NOT NULL,
    campaign    TEXT NOT NULL,
    found_at    BIGINT NOT NULL,
    PRIMARY KEY (hash, campaign)
);

CREATE INDEX IF NOT EXISTS idx_seeds_campaign ON seeds(campaign);

CREATE TABLE IF NOT EXISTS crashes (
    stack_hash       TEXT NOT NULL,
    input_hash       TEXT NOT NULL,
    data             BYTEA NOT NULL,
    sanitizer_output TEXT NOT NULL,
    source_node      TEXT NOT NULL,
    campaign         TEXT NOT NULL,
    found_at         BIGINT NOT NULL,
    PRIMARY KEY (input_hash, campaign)
);

CREATE INDEX IF NOT EXISTS idx_crashes_campaign ON crashes(campaign);
CREATE INDEX IF NOT EXISTS idx_crashes_stack ON crashes(stack_hash, campaign);

CREATE TABLE IF NOT EXISTS seed_distribution (
    seed_hash TEXT NOT NULL,
    node_id   TEXT NOT NULL,
    PRIMARY KEY (seed_hash, node_id)
);

CREATE TABLE IF NOT EXISTS campaigns (
    name           TEXT PRIMARY KEY,
    fuzzer_name    TEXT NOT NULL,
    fuzzer_command JSONB NOT NULL,
    triage_cmd     JSONB,
    harness_len    BIGINT NOT NULL DEFAULT 0,
    created_at     BIGINT NOT NULL,
    lifecycle      TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS metrics (
    campaign         TEXT NOT NULL,
    ts               BIGINT NOT NULL,
    total_execs_per_sec BIGINT NOT NULL DEFAULT 0,
    corpus_size      BIGINT NOT NULL DEFAULT 0,
    crashes          BIGINT NOT NULL DEFAULT 0,
    unique_bugs      BIGINT NOT NULL DEFAULT 0,
    edges            BIGINT NOT NULL DEFAULT 0,
    nodes_online     BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (campaign, ts)
);

CREATE INDEX IF NOT EXISTS idx_metrics_ts ON metrics(campaign, ts DESC);
