# mycelium

Universal harness for distributed fuzzing.

You write one AFL++ harness (or Honggfuzz, or whatever), mycelium runs it on N boxes and keeps the corpus in sync. Each instance thinks it's running locally.

The coordinator collects seeds and crashes from all nodes. When one node finds a new path, every other node gets the input within the sync interval. Crashes are deduplicated by stack hash so you don't triage the same bug twelve times.

Still early. Works on a tailnet, k3s manifests stubbed out for when there are more boxes.

## Build

```
cargo build --release
```

Binary lands at `target/release/mycelium`.

## Usage

Start the coordinator on one machine:

```
mycelium spawn --corpus /data/corpus --db /data/mycelium.db
```

Listens on `0.0.0.0:7100` by default.

On each fuzzing node, write a config file:

```toml
[node]
coordinator = "coordinator-hostname:7100"
priority = "shared"

[fuzzer]
name = "aflpp"
command = ["afl-fuzz", "-i", "/work/corpus", "-o", "/work/output", "--", "./target_binary"]
corpus_dir = "/work/output/default/queue"
crash_dir = "/work/output/default/crashes"
stats_file = "/work/output/default/fuzzer_stats"

[circle]
sync_interval = "30s"
inject_dir = "/work/corpus"
```

Then join the network:

```
mycelium join --coordinator coordinator-hostname:7100 --config node.toml
```

This registers with the coordinator, pulls any existing corpus, starts the fuzzer, and begins syncing. Seeds and crashes flow both ways until the fuzzer exits or you kill the process.

Check on a running campaign:

```
mycelium probe --coordinator coordinator-hostname:7100 --nodes
```

```
Campaign: default
  corpus: 1423  crashes: 7  nodes: 4

NODE             HOST         FUZZER       STATUS       LAST SYNC
sigil-a1f2       sigil        aflpp        online       14:32:07
songbird-b3e4    songbird     aflpp        online       14:32:05
glyph-c5d6       glyph        aflpp        online       14:31:58
tarot-d7e8       tarot        aflpp        online       14:32:01
```

Detach a node:

```
mycelium sever --coordinator coordinator-hostname:7100 --node-id sigil-a1f2 --drain
```

## How it works

Each node runs a filesystem watcher (inotify) on the fuzzer's corpus and crash directories. When AFL++ writes a new queue entry, the node hashes it and pushes it to the coordinator. On a timer (default 30s), the node pulls seeds it hasn't seen from the coordinator and drops them into the fuzzer's input directory.

Corpus dedup is content-addressed (SHA-256). Crash dedup is by stack hash (first 3 lines of sanitizer output). The coordinator tracks which seeds each node has already received so it doesn't re-send them.

The coordinator is a single process with a SQLite database. No external dependencies, no message queue, no consensus protocol. HTTP over whatever network you have. Designed for a tailnet but works anywhere the nodes can reach port 7100.

## Project layout

```
crates/
  mycelium-common/       shared types, corpus hashing, stats parsing
  mycelium-coordinator/  HTTP coordinator, SQLite storage
  mycelium-node/         filesystem watcher, sync client, config
  mycelium-cli/          binary, subcommands
deploy/
  k3s/                   PoC kubernetes manifests (untested)
```

## Config reference

### `[node]`

| Key | Default | Description |
|---|---|---|
| `coordinator` | required | Host:port of the coordinator |
| `priority` | `shared` | `dedicated`, `shared`, or `idle` |

### `[fuzzer]`

| Key | Default | Description |
|---|---|---|
| `name` | required | Fuzzer identifier (e.g. `aflpp`) |
| `command` | required | Command and args to start the fuzzer |
| `corpus_dir` | required | Where the fuzzer writes new queue entries |
| `crash_dir` | required | Where the fuzzer writes crashes |
| `stats_file` | none | Path to fuzzer_stats for heartbeat reporting |

### `[circle]`

| Key | Default | Description |
|---|---|---|
| `sync_interval` | `30s` | How often to pull seeds (e.g. `30s`, `2m`) |
| `inject_dir` | required | Where to drop seeds for the fuzzer to pick up |
| `stats_parser` | `aflpp` | Stats file format |
| `mode` | `persistent` | Fuzzer mode: `persistent`, `round`, or `api` |

## License

MIT
