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

### Distributed mode (harness distribution)

Start the coordinator:

```
mycelium spawn --corpus /data/corpus --db /data/mycelium.db
```

Upload a harness and create a campaign. The coordinator stores the binary and distributes it to every node that joins.

```
mycelium inoculate --coordinator sigil:7100 \
  --campaign fuzz-libpng \
  --harness ./fuzz_png \
  --fuzzer aflpp \
  -- afl-fuzz -i {corpus} -o {output} -- {harness}
```

`{harness}`, `{corpus}`, and `{output}` are placeholders. Each node fills them in with local paths.

On each fuzzing node, join the campaign. The node downloads the harness, creates working directories, and starts the fuzzer:

```
mycelium join --coordinator sigil:7100 --campaign fuzz-libpng --workdir /tmp/fuzz
```

That's it. Add more nodes the same way. The coordinator handles corpus sync and crash dedup across all of them.

### Manual mode (local config)

If you already have the harness on each machine, you can skip `inoculate` and pass a config file directly:

```
mycelium join --coordinator sigil:7100 --config node.toml --campaign my-campaign
```

The config file specifies the fuzzer command, directories, and sync settings. See the config reference below.

### Monitoring

Check on a running campaign:

```
mycelium probe --coordinator sigil:7100 --nodes
```

```
Campaign: fuzz-libpng
  corpus: 1423  crashes: 7  nodes: 4

NODE             HOST         FUZZER       STATUS       LAST SYNC
sigil-a1f2       sigil        aflpp        online       14:32:07
songbird-b3e4    songbird     aflpp        online       14:32:05
glyph-c5d6       glyph        aflpp        online       14:31:58
tarot-d7e8       tarot        aflpp        online       14:32:01
```

For machine-readable output (useful for automation):

```
mycelium probe --coordinator sigil:7100 --json
```

Detach a node:

```
mycelium sever --coordinator sigil:7100 --node-id sigil-a1f2 --drain
```

## How it works

Campaigns are created with `inoculate`, which uploads the harness binary and fuzzer command to the coordinator. Nodes that `join` a campaign pull the harness automatically, so you never need to copy binaries around.

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

### Manual mode config file

Only needed when using `join --config`. In distributed mode (`join --workdir`), the coordinator provides the fuzzer command and the node creates directories automatically.

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

### Command template placeholders

Used in the `inoculate` fuzzer command:

| Placeholder | Expanded to |
|---|---|
| `{harness}` | Path to the downloaded harness binary |
| `{corpus}` | Input corpus directory |
| `{output}` | Fuzzer output directory |

## License

MIT
