# Architecture

mycelium is a coordinator process plus any number of fuzzing nodes. The coordinator owns the shared corpus and the crash set. Each node runs a fuzzer locally and talks to the coordinator over HTTP. There is no message queue, no consensus layer, and no second service to stand up. The coordinator is one process backed by a SQLite database and a corpus directory on disk.

Everything the coordinator stores is durable: the corpus, the crashes, the harness binaries, and the node table all survive a restart because they live in SQLite and on the filesystem, not in memory.

## The crates

The workspace has four crates.

### mycelium-common

Shared types used by both sides of the wire. If a struct crosses the network, it is defined here.

- `protocol.rs` holds the request and response types for every endpoint. These derive `Serialize` and `Deserialize`, so the JSON shapes in [http-api.md](http-api.md) come straight from these definitions.
- `corpus.rs` holds `Seed` and `CrashEntry`, plus `hash_bytes`, the SHA-256 helper that gives every seed its content address.
- `node.rs` holds `NodeInfo`, the `Priority` enum (`dedicated`, `shared`, `idle`), and the `NodeStatus` enum (`online`, `unreachable`, `offline`, `suspended`). Both enums serialize as lowercase strings.
- `stats.rs` parses a fuzzer's stats file into a `FuzzerStats` struct (execs per second, total execs, corpus size, crashes, hangs, edges).

### mycelium-coordinator

The HTTP server and its storage. Built on axum.

- `server.rs` binds the listener and wires every route to its handler. This is the one place that lists all the endpoints.
- `routes.rs` has one handler per endpoint. Handlers are thin: they validate the request, call into state, and map the result to a status code.
- `state.rs` is `CoordinatorState`, the layer between the handlers and the database. It owns the `Db` behind a `Mutex` and owns the corpus directory. When a seed or crash is new, state writes the raw bytes to disk here, not just the row to SQLite.
- `db.rs` is the SQLite layer. Every table and query lives here.

The coordinator also serves a built-in web dashboard. `GET /` and `GET /ui` both return a single static HTML page that polls `GET /scry` every three seconds and draws the result. The dashboard is a plain client of the API, so anything it shows, an external frontend can get the same way.

### mycelium-node

The node side: run a fuzzer, watch its output, sync with the coordinator.

- `config.rs` parses the `node.toml` file used in manual mode. See [configuration.md](configuration.md).
- `sync.rs` is `SyncClient`, the HTTP client that talks to the coordinator. Every call a node makes (register, push seed, pull seeds, report crash, heartbeat, deregister) goes through here, along with the campaign and harness calls that `inoculate` uses.
- `watcher.rs` is `DirWatcher`, the filesystem watcher over the fuzzer's queue and crash directories.

### mycelium-cli

The `mycelium` binary. `main.rs` defines the clap subcommands and holds the node run loop (`run_fuzzer_loop`) that ties the watcher, the sync client, and the fuzzer process together. See [cli.md](cli.md) for the command surface.

## The sync loop

This is the heart of a node. It lives in `run_fuzzer_loop` in the CLI crate and runs the same way in both join modes, with the differences coming from how the directories get resolved.

Startup goes like this. The node pulls the current corpus from the coordinator into the fuzzer's seed directory (the `-i` dir in AFL++ terms) so the fuzzer has something to start from. If the campaign is brand new and there is nothing to pull, a distributed-mode node drops a one-byte starter seed so AFL++ does not refuse to launch on an empty input dir. Then, unless the node is in `api` mode, it spawns the fuzzer process.

Once the fuzzer is running, the node resolves the directories it actually writes to. Manual mode knows them from the config. Distributed mode only learns the AFL++ instance subdirectory name after the fuzzer starts (it could be `default`, `main`, or whatever `-M` was given), so it probes the output tree until a `queue` directory appears, then watches that instance's `queue` and `crashes`.

After that the node runs a select loop over three things:

- A watcher event. A new queue entry becomes a seed push. A new crash file becomes a crash report.
- A timer tick. On each tick the node pulls any seeds it has not seen yet and drops them into the inject directory (the AFL++ `-F` foreign-corpus dir), so the running fuzzer imports them without a restart. The node also reads the fuzzer's stats file, parses it, and sends a heartbeat with the current execs per second, corpus size, and crash count.
- The fuzzer process exiting. What happens next depends on the mode (see below).

### Pull cadence and priority

The timer interval is derived from the configured `sync_interval` and the node's `priority`. A `shared` node uses the interval as written. A `dedicated` node pulls twice as often (interval divided by two). An `idle` node pulls half as often (interval times two). There is a one-second floor, which also keeps a `0s` config from panicking the timer. The function is `effective_interval_secs` in the CLI crate.

### Fuzzer modes

The `mode` setting changes what the loop does when the fuzzer exits.

- `persistent` is the default. The fuzzer runs until it exits, and when it does, the node drains any last output and stops.
- `round` is for fuzzers that exit once per round. On exit, the node pulls fresh corpus into the seed directory and relaunches the fuzzer for the next round.
- `api` means mycelium never launches a fuzzer at all. It only watches the output directories you point it at and syncs them, for a fuzzer that something else is running.

In distributed mode the node always runs `persistent` with the `aflpp` stats parser. The `mode` and `stats_parser` settings only take effect in manual mode, where the config file sets them.

## The watcher

`DirWatcher` uses inotify (via the `notify` crate) on the corpus and crash directories. It handles two problems that come up when you watch a real fuzzer's output.

First, deduplication. notify fires both Create and Modify events for the rename-into-queue pattern AFL++ uses, so the same file can surface more than once. The watcher hashes every file it sees and keeps a set of hashes it has already handled, so a file is only ever pushed once. The same set is seeded with the hashes of the initial corpus and with every hash the node pulls, so a node never pushes back a seed it was just handed.

Second, metadata. AFL++ writes bookkeeping into the same directories as the real test cases: a `.state` subdirectory under `queue`, a `README.txt` in `crashes`, and flat files like `fuzzer_stats`, `fuzzer_setup`, `plot_data`, and `cmdline`. The watcher skips all of those, along with any dotfile and any empty file, so only genuine inputs get pushed.

On startup the watcher scans the directories for files that already exist before it starts listening for new events, so a restart does not miss anything.

## The SQLite schema

The coordinator creates five tables on startup (`init_tables` in `db.rs`). All timestamps are stored as integer Unix seconds.

### nodes

One row per registered node. The primary key is `id`, the coordinator-assigned node ID (hostname plus four hex characters). Columns: `id`, `hostname`, `campaign`, `fuzzer`, `priority`, `status`, `last_sync`, and the three live counters `execs_per_sec`, `corpus_size`, and `crashes_found` that the heartbeat updates. `priority` and `status` are stored as their lowercase string names.

### seeds

The shared corpus. The primary key is `hash`, the SHA-256 of the seed contents, so a seed is stored once no matter how many nodes find it. Columns: `hash`, `data` (the raw bytes as a BLOB), `source_node`, `campaign`, and `found_at`. Inserts use `INSERT OR IGNORE`, and the insert reports whether the row was actually new, which is how the coordinator knows when to write the blob to disk.

### crashes

The crash set. The primary key is `input_hash`, the SHA-256 of the crashing input, so one input is stored once. Columns: `stack_hash`, `input_hash`, `data`, `sanitizer_output`, `source_node`, `campaign`, and `found_at`. The `stack_hash` is the dedup-by-bug key from the sanitizer output and is stored alongside the input, not used as the primary key.

### seed_distribution

The record of which seed has gone to which node. The primary key is the pair `(seed_hash, node_id)`. When a node pulls, the coordinator selects seeds for that node's campaign that did not come from that node and are not already in this table for it, then marks each returned seed as sent by inserting a row here. That is how a node never gets the same seed twice and never gets its own seeds back.

### campaigns

One row per campaign, created by `inoculate`. The primary key is `name`. Columns: `name`, `fuzzer_name`, `fuzzer_command` (the command template, stored as a JSON array string), `harness_len` (the size of the uploaded harness in bytes, zero until a harness is uploaded), and `created_at`.

## The corpus directory on disk

Alongside SQLite, the coordinator keeps raw bytes under the `--corpus` directory, created on startup:

- `blobs/<hash>` is the raw bytes of each seed, written when the seed is first ingested.
- `crashes/<stack_hash>/input.bin` and `crashes/<stack_hash>/trace.txt` hold the crashing input and the sanitizer output for each new crash.
- `harnesses/<campaign>` is the uploaded harness binary for a campaign, stored executable.

The node also keeps local directories, either the `seeds`, `inject`, and `output` dirs it creates under `--workdir` in distributed mode, or the directories named in the config file in manual mode.
