# Configuration reference

This is the `node.toml` file for manual mode, the file you pass with `mycelium join --config node.toml`. It describes a fuzzer that is already set up on the box: where its binary runs, where it writes, and how the node should sync.

You only need this file in manual mode. In distributed mode (`join --workdir`) the coordinator supplies the fuzzer command, the node creates its own directories, and there is no config file to write.

The file has three tables: `[node]`, `[fuzzer]`, and `[circle]`.

## `[node]`

| Key | Default | Description |
|---|---|---|
| `coordinator` | required | Coordinator address, `host:port` or a full URL. |
| `priority` | `shared` | `dedicated`, `shared`, or `idle`. Scales how often this node pulls shared corpus. |

## `[fuzzer]`

| Key | Default | Description |
|---|---|---|
| `name` | required | Fuzzer identifier, which also selects the fuzzer profile (see below). `aflpp`, `libfuzzer`, `honggfuzz`, `libafl`, `go`, `syzkaller`, and the libFuzzer front ends `cargo-fuzz`, `atheris`, `jazzer`. An unknown name falls back to the AFL++ profile. Shown in `probe` output. |
| `command` | required | The command and arguments that start the fuzzer, as a TOML array of strings. |
| `corpus_dir` | required | The directory the fuzzer writes new queue entries into. The node watches this and pushes new seeds up. |
| `crash_dir` | required | The directory the fuzzer writes crashes into. The node watches this and reports new crashes. For libFuzzer this is the same path as `corpus_dir`, and crashes are told apart by filename. |
| `stats_file` | none | Path to the fuzzer's stats file. The node reads it each tick to fill in the heartbeat. With no stats file, heartbeats still go out with zeroed counters. |
| `triage_cmd` | none | Command run on a crashing input to capture a sanitizer trace, with `{file}` replaced by the input path. Point it at an ASAN build of the target (for libFuzzer the fuzzer binary itself works). The trace drives the per-bug stack hash. With none set, crashes are reported without a trace and deduped per input, not per bug. |

In manual mode the paths and the command are used as written. The `{corpus}`, `{output}`, and `{inject}` placeholders are a distributed-mode feature, so in a config file you give real paths, not placeholders.

### Fuzzer profiles

The `name` picks a profile that tells the node how to read the fuzzer's output: which files are new corpus, which are crashes, and which are bookkeeping to skip.

- `aflpp` expects AFL++'s layout: new corpus under a `queue` dir, crashes under a `crashes` dir, and it skips `README.txt`, `fuzzer_stats`, the `.state` dir, and the other AFL metadata.
- `libfuzzer` (and `cargo-fuzz`, `atheris`, `jazzer`, which are libFuzzer underneath) uses one dir for both corpus and artifacts, and tells crashes apart by the `crash-`, `oom-`, `timeout-`, `leak-`, and `slow-unit-` filename prefixes.
- `honggfuzz` reads new corpus from the input dir and crashes from the crash dir, skipping `HONGGFUZZ.REPORT.TXT`.
- `libafl` and `go` use the corpus dir for seeds and the crash dir for crashes.
- `syzkaller` treats the `repro*.prog` and `repro*.cprog` files under the crash dir as the crash reproducers and skips the surrounding metadata (`description`, `log*`, `report*`). Its corpus lives in a single `corpus.db`, not watchable files, so corpus sync for a syzkaller node goes through the hooks rather than the watcher.

The profile also sets the default `stats_parser`, so `name = "libfuzzer"` parses libFuzzer stats without you setting anything else.

### Custom fuzzers: `[fuzzer.hooks]`

A fuzzer that cannot be driven by watching directories uses two optional hooks. With neither set, the node drops pulled seeds into `inject_dir` and reads stats from `stats_file`, which is what the built-in profiles do.

| Key | Description |
|---|---|
| `import_cmd` | Run once per pulled seed to hand it to the fuzzer. The token `{file}` is replaced with the seed's path. Use for a fuzzer that takes new inputs through its own API or socket. |
| `stats_cmd` | Run each sync tick; its stdout is parsed by `stats_parser`. Use for a fuzzer that reports progress to a command rather than a stats file. |

```toml
[fuzzer]
name = "libfuzzer"
command = ["./my_fuzzer", "corpus/"]
corpus_dir = "corpus"
crash_dir = "corpus"

[fuzzer.hooks]
import_cmd = ["my-fuzzer-ctl", "add-seed", "{file}"]
stats_cmd = ["my-fuzzer-ctl", "stats"]
```

## `[circle]`

| Key | Default | Description |
|---|---|---|
| `sync_interval` | `30s` | How often the node pulls shared corpus. Accepts a seconds value like `30s` or a minutes value like `2m`. A bare number is read as seconds. |
| `inject_dir` | required | The directory the node drops pulled seeds into for the fuzzer to import. For AFL++ this is the `-F` foreign-corpus dir. |
| `stats_parser` | profile default | Which parser reads the stats. `aflpp` or `libfuzzer`. Defaults to the one the `[fuzzer] name` profile implies, so you only set this to override. |
| `mode` | `persistent` | How the node treats the fuzzer process: `persistent`, `round`, or `api`. |

### sync_interval and priority

The interval here is the baseline. The node's `priority` scales it: `shared` uses it as written, `dedicated` pulls twice as often, and `idle` pulls half as often. The effective interval never drops below one second, so a `0s` value becomes one second rather than a tight spin.

### mode

- `persistent` runs the fuzzer until it exits. This is the normal AFL++ case.
- `round` is for a fuzzer that exits once per round. When it exits, the node pulls fresh corpus into the seed directory and relaunches it.
- `api` tells the node not to launch a fuzzer at all. It only watches the directories you named and syncs them, for a fuzzer that something else is running.

### stats_parser

Selects the format of the stats file so the heartbeat counters are read correctly. `aflpp` parses an AFL++ `fuzzer_stats` file. `libfuzzer` parses libFuzzer output. If the stats file format and the parser do not match, the counters just come back as zero, which does not stop the node from fuzzing or syncing.

## Complete example

A manual-mode config for an AFL++ node whose fuzzer is already installed and whose target binary lives at `/work/target`:

```toml
[node]
coordinator = "sigil:7100"
priority = "dedicated"

[fuzzer]
name = "aflpp"
# the fuzzer this node runs, as literal paths (no placeholders in manual mode)
command = ["afl-fuzz", "-i", "/work/corpus", "-o", "/work/output", "-M", "main", "-F", "/work/inject", "--", "/work/target"]
# AFL++ writes queue entries and crashes under the instance dir named by -M
corpus_dir = "/work/output/main/queue"
crash_dir = "/work/output/main/crashes"
stats_file = "/work/output/main/fuzzer_stats"

[circle]
sync_interval = "30s"
# pulled seeds land here, the same -F dir as the command above
inject_dir = "/work/inject"
stats_parser = "aflpp"
mode = "persistent"
```

Two things to keep straight. The `-M main` instance makes AFL++ write under `/work/output/main`, so `corpus_dir`, `crash_dir`, and `stats_file` all point into `main`, not `default`. And `inject_dir` has to be the same path as the `-F` argument, so that the seeds the node pulls are the seeds AFL++ imports.

## Crash triage and dedup

Without `triage_cmd` a crash is reported with no trace, so the coordinator can only dedup by input: every distinct crashing input is its own entry. With `triage_cmd` set, the node re-runs each crashing input to capture a sanitizer trace, reduces it to a signature (the error class plus the top stack frames, with addresses dropped), and hashes that. Inputs that hit the same bug share a stack hash, so the coordinator groups them.

On disk the coordinator keeps `crashes/<stack_hash>/<input_hash>.bin` and a matching `.txt` trace, so every reproducer of a bug survives under that bug's directory. `probe` and the dashboard show both numbers: `crashes` is the count of distinct inputs, and `bugs` is the count of distinct stack hashes. A healthy triaged campaign shows far fewer bugs than crashes.

For an AFL++ node, point `triage_cmd` at an ASAN-instrumented standalone build of the target that takes the input as a file argument. For a libFuzzer node, the fuzzer binary itself reproduces a single input and prints the trace, so `triage_cmd = ["./harness", "{file}"]`.
