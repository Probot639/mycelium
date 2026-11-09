# CLI reference

The binary is `mycelium`. It has six subcommands: `spawn` starts the coordinator, `inoculate` creates a campaign, `join` attaches a fuzzing node, `probe` shows status, `sever` detaches a node, and `ping` checks fleet connectivity.

Wherever a command takes `--coordinator`, you can pass either a bare `host:port` (like `sigil:7100`) or a full `http://...` URL. A bare value gets `http://` prefixed for you.

## spawn

Start the coordinator. This is the one long-running server process.

```
mycelium spawn --corpus /data/corpus --db /data/mycelium.db
```

| Flag | Default | Description |
|---|---|---|
| `--listen` | `0.0.0.0:7100` | Address and port to bind. |
| `--corpus` | required | Directory for stored seeds, crashes, and harness binaries. Created if missing, along with its `blobs`, `crashes`, and `harnesses` subdirectories. |
| `--db` | required | Path to the SQLite database file. Created if missing. |

The coordinator serves the HTTP API and the web dashboard on the listen address. Point a browser at it to see the dashboard, or see [http-api.md](http-api.md) to build against it.

## inoculate

Upload a harness and create a campaign. Run this once per campaign against a running coordinator. It does two things back to back: creates the campaign record with your fuzzer command template, then uploads the harness binary.

```
mycelium inoculate --coordinator sigil:7100 \
  --campaign fuzz-libpng \
  --harness ./fuzz_png \
  --fuzzer aflpp \
  -- afl-fuzz -i {corpus} -o {output} -M main -F {inject} -- {harness}
```

| Flag | Default | Description |
|---|---|---|
| `--coordinator` | required | Coordinator address. |
| `--campaign` | required | Campaign name. Nodes join by this name. |
| `--harness` | required | Path to the harness binary to upload and distribute. |
| `--fuzzer` | `aflpp` | Fuzzer identifier stored with the campaign and shown in status. Also selects the fuzzer profile. |
| `--seeds` | none | Directory of starting seeds, uploaded as the campaign's base corpus so joining nodes begin from real inputs instead of an empty corpus. |
| `--triage-cmd` | none | Command to re-run a crashing input for dedup. `{file}` is replaced with the crash path. Point it at an ASAN build of the target. Without it, crashes are deduped per input, not per bug. See [configuration.md](configuration.md#crash-triage-and-dedup). |
| `-- <cmd>...` | required | The fuzzer command template, everything after `--`. |

### The command template

Everything after the `--` is the command each node runs, with four placeholders the node fills in with its own local paths:

| Placeholder | Expands to |
|---|---|
| `{harness}` | The downloaded harness binary. |
| `{corpus}` | The seed directory, the AFL++ `-i` input dir, read once at startup. |
| `{output}` | The fuzzer's output tree. |
| `{inject}` | The AFL++ `-F` foreign-corpus dir, imported while the fuzzer runs. |

For AFL++ the command has to run a main instance and import the inject directory, so that seeds pulled from the coordinator reach the running fuzzer:

```
afl-fuzz -i {corpus} -o {output} -M main -F {inject} -- {harness}
```

If the command has no `{inject}` placeholder, a joining node still starts, but it logs a warning that pulled seeds will not reach the fuzzer, because there is no foreign-corpus dir for them to land in.

Where a non-AFL fuzzer writes its new corpus and crashes decides which dirs the node watches, so point the command at the right places. The node watches `{output}` for new corpus for fuzzers that write there (honggfuzz, libafl, go, syzkaller) and `{corpus}` for libFuzzer, which appends new units to its positional corpus dir. It watches `{output}/crashes` for crashes in every case, so send crashes there:

```
# libFuzzer: new units in {corpus}, crashes via -artifact_prefix into {output}/crashes
{harness} {corpus} -artifact_prefix={output}/crashes/ -max_total_time=0

# honggfuzz: -o is the output corpus, --crashdir keeps crashes separate
honggfuzz -i {corpus} -o {output} --crashdir {output}/crashes -- {harness}
```

In distributed mode the node also tees the fuzzer's stdout and stderr to `{output}/mycelium-fuzzer.log` and reads throughput from it with the fuzzer's own stats parser, since a distributed node has no stats file to point at. libFuzzer prints a rate on every progress line; honggfuzz only prints a parseable summary when it exits, so a persistent honggfuzz node reports throughput only at the end of its run.

## join

Attach a node to a campaign and start fuzzing. There are two modes, picked by which of `--workdir` or `--config` you pass. Pass exactly one. Passing neither is an error.

Distributed mode, the node pulls the harness and command from the coordinator:

```
mycelium join --coordinator sigil:7100 --campaign fuzz-libpng --workdir /tmp/fuzz
```

Manual mode, the node reads a local config file:

```
mycelium join --coordinator sigil:7100 --campaign fuzz-libpng --config node.toml
```

| Flag | Default | Description |
|---|---|---|
| `--coordinator` | required | Coordinator address. |
| `--campaign` | `default` | Campaign to join. |
| `--config` | none | Local config file. Selects manual mode. See [configuration.md](configuration.md). |
| `--workdir` | none | Working directory for the downloaded harness and fuzzer output. Selects distributed mode. |
| `--priority` | `shared` | `dedicated`, `shared`, or `idle`. Scales how often this node pulls shared corpus. |

In distributed mode the node creates `seeds`, `inject`, and `output` directories under the workdir, downloads the harness into it, registers, and runs the fuzzer in `persistent` mode with the stats parser the campaign's fuzzer profile implies (so a honggfuzz campaign parses honggfuzz output, not AFL's). The node's hostname (read from `/etc/hostname`) is sent at registration and the coordinator hands back the generated node ID.

In manual mode the `mode`, `stats_parser`, and `sync_interval` come from the config file instead. The `--priority` flag on the command line and the `priority` key in the config both feed the same setting. In manual mode the config value is the one used.

### Priority and pull cadence

Priority scales the pull interval. `shared` uses the configured interval as written. `dedicated` pulls twice as often, for your primary fuzzing boxes that you want kept tightly in sync. `idle` pulls half as often, to stay out of the way on a borrowed machine. The interval never drops below one second.

## probe

Show campaign status. Reads `GET /scry` and prints it.

```
mycelium probe --coordinator sigil:7100 --nodes
```

```
Campaign: fuzz-libpng
  corpus: 1423  crashes: 7  nodes: 4

NODE             HOST         FUZZER       PRIORITY   STATUS       LAST SYNC
sigil-a1f2       sigil        aflpp        dedicated  online       14:32:07
songbird-b3e4    songbird     aflpp        shared     online       14:32:05
glyph1-c5d6      glyph-1      aflpp        shared     online       14:31:58
```

| Flag | Default | Description |
|---|---|---|
| `--coordinator` | required | Coordinator address. |
| `--nodes` | off | Show the per-node table. The table also prints whenever there are nodes to show. |
| `--json` | off | Print the raw `ScryResponse` JSON instead of the formatted view. Use this for automation. |

The JSON form is the full `/scry` payload, documented in [http-api.md](http-api.md).

## sever

Detach a node.

```
mycelium sever --coordinator sigil:7100 --node-id sigil-a1f2 --drain
```

| Flag | Default | Description |
|---|---|---|
| `--coordinator` | required | Coordinator address. |
| `--node-id` | required | The node ID to detach, as shown by `probe`. |
| `--drain` | off | Graceful detach: suspend the node and keep its corpus, crashes, and distribution history. Without it, the node and its history are removed outright. |

The node ID is the `hostname-xxxx` value the coordinator assigned at join, not the hostname on its own.

## ping

TCP-ping fleet nodes until all respond. No coordinator needed. Useful for checking that SSH (or any port) is reachable across the fleet before starting a campaign.

```
mycelium ping sigil songbird glyph-1
```

Probes port 22 on each host, prints round-trip times, and loops until every node responds. To check a different port (for example, the coordinator):

```
mycelium ping sigil --port 7100
```

| Flag | Default | Description |
|---|---|---|
| `<nodes>...` | required | One or more hostnames or IPs to probe. |
| `--port` | `22` | TCP port to connect to on each node. |
| `--interval` | `3` | Seconds between retry rounds when nodes are unreachable. |
