# HTTP API

Every interaction with the coordinator is an HTTP call. The nodes use this API, the CLI uses it, and the built-in dashboard uses it. If you want to build your own frontend or automation, this is the contract.

All request and response bodies are JSON unless noted, and the field names below are exactly the wire names (they come straight from the `Serialize`/`Deserialize` structs in `mycelium-common/src/protocol.rs`). The default listen address is `0.0.0.0:7100`.

Two conventions worth knowing before the endpoint list:

- Binary payloads (`data` on a seed or a crash) are JSON arrays of byte values, zero to 255, because they are Rust `Vec<u8>`. They are not base64.
- Timestamps (`found_at`, `last_sync`, `created_at`) are integer Unix seconds.

## Authentication

If the coordinator is started with `MYCELIUM_TOKEN` set in its environment, every endpoint except the read-only ones (`GET /`, `GET /ui`, `GET /scry`) requires an `Authorization: Bearer <token>` header. A missing or wrong token gets a `401`. Nodes and the CLI read the same `MYCELIUM_TOKEN` from their own environment and send it automatically, so a secured fleet just needs that one variable exported on every box. With no token set the coordinator logs a warning and leaves every endpoint open, which is only safe on a trusted network.

## Reading status: GET /scry

This is the one read endpoint. The dashboard polls it every three seconds, and any external frontend should do the same. It returns the full picture in one call.

`GET /scry` → `200 ScryResponse`

```json
{
  "nodes": [
    {
      "id": "sigil-a1f2",
      "hostname": "sigil",
      "campaign": "fuzz-libpng",
      "fuzzer": "aflpp",
      "priority": "dedicated",
      "status": "online",
      "time_limited": false,
      "last_sync": 1730649127
    }
  ],
  "campaign": {
    "name": "fuzz-libpng",
    "total_corpus": 1423,
    "total_crashes": 7,
    "unique_bugs": 2,
    "total_execs_per_sec": 48000,
    "nodes_online": 4
  }
}
```

`nodes` is an array of `NodeInfo`, one per registered node:

| Field | Type | Notes |
|---|---|---|
| `id` | string | Coordinator-assigned, `hostname-xxxx`. |
| `hostname` | string | The node's hostname. |
| `campaign` | string | Campaign the node joined. |
| `fuzzer` | string | Fuzzer identifier. |
| `priority` | string | `dedicated`, `shared`, or `idle`. |
| `status` | string | `online`, `unreachable`, `offline`, or `suspended`. |
| `time_limited` | boolean | `true` when the node's fuzzer has an overall time or run budget (honggfuzz `--run_time`, libFuzzer `-max_total_time`/`-runs`, Go `-fuzztime`, AFL++ `-V`/`-E`). Such a node exits and goes `suspended` on its own when the budget runs out, so a `suspended` node with `time_limited: true` finished its run rather than being drained by hand. Persistent fuzzers report `false`. |
| `last_sync` | integer | Unix seconds of the last heartbeat. |

`campaign` is a single `CampaignStatus`:

| Field | Type | Notes |
|---|---|---|
| `name` | string | Campaign name. |
| `total_corpus` | integer | Seeds stored for this campaign. |
| `total_crashes` | integer | Crashes stored for this campaign (distinct inputs). |
| `unique_bugs` | integer | Distinct bugs by stack hash. Below `total_crashes` once traces dedup them. |
| `total_execs_per_sec` | integer | Sum of execs per second across the campaign's online nodes. |
| `nodes_online` | integer | Count of online nodes. |

One thing to design around: `/scry` reports a single campaign, chosen as the campaign of the first node in the table. On a coordinator running one campaign (the usual case) this is exactly what you want. If you run more than one campaign at once, the `campaign` block reflects whichever node sorts first, while `nodes` still lists every node across all campaigns. A frontend that wants per-campaign totals should group the `nodes` array by its `campaign` field itself.

The dashboard lives on the same origin as the API, so it just fetches `/scry` directly. There is no CORS header set yet, so a frontend served from another origin would need that added first.

## Node lifecycle

### POST /register

A node announces itself and gets its ID back.

Request, `RegisterRequest`:

```json
{
  "hostname": "sigil",
  "campaign": "fuzz-libpng",
  "fuzzer": "aflpp",
  "priority": "dedicated",
  "requested_id": "sigil-a1f2",
  "time_limited": false
}
```

`priority` is one of `dedicated`, `shared`, or `idle`. `requested_id` is optional: a node persists a stable id and sends it so that on restart the coordinator reuses it (and the node keeps its seed-distribution history instead of re-pulling the whole corpus). When it is absent or invalid the coordinator mints a fresh `hostname-xxxx`. `time_limited` is optional and defaults to `false`; the node sets it to `true` when its fuzzer command carries an overall time or run budget, and the coordinator stores it and returns it in `/scry` so a frontend can tell a bounded node that finished from one that was drained.

Response, `200` with `RegisterResponse`:

```json
{ "node_id": "sigil-a1f2" }
```

The coordinator builds the ID from the hostname plus four hex characters. On a storage error it returns `500`.

### POST /heartbeat

A node reports its liveness and current counters. The coordinator updates the node's row and marks it `online`.

Request, `HeartbeatRequest`:

```json
{
  "node_id": "sigil-a1f2",
  "execs_per_sec": 12000,
  "corpus_size": 1423,
  "crashes_found": 7
}
```

Response: `200`, or `500` on a write error. There is no body.

### POST /deregister

Detach a node.

Request, `DeregisterRequest`:

```json
{ "node_id": "sigil-a1f2", "drain": true }
```

Response: `200`, or `500` on error. No body.

With `drain` true the coordinator suspends the node and keeps its corpus, crashes, and distribution history, so a node that comes back does not re-pull the whole corpus. With `drain` false the node and its `seed_distribution` rows are deleted outright.

## Corpus and crashes

### POST /seed/push

A node pushes a newly found seed.

Request, `PushSeedRequest`, where `seed` is a `Seed`:

```json
{
  "node_id": "sigil-a1f2",
  "seed": {
    "hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "data": [116, 101, 115, 116],
    "source_node": "sigil-a1f2",
    "campaign": "fuzz-libpng",
    "found_at": 1730649100
  }
}
```

`hash` is the SHA-256 of `data`, and it is the dedup key. Pushing a seed the coordinator already has is fine and still returns `200`. The response is `200` either way, or `500` on a storage error, with no body.

### POST /seed/push/batch

A node pushes a burst of seeds in one request, so a fast fuzzer is not bottlenecked on a round-trip per seed. Request is `PushSeedBatchRequest`: `{ "node_id": "...", "seeds": [ Seed, Seed, ... ] }`. Invalid seeds are skipped rather than failing the batch. Always `200`. `inoculate --seeds` uses this endpoint to upload a campaign's base corpus.

### POST /seed/pull

A node asks for seeds it has not received yet.

Request, `PullSeedsRequest`:

```json
{ "node_id": "sigil-a1f2", "campaign": "fuzz-libpng" }
```

The node sends its own `campaign` so the coordinator can look up its unsent seeds directly, without scanning the node table. The coordinator returns seeds for that campaign the node has not already received, excluding ones the node itself found.

Response, `200` with `PullSeedsResponse`:

```json
{ "seeds": [ { "hash": "...", "data": [ ... ], "source_node": "glyph-c5d6", "campaign": "fuzz-libpng", "found_at": 1730649200 } ] }
```

The coordinator returns seeds for the node's campaign that did not originate from that node and that have not been sent to it before, then records each one as sent so it will not come again. If the node ID is unknown, the response is `404` with an empty `seeds` array.

### POST /crash

A node reports a crash.

Request, `ReportCrashRequest`, where `crash` is a `CrashEntry`:

```json
{
  "node_id": "sigil-a1f2",
  "crash": {
    "stack_hash": "...",
    "input_hash": "...",
    "data": [ ... ],
    "sanitizer_output": "==1234==ERROR: AddressSanitizer: heap-buffer-overflow",
    "source_node": "sigil-a1f2",
    "campaign": "fuzz-libpng",
    "found_at": 1730649300
  }
}
```

`input_hash` is the SHA-256 of the crashing input and is the dedup key, so the same input is stored once. `stack_hash` is derived from the sanitizer output and is stored alongside the input to group crashes by bug. Response: `200`, or `500` on error, no body.

## Campaigns and harness

### POST /campaign

Create a campaign. This is the first half of what `inoculate` does.

Request, `CreateCampaignRequest`:

```json
{
  "name": "fuzz-libpng",
  "fuzzer_name": "aflpp",
  "fuzzer_command": ["afl-fuzz", "-i", "{corpus}", "-o", "{output}", "-M", "main", "-F", "{inject}", "--", "{harness}"]
}
```

`fuzzer_command` is the command template with the `{harness}`, `{corpus}`, `{output}`, and `{inject}` placeholders.

Responses:

- `201 Created` on success.
- `400 Bad Request` if `name` or `fuzzer_command` is empty.
- `409 Conflict` on a storage error, which includes trying to create a campaign whose name already exists.

### GET /campaign/{name}

Fetch a campaign's record. A joining distributed-mode node calls this to learn the command and to check that a harness has been uploaded.

Response, `200` with `CampaignInfo`:

```json
{
  "name": "fuzz-libpng",
  "fuzzer_name": "aflpp",
  "fuzzer_command": ["afl-fuzz", "..."],
  "harness_len": 2097152,
  "created_at": 1730649000
}
```

`harness_len` is the size of the uploaded harness in bytes, and it is `0` until a harness is uploaded. Returns `404` if there is no such campaign, or `500` on a read error.

### PUT /campaign/{name}/harness

Upload the harness binary for a campaign. This is the second half of `inoculate`. The body is the raw binary, not JSON.

- Content type: `application/octet-stream` (raw bytes).
- Body limit: 512 MiB.

Responses:

- `200` on success.
- `400 Bad Request` if the body is empty.
- `404 Not Found` if the campaign does not exist. Create it first with `POST /campaign`.
- `500` on a storage error.

### GET /campaign/{name}/harness

Download the harness binary. Joining distributed-mode nodes call this. The response is the raw binary with content type `application/octet-stream`, or `404` if no harness has been uploaded, or `500` on a read error.

## Dashboard

`GET /` and `GET /ui` both return the built-in dashboard, a single static HTML page. It is a plain client of `/scry` and holds no state of its own.

