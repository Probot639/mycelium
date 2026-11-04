# Coverage-management agent framework for mycelium

A design for a plug-and-play coverage-management agent. The agent (Oleg's
Claude agent) observes campaign coverage and steers the fleet. It only ever
speaks tool calls. Those tools wrap a stable coverage API on the coordinator,
and the coordinator gets its coverage data from the nodes. Three layers, each
replaceable without touching the others.

```
  Oleg's Claude agent
        |  tool calls only (MCP)
        v
  mycelium-coverage tool server  (the plug-and-play surface, ships with mycelium)
        |  HTTP /api/v1/coverage/*  and  /api/v1/control/*
        v
  coordinator  (aggregates per-node coverage, holds the control plane)
        ^  POST /coverage/report
        |
  nodes  (each reads its fuzzer's coverage through a cov reader)
```

The agent is stateless about mycelium. Everything it needs comes from a tool
call, and everything it does is a tool call. The tool server holds the
coordinator URL and the auth token, so the agent never handles a secret.

## Layer 1: coverage collection on the node

mycelium already has per-fuzzer profiles and per-fuzzer hooks (`stats_cmd`,
`triage_cmd`, `import_cmd`). Coverage is one more reader in that pattern: a
`cov_cmd` that emits a normalized coverage snapshot for the node's fuzzer.

- AFL++: read `out/<instance>/fuzz_bitmap`, or run `afl-showmap` to get the
  edge set. The bitmap gives covered edges directly.
- libFuzzer: `-print_coverage=1` / sancov, or the `cov:` count already parsed.
- honggfuzz: its coverage counters from the stats line.
- Custom: the `cov_cmd` hook, same as the other hooks.

Normalized snapshot the reader emits (small, so it ships every sync tick):

```json
{ "edges_covered": 41233, "edges_total": 98004, "new_edges": 128,
  "edge_digest": "<sha256 of the sorted covered-edge id set>",
  "edge_sample": [ /* optional: a bounded sample or a compressed bitmap */ ] }
```

The node POSTs this to the coordinator (either folded into the heartbeat or a
dedicated `POST /coverage/report`). `edge_digest` lets the coordinator detect
redundant nodes cheaply (same digest means same coverage) without shipping full
bitmaps every tick. Full bitmaps are sent on request or on a growth event.

## Layer 2: coordinator coverage API (HTTP, versioned)

The coordinator stores per-node coverage and computes campaign-level views. All
read endpoints are open like `/scry`; the control endpoints are token-gated.

Read:
- `GET /api/v1/coverage/{campaign}` -> aggregate: union edge count, total,
  percent, growth per minute, a `plateau` flag, node count.
- `GET /api/v1/coverage/{campaign}/nodes` -> per node: covered, unique edges
  (covered by this node alone), overlap percent, execs/sec, priority, status.
- `GET /api/v1/coverage/{campaign}/timeline?window=1h` -> coverage timeseries,
  for trend and plateau detection.
- `GET /api/v1/coverage/{campaign}/gaps?top=20` -> uncovered functions or
  modules, ranked. Needs a symbol map (edge id -> function) uploaded with the
  harness; optional, degrades to raw edge ids without it.
- `GET /api/v1/coverage/{campaign}/corpus-value` -> corpus inputs ranked by the
  edges they uniquely cover, for distillation.

Control (token-gated):
- `PATCH /api/v1/control/node/{id}` `{ "priority": "idle|shared|dedicated" }`.
- `POST /api/v1/control/{campaign}/seeds` -> targeted seeds (reuses
  `/seed/push/batch` semantics).
- `POST /api/v1/control/{campaign}/dictionary` `{ tokens: [...] }` -> nodes pull
  the dictionary and feed it to the fuzzer (`-x` for AFL, `-dict=` for
  libFuzzer).
- `POST /api/v1/control/{campaign}/distill` -> trigger a fleet corpus
  minimization (coordinator computes the minimal covering set, nodes cmin to it).
- `POST /api/v1/control/node/{id}/drain` and `.../resume`.

## Layer 3: the tool-call interface (the plug-and-play surface)

A small MCP server, `mycelium-coverage`, that the agent connects to. It
translates each tool call into one or more coordinator HTTP calls. This is the
contract Oleg builds against. Tools split into observe and act.

### Observe

- `coverage_overview(campaign)` ->
  `{ covered, total, pct, growth_per_min, plateau, nodes }`.
  The agent's situational read. One call answers "are we still making progress".
- `node_coverage(campaign)` ->
  `[ { node_id, fuzzer, covered, unique_edges, overlap_pct, execs_per_sec,
       priority, status } ]`.
  For spotting redundant nodes (high overlap, low unique) and idle capacity.
- `coverage_timeline(campaign, window)` -> `[ { t, covered } ]`.
  For the agent to reason about plateaus and the effect of its own actions.
- `coverage_gaps(campaign, top_n)` ->
  `[ { function, module, uncovered_edges, nearest_covered } ]`.
  Where to point effort next.
- `corpus_value(campaign)` ->
  `[ { input_hash, unique_edges, size } ]`. Which inputs carry the coverage,
  for distillation and for seeding directed work.
- `snapshot(campaign)` -> overview + node_coverage + top gaps in one call, so
  the agent can refill its context in a single round trip.

### Act

- `set_priority(node_id, priority)` -> rebalance effort across the fleet.
- `inject_seeds(campaign, seeds)` -> `seeds` is a list of base64 inputs; push
  targeted inputs toward a gap.
- `inject_dictionary(campaign, tokens)` -> steer fuzzers toward tokens the agent
  inferred from the uncovered code.
- `request_distillation(campaign)` -> shrink the corpus to the minimal covering
  set, so every node fuzzes a lean corpus.
- `drain_node(node_id)` / `resume_node(node_id)` -> take a node out for
  reassignment and bring it back.

Every tool returns a small JSON object the agent can reason over directly, and
every mutation returns the resulting state (for example `set_priority` returns
the node's new row), so the agent sees the effect without a second call.

## The agent's loop (how Oleg's agent uses this)

The agent does not need bespoke logic in mycelium. A typical turn:

1. `snapshot(campaign)` to read coverage, nodes, and gaps.
2. Decide: plateauing with high inter-node overlap -> redundant nodes. A gap
   cluster in one module -> directed effort there.
3. Act: `request_distillation`, then `set_priority` to move redundant nodes to a
   fresh target, `inject_dictionary`/`inject_seeds` toward the gap.
4. `coverage_timeline` on the next turn to confirm the action moved the curve,
   and adjust.

## Plug-and-play contract

- One MCP server entry in the agent's config: the server binary plus the
  coordinator URL and token. Nothing else to wire.
- The agent discovers the tools through MCP tool listing, so adding a tool does
  not require an agent change.
- The HTTP API is versioned (`/api/v1`), so the tool server and the coordinator
  can evolve independently.
- The tool server owns the token. The agent handles no secrets.
- Read tools are safe and idempotent. Act tools are the only ones that change
  state, and each names exactly what it changed.

## What mycelium needs to build to support this

1. Node: a per-profile coverage reader plus a `cov_cmd` hook, and
   `POST /coverage/report` with the normalized snapshot.
2. Coordinator: store per-node edge sets (digest always, full bitmap on
   request), compute union, overlap, and the timeline. A `coverage` table keyed
   by (campaign, node_id, t).
3. Coordinator: the `/api/v1/coverage/*` read endpoints and the
   `/api/v1/control/*` endpoints above.
4. Optional symbol map: accept an edge-id -> function map alongside the harness
   so `coverage_gaps` can name functions instead of raw edge ids.
5. The `mycelium-coverage` MCP server wrapping the API, shipped in the repo so
   it is the one thing Oleg points the agent at.

The ordering matters: layers 1 and 2 are the real work (collecting and
aggregating coverage). Layer 3 is thin once the API exists, and it is the only
piece Oleg's agent sees.
