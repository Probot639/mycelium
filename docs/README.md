# mycelium docs

Reference docs for mycelium, the distributed fuzzing orchestrator. One coordinator process holds the shared corpus, a crowd of fuzzing nodes keep it in sync over HTTP, and each node runs its own fuzzer against a harness it pulled from the coordinator.

If you just want to get a campaign running, the top-level [README](../README.md) has the quickstart. These docs are the deeper reference for when you need to know exactly what a flag does, what a config key means, or what an endpoint returns.

## Where to look

- [architecture.md](architecture.md) covers the shape of the system: the coordinator, the node, the shared `common` crate, the sync loop, the filesystem watcher, and the SQLite schema with what each table holds.
- [cli.md](cli.md) documents every subcommand and flag, with examples. The verbs are `spawn`, `inoculate`, `join`, `probe`, and `sever`.
- [configuration.md](configuration.md) is the full `node.toml` reference for manual mode, including the `mode`, `stats_parser`, and `priority` settings, with a complete annotated example.
- [http-api.md](http-api.md) describes every coordinator endpoint with its method, path, and request and response JSON. Read this if you are building a frontend or an automation client. The read endpoint everything consumes is `GET /scry`.
- [deployment.md](deployment.md) covers the Docker image, Kubernetes via the `deploy/` tree, and the Vagrant test setup.
- [coverage-agent.md](coverage-agent.md) is the framework for a plug-and-play coverage-management agent: the node coverage reader, the coordinator coverage API, and the tool-call surface an agent drives.

## A note on vocabulary

mycelium leans on a mushroom theme for its commands. A node is sometimes called a "circle" (as in a fungal ring), the status command is `scry`, and you grow a campaign by `inoculate`-ing a harness and letting nodes `join`. The config section that controls sync behavior is `[circle]`. None of this changes what the tool does, it is just the naming.

## Two ways to run a node

Most of the docs split along the same line, so it helps to know it up front.

Distributed mode is `join --workdir`. The coordinator holds the one harness binary and the fuzzer command template, each node downloads the harness, builds its own working directories, and runs the fuzzer. You never copy binaries around by hand.

Manual mode is `join --config node.toml`. The harness is already on the box and a local config file spells out the fuzzer command and every directory. This is the mode that exposes the full `[circle]` settings.
