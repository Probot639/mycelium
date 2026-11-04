# Deployment

mycelium was built for a tailnet, and the simplest deployment is still the original one: run `mycelium spawn` on one box, run `mycelium join` on the others, and let them reach the coordinator on port 7100 over whatever network you have. The `deploy/` tree is for when you want to run it on Kubernetes instead.

Treat `deploy/` as the source of truth. The manifests there are marked as proof-of-concept and untested, and the tree is still growing, so read the files before you rely on them rather than trusting any exact value quoted here.

## Docker image

`deploy/k3s/Dockerfile` is a two-stage build. The first stage builds the `mycelium` binary with `cargo build --release`. The second stage is an Ubuntu base with AFL++ installed from the distro package, into which the binary is copied, with `mycelium` as the entrypoint.

The one thing the image does not carry is your fuzzing target. The Dockerfile has a `TODO` for copying in the actual target binary, and in distributed mode the harness comes from the coordinator anyway, so how you get the target into the fuzzing pods is a choice you make per campaign rather than something baked into this image.

## Kubernetes

The `deploy/k3s/` directory has three manifests. They are written against k3s but are plain Kubernetes objects.

- `coordinator.yaml` runs the coordinator as a single-replica Deployment with `mycelium spawn`, exposes it as a Service on port 7100, and backs its `/data` with a PersistentVolumeClaim for the corpus and the SQLite file. Keep it at one replica. The coordinator is a single process with a local database, so it does not scale horizontally.
- `fuzzer-job.yaml` runs the fuzzing nodes as a Job with `parallelism` set to the number of nodes you want, each pod running `mycelium join --config` against the coordinator Service. Each pod registers independently and gets its own node ID, so pods do not collide. The Job deliberately sets no CPU limit, because a CPU limit throttles the fuzzer mid-run and drops execs per second. Request the cores you need and let it burst.
- `node-config.yaml` is a ConfigMap holding the `node.toml` the fuzzer pods mount. It is a manual-mode config, so it follows [configuration.md](configuration.md).

These are a starting point, not a turnkey install. They carry `TODO` markers for things like the real image registry path, and they have not been run end to end.

## What is still landing

The `deploy/` tree is being built out beyond the k3s manifests. Planned additions are a Helm chart and per-distro notes for kind, k3d, minikube, microk8s, k3s, and vanilla kubeadm, plus a Vagrant multi-node setup for local testing. These may not be present yet. When you pull the repo, check `deploy/` for a chart directory or a `Vagrantfile` and follow what is actually there. If this doc and the directory disagree, the directory is right.
