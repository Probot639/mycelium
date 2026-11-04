# Deploying mycelium on Kubernetes

The Helm chart at `deploy/helm/mycelium` runs the coordinator and a pool of
fuzzer pods. Fuzzer pods join in distributed mode, so they pull the harness from
the coordinator at startup and the image never needs a per-target rebuild.

The one real difference between kind, k3d, minikube, microk8s, k3s, and
kubeadm is how a locally built image reaches the cluster nodes. Everything else
is the same chart. Build once, load it the way your cluster wants, then install.

## Build the image

Build context is the repo root, not `deploy/k3s`:

```
docker build -f deploy/k3s/Dockerfile -t mycelium:dev .
```

The image carries the `mycelium` binary and AFL++. No fuzz target is baked in.

## Get the image into the cluster

Pick the line for your cluster. `TAG` is `mycelium:dev` from the build above.

| Cluster | Command |
|---|---|
| kind | `kind load docker-image mycelium:dev` |
| k3d | `k3d image import mycelium:dev -c CLUSTER` |
| minikube | `minikube image load mycelium:dev` |
| microk8s | `docker save mycelium:dev > img.tar && microk8s images import < img.tar` |
| k3s | `docker save mycelium:dev > img.tar && sudo k3s ctr images import img.tar` |
| kubeadm / cloud | push to a registry the nodes can reach, then set `image.repository` and `image.tag` in values |

microk8s and k3s also run a built-in or local registry if you prefer pushing
over importing a tarball. microk8s enables one with `microk8s enable registry`
(then push to `localhost:32000/mycelium:dev`). For a k3s local registry, point
`/etc/rancher/k3s/registries.yaml` at it and restart k3s.

Because a locally loaded image has no registry behind it, keep
`image.pullPolicy` at `IfNotPresent` or `Never` for every local cluster.
`Always` makes the kubelet try to pull and fail. The chart defaults to
`IfNotPresent`, which works for both local loads and registries.

## Service type per cluster

The coordinator Service is `ClusterIP` by default, which is all the in-cluster
fuzzer pods need. To reach the coordinator from your workstation (to run
`inoculate` and `probe`), use one of these.

| Cluster | How to reach the coordinator |
|---|---|
| kind, k3d, minikube, microk8s, k3s (local) | `kubectl port-forward`, or set `coordinator.service.type=NodePort` |
| k3d | NodePort works if you mapped the port at cluster create, otherwise port-forward |
| minikube | `minikube service` or `minikube tunnel` for NodePort/LoadBalancer |
| k3s | ships Klipper (ServiceLB), so `LoadBalancer` gets an external IP without extra setup |
| kubeadm / cloud | `LoadBalancer` where a cloud LB or MetalLB exists, otherwise NodePort |

Port-forward works on every one of them and needs no values change:

```
kubectl port-forward svc/mycelium-coordinator 7100:7100
```

## StorageClass defaults

The coordinator PVC uses the cluster default StorageClass when
`coordinator.storage.storageClassName` is empty.

- kind, k3d, minikube, microk8s, k3s all ship a working default provisioner
  (local-path or hostpath), so the empty default is fine.
- k3s names its class `local-path`. It is the default, so you do not need to set
  it, but you can pin it with `--set coordinator.storage.storageClassName=local-path`.
- A bare kubeadm cluster often has no default provisioner. Install one (for
  example local-path-provisioner) or set `storageClassName` to a class that
  exists, or the PVC stays Pending.

## Full install flow

```
# 1. build the image
docker build -f deploy/k3s/Dockerfile -t mycelium:dev .

# 2. load it into the cluster (kind shown, use your cluster's line from above)
kind load docker-image mycelium:dev

# 3. install the chart
helm install mycelium deploy/helm/mycelium \
  --set image.tag=dev

# 4. create the campaign and upload a harness (one-time operator step).
#    Port-forward the coordinator, then run inoculate from a box that has the
#    harness binary and the mycelium CLI.
kubectl port-forward svc/mycelium-coordinator 7100:7100 &
mycelium inoculate --coordinator localhost:7100 \
  --campaign default \
  --harness ./fuzz_png \
  --fuzzer aflpp \
  -- afl-fuzz -i {corpus} -o {output} -M main -F {inject} -- {harness}

# 5. watch it run
mycelium probe --coordinator localhost:7100 --nodes
```

The fuzzer pods come up with the chart in step 3 and start fuzzing as soon as
the campaign from step 4 exists. Scale them with `--set fuzzer.replicas=N`.

### AFL++ distributed-mode recipe

The fuzzer command passed to `inoculate` matters. mycelium fills these
placeholders per node: `{harness}`, `{corpus}` (the `-i` seed dir, read once),
`{output}`, and `{inject}` (the dir mycelium drops pulled seeds into while the
fuzzer runs). The correct AFL++ command runs a named main instance and imports
the inject dir as a foreign corpus:

```
afl-fuzz -i {corpus} -o {output} -M main -F {inject} -- {harness}
```

The `-F {inject}` part is what makes sync work. AFL++ reads `-i` only once at
startup, so seeds dropped there after the fuzzer starts never load. The `-F`
foreign-corpus dir gets re-scanned while running, so pulled seeds reach the live
fuzzer. Pointing sync at the `-i` dir instead is a silent no-op.

## Chart values worth knowing

| Key | Default | Notes |
|---|---|---|
| `image.repository` / `image.tag` | `mycelium` / `latest` | set `tag=dev` to match the build above |
| `image.pullPolicy` | `IfNotPresent` | keep off `Always` for locally loaded images |
| `coordinator.service.type` | `ClusterIP` | `NodePort` or `LoadBalancer` to expose it |
| `coordinator.storage.size` | `10Gi` | corpus plus the SQLite DB |
| `coordinator.storage.storageClassName` | `""` | empty uses the cluster default |
| `campaign.name` | `default` | must match the name you `inoculate` |
| `campaign.priority` | `shared` | `dedicated`, `shared`, or `idle` |
| `fuzzer.enabled` | `true` | turn off to run the coordinator alone |
| `fuzzer.replicas` | `3` | one pod per box you want fuzzing |
| `fuzzer.resources.requests.cpu` | `"2"` | requested, never limited (see below) |
| `inoculate.enabled` | `false` | optional one-shot Job, needs a harness in the image |

The fuzzer pods request CPU but set no CPU limit on purpose. A CPU limit makes
the kernel throttle the fuzzer mid-run, which cuts execs/sec hard. Memory keeps
a limit.

## Manual mode

Distributed mode is the default and the simpler path. If you would rather bake
the harness and seeds into the image and skip `inoculate`, there is a
manual-mode ConfigMap at `deploy/k3s/node-config.yaml` with the correct AFL++
wiring. It is a reference for the `join --config` path and is not wired into the
chart.
