# Poolsmith Kubernetes manifests

Minimal, production-shaped manifests. Apply with `kubectl apply -k .` (uses
the included `kustomization.yaml`).

```bash
cd deploy/k8s
kubectl apply -k .
```

## What's in here

| File               | Purpose                                                                  |
|--------------------|--------------------------------------------------------------------------|
| `namespace.yaml`   | Dedicated `poolsmith` namespace.                                         |
| `configmap.yaml`   | `poolsmith.ini` — pool sizes, upstream servers, databases.               |
| `secret.yaml`      | `userlist.txt` — **replace with SealedSecret / ExternalSecret**.         |
| `deployment.yaml`  | 3-replica rolling deployment, non-root, read-only rootfs, topology spread. |
| `service.yaml`     | ClusterIP exposing on port **5432** (apps connect as if it were Postgres). |
| `hpa.yaml`         | Autoscale 3→20 on CPU 70% / memory 80%.                                  |
| `pdb.yaml`         | PodDisruptionBudget: always keep ≥ 2 pods.                               |
| `kustomization.yaml` | Glue file for `kubectl apply -k .`.                                    |

## Rollouts

The deployment has `checksum/config` and `checksum/userlist` annotation
placeholders. Wire them in your CI:

```bash
kubectl patch deploy/poolsmith -n poolsmith --patch "$(cat <<EOF
spec:
  template:
    metadata:
      annotations:
        checksum/config: $(sha256sum configmap.yaml | cut -d' ' -f1)
        checksum/userlist: $(sha256sum secret.yaml   | cut -d' ' -f1)
EOF
)"
```

## Resource profile

The defaults (500m CPU req / 2 CPU limit, 256Mi / 1Gi memory) fit around
~2000 client connections per pod in transaction mode. Push that higher by:

- **Horizontally** — add replicas with HPA; each pod has its own pool.
- **Vertically** — bump `limits.cpu` and `GOMAXPROCS` (they stay linked).

The `GOMEMLIMIT` env is set just below the pod memory limit so the Go GC
tightens up before the kubelet OOMKills.

## Graceful shutdown

Poolsmith handles `SIGTERM` by refusing new client connections and draining
existing ones. `terminationGracePeriodSeconds: 60` in the deployment gives
it time; increase if your workloads run long-lived transactions.
