# Helm deployment on OpenShift 4.21

Deploys RedForge on OpenShift 4.21 using the `helm/` chart. The chart installs:

- **redforge-web** — Streamlit dashboard (port 8501)
- **redforge-mcp** — MCP/SSE server (port 8000)
- **redforge-virtuoso** — OpenLink Virtuoso SPARQL triplestore (port 8890)
- **redforge-ingest** — one-shot Job that downloads all CVE sources and loads them into Virtuoso

Both services are exposed via edge-TLS Routes using the cluster's wildcard certificate.

## Prerequisites

- OpenShift 4.21 cluster
- `oc` CLI installed and logged in
- `helm` CLI (see below)
- An NVD API key ([request one here](https://nvd.nist.gov/developers/request-an-api-key))
- The `quay.io/fsoppelsa/redforge:0.1.0` image available on Quay

### Installing helm on RHEL 9

Helm is not in the default RHEL 9 repositories. Install the binary directly:

```bash
HELM_VERSION=v3.17.3
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -fsSL https://get.helm.sh/helm-${HELM_VERSION}-linux-${ARCH}.tar.gz \
  | tar -xz
sudo mv linux-${ARCH}/helm /usr/local/bin/helm
rm -rf linux-${ARCH}
helm version
```

If you don't have `sudo`, install to your home directory instead:

```bash
mkdir -p ~/.local/bin
mv linux-${ARCH}/helm ~/.local/bin/helm
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

`install.sh` performs this automatically if `helm` is not found in `$PATH`.

## Who does what

| Task | Role |
|---|---|
| Run `setup-scc.sh` | **cluster-admin** — once per namespace |
| Run `install.sh` / `helm install` | normal user |
| Run `helm upgrade` | normal user |
| Run `uninstall.sh` / `helm uninstall` | normal user |

The only cluster-admin step is granting the `anyuid` SCC to the `redforge` service account. This is required because the upstream Virtuoso image runs as root. Every other resource in the chart (Deployments, PVCs, Routes, Secrets, Jobs) is created by a normal namespace-admin user.

## Install

### Step 1 — cluster admin (once)

```bash
NAMESPACE=redforge ./helm/setup-scc.sh
```

This creates the `redforge` namespace, pre-creates the service account, and grants `anyuid`. It only needs to run once. Upgrades and reinstalls do not require it again.

### Step 2 — normal user

```bash
NVD_API_KEY=<your-key> ./helm/install.sh
```

With a custom namespace:

```bash
NAMESPACE=my-ns NVD_API_KEY=<your-key> ./helm/install.sh
```

Directly with Helm (no script):

```bash
helm install redforge ./helm \
  --namespace redforge \
  --set credentials.nvdApiKey=<your-key>
```

## What happens after install

1. PVCs, Deployments, Services, and Routes are created immediately.
2. PVCs stay `Pending` until pods are scheduled — this is normal with the `lvms-vg1` storage class (`WaitForFirstConsumer` binding mode).
3. The `redforge-ingest` Job starts as a post-install hook:
   - **Phase 1 (initContainer):** downloads all configured sources into `/app/data/raw/`, then joins and RDFizes the dataset to `/app/data/rdf/redforge.ttl`. This takes 10–30 minutes depending on `maxPages` and network speed.
   - **Phase 2 (main container):** waits for Virtuoso to become ready, then calls `ld_dir + rdf_loader_run` via `isql` to bulk-load the Turtle file into the named graph.
4. The web and MCP pods restart a few times while the ingest runs — this is normal. They stabilize once data is available.

Watch progress:

```bash
oc get deploy,pod,job -n redforge -w

# Ingest logs
kubectl logs -n redforge -l app=redforge-ingest -c ingest -f
kubectl logs -n redforge -l app=redforge-ingest -c load-virtuoso -f
```

## Access

After the ingest Job completes:

```bash
oc get routes -n redforge
```

| Route | Port | Description |
|---|---|---|
| `redforge-web` | 8501 | Streamlit dashboard |
| `redforge-mcp` | 8000 | MCP/SSE server |

To wire the MCP server into an LLM client, use the SSE endpoint:

```
https://<redforge-mcp-route-host>/sse
```

## Upgrade — normal user

```bash
helm upgrade redforge ./helm \
  --namespace redforge \
  --set credentials.nvdApiKey=<your-key>
```

### Upgrade to 0.2.0 (suggest_v2, plan_insights, remediate_insights)

0.2.0 adds three new MCP tools and wires the Red Hat offline token Secret by default.
If the Secret already exists from a prior install, Helm will update it in place (the
token value is preserved unless you pass `--set mcp.rhOfflineToken.token=...`).

```bash
helm upgrade redforge ./helm \
  --namespace redforge \
  --set credentials.nvdApiKey=<your-key>
```

Populate the offline token if you haven't already:

```bash
kubectl patch secret redforge-rh-offline-token -n redforge \
  --type=merge \
  -p '{"stringData":{"RH_OFFLINE_TOKEN":"<your-offline-token>"}}'
kubectl rollout restart deployment/redforge-mcp -n redforge
```

The `redforge-ingest` Job re-runs on upgrade. Downloads are cached on the data PVC, so only new or changed files are re-fetched.

## Uninstall — normal user

```bash
./helm/uninstall.sh
```

Or manually:

```bash
helm uninstall redforge -n redforge
kubectl delete pvc redforge-data redforge-virtuoso-db -n redforge
oc delete project redforge
```

PVCs are not removed by `helm uninstall` and must be deleted explicitly to free storage.

## NVD API key

The key is stored in the `redforge-credentials` Secret and injected as the `NVD_API_KEY` environment variable at runtime. It overrides the empty `nvd_api_key = ""` placeholder in `redforge.toml`. The ConfigMap contains no credentials.

## Optional: SSH key mount for `redforge-mcp`

If you want the MCP container to SSH into remote targets, mount an SSH key Secret into the `redforge-mcp` pod.

Create the Secret (example for a private key file named `id_ed25519`):

```bash
kubectl create secret generic redforge-ssh-key \
  --from-file=id_ed25519=/path/to/id_ed25519 \
  -n redforge
```

Enable the mount via Helm values:

```bash
helm upgrade redforge ./helm \
  --namespace redforge \
  --set mcp.sshKey.enabled=true \
  --set mcp.sshKey.secretName=redforge-ssh-key \
  --set mcp.sshKey.mountPath=/etc/ssh-key \
  --set mcp.sshKey.defaultMode=256
```

Notes:
- `defaultMode` is an integer; `256` is `0400` (octal). SSH rejects overly-permissive key files.
- The Secret is mounted read-only. Use your SSH client config to point at the mounted key path.

## Red Hat offline token for `redforge-mcp` (Insights / Lightspeed)

The `redforge-rh-offline-token` Secret is created by Helm automatically. The `RH_OFFLINE_TOKEN` environment variable is injected into the MCP container on every install and upgrade — no extra steps needed to enable it.

### Populate the token at install time

```bash
helm install redforge ./helm \
  --namespace redforge \
  --set credentials.nvdApiKey=<nvd-key> \
  --set mcp.rhOfflineToken.token=<your-offline-token>
```

### Populate the token after install (without redeploying)

```bash
kubectl patch secret redforge-rh-offline-token -n redforge \
  --type=merge \
  -p '{"stringData":{"RH_OFFLINE_TOKEN":"<your-offline-token>"}}'
```

Then restart the MCP pod to pick up the new value:

```bash
kubectl rollout restart deployment/redforge-mcp -n redforge
```

### Obtain a Red Hat offline token

Log in to [console.redhat.com](https://console.redhat.com), open your account menu → **My Profile → API Token**, and copy the offline token. Offline tokens do not expire unless revoked.

### Rotate the token

Patch the Secret with the new value and restart the pod as above. The old token is overwritten in place; no Helm upgrade is required.

## Tuning

| Value | Default | Notes |
|---|---|---|
| `pipeline.maxPages` | `10` | Pages per source. Raise to 500+ for a full dataset. |
| `pipeline.perPage` | `100` | Items per API page. |
| `storage.data.size` | `1Gi` | Shared PVC for downloads and RDF. Raise if increasing `maxPages`. |
| `storage.data.storageClass` | `lvms-vg1` | topolvm node-local LVM; RWO only. |
| `virtuoso.graphUri` | `http://redforge.local/graph/main` | Named graph used by all components. |

## Troubleshooting

**Virtuoso pod stuck in `CreateContainerConfigError`**
The `anyuid` SCC grant is missing. A cluster admin must run:
```bash
oc adm policy add-scc-to-user anyuid -z redforge -n redforge
```

**Ingest Job stuck in Phase 2 (`load-virtuoso` container)**
Virtuoso may not have started. Check:
```bash
kubectl logs -n redforge deployment/redforge-virtuoso
```

**Web/MCP pods crash-looping before ingest completes**
Normal — they probe for data that does not exist yet. They recover automatically once the Job finishes.

**Streamlit is slow or shows a spinner indefinitely**
WebSocket may not be passing through the HAProxy router. The Route has a 300s timeout which covers most cases. Streamlit silently falls back to HTTP long-polling if WebSocket is blocked — the UI still works, just less responsive.
