# Integrations

RedForge connects CVE intelligence to Red Hat Insights remediation through a chain of MCP tools. An AI assistant can drive the full workflow — from SBOM generation to applied Ansible playbook — without leaving the conversation.

## Prerequisites

| Requirement | How to verify |
| --- | --- |
| Host registered with `insights-client` | `insights-client --status` on the host |
| Host connected via `rhc` | `rhc status` on the host |
| `RH_OFFLINE_TOKEN` Secret populated | `oc get secret redforge-rh-offline-token -n redforge` |
| `SSH_KEY_PATH` Secret populated (SSH targets) | `oc get secret redforge-ssh-key -n redforge` |
| Remote user has passwordless sudo (SSH targets) | `ssh user@host sudo id` |

## Full automated workflow

### Step 1 — Scan the target

Start a syft SBOM scan. The call returns immediately; the scan runs in the background.

```
suggest_v2(target="root@192.168.122.202", scan_path="/", top_n=25)
```

Returns:
```json
{
  "status": "scanning",
  "job_id": "3f8a1c2d-...",
  "cache_file": "/tmp/redforge-sbom/ssh__root@192.168.122.202__slash.json"
}
```

### Step 2 — Poll until the scan completes

```
suggest_v2_status(job_id="3f8a1c2d-...")
```

Returns `{"status": "running", "elapsed_seconds": 47.2}` while running, then:

```json
{
  "status": "done",
  "summary": {"cve_count": 18, "components_seen": 412, ...},
  "items": [
    {"cve_id": "CVE-2025-39981", "cvss3_score": 8.1, "priority": "1-Act", ...},
    ...
  ],
  "scan_metadata": {"target": "root@192.168.122.202", "from_cache": false, ...}
}
```

Subsequent `suggest_v2` calls for the same target return instantly from cache.

### Step 3 — Create a remediation plan

Take the CVE IDs from the scan result and create an Insights plan:

```
plan_insights(
  cves=[{"cve_id": "CVE-2025-39981"}, {"cve_id": "CVE-2025-68183"}],
  target_host="rhel8-redforge.internal"
)
```

Returns:
```json
{
  "remediation_id": "b3a9af8b-...",
  "system_uuid": "8a00277f-...",
  "matched": [
    {"cve_id": "CVE-2025-39981", "issue_id": "vulnerabilities:CVE-2025-39981"},
    {"cve_id": "CVE-2025-68183", "issue_id": "vulnerabilities:CVE-2025-68183"}
  ],
  "skipped": [],
  "coverage_summary": {"requested": 2, "matched": 2, "skipped": 0}
}
```

CVEs that don't apply to the system or have no available fix are in `skipped` with a reason — never silently dropped.

### Step 4 — Validate before executing (optional)

```
remediate_insights(remediation_id="b3a9af8b-...", dry_run=true)
```

Returns:
```json
{
  "dry_run": true,
  "runnable": true,
  "issue_count": 2,
  "message": "Plan is runnable.",
  "console_url": "https://console.redhat.com/insights/remediations/b3a9af8b-..."
}
```

### Step 5 — Execute the remediation

```
remediate_insights(remediation_id="b3a9af8b-...")
```

Triggers the Ansible playbook via RHC and polls until completion:

```json
{
  "run_id": "uuid",
  "status": "success",
  "started_at": "2026-06-03T15:44:41Z",
  "finished_at": "2026-06-03T15:46:12Z",
  "console_url": "https://console.redhat.com/insights/remediations/b3a9af8b-..."
}
```

## Authentication

The Insights tools authenticate using a Red Hat offline token exchanged for a short-lived access token via the SSO endpoint. The token is read from the `RH_OFFLINE_TOKEN` environment variable, which is injected from the `redforge-rh-offline-token` Kubernetes Secret.

To rotate the token:

```bash
oc patch secret redforge-rh-offline-token -n redforge \
  -p '{"data":{"RH_OFFLINE_TOKEN":"'$(echo -n '<new-token>' | base64 -w0)'"}}'
oc rollout restart deployment/redforge-mcp -n redforge
```

Get a fresh offline token from the [Red Hat Hybrid Cloud Console](https://console.redhat.com/openshift/token).

## SBOM cache

Completed syft scans are cached in `/tmp/redforge-sbom/` inside the MCP pod. The cache key is derived from `(target, target_type, scan_path)`. A cached scan is returned instantly on any subsequent `suggest_v2` call.

The cache is in-pod ephemeral storage — it does not survive pod restarts. Pass `force=true` to `suggest_v2` to invalidate the cache and trigger a fresh scan.

## Manual workflow (no AI assistant)

If you prefer to drive the flow directly via the Red Hat Console:

1. Run `suggest_v2` to get the CVE list for the target.
2. Navigate to **Hybrid Cloud Console → Insights → Vulnerability → CVEs**.
3. Search each CVE ID and click **Remediate** to create a plan.
4. Apply via **Ansible Automation Platform** or `dnf update --advisory=RHSA-XXXX:XXXX`.
