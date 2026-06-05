# MCP Server API Reference

RedForge exposes a Model Context Protocol (MCP) server that AI assistants and tooling can use to query vulnerability data and trigger remediation.

## Transport

- **stdio** — for Claude Desktop and local assistants
- **HTTP** — for containerized deployment (port 8000)
- **SSE** — Server-Sent Events transport

## Tools

### `list_products`

List all configured Red Hat products and their available versions.

**Returns:** `{"rhel": {"name": "Red Hat Enterprise Linux", "versions": ["8", "9", "10"]}, ...}`

### `query`

Query priority-ranked CVEs from the knowledge graph.

| Arg | Type | Default | Description |
| --- | ---- | ------- | ----------- |
| `product` | str | `"all"` | Product label (e.g. `"rhel"`, `"ocp"`) |
| `version` | str | `"all"` | Version string (e.g. `"9"`, `"4.17"`) |
| `min_cvss` | float | `0.0` | Minimum CVSS score 0.0–10.0 |
| `severity` | str | `"low"` | Minimum severity: low, medium, high, critical |
| `sort_by` | str | `"priority"` | Sort: priority, cvss, cve_id, public_date |
| `limit` | int | `50` | Max rows to return |

**Returns:** JSON array of CVE result rows.

### `suggest`

Return highest-priority CVEs affecting a CycloneDX SBOM estate.

| Arg | Type | Default | Description |
| --- | ---- | ------- | ----------- |
| `sbom` | dict | _required_ | CycloneDX JSON SBOM object |
| `top_n` | int | `25` | Number of CVEs to return |

**Returns:** JSON with `summary`, `items`, and `diagnostics`.

### `suggest_v2`

Generate a CycloneDX SBOM with syft, then return prioritized CVEs. Extends `suggest` by auto-generating the SBOM from a live target (SSH host, container image, or local path).

**Cached results are returned instantly** on repeated calls for the same target. Pass `force=true` to re-run syft.

**Non-blocking:** If no cached SBOM exists, the scan runs in the background and this call returns immediately with a `job_id`. Poll `suggest_v2_status` to retrieve the result when ready.

| Arg | Type | Default | Description |
| --- | ---- | ------- | ----------- |
| `target` | str | _required_ | SSH target (`user@host`), container image ref, or local path |
| `target_type` | str | `null` | `"ssh"`, `"image"`, or `"path"`. Auto-detected if omitted |
| `top_n` | int | `25` | Number of CVEs to return |
| `scan_path` | str | `"/"` | Directory to scan on SSH targets |
| `timeout` | int | `0` | Syft scan timeout in seconds (0 = use `SYFT_TIMEOUT` env, default 600s) |
| `force` | bool | `false` | Re-run syft even if a cached SBOM exists |
| `debug_save_path` | str | `null` | Write raw SBOM JSON to this path for inspection |

**Returns (cache hit):** Same structure as `suggest` plus a `scan_metadata` block.

**Returns (cache miss — background scan started):**
```json
{
  "status": "scanning",
  "job_id": "uuid",
  "cache_file": "/tmp/redforge-sbom/...",
  "message": "Scan started in background. Call suggest_v2_status with this job_id to check progress."
}
```

**SSH notes:** The private key is read from the `SSH_KEY_PATH` env var. The remote user must have passwordless sudo for syft to read the full filesystem.

### `suggest_v2_status`

Check the status of a background `suggest_v2` scan.

| Arg | Type | Default | Description |
| --- | ---- | ------- | ----------- |
| `job_id` | str | _required_ | The `job_id` returned by `suggest_v2` |

**Returns while running:**
```json
{"status": "running", "job_id": "uuid", "elapsed_seconds": 42.5}
```

**Returns when complete:**
```json
{"status": "done", "job_id": "uuid", "summary": {...}, "items": [...], "diagnostics": {...}, "scan_metadata": {...}}
```

**Returns on error:**
```json
{"status": "error", "job_id": "uuid", "error": true, "stage": "sbom_generation", "message": "..."}
```

**Note:** Job state is held in memory — jobs are lost if the MCP pod restarts. Once `status=done`, the SBOM is cached on disk and a subsequent `suggest_v2` call returns instantly without starting a new scan.

### `download`

Fetch CVE/KEV/Metasploit/ExploitDB/EPSS sources into local cache.

| Arg | Type | Default | Description |
| --- | ---- | ------- | ----------- |
| `force` | bool | `false` | Re-download even if already cached |

**Returns:** `{"redhat_cve_rhel8": "/path/to/file.json", ...}`

### `ingest`

Join all data sources and convert to RDF knowledge graph. Requires `download` first.

**Returns:** `{"rhel8": 1234, "rhel9": 5678, ...}` — CVE count per product.

### `export_report`

Export a JSON report of highest-priority actionable CVEs for the Red Hat Console.

| Arg | Type | Default | Description |
| --- | ---- | ------- | ----------- |
| `priority_threshold` | str | `"Attend"` | Act, Attend, Track, or Defer |
| `top_n` | int | `50` | Max CVEs to include |
| `product` | str | `"all"` | Product label (e.g. `"rhel"`, `"ocp"`) |

**Returns:** `{"generated_at": "...", "priority_threshold": "Attend", "cve_count": 25, "summary_by_priority": {"1-Act": 5, "2-Attend": 20}, "items": [...], "instructions": "..."}`

### `sparql_query`

Run a SPARQL SELECT against the RDF knowledge graph.

| Arg | Type | Default | Description |
| --- | ---- | ------- | ----------- |
| `query` | str | _required_ | SPARQL 1.1 SELECT query |

**Returns:** JSON array of result rows.

### `plan_insights`

Create a Red Hat Insights remediation plan for a list of CVEs on a registered host.

Resolves the host FQDN to an Insights inventory UUID, checks which of the requested CVEs affect that system and have a package-level fix available, then creates a remediation plan for the actionable subset. CVEs that don't apply or have no fix are reported in `skipped` — never silently dropped.

Requires `RH_OFFLINE_TOKEN` to be set (injected from the `redforge-rh-offline-token` Secret).

| Arg | Type | Default | Description |
| --- | ---- | ------- | ----------- |
| `cves` | list | _required_ | List of `{"cve_id": "CVE-XXXX-YYYY"}` objects |
| `target_host` | str | _required_ | FQDN as it appears in the Insights inventory (e.g. `rhel8-redforge.internal`) |

**Returns:**
```json
{
  "remediation_id": "uuid",
  "system_uuid": "uuid",
  "matched": [{"cve_id": "CVE-2025-39981", "issue_id": "vulnerabilities:CVE-2025-39981"}],
  "skipped": [{"cve_id": "CVE-2021-4034", "reason": "not applicable to this system per Vulnerability API"}],
  "coverage_summary": {"requested": 3, "matched": 2, "skipped": 1}
}
```

### `remediate_insights`

Execute or validate a Red Hat Insights remediation plan created by `plan_insights`.

Triggers an Ansible playbook run via the RHC-connected host and polls until the run reaches a terminal state (success / failure / canceled) or the poll timeout expires.

Requires `RH_OFFLINE_TOKEN` and the target host to be connected via `rhc` (`rhc status` on the host).

| Arg | Type | Default | Description |
| --- | ---- | ------- | ----------- |
| `remediation_id` | str | _required_ | UUID returned by `plan_insights` |
| `dry_run` | bool | `false` | Validate the plan is runnable without dispatching anything |

**Returns (dry_run=true):**
```json
{
  "dry_run": true,
  "remediation_id": "uuid",
  "runnable": true,
  "name": "redforge-20260603T154441Z",
  "issue_count": 3,
  "system_count": 1,
  "archived": false,
  "message": "Plan is runnable.",
  "console_url": "https://console.redhat.com/insights/remediations/uuid"
}
```

**Returns (live run):**
```json
{
  "run_id": "uuid",
  "status": "success",
  "started_at": "2026-06-03T15:44:41Z",
  "finished_at": "2026-06-03T15:46:12Z",
  "console_url": "https://console.redhat.com/insights/remediations/uuid"
}
```

### `whoami_session`

Return the active MCP process identity and logging context.

**Returns:** `{"pid": 12345, "cwd": "...", "transport": "stdio", ...}`

## Resources

### `redforge://ontology`

The full OWL ontology in Turtle format. Read this before writing SPARQL queries.

## Example SPARQL queries

Critical CVEs in KEV with a Metasploit module:

```sparql
PREFIX vs:  <http://redforge.local/ontology#>
PREFIX dct: <http://purl.org/dc/terms/>
SELECT ?id ?product WHERE {
  ?cve a vs:Vulnerability ;
       dct:identifier ?id ;
       vs:severity vs:CriticalSeverity ;
       vs:affectsProduct ?product ;
       vs:hasKEVEntry ?kev ;
       vs:hasExploit ?exploit .
}
```

Top RHEL 10 vulnerabilities by CVSS:

```sparql
PREFIX vs:  <http://redforge.local/ontology#>
PREFIX dct: <http://purl.org/dc/terms/>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
SELECT ?cveId ?cvss WHERE {
  ?cve a vs:Vulnerability ;
       dct:identifier ?cveId ;
       vs:affectsProduct vs:product-rhel10 ;
       vs:hasCvssMetric ?metric .
  ?metric vs:baseScore ?cvss .
}
ORDER BY DESC(xsd:decimal(?cvss))
LIMIT 25
```
