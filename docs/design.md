# RedForge Design

## Goal

RedForge collects, normalizes, and enriches open vulnerability data for Red Hat products to support **patching prioritization** and **automated remediation**.

## Architecture (4 layers)

### 1. Acquisition

Fetches raw data from configured sources and caches locally:

- Red Hat CVE API (per-product, paginated)
- CISA KEV catalog
- Metasploit modules metadata
- Exploit-DB CSV export
- Packet Storm XML feed
- GitHub Advisory Database
- EPSS scores

Files are stored in `data/raw/`.

### 2. Enrichment

Joins sources on CVE ID and adds operational signals:

- KEV entry presence and date
- Public exploit availability (Metasploit, ExploitDB, PacketStorm, GHSA)
- EPSS score and percentile
- CVSS base score

The datakit pipeline framework handles the fluent chaining: `read -> enrich -> process -> write -> rdfize`.

### 3. Semantic layer

The joined data is converted to RDF/Turtle using an OWL ontology defined in `src/redforge/ontology/vuln.ttl`. The graph is loaded into a Virtuoso triplestore for SPARQL querying, with `rdflib` as a local fallback.

The ontology defines:
- Core classes: `Vulnerability`, `Product`, `CVSSMetric`, `ExploitModule`, `KEVEntry`
- Controlled severity vocabulary: Low, Medium, High, Critical
- Priority classification: 1-Act, 2-Attend, 3-Track, 4-Defer

### 4. Application interfaces

- **CLI** (`redforge.py`) — download, ingest, query, suggest, MCP server
- **Dashboard** (`app.py`, Streamlit) — interactive query, SBOM suggest, SPARQL editor, manage
- **MCP server** (`src/redforge/mcp.py`) — 8 tools + 1 resource, stdio and HTTP transports

## Data pipeline

```
download  →  pull  →  rdfize  →  query
```

### download

Fetches remote sources. Red Hat CVE data is fetched per-product (one JSON per product version).

### pull (join)

Reads all cached sources, enriches CVE records with KEV/exploit/EPSS data, classifies each CVE using the SSVC-inspired algorithm, and writes per-product CSV files to `data/raw/{product_short}.csv`.

### rdfize

Converts all product DataFrames into a single merged RDF Graph and serializes to `data/rdf/redforge.ttl`.

### query

Two query paths:
- **DataFrame path** (dashboard): reads CSVs directly for interactive responsiveness.
- **SPARQL path** (CLI, MCP): queries the RDF graph via `rdflib` or Virtuoso endpoint.

## Priority classification

Uses an SSVC-inspired decision tree (arXiv:2506.01220v1):

| Class | Condition |
|-------|-----------|
| 1-Act | (KEV or EPSS >= 0.088) AND CVSS >= 7 |
| 2-Attend | High threat w/ CVSS < 7, or medium EPSS w/ CVSS >= 7 |
| 3-Track | No threat signal, CVSS >= 7 |
| 4-Defer | Low threat and CVSS < 7 |

## Containerized stack

Defined in `podman-compose.yml`:

| Service | Role | Port |
|---------|------|------|
| `redforge-web` | Streamlit dashboard | 8501 |
| `redforge-mcp` | MCP server (HTTP) | 8000 |
| `virtuoso` | RDF triplestore | 8890, 1111 |
| `pellet` | Optional OWL reasoner | — |

Managed via `scripts/stack.py`.

## Red Hat Insights integration

The `src/redforge/insights.py` module provides:
- System inventory querying
- CVE-to-system mapping
- Advisory (RHSA) lookup

Authenticated via Red Hat SSO offline token.

## Remediation workflow

RedForge exports a JSON report of actionable CVEs via the `export_report` MCP tool or CLI. Red Hat's native toolchain handles remediation: Insights identifies affected systems, Ansible Automation Platform generates playbooks, and `dnf update --advisory` applies fixes.

## Key design choices

- **Dual query paths**: DataFrame for dashboard speed, SPARQL for semantic depth.
- **Virtuoso as triplestore**: Real SPARQL endpoint with HTTP access; `rdflib` as local fallback.
- **SSVC-inspired prioritization**: More operationally useful than CVSS alone.
- **MCP as integration interface**: AI assistants can query CVEs, run batch operations, and trigger remediation.
