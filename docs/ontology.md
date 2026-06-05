# RedForge Ontology

The OWL ontology is defined in `src/redforge/ontology/vuln.ttl`.

## Core concept

Everything centres on the `vs:Vulnerability` class. A vulnerability affects one or more products, carries a CVSS severity metric, and may have associated KEV entries and public exploits.

## Main classes

| Class | Description |
|-------|-------------|
| `vs:Vulnerability` | A CVE entry |
| `vs:CVSSMetric` | CVSS score record (BNode, attached via `vs:hasCvssMetric`) |
| `vs:KEVEntry` | CISA KEV entry (attached via `vs:hasKEVEntry`) |
| `vs:ExploitModule` | Exploit module from Metasploit, Exploit-DB, PacketStorm, or GHSA |
| `vs:Product` | Affected product (e.g. `vs:product-rhel9`) |
| `vs:Severity` | Controlled severity vocabulary (Low, Medium, High, Critical) |
| `vs:UpstreamProject` | The upstream software project related to a vulnerability |
| `vs:ReleaseLine` | A specific release line of a product |

## Class hierarchies

### Vulnerability subclasses

- `vs:ActivelyExploitedVulnerability` — has a linked exploit or KEV entry
- `vs:LatentVulnerability` — no known active exploitation

### CVSS metric subclasses

- `vs:CVSSv2Metric`
- `vs:CVSSv3Metric`
- `vs:CVSSv4Metric`

### Product subclasses

- `vs:OperatingSystem` (e.g. RHEL)
- `vs:Middleware`
- `vs:ContainerPlatform` (e.g. OpenShift)
- `vs:AutomationPlatform` (e.g. Ansible Automation Platform)
- `vs:OtherProduct`

### Exploit subclasses

- `vs:MetasploitModule`
- `vs:ExploitDBEntry`
- `vs:PacketStormEntry`
- `vs:GHSAEntry`

## Properties

### Object properties

| Property | Domain | Range | Inverse |
|----------|--------|-------|---------|
| `vs:affectsProduct` | `vs:Vulnerability` | `vs:Product` | `vs:isAffectedBy` |
| `vs:hasCvssMetric` | `vs:Vulnerability` | `vs:CVSSMetric` | `vs:isMetricOf` |
| `vs:hasKEVEntry` | `vs:Vulnerability` | `vs:KEVEntry` | `vs:isKEVEntryOf` |
| `vs:hasExploit` | `vs:Vulnerability` | `vs:ExploitModule` | `vs:isExploitFor` |
| `vs:relatedToUpstream` | `vs:Vulnerability` | `vs:UpstreamProject` | `vs:hasVulnerability` |
| `vs:belongsToRelease` | `vs:Product` | `vs:ReleaseLine` | — |

### Datatype properties

| Property | Domain | Range |
|----------|--------|-------|
| `dcterms:identifier` | `vs:Vulnerability` | `xsd:string` (CVE ID) |
| `dcterms:issued` | `vs:Vulnerability` | `xsd:date` |
| `rdfs:label` | `vs:ExploitModule`, `vs:Product` | `xsd:string` |
| `rdfs:seeAlso` | `vs:Vulnerability` | `xsd:anyURI` (Red Hat CVE URL) |
| `vs:baseScore` | `vs:CVSSMetric` | `xsd:decimal` |
| `vs:severity` | `vs:Vulnerability` | `vs:Severity` |
| `vs:priorityClass` | `vs:Vulnerability` | `xsd:string` (1-Act, 2-Attend, etc.) |
| `vs:priorityScore` | `vs:Vulnerability` | `xsd:integer` |
| `vs:version` | `vs:Product`, `vs:ReleaseLine` | `xsd:string` |
| `dcterms:date` | `vs:KEVEntry` | `xsd:date` |

## Severity vocabulary (controlled)

| Individual | URI |
|------------|-----|
| No Severity | `vs:NoneSeverity` |
| Low | `vs:LowSeverity` |
| Medium | `vs:MediumSeverity` |
| High | `vs:HighSeverity` |
| Critical | `vs:CriticalSeverity` |

Owl:oneOf enumeration on `vs:Severity`.

## OWL restrictions

- `vs:Vulnerability` has `minCardinality 1` on `vs:hasCvssMetric`
- `vs:CVSSMetric` has `cardinality 1` on `vs:baseScore`
- `vs:ReleaseLine` has `cardinality 1` on `vs:version`
- Disjointness: sibling classes (e.g. `vs:CVSSv2Metric` disjoint from `vs:CVSSv3Metric`)

## Namespace prefixes

| Prefix | URI |
|--------|-----|
| `vs:` | `http://redforge.local/ontology#` |
| `res:` | `http://redforge.local/resource/` |
| `dcterms:` | `http://purl.org/dc/terms/` |
| `xsd:` | `http://www.w3.org/2001/XMLSchema#` |
| `rdfs:` | `http://www.w3.org/2000/01/rdf-schema#` |
