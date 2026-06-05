"""Query priority-ranked CVEs from the RDF knowledge graph."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
from datakit.processors.ranking import rank_vulnerabilities
from datakit.processors.scoring import compute_vulnerability_score

from redforge.pipeline import load_graph, query as run_sparql_query

_SEVERITY_INCLUDE: dict[str, set[str]] = {
    "low":      {"low", "moderate", "important", "critical"},
    "medium":   {"moderate", "important", "critical"},
    "high":     {"important", "critical"},
    "critical": {"critical"},
}

_SEVERITY_URIS: dict[str, tuple[str, ...]] = {
    "low": (
        "http://redforge.local/ontology#LowSeverity",
        "http://redforge.local/ontology#MediumSeverity",
        "http://redforge.local/ontology#HighSeverity",
        "http://redforge.local/ontology#CriticalSeverity",
    ),
    "medium": (
        "http://redforge.local/ontology#MediumSeverity",
        "http://redforge.local/ontology#HighSeverity",
        "http://redforge.local/ontology#CriticalSeverity",
    ),
    "high": (
        "http://redforge.local/ontology#HighSeverity",
        "http://redforge.local/ontology#CriticalSeverity",
    ),
    "critical": (
        "http://redforge.local/ontology#CriticalSeverity",
    ),
}

def normalize_sparql_input(sparql: str) -> str:
    """Normalize common accidental shell escapes in copied SPARQL."""
    return (
        sparql
        .replace(r"\#", "#")
        .replace(r"\>", ">")
        .replace(r"\<", "<")
    )


def _resolve_product_shorts(config: dict, product: str, version: str) -> list[str]:
    """Return the product short names to query."""
    products = {
        label: info
        for label, info in config.get("products", {}).items()
        if label != "families" and isinstance(info, dict)
    }

    if product == "all":
        return [
            label + v.replace(".", "")
            for label, info in products.items()
            for v in info.get("versions", [])
        ]

    if product not in products:
        raise ValueError(f"Product '{product}' not found in config.")

    versions = products[product].get("versions", [])

    if version == "all":
        return [product + v.replace(".", "") for v in versions]

    if version not in versions:
        raise ValueError(f"Version '{version}' not found for '{product}'.")
    return [product + version.replace(".", "")]


def _build_query_sparql(
    *,
    product_shorts: list[str],
    min_cvss: float,
    severity: str,
) -> str:
    if not product_shorts:
        return ""

    severity_key = severity.lower()
    if severity_key not in _SEVERITY_URIS:
        raise ValueError(f"Unsupported severity '{severity}'. Use low, medium, high, or critical.")

    product_values = " ".join(f"vs:product-{short}" for short in product_shorts)
    severity_values = " ".join(f"<{uri}>" for uri in _SEVERITY_URIS[severity_key])

    return f"""
PREFIX vs:  <http://redforge.local/ontology#>
PREFIX dct: <http://purl.org/dc/terms/>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>

SELECT
  ?cve_id
  (SAMPLE(?cve_url0) AS ?cve_url)
  (SAMPLE(?public_date0) AS ?public_date)
  (MAX(xsd:decimal(?cvss0)) AS ?cvss)
  (REPLACE(LCASE(STRAFTER(STR(SAMPLE(?severity_uri)), "#")), "severity", "") AS ?severity)
  (SAMPLE(?priority_class0) AS ?priority_class)
  (MAX(xsd:decimal(?priority_score0)) AS ?priority_score)
  (IF(COUNT(?kev) > 0, true, false) AS ?is_kev)
  (IF(COUNT(?exploit) > 0, true, false) AS ?has_public_exploit)
WHERE {{
  VALUES ?product {{ {product_values} }}
  VALUES ?severity_uri {{ {severity_values} }}

  ?cve a vs:Vulnerability ;
       dct:identifier ?cve_id ;
       vs:affectsProduct ?product ;
       vs:severity ?severity_uri ;
       vs:hasCvssMetric ?metric .

  ?metric vs:baseScore ?cvss0 .

  FILTER(xsd:decimal(?cvss0) >= {min_cvss:.1f})

  OPTIONAL {{ ?cve rdfs:seeAlso ?cve_url0 . }}
  OPTIONAL {{ ?cve dct:issued ?public_date0 . }}
  OPTIONAL {{ ?cve vs:priorityClass ?priority_class0 . }}
  OPTIONAL {{ ?cve vs:priorityScore ?priority_score0 . }}
  OPTIONAL {{ ?cve vs:hasKEVEntry ?kev . }}
  OPTIONAL {{ ?cve vs:hasExploit ?exploit . }}
}}
GROUP BY ?cve_id
""".strip()


def run_query(
    config: dict,
    product: str = "all",
    version: str = "all",
    min_cvss: float = 0.0,
    severity: str = "low",
    sort_by: str = "priority",
    graph=None,
    product_shorts: list[str] | None = None,
) -> pd.DataFrame:
    """Query CVEs from the RDF graph and return a DataFrame.

    Columns: cve_id, cve_url, cvss, severity, is_kev, public_date, risk_score (priority_class prepended when available).
    """
    shorts = product_shorts if product_shorts is not None else _resolve_product_shorts(config, product, version)
    graph = graph if graph is not None else load_graph(config)
    sparql = _build_query_sparql(product_shorts=shorts, min_cvss=min_cvss, severity=severity)
    if not sparql:
        return pd.DataFrame(
            columns=["cve_id", "cve_url", "cvss", "severity", "is_kev", "public_date", "risk_score"]
        )
    df = run_sparql_query(graph, sparql)
    return _finalize_query_results(df, sort_by=sort_by)


def run_query_dataframe(
    config: dict,
    product: str = "all",
    version: str = "all",
    min_cvss: float = 0.0,
    severity: str = "low",
    sort_by: str = "priority",
    product_shorts: list[str] | None = None,
) -> pd.DataFrame:
    """Load joined CVEs from cached CSV files and return a DataFrame.

    This path is kept for interactive UI responsiveness while the SPARQL-backed
    query path is used by CLI/MCP and semantic flows.
    """
    data_dir = Path(config.get("pipeline", {}).get("data_dir", "data/raw"))
    shorts = product_shorts if product_shorts is not None else _resolve_product_shorts(config, product, version)

    frames: list[pd.DataFrame] = []
    for short in shorts:
        csv_path = data_dir / f"{short}.csv"
        if not csv_path.exists():
            raise FileNotFoundError(
                f"Data for '{short}' not found in '{data_dir}'. "
                f"Run `redforge ingest` first."
            )
        df = pd.read_csv(
            csv_path,
            dtype={"in_kev": bool, "in_metasploit": bool},
        )
        frames.append(df)

    if not frames:
        return pd.DataFrame(
            columns=["cve_id", "cve_url", "cvss", "severity", "is_kev", "public_date", "risk_score"]
        )

    df = pd.concat(frames).drop_duplicates("cve_id").reset_index(drop=True)
    df = df.rename(columns={
        "cvss_score": "cvss",
        "rh_severity": "severity",
        "in_kev": "is_kev",
    })

    allowed = _SEVERITY_INCLUDE.get(severity.lower(), set())
    df = df[df["severity"].str.lower().isin(allowed)]
    df = df[df["cvss"] >= min_cvss]

    return _finalize_query_results(df, sort_by=sort_by)


def _finalize_query_results(df: pd.DataFrame, sort_by: str = "priority") -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(
            columns=["cve_id", "cve_url", "cvss", "severity", "is_kev", "public_date", "risk_score"]
        )

    result = df.copy()
    result["cvss"] = pd.to_numeric(result["cvss"], errors="coerce")
    for bool_col in ("is_kev", "has_public_exploit"):
        if bool_col in result.columns:
            result[bool_col] = result[bool_col].astype(str).str.lower().map({"true": True, "false": False})
            result[bool_col] = result[bool_col].fillna(False).astype(bool)
    if "priority_score" in result.columns:
        result["priority_score"] = pd.to_numeric(result["priority_score"], errors="coerce")
    result = compute_vulnerability_score(
        result.rename(columns={"cvss": "cvss_score"}),
        cvss_column="cvss_score",
        kev_column="is_kev",
        score_column="risk_score",
    ).rename(columns={"cvss_score": "cvss"})

    # priority_score is authoritative; priority_class (prefixed "1-Act" etc.) is the second fallback; risk_score is legacy
    has_score = "priority_score" in result.columns
    has_class = "priority_class" in result.columns
    rank_col = "priority_score" if has_score else "risk_score"
    result = rank_vulnerabilities(
        result,
        score_column=rank_col,
        rank_column="priority_rank",
        ascending=False,
    )

    sort_key = sort_by.lower()
    if sort_key == "cvss":
        result = result.sort_values(["cvss", "priority_rank", "cve_id"], ascending=[False, True, True], kind="stable")
    elif sort_key == "cve_id":
        result = result.sort_values(["cve_id", "priority_rank"], ascending=[True, True], kind="stable")
    elif sort_key == "public_date":
        result = result.sort_values(["public_date", "priority_rank", "cvss"], ascending=[False, True, False], kind="stable")
    else:
        if has_score:
            result = result.sort_values(
                ["priority_score", "cvss", "is_kev", "cve_id"],
                ascending=[False, False, False, True],
                kind="stable",
            )
        elif has_class:
            # seconda finalizazione (frame multi-versione): priority_score già eliminato,
            # ma priority_class con prefisso numerico ordina correttamente come stringa
            result = result.sort_values(
                ["priority_class", "cvss", "is_kev", "cve_id"],
                ascending=[True, False, False, True],
                kind="stable",
            )
        else:
            result = result.sort_values(
                ["priority_rank", "risk_score", "is_kev", "cvss", "cve_id"],
                ascending=[True, False, False, False, True],
                kind="stable",
            )

    base_cols = [
        "priority_rank", "priority_class", "priority_score", "cve_id", "vuln_name",
        "cve_url", "cvss", "severity", "is_kev", "has_public_exploit",
        "public_date", "risk_score", "matched_components", "affected_packages",
        "matched_component_count", "affected_package_count",
    ]
    cols = [col for col in base_cols if col in result.columns]
    return result[cols].reset_index(drop=True)
