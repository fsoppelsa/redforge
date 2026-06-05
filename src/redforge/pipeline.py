"""RedForge data pipeline — pull, rdfize, query.

Public API:
  pull(config)             -> dict[str, DataFrame]   join CVE/KEV/MSF data
  build_graph(data, config) -> rdflib.Graph           convert joined data to RDF
  rdfize(data, config)     -> Path                   build_graph + write Turtle
  query(graph, sparql)     -> DataFrame              SPARQL SELECT over the graph
"""

from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from pathlib import Path

import pandas as pd
from rdflib import Graph

from datakit import Pipeline, add_lookup_value, classify_vulnerability, save_csv, select_columns
from datakit.rdfizer import rdfize_product

logger = logging.getLogger(__name__)

_ORDER_BY_RE = re.compile(r"\bORDER\s+BY\b(.*?)(?=\bLIMIT\b|\bOFFSET\b|$)", re.IGNORECASE | re.DOTALL)
_LIMIT_RE = re.compile(r"\bLIMIT\s+(\d+)\b", re.IGNORECASE)
_OFFSET_RE = re.compile(r"\bOFFSET\s+(\d+)\b", re.IGNORECASE)
_ORDER_TERM_RE = re.compile(
    r"""
    (?:
        (?P<direction>ASC|DESC)\s*\(\s*
        (?:(?P<cast>[A-Za-z_][\w-]*:[A-Za-z_][\w-]*)\s*\(\s*)?
        \?(?P<var1>[A-Za-z_]\w*)
        \s*\)?\s*\)
    )
    |
    (?P<plain>\?[A-Za-z_]\w*)
    """,
    re.IGNORECASE | re.VERBOSE,
)


# ── constants ─────────────────────────────────────────────────────────────────

_FINAL_COLUMNS = [
    "cve_id", "cve_url", "public_date", "cvss_score", "rh_severity",
    "in_kev", "kev_date_added", "vuln_name", "in_metasploit", "msf_module_name",
    "in_exploitdb", "exploitdb_id", "exploitdb_title",
    "in_packetstorm", "packetstorm_title", "packetstorm_url",
    "in_github_advisory", "ghsa_id", "ghsa_url",
    "priority_class", "priority_score",
]

_REQUIRED_CACHE_FILES = [
    "kev.json",
    "metasploit.json",
]

_OPTIONAL_CACHE_FILES = [
    "exploitdb.csv",
    "packetstorm.json",
    "github_advisories.json",
    "epss.json",
]


# ── private readers ───────────────────────────────────────────────────────────

def _load_json_file(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON in '{path}': {exc.msg} "
            f"(line {exc.lineno}, column {exc.colno}, char {exc.pos}). "
            f"Re-run Download to refresh the cache."
        ) from exc

def _read_redhat(path: Path) -> pd.DataFrame:
    data = _load_json_file(path)
    if not data:
        return pd.DataFrame(columns=["cve_id", "cve_url", "public_date", "cvss_score", "rh_severity"])
    rows = [
        {
            "cve_id":      cve.get("CVE"),
            "cve_url":     (
                f"https://access.redhat.com/security/cve/{str(cve.get('CVE')).upper()}"
                if cve.get("CVE") else None
            ),
            "public_date": cve.get("public_date"),
            "cvss_score":  cve.get("cvss3_score"),
            "rh_severity": cve.get("severity"),
        }
        for cve in data
    ]
    df = pd.DataFrame(rows)
    df["cve_id"]     = df["cve_id"].astype("string")
    df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce")
    return df


def _read_kev(path: Path) -> pd.DataFrame:
    data = _load_json_file(path)
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return pd.DataFrame(columns=["cve_id", "dateAdded"])
    df = pd.json_normalize(vulns).rename(columns={"cveID": "cve_id"})
    df["cve_id"] = df["cve_id"].astype("string")
    keep = [c for c in ["cve_id", "dateAdded", "vulnerabilityName"] if c in df.columns]
    return select_columns(df, keep)


def _read_metasploit(path: Path) -> pd.DataFrame:
    data = _load_json_file(path)
    modules = data.values() if isinstance(data, dict) else data
    rows: list[dict] = []
    for mod in modules:
        if not isinstance(mod, dict):
            continue
        module_name = mod.get("fullname") or mod.get("name", "")
        for ref in mod.get("references", []):
            if isinstance(ref, str) and ref.upper().startswith("CVE-"):
                rows.append({"cve_id": ref.upper(), "msf_module_name": module_name})
    if not rows:
        logger.warning("No CVE references found in Metasploit metadata.")
        return pd.DataFrame(columns=["cve_id", "msf_module_name"])
    df = pd.DataFrame(rows)
    df["cve_id"] = df["cve_id"].astype("string")
    return df.drop_duplicates(subset=["cve_id"], keep="first").reset_index(drop=True)


def _read_exploitdb(path: Path) -> pd.DataFrame:
    """Read Exploit-DB CSV export and return CVE→Exploit-DB mapping.

    The upstream file is a CSV (e.g. ``files_exploits.csv``) with a CVE field.
    Column names have changed over time; we keep parsing permissive and fall back
    to extracting CVE patterns from the row when necessary.
    """
    # pandas handles large CSVs efficiently; force strings to avoid dtype churn.
    df_raw = pd.read_csv(path, dtype="string", keep_default_na=False, na_values=[])
    if df_raw.empty:
        return pd.DataFrame(columns=["cve_id", "exploitdb_id", "exploitdb_title"])

    # Common column names used by the Exploit-DB export.
    id_col = "id" if "id" in df_raw.columns else ("EDB-ID" if "EDB-ID" in df_raw.columns else None)
    title_col = (
        "description" if "description" in df_raw.columns
        else ("title" if "title" in df_raw.columns else None)
    )
    # Column holding CVE refs is "codes" in modern exports (semicolon-separated),
    # older exports may use "cve" or "CVE".
    cve_col = next(
        (c for c in ("codes", "cve", "CVE") if c in df_raw.columns),
        None,
    )

    def _extract_cves(text: str) -> list[str]:
        # Exploit-DB codes are semicolon-separated (e.g. "CVE-2024-1234;OSVDB-12345").
        import re
        if not text:
            return []
        found = re.findall(r"CVE-\d{4}-\d{4,7}", text.upper())
        # Preserve order, dedupe.
        seen: set[str] = set()
        out: list[str] = []
        for c in found:
            if c not in seen:
                seen.add(c)
                out.append(c)
        return out

    rows: list[dict] = []
    for _, row in df_raw.iterrows():
        raw_cve = str(row.get(cve_col) or "") if cve_col else ""
        cves = _extract_cves(raw_cve)
        if not cves:
            # Fall back: scan the whole row for CVE patterns.
            cves = _extract_cves(" ".join(str(v) for v in row.values if v))
        if not cves:
            continue
        exploitdb_id = str(row.get(id_col) or "") if id_col else ""
        title = str(row.get(title_col) or "") if title_col else ""
        for cve_id in cves:
            rows.append(
                {
                    "cve_id": cve_id,
                    "exploitdb_id": exploitdb_id or pd.NA,
                    "exploitdb_title": title or pd.NA,
                }
            )

    if not rows:
        logger.warning("No CVE references found in the Exploit-DB CSV export.")
        return pd.DataFrame(columns=["cve_id", "exploitdb_id", "exploitdb_title"])

    df = pd.DataFrame(rows)
    df["cve_id"] = df["cve_id"].astype("string")
    return df.drop_duplicates(subset=["cve_id"], keep="first").reset_index(drop=True)


def _read_packetstorm(path: Path) -> pd.DataFrame:
    data = _load_json_file(path)
    if not data:
        return pd.DataFrame(columns=["cve_id", "packetstorm_title", "packetstorm_url"])
    df = pd.DataFrame(data)
    if df.empty:
        return pd.DataFrame(columns=["cve_id", "packetstorm_title", "packetstorm_url"])
    df["cve_id"] = df["cve_id"].astype("string")
    return df.drop_duplicates(subset=["cve_id"], keep="first").reset_index(drop=True)


def _read_github_advisories(path: Path) -> pd.DataFrame:
    data = _load_json_file(path)
    if not data:
        return pd.DataFrame(columns=["cve_id", "ghsa_id", "ghsa_url"])
    df = pd.DataFrame(data)
    if df.empty:
        return pd.DataFrame(columns=["cve_id", "ghsa_id", "ghsa_url"])
    df["cve_id"] = df["cve_id"].astype("string")
    return df.drop_duplicates(subset=["cve_id"], keep="first").reset_index(drop=True)


def _read_epss(path: Path) -> pd.DataFrame:
    data = _load_json_file(path)
    if not data:
        return pd.DataFrame(columns=["cve_id", "epss_score", "epss_percentile"])
    df = pd.DataFrame(data).rename(columns={"epss": "epss_score", "percentile": "epss_percentile"})
    df["cve_id"] = df["cve_id"].astype("string")
    df["epss_score"] = pd.to_numeric(df["epss_score"], errors="coerce")
    df["epss_percentile"] = pd.to_numeric(df["epss_percentile"], errors="coerce")
    return df.drop_duplicates(subset=["cve_id"], keep="first").reset_index(drop=True)


# ── private enrichers ─────────────────────────────────────────────────────────

def _enrich_kev(df: pd.DataFrame, *, kev: pd.DataFrame, **_: object) -> pd.DataFrame:
    if not kev.empty and "dateAdded" in kev.columns:
        df = add_lookup_value(df, kev, "cve_id", "cve_id", "dateAdded", "kev_date_added")
        if "vulnerabilityName" in kev.columns:
            df = add_lookup_value(df, kev, "cve_id", "cve_id", "vulnerabilityName", "vuln_name")
        else:
            df["vuln_name"] = pd.NA
    else:
        df["kev_date_added"] = pd.NA
        df["vuln_name"] = pd.NA
    df["in_kev"] = df["kev_date_added"].notna()
    return df


def _enrich_msf(df: pd.DataFrame, *, msf: pd.DataFrame, **_: object) -> pd.DataFrame:
    if not msf.empty:
        df = add_lookup_value(df, msf, "cve_id", "cve_id", "msf_module_name", "msf_module_name")
    else:
        df["msf_module_name"] = pd.NA
    df["in_metasploit"] = df["msf_module_name"].notna()
    return df


def _enrich_exploitdb(df: pd.DataFrame, *, exploitdb: pd.DataFrame, **_: object) -> pd.DataFrame:
    if not exploitdb.empty:
        df = add_lookup_value(df, exploitdb, "cve_id", "cve_id", "exploitdb_id", "exploitdb_id")
        df = add_lookup_value(df, exploitdb, "cve_id", "cve_id", "exploitdb_title", "exploitdb_title")
    else:
        df["exploitdb_id"] = pd.NA
        df["exploitdb_title"] = pd.NA
    df["in_exploitdb"] = df["exploitdb_id"].notna() | df["exploitdb_title"].notna()
    return df


def _enrich_packetstorm(df: pd.DataFrame, *, packetstorm: pd.DataFrame, **_: object) -> pd.DataFrame:
    if not packetstorm.empty:
        df = add_lookup_value(df, packetstorm, "cve_id", "cve_id", "packetstorm_title", "packetstorm_title")
        df = add_lookup_value(df, packetstorm, "cve_id", "cve_id", "packetstorm_url", "packetstorm_url")
    else:
        df["packetstorm_title"] = pd.NA
        df["packetstorm_url"] = pd.NA
    df["in_packetstorm"] = df["packetstorm_url"].notna() | df["packetstorm_title"].notna()
    return df


def _enrich_github_advisory(df: pd.DataFrame, *, github: pd.DataFrame, **_: object) -> pd.DataFrame:
    if not github.empty:
        df = add_lookup_value(df, github, "cve_id", "cve_id", "ghsa_id", "ghsa_id")
        df = add_lookup_value(df, github, "cve_id", "cve_id", "ghsa_url", "ghsa_url")
    else:
        df["ghsa_id"] = pd.NA
        df["ghsa_url"] = pd.NA
    df["in_github_advisory"] = df["ghsa_id"].notna() | df["ghsa_url"].notna()
    return df


def _enrich_epss(df: pd.DataFrame, *, epss: pd.DataFrame, **_: object) -> pd.DataFrame:
    if not epss.empty:
        df = add_lookup_value(df, epss, "cve_id", "cve_id", "epss_score", "epss_score")
        df = add_lookup_value(df, epss, "cve_id", "cve_id", "epss_percentile", "epss_percentile")
    else:
        df["epss_score"] = pd.NA
        df["epss_percentile"] = pd.NA
    df["epss_score"] = pd.to_numeric(df["epss_score"], errors="coerce").fillna(0.0)
    df["epss_percentile"] = pd.to_numeric(df["epss_percentile"], errors="coerce").fillna(0.0)
    return df

# ── private helpers ───────────────────────────────────────────────────────────

def _iter_products(config: dict):
    """Yield (short, full_name) for every configured product version."""
    for label, info in config.get("products", {}).items():
        if label == "families" or not isinstance(info, dict):
            continue
        name = info["name"]
        for version in info.get("versions", []):
            yield label + version.replace(".", ""), f"{name} {version}"


# ── public API ────────────────────────────────────────────────────────────────

def pull(config: dict) -> dict[str, pd.DataFrame]:
    """Join cached vulnerability data and write one CSV per product.

    Raises FileNotFoundError if required cache files are missing.
    Returns a dict keyed by product short-name.
    """
    pipeline_cfg = config.get("pipeline", {})
    data_dir     = Path(pipeline_cfg.get("data_dir", "data/raw"))

    missing = [
        f for f in _REQUIRED_CACHE_FILES if not (data_dir / f).exists()
    ] + [
        f"redhat_cve_{short}.json"
        for short, _ in _iter_products(config)
        if not (data_dir / f"redhat_cve_{short}.json").exists()
    ]
    if missing:
        raise FileNotFoundError(
            f"Missing cache files: {', '.join(missing)}. "
            f"Run `redforge download` first."
        )

    optional_missing = [
        name for name in _OPTIONAL_CACHE_FILES if not (data_dir / name).exists()
    ]
    if optional_missing:
        logger.warning(
            "Optional enrichment sources are missing and will be skipped: %s",
            ", ".join(optional_missing),
        )

    logger.info("=== join: reading from cached files ===")
    df_kev = _read_kev(data_dir / "kev.json")
    df_msf = _read_metasploit(data_dir / "metasploit.json")
    df_edb = (
        _read_exploitdb(data_dir / "exploitdb.csv")
        if (data_dir / "exploitdb.csv").exists()
        else pd.DataFrame(columns=["cve_id", "exploitdb_id", "exploitdb_title"])
    )
    df_ps  = (
        _read_packetstorm(data_dir / "packetstorm.json")
        if (data_dir / "packetstorm.json").exists()
        else pd.DataFrame(columns=["cve_id", "packetstorm_title", "packetstorm_url"])
    )
    df_gh  = (
        _read_github_advisories(data_dir / "github_advisories.json")
        if (data_dir / "github_advisories.json").exists()
        else pd.DataFrame(columns=["cve_id", "ghsa_id", "ghsa_url"])
    )
    df_epss = (
        _read_epss(data_dir / "epss.json")
        if (data_dir / "epss.json").exists()
        else pd.DataFrame(columns=["cve_id", "epss_score", "epss_percentile"])
    )
    logger.info(
        "  kev=%d msf=%d edb=%d packetstorm=%d github=%d epss=%d mappings",
        len(df_kev), len(df_msf), len(df_edb), len(df_ps), len(df_gh), len(df_epss),
    )

    results: dict[str, pd.DataFrame] = {}
    for short, name in _iter_products(config):
        logger.info("Processing product: %s ...", name)
        result = (
            Pipeline()
            .source("kev", df_kev)
            .source("msf", df_msf)
            .source("exploitdb", df_edb)
            .source("packetstorm", df_ps)
            .source("github", df_gh)
            .source("epss", df_epss)
            .read(_read_redhat, data_dir / f"redhat_cve_{short}.json")
            .enrich(_enrich_kev)
            .enrich(_enrich_msf)
            .enrich(_enrich_exploitdb)
            .enrich(_enrich_packetstorm)
            .enrich(_enrich_github_advisory)
            .enrich(_enrich_epss)
            .process(classify_vulnerability)
            .process(select_columns, columns=_FINAL_COLUMNS)
            .write(save_csv, path=data_dir / f"{short}.csv")
            .run()
        )
        df = result.df
        logger.info(
            "  %s: kev=%d msf=%d edb=%d ps=%d gh=%d",
            short,
            df["in_kev"].sum(),
            df["in_metasploit"].sum(),
            df["in_exploitdb"].sum(),
            df["in_packetstorm"].sum(),
            df["in_github_advisory"].sum(),
        )
        results[short] = df

    logger.info("=== join complete: %d products ===", len(results))
    return results


def build_graph(data: dict[str, pd.DataFrame], config: dict) -> Graph:
    """Convert all products' DataFrames into a single merged RDF Graph."""
    combined = Graph()
    for short, df in data.items():
        combined += rdfize_product(df, product=short)
    logger.info("Graph built: %d triples across %d products", len(combined), len(data))
    return combined


def rdfize(data: dict[str, pd.DataFrame], config: dict) -> Path:
    """Build the RDF graph and serialise it to Turtle; return the output path."""
    pipeline_cfg = config.get("pipeline", {})
    rdf_dir = Path(pipeline_cfg.get("rdf_dir", "data/rdf"))
    rdf_dir.mkdir(parents=True, exist_ok=True)
    out_path = rdf_dir / "redforge.ttl"
    build_graph(data, config).serialize(destination=str(out_path), format="turtle")
    logger.info("Serialised graph to %s", out_path)
    return out_path


@lru_cache(maxsize=2)
def _load_graph_cached(ttl_path_str: str, mtime_ns: int, size: int) -> Graph:
    g = Graph()
    g.parse(ttl_path_str, format="turtle")
    return g


def load_graph(config: dict) -> Graph:
    """Load the serialised RDF graph from the configured rdf_dir."""
    pipeline_cfg = config.get("pipeline", {})
    ttl_path = Path(pipeline_cfg.get("rdf_dir", "data/rdf")) / "redforge.ttl"
    if not ttl_path.exists():
        raise FileNotFoundError(
            f"RDF graph not found at '{ttl_path}'. Run: redforge ingest"
        )
    stat = ttl_path.stat()
    return _load_graph_cached(str(ttl_path), stat.st_mtime_ns, stat.st_size)


def _results_to_dataframe(results) -> pd.DataFrame:
    if not results.vars:
        return pd.DataFrame()
    cols = [str(v) for v in results.vars]
    rows = [
        {col: (str(val) if val is not None else None) for col, val in zip(cols, row)}
        for row in results
    ]
    return pd.DataFrame(rows, columns=cols)


def _extract_order_limit_offset(sparql: str) -> tuple[str | None, int | None, int]:
    order_match = _ORDER_BY_RE.search(sparql)
    order_clause = order_match.group(1).strip() if order_match else None
    limit_match = _LIMIT_RE.search(sparql)
    offset_match = _OFFSET_RE.search(sparql)
    limit = int(limit_match.group(1)) if limit_match else None
    offset = int(offset_match.group(1)) if offset_match else 0
    return order_clause, limit, offset


def _strip_order_limit_offset(sparql: str) -> str:
    stripped = _ORDER_BY_RE.sub(" ", sparql)
    stripped = _LIMIT_RE.sub(" ", stripped)
    stripped = _OFFSET_RE.sub(" ", stripped)
    return " ".join(stripped.split())


def _sort_dataframe(df: pd.DataFrame, order_clause: str | None) -> pd.DataFrame:
    if df.empty or not order_clause:
        return df

    sort_columns: list[str] = []
    ascending: list[bool] = []
    work = df.copy()

    for idx, match in enumerate(_ORDER_TERM_RE.finditer(order_clause)):
        direction = (match.group("direction") or "ASC").upper()
        var_name = match.group("var1") or ((match.group("plain") or "")[1:])
        cast = (match.group("cast") or "").lower()
        if not var_name or var_name not in work.columns:
            continue

        temp_col = f"__sort_{idx}_{var_name}"
        series = work[var_name]
        numeric = pd.to_numeric(series, errors="coerce")
        use_numeric = False
        if cast:
            use_numeric = cast.endswith(("integer", "decimal", "double", "float"))
        elif series.notna().any():
            use_numeric = numeric.notna().sum() == series.notna().sum()

        work[temp_col] = numeric if use_numeric else series
        sort_columns.append(temp_col)
        ascending.append(direction != "DESC")

    if not sort_columns:
        return df

    work = work.sort_values(sort_columns, ascending=ascending, na_position="last", kind="stable")
    return work[df.columns].reset_index(drop=True)


def query(graph: Graph, sparql: str) -> pd.DataFrame:
    """Execute a SPARQL SELECT over *graph* and return results as a DataFrame."""
    caught_exc: TypeError | None = None
    try:
        return _results_to_dataframe(graph.query(sparql))
    except TypeError as exc:
        # rdflib can fail when ORDER BY compares mixed/unbound values.
        if "supported between instances" not in str(exc):
            raise
        caught_exc = exc

    order_clause, limit, offset = _extract_order_limit_offset(sparql)
    if not order_clause:
        assert caught_exc is not None
        raise caught_exc

    df = _results_to_dataframe(graph.query(_strip_order_limit_offset(sparql)))
    df = _sort_dataframe(df, order_clause)
    if offset:
        df = df.iloc[offset:]
    if limit is not None:
        df = df.iloc[:limit]
    return df.reset_index(drop=True)
