"""RedForge — Streamlit dashboard."""

from __future__ import annotations

import datetime
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

import base64

import altair as alt
import pandas as pd
import requests
import streamlit as st

try:
    from streamlit_ace import st_ace
except ImportError:
    st_ace = None

from redforge.config import load as load_config
from redforge.commands.query import run_query_dataframe
from redforge.commands.suggest import run_suggest, suggest_from_sbom
from redforge.commands.sync import run_sync
from redforge.sbom import parse_cyclonedx_sbom

_CONFIG_PATH    = os.environ.get("REDFORGE_CONFIG", "redforge.toml")
_LOGO_SVG_PATH  = Path(__file__).parent / "docs" / "img" / "redforge_logo.svg"

_PRIORITY_ORDER  = ["1-Act", "2-Attend", "3-Track", "4-Defer"]
_PRIORITY_COLORS = ["#d62728", "#ff7f0e", "#f5c400", "#2ca02c"]
_PRIORITY_SHORT  = ["Act", "Attend", "Track", "Defer"]

# Vega-Lite JS expression to show short labels on axes
_LABEL_EXPR = (
    "datum.value === '1-Act'    ? 'Act'    : "
    "datum.value === '2-Attend' ? 'Attend' : "
    "datum.value === '3-Track'  ? 'Track'  : "
    "datum.value === '4-Defer'  ? 'Defer'  : datum.value"
)

# Session-state keys for the two interactive charts
_BAR_KEY   = "vs_priority_bar"
_PIE_KEY   = "vs_priority_pie"
_PILLS_KEY = "vs_priority_pills"
_SPARQL_EDITOR_KEY = "vs_sparql_editor_value"
_SPARQL_EDITOR_REV_KEY = "vs_sparql_editor_rev"
_SPARQL_ENDPOINT = os.environ.get("REDFORGE_SPARQL_ENDPOINT", "http://127.0.0.1:8890/sparql")
_SPARQL_GRAPH_URI = os.environ.get("REDFORGE_SPARQL_GRAPH", "http://redforge.local/graph/main")


@st.cache_data
def _config() -> dict:
    return load_config(_CONFIG_PATH)


_EXPLOIT_COLS = {"in_metasploit", "in_exploitdb", "in_kev", "in_packetstorm"}

@st.cache_data
def _data_stats(data_dir_str: str, csv_signature: tuple[tuple[str, int, int], ...]) -> tuple[int, int]:
    """Return (unique_cves, unique_kev_cves) across all product CSVs."""
    data_dir = Path(data_dir_str)
    all_cves: set[str] = set()
    kev_cves: set[str] = set()
    for csv_path in data_dir.glob("*.csv"):
        try:
            df = pd.read_csv(csv_path, usecols=lambda c: c in {"cve_id", "in_kev"})
            if "cve_id" not in df.columns:
                continue
            all_cves.update(df["cve_id"].dropna().tolist())
            if "in_kev" in df.columns:
                mask = df["in_kev"].fillna(False).astype(bool)
                kev_cves.update(df.loc[mask, "cve_id"].dropna().tolist())
        except Exception:
            pass
    return len(all_cves), len(kev_cves)


def _csv_signature(data_dir: Path) -> tuple[tuple[str, int, int], ...]:
    """Return a cache key that changes when any product CSV changes."""
    signature: list[tuple[str, int, int]] = []
    for csv_path in sorted(data_dir.glob("*.csv")):
        try:
            stat = csv_path.stat()
        except FileNotFoundError:
            continue
        signature.append((csv_path.name, stat.st_mtime_ns, stat.st_size))
    return tuple(signature)


# ── helpers ───────────────────────────────────────────────────────────────────

def _active_filter() -> str | None:
    """Return the priority_class selected by pills or chart click, or None."""
    # Pills take precedence (direct Streamlit widget, always reliable)
    pill = st.session_state.get(_PILLS_KEY)
    if pill:
        return pill
    for key in (_BAR_KEY, _PIE_KEY):
        state = st.session_state.get(key)
        if state is None:
            continue
        try:
            pts = state.selection.select
            if pts:
                return pts[0].get("priority_class")
        except (AttributeError, KeyError, IndexError, TypeError):
            pass
    return None


def _reset_chart_selection() -> None:
    for key in (_BAR_KEY, _PIE_KEY):
        st.session_state.pop(key, None)
    st.session_state[_PILLS_KEY] = None


# ── sidebar ───────────────────────────────────────────────────────────────────

def _sidebar(config: dict) -> dict:
    products = {
        label: info
        for label, info in config.get("products", {}).items()
        if label != "families" and isinstance(info, dict)
    }
    data_dir = Path(config.get("pipeline", {}).get("data_dir", "data/raw"))

    with st.sidebar:
        if _LOGO_SVG_PATH.exists():
            svg_b64 = base64.b64encode(_LOGO_SVG_PATH.read_bytes()).decode()
            st.markdown(
                f'<img src="data:image/svg+xml;base64,{svg_b64}" style="width:100%;max-width:260px;margin-bottom:4px;">',
                unsafe_allow_html=True,
            )
        else:
            st.title("RedForge")

        n_cves, _ = _data_stats(str(data_dir), _csv_signature(data_dir))
        if n_cves:
            st.markdown(
                f'<p style="font-family:monospace;font-size:11px;font-weight:bold;color:#d62728;opacity:0.75;margin:2px 0 6px 0;">'
                f'&#x25B8; {n_cves:,} CVEs loaded</p>',
                unsafe_allow_html=True,
            )
        st.divider()
        run_clicked = st.button("Run", type="primary", width="stretch")
        st.divider()
        st.subheader("Filters")

        product = st.selectbox(
            "Product",
            ["all"] + list(products.keys()),
            format_func=lambda k: "All products" if k == "all"
                                  else products[k]["name"],
        )

        if product != "all":
            ver_options = products[product].get("versions", [])
            version_scope = st.radio(
                "Version scope",
                ["All versions", "Pick versions"],
                horizontal=True,
                help="Product queries can span every configured version, or a subset you choose explicitly.",
            )
            if version_scope == "All versions":
                versions = ver_options
                st.caption(f"Query scope: all configured versions for {products[product]['name']} ({', '.join(ver_options)}).")
            else:
                default_version = [ver_options[-1]] if ver_options else []
                versions = st.multiselect(
                    "Versions",
                    ver_options,
                    default=default_version,
                    help="Pick one or more versions. New product selections default to the latest configured version.",
                )
                if not versions:
                    versions = default_version
                    if versions:
                        st.caption(f"No version selected; using {versions[0]} to keep the query scoped.")
        else:
            versions = ["all"]

        _cur_year = datetime.date.today().year
        _year_opts = ["all"] + [str(y) for y in range(_cur_year, 2017, -1)]
        min_year = st.selectbox(
            "Published since",
            _year_opts,
            format_func=lambda v: "Any year" if v == "all" else v,
        )

        min_cvss = st.slider("Minimum CVSS", 0.0, 10.0, 0.0, 0.1)
        severity = st.selectbox("Minimum severity", ["low", "medium", "high", "critical"])

        st.markdown(
            '<p style="position:fixed;bottom:12px;font-family:monospace;font-size:10px;'
            'color:#888;line-height:1.4;">'
            '&copy; Fabrizio Soppelsa<br>'
            '<a href="mailto:fabrizio.soppelsa@community.unipa.it" style="color:#888;">'
            'fabrizio.soppelsa@community.unipa.it</a></p>',
            unsafe_allow_html=True,
        )

    return {
        "product":     product,
        "versions":    versions,
        "min_year":    min_year,
        "min_cvss":    min_cvss,
        "severity":    severity,
        "sort_by":     "priority",
        "run_clicked": run_clicked,
    }


# ── query runner ──────────────────────────────────────────────────────────────

def _apply_year_filter(df: pd.DataFrame, min_year: str) -> pd.DataFrame:
    if min_year == "all" or df.empty or "public_date" not in df.columns:
        return df
    return df[df["public_date"].fillna("").str[:4] >= min_year]


def _run(config: dict, params: dict) -> pd.DataFrame:
    product = params["product"]

    if product == "all" or params["versions"] == ["all"]:
        df = run_query_dataframe(
            config,
            product=product,
            min_cvss=params["min_cvss"],
            severity=params["severity"],
            sort_by=params["sort_by"],
        )
    else:
        shorts = [product + ver.replace(".", "") for ver in params["versions"]]
        df = run_query_dataframe(
            config,
            product=product,
            min_cvss=params["min_cvss"],
            severity=params["severity"],
            sort_by=params["sort_by"],
            product_shorts=shorts,
        )

    return _apply_year_filter(df, params["min_year"])


# ── interactive priority charts ───────────────────────────────────────────────

def _priority_charts(df: pd.DataFrame, product: str, versions: list[str]) -> None:
    counts_raw = df["priority_class"].value_counts()
    domain = [l for l in _PRIORITY_ORDER if l in counts_raw.index]
    if not domain:
        st.caption("No priority data — run **Ingest data** to rebuild the CSVs.")
        return

    counts = (
        pd.DataFrame({"priority_class": domain, "count": [counts_raw[l] for l in domain]})
    )
    range_colors = [_PRIORITY_COLORS[_PRIORITY_ORDER.index(l)] for l in domain]
    color_scale  = alt.Scale(domain=domain, range=range_colors)

    sel_pie = alt.selection_point(fields=["priority_class"], name="select")
    sel_bar = alt.selection_point(fields=["priority_class"], name="select")

    col_pie, col_bar = st.columns(2)

    with col_pie:
        pie = (
            alt.Chart(counts)
            .mark_arc(innerRadius=48, outerRadius=110, stroke="white", strokeWidth=1)
            .encode(
                theta=alt.Theta("count:Q"),
                color=alt.Color(
                    "priority_class:N",
                    scale=color_scale,
                    legend=None,
                ),
                opacity=alt.condition(sel_pie, alt.value(1.0), alt.value(0.45)),
                tooltip=[
                    alt.Tooltip("priority_class:N", title="Priority"),
                    alt.Tooltip("count:Q", title="CVEs"),
                ],
            )
            .add_params(sel_pie)
            .properties(height=280)
        )
        st.altair_chart(pie, on_select="rerun", key=_PIE_KEY, width="stretch")

    with col_bar:
        bar = (
            alt.Chart(counts)
            .mark_bar(cornerRadiusTopLeft=5, cornerRadiusTopRight=5)
            .encode(
                x=alt.X(
                    "priority_class:N",
                    sort=domain,
                    title=None,
                    axis=alt.Axis(labelAngle=0, labelExpr=_LABEL_EXPR),
                ),
                y=alt.Y("count:Q", title="CVEs"),
                color=alt.Color(
                    "priority_class:N",
                    scale=color_scale,
                    legend=alt.Legend(
                        title=None,
                        labelExpr=_LABEL_EXPR,
                        orient="bottom",
                        direction="horizontal",
                        symbolType="square",
                    ),
                ),
                opacity=alt.condition(sel_bar, alt.value(1.0), alt.value(0.45)),
                tooltip=[
                    alt.Tooltip("priority_class:N", title="Priority"),
                    alt.Tooltip("count:Q", title="CVEs"),
                ],
            )
            .add_params(sel_bar)
            .properties(height=280)
        )
        st.altair_chart(bar, on_select="rerun", key=_BAR_KEY, width="stretch")

    st.caption("Click a chart slice or bar to filter the table · click again to clear")


def _render_pills(df: pd.DataFrame) -> None:
    """Render priority filter pills above the results table."""
    if "priority_class" not in df.columns:
        return
    counts_raw = df["priority_class"].value_counts()
    domain = [l for l in _PRIORITY_ORDER if l in counts_raw.index]
    if not domain:
        return
    st.pills(
        "Filter by priority",
        options=domain,
        format_func=lambda v: _PRIORITY_SHORT[_PRIORITY_ORDER.index(v)],
        selection_mode="single",
        key=_PILLS_KEY,
        label_visibility="collapsed",
    )
    st.caption("Click a pill to filter the table · click again to clear")


# ── SPARQL tab content ────────────────────────────────────────────────────────

_DEFAULT_SPARQL = """\
PREFIX vs:      <http://redforge.local/ontology#>
PREFIX dcterms: <http://purl.org/dc/terms/>
PREFIX xsd:     <http://www.w3.org/2001/XMLSchema#>

SELECT ?cve ?score ?date
WHERE {
  ?vuln a vs:Vulnerability ;
        dcterms:identifier ?cve ;
        vs:hasCvssMetric   ?metric .
  ?metric vs:baseScore ?score .
  OPTIONAL { ?vuln dcterms:issued ?date }
  FILTER(xsd:decimal(?score) >= 7.0)
}
ORDER BY DESC(xsd:decimal(?score))
LIMIT 25
"""

_SPARQL_SUGGESTIONS = [
    {
        "title": "Top RHEL 10 CVSS vulnerabilities",
        "summary": "Highest-CVSS vulnerabilities affecting RHEL 10, newest fields included.",
        "query": """\
PREFIX vs:      <http://redforge.local/ontology#>
PREFIX dcterms: <http://purl.org/dc/terms/>
PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
PREFIX xsd:     <http://www.w3.org/2001/XMLSchema#>

SELECT ?cveId ?publicDate ?cvss ?severity ?cveUrl
WHERE {
  ?cve a vs:Vulnerability ;
       dcterms:identifier ?cveId ;
       vs:affectsProduct vs:product-rhel10 ;
       vs:severity ?severity ;
       vs:hasCvssMetric ?metric .
  ?metric vs:baseScore ?cvss .
  OPTIONAL { ?cve dcterms:issued ?publicDate }
  OPTIONAL { ?cve rdfs:seeAlso ?cveUrl }
}
ORDER BY DESC(xsd:decimal(?cvss)) DESC(?publicDate) ?cveId
LIMIT 25
""",
    },
    {
        "title": "Defer vulnerabilities across all products",
        "summary": "Lists CVEs tagged as `4-Defer`, with their affected products and max CVSS.",
        "query": """\
PREFIX vs:      <http://redforge.local/ontology#>
PREFIX dcterms: <http://purl.org/dc/terms/>
PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
PREFIX xsd:     <http://www.w3.org/2001/XMLSchema#>

SELECT ?cveId
       (GROUP_CONCAT(DISTINCT ?productLabel; separator=", ") AS ?products)
       (MAX(xsd:decimal(?cvss)) AS ?maxCvss)
       (SAMPLE(?priorityClass) AS ?priorityClass)
WHERE {
  ?cve a vs:Vulnerability ;
       dcterms:identifier ?cveId ;
       vs:priorityClass ?priorityClass ;
       vs:affectsProduct ?product ;
       vs:hasCvssMetric ?metric .
  ?product rdfs:label ?productLabel .
  ?metric vs:baseScore ?cvss .
  FILTER(?priorityClass = "4-Defer")
}
GROUP BY ?cveId
ORDER BY ASC(?maxCvss) ?cveId
LIMIT 100
""",
    },
    {
        "title": "KEV backlog without public exploit evidence",
        "summary": "Known exploited vulnerabilities that do not yet have a linked exploit artifact.",
        "query": """\
PREFIX vs:      <http://redforge.local/ontology#>
PREFIX dcterms: <http://purl.org/dc/terms/>
PREFIX xsd:     <http://www.w3.org/2001/XMLSchema#>

SELECT ?cveId ?publicDate ?kevDate ?cvss
WHERE {
  ?cve a vs:Vulnerability ;
       dcterms:identifier ?cveId ;
       vs:hasKEVEntry ?kev ;
       vs:hasCvssMetric ?metric .
  OPTIONAL { ?cve dcterms:issued ?publicDate }
  ?kev dcterms:date ?kevDate .
  ?metric vs:baseScore ?cvss .
  FILTER NOT EXISTS { ?cve vs:hasExploit ?exploit }
}
ORDER BY DESC(xsd:decimal(?cvss)) ?kevDate ?cveId
LIMIT 50
""",
    },
]

_SPARQL_CSS = """
<style>
textarea[data-testid="stTextArea"] {
    font-family: "JetBrains Mono", "Fira Mono", "Cascadia Code", "Consolas", monospace;
    font-size: 13px;
    background: #0e1117;
    color: #e0e0e0;
    border: 1px solid #333;
    border-radius: 6px;
    padding: 10px;
    line-height: 1.55;
}
</style>
"""

_ONTOLOGY_REF = """\
| Prefix | Namespace |
|--------|-----------|
| `vs:` | `http://redforge.local/ontology#` |
| `dcterms:` | `http://purl.org/dc/terms/` |
| `xsd:` | `http://www.w3.org/2001/XMLSchema#` |
| `rdfs:` | `http://www.w3.org/2000/01/rdf-schema#` |

**Classes**

| Class | Description |
|-------|-------------|
| `vs:Vulnerability` | A CVE entry |
| `vs:CVSSMetric` | CVSS score record (BNode attached via `vs:hasCvssMetric`) |
| `vs:KEVEntry` | CISA KEV entry (attached via `vs:hasKEVEntry`) |
| `vs:ExploitModule` | Exploit module from MSF / ExploitDB / PacketStorm / GHSA |
| `vs:Product` | Affected product (e.g. `rhel8`) |

**Properties**

| Property | Domain | Range |
|----------|--------|-------|
| `dcterms:identifier` | `vs:Vulnerability` | CVE string (e.g. `"CVE-2024-3094"`) |
| `dcterms:issued` | `vs:Vulnerability` | `xsd:date` |
| `rdfs:seeAlso` | `vs:Vulnerability` | Red Hat CVE URL |
| `vs:affectsProduct` | `vs:Vulnerability` | `vs:Product` |
| `vs:severity` | `vs:Vulnerability` | severity individual (e.g. `vs:CriticalSeverity`) |
| `vs:hasCvssMetric` | `vs:Vulnerability` | `vs:CVSSMetric` |
| `vs:hasKEVEntry` | `vs:Vulnerability` | `vs:KEVEntry` |
| `vs:hasExploit` | `vs:Vulnerability` | `vs:ExploitModule` |
| `vs:priorityClass` | `vs:Vulnerability` | string label (e.g. `"1-Act"`, `"4-Defer"`) |
| `vs:priorityScore` | `vs:Vulnerability` | numeric ranking score |
| `vs:baseScore` | `vs:CVSSMetric` | `xsd:decimal` |
| `dcterms:date` | `vs:KEVEntry` | `xsd:date` |
| `rdfs:label` | `vs:ExploitModule` | module name string |
"""


@st.cache_resource
def _graph(config: dict):
    from redforge.pipeline import load_graph
    return load_graph(config)


def _ensure_sparql_state() -> None:
    if _SPARQL_EDITOR_KEY not in st.session_state:
        st.session_state[_SPARQL_EDITOR_KEY] = _DEFAULT_SPARQL
    if _SPARQL_EDITOR_REV_KEY not in st.session_state:
        st.session_state[_SPARQL_EDITOR_REV_KEY] = 0


def _load_sparql_suggestion(query: str) -> None:
    st.session_state[_SPARQL_EDITOR_KEY] = query
    st.session_state[_SPARQL_EDITOR_REV_KEY] = st.session_state.get(_SPARQL_EDITOR_REV_KEY, 0) + 1


def _render_sparql_editor() -> str:
    _ensure_sparql_state()

    if st_ace is not None:
        value = st_ace(
            value=st.session_state[_SPARQL_EDITOR_KEY],
            language="sparql",
            theme="tomorrow_night_bright",
            key=f"vs_sparql_ace_{st.session_state[_SPARQL_EDITOR_REV_KEY]}",
            min_lines=18,
            max_lines=28,
            font_size=13,
            wrap=True,
            auto_update=True,
            show_gutter=True,
        )
        if value is not None:
            st.session_state[_SPARQL_EDITOR_KEY] = value
        return st.session_state[_SPARQL_EDITOR_KEY]

    sparql = st.text_area(
        "sparql_input",
        key=_SPARQL_EDITOR_KEY,
        height=320,
        label_visibility="collapsed",
    )
    st.caption("Install `streamlit-ace` to get in-editor syntax highlighting. The current environment uses the textarea fallback.")
    return sparql


@st.cache_data(show_spinner=False)
def _sparql_http_query(query: str, endpoint: str, graph_uri: str, timeout_s: int = 20) -> pd.DataFrame:
    """Execute a SPARQL SELECT via the configured HTTP endpoint."""
    payload = {"query": query}
    if graph_uri.strip():
        payload["default-graph-uri"] = graph_uri.strip()
    response = requests.post(
        endpoint,
        data=payload,
        headers={
            "Accept": "application/sparql-results+json",
        },
        timeout=timeout_s,
    )
    response.raise_for_status()
    payload = response.json()
    vars_ = payload.get("head", {}).get("vars", [])
    bindings = payload.get("results", {}).get("bindings", [])
    rows = []
    for binding in bindings:
        row = {
            var: binding.get(var, {}).get("value")
            for var in vars_
        }
        rows.append(row)
    return pd.DataFrame(rows, columns=vars_)


@st.cache_data(show_spinner=False, ttl=15)
def _sparql_endpoint_available(endpoint: str, graph_uri: str, timeout_s: int = 2) -> tuple[bool, str]:
    """Return whether the configured SPARQL HTTP endpoint is reachable and non-empty."""
    try:
        response = requests.post(
            endpoint,
            data={
                "query": "SELECT * WHERE { ?s ?p ?o } LIMIT 1",
                "default-graph-uri": graph_uri.strip(),
            },
            headers={"Accept": "application/sparql-results+json"},
            timeout=timeout_s,
        )
        response.raise_for_status()
        payload = response.json()
        bindings = payload.get("results", {}).get("bindings", [])
        if bindings:
            return True, "HTTP endpoint"
        return False, "Local RDF fallback (empty endpoint graph)"
    except requests.RequestException:
        return False, "Local RDF fallback"


def _sparql_local_query(config: dict, query: str) -> pd.DataFrame:
    """Execute a SPARQL SELECT via local rdflib over the Turtle graph."""
    from redforge.pipeline import query as sparql_query
    g = _graph(config)
    return sparql_query(g, query)


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    st.set_page_config(page_title="RedForge", layout="wide", page_icon="🔐")

    config = _config()
    params = _sidebar(config)

    tab_query, tab_suggest, tab_sparql, tab_manage = st.tabs(["⚡ Query", "🧠 Suggest", "🕸️ SPARQL", "⚙️ Manage"])

    # ── Query tab ────────────────────────────────────────────────────────────
    with tab_query:
        _products_cfg = {
            k: v for k, v in config.get("products", {}).items()
            if k != "families" and isinstance(v, dict)
        }
        _prod = params["product"]
        if _prod == "all":
            st.header("Query — All products")
        else:
            _pname = _products_cfg.get(_prod, {}).get("name", _prod.upper())
            st.header(f"Query — {_pname}")
            _vers = params["versions"]
            if _vers and _vers != ["all"]:
                _scope_note = "all configured versions" if len(_vers) == len(_products_cfg.get(_prod, {}).get("versions", [])) else "selected versions"
                st.markdown(
                    f'<p style="font-size:15px;color:#bbb;margin-top:-10px;margin-bottom:6px;">'
                    f'Versions: {", ".join(_vers)} <span style="opacity:0.7;">({_scope_note})</span></p>',
                    unsafe_allow_html=True,
                )

        if params.get("run_clicked"):
            try:
                with st.spinner("Running query…"):
                    df_result = _run(config, params)
                st.session_state["query_results"] = df_result
                _reset_chart_selection()
            except FileNotFoundError as exc:
                st.warning(str(exc))
                st.session_state.pop("query_results", None)
            except ValueError as exc:
                st.error(str(exc))
                st.session_state.pop("query_results", None)

        df = st.session_state.get("query_results")
        if df is not None:
            if df.empty:
                st.info("No results for the selected filters.")
            else:
                active = _active_filter()
                has_class_col = "priority_class" in df.columns

                if has_class_col:
                    _render_pills(df)

                if active and has_class_col:
                    display_df = df[df["priority_class"] == active]
                    short = _PRIORITY_SHORT[_PRIORITY_ORDER.index(active)] if active in _PRIORITY_ORDER else active
                    st.info(
                        f"Filtered: **{short}** — {len(display_df)} of {len(df)} CVEs.  "
                        "_Click the same element again to clear._"
                    )
                else:
                    display_df = df
                    st.caption(f"{len(df)} CVEs found")

                st.dataframe(
                    display_df,
                    width="stretch",
                    hide_index=True,
                    column_config={
                        "cve_url": st.column_config.LinkColumn(
                            "CVE link",
                            display_text="Red Hat CVE",
                        ),
                        "is_kev":    st.column_config.CheckboxColumn("exploit?"),
                        "vuln_name": st.column_config.TextColumn("name"),
                    },
                )

                if params["product"] != "all" and has_class_col:
                    _priority_charts(df, params["product"], params["versions"])

    # ── Suggest tab ──────────────────────────────────────────────────────────
    with tab_suggest:
        st.header("Suggestions")

        col_n, col_upload = st.columns([1, 3])
        with col_n:
            top_n = st.number_input("Top N", min_value=1, max_value=200, value=25)
        with col_upload:
            sbom_file = st.file_uploader(
                "SBOM (CycloneDX JSON)",
                type=["json"],
                label_visibility="visible",
            )

        sbom_components: list[dict] = []
        sbom_payload: bytes | None = None
        if sbom_file is not None:
            sbom_payload = sbom_file.read()
            try:
                sbom_components = parse_cyclonedx_sbom(sbom_payload)
            except ValueError as exc:
                st.warning(str(exc))
                sbom_components = []
            else:
                with st.expander(f"SBOM parsed (CycloneDX) — {len(sbom_components)} components", expanded=False):
                    st.dataframe(
                        pd.DataFrame(sbom_components),
                        width="stretch",
                        hide_index=True,
                    )
        else:
            st.caption("Upload a CycloneDX JSON SBOM to rank the estate globally.")

        if st.button("Run", type="primary", key="suggest_run"):
            try:
                with st.spinner("Running…"):
                    if sbom_payload is None:
                        raise ValueError("A CycloneDX JSON SBOM is required.")
                    suggest_result = suggest_from_sbom(config, sbom=sbom_payload, top_n=int(top_n))
                    df_suggest = pd.DataFrame(suggest_result["items"])
                st.session_state["suggest_results"] = df_suggest
                st.session_state["suggest_summary"] = suggest_result["summary"]
                st.session_state["suggest_diagnostics"] = suggest_result["diagnostics"]
            except FileNotFoundError as exc:
                st.warning(str(exc))
                st.session_state.pop("suggest_results", None)
            except Exception as exc:
                st.error(str(exc))
                st.session_state.pop("suggest_results", None)

        df_s = st.session_state.get("suggest_results")
        if df_s is not None:
            if df_s.empty:
                st.info("No suggestions available.")
            else:
                summary = st.session_state.get("suggest_summary", {})
                st.caption(
                    f"{summary.get('returned_items', len(df_s))} CVEs · "
                    f"{summary.get('components_matched', 0)}/{summary.get('components_seen', 0)} components matched"
                )
                st.dataframe(
                    df_s,
                    width="stretch",
                    hide_index=True,
                    column_config={
                        "cve_url": st.column_config.LinkColumn(
                            "CVE link",
                            display_text="Red Hat CVE",
                        ),
                        "is_kev":    st.column_config.CheckboxColumn("exploit?"),
                        "vuln_name": st.column_config.TextColumn("name"),
                    },
                )
                diagnostics = st.session_state.get("suggest_diagnostics", {})
                unmatched = diagnostics.get("unmatched_components", [])
                if unmatched:
                    st.caption(f"Unmatched components: {', '.join(unmatched[:20])}" + (" …" if len(unmatched) > 20 else ""))

    # ── Custom SPARQL tab ─────────────────────────────────────────────────────
    with tab_sparql:
        _ensure_sparql_state()
        st.markdown(_SPARQL_CSS, unsafe_allow_html=True)
        endpoint_ok, backend_label = _sparql_endpoint_available(_SPARQL_ENDPOINT, _SPARQL_GRAPH_URI)

        st.markdown("### SPARQL Query Editor")
        st.caption("Query the RedForge RDF graph directly. The graph is built from the ingested CVE data.")
        if endpoint_ok:
            st.caption(f"Backend: {backend_label} · `{_SPARQL_ENDPOINT}` · graph `{_SPARQL_GRAPH_URI}`")
        else:
            st.warning(f"{backend_label}. Using local RDF fallback via rdflib; broad queries may be slower.")

        with st.expander("Ontology reference — prefixes, classes, properties"):
            st.markdown(_ONTOLOGY_REF)

        st.markdown("#### Starter queries")
        st.caption("Open a suggestion and click `Use this query` to prefill the editor.")
        for idx, suggestion in enumerate(_SPARQL_SUGGESTIONS):
            with st.expander(suggestion["title"], expanded=False):
                st.caption(suggestion["summary"])
                st.code(suggestion["query"], language="sparql")
                if st.button("Use this query", key=f"sparql_suggestion_{idx}", width="stretch"):
                    _load_sparql_suggestion(suggestion["query"])
                    st.rerun()

        st.markdown(" ")
        sparql = _render_sparql_editor()

        col_btn, col_hint = st.columns([1, 6])
        with col_btn:
            run_sparql = st.button("Execute", type="primary", width="stretch")
        with col_hint:
            st.caption("Tip: use `LIMIT` to keep results manageable.")

        if run_sparql:
            from redforge.commands.query import normalize_sparql_input
            try:
                t0 = time.perf_counter()
                with st.spinner("Running…"):
                    normalized = normalize_sparql_input(sparql)
                    if endpoint_ok:
                        result_df = _sparql_http_query(
                            normalized,
                            _SPARQL_ENDPOINT,
                            _SPARQL_GRAPH_URI,
                        )
                    else:
                        result_df = _sparql_local_query(config, normalized)
                elapsed = time.perf_counter() - t0

                if result_df.empty:
                    st.info("Query returned no results.")
                else:
                    m1, m2, m3 = st.columns(3)
                    m1.metric("Rows", len(result_df))
                    m2.metric("Columns", len(result_df.columns))
                    m3.metric("Time", f"{elapsed:.2f} s")

                    st.dataframe(result_df, width="stretch", hide_index=True)

                    st.download_button(
                        "Download CSV",
                        data=result_df.to_csv(index=False).encode(),
                        file_name="sparql_results.csv",
                        mime="text/csv",
                    )
            except FileNotFoundError as exc:
                st.warning(str(exc))
            except requests.Timeout:
                st.error("SPARQL query timed out. Narrow the query or add a smaller LIMIT.")
            except requests.RequestException as exc:
                st.error(f"SPARQL endpoint error: {exc}")
            except Exception as exc:
                st.error(str(exc))

    # ── Manage tab ───────────────────────────────────────────────────────────
    with tab_manage:
        st.header("Manage")

        st.subheader("Download data")
        st.caption("Fetch the latest raw data from all configured sources.")
        if st.button("Download", type="primary", key="manage_download"):
            bars: dict = {}

            def on_step(name: str, pct: int) -> None:
                pct = max(0, min(int(pct), 100))
                if name not in bars:
                    bars[name] = st.progress(0, text=name)
                bars[name].progress(pct, text=f"{name}  {pct}%")

            try:
                paths = run_sync(config, force=True, on_step=on_step)
                for b in bars.values():
                    b.empty()
                st.success(f"{len(paths)} sources updated.")
            except Exception as exc:
                st.error(str(exc))

        st.divider()

        st.subheader("Ingest data")
        st.caption("Process downloaded files and rebuild the local CVE cache.")
        if st.button("Ingest", type="primary", key="manage_ingest"):
            try:
                from redforge.pipeline import pull
                with st.spinner("Ingesting data…"):
                    results = pull(config)
                st.success(f"{len(results)} products updated.")
                st.cache_data.clear()
            except FileNotFoundError as exc:
                st.error(str(exc))
            except Exception as exc:
                st.error(str(exc))


main()
