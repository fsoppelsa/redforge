"""Prioritized vulnerability suggestions."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pandas as pd

from .query import _finalize_query_results, _resolve_product_shorts, run_query
from ..sbom import parse_cyclonedx_sbom

_PACKAGE_VERSION_RE = re.compile(r"^(?P<name>.+?)-\d+:")
_PKG_URL_NAME_RE = re.compile(r"^pkg:[^/]+/(?:[^/]+/)?(?P<name>[^@]+)")
_SEVERITY_RANK = {"critical": 4, "important": 3, "high": 3, "moderate": 2, "medium": 2, "low": 1}
_PRIORITY_RANK = {"1-Act": 1, "2-Attend": 2, "3-Track": 3, "4-Defer": 4}


def run_suggest(
    config: dict,
    top_n: int = 25,
    product: str = "all",
    sbom: bytes | str | dict[str, Any] | None = None,
) -> pd.DataFrame:
    """Return prioritized suggestions as a DataFrame."""
    if sbom is None:
        df = run_query(config, product=product, min_cvss=0.0, severity="low", sort_by="priority")
        if df.empty:
            return df
        want = [
            "priority_rank", "priority_class", "priority_score", "cve_id", "vuln_name",
            "cve_url", "cvss", "severity", "is_kev", "has_public_exploit",
            "public_date", "risk_score",
        ]
        cols = [c for c in want if c in df.columns]
        return df[cols].head(top_n).reset_index(drop=True)

    result = suggest_from_sbom(config, sbom=sbom, top_n=top_n)
    return pd.DataFrame(result["items"])


def suggest_from_sbom(
    config: dict,
    sbom: bytes | str | dict[str, Any],
    top_n: int = 25,
) -> dict[str, Any]:
    """Return top vulnerabilities affecting components present in a CycloneDX SBOM."""
    components = parse_cyclonedx_sbom(sbom)
    alias_map = _build_component_aliases(components)
    if not alias_map:
        return {
            "summary": {
                "components_seen": len(components),
                "components_matched": 0,
                "candidate_cves": 0,
                "returned_items": 0,
            },
            "items": [],
            "diagnostics": {
                "unmatched_components": [c["name"] for c in components],
            },
        }

    matched = _match_sbom_components(config, alias_map)
    if matched.empty:
        return {
            "summary": {
                "components_seen": len(components),
                "components_matched": 0,
                "candidate_cves": 0,
                "returned_items": 0,
            },
            "items": [],
            "diagnostics": {
                "unmatched_components": [c["name"] for c in components],
            },
        }

    matched = _aggregate_matches(matched)
    ranked = _finalize_query_results(matched, sort_by="priority").head(top_n).reset_index(drop=True)
    if "matched_components" in ranked.columns:
        ranked["matched_component_count"] = ranked["matched_components"].apply(len)
        ranked["matched_components"] = ranked["matched_components"].apply(lambda values: ", ".join(values))
    if "affected_packages" in ranked.columns:
        ranked["affected_package_count"] = ranked["affected_packages"].apply(len)
        ranked["affected_packages"] = ranked["affected_packages"].apply(lambda values: ", ".join(values))

    matched_components = {
        component
        for values in matched["matched_components"]
        for component in values
    }
    all_components = {_component_label(component) for component in components}
    unmatched_components = sorted(all_components - matched_components)

    summary = {
        "components_seen": len(components),
        "components_matched": len(matched_components),
        "candidate_cves": len(matched),
        "returned_items": len(ranked),
        "priority_counts": (
            ranked["priority_class"].value_counts().sort_index(key=lambda idx: idx.map(_priority_sort_key)).to_dict()
            if "priority_class" in ranked.columns else {}
        ),
    }
    return {
        "summary": summary,
        "items": ranked.to_dict(orient="records"),
        "diagnostics": {
            "unmatched_components": unmatched_components,
        },
    }


def _priority_sort_key(value: str) -> int:
    return _PRIORITY_RANK.get(str(value), 99)


def _build_component_aliases(components: list[dict[str, str]]) -> dict[str, set[str]]:
    alias_map: dict[str, set[str]] = {}
    for component in components:
        label = _component_label(component)
        for alias in _component_aliases(component):
            alias_map.setdefault(alias, set()).add(label)
    return alias_map


def _component_label(component: dict[str, str]) -> str:
    version = component.get("version") or ""
    return f"{component['name']}@{version}" if version else component["name"]


def _component_aliases(component: dict[str, str]) -> set[str]:
    aliases = {_normalize_name(component.get("name", ""))}
    purl_name = _extract_purl_name(component.get("purl", ""))
    if purl_name:
        aliases.add(_normalize_name(purl_name))
    return {alias for alias in aliases if alias}


def _extract_purl_name(purl: str) -> str:
    match = _PKG_URL_NAME_RE.match(purl.strip())
    return match.group("name") if match else ""


def _normalize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9.+-]+", "-", value.strip().lower()).strip("-")


def _match_sbom_components(config: dict, alias_map: dict[str, set[str]]) -> pd.DataFrame:
    data_dir = Path(config.get("pipeline", {}).get("data_dir", "data/raw"))
    shorts = _resolve_product_shorts(config, product="all", version="all")

    frames: list[pd.DataFrame] = []
    for short in shorts:
        csv_path = data_dir / f"{short}.csv"
        raw_path = data_dir / f"redhat_cve_{short}.json"
        if not csv_path.exists() or not raw_path.exists():
            continue

        df = pd.read_csv(csv_path)
        package_map = _load_affected_packages(raw_path)
        if not package_map:
            continue

        df["affected_packages"] = df["cve_id"].map(package_map)
        df = df[df["affected_packages"].map(bool)].copy()
        if df.empty:
            continue

        df["matched_components"] = df["affected_packages"].apply(
            lambda packages: _match_packages_to_components(packages, alias_map)
        )
        df = df[df["matched_components"].map(bool)].copy()
        if not df.empty:
            frames.append(df)

    if not frames:
        return pd.DataFrame()

    combined = pd.concat(frames, ignore_index=True)
    return combined.rename(columns={
        "cvss_score": "cvss",
        "rh_severity": "severity",
        "in_kev": "is_kev",
    })


def _load_affected_packages(path: Path) -> dict[str, list[str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    package_map: dict[str, list[str]] = {}
    for entry in data:
        cve_id = str(entry.get("CVE") or "").strip().upper()
        packages = entry.get("affected_packages") or []
        if cve_id and isinstance(packages, list):
            package_map[cve_id] = sorted({str(pkg).strip() for pkg in packages if str(pkg).strip()})
    return package_map


def _match_packages_to_components(packages: list[str], alias_map: dict[str, set[str]]) -> list[str]:
    matched: set[str] = set()
    for package in packages:
        for alias in _package_aliases(package):
            matched.update(alias_map.get(alias, set()))
    return sorted(matched)


def _package_aliases(package: str) -> set[str]:
    raw = package.strip()
    aliases = {_normalize_name(raw)}

    version_match = _PACKAGE_VERSION_RE.match(raw)
    if version_match:
        aliases.add(_normalize_name(version_match.group("name")))

    if "/" in raw:
        aliases.add(_normalize_name(raw.rsplit("/", 1)[-1].split(":", 1)[0]))

    if ":" in raw and "/" not in raw:
        aliases.add(_normalize_name(raw.split(":", 1)[0]))

    return {alias for alias in aliases if alias}


def _aggregate_matches(df: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for cve_id, group in df.groupby("cve_id", dropna=False, sort=False):
        matched_components = sorted({
            component
            for values in group["matched_components"]
            for component in values
        })
        affected_packages = sorted({
            package
            for values in group["affected_packages"]
            for package in values
        })
        priority_score = pd.to_numeric(group.get("priority_score"), errors="coerce").max()
        row = {
            "cve_id": cve_id,
            "cve_url": _first_value(group.get("cve_url")),
            "public_date": _first_value(group.get("public_date")),
            "cvss": pd.to_numeric(group.get("cvss"), errors="coerce").max(),
            "severity": _max_severity(group.get("severity")),
            "is_kev": bool(group.get("is_kev").fillna(False).astype(bool).any()),
            "vuln_name": _first_value(group.get("vuln_name")),
            "priority_class": _best_priority_class(group.get("priority_class")),
            "priority_score": None if pd.isna(priority_score) else float(priority_score),
            "in_metasploit": bool(group.get("in_metasploit").fillna(False).astype(bool).any()),
            "in_exploitdb": bool(group.get("in_exploitdb").fillna(False).astype(bool).any()),
            "in_packetstorm": bool(group.get("in_packetstorm").fillna(False).astype(bool).any()),
            "matched_components": matched_components,
            "affected_packages": affected_packages,
        }
        rows.append(row)
    return pd.DataFrame(rows)


def _first_value(series: pd.Series | None) -> Any:
    if series is None:
        return None
    for value in series:
        if pd.notna(value) and str(value).strip():
            return value
    return None


def _max_severity(series: pd.Series | None) -> str | None:
    if series is None:
        return None
    values = [str(value) for value in series if pd.notna(value)]
    if not values:
        return None
    return max(values, key=lambda value: _SEVERITY_RANK.get(value.lower(), 0))


def _best_priority_class(series: pd.Series | None) -> str | None:
    if series is None:
        return None
    values = [str(value) for value in series if pd.notna(value)]
    if not values:
        return None
    return min(values, key=_priority_sort_key)
