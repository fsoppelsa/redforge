"""Configuration loader and compatibility helpers for ``redforge.toml``."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

# Default configuration file shipped at the project root.
_DEFAULT = Path(__file__).parents[2] / "redforge.toml"

# Built-in source URLs used when the configuration omits one or more feeds.
_DEFAULT_SOURCES: dict[str, str] = {
    "redhat_cve": "https://access.redhat.com/hydra/rest/securitydata/cve.json",
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "metasploit": "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json",
    "exploitdb": "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
    "packetstorm": "https://packetstormsecurity.com/feeds/files.xml",
    "epss": "https://epss.cyentia.com/epss_scores-current.csv.gz",
    "github_advisory_db": "https://codeload.github.com/github/advisory-database/tar.gz/refs/heads/main",
    "nvd_cvss": "https://services.nvd.nist.gov/rest/json/cves/2.0",
}


def _normalize_products(config: dict[str, Any]) -> dict[str, Any]:
    """Normalize product definitions between legacy and family-based formats."""
    products = config.get("products")
    if not isinstance(products, dict):
        return config

    families = products.get("families")

    if isinstance(families, list):
        # Convert configured families into the legacy product mapping expected by
        # older callers, keeping the original family list intact.
        normalized: dict[str, dict[str, Any]] = {}
        for family in families:
            if not isinstance(family, dict):
                continue

            versions = family.get("versions", [])
            if not isinstance(versions, list) or not versions:
                continue

            label = None
            first_version = versions[0]
            if isinstance(first_version, dict):
                short = first_version.get("short")
                if isinstance(short, str) and short:
                    # Derive the product key from the short version code by
                    # removing digits, for example "rhel9" becomes "rhel".
                    label = "".join(ch for ch in short if not ch.isdigit())

            if not label:
                family_label = family.get("label")
                if isinstance(family_label, str) and family_label:
                    # Fall back to a compact lower-case family label.
                    label = family_label.lower().replace(" ", "")

            if not label:
                continue

            normalized[label] = {
                "name": family.get("api_prefix", family.get("name", label)),
                "versions": [
                    version.get("label")
                    for version in versions
                    if isinstance(version, dict) and isinstance(version.get("label"), str)
                ],
            }

        for label, info in normalized.items():
            products.setdefault(label, info)

        return config

    named_products = {
        label: info
        for label, info in products.items()
        if label != "families" and isinstance(info, dict)
    }
    if not named_products:
        return config

    # Build the family-based representation from legacy named products so newer
    # callers can rely on the ``products.families`` structure.
    products["families"] = [
        {
            "label": label.upper(),
            "api_prefix": info["name"],
            "versions": [
                {
                    "label": version,
                    "short": f"{label}{version.replace('.', '')}",
                }
                for version in info.get("versions", [])
            ],
        }
        for label, info in named_products.items()
        if isinstance(info.get("name"), str)
    ]

    return config


def _merge_default_sources(config: dict[str, Any]) -> dict[str, Any]:
    """Ensure all built-in source URLs are available in the loaded config."""
    sources = config.get("sources")
    if not isinstance(sources, dict):
        config["sources"] = dict(_DEFAULT_SOURCES)
        return config

    for name, url in _DEFAULT_SOURCES.items():
        sources.setdefault(name, url)
    return config


def _resolve_paths(config: dict[str, Any], config_dir: Path) -> dict[str, Any]:
    """Resolve relative data_dir / rdf_dir against the config file's directory."""
    pipeline = config.setdefault("pipeline", {})
    for key, default in (("data_dir", "data/raw"), ("rdf_dir", "data/rdf")):
        raw = pipeline.get(key, default)
        p = Path(raw)
        if not p.is_absolute():
            p = (config_dir / p).resolve()
        pipeline[key] = str(p)
    return config


def load(path: Path | str = _DEFAULT) -> dict:
    """Load, normalize, and return the TOML configuration as a plain dict."""
    import os

    path = Path(path)
    with path.open("rb") as fh:
        config = tomllib.load(fh)
    config = _normalize_products(config)
    config = _merge_default_sources(config)
    config = _resolve_paths(config, path.parent)

    nvd_key = os.environ.get("NVD_API_KEY", "")
    if nvd_key:
        config.setdefault("credentials", {})["nvd_api_key"] = nvd_key

    # Optional: allow injecting the Red Hat offline token via environment.
    # This is useful for container deployments where the on-disk config is a ConfigMap.
    rh_offline_token = os.environ.get("RH_OFFLINE_TOKEN", "")
    if rh_offline_token:
        insights = config.setdefault("insights", {})
        if isinstance(insights, dict):
            insights["offline_token"] = rh_offline_token
            insights.setdefault("enabled", True)

    return config
