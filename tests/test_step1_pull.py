"""Tests for pipeline step 1 (pull / join)."""

import sys
import importlib
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
if "redforge" in sys.modules and not hasattr(sys.modules["redforge"], "__path__"):
    del sys.modules["redforge"]


def test_pull_raises_when_cache_missing(tmp_path):
    if "redforge" in sys.modules and not hasattr(sys.modules["redforge"], "__path__"):
        del sys.modules["redforge"]
    pull = importlib.import_module("src.redforge.pipeline").pull
    config = {
        "pipeline": {"data_dir": str(tmp_path)},
        "products": {},
    }
    with pytest.raises(FileNotFoundError):
        pull(config)


def test_pull_allows_missing_optional_enrichment_sources(tmp_path):
    pull = importlib.import_module("src.redforge.pipeline").pull

    data_dir = tmp_path
    (data_dir / "kev.json").write_text('{"vulnerabilities": []}', encoding="utf-8")
    (data_dir / "metasploit.json").write_text("{}", encoding="utf-8")
    (data_dir / "redhat_cve_rhel8.json").write_text(
        '[{"CVE":"CVE-2024-0001","public_date":"2024-01-01","cvss3_score":7.5,"severity":"important"}]',
        encoding="utf-8",
    )

    config = {
        "pipeline": {"data_dir": str(data_dir)},
        "products": {
            "rhel": {
                "name": "Red Hat Enterprise Linux",
                "versions": ["8"],
            }
        },
    }

    results = pull(config)

    assert "rhel8" in results
    df = results["rhel8"]
    assert len(df) == 1
    assert df.loc[0, "cve_url"] == "https://access.redhat.com/security/cve/CVE-2024-0001"
    assert bool(df.loc[0, "in_exploitdb"]) is False
    assert bool(df.loc[0, "in_packetstorm"]) is False
    assert bool(df.loc[0, "in_github_advisory"]) is False


def test_finalize_query_results_preserves_link_and_priority_order():
    finalize = importlib.import_module("src.redforge.commands.query")._finalize_query_results

    df = pd.DataFrame([
        {
            "cve_id": "CVE-2024-0002",
            "cve_url": "https://access.redhat.com/security/cve/CVE-2024-0002",
            "cvss": 7.0,
            "severity": "important",
            "is_kev": True,
            "public_date": "2024-01-02",
        },
        {
            "cve_id": "CVE-2024-0001",
            "cve_url": "https://access.redhat.com/security/cve/CVE-2024-0001",
            "cvss": 9.0,
            "severity": "critical",
            "is_kev": False,
            "public_date": "2024-01-01",
        },
    ])

    result = finalize(df, sort_by="priority")

    assert list(result.columns) == [
        "priority_rank", "cve_id", "cve_url", "cvss", "severity", "is_kev", "public_date", "risk_score",
    ]
    assert result.loc[0, "cve_id"] == "CVE-2024-0002"
    assert result.loc[0, "cve_url"] == "https://access.redhat.com/security/cve/CVE-2024-0002"
