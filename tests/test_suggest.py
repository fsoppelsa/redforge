"""Tests for SBOM-driven suggestions."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
if "redforge" in sys.modules and not hasattr(sys.modules["redforge"], "__path__"):
    del sys.modules["redforge"]


def test_parse_cyclonedx_sbom_rejects_non_cyclonedx():
    parse = importlib.import_module("src.redforge.sbom").parse_cyclonedx_sbom

    with pytest.raises(ValueError, match="CycloneDX"):
        parse(b'{"spdxVersion":"SPDX-2.3"}')


def test_parse_cyclonedx_sbom_accepts_xml():
    parse = importlib.import_module("src.redforge.sbom").parse_cyclonedx_sbom
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
  <components>
    <component bom-ref="x" type="library">
      <name>curl</name>
      <version>8.0.1</version>
      <purl>pkg:rpm/redhat/curl@8.0.1</purl>
    </component>
  </components>
</bom>
"""
    comps = parse(xml)
    assert comps == [
        {"name": "curl", "version": "8.0.1", "purl": "pkg:rpm/redhat/curl@8.0.1", "bom_ref": "x", "type": "library"}
    ]


def test_suggest_from_sbom_returns_global_top_distinct_cves(tmp_path):
    suggest = importlib.import_module("src.redforge.commands.suggest").suggest_from_sbom

    data_dir = tmp_path
    _write_csv(
        data_dir / "rhel8.csv",
        """cve_id,cve_url,public_date,cvss_score,rh_severity,in_kev,kev_date_added,vuln_name,in_metasploit,msf_module_name,in_exploitdb,exploitdb_id,exploitdb_title,in_packetstorm,packetstorm_title,packetstorm_url,in_github_advisory,ghsa_id,ghsa_url,priority_class,priority_score
CVE-2024-0001,https://example/CVE-2024-0001,2024-01-01,7.5,important,False,,openssl issue,False,,False,,,False,,,False,,,3-Track,4
CVE-2024-0002,https://example/CVE-2024-0002,2024-01-02,8.8,critical,True,2024-01-03,curl issue,True,module,False,,,False,,,False,,,1-Act,9
""",
    )
    _write_json(
        data_dir / "redhat_cve_rhel8.json",
        [
            {"CVE": "CVE-2024-0001", "affected_packages": ["openssl-0:3.0.0-1.el8"]},
            {"CVE": "CVE-2024-0002", "affected_packages": ["curl-0:8.0.1-1.el8"]},
        ],
    )
    _write_csv(
        data_dir / "rhel9.csv",
        """cve_id,cve_url,public_date,cvss_score,rh_severity,in_kev,kev_date_added,vuln_name,in_metasploit,msf_module_name,in_exploitdb,exploitdb_id,exploitdb_title,in_packetstorm,packetstorm_title,packetstorm_url,in_github_advisory,ghsa_id,ghsa_url,priority_class,priority_score
CVE-2024-0003,https://example/CVE-2024-0003,2024-02-01,9.8,critical,False,,nginx issue,False,,False,,,False,,,False,,,2-Attend,8
""",
    )
    _write_json(
        data_dir / "redhat_cve_rhel9.json",
        [
            {"CVE": "CVE-2024-0003", "affected_packages": ["nginx-1:1.24.0-1.el9"]},
        ],
    )

    config = {
        "pipeline": {"data_dir": str(data_dir)},
        "products": {
            "rhel": {"name": "Red Hat Enterprise Linux", "versions": ["8", "9"]},
        },
    }
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"name": "curl", "version": "8.0.1"},
            {"name": "nginx", "version": "1.24.0"},
        ],
    }

    result = suggest(config, sbom=sbom, top_n=25)

    assert result["summary"]["components_seen"] == 2
    assert result["summary"]["components_matched"] == 2
    assert result["summary"]["candidate_cves"] == 2
    assert [item["cve_id"] for item in result["items"]] == ["CVE-2024-0002", "CVE-2024-0003"]
    assert result["items"][0]["matched_components"] == "curl@8.0.1"


def _write_csv(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")
