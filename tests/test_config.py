"""Tests for redforge.config."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from redforge.config import load

_FAMILY_TOML = """
[[products.families]]
label      = "RHEL"
api_prefix = "Red Hat Enterprise Linux"

[[products.families.versions]]
label = "8"
short = "rhel8"

[[products.families.versions]]
label = "9"
short = "rhel9"
"""

_NAMED_PRODUCTS_TOML = """
[products.rhel]
name = "Red Hat Enterprise Linux"
versions = ["8", "9"]
"""


def test_load_returns_dict(tmp_path):
    cfg = tmp_path / "redforge.toml"
    cfg.write_text("[products]\n")
    assert isinstance(load(cfg), dict)


def test_load_families(tmp_path):
    cfg = tmp_path / "redforge.toml"
    cfg.write_text(_FAMILY_TOML)
    families = load(cfg)["products"]["families"]
    assert families[0]["label"] == "RHEL"
    assert families[0]["api_prefix"] == "Red Hat Enterprise Linux"


def test_load_versions(tmp_path):
    cfg = tmp_path / "redforge.toml"
    cfg.write_text(_FAMILY_TOML)
    versions = load(cfg)["products"]["families"][0]["versions"]
    assert [v["short"] for v in versions] == ["rhel8", "rhel9"]


def test_load_sources(tmp_path):
    cfg = tmp_path / "redforge.toml"
    cfg.write_text('[sources]\nkev = "https://example.com/kev.json"\n')
    assert "kev" in load(cfg)["sources"]


def test_load_backfills_default_sources(tmp_path):
    cfg = tmp_path / "redforge.toml"
    cfg.write_text('[sources]\nkev = "https://example.com/kev.json"\n')
    sources = load(cfg)["sources"]
    assert sources["kev"] == "https://example.com/kev.json"
    assert "exploitdb" in sources
    assert "packetstorm" in sources
    assert "github_advisory_db" in sources


def test_load_normalizes_families_into_named_products(tmp_path):
    cfg = tmp_path / "redforge.toml"
    cfg.write_text(_FAMILY_TOML)
    products = load(cfg)["products"]
    assert products["rhel"]["name"] == "Red Hat Enterprise Linux"
    assert products["rhel"]["versions"] == ["8", "9"]


def test_load_normalizes_named_products_into_families(tmp_path):
    cfg = tmp_path / "redforge.toml"
    cfg.write_text(_NAMED_PRODUCTS_TOML)
    families = load(cfg)["products"]["families"]
    assert families[0]["api_prefix"] == "Red Hat Enterprise Linux"
    assert [v["short"] for v in families[0]["versions"]] == ["rhel8", "rhel9"]
