#!/usr/bin/env python3
"""Standalone test for plan_insights and remediate_insights core logic.

Exercises each stage independently so API bugs are isolated from MCP wiring.
All tests are gated on env vars so the script is safe to run in CI (skips
any test whose prerequisites aren't set).

Usage:
    RH_OFFLINE_TOKEN=<token> python scripts/test_insights.py

Env vars:
    RH_OFFLINE_TOKEN     required for all tests
    TEST_FQDN            FQDN of a registered Insights host — enables inventory + plan tests
    TEST_CVES            comma-separated CVE IDs, e.g. CVE-2021-44228,CVE-2022-0847
    TEST_REMEDIATION_ID  UUID from a prior plan run — enables remediate dry-run test
    INSIGHTS_RUN_TIMEOUT poll timeout in seconds (default 600)
    INSIGHTS_POLL_INTERVAL poll interval in seconds (default 10)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
# Remove the redforge.py shadow module if present
_mod = sys.modules.get("redforge")
if _mod is not None and not hasattr(_mod, "__path__"):
    del sys.modules["redforge"]

from redforge.commands.insights import (
    InsightsError,
    fetch_cves_for_system,
    get_access_token,
    get_remediation,
    plan_insights_core,
    remediate_insights_core,
    resolve_host,
)


def _header(title: str) -> None:
    print(f"\n{'=' * 60}\n{title}\n{'=' * 60}")


def _skip(reason: str) -> None:
    print(f"  SKIPPED — {reason}")


def _ok(label: str, value: object) -> None:
    print(f"  {label}: {value}")


def _err(exc: InsightsError) -> None:
    print(f"  [InsightsError] stage={exc.stage}  status={exc.status_code}")
    print(f"  message: {exc}")
    if exc.body:
        print(f"  body: {str(exc.body)[:300]}")


# ── Test 1: Auth ──────────────────────────────────────────────────────────────

def test_auth() -> str | None:
    _header("Test 1: Token exchange (SSO auth)")
    if not os.environ.get("RH_OFFLINE_TOKEN"):
        _skip("RH_OFFLINE_TOKEN not set")
        return None
    try:
        token = get_access_token()
        # Never print the token; confirm it looks like a JWT
        looks_like_jwt = token.count(".") == 2 and len(token) > 100
        _ok("token shape", "JWT (3 parts)" if looks_like_jwt else f"unexpected ({len(token)} chars)")
        _ok("cache hit", get_access_token() is token or "new token (cache miss)")
        return token
    except InsightsError as exc:
        _err(exc)
        return None


# ── Test 2: Inventory lookup ──────────────────────────────────────────────────

def test_inventory(token: str) -> str | None:
    _header("Test 2: Inventory — FQDN → UUID")
    fqdn = os.environ.get("TEST_FQDN", "")
    if not fqdn:
        _skip("set TEST_FQDN=your.host.fqdn to run")
        return None
    try:
        system_id = resolve_host(token, fqdn)
        _ok("fqdn", fqdn)
        _ok("system_uuid", system_id)
        return system_id
    except InsightsError as exc:
        _err(exc)
        return None


# ── Test 3: Vulnerability — system CVE list ───────────────────────────────────

def test_vulnerability(token: str, system_id: str) -> None:
    _header("Test 3: Vulnerability — fetch patchable CVEs for system")
    cve_str = os.environ.get("TEST_CVES", "")
    if not cve_str:
        _skip("set TEST_CVES=CVE-XXXX-YYYY,... to run")
        return
    cves = [c.strip() for c in cve_str.split(",") if c.strip()]
    try:
        cve_map = fetch_cves_for_system(token, system_id, cves)
        _ok("CVEs queried", cves)
        _ok("CVEs found (patchable)", list(cve_map.keys()))
        for cve_id, attrs in cve_map.items():
            _ok(f"  {cve_id} advisory_available", attrs.get("advisory_available"))
            _ok(f"  {cve_id} remediation", attrs.get("remediation"))
    except InsightsError as exc:
        _err(exc)


# ── Test 4: Full plan_insights pipeline ───────────────────────────────────────

def test_plan_insights() -> str | None:
    _header("Test 4: plan_insights — full pipeline")
    fqdn = os.environ.get("TEST_FQDN", "")
    cve_str = os.environ.get("TEST_CVES", "")
    if not fqdn or not cve_str:
        _skip("set TEST_FQDN and TEST_CVES=CVE-XXXX-YYYY,... to run")
        return None

    cves = [{"cve_id": c.strip()} for c in cve_str.split(",") if c.strip()]
    _ok("target_host", fqdn)
    _ok("cves", [c["cve_id"] for c in cves])

    try:
        result = plan_insights_core(cves=cves, target_host=fqdn)
        if result.get("error"):
            print(f"  [plan error] {result.get('message')}")
            print(f"  stage: {result.get('stage')}")
        else:
            _ok("remediation_id", result["remediation_id"])
            _ok("system_uuid", result["system_uuid"])
            _ok("matched", result["matched"])
            _ok("skipped", result["skipped"])
            _ok("coverage_summary", result["coverage_summary"])
            return result["remediation_id"]
    except InsightsError as exc:
        _err(exc)
    return None


# ── Test 5: remediate_insights dry-run ───────────────────────────────────────

def test_remediate_dry_run(remediation_id: str) -> None:
    _header("Test 5: remediate_insights — dry_run=True")
    try:
        result = remediate_insights_core(remediation_id=remediation_id, dry_run=True)
        _ok("dry_run", result.get("dry_run"))
        _ok("runnable", result.get("runnable"))
        _ok("name", result.get("name"))
        _ok("issue_count", result.get("issue_count"))
        _ok("system_count", result.get("system_count"))
        _ok("archived", result.get("archived"))
        _ok("message", result.get("message"))
        _ok("console_url", result.get("console_url"))
    except InsightsError as exc:
        _err(exc)


# ── Test 6: remediate_insights live run (explicit opt-in only) ────────────────

def test_remediate_live(remediation_id: str) -> None:
    _header("Test 6: remediate_insights — live run (INSIGHTS_LIVE_RUN=1 to enable)")
    if os.environ.get("INSIGHTS_LIVE_RUN") != "1":
        _skip("set INSIGHTS_LIVE_RUN=1 to dispatch a real playbook run")
        return
    try:
        result = remediate_insights_core(
            remediation_id=remediation_id,
            dry_run=False,
        )
        _ok("run_id", result.get("run_id"))
        _ok("status", result.get("status"))
        _ok("started_at", result.get("started_at"))
        _ok("finished_at", result.get("finished_at"))
        _ok("console_url", result.get("console_url"))
        if result.get("message"):
            _ok("message", result["message"])
    except InsightsError as exc:
        _err(exc)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("[test_insights] starting")

    token = test_auth()
    if not token:
        print("\n[test_insights] auth failed or skipped — stopping here.")
        return

    system_id = test_inventory(token)

    if system_id:
        test_vulnerability(token, system_id)

    # plan test creates a remediation_id; if one is already provided via env, use that too
    new_remediation_id = test_plan_insights()

    remediation_id = (
        new_remediation_id
        or os.environ.get("TEST_REMEDIATION_ID", "")
    )
    if remediation_id:
        test_remediate_dry_run(remediation_id)
        test_remediate_live(remediation_id)
    else:
        _header("Tests 5 & 6: remediate_insights")
        _skip("no remediation_id available — run test 4 first or set TEST_REMEDIATION_ID")

    print("\n[test_insights] done.")


if __name__ == "__main__":
    main()
