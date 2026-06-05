#!/usr/bin/env python3
"""Standalone test for suggest_v2 scan logic.

Exercises all three target types with real syft calls so that scan bugs can
be isolated from MCP wiring before the tool is deployed.

Usage:
    python scripts/test_suggest_v2.py

Env vars:
    TEST_SSH_TARGET   user@hostname for SSH test (test skipped when unset)
    TEST_IMAGE        container image for image test (default: alpine:latest)
    TEST_LOCAL_PATH   local directory for path test (default: /usr/bin)
    SSH_KEY_PATH      path to SSH private key (default: /etc/ssh-key/id_ed25519)
    REDFORGE_CONFIG   path to redforge.toml
    SYFT_TIMEOUT      scan timeout in seconds (default: 300)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from redforge.config import load as load_config
from redforge.commands.suggest_v2 import (
    ScanError,
    detect_target_type,
    get_syft_version,
    suggest_v2_core,
)

_CONFIG_PATH = os.environ.get(
    "REDFORGE_CONFIG",
    str(Path(__file__).parents[1] / "redforge.toml"),
)


def _header(title: str) -> None:
    print(f"\n{'=' * 60}\n{title}\n{'=' * 60}")


def _print_result(result: dict) -> None:
    if result.get("error"):
        print(f"  [SCAN ERROR]  {result.get('message')}")
        print(f"  stage:        {result.get('stage')}")
        print(f"  exit_code:    {result.get('exit_code')}")
        print(f"  hint:         {result.get('hint')}")
        stderr = (result.get("stderr") or "")[:500]
        if stderr:
            print(f"  stderr:\n{stderr}")
        return

    meta = result.get("scan_metadata", {})
    summary = result.get("summary") or {}
    diagnostics = result.get("diagnostics", {})

    print(f"  syft_version:       {meta.get('syft_version')}")
    print(f"  component_count:    {meta.get('component_count')}")
    print(f"  duration_seconds:   {meta.get('duration_seconds')}")
    print(f"  stage_reached:      {meta.get('stage_reached')}")
    print(f"  components_seen:    {summary.get('components_seen')}")
    print(f"  components_matched: {summary.get('components_matched')}")
    print(f"  candidate_cves:     {summary.get('candidate_cves')}")
    print(f"  returned_items:     {summary.get('returned_items')}")

    cw = diagnostics.get("coverage_warning")
    if cw:
        print(f"  [WARN] {cw}")

    items = result.get("items") or []
    if items:
        top = items[0]
        print(
            f"  top CVE: {top.get('cve_id')}  "
            f"class={top.get('priority_class')}  cvss={top.get('cvss')}"
        )
    else:
        print("  (no CVEs returned)")


def test_ssh(config: dict) -> None:
    _header("Test 1: SSH remote host")
    target = os.environ.get("TEST_SSH_TARGET", "")
    if not target:
        print("  SKIPPED — set TEST_SSH_TARGET=user@hostname to run this test")
        return

    print(f"  target:        {target}")
    print(f"  detected type: {detect_target_type(target)}")
    try:
        result = suggest_v2_core(config, target=target, scan_path="/", top_n=10)
        _print_result(result)
    except ScanError as exc:
        print(f"  ScanError: {exc}")
        print(f"  hint: {exc.hint}")
        if exc.stderr:
            print(f"  stderr: {exc.stderr[:300]}")


def test_image(config: dict) -> None:
    _header("Test 2: Container image")
    target = os.environ.get("TEST_IMAGE", "alpine:latest")
    print(f"  target:        {target}")
    print(f"  detected type: {detect_target_type(target)}")
    try:
        result = suggest_v2_core(config, target=target, top_n=10)
        _print_result(result)
    except ScanError as exc:
        print(f"  ScanError: {exc}")
        print(f"  hint: {exc.hint}")
        if exc.stderr:
            print(f"  stderr: {exc.stderr[:300]}")


def test_local_path(config: dict) -> None:
    _header("Test 3: Local filesystem path")
    target = os.environ.get("TEST_LOCAL_PATH", "/usr/bin")
    print(f"  target:        {target}")
    print(f"  detected type: {detect_target_type(target)}")
    try:
        result = suggest_v2_core(config, target=target, top_n=10)
        _print_result(result)
    except ScanError as exc:
        print(f"  ScanError: {exc}")
        print(f"  hint: {exc.hint}")
        if exc.stderr:
            print(f"  stderr: {exc.stderr[:300]}")


def main() -> None:
    print(f"[test_suggest_v2] syft version:  {get_syft_version()}")
    print(f"[test_suggest_v2] config:        {_CONFIG_PATH}")

    try:
        config = load_config(_CONFIG_PATH)
    except Exception as exc:
        print(f"[test_suggest_v2] failed to load config: {exc}")
        sys.exit(1)

    test_ssh(config)
    test_image(config)
    test_local_path(config)

    print("\n[test_suggest_v2] done.")


if __name__ == "__main__":
    main()
