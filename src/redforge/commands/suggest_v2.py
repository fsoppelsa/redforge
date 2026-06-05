"""suggest_v2: syft SBOM generation + existing prioritization in one pipeline.

The only new responsibility here is producing the CycloneDX SBOM via syft
and handing it to suggest_from_sbom. No prioritization logic is reimplemented.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .suggest import suggest_from_sbom

_DEFAULT_TIMEOUT = int(os.environ.get("SYFT_TIMEOUT", "600"))
_DEFAULT_SSH_KEY_PATH = os.environ.get("SSH_KEY_PATH", "/etc/ssh-key/id_ed25519")
_SBOM_CACHE_DIR = Path(os.environ.get("SYFT_CACHE_DIR", "/tmp/redforge-sbom"))


class ScanError(Exception):
    """Raised when SBOM generation fails (scan stage, not triage)."""

    def __init__(
        self,
        message: str,
        exit_code: int | None = None,
        stderr: str = "",
        hint: str = "",
    ) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.stderr = stderr
        self.hint = hint


def detect_target_type(target: str, explicit: str | None = None) -> str:
    """Return 'ssh', 'image', or 'path'. Raises ValueError for unknown explicit types."""
    if explicit:
        t = explicit.lower()
        if t not in ("ssh", "image", "path"):
            raise ValueError(f"Unknown target_type: {explicit!r}. Use 'ssh', 'image', or 'path'.")
        return t
    # SSH: user@hostname — contains @ and doesn't start with a path prefix
    if "@" in target and not target.startswith("/") and not target.startswith("."):
        return "ssh"
    # Local path: rooted, relative, or already exists on disk
    if target.startswith("/") or target.startswith(".") or Path(target).exists():
        return "path"
    return "image"


def get_syft_version(syft_bin: str = "syft") -> str:
    """Return the installed syft version string, or 'unknown' on failure."""
    try:
        r = subprocess.run([syft_bin, "--version"], capture_output=True, text=True, timeout=10)
        first = (r.stdout or "").strip().splitlines()[0] if (r.stdout or "").strip() else ""
        m = re.search(r"(\d+\.\d+[\.\d]*)", first)
        return m.group(1) if m else first or "unknown"
    except Exception:
        return "unknown"


# ── SSH scanning ──────────────────────────────────────────────────────────────

def _ssh_options(ssh_key_path: str) -> list[str]:
    """Shared ssh client options for non-interactive, key-based connections."""
    return [
        "-i", ssh_key_path,
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "UserKnownHostsFile=/tmp/known_hosts",
    ]


def _ssh_hint(stderr: str, exit_code: int) -> str:
    lower = stderr.lower()
    if "permission denied" in lower or "publickey" in lower:
        return (
            "SSH authentication failed. Verify SSH_KEY_PATH points to the correct private key "
            "and the public key is listed in ~/.ssh/authorized_keys on the target host."
        )
    if any(x in lower for x in ("connection timed out", "no route to host", "connection refused")):
        return "Host unreachable or port 22 blocked. Verify hostname and network connectivity."
    if "sudo" in lower and any(x in lower for x in ("password", "tty", "sorry")):
        return (
            "sudo prompted for a password, which caused the SSH session to hang or fail. "
            "Configure passwordless sudo: add 'user ALL=(ALL) NOPASSWD: ALL' to /etc/sudoers.d/."
        )
    if exit_code == 127:
        return "syft not found on the remote host. Install syft on the target machine."
    return "SSH scan failed. Review stderr for details."


def _run_syft_ssh(
    target: str,
    scan_path: str,
    timeout: int,
    ssh_key_path: str,
) -> tuple[str, str]:
    """Run syft over SSH. Returns (stdout, stderr). Raises ScanError on failure."""
    if not shutil.which("ssh"):
        raise ScanError("ssh not found in PATH", hint="Ensure openssh-client is installed.")

    cmd = [
        "ssh",
        "-i", ssh_key_path,
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "UserKnownHostsFile=/tmp/known_hosts",
        target,
        f"sudo syft dir:{scan_path} -o cyclonedx-json",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ScanError(
            f"SSH scan timed out after {timeout}s",
            hint=(
                "Timeout usually means a sudo password prompt or an extremely large filesystem. "
                "Verify passwordless sudo and consider narrowing scan_path."
            ),
        )

    stderr = result.stderr or ""
    stdout = result.stdout or ""

    if result.returncode != 0:
        raise ScanError(
            f"SSH scan failed (exit {result.returncode})",
            exit_code=result.returncode,
            stderr=stderr,
            hint=_ssh_hint(stderr, result.returncode),
        )

    if not stdout.strip():
        raise ScanError(
            "SSH scan produced empty stdout",
            exit_code=result.returncode,
            stderr=stderr,
            hint=(
                "Empty SBOM usually indicates a privilege or path problem. "
                "Verify the SSH user has passwordless sudo and scan_path exists on the host."
            ),
        )

    return stdout, stderr


def _remote_is_file(target: str, scan_path: str, ssh_key_path: str) -> bool:
    """Return True if scan_path is an existing regular file on the remote host.

    Best-effort probe: any ssh/connection failure returns False so the caller
    falls back to a normal syft directory scan (which surfaces the real error).
    """
    if not shutil.which("ssh"):
        return False
    cmd = ["ssh", *_ssh_options(ssh_key_path), target, f"test -f {shlex.quote(scan_path)}"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        return False
    return result.returncode == 0


def _read_remote_sbom(
    target: str,
    scan_path: str,
    timeout: int,
    ssh_key_path: str,
) -> tuple[str, str]:
    """Read a pre-generated SBOM file from the remote host over SSH.

    Returns (stdout, stderr). Raises ScanError on failure or empty output.
    """
    cmd = ["ssh", *_ssh_options(ssh_key_path), target, f"sudo cat {shlex.quote(scan_path)}"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ScanError(
            f"Reading remote SBOM timed out after {timeout}s",
            hint="The SBOM file may be very large, or sudo prompted for a password.",
        )

    stderr = result.stderr or ""
    stdout = result.stdout or ""

    if result.returncode != 0:
        if "no such file" in stderr.lower():
            hint = f"{scan_path} does not exist on the host. Generate the SBOM there first, or omit remote_sbom to scan."
        else:
            hint = _ssh_hint(stderr, result.returncode)
        raise ScanError(
            f"Failed to read remote SBOM file (exit {result.returncode})",
            exit_code=result.returncode,
            stderr=stderr,
            hint=hint,
        )

    if not stdout.strip():
        raise ScanError(
            "Remote SBOM file is empty",
            exit_code=result.returncode,
            stderr=stderr,
            hint=f"{scan_path} exists on the host but contains no data.",
        )

    return stdout, stderr


# ── Local scanning ─────────────────────────────────────────────────────────────

def _run_syft_local(syft_arg: str, timeout: int) -> tuple[str, str]:
    """Run syft locally on the MCP host. Returns (stdout, stderr). Raises ScanError."""
    syft_bin = shutil.which("syft")
    if not syft_bin:
        raise ScanError(
            "syft not found in PATH on the MCP host",
            hint="Install syft: https://github.com/anchore/syft",
        )

    cmd = [syft_bin, syft_arg, "-o", "cyclonedx-json"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ScanError(
            f"Local syft scan timed out after {timeout}s",
            hint="Try narrowing scan_path or increasing SYFT_TIMEOUT.",
        )

    stderr = result.stderr or ""
    stdout = result.stdout or ""

    if result.returncode != 0:
        raise ScanError(
            f"syft scan failed (exit {result.returncode})",
            exit_code=result.returncode,
            stderr=stderr,
            hint="Check the syft error output in stderr.",
        )

    if not stdout.strip():
        raise ScanError(
            "syft produced empty stdout",
            exit_code=result.returncode,
            stderr=stderr,
            hint="Empty SBOM may indicate a privilege problem or no components at the target path.",
        )

    return stdout, stderr


# ── SBOM cache ────────────────────────────────────────────────────────────────

def _cache_path(target: str, target_type: str, scan_path: str) -> Path:
    """Return the fixed cache path for this (target, scan_path) combination."""
    key = f"{target_type}__{target}__{scan_path}"
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", key)[:180]
    return _SBOM_CACHE_DIR / f"{safe}.json"


def _load_cached_sbom(path: Path) -> dict[str, Any] | None:
    """Return cached SBOM dict if the file exists, otherwise None."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _save_cached_sbom(path: Path, sbom: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")


# ── SBOM dispatch ──────────────────────────────────────────────────────────────

def scan_to_sbom(
    target: str,
    target_type: str,
    scan_path: str = "/",
    timeout: int = _DEFAULT_TIMEOUT,
    ssh_key_path: str = _DEFAULT_SSH_KEY_PATH,
    remote_sbom: bool = False,
) -> tuple[dict[str, Any], str, str]:
    """
    Run syft (or read a pre-generated SBOM) and return (sbom_dict, stderr, source).

    source is one of: "ssh_file" (read an existing SBOM off the remote host),
    "ssh_syft", "image", or "path". Raises ScanError on any failure or invalid
    output. Never returns an empty or unparseable SBOM.

    When remote_sbom is True, scan_path is treated as a pre-generated SBOM file
    on the SSH host and read directly — no syft scan, no fallback. This is the
    deterministic choice for demos; if the file can't be read it errors loudly.
    """
    if target_type == "ssh":
        # Read a pre-generated SBOM directly when asked explicitly (remote_sbom)
        # or when scan_path happens to point at an existing file — both skip the
        # potentially very long syft scan. remote_sbom never falls back to syft.
        if remote_sbom or _remote_is_file(target, scan_path, ssh_key_path):
            stdout, stderr = _read_remote_sbom(target, scan_path, timeout, ssh_key_path)
            source = "ssh_file"
        else:
            stdout, stderr = _run_syft_ssh(target, scan_path, timeout, ssh_key_path)
            source = "ssh_syft"
    elif target_type == "image":
        stdout, stderr = _run_syft_local(target, timeout)
        source = "image"
    elif target_type == "path":
        stdout, stderr = _run_syft_local(f"dir:{target}", timeout)
        source = "path"
    else:
        raise ValueError(f"Unknown target_type: {target_type!r}")

    try:
        sbom = json.loads(stdout)
    except json.JSONDecodeError as exc:
        if source == "ssh_file":
            hint = f"JSON parse error: {exc}. {scan_path} does not contain valid CycloneDX JSON."
        else:
            hint = f"JSON parse error: {exc}. Ensure syft writes only SBOM JSON to stdout."
        raise ScanError("SBOM output is not valid JSON", stderr=stderr, hint=hint)

    return sbom, stderr, source


# ── Public pipeline entry point ───────────────────────────────────────────────

def _acquire_sbom(
    target: str,
    target_type: str | None,
    scan_path: str,
    timeout: int,
    ssh_key_path: str,
    force: bool,
    remote_sbom: bool,
    debug_save_path: str | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Generate (or load from cache) the SBOM only — no triage.

    Returns (sbom, metadata). Shared by suggest_v2_core and generate_sbom_core so
    the cache/scan/source logic lives in exactly one place. The SBOM is saved to
    the shared cache after a fresh scan. Raises ScanError if the scan stage fails.
    """
    resolved_type = detect_target_type(target, target_type)
    if remote_sbom and resolved_type != "ssh":
        raise ScanError(
            f"remote_sbom is only valid for SSH targets, not {resolved_type!r}",
            hint="Drop remote_sbom, or pass an SSH target (user@host) with scan_path set to the SBOM file.",
        )
    reported_scan_path = scan_path if resolved_type == "ssh" else target
    cache_file = _cache_path(target, resolved_type, scan_path)

    t0 = time.perf_counter()
    from_cache = False
    sbom_source = "cache"

    if not force:
        cached = _load_cached_sbom(cache_file)
        if cached is not None:
            sbom = cached
            from_cache = True

    if not from_cache:
        sbom, _syft_stderr, sbom_source = scan_to_sbom(
            target=target,
            target_type=resolved_type,
            scan_path=scan_path,
            timeout=timeout,
            ssh_key_path=ssh_key_path,
            remote_sbom=remote_sbom,
        )
        _save_cached_sbom(cache_file, sbom)
        syft_version = "remote-file" if sbom_source == "ssh_file" else get_syft_version()
    else:
        syft_version = "cached"

    if debug_save_path:
        Path(debug_save_path).write_text(json.dumps(sbom, indent=2), encoding="utf-8")

    metadata: dict[str, Any] = {
        "target": target,
        "target_type": resolved_type,
        "scan_path": reported_scan_path,
        "sbom_source": sbom_source,
        "syft_version": syft_version,
        "component_count": len(sbom.get("components") or []),
        "duration_seconds": round(time.perf_counter() - t0, 2),
        "from_cache": from_cache,
        "cache_file": str(cache_file),
    }
    return sbom, metadata


def generate_sbom_core(
    target: str,
    target_type: str | None = None,
    scan_path: str = "/",
    timeout: int = _DEFAULT_TIMEOUT,
    ssh_key_path: str = _DEFAULT_SSH_KEY_PATH,
    force: bool = False,
    remote_sbom: bool = False,
    debug_save_path: str | None = None,
) -> dict[str, Any]:
    """Generate (or reuse cached) the CycloneDX SBOM only — no CVE triage.

    Returns the scan_metadata block (component_count, cache_file, from_cache, …).
    The SBOM is written to the shared cache so a later suggest_v2 for the same
    target/scan_path reuses it and only pays the triage cost. Raises ScanError if
    the scan stage fails.
    """
    _sbom, metadata = _acquire_sbom(
        target, target_type, scan_path, timeout, ssh_key_path, force, remote_sbom, debug_save_path
    )
    metadata["stage_reached"] = "sbom_generated"
    return metadata


def sbom_cache_status(
    target: str,
    target_type: str | None = None,
    scan_path: str = "/",
) -> dict[str, Any]:
    """Report whether a cached SBOM exists for this target/scan_path — no scan.

    Read-only: never runs syft or SSH. Returns the cached flag plus component_count,
    size and age when a cached SBOM is present. Uses the same cache key as
    suggest_v2/generate_sbom, so a True result means suggest_v2 will reuse it.
    """
    resolved_type = detect_target_type(target, target_type)
    cache_file = _cache_path(target, resolved_type, scan_path)
    reported_scan_path = scan_path if resolved_type == "ssh" else target

    status: dict[str, Any] = {
        "cached": cache_file.exists(),
        "target": target,
        "target_type": resolved_type,
        "scan_path": reported_scan_path,
        "cache_file": str(cache_file),
    }
    if status["cached"]:
        sbom = _load_cached_sbom(cache_file)
        stat = cache_file.stat()
        status["component_count"] = len(sbom.get("components") or []) if sbom else None
        status["size_bytes"] = stat.st_size
        status["age_seconds"] = round(time.time() - stat.st_mtime, 1)
    return status


def suggest_v2_core(
    config: dict[str, Any],
    target: str,
    target_type: str | None = None,
    scan_path: str = "/",
    top_n: int = 25,
    timeout: int = _DEFAULT_TIMEOUT,
    ssh_key_path: str = _DEFAULT_SSH_KEY_PATH,
    debug_save_path: str | None = None,
    force: bool = False,
    remote_sbom: bool = False,
) -> dict[str, Any]:
    """
    Full suggest_v2 pipeline: detect target type, generate SBOM, triage.

    If a cached SBOM exists for this target it is reused unless force=True.
    The SBOM is always saved to the cache after a fresh scan.

    When remote_sbom is True, scan_path is read as a pre-generated SBOM file on
    the SSH host (no syft scan, no fallback). Only valid for SSH targets.

    Returns a dict with summary, items, diagnostics (same shape as suggest_from_sbom),
    plus a scan_metadata block. Raises ScanError if the scan stage fails so that
    callers can distinguish scan failures from triage failures.
    """
    sbom, scan_metadata = _acquire_sbom(
        target, target_type, scan_path, timeout, ssh_key_path, force, remote_sbom, debug_save_path
    )
    scan_metadata["stage_reached"] = "triage"
    component_count = scan_metadata["component_count"]

    # Hand off to existing prioritization — no logic reimplemented here.
    result = suggest_from_sbom(config, sbom=sbom, top_n=top_n)

    scan_metadata["stage_reached"] = "complete"

    # Annotate diagnostics with a coverage warning when matching is partial.
    diagnostics = result.get("diagnostics", {})
    summary = result.get("summary", {})
    seen = summary.get("components_seen", 0)
    matched = summary.get("components_matched", 0)
    if component_count == 0:
        diagnostics["coverage_warning"] = (
            "SBOM contains 0 components. This may indicate a privilege or path problem "
            "on the scanned target. Verify syft had read access to the intended location."
        )
    elif seen > 0 and matched < seen:
        diagnostics["coverage_warning"] = (
            f"Only {matched}/{seen} components matched the CVE database. "
            "Coverage is incomplete; some vulnerabilities may not be reported."
        )

    return {
        "summary": result["summary"],
        "items": result["items"],
        "diagnostics": diagnostics,
        "scan_metadata": scan_metadata,
    }
