"""RedForge MCP server — exposes CVE query, download, ingest, SPARQL, and report tools.

Start (stdio, for Claude Desktop):
  ./redforge.py mcp

Start (HTTP, for containers / network clients):
  ./redforge.py mcp --transport http --host 0.0.0.0 --port 8000

Or directly:
  REDFORGE_CONFIG=redforge.toml python -m redforge.mcp
"""

from __future__ import annotations

import io
import json
import os
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastmcp import FastMCP

_here = Path(__file__).parent
sys.path.insert(0, str(_here.parents[1]))  # root/ (for datakit)
sys.path.insert(0, str(_here.parent))      # src/  (for redforge package)

from redforge.config import load as _load_config
from redforge.pipeline import load_graph as _load_graph

_CONFIG_PATH = os.environ.get(
    "REDFORGE_CONFIG",
    str(Path(__file__).parents[2] / "redforge.toml"),
)
_config = _load_config(_CONFIG_PATH)
_graph = _load_graph(_config)

_ONTOLOGY_PATH = Path(__file__).parent / "ontology" / "vuln.ttl"
_LOGS_DIR = Path("logs")
_MCP_TRANSPORT = "unknown"
_MCP_BIND = None  # (host, port) when applicable
_FIRST_TOOL_CALL_SEEN = False
_LOG_WRITE_ERROR_SHOWN = False

# Background scan jobs: job_id → {status, started, result, error, cache_file}
_scan_jobs: dict[str, dict] = {}

mcp = FastMCP(
    "RedForge",
    instructions=(
        "RedForge is a CVE intelligence and remediation tool for Red Hat products. "
        "Call 'list_products' to see available products and versions. "
        "Call 'query' to get priority-ranked CVEs for a product. "
        "Call 'suggest' with a CycloneDX JSON SBOM to get a global top-N list. "
        "For deeper analysis, call 'download' then 'ingest' to rebuild the "
        "knowledge graph, then use 'sparql_query' with the 'redforge://ontology' "
        "resource as schema reference. "
        "Call 'export_report' to get a JSON report of actionable CVEs "
        "ready to take to the Red Hat Console for remediation."
    ),
)

def _log_path_for_day(ts: datetime) -> Path:
    # One file per UTC day to keep rotations simple.
    return _LOGS_DIR / f"redforge-mcp-{ts.strftime('%Y-%m-%d')}.log"


def _stderr_log(message: str) -> None:
    try:
        print(message, file=sys.stderr, flush=True)
    except Exception:
        return


def _format_log_value(value: object) -> str:
    if isinstance(value, dict):
        inner = ", ".join(f"{k}={_format_log_value(v)}" for k, v in value.items())
        return "{" + inner + "}"
    if isinstance(value, (list, tuple, set)):
        inner = ", ".join(_format_log_value(v) for v in value)
        return "[" + inner + "]"
    text = str(value)
    if any(ch.isspace() for ch in text) or any(ch in text for ch in "={}[],"):
        return repr(text)
    return text


def _format_log_line(event: dict) -> str:
    parts = [f"{key}={_format_log_value(value)}" for key, value in event.items()]
    return " ".join(parts)


def _safe_write_log(path: Path, event: dict) -> None:
    global _LOG_WRITE_ERROR_SHOWN
    try:
        _LOGS_DIR.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(_format_log_line(event) + "\n")
    except Exception:
        if not _LOG_WRITE_ERROR_SHOWN:
            _stderr_log(f"[redforge-mcp] log write failed: {path}")
            _LOG_WRITE_ERROR_SHOWN = True


def _init_log_file() -> None:
    ts = datetime.now(timezone.utc)
    path = _log_path_for_day(ts)
    event = {
        "ts": ts.isoformat(timespec="seconds"),
        "event": "startup",
        "transport": _MCP_TRANSPORT,
        "bind": _MCP_BIND,
        "cwd": str(Path.cwd()),
        "config_path": _CONFIG_PATH,
        "pid": os.getpid(),
    }
    _safe_write_log(path, event)


def _summarize_sbom(sbom: object) -> dict:
    if isinstance(sbom, dict):
        comps = sbom.get("components")
        return {
            "type": "dict",
            "bomFormat": sbom.get("bomFormat"),
            "specVersion": sbom.get("specVersion"),
            "component_count": len(comps) if isinstance(comps, list) else None,
        }
    return {"type": type(sbom).__name__}


def _tool_log(tool: str, args_summary: dict, started: float, ok: bool, err: str | None = None) -> None:
    global _FIRST_TOOL_CALL_SEEN
    ts = datetime.now(timezone.utc)
    duration_ms = int((time.perf_counter() - started) * 1000)
    event = {
        "ts": ts.isoformat(timespec="seconds"),
        "tool": tool,
        "ok": ok,
        "duration_ms": duration_ms,
        "source": {
            "transport": _MCP_TRANSPORT,
            "bind": _MCP_BIND,
        },
        "args": args_summary,
        "config_path": _CONFIG_PATH,
        "pid": os.getpid(),
    }
    if err:
        event["error"] = err
    if not _FIRST_TOOL_CALL_SEEN:
        _stderr_log(f"[redforge-mcp] client active transport={_MCP_TRANSPORT}")
        _FIRST_TOOL_CALL_SEEN = True
    status = "ok" if ok else "error"
    _stderr_log(f"[redforge-mcp] tool={tool} status={status} duration_ms={duration_ms}")
    _safe_write_log(_log_path_for_day(ts), event)


# ── Tools ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def list_products() -> dict:
    """List all configured products and their available versions.

    Returns:
        Dict mapping product label to {name, versions}.
    """
    started = time.perf_counter()
    try:
        out = {
            label: {"name": info.get("name", label), "versions": info.get("versions", [])}
            for label, info in _config.get("products", {}).items()
            if label != "families" and isinstance(info, dict)
        }
        _tool_log("list_products", {}, started, ok=True)
        return out
    except Exception as exc:
        _tool_log("list_products", {}, started, ok=False, err=str(exc))
        raise


@mcp.tool()
def whoami_session() -> dict:
    """Return the active MCP process identity and logging context."""
    ts = datetime.now(timezone.utc)
    return {
        "pid": os.getpid(),
        "cwd": str(Path.cwd()),
        "config_path": _CONFIG_PATH,
        "transport": _MCP_TRANSPORT,
        "bind": _MCP_BIND,
        "log_dir": str(_LOGS_DIR.resolve()),
        "log_file": str(_log_path_for_day(ts).resolve()),
    }


@mcp.tool()
def query(
    product: str = "all",
    version: str = "all",
    min_cvss: float = 0.0,
    severity: str = "low",
    sort_by: str = "priority",
    limit: int = 50,
) -> str:
    """Query priority-ranked CVEs from the RDF knowledge graph.

    Call 'list_products' first to find valid product labels and versions.

    Args:
        product: Product label (e.g. "rhel", "ocp", "aap") or "all".
        version: Version string (e.g. "9", "4.17") or "all".
        min_cvss: Minimum CVSS base score 0.0–10.0.
        severity: Minimum severity — "low", "medium", "high", or "critical".
        sort_by: Sort order — "priority" (default), "cvss", "cve_id", "public_date".
        limit: Max rows to return (default 50).

    Returns:
        JSON array of CVE result rows produced from a SPARQL-backed query.
    """
    started = time.perf_counter()
    from redforge.commands.query import run_query

    try:
        df = run_query(
            _config,
            product=product,
            version=version,
            min_cvss=min_cvss,
            severity=severity,
            sort_by=sort_by,
            graph=_graph,
        )
        _tool_log(
            "query",
            {
                "product": product,
                "version": version,
                "min_cvss": min_cvss,
                "severity": severity,
                "sort_by": sort_by,
                "limit": limit,
            },
            started,
            ok=True,
        )
        return df.head(limit).to_json(orient="records", indent=2)
    except Exception as exc:
        _tool_log(
            "query",
            {"product": product, "version": version, "limit": limit},
            started,
            ok=False,
            err=str(exc),
        )
        raise


@mcp.tool()
def suggest(sbom: dict, top_n: int = 25) -> str:
    """Return the highest-priority CVEs affecting a CycloneDX SBOM estate.

    Args:
        sbom: CycloneDX JSON SBOM object.
        top_n: Number of CVEs to return (default 25).

    Returns:
        JSON object with summary, items, and diagnostics.
    """
    started = time.perf_counter()
    from redforge.commands.suggest import suggest_from_sbom

    try:
        result = suggest_from_sbom(_config, sbom=sbom, top_n=top_n)
        _tool_log("suggest", {"top_n": top_n, "sbom": _summarize_sbom(sbom)}, started, ok=True)
        return json.dumps(result, indent=2)
    except Exception as exc:
        _tool_log("suggest", {"top_n": top_n, "sbom": _summarize_sbom(sbom)}, started, ok=False, err=str(exc))
        raise


@mcp.tool()
def suggest_v2(
    target: str,
    target_type: str | None = None,
    top_n: int = 25,
    scan_path: str = "/",
    timeout: int = 0,
    force: bool = False,
    remote_sbom: bool = False,
    debug_save_path: str | None = None,
) -> str:
    """Generate a CycloneDX SBOM with syft, then return prioritized CVEs.

    Extends 'suggest' by adding SBOM generation. Auto-detects the target type
    from the value, or pass target_type explicitly.

    ASYNC: this call returns immediately with {"status":"scanning","job_id":...}.
    Poll suggest_v2_status(job_id) until it returns status="done" (or "error").
    Triage runs on every call and can take 20-30s, so the work always happens in
    the background to avoid agent-turn timeouts — even a cached SBOM is async.
    A cached SBOM is reused on repeat calls (skips syft); pass force=true to
    re-run syft and refresh the cache.

    Args:
        target: SSH target (user@host), container image reference, or local path.
        target_type: "ssh", "image", or "path". Auto-detected from target if omitted.
        top_n: Number of CVEs to return (default 25).
        scan_path: Directory to scan on a remote SSH host (default "/").
                   If this points to an existing SBOM file (CycloneDX JSON) on
                   the remote host, that file is read and used directly instead
                   of running syft — avoiding a potentially very long scan.
                   Ignored for image and path targets.
        timeout: Syft scan timeout in seconds. 0 uses the server default (SYFT_TIMEOUT
                 env var, fallback 600s). Large images or full-host scans may need
                 1200–1800s.
        force: Re-run syft even if a cached SBOM exists (default false).
        remote_sbom: SSH only. Treat scan_path as a pre-generated SBOM file on the
                     remote host: read it directly, never run syft, and never fall
                     back to a scan. Errors loudly if the file can't be read. The
                     deterministic, demo-safe way to use an existing SBOM.
        debug_save_path: When set, write the raw SBOM JSON to this path for inspection.

    Returns:
        JSON with {"status":"scanning","job_id":...}. Call suggest_v2_status(job_id)
        to retrieve the final result (summary, items, diagnostics, scan_metadata —
        same structure as 'suggest') or a structured error with
        stage="sbom_generation".

    SSH notes:
        The private key is read from SSH_KEY_PATH env var (e.g. /etc/ssh-key/id_ed25519).
        Never pass credentials as tool arguments.
        The remote SSH user must have passwordless sudo for syft to read the full filesystem.
    """
    started = time.perf_counter()
    from redforge.commands.suggest_v2 import (
        ScanError, detect_target_type, suggest_v2_core, _cache_path,
    )

    ssh_key_path = os.environ.get("SSH_KEY_PATH", "/etc/ssh-key/id_ed25519")
    effective_timeout = timeout if timeout > 0 else int(os.environ.get("SYFT_TIMEOUT", "600"))

    try:
        resolved_type = detect_target_type(target, target_type)
    except ValueError as exc:
        return json.dumps({"error": True, "stage": "input_validation", "message": str(exc)}, indent=2)

    args_summary = {"target": target, "target_type": resolved_type, "top_n": top_n, "scan_path": scan_path}

    # Always run in the background and return a job_id immediately. Triage runs
    # on every call (even on a cached SBOM) and can take 20-30s, which exceeds
    # the playground's agent-turn timeout — so we never block the tool call here.
    # The caller polls suggest_v2_status; each poll is sub-second.
    job_id = str(uuid.uuid4())
    cache_file = _cache_path(target, resolved_type, scan_path)
    _scan_jobs[job_id] = {
        "status": "running",
        "started": time.time(),
        "result": None,
        "error": None,
        "cache_file": str(cache_file),
    }

    def _run_scan() -> None:
        try:
            result = suggest_v2_core(
                _config,
                target=target,
                target_type=target_type,
                scan_path=scan_path,
                top_n=top_n,
                timeout=effective_timeout,
                ssh_key_path=ssh_key_path,
                debug_save_path=debug_save_path,
                force=force,
                remote_sbom=remote_sbom,
            )
            _scan_jobs[job_id]["result"] = result
            _scan_jobs[job_id]["status"] = "done"
            _tool_log("suggest_v2", args_summary, started, ok=True)
        except ScanError as exc:
            _scan_jobs[job_id]["error"] = str(exc)
            _scan_jobs[job_id]["error_detail"] = {
                "exit_code": exc.exit_code, "stderr": exc.stderr, "hint": exc.hint,
            }
            _scan_jobs[job_id]["status"] = "error"
            _tool_log("suggest_v2", args_summary, started, ok=False, err=str(exc))
        except Exception as exc:
            _scan_jobs[job_id]["error"] = str(exc)
            _scan_jobs[job_id]["status"] = "error"
            _tool_log("suggest_v2", args_summary, started, ok=False, err=str(exc))

    threading.Thread(target=_run_scan, daemon=True).start()
    return json.dumps({
        "status": "scanning",
        "job_id": job_id,
        "cache_file": str(cache_file),
        "message": "Scan started in background. Call suggest_v2_status with this job_id to check progress.",
    }, indent=2)


@mcp.tool()
def suggest_v2_status(job_id: str) -> str:
    """Check the status of a background suggest_v2 scan.

    Args:
        job_id: The job_id returned by suggest_v2 when a background scan was started.

    Returns:
        JSON with status="running" and elapsed_seconds while the scan is in progress.
        JSON with status="done" and the full suggest_v2 result when complete.
        JSON with status="error" and error details if the scan failed.
    """
    job = _scan_jobs.get(job_id)
    if job is None:
        return json.dumps({"error": True, "message": f"Unknown job_id: {job_id!r}. Only jobs from this server session are tracked."}, indent=2)

    if job["status"] == "running":
        elapsed = round(time.time() - job["started"], 1)
        return json.dumps({"status": "running", "job_id": job_id, "elapsed_seconds": elapsed}, indent=2)

    if job["status"] == "error":
        detail = job.get("error_detail", {})
        return json.dumps({
            "status": "error",
            "job_id": job_id,
            "error": True,
            "stage": "sbom_generation",
            "message": job["error"],
            **detail,
            "summary": None,
            "items": [],
            "diagnostics": {},
        }, indent=2)

    # done — return full result
    result = job["result"]
    return json.dumps({"status": "done", "job_id": job_id, **result}, indent=2)


@mcp.tool()
def generate_sbom(
    target: str,
    target_type: str | None = None,
    scan_path: str = "/",
    timeout: int = 0,
    force: bool = False,
    remote_sbom: bool = False,
    debug_save_path: str | None = None,
) -> str:
    """Generate a CycloneDX SBOM for a target and cache it — no CVE triage.

    Use this to pre-build the SBOM (the slow part for a fresh full-host scan)
    ahead of time and out of band. A later suggest_v2 for the same target and
    scan_path reuses the cached SBOM and only pays the fast triage cost.

    ASYNC: returns immediately with {"status":"scanning","job_id":...}. Poll
    generate_sbom_status(job_id) until status="done".

    Args:
        target: SSH target (user@host), container image reference, or local path.
        target_type: "ssh", "image", or "path". Auto-detected from target if omitted.
        scan_path: Directory to scan on a remote SSH host (default "/"). With
                   remote_sbom, this is the path to a pre-generated SBOM file.
                   Ignored for image and path targets.
        timeout: Syft scan timeout in seconds. 0 uses the server default.
        force: Re-run syft even if a cached SBOM exists (default false).
        remote_sbom: SSH only. Read scan_path as a pre-generated SBOM file instead
                     of running syft (no fallback). Errors loudly if unreadable.
        debug_save_path: When set, write the raw SBOM JSON to this path.

    Returns:
        JSON {"status":"scanning","job_id":...}. generate_sbom_status returns the
        SBOM metadata (component_count, cache_file, from_cache, sbom_source, …).
    """
    started = time.perf_counter()
    from redforge.commands.suggest_v2 import ScanError, detect_target_type, generate_sbom_core

    ssh_key_path = os.environ.get("SSH_KEY_PATH", "/etc/ssh-key/id_ed25519")
    effective_timeout = timeout if timeout > 0 else int(os.environ.get("SYFT_TIMEOUT", "600"))

    try:
        resolved_type = detect_target_type(target, target_type)
    except ValueError as exc:
        return json.dumps({"error": True, "stage": "input_validation", "message": str(exc)}, indent=2)

    args_summary = {"target": target, "target_type": resolved_type, "scan_path": scan_path}

    job_id = str(uuid.uuid4())
    _scan_jobs[job_id] = {"status": "running", "started": time.time(), "result": None, "error": None}

    def _run() -> None:
        try:
            metadata = generate_sbom_core(
                target=target,
                target_type=target_type,
                scan_path=scan_path,
                timeout=effective_timeout,
                ssh_key_path=ssh_key_path,
                force=force,
                remote_sbom=remote_sbom,
                debug_save_path=debug_save_path,
            )
            _scan_jobs[job_id]["result"] = metadata
            _scan_jobs[job_id]["status"] = "done"
            _tool_log("generate_sbom", args_summary, started, ok=True)
        except ScanError as exc:
            _scan_jobs[job_id]["error"] = str(exc)
            _scan_jobs[job_id]["error_detail"] = {"exit_code": exc.exit_code, "stderr": exc.stderr, "hint": exc.hint}
            _scan_jobs[job_id]["status"] = "error"
            _tool_log("generate_sbom", args_summary, started, ok=False, err=str(exc))
        except Exception as exc:
            _scan_jobs[job_id]["error"] = str(exc)
            _scan_jobs[job_id]["status"] = "error"
            _tool_log("generate_sbom", args_summary, started, ok=False, err=str(exc))

    threading.Thread(target=_run, daemon=True).start()
    return json.dumps({
        "status": "scanning",
        "job_id": job_id,
        "message": "SBOM generation started in background. Call generate_sbom_status with this job_id.",
    }, indent=2)


@mcp.tool()
def generate_sbom_status(job_id: str) -> str:
    """Check the status of a background generate_sbom job.

    Args:
        job_id: The job_id returned by generate_sbom.

    Returns:
        status="running" with elapsed_seconds while in progress;
        status="done" with the SBOM metadata (component_count, cache_file, …);
        status="error" with details on failure.
    """
    job = _scan_jobs.get(job_id)
    if job is None:
        return json.dumps({"error": True, "message": f"Unknown job_id: {job_id!r}. Only jobs from this server session are tracked."}, indent=2)

    if job["status"] == "running":
        elapsed = round(time.time() - job["started"], 1)
        return json.dumps({"status": "running", "job_id": job_id, "elapsed_seconds": elapsed}, indent=2)

    if job["status"] == "error":
        detail = job.get("error_detail", {})
        return json.dumps({
            "status": "error", "job_id": job_id, "error": True,
            "stage": "sbom_generation", "message": job["error"], **detail,
        }, indent=2)

    return json.dumps({"status": "done", "job_id": job_id, **job["result"]}, indent=2)


@mcp.tool()
def plan_insights(cves: list[dict], target_host: str) -> str:
    """Create a Red Hat Insights remediation plan for a list of CVEs on a specific host.

    Resolves the host to an inventory UUID, verifies each CVE applies to that system
    and has an available fix via the Vulnerability API, then creates a remediation plan
    for the resolvable subset. CVEs that don't apply or have no fix are reported in
    the skipped list — never silently dropped, never fabricated.

    Requires RH_OFFLINE_TOKEN to be set (injected from the redforge-rh-offline-token Secret).

    Args:
        cves: List of {cve_id} objects, e.g. [{"cve_id": "CVE-2021-44228"}].
        target_host: Fully-qualified hostname as it appears in Insights inventory
                     (e.g. "rhel8-redforge.internal").

    Returns:
        JSON with remediation_id, system_uuid, matched, skipped, coverage_summary.
        On any API failure: {error, stage, status_code, endpoint, body}.
    """
    started = time.perf_counter()
    from redforge.commands.insights import InsightsError, plan_insights_core

    args_summary = {"host": target_host, "cve_count": len(cves)}
    try:
        result = plan_insights_core(cves=cves, target_host=target_host)
        _tool_log("plan_insights", args_summary, started, ok=True)
        return json.dumps(result, indent=2)
    except InsightsError as exc:
        _tool_log("plan_insights", args_summary, started, ok=False, err=str(exc))
        return json.dumps(exc.to_dict(), indent=2)
    except Exception as exc:
        _tool_log("plan_insights", args_summary, started, ok=False, err=str(exc))
        raise


@mcp.tool()
def remediate_insights(remediation_id: str, dry_run: bool = False) -> str:
    """Execute or validate a Red Hat Insights remediation plan.

    Triggers a playbook run against the RHC-connected host and polls until the
    run reaches a terminal state (success/failure/canceled) or times out.

    With dry_run=True, validates that the plan is non-empty and not archived
    without dispatching anything.

    Requires RH_OFFLINE_TOKEN to be set (injected from the redforge-rh-offline-token Secret).

    Args:
        remediation_id: UUID returned by plan_insights.
        dry_run: If true, validate the plan is runnable without triggering execution.

    Returns:
        JSON with run_id, status, started_at, finished_at, console_url.
        dry_run=True returns {dry_run, remediation_id, runnable, issue_count, ...}.
        On any API failure: {error, stage, status_code, endpoint, body}.
    """
    started = time.perf_counter()
    from redforge.commands.insights import InsightsError, remediate_insights_core

    args_summary = {"remediation_id": remediation_id, "dry_run": dry_run}
    try:
        result = remediate_insights_core(
            remediation_id=remediation_id,
            dry_run=dry_run,
        )
        _tool_log("remediate_insights", args_summary, started, ok=True)
        return json.dumps(result, indent=2)
    except InsightsError as exc:
        _tool_log("remediate_insights", args_summary, started, ok=False, err=str(exc))
        return json.dumps(exc.to_dict(), indent=2)
    except Exception as exc:
        _tool_log("remediate_insights", args_summary, started, ok=False, err=str(exc))
        raise


@mcp.tool()
def download(force: bool = False) -> dict[str, str]:
    """Fetch CVE/KEV/Metasploit/ExploitDB/EPSS sources into the local cache.

    Args:
        force: Re-download even if files already exist.

    Returns:
        Dict mapping source name to local file path.
    """
    started = time.perf_counter()
    from redforge.commands.sync import run_sync

    try:
        paths = run_sync(_config, force=force)
        _tool_log("download", {"force": force}, started, ok=True)
        return {name: str(path) for name, path in paths.items()}
    except Exception as exc:
        _tool_log("download", {"force": force}, started, ok=False, err=str(exc))
        raise


@mcp.tool()
def ingest() -> dict[str, int]:
    """Join all data sources and convert to an RDF knowledge graph.

    Requires 'download' to have been run first.
    Produces data/rdf/redforge.ttl, which 'sparql_query' reads.

    Returns:
        Dict mapping product short-name to CVE count.
    """
    started = time.perf_counter()
    from redforge.pipeline import pull, rdfize

    try:
        results = pull(_config)
        rdfize(results, _config)
        _tool_log("ingest", {}, started, ok=True)
        return {short: len(df) for short, df in results.items()}
    except Exception as exc:
        _tool_log("ingest", {}, started, ok=False, err=str(exc))
        raise


@mcp.tool()
def export_report(
    priority_threshold: str = "Attend",
    top_n: int = 50,
    product: str = "all",
) -> str:
    """Export a JSON report of highest-priority actionable CVEs.

    This report is designed to be taken to the Red Hat Console for remediation.
    Red Hat's native tools (Insights, Ansible Automation Platform, patch
    management) can consume this list to generate and apply fixes.

    Args:
        priority_threshold: Minimum priority class — "Act", "Attend", "Track", or "Defer".
        top_n: Max CVEs to include.
        product: Product label (e.g. "rhel") or "all".

    Returns:
        JSON object with generated_at, priority_threshold, cve_count,
        summary_by_priority, and an items array of actionable CVEs.
    """
    started = time.perf_counter()
    from redforge.commands.query import run_query_dataframe
    from datetime import datetime

    try:
        df = run_query_dataframe(_config, product=product, sort_by="priority")

        _PRIORITY_ORDER = ["1-Act", "2-Attend", "3-Track", "4-Defer"]
        threshold_short = priority_threshold.capitalize()
        priority_map = {s.split("-", 1)[1]: s for s in _PRIORITY_ORDER}
        threshold_label = priority_map.get(threshold_short, "2-Attend")
        threshold_idx = _PRIORITY_ORDER.index(threshold_label) if threshold_label in _PRIORITY_ORDER else 1

        if "priority_class" in df.columns:
            df["_prio_order"] = df["priority_class"].map({c: i for i, c in enumerate(_PRIORITY_ORDER)})
            df = df[df["_prio_order"] <= threshold_idx]
            df = df.drop(columns=["_prio_order"])

        df = df.head(top_n)

        summary_by_priority = {}
        if "priority_class" in df.columns:
            counts = df["priority_class"].value_counts().to_dict()
            summary_by_priority = {k: int(v) for k, v in counts.items()}

        items = []
        cols = ["priority_rank", "priority_class", "cve_id", "vuln_name", "cvss", "severity", "is_kev", "has_public_exploit", "public_date"]
        for _, row in df.iterrows():
            item = {}
            for col in cols:
                if col in df.columns:
                    val = row[col]
                    if isinstance(val, (float,)) and pd.isna(val):
                        val = None
                    elif isinstance(val, (bool,)):
                        val = bool(val)
                    item[col] = val
            items.append(item)

        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "priority_threshold": priority_threshold,
            "product": product,
            "cve_count": len(df),
            "summary_by_priority": summary_by_priority,
            "items": items,
            "instructions": (
                "Take this report to the Red Hat Console. Use Insights to find "
                "affected systems and Ansible Automation Platform to remediate. "
                "For each CVE, search the Red Hat CVE Database for the associated "
                "RHSA advisory and apply via 'dnf update --advisory=RHSA-XXXX:XXXX'."
            ),
        }

        _tool_log("export_report", {"priority_threshold": priority_threshold, "top_n": top_n, "product": product}, started, ok=True)
        return json.dumps(report, indent=2)
    except Exception as exc:
        _tool_log("export_report", {"priority_threshold": priority_threshold, "top_n": top_n}, started, ok=False, err=str(exc))
        raise


@mcp.tool()
def sparql_query(query: str) -> str:
    """Run a SPARQL SELECT against the RedForge RDF knowledge graph.

    Read the 'redforge://ontology' resource for the full schema before
    writing queries.

    Quick reference:
      Prefixes:
        vs:  = <http://redforge.local/ontology#>
        res: = <http://redforge.local/resource/>

      Classes:
        vs:Vulnerability   — a CVE entry
        vs:Product         — e.g. vs:product-rhel8, vs:product-rhel9
        vs:CVSSMetric      — CVSS scoring record (blank node)
        vs:KEVEntry        — CISA KEV catalog entry
        vs:ExploitModule   — Metasploit / ExploitDB module

      Key properties on vs:Vulnerability:
        dcterms:identifier  CVE ID string (e.g. "CVE-2021-44228")
        dcterms:issued      public date (xsd:date)
        vs:affectsProduct   → vs:Product
        vs:severity         → vs:CriticalSeverity | vs:HighSeverity |
                               vs:MediumSeverity  | vs:LowSeverity
        vs:hasCvssMetric    → vs:CVSSMetric  (vs:baseScore xsd:decimal)
        vs:hasKEVEntry      → vs:KEVEntry    (dcterms:date xsd:date)
        vs:hasExploit       → vs:ExploitModule (rdfs:label module name)

    Example — critical CVEs in KEV with a Metasploit module:
      PREFIX vs:  <http://redforge.local/ontology#>
      PREFIX dct: <http://purl.org/dc/terms/>
      SELECT ?id ?product WHERE {
        ?cve a vs:Vulnerability ;
             dct:identifier ?id ;
             vs:severity vs:CriticalSeverity ;
             vs:affectsProduct ?product ;
             vs:hasKEVEntry ?kev ;
             vs:hasExploit ?exploit .
      }

    Args:
        query: A SPARQL 1.1 SELECT query string.

    Returns:
        JSON array of result rows (one object per row, keyed by variable name).
    """
    started = time.perf_counter()
    from redforge.pipeline import query as run_query
    from redforge.commands.query import normalize_sparql_input

    try:
        df = run_query(_graph, normalize_sparql_input(query))
        _tool_log(
            "sparql_query",
            {"query_len": len(query or ""), "query_prefix": (query or "")[:80]},
            started,
            ok=True,
        )
        return df.to_json(orient="records", indent=2)
    except Exception as exc:
        _tool_log("sparql_query", {"query_len": len(query or "")}, started, ok=False, err=str(exc))
        raise


# ── Resources ─────────────────────────────────────────────────────────────────

@mcp.resource("redforge://ontology")
def ontology() -> str:
    """The RedForge OWL ontology in Turtle format.

    Read this before writing SPARQL queries to understand the full class
    hierarchy, properties, domains, ranges, and severity vocabulary.
    """
    return _ONTOLOGY_PATH.read_text(encoding="utf-8")


# ── Stdin blank-line filter (stdio transport only) ────────────────────────────

class _BlankLineFilter(io.RawIOBase):
    """Wraps sys.stdin's raw buffer, dropping bare blank lines.

    Some MCP clients (e.g. Claude Desktop) send a bare '\\n' between
    JSON-RPC messages. The mcp library treats empty lines as malformed
    JSON and sends spurious "Internal Server Error" notifications.
    This filter intercepts blank lines before they reach the parser.
    """

    def __init__(self, buf: io.RawIOBase) -> None:
        self._buf = buf

    def readable(self) -> bool:
        return True

    def readline(self, size: int = -1) -> bytes:
        while True:
            line = self._buf.readline() if size < 0 else self._buf.readline(size)
            if not line or line.strip(b" \t\r\n"):
                return line
            # blank line — skip and read the next one

    def readinto(self, b: bytearray) -> int:
        line = self.readline()
        if not line:
            return 0
        n = min(len(line), len(b))
        b[:n] = line[:n]
        return n


def _patch_stdin() -> None:
    """Replace sys.stdin with a blank-line-filtered version."""
    raw = getattr(sys.stdin.buffer, "raw", sys.stdin.buffer)
    sys.stdin = io.TextIOWrapper(
        io.BufferedReader(_BlankLineFilter(raw)),
        encoding="utf-8",
        errors="replace",
    )


# ── Entry point ───────────────────────────────────────────────────────────────

def run(
    transport: str = "stdio",
    host: str = "0.0.0.0",
    port: int = 8000,
) -> None:
    """Entry point for ./redforge.py mcp."""
    global _MCP_TRANSPORT, _MCP_BIND
    _MCP_TRANSPORT = transport
    _MCP_BIND = (host, port) if transport != "stdio" else None
    _stderr_log(
        f"[redforge-mcp] starting transport={transport} "
        f"cwd={Path.cwd()} config={_CONFIG_PATH} log_dir={_LOGS_DIR.resolve()}"
    )
    _init_log_file()
    if transport == "stdio":
        _patch_stdin()
        mcp.run(transport="stdio", show_banner=False)
    else:
        mcp.run(transport=transport, host=host, port=port, show_banner=False)


if __name__ == "__main__":
    run()
