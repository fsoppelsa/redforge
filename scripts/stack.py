#!/usr/bin/env python3
"""Manage the local RedForge Podman stack."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
COMPOSE_FILE = REPO_ROOT / "podman-compose.yml"
TTL_PATH = REPO_ROOT / "data" / "rdf" / "redforge.ttl"
GRAPH_URI = os.environ.get("VIRTUOSO_DEFAULT_GRAPH", "http://redforge.local/graph/main")
VIRTUOSO_IMPORT_PATH = "/usr/share/proj/redforge.ttl"

PROFILE_SERVICES = {
    "minimal": ["virtuoso", "redforge-web"],
    "full": ["virtuoso", "redforge-web", "redforge-mcp", "pellet"],
}

ALL_SERVICES = ["redforge-web", "redforge-mcp", "virtuoso", "pellet"]

SERVICE_HINTS = {
    "redforge-web": "http://localhost:8501",
    "redforge-mcp": "stdio MCP server",
    "virtuoso": "http://localhost:8890/sparql",
    "pellet": "reasoner service",
}


def _console():
    try:
        from rich.console import Console

        return Console()
    except ImportError:
        return None


CONSOLE = _console()


def _print(msg: str) -> None:
    if CONSOLE is not None:
        CONSOLE.print(msg)
    else:
        print(msg, flush=True)


def _die(msg: str, code: int = 1) -> int:
    _print(f"[red]error:[/] {msg}" if CONSOLE is not None else f"error: {msg}")
    return code


def _run(
    args: list[str],
    *,
    capture: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.setdefault("PODMAN_COMPOSE_WARNING_LOGS", "false")
    return subprocess.run(
        args,
        cwd=str(REPO_ROOT),
        env=env,
        text=True,
        capture_output=capture,
        check=check,
    )


def _compose(args: list[str], *, capture: bool = False, check: bool = True) -> subprocess.CompletedProcess[str]:
    return _run(["podman", "compose", "-f", str(COMPOSE_FILE), *args], capture=capture, check=check)


def _podman(args: list[str], *, capture: bool = False, check: bool = True) -> subprocess.CompletedProcess[str]:
    return _run(["podman", *args], capture=capture, check=check)


def _require_prereqs() -> None:
    if shutil.which("podman") is None:
        raise SystemExit(_die("podman not found in PATH"))
    if not COMPOSE_FILE.exists():
        raise SystemExit(_die(f"{COMPOSE_FILE} not found"))


def _service_list(profile: str) -> list[str]:
    if profile not in PROFILE_SERVICES:
        raise SystemExit(_die(f"unknown profile '{profile}'"))
    return PROFILE_SERVICES[profile]


def _virt_isql(sql: str) -> subprocess.CompletedProcess[str]:
    shell = f"""
if command -v isql >/dev/null 2>&1; then
  isql 1111 dba "${{DBA_PASSWORD:-dba}}" VERBOSE=OFF PROMPT=OFF ERRORS=STDOUT <<'SQL'
{sql}
SQL
elif command -v isql-v >/dev/null 2>&1; then
  isql-v 1111 dba "${{DBA_PASSWORD:-dba}}" VERBOSE=OFF PROMPT=OFF ERRORS=STDOUT <<'SQL'
{sql}
SQL
elif command -v isql-vt >/dev/null 2>&1; then
  isql-vt 1111 dba "${{DBA_PASSWORD:-dba}}" VERBOSE=OFF PROMPT=OFF ERRORS=STDOUT <<'SQL'
{sql}
SQL
else
  echo 'error: no isql client found in virtuoso container' >&2
  exit 1
fi
"""
    return _podman(["exec", "virtuoso", "sh", "-lc", shell], capture=True, check=False)


def _virt_isql_checked(sql: str) -> tuple[bool, str]:
    proc = _virt_isql(sql)
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0 or "*** Error " in out:
        return False, out.strip()
    return True, out.strip()


def _wait_for_virtuoso(timeout_s: int = 60) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        ok, _ = _virt_isql_checked("SELECT 1;")
        if ok:
            return True
        time.sleep(2)
    return False


def _load_ttl_into_virtuoso() -> None:
    if not TTL_PATH.exists():
        _print(f"[yellow]warning:[/] {TTL_PATH} not found, skipping Virtuoso load" if CONSOLE else f"warning: {TTL_PATH} not found, skipping Virtuoso load")
        return

    _print("Waiting for Virtuoso SQL readiness...")
    if not _wait_for_virtuoso():
        _print("[yellow]warning:[/] Virtuoso not ready; skipping RDF load" if CONSOLE else "warning: Virtuoso not ready; skipping RDF load")
        return

    _print("Staging Turtle into Virtuoso import path...")
    _podman(["exec", "virtuoso", "sh", "-lc", "mkdir -p /usr/share/proj && cp -f /database/import/redforge.ttl /usr/share/proj/redforge.ttl"])

    _print(f"Loading Turtle into graph <{GRAPH_URI}> ...")
    ok, out = _virt_isql_checked(
        f"""
SPARQL CLEAR GRAPH <{GRAPH_URI}> ;
DELETE FROM DB.DBA.load_list WHERE ll_file = '{VIRTUOSO_IMPORT_PATH}' ;
ld_dir('/usr/share/proj', 'redforge.ttl', '{GRAPH_URI}') ;
rdf_loader_run() ;
checkpoint ;
"""
    )
    if not ok:
        raise SystemExit(_die(f"Virtuoso RDF load failed\n{out}"))
    ok, count_out = _virt_isql_checked(
        f"SPARQL SELECT (COUNT(*) AS ?n) FROM <{GRAPH_URI}> WHERE {{ ?s ?p ?o }} ;"
    )
    if not ok:
        raise SystemExit(_die(f"Virtuoso RDF load verification failed\n{count_out}"))
    lines = [line.strip() for line in count_out.splitlines() if line.strip()]
    triple_count = next((line for line in reversed(lines) if line.isdigit()), "0")
    if triple_count == "0":
        raise SystemExit(_die(f"Virtuoso RDF load produced an empty graph for <{GRAPH_URI}>"))
    _print("[green]ok:[/] Virtuoso RDF load completed" if CONSOLE else "ok: Virtuoso RDF load completed")


def _cmd_start(profile: str) -> int:
    services = _service_list(profile)
    _print(f"Starting profile '{profile}' ({', '.join(services)})")
    _compose(["up", "-d", *services])
    if "virtuoso" in services:
        _load_ttl_into_virtuoso()
    return 0


def _cmd_stop(profile: str) -> int:
    services = _service_list(profile)
    _print(f"Stopping profile '{profile}' ({', '.join(services)})")
    _compose(["stop", *services])
    return 0


def _cmd_restart(profile: str) -> int:
    _cmd_stop(profile)
    return _cmd_start(profile)


def _container_state(name: str) -> tuple[str, str]:
    proc = _podman(["inspect", name], capture=True, check=False)
    if proc.returncode != 0:
        return "absent", ""
    try:
        payload = json.loads(proc.stdout)[0]
    except Exception:
        return "unknown", ""
    state = payload.get("State", {}) or {}
    status = state.get("Status", "unknown")
    running = state.get("Running", False)
    if not running and status == "exited":
        status = "stopped"
    port_proc = _podman(["port", name], capture=True, check=False)
    ports = (port_proc.stdout or "").strip().replace("\n", ", ")
    return status, ports


def _status_ball(status: str) -> str:
    return "🟢" if status == "running" else "🔴"


def _status_label(status: str) -> str:
    return f"{_status_ball(status)} {status}"


def _cmd_status() -> int:
    try:
        from rich.table import Table
    except ImportError:
        for name in ALL_SERVICES:
            status, ports = _container_state(name)
            hint = SERVICE_HINTS.get(name, "-")
            print(f"{name:16} {_status_label(status):12} {ports or '-':24} {hint}", flush=True)
        return 0

    table = Table(title="RedForge Stack")
    table.add_column("Service")
    table.add_column("Status")
    table.add_column("Ports")
    table.add_column("Access")
    for name in ALL_SERVICES:
        status, ports = _container_state(name)
        hint = SERVICE_HINTS.get(name, "-")
        styled_status = (
            f"[green]{_status_ball(status)}[/] {status}"
            if status == "running"
            else f"[red]{_status_ball(status)}[/] {status}"
        )
        table.add_row(name, styled_status, ports or "-", hint)
    CONSOLE.print(table)
    return 0


def _cmd_logs(service: str | None) -> int:
    args = ["logs", "-f"]
    if service:
        args.append(service)
    _compose(args)
    return 0


def _cmd_build() -> int:
    _compose(["build", "redforge-web", "redforge-mcp"])
    return 0


def _cmd_pull() -> int:
    _compose(["pull"])
    return 0


def _cmd_load() -> int:
    _load_ttl_into_virtuoso()
    return 0


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="stack.py", description="Manage the local RedForge Podman stack.")
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def add_profile(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--profile", default="minimal", choices=["minimal", "full"], help="stack profile to target")

    add_profile(sub.add_parser("start", help="start a stack profile"))
    add_profile(sub.add_parser("stop", help="stop a stack profile"))
    add_profile(sub.add_parser("restart", help="restart a stack profile"))

    sub.add_parser("status", help="show service status")
    logs = sub.add_parser("logs", help="follow service logs")
    logs.add_argument("service", nargs="?", choices=ALL_SERVICES, help="optional single service to follow")
    sub.add_parser("build", help="build app images")
    sub.add_parser("pull", help="pull upstream images")
    sub.add_parser("load", help="load data/rdf/redforge.ttl into Virtuoso")
    return p


def main() -> int:
    _require_prereqs()
    legacy = {
        "up": ["start", "--profile", "minimal"],
        "down": ["stop", "--profile", "full"],
        "ps": ["status"],
        "reasoning-up": ["start", "--profile", "full"],
        "reasoning-down": ["stop", "--profile", "full"],
    }
    argv = sys.argv[1:]
    if argv and argv[0] in legacy:
        argv = legacy[argv[0]] + argv[1:]
    args = _parser().parse_args(argv)
    cmd = args.command

    if cmd == "start":
        return _cmd_start(args.profile)
    if cmd == "stop":
        return _cmd_stop(args.profile)
    if cmd == "restart":
        return _cmd_restart(args.profile)
    if cmd == "status":
        return _cmd_status()
    if cmd == "logs":
        return _cmd_logs(args.service)
    if cmd == "build":
        return _cmd_build()
    if cmd == "pull":
        return _cmd_pull()
    if cmd == "load":
        return _cmd_load()

    return _die(f"unknown command '{cmd}'", 2)


if __name__ == "__main__":
    raise SystemExit(main())
