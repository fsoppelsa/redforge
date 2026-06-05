#!/usr/bin/env python
"""RedForge — vulnerability intelligence and remediation toolkit.

Usage:
  ./redforge.py server                          launch the Streamlit dashboard
  ./redforge.py download [--force]              fetch remote sources into cache
  ./redforge.py ingest                          join + RDFize (requires download)
  ./redforge.py query --product rhel --version 9
  ./redforge.py query --product all
  ./redforge.py suggest --sbom estate.cdx.json [--top 25]
  ./redforge.py mcp                             start the MCP server on stdio
"""

import sys
import re
from pathlib import Path
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent / "src"))

_BANNER = r"""
██████╗ ███████╗██████╗ ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
██████╔╝█████╗  ██║  ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗
██╔══██╗██╔══╝  ██║  ██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
██║  ██║███████╗██████╔╝██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
"""


def _print_banner() -> None:
    banner = _BANNER.strip("\n")
    try:
        from rich.console import Console

        console = Console()
        console.print(f"[bold red]{banner}[/]")
        console.print("[bold white]REDFORGE[/]\n")
    except ImportError:
        print(banner, flush=True)
        print("REDFORGE\n", flush=True)


def _parser():
    import argparse

    class _VSArgumentParser(argparse.ArgumentParser):
        def print_help(self, file=None) -> None:  # type: ignore[override]
            _print_banner()
            return super().print_help(file=file)

    p = _VSArgumentParser(
        prog="redforge",
        usage="%(prog)s COMMAND [args]",
        description="RedForge — vulnerability intelligence and remediation toolkit.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--config",
        default="redforge.toml",
        metavar="PATH",
        help="configuration file (default: redforge.toml)",
    )

    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    # server
    srv = sub.add_parser("server", help="launch the Streamlit dashboard")
    srv.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    srv.add_argument("--port", type=int, default=8501, help="port (default: 8501)")

    # download
    dwn = sub.add_parser("download", help="fetch remote sources into local cache")
    dwn.add_argument("--force", action="store_true", help="re-download even if already cached")

    # ingest
    ing = sub.add_parser(
        "ingest",
        help="join CVE/KEV/MSF + RDFize -> data/rdf/redforge.ttl (requires download)",
    )
    ing.add_argument(
        "--skip-rdf", action="store_true",
        help="perform CSV join only, skip RDF conversion",
    )

    # query
    qry = sub.add_parser(
        "query",
        help="run a SPARQL SELECT over the RDF knowledge graph (requires ingest)",
        description=(
            "Execute a SPARQL SELECT over data/rdf/redforge.ttl.\n\n"
            "Example:\n"
            "  ./redforge.py query "
            "'SELECT ?cve WHERE { ?cve a <http://redforge.local/ontology#Vulnerability> }'"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sparql_src = qry.add_mutually_exclusive_group(required=True)
    sparql_src.add_argument(
        "sparql", nargs="?", metavar="SPARQL",
        help="inline SPARQL query",
    )
    sparql_src.add_argument(
        "--file", metavar="PATH",
        help="read query from .sparql or .rq file",
    )
    qry.add_argument("--format", dest="fmt", default="table",
                     choices=["table", "json", "csv"])

    # suggest
    sgg = sub.add_parser("suggest", help="rank top vulnerabilities for a CycloneDX SBOM estate")
    sgg.add_argument("--sbom", required=True, metavar="PATH", help="CycloneDX JSON SBOM path")
    sgg.add_argument("--top", type=int, default=25, metavar="N", help="number of vulnerabilities to return (default: 25)")
    sgg.add_argument("--format", dest="fmt", default="json", choices=["table", "json", "csv"])

    # mcp
    mcp_p = sub.add_parser("mcp", help="start the MCP server")
    mcp_p.add_argument(
        "--transport",
        default="stdio",
        choices=["stdio", "http", "sse", "streamable-http"],
        help="transport protocol (default: stdio)",
    )
    mcp_p.add_argument("--host", default="0.0.0.0", help="bind host for HTTP/SSE (default: 0.0.0.0)")
    mcp_p.add_argument("--port", type=int, default=8000, help="bind port for HTTP/SSE (default: 8000)")

    return p


def _make_printer():
    """Return a (kind, name, msg) → None callable that uses rich when available."""
    try:
        from rich.console import Console
        console = Console()

        def _print(kind: str, name: str, msg: str) -> None:
            if kind == "step":
                console.print(f"\n[bold cyan]→ {name:<12}[/] {msg}")
            else:
                console.print(f"  [green]✓[/] {name:<20} {msg}")
    except ImportError:
        def _print(kind: str, name: str, msg: str) -> None:
            prefix = f"\n→ {name}" if kind == "step" else f"  ✓ {name:<20}"
            print(f"{prefix} {msg}", flush=True)

    return _print


def _handle_missing_dependency(exc: ModuleNotFoundError) -> None:
    missing = exc.name or "a required package"
    python_bin = sys.executable
    conda_prefix = Path(sys.prefix)

    lines = [
        f"Missing Python dependency: {missing}",
        f"Interpreter in use: {python_bin}",
    ]

    if "conda" in str(conda_prefix).lower():
        lines.extend(
            [
                "The active Conda environment does not have project dependencies installed.",
                "Run:",
                f"  {python_bin} -m pip install -r requirements.txt",
            ]
        )
    else:
        lines.extend(
            [
                "This script is not running inside a project-ready Conda environment.",
                "Run:",
                "  conda activate <env>",
                "  ./install.sh",
            ]
        )

    sys.exit("\n".join(lines))


def main() -> None:
    parser = _parser()
    args = parser.parse_args()

    try:
        if args.command == "server":
            from redforge.server import serve
            serve(config_path=args.config, host=args.host, port=args.port)

        elif args.command == "download":
            from redforge.commands.sync import run_sync
            from redforge.config import load

            config = load(args.config)

            try:
                from rich.console import Console
                from rich.progress import (
                    BarColumn,
                    Progress,
                    SpinnerColumn,
                    TaskProgressColumn,
                    TextColumn,
                )

                console = Console()
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold]{task.fields[name]:<22}"),
                    BarColumn(bar_width=28),
                    TaskProgressColumn(),
                    TextColumn("{task.fields[status]}"),
                    console=console,
                ) as bar:
                    task_ids: dict[str, int] = {}
                    msg_re = re.compile(r"^\[([^\]]+)\]\s*(.*)$")

                    def on_step(name: str, pct: int) -> None:
                        if name not in task_ids:
                            task_ids[name] = bar.add_task(
                                description=name,
                                total=100,
                                completed=0,
                                name=name,
                                status="",
                            )
                        task_id = task_ids[name]
                        task = bar.tasks[task_id]
                        if task.total is None:
                            bar.update(task_id, total=100, completed=0)
                        bar.update(task_id, completed=max(0, min(100, pct)))

                    def on_progress(msg: str) -> None:
                        m = msg_re.match(msg)
                        if not m:
                            return
                        name, status = m.group(1), m.group(2).strip()
                        if name not in task_ids:
                            task_ids[name] = bar.add_task(
                                description=name,
                                total=None,
                                completed=0,
                                name=name,
                                status="",
                            )
                        bar.update(task_ids[name], status=status[:80])

                    paths = run_sync(config, force=args.force, on_step=on_step, on_progress=on_progress)

                console.print(f"\nCompleted: {len(paths)} sources.")
                for name, path in paths.items():
                    console.print(f"  ✓ {name:<20} → {path}")

            except ImportError:
                paths = run_sync(
                    config,
                    force=args.force,
                    on_progress=lambda msg: print(msg, flush=True),
                )
                print(f"\nCompleted: {len(paths)} sources.")
                for name, path in paths.items():
                    print(f"  ✓ {name:<20} → {path}")

        elif args.command == "ingest":
            from redforge.pipeline import pull, rdfize
            from redforge.config import load

            config = load(args.config)
            try:
                _print = _make_printer()

                _print("step", "join", "joining vulnerability data…")
                results = pull(config)
                for short, df in results.items():
                    _print("ok", short, f"{len(df)} CVE")

                if not args.skip_rdf:
                    _print("step", "rdfize", "converting to RDF…")
                    ttl_path = rdfize(results, config)
                    _print("ok", "graph", str(ttl_path))

                # TODO: load ttl_path into Virtuoso / Fuseki triplestore

            except FileNotFoundError as exc:
                sys.exit(f"Error: {exc}")

        elif args.command == "query":
            from redforge.pipeline import load_graph, query as sparql_query
            from redforge.commands.query import normalize_sparql_input
            from redforge.commands.output import print_df
            from redforge.config import load

            config = load(args.config)
            try:
                sparql = Path(args.file).read_text() if args.file else args.sparql
                sparql = normalize_sparql_input(sparql)
                graph = load_graph(config)
                df = sparql_query(graph, sparql)
                print_df(df, fmt=args.fmt)
            except (FileNotFoundError, ValueError) as exc:
                sys.exit(f"Error: {exc}")

        elif args.command == "suggest":
            import json

            from redforge.commands.output import print_df
            from redforge.commands.suggest import suggest_from_sbom
            from redforge.config import load

            config = load(args.config)
            try:
                sbom = Path(args.sbom).read_bytes()
                result = suggest_from_sbom(config, sbom=sbom, top_n=args.top)
                if args.fmt == "json":
                    print(json.dumps(result, indent=2))
                else:
                    df = pd.DataFrame(result["items"])
                    if not df.empty and "public_date" in df.columns:
                        # Render compact YYYY-MM-DD for terminals.
                        df["public_date"] = (
                            pd.to_datetime(df["public_date"], errors="coerce")
                              .dt.strftime("%Y-%m-%d")
                              .fillna("")
                        )
                    if args.fmt == "table" and not df.empty:
                        want = ["priority_rank", "priority_class", "cve_id", "public_date", "cvss", "is_kev", "has_public_exploit"]
                        cols = [c for c in want if c in df.columns]
                        df = df[cols]
                    print_df(df, fmt=args.fmt)
            except (FileNotFoundError, ValueError) as exc:
                sys.exit(f"Error: {exc}")

        elif args.command == "mcp":
            import os

            os.environ.setdefault("REDFORGE_CONFIG", str(Path(args.config).resolve()))
            from redforge.mcp import run as mcp_run

            mcp_run(transport=args.transport, host=args.host, port=args.port)

        else:
            parser.print_help()

    except ModuleNotFoundError as exc:
        _handle_missing_dependency(exc)


if __name__ == "__main__":
    main()
