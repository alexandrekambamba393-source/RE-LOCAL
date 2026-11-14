"""Command-line interface. Run `rea --help` for the full list."""

from __future__ import annotations

import argparse
import json
import sys

from rea import paths
from rea.audit import SEVERITIES
from rea.errors import ReaError
from rea.investigate import (
    audit,
    delete_investigation,
    diff,
    export_graph_for,
    investigate,
    list_investigations,
    load_investigation,
)
from rea.setup_flow import doctor, run_setup


def _common_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--export-graph", action="store_true", help="also write graph.mmd and graph.html to the report folder")
    p.add_argument("--sandbox", action="store_true", help="run external tools in bubblewrap/firejail if available")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rea", description="Local reverse-engineering helper. Everything stays on this machine.")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("setup", help="Check tools and prepare local state. Shows a plan and asks first.")
    s.add_argument("--yes", action="store_true", help="apply without asking")
    s.add_argument("--dry-run", action="store_true", help="show the plan and change nothing")
    s.add_argument("--allow", action="append", default=[], metavar="DIR", help="folder REA may investigate (repeatable)")

    sub.add_parser("doctor", help="Show tools, sandbox, allowed folders, and history status")

    i = sub.add_parser("investigate", help="Answer a question about a file or folder, with cited evidence")
    i.add_argument("target", help="path to a file or folder")
    i.add_argument("-q", "--question", required=True, help="plain-English question")
    i.add_argument("--json", action="store_true", help="print a JSON summary instead of the report")
    _common_flags(i)

    a = sub.add_parser("audit", help="Flag common security risks with severities and evidence")
    a.add_argument("target", help="path to an ELF/PE binary, JS/Electron folder, or APK")
    a.add_argument("--min-severity", default="INFO", choices=SEVERITIES, help="hide findings below this level")
    a.add_argument("--json", action="store_true", help="print a JSON summary instead of the report")
    _common_flags(a)

    d = sub.add_parser("diff", help="Compare two versions of a binary, JS/Electron folder, or APK")
    d.add_argument("old", help="first (older) version")
    d.add_argument("new", help="second (newer) version")
    d.add_argument("--json", action="store_true", help="print a JSON summary instead of the report")
    _common_flags(d)

    h = sub.add_parser("history", help="List past runs")
    h.add_argument("--limit", type=int, default=20)

    sh = sub.add_parser("show", help="Print a run's report, optionally rebuilding its graph")
    sh.add_argument("id")
    sh.add_argument("--export-graph", action="store_true", help="rebuild graph.mmd and graph.html for this run")

    dl = sub.add_parser("delete", help="Delete one run and its report folder")
    dl.add_argument("id")
    dl.add_argument("--yes", action="store_true", help="delete without asking")

    lg = sub.add_parser("logs", help="List setup logs, or print the latest one")
    lg.add_argument("--last", action="store_true")

    sub.add_parser("mcp", help="Run the MCP server on stdio (for agent clients)")
    return p


def _print_doctor(info: dict) -> None:
    print(f"REA home:        {info['home']}")
    print(f"Config:          {'present' if info['config_present'] else 'missing (run `rea setup`)'}")
    print(f"Runs in history: {info['investigations']}")
    roots = info["allowed_roots"]
    print(f"Allowed folders: {', '.join(roots) if roots else 'none (agent investigations are off)'}")
    sb = info["sandbox"]
    print(f"Sandbox:         {sb if sb else 'none available (bubblewrap or firejail not working)'}")
    print("Tools:")
    for t in info["tools"]:
        state = "found  " if t["found"] else "missing"
        note = "" if t["implemented"] else " [detected only]"
        version = f"  {t['version']}" if t["version"] else ""
        print(f"  {state} {t['name']:<15} {t['purpose']}{note}{version}")


def _print_result(rec, as_json: bool) -> None:
    if as_json:
        print(json.dumps(rec.summary_dict(), indent=2))
    else:
        print(rec.report)
        print(f"Saved as {rec.id} at {rec.report_path}")


def _dispatch(args: argparse.Namespace, home) -> int:
    if args.command == "setup":
        return run_setup(home, assume_yes=args.yes, dry_run=args.dry_run, allow=args.allow)

    if args.command == "doctor":
        _print_doctor(doctor(home))
        return 0

    if args.command == "investigate":
        rec = investigate(args.target, args.question, home=home, sandbox=args.sandbox, export_graph=args.export_graph)
        _print_result(rec, args.json)
        return 0

    if args.command == "audit":
        rec = audit(args.target, home=home, sandbox=args.sandbox, export_graph=args.export_graph, min_severity=args.min_severity)
        _print_result(rec, args.json)
        return 0

    if args.command == "diff":
        rec = diff(args.old, args.new, home=home, sandbox=args.sandbox, export_graph=args.export_graph)
        _print_result(rec, args.json)
        return 0

    if args.command == "history":
        rows = list_investigations(home, args.limit)
        if not rows:
            print("No runs yet. Try: rea audit <target>  or  rea investigate <target> -q '<question>'")
            return 0
        for r in rows:
            print(f"{r['id']}  {r['created_at']}  {r['run_type']:<11} {r['target_kind']:<14} {r['evidence_count']:>4} evidence  {r['question'][:50]}")
        return 0

    if args.command == "show":
        rec = load_investigation(home, args.id)
        print(rec["report"])
        if args.export_graph:
            mmd, html_path = export_graph_for(home, args.id)
            print(f"Graph written: {html_path} (Mermaid source: {mmd})")
        return 0

    if args.command == "delete":
        if not args.yes:
            if not sys.stdin.isatty():
                raise ReaError("Refusing to delete without --yes in a non-interactive shell.")
            if input(f"Delete run {args.id}? [y/N] ").strip().lower() not in ("y", "yes"):
                print("Kept.")
                return 0
        removed = delete_investigation(home, args.id)
        print("Deleted." if removed else f"No run named {args.id}.")
        return 0 if removed else 1

    if args.command == "logs":
        logs = sorted(paths.logs_dir(home).glob("setup-*.log"))
        if not logs:
            print("No setup logs yet. Run `rea setup`.")
            return 0
        if args.last:
            print(logs[-1].read_text(encoding="utf-8"))
        else:
            for log in logs:
                print(log)
        return 0

    if args.command == "mcp":
        from rea.mcp_server import serve

        return serve(home=home)

    raise ReaError(f"Unknown command: {args.command}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    home = paths.rea_home()
    try:
        return _dispatch(args, home)
    except ReaError as exc:
        print(f"rea: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
