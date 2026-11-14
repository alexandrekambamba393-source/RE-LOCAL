"""Command-line interface. Run `rea --help` for the full list."""

from __future__ import annotations

import argparse
import json
import sys

from rea import paths
from rea.errors import ReaError
from rea.investigate import delete_investigation, investigate, list_investigations, load_investigation
from rea.setup_flow import doctor, run_setup


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rea", description="Local reverse-engineering helper. Everything stays on this machine.")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("setup", help="Check tools and prepare local state. Shows a plan and asks first.")
    s.add_argument("--yes", action="store_true", help="apply without asking")
    s.add_argument("--dry-run", action="store_true", help="show the plan and change nothing")
    s.add_argument("--allow", action="append", default=[], metavar="DIR", help="folder REA may investigate (repeatable)")

    sub.add_parser("doctor", help="Show tools, allowed folders, and history status")

    i = sub.add_parser("investigate", help="Investigate a file or folder")
    i.add_argument("target", help="path to a file or folder")
    i.add_argument("-q", "--question", required=True, help="plain-English question")
    i.add_argument("--json", action="store_true", help="print a JSON summary instead of the report")

    h = sub.add_parser("history", help="List past investigations")
    h.add_argument("--limit", type=int, default=20)

    sh = sub.add_parser("show", help="Print an investigation's report")
    sh.add_argument("id")

    d = sub.add_parser("delete", help="Delete one investigation and its report")
    d.add_argument("id")
    d.add_argument("--yes", action="store_true", help="delete without asking")

    lg = sub.add_parser("logs", help="List setup logs, or print the latest one")
    lg.add_argument("--last", action="store_true")

    sub.add_parser("mcp", help="Run the MCP server on stdio (for agent clients)")
    return p


def _print_doctor(info: dict) -> None:
    print(f"REA home:        {info['home']}")
    print(f"Config:          {'present' if info['config_present'] else 'missing (run `rea setup`)'}")
    print(f"Investigations:  {info['investigations']}")
    roots = info["allowed_roots"]
    print(f"Allowed folders: {', '.join(roots) if roots else 'none (agent investigations are off)'}")
    print("Tools:")
    for t in info["tools"]:
        state = "found  " if t["found"] else "missing"
        note = "" if t["implemented"] else " [reserved, not used yet]"
        version = f"  {t['version']}" if t["version"] else ""
        print(f"  {state} {t['name']:<8} {t['purpose']}{note}{version}")


def _dispatch(args: argparse.Namespace, home) -> int:
    if args.command == "setup":
        return run_setup(home, assume_yes=args.yes, dry_run=args.dry_run, allow=args.allow)

    if args.command == "doctor":
        _print_doctor(doctor(home))
        return 0

    if args.command == "investigate":
        rec = investigate(args.target, args.question, home=home)
        if args.json:
            print(json.dumps(rec.summary(), indent=2))
        else:
            print(rec.report)
            print(f"Saved as {rec.id} at {rec.report_path}")
        return 0

    if args.command == "history":
        rows = list_investigations(home, args.limit)
        if not rows:
            print("No investigations yet. Try: rea investigate <target> -q '<question>'")
            return 0
        for r in rows:
            print(f"{r['id']}  {r['created_at']}  {r['target_kind']:<14} {r['evidence_count']:>4} evidence  {r['question'][:60]}")
        return 0

    if args.command == "show":
        print(load_investigation(home, args.id)["report"])
        return 0

    if args.command == "delete":
        if not args.yes:
            if not sys.stdin.isatty():
                raise ReaError("Refusing to delete without --yes in a non-interactive shell.")
            if input(f"Delete investigation {args.id}? [y/N] ").strip().lower() not in ("y", "yes"):
                print("Kept.")
                return 0
        removed = delete_investigation(home, args.id)
        print("Deleted." if removed else f"No investigation named {args.id}.")
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
