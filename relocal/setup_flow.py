"""Guided setup: detect tools, show exactly what would change, and change nothing until you agree.

Safe to rerun at any time. Existing settings are kept; each run writes a new log under RELOCAL_HOME/logs.
"""

from __future__ import annotations

import datetime as dt
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from relocal import paths
from relocal import sandbox as sandbox_mod
from relocal.config import DEFAULT_LIMITS, build_config, load_config
from relocal.errors import RelocalError
from relocal.store import Store
from relocal.tools_probe import ToolStatus, probe_tools


@dataclass(frozen=True)
class PlanStep:
    action: str
    target: str
    note: str


def _normalize_new_roots(allow: Iterable[str]) -> list[str]:
    roots: list[str] = []
    for raw in allow:
        folder = Path(raw).expanduser().resolve()
        if not folder.is_dir():
            raise RelocalError(f"Allowed folder does not exist or is not a folder: {raw}")
        if str(folder) not in roots:
            roots.append(str(folder))
    return roots


def _plan(home: Path, log_path: Path) -> list[PlanStep]:
    steps: list[PlanStep] = []
    for folder in (home, paths.logs_dir(home), paths.investigations_dir(home)):
        if not folder.is_dir():
            steps.append(PlanStep("create_dir", str(folder), "RE LOCAL state folder"))
    steps.append(
        PlanStep(
            "write_file",
            str(paths.config_file(home)),
            "tool detection, allowed folders, and limits (existing settings are kept)",
        )
    )
    steps.append(
        PlanStep(
            "write_file",
            str(paths.mcp_snippet_file(home)),
            "example MCP client entry. You copy it into your client yourself; RE LOCAL edits no client config",
        )
    )
    steps.append(PlanStep("write_file", str(log_path), "record of this setup run"))
    return steps


def _apply(
    home: Path,
    steps: list[PlanStep],
    config: dict,
    log_path: Path,
    statuses: list[ToolStatus],
    out: Callable[..., None],
) -> None:
    for folder in (home, paths.logs_dir(home), paths.investigations_dir(home)):
        folder.mkdir(parents=True, exist_ok=True)
    paths.config_file(home).write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    snippet = {
        "mcpServers": {
            "relocal": {
                "command": sys.executable,
                "args": ["-m", "relocal", "mcp"],
                "cwd": str(paths.PROJECT_ROOT),
                "env": {"RELOCAL_HOME": str(home)},
            }
        }
    }
    paths.mcp_snippet_file(home).write_text(json.dumps(snippet, indent=2) + "\n", encoding="utf-8")
    with Store(paths.db_file(home)):
        pass

    log = [f"RE LOCAL setup run {log_path.stem}", "", "Plan applied:"]
    log += [f"  [{s.action}] {s.target}  -- {s.note}" for s in steps]
    log += ["", "Tool check:"]
    log += [f"  {'found' if t.found else 'missing'} {t.name}: {t.path or '-'} {t.version or ''}".rstrip() for t in statuses]
    log += ["", "Result: applied"]
    log_path.write_text("\n".join(log) + "\n", encoding="utf-8")
    out(f"Setup complete. Log: {log_path}")
    out(f"MCP client example: {paths.mcp_snippet_file(home)}")


def run_setup(
    home: Path | None = None,
    *,
    assume_yes: bool = False,
    dry_run: bool = False,
    allow: Iterable[str] = (),
    input_fn: Callable[[str], str] = input,
    out: Callable[..., None] = print,
) -> int:
    home = home or paths.relocal_home()
    existing = load_config(home)
    kept = [r for r in existing.get("allowed_roots", []) if Path(r).is_dir()]
    roots = list(dict.fromkeys([*kept, *_normalize_new_roots(allow)]))

    statuses = probe_tools()
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    log_path = paths.logs_dir(home) / f"setup-{stamp}.log"
    steps = _plan(home, log_path)
    tools = {s.name: {"found": s.found, "path": s.path, "version": s.version} for s in statuses}
    config = build_config(tools, roots, existing.get("limits", dict(DEFAULT_LIMITS)))

    out("RE LOCAL setup")
    out(f"Home: {home}")
    out("")
    out("Tool check (optional tools only add capabilities; nothing is installed):")
    for s in statuses:
        state = "found  " if s.found else "missing"
        note = "" if s.implemented else "  [reserved, not used yet]"
        out(f"  {state} {s.name:<8} {s.purpose}{note}")
    out("")
    out("Plan:" if not dry_run else "Plan (dry run, nothing will be changed):")
    for step in steps:
        out(f"  [{step.action}] {step.target}  -- {step.note}")
    out(f"  Allowed folders: {', '.join(roots) if roots else 'none'}")
    if not roots:
        out("  Note: agent (MCP) investigations stay off until you add one with `relocal setup --allow <folder>`.")

    if dry_run:
        out("")
        out("Dry run: no changes made.")
        return 0

    if not assume_yes:
        if not sys.stdin.isatty():
            out("")
            out("Not running interactively and --yes was not given. Nothing was changed.")
            return 2
        answer = input_fn("\nApply this plan? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            out("Cancelled. Nothing was changed.")
            return 1
    out("")

    _apply(home, steps, config, log_path, statuses, out)
    return 0


def doctor(home: Path | None = None) -> dict:
    home = home or paths.relocal_home()
    config = load_config(home)
    count = 0
    db = paths.db_file(home)
    if db.is_file():
        with Store(db) as store:
            count = store.count()
    sb = sandbox_mod.detect()
    return {
        "home": str(home),
        "config_present": paths.config_file(home).is_file(),
        "allowed_roots": config.get("allowed_roots", []),
        "investigations": count,
        "sandbox": sb.name if sb else None,
        "tools": [s.to_dict() for s in probe_tools()],
    }
