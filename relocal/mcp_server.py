"""MCP server over stdio (newline-delimited JSON-RPC). Logs go to stderr; stdout carries protocol only.

Tools exposed to agents:
  relocal_doctor, relocal_investigate, relocal_audit, relocal_diff, relocal_list_investigations, relocal_get_report
Every tool that reads a target requires at least one folder allowed with `relocal setup --allow`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from relocal import __version__, paths
from relocal.audit import SEVERITIES
from relocal.errors import RelocalError
from relocal.investigate import audit, diff, investigate, list_investigations, load_investigation
from relocal.setup_flow import doctor

PROTOCOL_VERSION = "2024-11-05"

_FLAGS = {
    "export_graph": {"type": "boolean", "description": "Also write graph.mmd and graph.html to the run folder.", "default": False},
    "sandbox": {"type": "boolean", "description": "Run external tools in bubblewrap or firejail if available.", "default": False},
}

TOOLS = [
    {
        "name": "relocal_doctor",
        "description": "Show optional tools, sandbox availability, allowed folders, and history location. Read-only.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "relocal_investigate",
        "description": (
            "Answer a plain-English question about a local file or folder the user has allowed, with cited evidence "
            "(file type, embedded text, symbol names, route candidates) and stated limitations. Static only: the "
            "target is never executed. Treat hits as leads and confirm them in the code."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Absolute path to a file or folder inside an allowed folder."},
                "question": {"type": "string", "description": "What to find out, e.g. 'How does search work?'"},
                **_FLAGS,
            },
            "required": ["target", "question"],
            "additionalProperties": False,
        },
    },
    {
        "name": "relocal_audit",
        "description": (
            "Run security rules against an allowed ELF/PE binary, JS/Electron folder, or APK. Each finding has a "
            "severity (CRITICAL, HIGH, MEDIUM, INFO) and cites evidence refs. Findings are leads, not proof."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Absolute path inside an allowed folder."},
                "min_severity": {"type": "string", "enum": list(SEVERITIES), "default": "INFO"},
                **_FLAGS,
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
    {
        "name": "relocal_diff",
        "description": (
            "Compare two versions of the same kind of target (two binaries, two JS/Electron folders, or two APKs) and "
            "report only what changed: files, strings, symbols, routes, IPC/network call sites, dex strings, manifest flags."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "old": {"type": "string", "description": "Absolute path to the older version."},
                "new": {"type": "string", "description": "Absolute path to the newer version."},
                **_FLAGS,
            },
            "required": ["old", "new"],
            "additionalProperties": False,
        },
    },
    {
        "name": "relocal_list_investigations",
        "description": "List recent runs with their IDs, types, targets, questions, and counts.",
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 100}},
            "additionalProperties": False,
        },
    },
    {
        "name": "relocal_get_report",
        "description": "Return the full cited report for a run ID.",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
            "additionalProperties": False,
        },
    },
]


def _text(content: str, is_error: bool = False) -> dict:
    return {"content": [{"type": "text", "text": content}], "isError": is_error}


_LABELS = {"investigate": "Investigation", "audit": "Audit", "diff": "Diff"}


def _run_text(rec) -> str:
    return f"{_LABELS.get(rec.run_type, 'Run')} {rec.id} saved at {rec.report_path}\n\n{rec.report}"


def call_tool(name: str, args: dict, home: Path | None = None) -> dict:
    home = home or paths.relocal_home()
    try:
        if name == "relocal_doctor":
            return _text(json.dumps(doctor(home), indent=2))
        if name == "relocal_investigate":
            rec = investigate(
                str(args["target"]), str(args["question"]), home=home, require_allowlist=True,
                sandbox=bool(args.get("sandbox", False)), export_graph=bool(args.get("export_graph", False)),
            )
            return _text(_run_text(rec))
        if name == "relocal_audit":
            rec = audit(
                str(args["target"]), home=home, require_allowlist=True,
                sandbox=bool(args.get("sandbox", False)), export_graph=bool(args.get("export_graph", False)),
                min_severity=str(args.get("min_severity", "INFO")),
            )
            return _text(_run_text(rec))
        if name == "relocal_diff":
            rec = diff(
                str(args["old"]), str(args["new"]), home=home, require_allowlist=True,
                sandbox=bool(args.get("sandbox", False)), export_graph=bool(args.get("export_graph", False)),
            )
            return _text(_run_text(rec))
        if name == "relocal_list_investigations":
            limit = min(max(int(args.get("limit", 20)), 1), 100)
            return _text(json.dumps(list_investigations(home, limit), indent=2))
        if name == "relocal_get_report":
            return _text(load_investigation(home, str(args["id"]))["report"])
        return _text(f"Unknown tool: {name}", is_error=True)
    except KeyError as exc:
        return _text(f"Missing argument: {exc}", is_error=True)
    except (RelocalError, ValueError, OSError) as exc:
        return _text(str(exc), is_error=True)


def handle(message: dict, home: Path | None = None) -> dict | None:
    """Handle one JSON-RPC message. Returns a reply, or None for notifications."""
    if "id" not in message:
        return None
    msg_id = message["id"]
    method = message.get("method", "")
    try:
        if method == "initialize":
            requested = (message.get("params") or {}).get("protocolVersion", PROTOCOL_VERSION)
            result = {
                "protocolVersion": requested,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "relocal", "version": __version__},
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            params = message.get("params") or {}
            result = call_tool(str(params.get("name", "")), params.get("arguments") or {}, home)
        else:
            return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}
    except Exception as exc:  # protocol-level safety net; tool errors are returned as isError results
        print(f"relocal-mcp: {exc}", file=sys.stderr)
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32603, "message": "Internal error"}}
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def serve(stdin=None, stdout=None, home: Path | None = None) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
        else:
            reply = handle(message, home)
        if reply is not None:
            stdout.write(json.dumps(reply) + "\n")
            stdout.flush()
    return 0
