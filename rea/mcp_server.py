"""MCP server over stdio (newline-delimited JSON-RPC). Logs go to stderr; stdout carries protocol only.

Tools exposed to agents:
  rea_doctor, rea_investigate, rea_list_investigations, rea_get_report
rea_investigate is refused until the user has allowed at least one folder with `rea setup --allow`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from rea import __version__, paths
from rea.errors import ReaError
from rea.investigate import investigate, list_investigations, load_investigation
from rea.setup_flow import doctor

PROTOCOL_VERSION = "2024-11-05"

TOOLS = [
    {
        "name": "rea_doctor",
        "description": "Show which optional local reverse-engineering tools are installed, which folders are allowed, and where history lives. Read-only.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "rea_investigate",
        "description": (
            "Investigate a local file or folder the user has allowed, and answer a plain-English question with "
            "cited evidence (file type, embedded text, symbol names, route candidates) and stated limitations. "
            "Static only: the target is never executed. Treat hits as leads and confirm them in the code."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Absolute path to a file or folder inside an allowed folder."},
                "question": {"type": "string", "description": "What to find out, e.g. 'How does search work?'"},
            },
            "required": ["target", "question"],
            "additionalProperties": False,
        },
    },
    {
        "name": "rea_list_investigations",
        "description": "List recent investigations with their IDs, targets, questions, and evidence counts.",
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 100}},
            "additionalProperties": False,
        },
    },
    {
        "name": "rea_get_report",
        "description": "Return the full cited report for an investigation ID.",
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


def call_tool(name: str, args: dict, home: Path | None = None) -> dict:
    home = home or paths.rea_home()
    try:
        if name == "rea_doctor":
            return _text(json.dumps(doctor(home), indent=2))
        if name == "rea_investigate":
            rec = investigate(str(args["target"]), str(args["question"]), home=home, require_allowlist=True)
            return _text(f"Investigation {rec.id} saved at {rec.report_path}\n\n{rec.report}")
        if name == "rea_list_investigations":
            limit = min(max(int(args.get("limit", 20)), 1), 100)
            return _text(json.dumps(list_investigations(home, limit), indent=2))
        if name == "rea_get_report":
            return _text(load_investigation(home, str(args["id"]))["report"])
        return _text(f"Unknown tool: {name}", is_error=True)
    except KeyError as exc:
        return _text(f"Missing argument: {exc}", is_error=True)
    except (ReaError, ValueError, OSError) as exc:
        return _text(str(exc), is_error=True)


def handle(message: dict, home: Path | None = None) -> dict | None:
    """Handle one JSON-RPC message. Returns a reply, or None for notifications."""
    if "id" not in message:
        return None  # notifications such as notifications/initialized need no reply
    msg_id = message["id"]
    method = message.get("method", "")
    try:
        if method == "initialize":
            requested = (message.get("params") or {}).get("protocolVersion", PROTOCOL_VERSION)
            result = {
                "protocolVersion": requested,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "rea", "version": __version__},
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
        print(f"rea-mcp: {exc}", file=sys.stderr)
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
