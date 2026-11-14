"""Configuration: detected tools, folders RE LOCAL may investigate, and resource limits. Stored as REA_HOME/config.json."""

from __future__ import annotations

import json
from pathlib import Path

from rea import paths
from rea.errors import ReaError

CONFIG_VERSION = 1
DEFAULT_LIMITS = {
    "command_timeout_seconds": 60,
    "max_output_bytes": 2_000_000,
    "max_file_bytes": 5_000_000,
}


def load_config(home: Path | None = None) -> dict:
    path = paths.config_file(home)
    if not path.is_file():
        return {"config_version": CONFIG_VERSION, "allowed_roots": [], "limits": dict(DEFAULT_LIMITS), "tools": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReaError(f"{path} is not valid JSON ({exc}). Fix it, or delete it and run `rea setup`.") from exc
    if not isinstance(data, dict):
        raise ReaError(f"{path} must contain a JSON object. Delete it and run `rea setup`.")
    data["allowed_roots"] = [str(r) for r in data.get("allowed_roots", [])]
    data["limits"] = {**DEFAULT_LIMITS, **data.get("limits", {})}
    data.setdefault("tools", {})
    return data


def build_config(tools: dict, allowed_roots: list[str], limits: dict) -> dict:
    return {
        "config_version": CONFIG_VERSION,
        "allowed_roots": allowed_roots,
        "limits": limits,
        "tools": tools,
    }
