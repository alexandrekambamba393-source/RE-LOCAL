"""Where REA keeps its state. Everything lives under one folder on this machine (REA_HOME, default ~/.rea)."""

from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def rea_home() -> Path:
    env = os.environ.get("REA_HOME")
    return Path(env).expanduser().resolve() if env else (Path.home() / ".rea").resolve()


def config_file(home: Path | None = None) -> Path:
    return (home or rea_home()) / "config.json"


def db_file(home: Path | None = None) -> Path:
    return (home or rea_home()) / "history.sqlite3"


def logs_dir(home: Path | None = None) -> Path:
    return (home or rea_home()) / "logs"


def investigations_dir(home: Path | None = None) -> Path:
    return (home or rea_home()) / "investigations"


def mcp_snippet_file(home: Path | None = None) -> Path:
    return (home or rea_home()) / "mcp-client-config.json"
