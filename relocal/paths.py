"""Where RE LOCAL keeps its state. Everything lives under one folder on this machine (RELOCAL_HOME, default ~/.relocal)."""

from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def relocal_home() -> Path:
    env = os.environ.get("RELOCAL_HOME")
    return Path(env).expanduser().resolve() if env else (Path.home() / ".relocal").resolve()


def config_file(home: Path | None = None) -> Path:
    return (home or relocal_home()) / "config.json"


def db_file(home: Path | None = None) -> Path:
    return (home or relocal_home()) / "history.sqlite3"


def logs_dir(home: Path | None = None) -> Path:
    return (home or relocal_home()) / "logs"


def investigations_dir(home: Path | None = None) -> Path:
    return (home or relocal_home()) / "investigations"


def mcp_snippet_file(home: Path | None = None) -> Path:
    return (home or relocal_home()) / "mcp-client-config.json"
