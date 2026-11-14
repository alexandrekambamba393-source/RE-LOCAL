"""Detect optional local tools. Detection only: nothing is installed or downloaded."""

from __future__ import annotations

import shutil
from dataclasses import asdict, dataclass

from rea.subproc import run_tool


@dataclass(frozen=True)
class ToolSpec:
    name: str
    purpose: str
    implemented: bool  # False means the tool is reserved for a planned capability


SPECS = (
    ToolSpec("file", "identify file types", True),
    ToolSpec("strings", "pull embedded text out of binaries", True),
    ToolSpec("nm", "list native symbol names", True),
    ToolSpec("objdump", "list ELF/PE sections", True),
    ToolSpec("jadx", "decompile Android APKs", False),
    ToolSpec("gdb", "native debugger sessions", False),
    ToolSpec("node", "run JavaScript tooling", False),
)


@dataclass
class ToolStatus:
    name: str
    purpose: str
    implemented: bool
    found: bool
    path: str | None
    version: str | None

    def to_dict(self) -> dict:
        return asdict(self)


def probe_tools(specs: tuple[ToolSpec, ...] = SPECS) -> list[ToolStatus]:
    statuses: list[ToolStatus] = []
    for spec in specs:
        path = shutil.which(spec.name)
        version = None
        if path:
            res = run_tool([path, "--version"], timeout=5, max_bytes=4096)
            lines = res.stdout.strip().splitlines()
            version = lines[0][:120] if lines else None
        statuses.append(ToolStatus(spec.name, spec.purpose, spec.implemented, path is not None, path, version))
    return statuses
