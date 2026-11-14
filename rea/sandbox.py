"""Optional sandbox for external analysis tools (bubblewrap or firejail).

Sandboxing is opt-in (`--sandbox`). When requested but unavailable, REA still runs the static
tools (the target is never executed either way) and records that the sandbox was not active.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from rea.subproc import run_tool


@dataclass(frozen=True)
class Sandbox:
    name: str
    binary: str

    def wrap(self, argv: list[str], scratch_dir: Path | None = None) -> list[str]:
        """Return argv wrapped so the tool gets a read-only filesystem, no network, and one writable scratch dir."""
        if self.name == "bubblewrap":
            cmd = [
                self.binary,
                "--ro-bind", "/", "/",
                "--dev", "/dev",
                "--proc", "/proc",
                "--tmpfs", "/tmp",
                "--unshare-net",
                "--unshare-pid",
                "--die-with-parent",
            ]
            if scratch_dir is not None:
                cmd += ["--bind", str(scratch_dir), str(scratch_dir)]
            return cmd + ["--", *argv]
        if self.name == "firejail":
            cmd = [self.binary, "--quiet", "--noprofile", "--net=none", "--private-tmp"]
            if scratch_dir is not None:
                cmd.append(f"--whitelist={scratch_dir}")
            return cmd + ["--", *argv]
        raise ValueError(f"Unknown sandbox: {self.name}")


def _probe(binary: str, argv_after: list[str]) -> bool:
    res = run_tool([binary, *argv_after], timeout=15, max_bytes=4096)
    return res.ok


def detect(which: Callable[[str], str | None] = shutil.which) -> Sandbox | None:
    """Return the first working sandbox. A binary on PATH is not enough: it must also run a trivial command."""
    bwrap = which("bwrap")
    if bwrap and _probe(bwrap, ["--ro-bind", "/", "/", "--unshare-net", "--", "true"]):
        return Sandbox("bubblewrap", bwrap)
    firejail = which("firejail")
    if firejail and _probe(firejail, ["--quiet", "--noprofile", "--net=none", "--", "true"]):
        return Sandbox("firejail", firejail)
    return None


def describe(sandbox: Sandbox | None, requested: bool) -> str:
    if not requested:
        return "not requested"
    if sandbox is None:
        return "requested but unavailable (no working bubblewrap or firejail)"
    return f"active ({sandbox.name})"
