"""Run external tools safely: fixed argument lists, no shell, a timeout, and capped output."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass
class CommandResult:
    ok: bool
    stdout: str
    error: str = ""
    truncated: bool = False


def run_tool(argv: list[str], timeout: float = 60, max_bytes: int = 2_000_000) -> CommandResult:
    """Run argv without a shell. Callers always pass absolute paths, so a target name cannot be read as a flag."""
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError:
        return CommandResult(False, "", f"{argv[0]} is not installed")
    except subprocess.TimeoutExpired:
        return CommandResult(False, "", f"{argv[0]} timed out after {timeout:g}s")
    except OSError as exc:
        return CommandResult(False, "", str(exc))

    truncated = len(proc.stdout) > max_bytes
    text = proc.stdout[:max_bytes].decode("utf-8", errors="replace")
    if proc.returncode == 0:
        return CommandResult(True, text, "", truncated)
    err = proc.stderr.decode("utf-8", errors="replace").strip()[:500]
    return CommandResult(False, text, err or f"exit code {proc.returncode}", truncated)
