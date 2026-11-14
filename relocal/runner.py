"""The single gateway for running external tools: fixed argv, timeouts, output caps, optional sandbox."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from relocal.sandbox import Sandbox
from relocal.subproc import CommandResult, run_tool


class Runner:
    def __init__(
        self,
        timeout: float = 60,
        max_bytes: int = 2_000_000,
        sandbox: Sandbox | None = None,
        scratch_root: Path | None = None,
    ) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.sandbox = sandbox
        self.scratch_root = scratch_root
        self._scratch: Path | None = None

    def _scratch_dir(self) -> Path | None:
        if self.sandbox is None:
            return None
        if self._scratch is None:
            root = self.scratch_root
            if root is not None:
                root.mkdir(parents=True, exist_ok=True)
            self._scratch = Path(tempfile.mkdtemp(prefix="relocal-sbx-", dir=root))
        return self._scratch

    def run(self, argv: list[str]) -> CommandResult:
        if self.sandbox is not None:
            argv = self.sandbox.wrap(argv, self._scratch_dir())
        return run_tool(argv, self.timeout, self.max_bytes)

    def close(self) -> None:
        if self._scratch is not None:
            shutil.rmtree(self._scratch, ignore_errors=True)
            self._scratch = None
