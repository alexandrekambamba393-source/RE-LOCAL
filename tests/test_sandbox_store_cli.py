"""Sandbox wrapping, optional radare2/rizin extraction, history migration, MCP and CLI surfaces."""

from __future__ import annotations

import io
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from helpers import FakeRunner, make_js_app, quiet

from relocal import mcp_server, native_tools
from relocal import sandbox as sandbox_mod
from relocal.cli import main
from relocal.investigate import investigate
from relocal.runner import Runner
from relocal.sandbox import Sandbox
from relocal.setup_flow import doctor, run_setup
from relocal.store import Store


class SandboxWrapTests(unittest.TestCase):
    def test_bubblewrap_gives_readonly_root_no_network_and_one_scratch_dir(self):
        cmd = Sandbox("bubblewrap", "/usr/bin/bwrap").wrap(["strings", "-n", "6", "/x/app"], Path("/scratch/s1"))
        self.assertEqual(cmd[0], "/usr/bin/bwrap")
        self.assertEqual(cmd[1:4], ["--ro-bind", "/", "/"])
        self.assertIn("--unshare-net", cmd)
        self.assertIn("--die-with-parent", cmd)
        self.assertEqual(cmd[cmd.index("--bind") : cmd.index("--bind") + 3], ["--bind", "/scratch/s1", "/scratch/s1"])
        self.assertEqual(cmd[-5:], ["--", "strings", "-n", "6", "/x/app"])

    def test_bubblewrap_without_scratch_dir_has_no_writable_bind(self):
        cmd = Sandbox("bubblewrap", "/usr/bin/bwrap").wrap(["file", "/x"])
        self.assertNotIn("--bind", cmd)

    def test_firejail_disables_network_and_whitelists_scratch(self):
        cmd = Sandbox("firejail", "/usr/bin/firejail").wrap(["nm", "/x"], Path("/scratch/s2"))
        self.assertIn("--net=none", cmd)
        self.assertIn("--private-tmp", cmd)
        self.assertIn("--whitelist=/scratch/s2", cmd)
        self.assertEqual(cmd[-3:], ["--", "nm", "/x"])

    def test_unknown_sandbox_is_an_error(self):
        with self.assertRaises(ValueError):
            Sandbox("docker", "/usr/bin/docker").wrap(["true"])

    def test_detect_returns_none_when_nothing_is_installed(self):
        self.assertIsNone(sandbox_mod.detect(which=lambda name: None))

    def test_detect_ignores_a_binary_that_does_not_run(self):
        self.assertIsNone(sandbox_mod.detect(which=lambda name: f"/nonexistent/{name}"))

    def test_describe_states(self):
        self.assertEqual(sandbox_mod.describe(None, requested=False), "not requested")
        self.assertIn("unavailable", sandbox_mod.describe(None, requested=True))
        self.assertEqual(sandbox_mod.describe(Sandbox("firejail", "/x"), requested=True), "active (firejail)")


class RunnerSandboxTests(unittest.TestCase):
    def test_runner_wraps_argv_and_cleans_its_scratch_dir(self):
        with tempfile.TemporaryDirectory() as d:
            scratch_root = Path(d) / "scratch"
            runner = Runner(timeout=5, max_bytes=1000, sandbox=Sandbox("firejail", "/nonexistent/firejail"),
                            scratch_root=scratch_root)
            res = runner.run(["/bin/true"])
            self.assertFalse(res.ok)
            self.assertIn("/nonexistent/firejail is not installed", res.error)
            self.assertTrue(any(scratch_root.iterdir()))
            runner.close()
            self.assertEqual(list(scratch_root.iterdir()), [])

    def test_runner_without_sandbox_runs_directly(self):
        if not Path("/bin/true").exists():
            self.skipTest("/bin/true not available")
        res = Runner(timeout=5).run(["/bin/true"])
        self.assertTrue(res.ok)


class SandboxInInvestigationTests(unittest.TestCase):
    def test_requested_but_unavailable_is_recorded_as_a_limitation(self):
        with tempfile.TemporaryDirectory() as d:
            app = make_js_app(Path(d) / "app")
            with mock.patch("relocal.investigate.sandbox_mod.detect", return_value=None):
                rec = investigate(str(app), "search", home=Path(d) / "home", sandbox=True)
            self.assertTrue(any("Sandbox requested but unavailable" in t for t in rec.limitations))
            self.assertIn("Sandbox requested but unavailable", rec.report)

    def test_active_sandbox_is_recorded_as_a_limitation(self):
        with tempfile.TemporaryDirectory() as d:
            app = make_js_app(Path(d) / "app")
            fake = Sandbox("bubblewrap", "/nonexistent/bwrap")
            with mock.patch("relocal.investigate.sandbox_mod.detect", return_value=fake):
                rec = investigate(str(app), "search", home=Path(d) / "home", sandbox=True)
            self.assertTrue(any(t.startswith("Sandbox active (bubblewrap)") for t in rec.limitations))

    def test_sandbox_not_requested_leaves_no_sandbox_note(self):
        with tempfile.TemporaryDirectory() as d:
            app = make_js_app(Path(d) / "app")
            rec = investigate(str(app), "search", home=Path(d) / "home")
            self.assertFalse(any("Sandbox" in t for t in rec.limitations))


class RadareRizinTests(unittest.TestCase):
    JSON = json.dumps({
        "imports": [{"name": "puts"}, {"name": "strcpy"}],
        "exports": [{"name": "main"}],
        "sections": [{"name": ".text"}, {"name": ".data"}],
    })

    def test_extraction_reads_imports_exports_and_sections(self):
        runner = FakeRunner({("rabin2", "-j"): self.JSON})
        out = native_tools.run_bin_tool_extract(runner, "rabin2", "/fake/rabin2", "/fake/bin")
        self.assertEqual(out["imports"], ["puts", "strcpy"])
        self.assertEqual(out["exports"], ["main"])
        self.assertEqual(out["sections"], [".text", ".data"])
        self.assertEqual([c[0] for c in runner.calls], ["/fake/rabin2"] * 3)

    def test_rz_bin_uses_the_same_json_contract(self):
        runner = FakeRunner({("rz-bin", "-j"): self.JSON})
        out = native_tools.run_bin_tool_extract(runner, "rz-bin", "/fake/rz-bin", "/fake/bin")
        self.assertEqual(out["imports"], ["puts", "strcpy"])

    def test_failed_extraction_records_errors_instead_of_crashing(self):
        out = native_tools.run_bin_tool_extract(FakeRunner({}), "rabin2", "/fake/rabin2", "/fake/bin")
        self.assertEqual(out["imports"], [])
        self.assertTrue(out["errors"])

    def test_analyze_headless_is_detected_but_not_run(self):
        from relocal.tools_probe import SPECS

        spec = next(s for s in SPECS if s.name == "analyzeHeadless")
        self.assertFalse(spec.implemented)
        self.assertIsNone(spec.version_arg)  # never launch the JVM just to read a version


class HistoryMigrationTests(unittest.TestCase):
    def test_old_database_gains_new_columns(self):
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "history.sqlite3"
            conn = sqlite3.connect(db)
            conn.executescript(
                "CREATE TABLE investigations (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, target TEXT NOT NULL,"
                " target_kind TEXT NOT NULL, target_sha256 TEXT, question TEXT NOT NULL, terms TEXT NOT NULL,"
                " evidence_count INTEGER NOT NULL, limitations TEXT NOT NULL, report_path TEXT NOT NULL);"
                "INSERT INTO investigations VALUES ('inv-1','2026-01-01T00:00:00+00:00','/t','elf-binary',NULL,"
                "'q','[]',0,'[]','/r');"
            )
            conn.commit()
            conn.close()
            with Store(db) as store:
                row = store.get("inv-1")
            self.assertEqual(row["run_type"], "investigate")
            self.assertEqual(row["findings"], [])


class DoctorTests(unittest.TestCase):
    def test_doctor_reports_sandbox_and_new_tools(self):
        with tempfile.TemporaryDirectory() as d:
            info = doctor(Path(d) / "home")
            self.assertIn("sandbox", info)
            names = {t["name"] for t in info["tools"]}
            self.assertTrue({"readelf", "rabin2", "rz-bin", "analyzeHeadless", "bwrap", "firejail"} <= names)


class McpAuditDiffTests(unittest.TestCase):
    def _call(self, home: Path, name: str, args: dict) -> dict:
        reply = mcp_server.handle(
            {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": name, "arguments": args}},
            home=home,
        )
        return reply["result"]

    def test_audit_is_refused_until_a_folder_is_allowed(self):
        with tempfile.TemporaryDirectory() as d:
            app = make_js_app(Path(d) / "app")
            result = self._call(Path(d) / "home", "relocal_audit", {"target": str(app)})
            self.assertTrue(result["isError"])

    def test_audit_and_diff_work_inside_an_allowed_folder(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d) / "home"
            work = Path(d) / "work"
            v1 = make_js_app(work / "v1")
            v2 = make_js_app(work / "v2")
            run_setup(home, assume_yes=True, allow=[str(work)], out=quiet)
            audit_result = self._call(home, "relocal_audit", {"target": str(v1), "min_severity": "HIGH", "export_graph": True})
            self.assertFalse(audit_result["isError"])
            self.assertIn("Audit inv-", audit_result["content"][0]["text"])
            diff_result = self._call(home, "relocal_diff", {"old": str(v1), "new": str(v2)})
            self.assertFalse(diff_result["isError"])
            self.assertIn("Diff inv-", diff_result["content"][0]["text"])

    def test_invalid_severity_is_a_tool_error(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d) / "home"
            work = Path(d) / "work"
            app = make_js_app(work / "app")
            run_setup(home, assume_yes=True, allow=[str(work)], out=quiet)
            result = self._call(home, "relocal_audit", {"target": str(app), "min_severity": "URGENT"})
            self.assertTrue(result["isError"])

    def test_new_tools_declare_their_optional_flags(self):
        by_name = {t["name"]: t for t in mcp_server.TOOLS}
        self.assertIn("export_graph", by_name["relocal_audit"]["inputSchema"]["properties"])
        self.assertIn("sandbox", by_name["relocal_diff"]["inputSchema"]["properties"])
        self.assertIn("sandbox", by_name["relocal_investigate"]["inputSchema"]["properties"])


class CliTests(unittest.TestCase):
    def test_audit_json_output_and_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            app = make_js_app(Path(d) / "app")
            out = io.StringIO()
            with mock.patch.dict(os.environ, {"RELOCAL_HOME": str(Path(d) / "home")}), redirect_stdout(out):
                code = main(["audit", str(app), "--json"])
            self.assertEqual(code, 0)
            data = json.loads(out.getvalue())
            self.assertEqual(data["run_type"], "audit")
            self.assertIn("finding_count", data)

    def test_diff_command_runs(self):
        with tempfile.TemporaryDirectory() as d:
            a = make_js_app(Path(d) / "a")
            b = make_js_app(Path(d) / "b")
            out = io.StringIO()
            with mock.patch.dict(os.environ, {"RELOCAL_HOME": str(Path(d) / "home")}), redirect_stdout(out):
                self.assertEqual(main(["diff", str(a), str(b)]), 0)
            self.assertIn("# Diff", out.getvalue())

    def test_show_export_graph_writes_files(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d) / "home"
            app = make_js_app(Path(d) / "app")
            with mock.patch.dict(os.environ, {"RELOCAL_HOME": str(home)}), redirect_stdout(io.StringIO()):
                main(["investigate", str(app), "-q", "search"])
                rec_id = next((home / "investigations").iterdir()).name
                out = io.StringIO()
                with redirect_stdout(out):
                    self.assertEqual(main(["show", rec_id, "--export-graph"]), 0)
            self.assertTrue((home / "investigations" / rec_id / "graph.html").is_file())
            self.assertIn("Graph written", out.getvalue())

    def test_unknown_run_id_is_a_clean_error(self):
        with tempfile.TemporaryDirectory() as d:
            err = io.StringIO()
            with mock.patch.dict(os.environ, {"RELOCAL_HOME": str(Path(d) / "home")}), redirect_stderr(err):
                code = main(["show", "inv-20261114-000000-ffff"])
            self.assertEqual(code, 1)
            self.assertIn("No investigation named", err.getvalue())


if __name__ == "__main__":
    unittest.main()
