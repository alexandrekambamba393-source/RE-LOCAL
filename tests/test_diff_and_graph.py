"""Patch diffing (folders, binaries, APKs) and evidence graph export."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from helpers import build_apk, make_js_app

from rea.errors import ReaError
from rea.graph import build_html, build_mermaid, write_graph
from rea.investigate import diff, export_graph_for, investigate, load_investigation


def _write(root: Path, name: str, text: str) -> None:
    (root / name).parent.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(text, encoding="utf-8")


class FolderDiffTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = self.tmp / "home"
        self.v1 = self.tmp / "v1"
        self.v2 = self.tmp / "v2"
        make_js_app(self.v1)
        _write(self.v1, "old.txt", "gone in v2")
        make_js_app(self.v2)
        _write(self.v2, "main.js",
               'ipcMain.handle("search", run);\n'
               'const url = "/api/query";\n'
               "function run(q) { return fetch(url + q); fetch(url); }\n")
        _write(self.v2, "new.txt", "added in v2")
        (self.v2 / "old.txt").unlink(missing_ok=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_tree_changes_are_detected(self):
        rec = diff(str(self.v1), str(self.v2), home=self.home)
        claims = [e["claim"] for e in rec.evidence if e["capability"] == "diff-tree"]
        self.assertTrue(any("File added: new.txt" in c for c in claims))
        self.assertTrue(any("File removed: old.txt" in c for c in claims))
        self.assertTrue(any("File changed (SHA-256 differs): main.js" in c for c in claims))

    def test_route_changes_are_isolated(self):
        rec = diff(str(self.v1), str(self.v2), home=self.home)
        added = [e["claim"] for e in rec.evidence if e["kind"] == "route-added"]
        removed = [e["claim"] for e in rec.evidence if e["kind"] == "route-removed"]
        self.assertIn("Route literal added: /api/query", added)
        self.assertIn("Route literal removed: /api/search", removed)

    def test_network_call_count_change_is_reported(self):
        rec = diff(str(self.v1), str(self.v2), home=self.home)
        changed = [e["claim"] for e in rec.evidence if e["kind"] == "call-site-changed"]
        self.assertTrue(any(c.startswith("Call-site count changed: fetch: 1 -> 2") for c in changed), changed)

    def test_summary_and_history_record(self):
        rec = diff(str(self.v1), str(self.v2), home=self.home)
        self.assertEqual(rec.run_type, "diff")
        self.assertIn("Changes found", rec.summary)
        stored = load_investigation(self.home, rec.id)
        self.assertEqual(stored["run_type"], "diff")
        self.assertTrue(Path(rec.report_path).is_file())
        self.assertIn("# Diff", rec.report)

    def test_identical_folders_have_no_tree_changes(self):
        rec = diff(str(self.v1), str(self.v1), home=self.home)
        self.assertEqual([e for e in rec.evidence if e["capability"] == "diff-tree"], [])

    def test_mixed_kinds_are_refused(self):
        apk = build_apk(self.tmp / "a.apk", [("application", [])], ["x"])
        with self.assertRaises(ReaError):
            diff(str(self.v1), str(apk), home=self.home)


class BinaryDiffTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = self.tmp / "home"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_identical_binaries_short_circuit(self):
        a = self.tmp / "a.bin"
        a.write_bytes(b"\x7fELF" + b"same content here\x00" * 4)
        b = self.tmp / "b.bin"
        shutil.copy(a, b)
        rec = diff(str(a), str(b), home=self.home)
        self.assertIn("byte-identical", rec.summary)

    @unittest.skipUnless(shutil.which("strings"), "strings is not installed")
    def test_string_changes_between_binaries(self):
        a = self.tmp / "a.bin"
        a.write_bytes(b"\x7fELF" + b"\x00" * 16 + b"legacy_endpoint_v1\x00" + b"\x00" * 8)
        b = self.tmp / "b.bin"
        b.write_bytes(b"\x7fELF" + b"\x00" * 16 + b"modern_endpoint_v2\x00" + b"\x00" * 8)
        rec = diff(str(a), str(b), home=self.home)
        added = [e["claim"] for e in rec.evidence if e["kind"] == "string-added"]
        removed = [e["claim"] for e in rec.evidence if e["kind"] == "string-removed"]
        self.assertTrue(any("modern_endpoint_v2" in c for c in added), added)
        self.assertTrue(any("legacy_endpoint_v1" in c for c in removed), removed)


class ApkDiffTests(unittest.TestCase):
    def test_manifest_and_dex_changes(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            v1 = build_apk(tmp / "v1.apk", [("application", [("debuggable", "bool", False)])], ["hello"])
            v2 = build_apk(
                tmp / "v2.apk",
                [
                    ("uses-permission", [("name", "str", "android.permission.CAMERA")]),
                    ("application", [("debuggable", "bool", True)]),
                ],
                ["hello", "new-feature-flag"],
            )
            rec = diff(str(v1), str(v2), home=tmp / "home")
            kinds = [e["kind"] for e in rec.evidence]
            self.assertIn("dex-string-added", kinds)
            manifest = [e["claim"] for e in rec.evidence if e["kind"] == "manifest-changed"]
            self.assertIn("debuggable: False -> True", manifest)
            self.assertIn("Sensitive permission added: android.permission.CAMERA", manifest)
            self.assertTrue(any(e["claim"].startswith("Dex string added: new-feature-flag") for e in rec.evidence))


class GraphTests(unittest.TestCase):
    def _data(self, claim: str = "search appears in main.js") -> dict:
        return {
            "id": "inv-20261114-000000-abcd",
            "target": "/work/app",
            "evidence": [
                {"ref": "E1", "source": "/work/app/main.js:3", "claim": claim, "kind": "js-term-hit", "capability": "js-scan"},
                {"ref": "E2", "source": "/work/app", "claim": "scan summary", "kind": "scan-summary", "capability": "js-scan"},
            ],
            "findings": [
                {"rule_id": "JS-001", "severity": "CRITICAL", "title": "nodeIntegration is enabled",
                 "source": "main.js:3", "refs": ["E1"], "detail": ""},
            ],
        }

    def test_mermaid_structure(self):
        mmd = build_mermaid(self._data())
        self.assertTrue(mmd.startswith("flowchart TD"))
        self.assertIn("T --> M1", mmd)  # target to module
        self.assertIn("M1 --> E1", mmd)  # module to evidence
        self.assertIn("E1 --> F1", mmd)  # evidence to finding
        self.assertIn("class F1 CRITICAL", mmd)
        self.assertIn("classDef CRITICAL", mmd)

    def test_html_escapes_hostile_content(self):
        page = build_html(self._data(claim='<script>alert("pwned")</script>'))
        self.assertNotIn('<script>alert("pwned")', page)
        self.assertIn("&lt;script&gt;alert(&quot;pwned&quot;)", page)
        self.assertIn("<svg", page)  # offline fallback is always present

    def test_mermaid_source_is_escaped_in_the_page(self):
        page = build_html(self._data(claim='x"y<b>z'))
        self.assertNotIn("<b>z", page)

    def test_evidence_about_the_target_itself_attaches_to_target(self):
        self.assertIn("T --> E2", build_mermaid(self._data()))

    def test_write_graph_creates_both_files(self):
        with tempfile.TemporaryDirectory() as d:
            mmd, html_path = write_graph(Path(d) / "inv", self._data())
            self.assertTrue(mmd.read_text(encoding="utf-8").startswith("flowchart TD"))
            self.assertIn("<!doctype html>", html_path.read_text(encoding="utf-8"))

    def test_export_graph_for_stored_run(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d) / "home"
            app = make_js_app(Path(d) / "app")
            rec = investigate(str(app), "search", home=home, export_graph=True)
            self.assertEqual(rec.graph_files, ["graph.mmd", "graph.html"])
            self.assertTrue((Path(rec.report_path).parent / "graph.html").is_file())
            mmd, html_path = export_graph_for(home, rec.id)
            self.assertTrue(html_path.is_file())
            self.assertIn("flowchart TD", mmd.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
