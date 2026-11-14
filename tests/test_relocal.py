"""Standard-library tests. Run from the project folder with: python3 -m unittest discover -s tests -v"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from relocal import mcp_server  # noqa: E402
from relocal import static_analysis as sa  # noqa: E402
from relocal.errors import RelocalError  # noqa: E402
from relocal.investigate import delete_investigation, investigate, list_investigations, load_investigation  # noqa: E402
from relocal.setup_flow import run_setup  # noqa: E402


def quiet(*_args, **_kwargs) -> None:
    pass


def make_js_app(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(
        json.dumps({"name": "demo", "devDependencies": {"electron": "30.0.0"}}), encoding="utf-8"
    )
    (root / "main.js").write_text(
        'ipcMain.handle("search", run);\n'
        'const url = "/api/search";\n'
        "function run(q) { return fetch(url + q); }\n",
        encoding="utf-8",
    )
    return root


def call(home: Path, name: str, arguments: dict) -> dict:
    reply = mcp_server.handle(
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": name, "arguments": arguments}},
        home=home,
    )
    return reply["result"]


class ExtractTermsTests(unittest.TestCase):
    def test_drops_stopwords(self):
        self.assertEqual(sa.extract_terms("How does search work in this app?"), ["search"])

    def test_empty_when_only_stopwords(self):
        self.assertEqual(sa.extract_terms("how does this work?"), [])


class IdentifyTests(unittest.TestCase):
    def test_elf_and_plain_text(self):
        with tempfile.TemporaryDirectory() as d:
            elf = Path(d, "fake-elf")
            elf.write_bytes(b"\x7fELF" + bytes(60))
            txt = Path(d, "notes.txt")
            txt.write_text("hello", encoding="utf-8")
            self.assertEqual(sa.identify(elf), "elf-binary")
            self.assertEqual(sa.identify(txt), "unknown")

    def test_electron_folder(self):
        with tempfile.TemporaryDirectory() as d:
            app = make_js_app(Path(d, "app"))
            self.assertEqual(sa.identify(app), "electron-app")


class JsInvestigationTests(unittest.TestCase):
    def test_scan_finds_term_route_and_ipc(self):
        with tempfile.TemporaryDirectory() as d:
            app = make_js_app(Path(d, "app"))
            rec = investigate(str(app), "How does search work?", home=Path(d, "home"))
            self.assertEqual(rec.target_kind, "electron-app")
            self.assertEqual(rec.terms, ["search"])
            self.assertIn("js-term-hit", {e["kind"] for e in rec.evidence})
            self.assertTrue(any("/api/search" in e["claim"] for e in rec.evidence if e["kind"] == "route-candidate"))
            self.assertTrue(any(e["kind"] == "network-call-sites" for e in rec.evidence))
            self.assertIn("## Limitations", rec.report)

    def test_unknown_file_reports_limitation_not_guess(self):
        with tempfile.TemporaryDirectory() as d:
            note = Path(d, "notes.txt")
            note.write_text("search everywhere", encoding="utf-8")
            rec = investigate(str(note), "search", home=Path(d, "home"))
            self.assertEqual(rec.target_kind, "unknown")
            self.assertEqual(rec.evidence, [])
            self.assertTrue(any("No capability handles" in text for text in rec.limitations))


class HistoryTests(unittest.TestCase):
    def test_save_list_load_delete(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d, "home")
            rec = investigate(str(make_js_app(Path(d, "app"))), "search", home=home)
            self.assertEqual(list_investigations(home)[0]["id"], rec.id)
            self.assertIn("Investigation", load_investigation(home, rec.id)["report"])
            self.assertTrue(delete_investigation(home, rec.id))
            self.assertEqual(list_investigations(home), [])
            self.assertFalse(Path(rec.report_path).parent.exists())

    def test_rejects_path_like_ids(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(RelocalError):
                delete_investigation(Path(d, "home"), "../../etc")


class SetupTests(unittest.TestCase):
    def test_dry_run_changes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d, "home")
            self.assertEqual(run_setup(home, dry_run=True, out=quiet), 0)
            self.assertFalse(home.exists())

    def test_refuses_to_change_anything_without_consent(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d, "home")
            rc = run_setup(home, out=quiet, input_fn=lambda _prompt: "n")
            self.assertIn(rc, (1, 2))
            self.assertFalse(home.exists())

    def test_assume_yes_writes_config_and_keeps_roots_on_rerun(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d, "home")
            allowed = Path(d, "allowed")
            allowed.mkdir()
            self.assertEqual(run_setup(home, assume_yes=True, allow=[str(allowed)], out=quiet), 0)
            config = json.loads((home / "config.json").read_text(encoding="utf-8"))
            self.assertIn(str(allowed.resolve()), config["allowed_roots"])
            self.assertEqual(run_setup(home, assume_yes=True, out=quiet), 0)
            config = json.loads((home / "config.json").read_text(encoding="utf-8"))
            self.assertIn(str(allowed.resolve()), config["allowed_roots"])
            self.assertTrue(any((home / "logs").glob("setup-*.log")))


class AllowlistTests(unittest.TestCase):
    def test_target_outside_allowed_folder_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            allowed = Path(d, "allowed")
            allowed.mkdir()
            outside = make_js_app(Path(d, "outside"))
            inside = make_js_app(allowed / "app")
            home = Path(d, "home")
            run_setup(home, assume_yes=True, allow=[str(allowed)], out=quiet)
            with self.assertRaises(RelocalError):
                investigate(str(outside), "search", home=home, require_allowlist=True)
            self.assertTrue(investigate(str(inside), "search", home=home, require_allowlist=True).id)


class McpTests(unittest.TestCase):
    def test_handshake_and_tool_list(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d, "home")
            init = mcp_server.handle(
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
                home=home,
            )
            self.assertEqual(init["result"]["serverInfo"]["name"], "relocal")
            self.assertIsNone(mcp_server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, home=home))
            tools = mcp_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, home=home)["result"]["tools"]
            names = {t["name"] for t in tools}
            self.assertTrue({"relocal_doctor", "relocal_investigate", "relocal_list_investigations", "relocal_get_report"} <= names)
            self.assertTrue({"relocal_audit", "relocal_diff"} <= names)

    def test_investigate_refused_until_a_folder_is_allowed(self):
        with tempfile.TemporaryDirectory() as d:
            app = make_js_app(Path(d, "app"))
            result = call(Path(d, "home"), "relocal_investigate", {"target": str(app), "question": "search"})
            self.assertTrue(result["isError"])
            self.assertIn("relocal setup --allow", result["content"][0]["text"])

    def test_investigate_works_inside_allowed_folder(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d, "home")
            app = make_js_app(Path(d, "work") / "app")
            run_setup(home, assume_yes=True, allow=[str(Path(d, "work"))], out=quiet)
            result = call(home, "relocal_investigate", {"target": str(app), "question": "search"})
            self.assertFalse(result["isError"])
            self.assertIn("Investigation inv-", result["content"][0]["text"])

    def test_stdio_loop_writes_only_protocol_json(self):
        with tempfile.TemporaryDirectory() as d:
            stdin = io.StringIO(
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\nnot json\n"
            )
            stdout = io.StringIO()
            mcp_server.serve(stdin=stdin, stdout=stdout, home=Path(d, "home"))
            lines = stdout.getvalue().splitlines()
            self.assertEqual(len(lines), 2)
            for line in lines:
                json.loads(line)


if __name__ == "__main__":
    unittest.main()
