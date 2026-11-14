"""Audit rules: JavaScript/Electron, native ELF/PE protections, APK manifest and dex checks."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from helpers import FakeRunner, build_apk, quiet  # noqa: F401  (helpers sets sys.path)

from rea import native_tools
from rea.apk_format import parse_axml, parse_dex_strings
from rea.audit import audit_native, meets_minimum, redact
from rea.errors import ReaError
from rea.evidence import EvidenceBook
from rea.investigate import audit
from rea.setup_flow import run_setup


def _write(root: Path, name: str, text: str) -> None:
    (root / name).parent.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(text, encoding="utf-8")


def make_risky_electron_app(root: Path) -> Path:
    _write(root, "package.json", '{"name":"risky","devDependencies":{"electron":"30.0.0"}}')
    _write(root, "main.js",
           "const win = new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } });\n"
           "const userInput = readFromWeb();\n"
           "eval(userInput);\n"
           'eval("1 + 1");\n')
    _write(root, "preload.js",
           'const { contextBridge, ipcRenderer } = require("electron");\n'
           'contextBridge.exposeInMainWorld("api", { raw: ipcRenderer });\n'
           "function send(channel, data) { ipcRenderer.send(channel, data); }\n"
           'ipcRenderer.send("save-file", 1);\n')
    _write(root, "config/secrets.js",
           'const apiKey = "sk_live_abcdefghijklmnop123456";\n'
           'const aws = "AKIAIOSFODNN7EXAMPLE";\n'
           'const pem = "-----BEGIN RSA PRIVATE KEY-----";\n')
    _write(root, "worker.js",
           'const cp = require("child_process");\n'
           'cp.exec("ls -la");\n'
           "cp.exec(userCommand);\n"
           "const re = /x/; re.exec(text);\n")
    return root


class JsAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = self.tmp / "home"
        self.app = make_risky_electron_app(self.tmp / "app")
        self.rec = audit(str(self.app), home=self.home)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _rules(self) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = {}
        for f in self.rec.findings:
            out.setdefault(f["rule_id"], []).append(f)
        return out

    def test_flags_each_expected_rule(self):
        rules = self._rules()
        for rule in ("JS-001", "JS-002", "JS-003", "JS-004", "JS-005", "JS-006", "JS-007", "JS-008", "JS-009"):
            self.assertIn(rule, rules, f"{rule} did not fire")

    def test_severities_match_the_rule_table(self):
        rules = self._rules()
        self.assertEqual(rules["JS-001"][0]["severity"], "CRITICAL")
        self.assertEqual(rules["JS-002"][0]["severity"], "HIGH")
        self.assertEqual(rules["JS-007"][0]["severity"], "MEDIUM")

    def test_literal_eval_and_exec_are_not_flagged(self):
        # eval("1 + 1"), cp.exec("ls -la") and re.exec(text) are literal or method calls, not risky.
        sources = [f["source"] for f in self.rec.findings if f["rule_id"] in ("JS-008", "JS-009")]
        self.assertFalse(any(s.startswith("main.js:4") for s in sources))
        self.assertFalse(any(s.startswith("worker.js:2") for s in sources))
        self.assertFalse(any(s.startswith("worker.js:4") for s in sources))

    def test_every_finding_cites_an_evidence_ref(self):
        evidence_refs = {e["ref"] for e in self.rec.evidence}
        for f in self.rec.findings:
            self.assertTrue(f["refs"], f)
            self.assertTrue(set(f["refs"]) <= evidence_refs)

    def test_secrets_are_masked_everywhere(self):
        blob = json.dumps({"evidence": self.rec.evidence, "findings": self.rec.findings, "report": self.rec.report})
        self.assertNotIn("sk_live_abcdefghijklmnop123456", blob)
        self.assertNotIn("IOSFODNN7EXAMPLE", blob)
        self.assertIn("redacted", blob)

    def test_redact_masks_quoted_values_and_key_ids(self):
        self.assertEqual(redact('key = "sk_live_abcdefghijklmnop"'), 'key = "…[redacted]"')
        self.assertIn("AKIA…[redacted]", redact("AKIAIOSFODNN7EXAMPLE"))

    def test_minimum_severity_filter(self):
        rec = audit(str(self.app), home=self.home, min_severity="CRITICAL")
        self.assertTrue(rec.findings)
        self.assertTrue(all(f["severity"] == "CRITICAL" for f in rec.findings))
        self.assertTrue(meets_minimum("HIGH", "HIGH") and not meets_minimum("MEDIUM", "HIGH"))

    def test_invalid_minimum_severity_is_refused(self):
        with self.assertRaises(ReaError):
            audit(str(self.app), home=self.home, min_severity="URGENT")

    def test_clean_folder_says_no_rule_matched_and_is_not_called_safe(self):
        clean = self.tmp / "clean"
        _write(clean, "package.json", '{"name":"clean"}')
        _write(clean, "index.js", "console.log('hello');\n")
        rec = audit(str(clean), home=self.home)
        self.assertEqual(rec.findings, [])
        self.assertIn("does not mean the target is safe", rec.summary)


class NativeAuditTests(unittest.TestCase):
    ELF_HARDENED = {
        ("readelf", "-h"): "  Type: DYN (Position-Independent Executable file)\n",
        ("readelf", "-l"): "  GNU_STACK      0x0 0x0 0x0 0x0 0x0 RW  0x10\n  GNU_RELRO      0x0 0x0 0x0 0x0 0x0 R   0x1\n",
        ("readelf", "-d"): "0x000000000000001e (FLAGS)  BIND_NOW\n",
        ("readelf", "--dyn-syms"): "     5: 0  FUNC  GLOBAL DEFAULT UND __stack_chk_fail@GLIBC_2.4\n",
        ("nm", "-D"): "                 U __stack_chk_fail@GLIBC_2.4\n                 U puts@GLIBC_2.2.5\n",
    }
    ELF_WEAK = {
        ("readelf", "-h"): "  Type: EXEC (Executable file)\n",
        ("readelf", "-l"): "  GNU_STACK      0x0 0x0 0x0 0x0 0x0 RWE 0x10\n",
        ("readelf", "-d"): "",
        ("readelf", "--dyn-syms"): "",
        ("nm", "-D"): "                 U strcpy@GLIBC_2.2.5\n                 U gets@GLIBC_2.2.5\n",
    }

    def _audit(self, responses):
        book = EvidenceBook()
        tools = {"readelf": "/fake/readelf", "nm": "/fake/nm"}
        findings = audit_native(book, Path("/fake/target"), "elf-binary", tools, FakeRunner(responses))
        return book, findings

    def test_hardened_elf_has_no_protection_findings(self):
        _book, findings = self._audit(self.ELF_HARDENED)
        self.assertEqual([f for f in findings if f.rule_id in ("NAT-001", "NAT-002", "NAT-003", "NAT-004")], [])

    def test_weak_elf_reports_each_missing_protection(self):
        _book, findings = self._audit(self.ELF_WEAK)
        titles = " | ".join(f.title for f in findings)
        self.assertIn("Stack is executable", titles)
        self.assertIn("Not built as position-independent", titles)
        self.assertIn("No stack canary", titles)
        self.assertIn("No RELRO", titles)

    def test_unsafe_imports_are_flagged_with_their_severity(self):
        _book, findings = self._audit(self.ELF_WEAK)
        by_name = {f.title.split(": ")[-1]: f.severity for f in findings if f.rule_id == "NAT-005"}
        self.assertEqual(by_name, {"strcpy": "MEDIUM", "gets": "HIGH"})

    def test_findings_point_to_evidence(self):
        book, findings = self._audit(self.ELF_WEAK)
        refs = {e.ref for e in book.items}
        for f in findings:
            self.assertTrue(set(f.refs) <= refs)

    def test_parse_elf_protections_on_canned_text(self):
        # GNU_RELRO without BIND_NOW is partial RELRO.
        p = native_tools.parse_elf_protections(
            "  Type: DYN (Position-Independent Executable file)",
            "GNU_STACK ... RW\n GNU_RELRO ... R",
            "", "__stack_chk_fail",
        )
        self.assertEqual((p["pie"], p["nx"], p["relro"], p["canary"]), (True, True, "partial", True))
        full = native_tools.parse_elf_protections(
            "Position-Independent Executable", "GNU_RELRO ...\nGNU_STACK ... RW", "(FLAGS) BIND_NOW", ""
        )
        self.assertEqual(full["relro"], "full")

    def test_parse_pe_protections(self):
        self.assertEqual(
            native_tools.parse_pe_protections("DllCharacteristics 0x8160\n\tDYNAMIC_BASE\n\tNX_COMPAT\n"),
            {"format": "pe", "aslr": True, "nx": True},
        )
        self.assertFalse(native_tools.parse_pe_protections("DllCharacteristics 0x0000")["nx"])

    def test_nm_undefined_parser_ignores_defined_symbols(self):
        names = native_tools.parse_nm_undefined("0000 T main\n   U strcpy@GLIBC_2.2.5\n   U puts\n")
        self.assertEqual(names, {"strcpy", "puts"})

    def test_bin_tool_json_parser_is_defensive(self):
        self.assertEqual(native_tools.parse_bin_json('{"imports":[{"name":"puts"},{"x":1}]}', "imports"), ["puts"])
        self.assertEqual(native_tools.parse_bin_json("not json", "imports"), [])
        self.assertEqual(native_tools.parse_bin_json('{"imports": 3}', "imports"), [])


class ApkAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = self.tmp / "home"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_manifest_and_bytecode_checks(self):
        apk = build_apk(
            self.tmp / "app.apk",
            manifest=[
                ("manifest", []),
                ("uses-permission", [("name", "str", "android.permission.CAMERA")]),
                ("application", [
                    ("debuggable", "bool", True),
                    ("allowBackup", "bool", True),
                    ("usesCleartextTraffic", "bool", True),
                ]),
            ],
            dex_strings=["hello", "http://api.example.com/v1/login", "http://localhost:8080/dev"],
        )
        rec = audit(str(apk), home=self.home)
        rules = {f["rule_id"]: f for f in rec.findings}
        self.assertEqual(rules["APK-001"]["severity"], "HIGH")
        self.assertEqual(rules["APK-002"]["severity"], "HIGH")
        self.assertEqual(rules["APK-003"]["severity"], "MEDIUM")
        self.assertEqual(rules["APK-004"]["severity"], "INFO")
        cleartext = [f for f in rec.findings if f["rule_id"] == "APK-005"]
        self.assertEqual([f["detail"] for f in cleartext], ["http://api.example.com/v1/login"])  # localhost is ignored

    def test_hardened_manifest_has_no_manifest_findings(self):
        apk = build_apk(
            self.tmp / "safe.apk",
            manifest=[("application", [("debuggable", "bool", False), ("allowBackup", "bool", False)])],
            dex_strings=["plain"],
        )
        rec = audit(str(apk), home=self.home)
        self.assertEqual(rec.findings, [])

    def test_axml_and_dex_parsers_round_trip(self):
        from helpers import build_axml, build_dex

        elements = parse_axml(build_axml([("application", [("debuggable", "bool", True)])]))
        self.assertEqual(elements[0]["name"], "application")
        self.assertEqual(elements[0]["attrs"]["debuggable"], "true")
        self.assertEqual(parse_dex_strings(build_dex(["alpha", "beta"])), ["alpha", "beta"])

    def test_malformed_inputs_raise_value_error(self):
        with self.assertRaises(ValueError):
            parse_axml(b"not xml at all")
        with self.assertRaises(ValueError):
            parse_dex_strings(b"not dex")


class RedactionInEvidenceTests(unittest.TestCase):
    def test_book_excerpts_never_carry_raw_secrets(self):
        from rea.audit import audit_js
        from rea.static_analysis import _iter_sources  # noqa: F401

        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "app"
            _write(root, "s.js", 'const token = "ghp_0123456789abcdefghij";\n')
            book = EvidenceBook()
            audit_js(book, root, {"max_file_bytes": 1_000_000})
            for ev in book.items:
                self.assertNotIn("ghp_0123456789abcdefghij", ev.excerpt)


class ApkAuditApiTests(unittest.TestCase):
    def test_audit_works_without_an_allowlist_when_none_is_configured(self):
        # With no folders configured, the local CLI may audit any readable path; MCP requires an allowlist.
        with tempfile.TemporaryDirectory() as d:
            app = make_risky_electron_app(Path(d) / "app")
            rec = audit(str(app), home=Path(d) / "home")
            self.assertTrue(rec.findings)

    def test_audit_respects_allowlist_when_configured(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d) / "home"
            allowed = Path(d) / "allowed"
            allowed.mkdir()
            outside = make_risky_electron_app(Path(d) / "outside")
            run_setup(home, assume_yes=True, allow=[str(allowed)], out=quiet)
            with self.assertRaises(ReaError):
                audit(str(outside), home=home, require_allowlist=True)


if __name__ == "__main__":
    unittest.main()
