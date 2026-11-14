"""Audit rules: static signatures and structural checks that flag common risks. Each finding cites evidence.

Severity scale: CRITICAL > HIGH > MEDIUM > INFO. Findings are leads for a human reviewer. They are not
proof of exploitability.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from relocal import native_tools
from relocal.apk_format import SENSITIVE_PERMISSIONS, cleartext_urls, manifest_facts, parse_axml, parse_dex_strings
from relocal.evidence import EvidenceBook
from relocal.runner import Runner
from relocal.static_analysis import _iter_sources, _window

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "INFO")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
MAX_FINDINGS_PER_RULE = 25


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    source: str
    refs: list[str] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def meets_minimum(severity: str, minimum: str) -> bool:
    return SEVERITY_RANK[severity] <= SEVERITY_RANK[minimum]


# Secret values never reach the report: they are masked in every excerpt.
_SECRET_MASKS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), lambda m: "AKIA…[redacted]"),
    (re.compile(r"(['\"])[^'\"\s]{12,}(['\"])"), lambda m: f"{m.group(1)}…[redacted]{m.group(2)}"),
]


def redact(text: str) -> str:
    for pattern, repl in _SECRET_MASKS:
        text = pattern.sub(repl, text)
    return text


def _is_preload(path: Path, text: str) -> bool:
    return "preload" in path.name.lower() or "contextbridge" in text.lower()


def _uses_child_process(path: Path, text: str) -> bool:
    return "child_process" in text


@dataclass(frozen=True)
class JsRule:
    rule_id: str
    severity: str
    title: str
    pattern: re.Pattern
    scope: Callable[[Path, str], bool] | None = None
    secret: bool = False


JS_RULES = (
    JsRule("JS-001", "CRITICAL", "nodeIntegration is enabled", re.compile(r"nodeIntegration\s*:\s*true")),
    JsRule("JS-002", "HIGH", "contextIsolation is disabled", re.compile(r"contextIsolation\s*:\s*false")),
    JsRule(
        "JS-003", "HIGH", "Raw ipcRenderer exposed to the page",
        re.compile(r"exposeInMainWorld[^\n]*\bipcRenderer\b"), _is_preload,
    ),
    JsRule(
        "JS-004", "HIGH", "IPC channel name is not a fixed string",
        re.compile(r"\bipcRenderer\.(?:send|sendSync|invoke|on|once)\(\s*(?![\'\"`])"), _is_preload,
    ),
    JsRule("JS-005", "CRITICAL", "Private key embedded in source",
           re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), None, True),
    JsRule("JS-006", "HIGH", "AWS access key ID embedded", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), None, True),
    JsRule(
        "JS-007", "MEDIUM", "Possible hard-coded secret",
        re.compile(r"(?i)\b(api[_-]?key|secret|token|passw(?:or)?d)\b['\"]?\s*[:=]\s*['\"][^'\"\s]{12,}['\"]"),
        None, True,
    ),
    JsRule("JS-008", "HIGH", "eval() called on a non-literal value",
           re.compile(r"(?<![.\w])eval\(\s*(?![\'\"`])")),
    JsRule(
        "JS-009", "HIGH", "Shell command built from a non-literal value",
        # A bare exec(...) call, or a method call on a child_process-style receiver.
        # Other receivers such as re.exec(...) are deliberately not matched.
        re.compile(
            r"(?:(?<![.\w])(?:exec|execSync)|\b(?:cp|childProcess|child_process)\.(?:exec|execSync))\(\s*(?![\'\"`])"
        ),
        _uses_child_process,
    ),
)


def audit_js(book: EvidenceBook, root: Path, limits: dict) -> list[Finding]:
    findings: list[Finding] = []
    per_rule: dict[str, int] = {}
    stats = {"scanned": 0, "skipped": 0}
    for path, text in _iter_sources(root, limits["max_file_bytes"], stats):
        rel = path.relative_to(root).as_posix()
        for lineno, line in enumerate(text.splitlines(), 1):
            for rule in JS_RULES:
                for m in rule.pattern.finditer(line):
                    if rule.scope is not None and not rule.scope(path, text):
                        continue
                    if per_rule.get(rule.rule_id, 0) >= MAX_FINDINGS_PER_RULE:
                        book.limit(f"{rule.rule_id} stopped after {MAX_FINDINGS_PER_RULE} findings.")
                        break
                    per_rule[rule.rule_id] = per_rule.get(rule.rule_id, 0) + 1
                    excerpt = redact(_window(line, m.start(), m.end() - m.start()))
                    ev = book.add("audit-js", f"{rel}:{lineno}", "rule-hit", f"{rule.rule_id}: {rule.title}", excerpt)
                    findings.append(Finding(rule.rule_id, rule.severity, rule.title, f"{rel}:{lineno}", [ev.ref]))
    book.add("audit-js", str(root), "scan-summary", f"Scanned {stats['scanned']} source files for {len(JS_RULES)} rules")
    book.limit("Rules match text patterns. Minified or obfuscated code can hide or fake a match; confirm each finding in context.")
    return findings


def audit_native(book: EvidenceBook, path: Path, kind: str, tools: dict[str, str | None], runner: Runner) -> list[Finding]:
    target = str(path)
    findings: list[Finding] = []
    prot: dict = {}
    if kind == "elf-binary" and tools.get("readelf"):
        prot = native_tools.run_elf_protections(runner, tools["readelf"], target)
    elif kind == "pe-binary" and tools.get("objdump"):
        prot = native_tools.run_pe_protections(runner, tools["objdump"], target)
    else:
        book.limit("Protection checks need readelf (ELF) or objdump (PE). They were skipped.")

    if prot.get("error"):
        book.limit(f"Protection check failed: {prot['error']}")
        prot = {}

    if prot.get("format") == "elf":
        ev_nx = book.add("audit-native", target, "protection", f"NX (non-executable stack): {_yn(prot['nx'])} (readelf GNU_STACK)")
        ev_pie = book.add("audit-native", target, "protection", f"PIE: {_yn(prot['pie'])} (readelf ELF header type)")
        ev_relro = book.add("audit-native", target, "protection", f"RELRO: {prot['relro']} (readelf GNU_RELRO and BIND_NOW)")
        ev_canary = book.add("audit-native", target, "protection", f"Stack canary: {_yn(prot['canary'])} (__stack_chk_fail in dynamic symbols)")
        if prot["nx"] is False:
            findings.append(Finding("NAT-001", "HIGH", "Stack is executable (no NX)", target, [ev_nx.ref]))
        elif prot["nx"] is None:
            findings.append(Finding("NAT-001", "INFO", "No GNU_STACK header, so stack executability is unknown", target, [ev_nx.ref]))
        if not prot["pie"]:
            findings.append(Finding("NAT-002", "MEDIUM", "Not built as position-independent (no PIE)", target, [ev_pie.ref]))
        if not prot["canary"]:
            findings.append(Finding("NAT-003", "MEDIUM", "No stack canary detected", target, [ev_canary.ref],
                                    "Heuristic: the canary runtime symbol is absent from the dynamic symbol table."))
        if prot["relro"] == "none":
            findings.append(Finding("NAT-004", "MEDIUM", "No RELRO", target, [ev_relro.ref]))
        elif prot["relro"] == "partial":
            findings.append(Finding("NAT-004", "INFO", "Partial RELRO (BIND_NOW missing)", target, [ev_relro.ref]))

    if prot.get("format") == "pe":
        ev_nx = book.add("audit-native", target, "protection", f"NX_COMPAT (DEP): {_yn(prot['nx'])} (objdump -p DllCharacteristics)")
        ev_aslr = book.add("audit-native", target, "protection", f"DYNAMIC_BASE (ASLR): {_yn(prot['aslr'])} (objdump -p DllCharacteristics)")
        if not prot["nx"]:
            findings.append(Finding("NAT-001", "HIGH", "DEP/NX not enabled (NX_COMPAT missing)", target, [ev_nx.ref]))
        if not prot["aslr"]:
            findings.append(Finding("NAT-002", "MEDIUM", "ASLR disabled (DYNAMIC_BASE missing)", target, [ev_aslr.ref]))

    names: set[str] = set()
    if kind == "elf-binary" and tools.get("nm"):
        names |= native_tools.run_nm_undefined(runner, tools["nm"], target, dynamic=True)
    elif kind == "pe-binary" and tools.get("nm"):
        names |= native_tools.run_nm_undefined(runner, tools["nm"], target, dynamic=False)
    bin_tool = next(((n, tools[n]) for n in ("rabin2", "rz-bin") if tools.get(n)), None)
    if bin_tool:
        names |= set(native_tools.run_bin_tool_extract(runner, bin_tool[0], bin_tool[1], target)["imports"])

    for name, severity in native_tools.dangerous_imports(names):
        ev = book.add("audit-native", target, "import-hit", f"Unsafe C function imported: {name}", name)
        findings.append(Finding("NAT-005", severity, f"Unsafe C function imported: {name}", target, [ev.ref],
                                "Imported, so reachable from code. Check every call site for bounds handling."))
    if not names:
        book.limit("No import table was readable, so unsafe-function checks found nothing either way.")
    book.limit("Protection flags describe how the binary was built. They do not prove a bug exists.")
    return findings


def _yn(value: bool | None) -> str:
    if value is None:
        return "unknown"
    return "yes" if value else "no"


def audit_apk(book: EvidenceBook, path: Path) -> list[Finding]:
    target = str(path)
    findings: list[Finding] = []
    try:
        with zipfile.ZipFile(path) as zf:
            axml = zf.read("AndroidManifest.xml")
            dex_names = [n for n in zf.namelist() if re.fullmatch(r"classes\d*\.dex", n)]
            dex_blobs = {n: zf.read(n) for n in dex_names}
    except (zipfile.BadZipFile, KeyError, OSError) as exc:
        book.limit(f"APK could not be read for audit: {exc}")
        return findings

    try:
        facts = manifest_facts(parse_axml(axml))
    except ValueError as exc:
        book.limit(f"AndroidManifest.xml could not be parsed: {exc}")
        facts = None

    if facts is not None:
        if facts["debuggable"]:
            ev = book.add("audit-apk", "AndroidManifest.xml", "manifest-attr", 'android:debuggable="true" on <application>')
            findings.append(Finding("APK-001", "HIGH", "App is debuggable", target, [ev.ref],
                                    "Debuggable builds let other processes attach a debugger."))
        if facts["usesCleartextTraffic"]:
            ev = book.add("audit-apk", "AndroidManifest.xml", "manifest-attr", 'android:usesCleartextTraffic="true"')
            findings.append(Finding("APK-002", "HIGH", "Cleartext (HTTP) traffic is allowed", target, [ev.ref]))
        if facts["allowBackup"]:
            ev = book.add("audit-apk", "AndroidManifest.xml", "manifest-attr", 'android:allowBackup="true" on <application>')
            findings.append(Finding("APK-003", "MEDIUM", "App data can be backed up", target, [ev.ref]))
        for perm in facts["permissions"]:
            if perm in SENSITIVE_PERMISSIONS:
                ev = book.add("audit-apk", "AndroidManifest.xml", "manifest-attr", f"Sensitive permission requested: {perm}")
                findings.append(Finding("APK-004", "INFO", f"Sensitive permission: {perm}", target, [ev.ref]))

    all_strings: list[tuple[str, str]] = []
    for name, blob in dex_blobs.items():
        try:
            all_strings += [(name, s) for s in parse_dex_strings(blob)]
        except ValueError as exc:
            book.limit(f"{name} could not be parsed: {exc}")
    urls: dict[str, str] = {}
    for name, s in all_strings:
        for url in cleartext_urls([s]):
            urls.setdefault(url, name)
    for url, dex_name in list(urls.items())[:MAX_FINDINGS_PER_RULE]:
        ev = book.add("audit-apk", dex_name, "string-hit", f"Cleartext HTTP URL in bytecode: {url}")
        findings.append(Finding("APK-005", "MEDIUM", "Cleartext HTTP URL in bytecode", dex_name, [ev.ref], url))
    book.limit("Only string constants in the dex files were searched. URLs assembled at runtime are not visible.")
    return findings
