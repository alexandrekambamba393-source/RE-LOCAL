"""Static capabilities. Everything here reads or parses the target. Nothing executes it."""

from __future__ import annotations

import json
import os
import re
import zipfile
from collections import Counter
from pathlib import Path
from typing import Iterator

from rea import native_tools
from rea.evidence import EvidenceBook
from rea.runner import Runner

BINARY_KINDS = {"elf-binary", "pe-binary", "macho-binary", "cafebabe-object"}
JS_KINDS = {"javascript-app", "electron-app"}
TERM_KINDS = {"string-hit", "symbol-hit", "js-term-hit", "apk-entry-hit", "managed-runtime-marker", "bin-tool-hit"}

MACHO_MAGICS = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}
STOPWORDS = {
    "how", "does", "do", "work", "works", "the", "this", "that", "app", "application", "what", "where",
    "when", "why", "which", "for", "and", "with", "from", "into", "are", "is", "in", "of", "to", "a", "an",
    "it", "its", "can", "you", "show", "find", "explain", "feature", "use", "used", "using",
}
JS_SUFFIXES = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".html", ".json"}
JS_SKIP_DIRS = {"node_modules", ".git"}
MAX_HITS_PER_TERM = 8
MAX_ROUTES = 30
MAX_FILES = 3000

ROUTE_RE = re.compile(r"""['"`](/(?:api/)?[A-Za-z0-9_\-/{}:.]{2,120})['"`]""")
NET_RE = re.compile(
    r"\b(fetch|XMLHttpRequest|WebSocket|axios\.(?:get|post|put|delete|patch)|ipcRenderer\.invoke|ipcMain\.handle)\b"
)


def extract_terms(question: str, limit: int = 8) -> list[str]:
    terms: list[str] = []
    for word in re.findall(r"[a-z][a-z0-9_\-]{2,}", question.lower()):
        if word not in STOPWORDS and word not in terms:
            terms.append(word)
    return terms[:limit]


def identify(path: Path) -> str:
    if path.is_dir():
        pkg = path / "package.json"
        if pkg.is_file():
            return "electron-app" if _is_electron(path, pkg) else "javascript-app"
        return "directory"
    if path.suffix.lower() == ".asar":
        return "asar-archive"
    with path.open("rb") as fh:
        head = fh.read(4)
    if head == b"\x7fELF":
        return "elf-binary"
    if head[:2] == b"MZ":
        return "pe-binary"
    if head in MACHO_MAGICS:
        return "macho-binary"
    if head == b"\xca\xfe\xba\xbe":
        return "cafebabe-object"  # universal Mach-O or Java class; both start this way
    if head == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(path) as zf:
                names = set(zf.namelist())
        except zipfile.BadZipFile:
            return "unknown"
        return "android-apk" if "AndroidManifest.xml" in names else "zip-archive"
    return "unknown"


def _is_electron(root: Path, pkg: Path) -> bool:
    if (root / "resources" / "app.asar").exists():
        return True
    try:
        data = json.loads(pkg.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(data, dict):
        return False
    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    return "electron" in deps


def _window(line: str, start: int, length: int, radius: int = 80) -> str:
    lo = max(0, start - radius)
    hi = min(len(line), start + length + radius)
    return line[lo:hi].strip()


def _term_hits(
    book: EvidenceBook,
    capability: str,
    source: str,
    kind: str,
    lines: list[str],
    terms: list[str],
    template: str,
) -> None:
    for term in terms:
        hits = [ln for ln in lines if term in ln.lower()]
        for ln in hits[:MAX_HITS_PER_TERM]:
            book.add(capability, source, kind, template.format(t=term), ln.strip()[:200])
        if len(hits) > MAX_HITS_PER_TERM:
            book.add(
                capability,
                source,
                "hit-count",
                f"{len(hits)} matches for '{term}' in total; the first {MAX_HITS_PER_TERM} are listed",
            )


def collect_binary(
    book: EvidenceBook,
    path: Path,
    kind: str,
    tools: dict[str, str | None],
    runner: Runner,
    terms: list[str],
) -> None:
    target = str(path)  # absolute, so it can never be read as a command-line flag

    book.limit("Static only: the target was not executed. Each hit is a lead to verify in code, not proof of behavior.")
    book.limit("No disassembly, decompilation, or debugger session runs in this version.")

    if tools.get("file"):
        res = runner.run([tools["file"], "-b", target])
        if res.ok:
            book.add("file-id", target, "file-type", f"file(1) reports: {res.stdout.strip()[:200]}")
    else:
        book.limit("`file` is not installed, so the file type was not cross-checked.")

    lines: list[str] = []
    if tools.get("strings"):
        res = runner.run([tools["strings"], "-n", "6", target])
        if res.ok:
            lines = res.stdout.splitlines()
            _term_hits(book, "strings", target, "string-hit", lines, terms, "Embedded text contains '{t}'")
        else:
            book.limit(f"strings failed: {res.error}")
    else:
        book.limit("`strings` is not installed, so embedded text was not searched.")

    marker = next((ln for ln in lines if "mscoree" in ln.lower()), None)
    if marker is not None:
        book.add(
            "strings",
            target,
            "managed-runtime-marker",
            "Binary references mscoree.dll, which suggests a .NET (managed) build",
            marker.strip()[:200],
        )
        book.limit("Managed .NET internals need a managed decompiler, which is not wired in yet.")

    if tools.get("nm"):
        argv = [tools["nm"], "--defined-only", target]
        if kind == "elf-binary":
            argv.insert(1, "-D")
        res = runner.run(argv)
        names = [parts[-1] for parts in (ln.split() for ln in res.stdout.splitlines()) if parts]
        if names:
            _term_hits(book, "symbols", target, "symbol-hit", names, terms, "Symbol name contains '{t}'")
        else:
            book.limit("No readable defined symbols. The binary may be stripped, or nm could not read it.")
    else:
        book.limit("`nm` is not installed, so symbol names were not searched.")

    if tools.get("objdump"):
        res = runner.run([tools["objdump"], "-h", target])
        sections = re.findall(r"^\s+\d+\s+(\S+)\s+[0-9a-fA-F]+", res.stdout, re.M)
        if sections:
            book.add("sections", target, "section-list", f"{len(sections)} sections; first ones: {', '.join(sections[:12])}")

    bin_tool = next(((n, tools[n]) for n in ("rabin2", "rz-bin") if tools.get(n)), None)
    if bin_tool:
        extract = native_tools.run_bin_tool_extract(runner, bin_tool[0], bin_tool[1], target)
        for key in ("imports", "exports"):
            names = extract[key]
            if names:
                book.add("bin-tools", target, "bin-tool-list", f"{bin_tool[0]} lists {len(names)} {key}")
                _term_hits(book, "bin-tools", target, "bin-tool-hit", names, terms, f"{key[:-1].capitalize()} name contains '{{t}}'")
        if extract["sections"]:
            book.add("bin-tools", target, "bin-tool-list", f"{bin_tool[0]} lists {len(extract['sections'])} sections")
        for err in extract.get("errors", []):
            book.limit(f"Optional tool issue: {err}")


def _iter_sources(root: Path, max_bytes: int, stats: dict) -> Iterator[tuple[Path, str]]:
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in JS_SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.suffix.lower() not in JS_SUFFIXES or path.is_symlink():
                continue
            if count >= MAX_FILES:
                return
            count += 1
            try:
                if path.stat().st_size > max_bytes:
                    stats["skipped"] += 1
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                stats["skipped"] += 1
                continue
            stats["scanned"] += 1
            yield path, text


def collect_js_tree(book: EvidenceBook, root: Path, kind: str, limits: dict, terms: list[str]) -> None:
    target = str(root)
    book.limit("Static only: scanned source was not run. Route literals are candidates until confirmed in code.")
    if (root / "resources" / "app.asar").exists():
        book.limit("resources/app.asar is packed and was not extracted, so only loose files were scanned.")

    stats = {"scanned": 0, "skipped": 0}
    per_term = {t: 0 for t in terms}
    routes = 0
    net: Counter[str] = Counter()

    for path, text in _iter_sources(root, limits["max_file_bytes"], stats):
        rel = path.relative_to(root).as_posix()
        for lineno, line in enumerate(text.splitlines(), 1):
            lower = line.lower()
            for term in terms:
                if per_term[term] >= MAX_HITS_PER_TERM:
                    continue
                idx = lower.find(term)
                if idx != -1:
                    per_term[term] += 1
                    book.add(
                        "js-scan",
                        f"{rel}:{lineno}",
                        "js-term-hit",
                        f"'{term}' appears in {rel} at line {lineno}",
                        _window(line, idx, len(term)),
                    )
            if routes < MAX_ROUTES:
                for m in ROUTE_RE.finditer(line):
                    if routes >= MAX_ROUTES:
                        break
                    routes += 1
                    book.add(
                        "js-scan",
                        f"{rel}:{lineno}",
                        "route-candidate",
                        f"Possible route literal: {m.group(1)}",
                        _window(line, m.start(), len(m.group(0))),
                        confidence="inferred",
                    )
            net.update(m.group(1) for m in NET_RE.finditer(line))

    book.add(
        "js-scan",
        target,
        "scan-summary",
        f"Scanned {stats['scanned']} source files; skipped {stats['skipped']} (too large or unreadable)",
    )
    if net:
        summary = ", ".join(f"{name} x{count}" for name, count in net.most_common(6))
        book.add("js-scan", target, "network-call-sites", f"Network and IPC call sites seen: {summary}")


def collect_apk(book: EvidenceBook, path: Path, tools: dict[str, str | None], terms: list[str]) -> None:
    target = str(path)
    book.limit("Dex bytecode is not decompiled in this version, so method-level behavior is not visible.")
    book.limit("AndroidManifest.xml is binary XML. Its security attributes are checked by `rea audit`.")
    if tools.get("jadx"):
        book.limit("jadx is installed, but APK decompilation is not wired into RE LOCAL yet.")
    else:
        book.limit("jadx is not installed. It will be needed once APK decompilation is added.")
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except zipfile.BadZipFile:
        book.limit("The APK could not be read as a zip archive.")
        return
    dex = [n for n in names if re.fullmatch(r"classes\d*\.dex", n)]
    book.add("apk", target, "apk-layout", f"{len(names)} archive entries; {len(dex)} dex file(s): {', '.join(dex) or 'none'}")
    _term_hits(book, "apk", target, "apk-entry-hit", names, terms, "Archive entry name contains '{t}'")
