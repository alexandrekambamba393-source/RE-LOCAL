"""Patch diffing: compare two versions of the same kind of target and record only what changed.

Supported pairs: two folders (file tree, plus routes and IPC/network call sites for JS/Electron),
two native binaries (strings, symbol names, section names), or two APKs (entries, dex strings, manifest).
"""

from __future__ import annotations

import hashlib
import os
import re
import zipfile
from collections import Counter
from pathlib import Path

from rea import native_tools
from rea import static_analysis as sa
from rea.apk_format import SENSITIVE_PERMISSIONS, manifest_facts, parse_axml, parse_dex_strings
from rea.errors import ReaError
from rea.evidence import EvidenceBook
from rea.runner import Runner

MAX_LISTED = 200  # per change category; the rest is counted, not listed


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree(root: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_file() and not path.is_symlink():
                files[path.relative_to(root).as_posix()] = path
    return files


def _emit(book: EvidenceBook, capability: str, source: str, kind: str, items: list[str], template: str) -> dict:
    """Record up to MAX_LISTED changes as evidence and count the rest."""
    for item in items[:MAX_LISTED]:
        book.add(capability, source, kind, template.format(item=item))
    extra = len(items) - MAX_LISTED
    if extra > 0:
        book.add(capability, source, "hit-count", f"{extra} more {kind} changes not listed")
    return {"count": len(items)}


def _set_diff(old: set[str], new: set[str]) -> tuple[list[str], list[str]]:
    return sorted(new - old), sorted(old - new)


def diff_targets(
    book: EvidenceBook,
    old: Path,
    new: Path,
    old_kind: str,
    new_kind: str,
    tools: dict[str, str | None],
    runner: Runner,
    limits: dict,
) -> dict:
    if old_kind == new_kind == "unknown":
        raise ReaError("Neither target is a kind REA can diff yet.")
    if old_kind in sa.JS_KINDS | {"directory"} and new_kind in sa.JS_KINDS | {"directory"} and old.is_dir() and new.is_dir():
        return _diff_folders(book, old, new, old_kind in sa.JS_KINDS, limits)
    if old_kind in sa.BINARY_KINDS and new_kind == old_kind:
        return _diff_binaries(book, old, new, old_kind, tools, runner)
    if old_kind == new_kind == "android-apk":
        return _diff_apks(book, old, new)
    raise ReaError(f"Cannot diff a {old_kind} against a {new_kind}. Give two versions of the same kind of target.")


def _diff_folders(book: EvidenceBook, old: Path, new: Path, is_js: bool, limits: dict) -> dict:
    old_files, new_files = _tree(old), _tree(new)
    added = sorted(set(new_files) - set(old_files))
    removed = sorted(set(old_files) - set(new_files))
    modified = sorted(
        p for p in set(old_files) & set(new_files) if _sha256(old_files[p]) != _sha256(new_files[p])
    )
    summary = {
        "files_added": _emit(book, "diff-tree", str(new), "file-added", added, "File added: {item}")["count"],
        "files_removed": _emit(book, "diff-tree", str(new), "file-removed", removed, "File removed: {item}")["count"],
        "files_modified": _emit(book, "diff-tree", str(new), "file-modified", modified, "File changed (SHA-256 differs): {item}")["count"],
    }
    if is_js:
        old_routes, old_net = _js_surface(old, limits)
        new_routes, new_net = _js_surface(new, limits)
        r_added, r_removed = _set_diff(old_routes, new_routes)
        summary["routes_added"] = _emit(book, "diff-js", str(new), "route-added", r_added, "Route literal added: {item}")["count"]
        summary["routes_removed"] = _emit(book, "diff-js", str(new), "route-removed", r_removed, "Route literal removed: {item}")["count"]
        changed_net = [
            f"{name}: {old_net.get(name, 0)} -> {new_net.get(name, 0)}"
            for name in sorted(set(old_net) | set(new_net))
            if old_net.get(name, 0) != new_net.get(name, 0)
        ]
        summary["network_ipc_changed"] = _emit(book, "diff-js", str(new), "call-site-changed", changed_net, "Call-site count changed: {item}")["count"]
        book.limit("Route and call-site comparison uses literal text. Routes built at runtime are not compared.")
    return summary


def _js_surface(root: Path, limits: dict) -> tuple[set[str], Counter]:
    routes: set[str] = set()
    net: Counter[str] = Counter()
    stats = {"scanned": 0, "skipped": 0}
    for _path, text in sa._iter_sources(root, limits["max_file_bytes"], stats):
        for m in sa.ROUTE_RE.finditer(text):
            routes.add(m.group(1))
        net.update(m.group(1) for m in sa.NET_RE.finditer(text))
    return routes, net


def _strings_of(path: Path, runner: Runner, strings_bin: str | None) -> set[str]:
    if not strings_bin:
        return set()
    res = runner.run([strings_bin, "-n", "6", str(path)])
    return set(res.stdout.splitlines()) if res.ok else set()


def _symbols_of(path: Path, kind: str, runner: Runner, nm: str | None) -> set[str]:
    if not nm:
        return set()
    argv = [nm, "--defined-only", str(path)]
    if kind == "elf-binary":
        argv.insert(1, "-D")
    res = runner.run(argv)
    return {parts[-1] for parts in (ln.split() for ln in res.stdout.splitlines()) if parts}


def _sections_of(path: Path, runner: Runner, objdump: str | None) -> set[str]:
    if not objdump:
        return set()
    res = runner.run([objdump, "-h", str(path)])
    return set(re.findall(r"^\s+\d+\s+(\S+)\s+[0-9a-fA-F]+", res.stdout, re.M))


def _diff_binaries(book, old, new, kind, tools, runner) -> dict:
    old_hash, new_hash = _sha256(old), _sha256(new)
    summary = {"identical": old_hash == new_hash, "binary_hash_changed": old_hash != new_hash}
    book.add("diff-binary", str(new), "hash", f"SHA-256 {'identical' if not summary['binary_hash_changed'] else 'changed'}: {old_hash[:12]} -> {new_hash[:12]}")
    if not summary["binary_hash_changed"]:
        return summary
    if tools.get("strings"):
        s_add, s_rm = _set_diff(_strings_of(old, runner, tools["strings"]), _strings_of(new, runner, tools["strings"]))
        summary["strings_added"] = _emit(book, "diff-binary", str(new), "string-added", s_add, "String added: {item}")["count"]
        summary["strings_removed"] = _emit(book, "diff-binary", str(new), "string-removed", s_rm, "String removed: {item}")["count"]
    else:
        book.limit("`strings` is not installed, so string changes were not compared.")
    if tools.get("nm"):
        y_add, y_rm = _set_diff(_symbols_of(old, kind, runner, tools["nm"]), _symbols_of(new, kind, runner, tools["nm"]))
        summary["symbols_added"] = _emit(book, "diff-binary", str(new), "symbol-added", y_add, "Symbol added: {item}")["count"]
        summary["symbols_removed"] = _emit(book, "diff-binary", str(new), "symbol-removed", y_rm, "Symbol removed: {item}")["count"]
    else:
        book.limit("`nm` is not installed, so symbol changes were not compared.")
    if tools.get("objdump"):
        c_add, c_rm = _set_diff(_sections_of(old, runner, tools["objdump"]), _sections_of(new, runner, tools["objdump"]))
        summary["sections_changed"] = _emit(book, "diff-binary", str(new), "section-changed", c_add + [f"-{s}" for s in c_rm], "Section change: {item}")["count"]
    book.limit("Diffs compare text that appears in the binaries. Code changes are visible only through these proxies.")
    return summary


def _apk_entries(path: Path) -> dict[str, int]:
    with zipfile.ZipFile(path) as zf:
        return {info.filename: info.CRC for info in zf.infolist()}


def _apk_dex_strings(path: Path, book: EvidenceBook) -> set[str]:
    out: set[str] = set()
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            if re.fullmatch(r"classes\d*\.dex", name):
                try:
                    out.update(parse_dex_strings(zf.read(name)))
                except ValueError as exc:
                    book.limit(f"{name} could not be parsed for diffing: {exc}")
    return out


def _apk_manifest(path: Path, book: EvidenceBook) -> dict | None:
    with zipfile.ZipFile(path) as zf:
        try:
            return manifest_facts(parse_axml(zf.read("AndroidManifest.xml")))
        except (KeyError, ValueError) as exc:
            book.limit(f"Manifest could not be compared: {exc}")
            return None


def _diff_apks(book, old, new) -> dict:
    old_e, new_e = _apk_entries(old), _apk_entries(new)
    added = sorted(set(new_e) - set(old_e))
    removed = sorted(set(old_e) - set(new_e))
    modified = sorted(n for n in set(old_e) & set(new_e) if old_e[n] != new_e[n])
    summary = {
        "entries_added": _emit(book, "diff-apk", str(new), "entry-added", added, "Archive entry added: {item}")["count"],
        "entries_removed": _emit(book, "diff-apk", str(new), "entry-removed", removed, "Archive entry removed: {item}")["count"],
        "entries_modified": _emit(book, "diff-apk", str(new), "entry-modified", modified, "Archive entry changed (CRC differs): {item}")["count"],
    }
    s_add, s_rm = _set_diff(_apk_dex_strings(old, book), _apk_dex_strings(new, book))
    summary["dex_strings_added"] = _emit(book, "diff-apk", str(new), "dex-string-added", s_add, "Dex string added: {item}")["count"]
    summary["dex_strings_removed"] = _emit(book, "diff-apk", str(new), "dex-string-removed", s_rm, "Dex string removed: {item}")["count"]
    old_m, new_m = _apk_manifest(old, book), _apk_manifest(new, book)
    if old_m is not None and new_m is not None:
        for key in ("debuggable", "allowBackup", "usesCleartextTraffic"):
            if old_m[key] != new_m[key]:
                book.add("diff-apk", "AndroidManifest.xml", "manifest-changed", f"{key}: {old_m[key]} -> {new_m[key]}")
        p_add, p_rm = _set_diff(set(old_m["permissions"]), set(new_m["permissions"]))
        for perm in p_add:
            if perm in SENSITIVE_PERMISSIONS:
                book.add("diff-apk", "AndroidManifest.xml", "manifest-changed", f"Sensitive permission added: {perm}")
        for perm in p_rm:
            book.add("diff-apk", "AndroidManifest.xml", "manifest-changed", f"Permission removed: {perm}")
    return summary
