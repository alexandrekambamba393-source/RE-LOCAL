"""Shared fixtures: synthetic APK/dex/AXML builders, fake tool runner, and small project helpers.

The builders write the real binary layouts that rea.apk_format parses, so APK tests need no Android tools.
"""

from __future__ import annotations

import json
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from rea.subproc import CommandResult  # noqa: E402


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


# ---------- Android binary XML ----------

def _string_pool_chunk(strings: list[str]) -> bytes:
    body = bytearray()
    offsets: list[int] = []
    for s in strings:
        offsets.append(len(body))
        body += struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00"
    while len(body) % 4:
        body += b"\x00"
    start = 28 + 4 * len(strings)
    size = start + len(body)
    head = struct.pack("<HHI", 0x0001, 28, size) + struct.pack("<IIIII", len(strings), 0, 0, start, 0)
    return head + b"".join(struct.pack("<I", o) for o in offsets) + bytes(body)


def build_axml(elements: list[tuple[str, list[tuple[str, str, object]]]]) -> bytes:
    """elements: [(element_name, [(attr_name, "str"|"bool", value)])]. Returns Android binary XML bytes."""
    strings: list[str] = []
    index: dict[str, int] = {}

    def intern(s: str) -> int:
        if s not in index:
            index[s] = len(strings)
            strings.append(s)
        return index[s]

    for name, attrs in elements:
        intern(name)
        for aname, kind, value in attrs:
            intern(aname)
            if kind == "str":
                intern(str(value))
    pool = _string_pool_chunk(strings)
    body = b""
    for name, attrs in elements:
        abytes = b""
        for aname, kind, value in attrs:
            if kind == "bool":
                raw, dtype, data = 0xFFFFFFFF, 0x12, (0xFFFFFFFF if value else 0)
            else:
                raw = index[str(value)]
                dtype, data = 0x03, raw
            abytes += struct.pack("<IIIHBBI", 0xFFFFFFFF, index[aname], raw, 8, 0, dtype, data)
        size = 36 + len(abytes)
        chunk = struct.pack("<HHI", 0x0102, 16, size) + struct.pack("<II", 1, 0xFFFFFFFF)
        chunk += struct.pack("<IIHHHHHH", 0xFFFFFFFF, index[name], 20, 20, len(attrs), 0, 0, 0) + abytes
        body += chunk
    total = 8 + len(pool) + len(body)
    return struct.pack("<HHI", 0x0003, 8, total) + pool + body


# ---------- dex ----------

def _uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def build_dex(strings: list[str]) -> bytes:
    header = bytearray(112)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 36, 112)  # header_size
    struct.pack_into("<I", header, 40, 0x12345678)  # endian tag
    count = len(strings)
    ids_off = 112
    data_off = ids_off + 4 * count
    data = bytearray()
    offsets: list[int] = []
    for s in strings:
        offsets.append(data_off + len(data))
        data += _uleb(len(s)) + s.encode("utf-8") + b"\x00"
    struct.pack_into("<I", header, 56, count)
    struct.pack_into("<I", header, 60, ids_off)
    ids = b"".join(struct.pack("<I", o) for o in offsets)
    return bytes(header) + ids + bytes(data)


# ---------- APK ----------

def build_apk(
    path: Path,
    manifest: list[tuple[str, list[tuple[str, str, object]]]],
    dex_strings: list[str],
) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", build_axml(manifest))
        zf.writestr("classes.dex", build_dex(dex_strings))
    return path


# ---------- fake tool runner ----------

class FakeRunner:
    """Stands in for rea.runner.Runner. Answers from a dict keyed by (tool basename, first flag)."""

    def __init__(self, responses: dict[tuple[str, str], str]) -> None:
        self.responses = responses
        self.calls: list[list[str]] = []

    def run(self, argv: list[str]) -> CommandResult:
        self.calls.append(argv)
        key = (Path(argv[0]).name, argv[1] if len(argv) > 1 else "")
        if key in self.responses:
            return CommandResult(True, self.responses[key])
        return CommandResult(False, "", f"not faked: {key}")

    def close(self) -> None:
        pass
