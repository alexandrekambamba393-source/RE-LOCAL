"""Parse the two binary formats inside an APK, using only the standard library:

- classes*.dex: the string table (every string constant in the app's bytecode)
- AndroidManifest.xml: Android binary XML (AXML), for the attributes that matter to security review

Parsers raise ValueError on malformed input. Callers catch it and report a limitation instead of crashing.
"""

from __future__ import annotations

import re
import struct

RES_XML_TYPE = 0x0003
RES_STRING_POOL = 0x0001
RES_XML_START_ELEMENT = 0x0102
TYPE_STRING = 0x03
TYPE_INT_BOOLEAN = 0x12
MAX_DEX_STRINGS = 200_000


def _uleb128(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if pos >= len(data) or shift > 28:
            raise ValueError("malformed uleb128")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def parse_dex_strings(data: bytes) -> list[str]:
    if data[:4] != b"dex\n":
        raise ValueError("not a dex file")
    try:
        count, table = struct.unpack_from("<II", data, 56)
        if count > MAX_DEX_STRINGS:
            raise ValueError("string table too large")
        out: list[str] = []
        for i in range(count):
            (offset,) = struct.unpack_from("<I", data, table + 4 * i)
            _length, pos = _uleb128(data, offset)
            end = data.index(b"\x00", pos)
            out.append(data[pos:end].decode("utf-8", errors="replace"))
        return out
    except (struct.error, ValueError) as exc:
        raise ValueError(f"malformed dex string table: {exc}") from exc


def _string_pool(data: bytes, pos: int) -> list[str]:
    header = struct.unpack_from("<H", data, pos + 2)[0]
    count, _styles, flags, strings_start = struct.unpack_from("<IIII", data, pos + 8)
    utf8 = bool(flags & 0x100)
    base = pos + strings_start
    pool: list[str] = []
    for i in range(count):
        (offset,) = struct.unpack_from("<I", data, pos + header + 4 * i)
        p = base + offset
        if utf8:
            if data[p] & 0x80:
                p += 2
            else:
                p += 1
            nbytes = data[p]
            p += 1
            if nbytes & 0x80:
                nbytes = ((nbytes & 0x7F) << 8) | data[p]
                p += 1
            pool.append(data[p : p + nbytes].decode("utf-8", errors="replace"))
        else:
            (length,) = struct.unpack_from("<H", data, p)
            p += 2
            if length & 0x8000:
                (low,) = struct.unpack_from("<H", data, p)
                length = ((length & 0x7FFF) << 16) | low
                p += 2
            pool.append(data[p : p + 2 * length].decode("utf-16-le", errors="replace"))
    return pool


def parse_axml(data: bytes) -> list[dict]:
    """Return start elements as {"name": str, "attrs": {attr_name: value}}."""
    if len(data) < 8:
        raise ValueError("truncated XML")
    magic, header_size, total = struct.unpack_from("<HHI", data, 0)
    if magic != RES_XML_TYPE:
        raise ValueError("not Android binary XML")
    pool: list[str] = []
    elements: list[dict] = []
    pos = header_size
    end = min(len(data), total)
    try:
        while pos + 8 <= end:
            ctype, _hsize, csize = struct.unpack_from("<HHI", data, pos)
            if csize < 8:
                break
            if ctype == RES_STRING_POOL:
                pool = _string_pool(data, pos)
            elif ctype == RES_XML_START_ELEMENT:
                elements.append(_start_element(data, pos, pool))
            pos += csize
    except (struct.error, IndexError) as exc:
        raise ValueError(f"malformed binary XML: {exc}") from exc
    return elements


def _name(pool: list[str], index: int) -> str:
    return pool[index] if 0 <= index < len(pool) else ""


def _start_element(data: bytes, pos: int, pool: list[str]) -> dict:
    _ns, name_idx, attr_start, attr_size, attr_count = struct.unpack_from("<IIHHH", data, pos + 16)
    attrs: dict[str, str] = {}
    base = pos + 16 + attr_start
    for i in range(attr_count):
        a = base + i * attr_size
        _ans, aname, raw, _tsize, _res, dtype, value = struct.unpack_from("<IIIHBBI", data, a)
        key = _name(pool, aname)
        if dtype == TYPE_STRING:
            attrs[key] = _name(pool, raw if raw != 0xFFFFFFFF else value)
        elif dtype == TYPE_INT_BOOLEAN:
            attrs[key] = "true" if value else "false"
        else:
            attrs[key] = str(value)
    return {"name": _name(pool, name_idx), "attrs": attrs}


def manifest_facts(elements: list[dict]) -> dict:
    facts: dict = {"debuggable": None, "allowBackup": None, "usesCleartextTraffic": None, "permissions": []}
    for el in elements:
        attrs = el["attrs"]
        if el["name"] == "application":
            for key in ("debuggable", "allowBackup", "usesCleartextTraffic"):
                if key in attrs:
                    facts[key] = attrs[key] == "true"
        elif el["name"] == "uses-permission":
            perm = attrs.get("name", "")
            if perm:
                facts["permissions"].append(perm)
    return facts


SENSITIVE_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
}

HTTP_URL_RE = re.compile(r"http://[^\s\"'<>]{3,200}")
LOCAL_OR_SCHEMA_RE = re.compile(r"http://(localhost|127\.0\.0\.1|10\.0\.2\.2|schemas\.android\.com|www\.w3\.org|schemas\.xmlsoap\.org)")


def cleartext_urls(strings: list[str]) -> list[str]:
    urls: list[str] = []
    for s in strings:
        for m in HTTP_URL_RE.finditer(s):
            url = m.group(0)
            if not LOCAL_OR_SCHEMA_RE.match(url) and url not in urls:
                urls.append(url)
    return urls
