"""Native binary helpers: protection checks (readelf/objdump), import reading (nm), and radare2/rizin extraction.

Each run_* function takes a Runner and an absolute path, and uses fixed argv lists. Each parse_* function is
pure text in, data out, so it can be tested without real binaries.
"""

from __future__ import annotations

import json
import re

from rea.runner import Runner

# Unsafe C functions. Import-level finding only: a name in the import table means the program can call it.
DANGEROUS_FUNCS = {
    "gets": "HIGH",       # removed from C11; cannot be used safely
    "strcpy": "MEDIUM",
    "strcat": "MEDIUM",
    "sprintf": "MEDIUM",
    "vsprintf": "MEDIUM",
}


# ---------- ELF ----------

def parse_elf_protections(header: str, program: str, dynamic: str, dynsyms: str) -> dict:
    pie = "Position-Independent Executable" in header
    nx: bool | None = None
    for line in program.splitlines():
        if line.lstrip().startswith("GNU_STACK"):
            flags = next((tok for tok in line.split() if re.fullmatch(r"[RWE]+", tok)), "")
            nx = "E" not in flags
    has_relro = any(line.lstrip().startswith("GNU_RELRO") for line in program.splitlines())
    bind_now = bool(re.search(r"BIND_NOW|\bNOW\b", dynamic))
    if has_relro and bind_now:
        relro = "full"
    elif has_relro:
        relro = "partial"
    else:
        relro = "none"
    canary = "__stack_chk_fail" in dynsyms
    return {"format": "elf", "pie": pie, "nx": nx, "relro": relro, "canary": canary}


def run_elf_protections(runner: Runner, readelf: str, path: str) -> dict:
    header = runner.run([readelf, "-h", "-W", path])
    program = runner.run([readelf, "-l", "-W", path])
    dynamic = runner.run([readelf, "-d", "-W", path])
    dynsyms = runner.run([readelf, "--dyn-syms", "-W", path])
    if not header.ok:
        return {"format": "elf", "error": header.error}
    return parse_elf_protections(header.stdout, program.stdout, dynamic.stdout, dynsyms.stdout)


# ---------- PE ----------

def parse_pe_protections(objdump_headers: str) -> dict:
    return {
        "format": "pe",
        "aslr": "DYNAMIC_BASE" in objdump_headers,
        "nx": "NX_COMPAT" in objdump_headers,
    }


def run_pe_protections(runner: Runner, objdump: str, path: str) -> dict:
    res = runner.run([objdump, "-p", path])
    if not res.ok:
        return {"format": "pe", "error": res.error}
    return parse_pe_protections(res.stdout)


# ---------- imports ----------

def parse_nm_undefined(text: str) -> set[str]:
    names: set[str] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-2] == "U":
            names.add(parts[-1].split("@")[0])
    return names


def run_nm_undefined(runner: Runner, nm: str, path: str, dynamic: bool) -> set[str]:
    argv = [nm, "-D", path] if dynamic else [nm, path]
    res = runner.run(argv)
    return parse_nm_undefined(res.stdout) if res.ok else set()


def dangerous_imports(imports: set[str]) -> list[tuple[str, str]]:
    return [(name, DANGEROUS_FUNCS[name]) for name in sorted(imports) if name in DANGEROUS_FUNCS]


# ---------- radare2 / rizin (JSON) ----------

def parse_bin_json(text: str, key: str) -> list[str]:
    """Pull `name` fields from a rabin2/rz-bin JSON list such as {"imports":[{"name":"puts"}]}."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict) or not isinstance(data.get(key), list):
        return []
    names: list[str] = []
    for item in data[key]:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            names.append(item["name"])
    return names


def run_bin_tool_extract(runner: Runner, tool_name: str, tool_path: str, path: str) -> dict:
    """Run one radare2 (rabin2) or rizin (rz-bin) family tool in read-only JSON mode."""
    result: dict = {"tool": tool_name, "imports": [], "exports": [], "sections": []}
    for flag, key, field in (("-i", "imports", "imports"), ("-E", "exports", "exports"), ("-S", "sections", "sections")):
        res = runner.run([tool_path, "-j", flag, path])
        if res.ok:
            result[field] = parse_bin_json(res.stdout, key)
        else:
            result.setdefault("errors", []).append(f"{tool_name} {flag}: {res.error}")
    return result
