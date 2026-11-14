"""Route a target to its capabilities, write a cited report, and keep the history organized."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import secrets
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path

from rea import paths
from rea import static_analysis as sa
from rea.config import load_config
from rea.errors import ReaError
from rea.evidence import EvidenceBook
from rea.store import Store

NEEDED_TOOLS = ("file", "strings", "nm", "objdump", "jadx")
INV_ID_RE = re.compile(r"inv-\d{8}-\d{6}-[0-9a-f]{4}")


@dataclass
class InvestigationRecord:
    id: str
    created_at: str
    target: str
    target_kind: str
    target_sha256: str | None
    question: str
    terms: list[str]
    evidence: list[dict] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    report_path: str = ""
    report: str = ""

    def summary(self) -> dict:
        data = asdict(self)
        data.pop("report")
        data.pop("evidence")
        data["evidence_count"] = len(self.evidence)
        return data


def _new_id() -> str:
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"inv-{stamp}-{secrets.token_hex(2)}"


def _check_id(inv_id: str) -> None:
    if not INV_ID_RE.fullmatch(inv_id or ""):
        raise ReaError(f"'{inv_id}' is not a valid investigation id (expected inv-YYYYMMDD-HHMMSS-xxxx).")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_target(path: Path, config: dict, require_allowlist: bool) -> None:
    roots = [Path(r).expanduser().resolve() for r in config.get("allowed_roots", [])]
    if require_allowlist and not roots:
        raise ReaError("No folders are allowed yet. Run `rea setup --allow <folder>` first.")
    if roots and not any(path == root or root in path.parents for root in roots):
        allowed = ", ".join(str(r) for r in roots)
        raise ReaError(f"{path} is outside the allowed folders: {allowed}")


def investigate(
    target: str,
    question: str,
    home: Path | None = None,
    require_allowlist: bool = False,
) -> InvestigationRecord:
    home = home or paths.rea_home()
    question = (question or "").strip()
    if not question:
        raise ReaError("A question is required so REA knows what to look for.")

    raw = Path(target).expanduser()
    if not raw.exists():
        raise ReaError(f"No file or folder at {target}")
    path = raw.resolve()
    if not (path.is_file() or path.is_dir()):
        raise ReaError("The target must be a regular file or a folder.")

    config = load_config(home)
    check_target(path, config, require_allowlist)

    kind = sa.identify(path)
    terms = sa.extract_terms(question)
    tools = {name: shutil.which(name) for name in NEEDED_TOOLS}
    limits = config["limits"]
    book = EvidenceBook()

    if kind in sa.BINARY_KINDS:
        sa.collect_binary(book, path, kind, tools, limits, terms)
    elif kind in sa.JS_KINDS:
        sa.collect_js_tree(book, path, kind, limits, terms)
    elif kind == "android-apk":
        sa.collect_apk(book, path, tools, terms)
    else:
        book.limit(f"No capability handles '{kind}' yet, so only identification ran.")
    if not terms:
        book.limit("The question had no searchable words, so no term searches ran.")

    inv_id = _new_id()
    inv_dir = paths.investigations_dir(home) / inv_id
    inv_dir.mkdir(parents=True, exist_ok=False)
    report_path = inv_dir / "report.md"

    record = InvestigationRecord(
        id=inv_id,
        created_at=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        target=str(path),
        target_kind=kind,
        target_sha256=None if path.is_dir() else _sha256(path),
        question=question,
        terms=terms,
        evidence=[e.to_dict() for e in book.items],
        limitations=list(book.limitations),
        report_path=str(report_path),
    )
    record.report = render_report(record)
    report_path.write_text(record.report, encoding="utf-8")
    (inv_dir / "evidence.json").write_text(
        json.dumps({"id": inv_id, "evidence": record.evidence, "limitations": record.limitations}, indent=2),
        encoding="utf-8",
    )
    with Store(paths.db_file(home)) as store:
        store.save(record)
    return record


def _summary_text(rec: InvestigationRecord) -> str:
    if not rec.terms:
        return "The question had no searchable words, so REA only recorded what the target is."
    hits = [e for e in rec.evidence if e["kind"] in sa.TERM_KINDS]
    joined = ", ".join(rec.terms)
    if hits:
        return (
            f"REA found {len(hits)} lead(s) that mention {joined}. They show where those words appear in the "
            "target, not how the feature works. Read the cited locations to confirm the flow."
        )
    return (
        f"REA found no direct hits for {joined}. Try words the app shows users (button labels, page titles, "
        "error text) or route names."
    )


def render_report(rec: InvestigationRecord) -> str:
    out = [
        f"# Investigation {rec.id}",
        "",
        f"- **Target:** `{rec.target}`",
        f"- **Detected as:** {rec.target_kind}",
        f"- **SHA-256:** {rec.target_sha256 or 'n/a (folder)'}",
        f"- **Question:** {rec.question}",
        f"- **Searched for:** {', '.join(rec.terms) or 'nothing'}",
        f"- **Run at:** {rec.created_at}",
        "",
        "## Summary",
        "",
        _summary_text(rec),
        "",
        "## Evidence",
        "",
    ]
    if not rec.evidence:
        out.append("_No evidence was collected._")
    grouped: dict[str, list[dict]] = {}
    for ev in rec.evidence:
        grouped.setdefault(ev["capability"], []).append(ev)
    for capability, items in grouped.items():
        out += [f"### {capability}", ""]
        for ev in items:
            out.append(f"- **{ev['ref']}** [{ev['confidence']}] {ev['claim']}  ")
            out.append(f"  Source: `{ev['source']}`")
            if ev["excerpt"]:
                out.append(f"  > {ev['excerpt']}")
            out.append("")
    out += ["## Limitations", ""]
    if rec.limitations:
        out += [f"- {text}" for text in rec.limitations]
    else:
        out.append("_None recorded._")
    out += [
        "",
        "## Next steps",
        "",
        "- Open each cited source and read the code around the hit.",
        "- Ask a follow-up with a more specific term, such as a button label, route, or error text.",
        "- Before rebuilding a feature, write down the inputs, outputs, and calls you confirmed in the code.",
        "",
    ]
    return "\n".join(out)


def list_investigations(home: Path | None = None, limit: int = 20) -> list[dict]:
    home = home or paths.rea_home()
    db = paths.db_file(home)
    if not db.is_file():
        return []
    with Store(db) as store:
        return store.recent(limit)


def load_investigation(home: Path | None, inv_id: str) -> dict:
    home = home or paths.rea_home()
    _check_id(inv_id)
    db = paths.db_file(home)
    row = None
    if db.is_file():
        with Store(db) as store:
            row = store.get(inv_id)
    if row is None:
        raise ReaError(f"No investigation named {inv_id}.")
    report = Path(row["report_path"])
    row["report"] = report.read_text(encoding="utf-8") if report.is_file() else "(report file is missing)"
    return row


def delete_investigation(home: Path | None, inv_id: str) -> bool:
    home = home or paths.rea_home()
    _check_id(inv_id)
    base = paths.investigations_dir(home).resolve()
    inv_dir = (base / inv_id).resolve()
    # Only ever remove a folder that sits directly inside the investigations folder.
    if inv_dir.parent == base and inv_dir.exists():
        shutil.rmtree(inv_dir)
    db = paths.db_file(home)
    if not db.is_file():
        return False
    with Store(db) as store:
        return store.delete(inv_id)
