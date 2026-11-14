"""Pipelines for `investigate`, `audit`, and `diff`. Each writes a cited report and records it in history."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import secrets
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path

from relocal import paths
from relocal import sandbox as sandbox_mod
from relocal import static_analysis as sa
from relocal.audit import SEVERITIES, SEVERITY_RANK, audit_apk, audit_js, audit_native, meets_minimum
from relocal.config import load_config
from relocal.diffing import diff_targets
from relocal.errors import RelocalError
from relocal.evidence import EvidenceBook
from relocal.graph import write_graph
from relocal.runner import Runner
from relocal.store import Store

NEEDED_TOOLS = ("file", "strings", "nm", "objdump", "readelf", "rabin2", "rz-bin", "jadx")
INV_ID_RE = re.compile(r"inv-\d{8}-\d{6}-[0-9a-f]{4}")
RUN_LABELS = {"investigate": "Investigation", "audit": "Audit", "diff": "Diff"}


@dataclass
class InvestigationRecord:
    id: str
    created_at: str
    run_type: str
    target: str
    target_kind: str
    target_sha256: str | None
    question: str
    terms: list[str]
    evidence: list[dict] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    report_path: str = ""
    report: str = ""
    summary: str = ""
    graph_files: list[str] = field(default_factory=list)

    def summary_dict(self) -> dict:
        data = asdict(self)
        for key in ("report", "evidence", "findings", "summary"):
            data.pop(key)
        data["evidence_count"] = len(self.evidence)
        data["finding_count"] = len(self.findings)
        return data


def _new_id() -> str:
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"inv-{stamp}-{secrets.token_hex(2)}"


def _check_id(inv_id: str) -> None:
    if not INV_ID_RE.fullmatch(inv_id or ""):
        raise RelocalError(f"'{inv_id}' is not a valid investigation id (expected inv-YYYYMMDD-HHMMSS-xxxx).")


def _sha256(path: Path) -> str | None:
    if path.is_dir():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_target(path: Path, config: dict, require_allowlist: bool) -> None:
    roots = [Path(r).expanduser().resolve() for r in config.get("allowed_roots", [])]
    if require_allowlist and not roots:
        raise RelocalError("No folders are allowed yet. Run `relocal setup --allow <folder>` first.")
    if roots and not any(path == root or root in path.parents for root in roots):
        allowed = ", ".join(str(r) for r in roots)
        raise RelocalError(f"{path} is outside the allowed folders: {allowed}")


def _resolve(target: str, config: dict, require_allowlist: bool) -> Path:
    raw = Path(target).expanduser()
    if not raw.exists():
        raise RelocalError(f"No file or folder at {target}")
    path = raw.resolve()
    if not (path.is_file() or path.is_dir()):
        raise RelocalError("The target must be a regular file or a folder.")
    check_target(path, config, require_allowlist)
    return path


def _tools() -> dict[str, str | None]:
    return {name: shutil.which(name) for name in NEEDED_TOOLS}


def _start(home: Path, config: dict, sandbox_requested: bool) -> tuple[EvidenceBook, Runner]:
    """Create the evidence book and runner. Records a limitation for the sandbox state when it was requested."""
    book = EvidenceBook()
    sb = None
    if sandbox_requested:
        sb = sandbox_mod.detect()
        if sb is not None:
            book.limit(
                f"Sandbox active ({sb.name}): external tools ran with a read-only filesystem, "
                "no network, and a private scratch folder. The target was never executed."
            )
        else:
            book.limit(
                "Sandbox requested but unavailable (no working bubblewrap or firejail). External tools ran "
                "unsandboxed. The target was still never executed."
            )
    limits = config["limits"]
    runner = Runner(
        timeout=limits["command_timeout_seconds"],
        max_bytes=limits["max_output_bytes"],
        sandbox=sb,
        scratch_root=home / "sandbox-scratch",
    )
    return book, runner


def _create(
    home: Path,
    *,
    run_type: str,
    target: str,
    target_kind: str,
    target_sha256: str | None,
    question: str,
    terms: list[str],
    book: EvidenceBook,
    findings: list[dict],
    summary: str,
    export_graph: bool,
) -> InvestigationRecord:
    inv_id = _new_id()
    inv_dir = paths.investigations_dir(home) / inv_id
    inv_dir.mkdir(parents=True, exist_ok=False)
    report_path = inv_dir / "report.md"
    rec = InvestigationRecord(
        id=inv_id,
        created_at=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        run_type=run_type,
        target=target,
        target_kind=target_kind,
        target_sha256=target_sha256,
        question=question,
        terms=terms,
        evidence=[e.to_dict() for e in book.items],
        limitations=list(book.limitations),
        findings=findings,
        report_path=str(report_path),
        summary=summary,
    )
    if export_graph:
        mmd, html_path = write_graph(inv_dir, {"id": inv_id, "target": target, "evidence": rec.evidence, "findings": findings})
        rec.graph_files = [mmd.name, html_path.name]
    rec.report = render_report(rec)
    report_path.write_text(rec.report, encoding="utf-8")
    (inv_dir / "evidence.json").write_text(
        json.dumps({"id": inv_id, "evidence": rec.evidence, "findings": findings, "limitations": rec.limitations}, indent=2),
        encoding="utf-8",
    )
    with Store(paths.db_file(home)) as store:
        store.save(rec)
    return rec


def investigate(
    target: str,
    question: str,
    home: Path | None = None,
    require_allowlist: bool = False,
    sandbox: bool = False,
    export_graph: bool = False,
) -> InvestigationRecord:
    home = home or paths.relocal_home()
    question = (question or "").strip()
    if not question:
        raise RelocalError("A question is required so RE LOCAL knows what to look for.")
    config = load_config(home)
    path = _resolve(target, config, require_allowlist)
    book, runner = _start(home, config, sandbox)
    try:
        kind = sa.identify(path)
        terms = sa.extract_terms(question)
        tools = _tools()
        if kind in sa.BINARY_KINDS:
            sa.collect_binary(book, path, kind, tools, runner, terms)
        elif kind in sa.JS_KINDS:
            sa.collect_js_tree(book, path, kind, config["limits"], terms)
        elif kind == "android-apk":
            sa.collect_apk(book, path, tools, terms)
        else:
            book.limit(f"No capability handles '{kind}' yet, so only identification ran.")
        if not terms:
            book.limit("The question had no searchable words, so no term searches ran.")
    finally:
        runner.close()
    hits = sum(1 for e in book.items if e.kind in sa.TERM_KINDS)
    if not terms:
        summary = "The question had no searchable words, so RE LOCAL only recorded what the target is."
    elif hits:
        summary = (
            f"RE LOCAL found {hits} lead(s) that mention {', '.join(terms)}. They show where those words appear in the "
            "target, not how the feature works. Read the cited locations to confirm the flow."
        )
    else:
        summary = (
            f"RE LOCAL found no direct hits for {', '.join(terms)}. Try words the app shows users (button labels, page "
            "titles, error text) or route names."
        )
    return _create(
        home,
        run_type="investigate",
        target=str(path),
        target_kind=kind,
        target_sha256=_sha256(path),
        question=question,
        terms=terms,
        book=book,
        findings=[],
        summary=summary,
        export_graph=export_graph,
    )


def audit(
    target: str,
    home: Path | None = None,
    require_allowlist: bool = False,
    sandbox: bool = False,
    export_graph: bool = False,
    min_severity: str = "INFO",
) -> InvestigationRecord:
    home = home or paths.relocal_home()
    min_severity = min_severity.upper()
    if min_severity not in SEVERITY_RANK:
        raise RelocalError(f"min_severity must be one of {', '.join(SEVERITIES)}.")
    config = load_config(home)
    path = _resolve(target, config, require_allowlist)
    book, runner = _start(home, config, sandbox)
    try:
        kind = sa.identify(path)
        tools = _tools()
        if kind in sa.BINARY_KINDS:
            found = audit_native(book, path, kind, tools, runner)
        elif kind in sa.JS_KINDS:
            found = audit_js(book, path, config["limits"])
        elif kind == "android-apk":
            found = audit_apk(book, path)
        else:
            found = []
            book.limit(f"No audit rules cover '{kind}' yet.")
    finally:
        runner.close()

    shown = sorted((f for f in found if meets_minimum(f.severity, min_severity)), key=lambda f: SEVERITY_RANK[f.severity])
    counts = {s: sum(1 for f in found if f.severity == s) for s in SEVERITIES}
    if found:
        counts_text = ", ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts[s])
        summary = (
            f"{len(found)} finding(s): {counts_text}. Each one cites evidence. Confirm in code before acting; "
            "these are leads, not proof of exploitability."
        )
    else:
        summary = (
            "No audit rule matched. This does not mean the target is safe. Only the checks listed in "
            "Limitations were run."
        )
    return _create(
        home,
        run_type="audit",
        target=str(path),
        target_kind=kind,
        target_sha256=_sha256(path),
        question=f"Security audit (minimum severity {min_severity})",
        terms=[],
        book=book,
        findings=[f.to_dict() for f in shown],
        summary=summary,
        export_graph=export_graph,
    )


def diff(
    old: str,
    new: str,
    home: Path | None = None,
    require_allowlist: bool = False,
    sandbox: bool = False,
    export_graph: bool = False,
) -> InvestigationRecord:
    home = home or paths.relocal_home()
    config = load_config(home)
    old_path = _resolve(old, config, require_allowlist)
    new_path = _resolve(new, config, require_allowlist)
    old_kind, new_kind = sa.identify(old_path), sa.identify(new_path)
    book, runner = _start(home, config, sandbox)
    try:
        changes = diff_targets(book, old_path, new_path, old_kind, new_kind, _tools(), runner, config["limits"])
    finally:
        runner.close()
    nonzero = {k: v for k, v in changes.items() if isinstance(v, int) and v}
    if changes.get("identical"):
        summary = "The two versions are byte-identical (same SHA-256)."
    elif nonzero:
        summary = "Changes found: " + ", ".join(f"{k.replace('_', ' ')}={v}" for k, v in nonzero.items()) + "."
    else:
        summary = "No differences found in the compared surfaces."
    return _create(
        home,
        run_type="diff",
        target=f"{old_path} -> {new_path}",
        target_kind=new_kind,
        target_sha256=None,
        question=f"Diff {old_path.name} -> {new_path.name}",
        terms=[],
        book=book,
        findings=[],
        summary=summary,
        export_graph=export_graph,
    )


def render_report(rec: InvestigationRecord) -> str:
    out = [
        f"# {RUN_LABELS.get(rec.run_type, 'Run')} {rec.id}",
        "",
        f"- **Target:** `{rec.target}`",
        f"- **Detected as:** {rec.target_kind}",
        f"- **SHA-256:** {rec.target_sha256 or 'n/a'}",
        f"- **Question:** {rec.question}",
    ]
    if rec.terms:
        out.append(f"- **Searched for:** {', '.join(rec.terms)}")
    out += [f"- **Run at:** {rec.created_at}", "", "## Summary", "", rec.summary, ""]

    if rec.run_type == "audit":
        out += ["## Findings", ""]
        if not rec.findings:
            out.append("_No findings at or above the chosen minimum severity._")
            out.append("")
        for f in rec.findings:
            refs = ", ".join(f["refs"]) or "no evidence ref"
            out.append(f"- **{f['severity']}** `{f['rule_id']}` {f['title']}  ")
            out.append(f"  Evidence: {refs} · Source: `{f['source']}`")
            if f.get("detail"):
                out.append(f"  {f['detail']}")
            out.append("")

    out += ["## Evidence", ""]
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

    if rec.graph_files:
        out += ["", "## Graph", "", f"Open `{rec.graph_files[1]}` in a browser. Mermaid source: `{rec.graph_files[0]}`."]

    out += [
        "",
        "## Next steps",
        "",
        "- Open each cited source and read the code around the hit.",
        "- Before rebuilding a feature, write down the inputs, outputs, and calls you confirmed in the code.",
        "",
    ]
    return "\n".join(out)


def list_investigations(home: Path | None = None, limit: int = 20) -> list[dict]:
    home = home or paths.relocal_home()
    db = paths.db_file(home)
    if not db.is_file():
        return []
    with Store(db) as store:
        return store.recent(limit)


def load_investigation(home: Path | None, inv_id: str) -> dict:
    home = home or paths.relocal_home()
    _check_id(inv_id)
    db = paths.db_file(home)
    row = None
    if db.is_file():
        with Store(db) as store:
            row = store.get(inv_id)
    if row is None:
        raise RelocalError(f"No investigation named {inv_id}.")
    report = Path(row["report_path"])
    row["report"] = report.read_text(encoding="utf-8") if report.is_file() else "(report file is missing)"
    return row


def export_graph_for(home: Path | None, inv_id: str) -> tuple[Path, Path]:
    """Regenerate graph.mmd and graph.html for a stored investigation."""
    row = load_investigation(home, inv_id)
    inv_dir = Path(row["report_path"]).parent
    return write_graph(inv_dir, {"id": inv_id, "target": row["target"], "evidence": row["evidence"], "findings": row["findings"]})


def delete_investigation(home: Path | None, inv_id: str) -> bool:
    home = home or paths.relocal_home()
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
