"""SQLite history. One row per investigation, plus its evidence rows. Reports live on disk next to it."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    target TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_sha256 TEXT,
    question TEXT NOT NULL,
    terms TEXT NOT NULL,
    evidence_count INTEGER NOT NULL,
    limitations TEXT NOT NULL,
    report_path TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    ref TEXT NOT NULL,
    capability TEXT NOT NULL,
    source TEXT NOT NULL,
    kind TEXT NOT NULL,
    claim TEXT NOT NULL,
    excerpt TEXT NOT NULL,
    confidence TEXT NOT NULL,
    PRIMARY KEY (investigation_id, ref)
);
"""


class Store:
    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        """Add columns introduced after the first release. Older databases keep working."""
        existing = {row[1] for row in self.conn.execute("PRAGMA table_info(investigations)")}
        if "run_type" not in existing:
            self.conn.execute("ALTER TABLE investigations ADD COLUMN run_type TEXT NOT NULL DEFAULT 'investigate'")
        if "findings" not in existing:
            self.conn.execute("ALTER TABLE investigations ADD COLUMN findings TEXT NOT NULL DEFAULT '[]'")
        self.conn.commit()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self.conn.close()

    def save(self, rec) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO investigations (id, created_at, target, target_kind, target_sha256, question, "
                "terms, evidence_count, limitations, report_path, run_type, findings) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    rec.id,
                    rec.created_at,
                    rec.target,
                    rec.target_kind,
                    rec.target_sha256,
                    rec.question,
                    json.dumps(rec.terms),
                    len(rec.evidence),
                    json.dumps(rec.limitations),
                    rec.report_path,
                    rec.run_type,
                    json.dumps(rec.findings),
                ),
            )
            self.conn.executemany(
                "INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?)",
                [
                    (rec.id, e["ref"], e["capability"], e["source"], e["kind"], e["claim"], e["excerpt"], e["confidence"])
                    for e in rec.evidence
                ],
            )

    def recent(self, limit: int = 20) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, created_at, target, target_kind, run_type, question, evidence_count FROM investigations "
            "ORDER BY created_at DESC, id DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in rows]

    def get(self, inv_id: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM investigations WHERE id = ?", (inv_id,)).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["terms"] = json.loads(data["terms"])
        data["limitations"] = json.loads(data["limitations"])
        data["findings"] = json.loads(data["findings"])
        data["evidence"] = [
            dict(r)
            for r in self.conn.execute(
                "SELECT ref, capability, source, kind, claim, excerpt, confidence FROM evidence "
                "WHERE investigation_id = ? ORDER BY length(ref), ref",
                (inv_id,),
            )
        ]
        return data

    def delete(self, inv_id: str) -> bool:
        with self.conn:
            cur = self.conn.execute("DELETE FROM investigations WHERE id = ?", (inv_id,))
        return cur.rowcount > 0

    def count(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM investigations").fetchone()[0])
