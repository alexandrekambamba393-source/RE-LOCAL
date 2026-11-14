"""Evidence records. Every claim REA reports must point at something it actually observed."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass
class Evidence:
    ref: str
    capability: str
    source: str
    kind: str
    claim: str
    excerpt: str = ""
    confidence: str = "observed"  # "observed" = seen in the target; "inferred" = a candidate to verify

    def to_dict(self) -> dict:
        return asdict(self)


class EvidenceBook:
    def __init__(self) -> None:
        self.items: list[Evidence] = []
        self.limitations: list[str] = []

    def add(
        self,
        capability: str,
        source: str,
        kind: str,
        claim: str,
        excerpt: str = "",
        confidence: str = "observed",
    ) -> Evidence:
        ev = Evidence(
            ref=f"E{len(self.items) + 1}",
            capability=capability,
            source=source,
            kind=kind,
            claim=claim,
            excerpt=excerpt,
            confidence=confidence,
        )
        self.items.append(ev)
        return ev

    def limit(self, text: str) -> None:
        if text not in self.limitations:
            self.limitations.append(text)
