"""Core data types shared by every engine and reporter.

A ``Finding`` is a *candidate*: the fast, deterministic engines (stage 1 of the
RedWall funnel) produce them, and later stages (LLM verification, proof) only
change ``status`` and add evidence. Findings are never silently dropped.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls(value.lower())
        except ValueError as exc:
            choices = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {value!r} (choose from: {choices})") from exc


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2}[self.value]


class Status(str, Enum):
    """Where a finding is in the funnel. Stage 1 only emits ``candidate``."""

    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"  # verified by the panel (phase 2)
    PROVEN = "proven"  # reproduced in the sandbox (phase 3)
    DEPRIORITIZED = "deprioritized"  # panel doubts it; kept, never deleted


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    cwe: Optional[str]
    description: str
    engine: str
    languages: tuple = ()
    remediation: str = ""
    references: tuple = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "cwe": self.cwe,
            "description": self.description,
            "engine": self.engine,
            "languages": list(self.languages),
            "remediation": self.remediation,
            "references": list(self.references),
        }


@dataclass(frozen=True)
class TraceStep:
    """One hop of a data-flow trace (source -> ... -> sink)."""

    line: int
    note: str

    def to_dict(self) -> Dict[str, Any]:
        return {"line": self.line, "note": self.note}


@dataclass
class Finding:
    rule_id: str
    title: str
    message: str
    severity: Severity
    confidence: Confidence
    path: str  # POSIX path relative to the scan root
    line: int
    column: int = 1
    end_line: Optional[int] = None
    snippet: str = ""
    cwe: Optional[str] = None
    engine: str = ""
    function: Optional[str] = None  # enclosing function, used for grouping and fingerprints
    status: Status = Status.CANDIDATE
    trace: List[TraceStep] = field(default_factory=list)
    fingerprint: str = ""

    def sort_key(self):
        return (self.path, self.line, self.column, self.rule_id, self.message)

    def compute_fingerprint(self, occurrence: int = 0) -> str:
        """Stable id that survives unrelated edits that only shift line numbers.

        Built from the rule, the file, the enclosing function and the
        whitespace-normalised source line, plus an occurrence counter for
        identical lines in the same function.
        """
        normalized = " ".join(self.snippet.split())
        raw = f"{self.rule_id}\x00{self.path}\x00{self.function or ''}\x00{normalized}\x00{occurrence}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "title": self.title,
            "message": self.message,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "status": self.status.value,
            "cwe": self.cwe,
            "engine": self.engine,
            "function": self.function,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line or self.line,
            "snippet": self.snippet,
            "trace": [step.to_dict() for step in self.trace],
        }


@dataclass
class EngineRun:
    name: str
    status: str  # "ok" | "skipped" | "error"
    detail: str = ""
    files: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "status": self.status, "detail": self.detail, "files": self.files}


@dataclass
class ScanResult:
    root: str
    findings: List[Finding]
    engines: List[EngineRun]
    files_scanned: int
    suppressed: int = 0
    errors: List[str] = field(default_factory=list)
    duration_s: float = 0.0  # never written to machine-readable output (determinism)

    def counts_by_severity(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts
