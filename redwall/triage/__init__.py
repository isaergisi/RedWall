"""Stage 2: order every finding by risk and explain why it is still open.

``prioritize()`` is deterministic and needs only the standard library. The
optional LLM layer (``redwall.triage.llm``) can add an advisory note and move a
finding by a few points, but it can never remove, hide or re-status one.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from ..engines import all_rules
from ..models import Finding, ScanResult, Triage
from . import explain, scoring

__all__ = ["prioritize", "rank", "LANGS"]
LANGS = explain.LANGS


def _remediations() -> Dict[str, str]:
    return {r.id: r.remediation for r in all_rules()}


def triage_finding(f: Finding, lang: str = "en", remediation: Optional[Dict[str, str]] = None) -> Triage:
    s = scoring.score(f)
    rem = (remediation if remediation is not None else _remediations()).get(f.rule_id, "")
    return Triage(
        rank=0,
        score=s.total,
        tier=scoring.tier_of(s.total),
        base_score=s.total,
        factors=explain.factor_texts(s, f, lang),
        why_open=explain.why_open(f, s, lang),
        how_to_close=rem,
    )


def rank(findings: List[Finding]) -> List[Finding]:
    """Sort by current triage score (highest first) and number the ranks 1..N. Deterministic."""
    ordered = sorted(findings, key=lambda f: scoring.sort_key(f, f.triage.score if f.triage else 0))
    for i, f in enumerate(ordered, 1):
        if f.triage is not None:
            f.triage.rank = i
    return ordered


def prioritize(result: ScanResult, lang: str = "en") -> ScanResult:
    """Attach a ``Triage`` to every finding (open and suppressed) and order them by risk.

    The number of findings never changes: this is checked, not assumed.
    """
    rem = _remediations()
    before = len(result.findings), len(result.suppressed_findings)
    for f in result.findings + result.suppressed_findings:
        f.triage = triage_finding(f, lang, rem)
    result.findings = rank(result.findings)
    result.suppressed_findings = rank(result.suppressed_findings)
    if (len(result.findings), len(result.suppressed_findings)) != before:  # pragma: no cover - invariant
        raise AssertionError("triage must never add or drop findings")
    return result
