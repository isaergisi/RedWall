"""Human-readable terminal output, in priority order."""

from __future__ import annotations

from typing import List

from ..models import Finding, ScanResult, Severity
from .labels import labels

_COLORS = {
    Severity.CRITICAL: "\033[1;35m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[37m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"


def ordered(findings: List[Finding]) -> List[Finding]:
    """Triage order when available, otherwise severity then location."""
    if findings and all(f.triage is not None for f in findings):
        return sorted(findings, key=lambda f: f.triage.rank)  # type: ignore[union-attr]
    return sorted(findings, key=lambda f: (-f.severity.rank, f.path, f.line))


def render_text(result: ScanResult, color: bool = False, lang: str = "en", brief: bool = False, **_) -> str:
    def c(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    lab = labels(lang)
    lines = []

    def block(f: Finding) -> None:
        sev = c(_COLORS[f.severity], f"{f.severity.value.upper():8}")
        prefix = f"#{f.triage.rank:<3} {f.triage.tier} {f.triage.score:3}  " if f.triage else ""
        lines.append(f"{prefix}{sev} {f.path}:{f.line}:{f.column}  {f.rule_id}  {f.title}")
        lines.append(f"         {f.message} (confidence: {f.confidence.value}{', ' + f.cwe if f.cwe else ''})")
        if f.snippet:
            lines.append(c(_DIM, f"         > {f.snippet}"))
        for step in f.trace:
            lines.append(c(_DIM, f"           line {step.line}: {step.note}"))
        if f.triage and not brief:
            lines.append(f"         {lab['why_open']}:")
            for reason in f.triage.why_open:
                lines.append(f"           - {reason}")
            factors = " ".join(f"{x.points:+d} ({x.reason})" for x in f.triage.factors)
            lines.append(c(_DIM, f"         {lab['score']}: {f.triage.base_score} = {factors}"))
            llm = f.triage.llm
            if llm and llm.get("status") == "ok":
                moved = f", {llm['adjustment']:+d}" if llm.get("adjustment") else ""
                lines.append(f"         LLM: {llm['exploitability']}{moved}: {llm.get('explanation', '')}")
            elif llm:
                lines.append(c(_DIM, f"         LLM: {llm.get('status')}: {llm.get('detail', '')}"))
        lines.append("")

    for f in ordered(result.findings):
        block(f)
    if result.suppressed_findings:
        lines.append(lab["suppressed"] + ":")
        lines.append("")
        for f in ordered(result.suppressed_findings):
            block(f)

    counts = result.counts_by_severity()
    summary = ", ".join(f"{n} {s}" for s, n in reversed(list(counts.items())) if n)
    lines.append(f"Scanned {result.files_scanned} files in {result.duration_s:.2f}s: "
                 f"{len(result.findings)} findings" + (f" ({summary})" if summary else "")
                 + (f", {result.suppressed} suppressed (listed above)" if result.suppressed else "") + ".")
    if result.findings and all(f.triage for f in result.findings):
        tiers = result.counts_by_tier()
        lines.append("Priority: " + ", ".join(f"{n} {t}" for t, n in tiers.items() if n) + f"  [{lab['tiers']}]")
    if result.filtered:
        lines.append(c(_DIM, "note: " + lab["filtered"].format(n=result.filtered)))
    for note in result.notes:
        lines.append(c(_DIM, f"note: {note}"))
    for e in result.engines:
        if e.status != "ok":
            lines.append(c(_DIM, f"note: engine {e.name} {e.status}: {e.detail}"))
    for err in result.errors:
        lines.append(c(_DIM, f"warning: {err}"))
    return "\n".join(lines) + "\n"
