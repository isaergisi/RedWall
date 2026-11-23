"""Markdown report, meant to be committed under .redwall/ or posted on a PR."""

from __future__ import annotations

from typing import List

from .. import __version__
from ..models import Finding, ScanResult, Severity
from .labels import labels
from .text import ordered


def _esc(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _details(f: Finding, lab: dict, out: List[str]) -> None:
    out.append("")
    head = f"{f.triage.rank}. " if f.triage else ""
    out.append(f"### {head}{f.title} · `{f.path}:{f.line}`")
    out.append("")
    meta = []
    if f.triage:
        meta.append(f"**{f.triage.tier}** (score {f.triage.score})")
    meta += [f"**{f.severity.value}**", f"confidence {f.confidence.value}", f"`{f.rule_id}`"]
    if f.cwe:
        meta.append(f.cwe)
    meta.append(f"status `{f.status.value}`")
    meta.append(f"id `{f.fingerprint}`")
    out.append(" · ".join(meta))
    out.append("")
    out.append(f.message)
    if f.snippet:
        out.extend(["", "```", f.snippet, "```"])
    if f.trace:
        out.extend(["", f"{lab['data_flow']}:", ""])
        for i, step in enumerate(f.trace, 1):
            out.append(f"{i}. line {step.line}: {step.note}")
    t = f.triage
    if t is None:
        return
    out.extend(["", f"**{lab['why_open']}:**", ""])
    out.extend(f"- {reason}" for reason in t.why_open)
    factors = " ".join(f"{x.points:+d} ({x.reason})" for x in t.factors)
    out.extend(["", f"**{lab['score']}:** {t.base_score} = {factors}"
                + (f" → {t.score} after LLM" if t.score != t.base_score else "")])
    if t.how_to_close:
        out.extend(["", f"**{lab['how_to_close']}:** {t.how_to_close}"])
    if t.llm:
        out.extend(["", f"**{lab['llm']}:** `{t.llm.get('model', '')}`", ""])
        if t.llm.get("status") == "ok":
            out.append(f"- {lab['llm_verdict']}: **{t.llm['exploitability']}**"
                       + (f" ({t.llm['adjustment']:+d})" if t.llm.get("adjustment") else ""))
            if t.llm.get("evidence_lines"):
                out.append(f"- {lab['llm_evidence']}: {', '.join(map(str, t.llm['evidence_lines']))}")
            if t.llm.get("explanation"):
                out.append(f"- {t.llm['explanation']}")
            if t.llm.get("attack_scenario"):
                out.append(f"- {lab['llm_scenario']}: {t.llm['attack_scenario']}")
            if t.llm.get("fix"):
                out.append(f"- {lab['llm_fix']}: {t.llm['fix']}")
            if t.llm.get("detail"):
                out.append(f"- note: {t.llm['detail']}")
        else:
            out.append(f"- {t.llm.get('status')}: {t.llm.get('detail', '')}")


def render_markdown(result: ScanResult, lang: str = "en", **_) -> str:
    lab = labels(lang)
    counts = result.counts_by_severity()
    out = ["# RedWall report", ""]
    out.append(f"RedWall {__version__} scanned **{result.files_scanned}** files and found "
               f"**{len(result.findings)}** open candidate findings"
               + (f" plus **{result.suppressed}** suppressed inline." if result.suppressed else "."))
    out.append("")
    out.append("| Critical | High | Medium | Low | Info |")
    out.append("|---:|---:|---:|---:|---:|")
    out.append("| " + " | ".join(str(counts[s.value]) for s in reversed(list(Severity))) + " |")
    out.append("")
    triaged = bool(result.findings) and all(f.triage for f in result.findings)
    if triaged:
        tiers = result.counts_by_tier()
        out.append("| P1 | P2 | P3 | P4 |")
        out.append("|---:|---:|---:|---:|")
        out.append("| " + " | ".join(str(tiers[t]) for t in ("P1", "P2", "P3", "P4")) + " |")
        out.append("")
        out.append(f"_{lab['tiers']}_")
        out.append("")
        out.append(lab["nothing_hidden"])
        out.append("")
    if result.filtered:
        out.append("> **Note:** " + lab["filtered"].format(n=result.filtered))
        out.append("")
    for note in result.notes:
        out.append(f"> **Note:** {_esc(note)}")
        out.append("")
    skipped = [e for e in result.engines if e.status != "ok"]
    if skipped:
        out.append("> **Note:** " + "; ".join(f"`{e.name}` {e.status}: {e.detail}" for e in skipped))
        out.append("")
    if not result.findings and not result.suppressed_findings:
        out.append("No findings.")
        return "\n".join(out) + "\n"

    if result.findings:
        out.append(f"## {lab['priority_order'] if triaged else 'Findings'}")
        out.append("")
        if triaged:
            out.append("| # | Priority | Score | Severity | Rule | Location | Confidence | Message |")
            out.append("|---:|---|---:|---|---|---|---|---|")
        else:
            out.append("| Severity | Rule | Location | Confidence | Message |")
            out.append("|---|---|---|---|---|")
        for f in ordered(result.findings):
            row = (f"| {f.severity.value} | `{f.rule_id}` | `{f.path}:{f.line}` | {f.confidence.value} "
                   f"| {_esc(f.message)} |")
            if triaged:
                row = f"| {f.triage.rank} | {f.triage.tier} | {f.triage.score} " + row  # type: ignore[union-attr]
            out.append(row)
        out.append("")
        out.append("## Details")
        for f in ordered(result.findings):
            _details(f, lab, out)
    if result.suppressed_findings:
        out.extend(["", f"## {lab['suppressed']}"])
        for f in ordered(result.suppressed_findings):
            _details(f, lab, out)
    if result.errors:
        out.extend(["", "## Errors", ""])
        out.extend(f"- {_esc(e)}" for e in result.errors)
    return "\n".join(out) + "\n"
