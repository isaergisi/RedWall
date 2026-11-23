"""Markdown report, meant to be committed under .redwall/ or posted on a PR."""

from __future__ import annotations

from .. import __version__
from ..models import ScanResult, Severity


def _esc(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(result: ScanResult, **_) -> str:
    counts = result.counts_by_severity()
    out = ["# RedWall report", ""]
    out.append(f"RedWall {__version__} scanned **{result.files_scanned}** files and found "
               f"**{len(result.findings)}** candidate findings"
               + (f" ({result.suppressed} suppressed inline)." if result.suppressed else "."))
    out.append("")
    out.append("| Critical | High | Medium | Low | Info |")
    out.append("|---:|---:|---:|---:|---:|")
    out.append("| " + " | ".join(str(counts[s.value]) for s in reversed(list(Severity))) + " |")
    out.append("")
    skipped = [e for e in result.engines if e.status != "ok"]
    if skipped:
        out.append("> **Note:** " + "; ".join(f"`{e.name}` {e.status}: {e.detail}" for e in skipped))
        out.append("")
    if not result.findings:
        out.append("No findings.")
        return "\n".join(out) + "\n"

    out.append("## Findings")
    out.append("")
    out.append("| Severity | Rule | Location | Confidence | Message |")
    out.append("|---|---|---|---|---|")
    ordered = sorted(result.findings, key=lambda f: (-f.severity.rank, f.path, f.line))
    for f in ordered:
        out.append(f"| {f.severity.value} | `{f.rule_id}` | `{f.path}:{f.line}` | {f.confidence.value} | {_esc(f.message)} |")
    out.append("")
    out.append("## Details")
    for f in ordered:
        out.append("")
        out.append(f"### {f.title} · `{f.path}:{f.line}`")
        out.append("")
        meta = [f"**{f.severity.value}**", f"confidence {f.confidence.value}", f"`{f.rule_id}`"]
        if f.cwe:
            meta.append(f.cwe)
        out.append(" · ".join(meta))
        out.append("")
        out.append(f.message)
        if f.snippet:
            out.extend(["", "```", f.snippet, "```"])
        if f.trace:
            out.append("")
            out.append("Data flow:")
            out.append("")
            for i, step in enumerate(f.trace, 1):
                out.append(f"{i}. line {step.line}: {step.note}")
    if result.errors:
        out.extend(["", "## Errors", ""])
        out.extend(f"- {_esc(e)}" for e in result.errors)
    return "\n".join(out) + "\n"
