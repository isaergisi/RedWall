"""Human-readable terminal output."""

from __future__ import annotations

from ..models import ScanResult, Severity

_COLORS = {
    Severity.CRITICAL: "\033[1;35m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[37m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"


def render_text(result: ScanResult, color: bool = False, **_) -> str:
    def c(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    lines = []
    for f in sorted(result.findings, key=lambda f: (-f.severity.rank, f.path, f.line)):
        sev = c(_COLORS[f.severity], f"{f.severity.value.upper():8}")
        lines.append(f"{sev} {f.path}:{f.line}:{f.column}  {f.rule_id}  {f.title}")
        lines.append(f"         {f.message} (confidence: {f.confidence.value}{', ' + f.cwe if f.cwe else ''})")
        if f.snippet:
            lines.append(c(_DIM, f"         > {f.snippet}"))
        for step in f.trace:
            lines.append(c(_DIM, f"           line {step.line}: {step.note}"))
        lines.append("")

    counts = result.counts_by_severity()
    summary = ", ".join(f"{n} {s}" for s, n in reversed(list(counts.items())) if n)
    lines.append(f"Scanned {result.files_scanned} files in {result.duration_s:.2f}s: "
                 f"{len(result.findings)} findings" + (f" ({summary})" if summary else "")
                 + (f", {result.suppressed} suppressed" if result.suppressed else "") + ".")
    for e in result.engines:
        if e.status != "ok":
            lines.append(c(_DIM, f"note: engine {e.name} {e.status}: {e.detail}"))
    for err in result.errors:
        lines.append(c(_DIM, f"warning: {err}"))
    return "\n".join(lines) + "\n"
