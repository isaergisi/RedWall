from __future__ import annotations

import json

from .. import __version__
from ..models import ScanResult


def _summary(result: ScanResult) -> dict:
    out = {
        "files_scanned": result.files_scanned,
        "findings": len(result.findings),
        "suppressed": result.suppressed,
        "filtered_by_options": result.filtered,
        "by_severity": result.counts_by_severity(),
    }
    if any(f.triage for f in result.findings):
        out["by_priority"] = result.counts_by_tier()
    return out


def render_json(result: ScanResult, **_) -> str:
    doc = {
        "tool": {"name": "redwall", "version": __version__},
        "summary": _summary(result),
        "engines": [e.to_dict() for e in result.engines],
        "errors": result.errors,
        "notes": result.notes,
        "findings": [f.to_dict() for f in result.findings],
        "suppressed_findings": [f.to_dict() for f in result.suppressed_findings],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def render_jsonl(result: ScanResult, **_) -> str:
    """One finding per line (open ones first, then suppressed): easy to diff, grep and stream."""
    rows = result.findings + result.suppressed_findings
    return "".join(json.dumps(f.to_dict(), ensure_ascii=False, sort_keys=True) + "\n" for f in rows)
