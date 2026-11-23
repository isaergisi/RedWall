from __future__ import annotations

import json

from .. import __version__
from ..models import ScanResult


def _summary(result: ScanResult) -> dict:
    return {
        "files_scanned": result.files_scanned,
        "findings": len(result.findings),
        "suppressed": result.suppressed,
        "by_severity": result.counts_by_severity(),
    }


def render_json(result: ScanResult, **_) -> str:
    doc = {
        "tool": {"name": "redwall", "version": __version__},
        "summary": _summary(result),
        "engines": [e.to_dict() for e in result.engines],
        "errors": result.errors,
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def render_jsonl(result: ScanResult, **_) -> str:
    """One finding per line: easy to diff, grep and stream into later stages."""
    return "".join(json.dumps(f.to_dict(), ensure_ascii=False, sort_keys=True) + "\n" for f in result.findings)
