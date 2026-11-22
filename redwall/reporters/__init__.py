"""Output formats. Machine formats are deterministic (no timings, sorted)."""

from __future__ import annotations

from typing import Callable, Dict

from ..models import ScanResult
from .jsonfmt import render_json, render_jsonl
from .markdown import render_markdown
from .sarif import render_sarif
from .text import render_text

RENDERERS: Dict[str, Callable[..., str]] = {
    "text": render_text,
    "json": render_json,
    "jsonl": render_jsonl,
    "sarif": render_sarif,
    "markdown": render_markdown,
}
FORMATS = tuple(RENDERERS)


def render(result: ScanResult, fmt: str, **kwargs) -> str:
    try:
        renderer = RENDERERS[fmt]
    except KeyError:
        raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}") from None
    return renderer(result, **kwargs)
