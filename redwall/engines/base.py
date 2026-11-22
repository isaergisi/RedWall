"""Engine interface. Every scanner in stage 1 of the funnel implements this."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from ..models import Finding, Rule

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}


@dataclass
class SourceFile:
    abs_path: Path
    rel_path: str  # POSIX, relative to the scan root
    language: Optional[str]
    _text: Optional[str] = field(default=None, repr=False)

    @property
    def text(self) -> str:
        if self._text is None:
            self._text = self.abs_path.read_text(encoding="utf-8", errors="replace")
        return self._text

    def line(self, number: int) -> str:
        lines = self.text.splitlines()
        if 1 <= number <= len(lines):
            return lines[number - 1]
        return ""


class Engine:
    name: str = "base"

    def rules(self) -> Sequence[Rule]:
        return ()

    def available(self) -> Tuple[bool, str]:
        """Return (usable, reason). Unavailable engines are reported as skipped."""
        return True, ""

    def wants(self, source: SourceFile) -> bool:
        return True

    def scan(self, files: List[SourceFile]) -> Tuple[List[Finding], List[str]]:
        """Return (findings, error messages). Must not raise for bad input files."""
        raise NotImplementedError
