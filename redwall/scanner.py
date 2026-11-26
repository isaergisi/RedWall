"""Stage 1 orchestration: discover files, run engines, normalise findings.

Everything here is deterministic: the same tree always yields the same
findings, in the same order, with the same fingerprints.
"""

from __future__ import annotations

import fnmatch
import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .engines import default_engines
from .engines.base import LANGUAGE_BY_SUFFIX, Engine, SourceFile
from .models import Confidence, EngineRun, Finding, ScanResult, Severity, Status

DEFAULT_EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "__pycache__", ".venv", "venv",
    "env", ".env.d", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build",
    ".next", ".nuxt", "coverage", "site-packages", ".idea", ".vscode", ".redwall",
}

# `# redwall: ignore`, `// redwall: ignore[RW-PY-SQLI, RW-JS-XSS]`, also accepts `nosec`-style marker
_SUPPRESS = re.compile(r"redwall:\s*ignore(?:\[(?P<ids>[A-Za-z0-9_,\s\-]+)\])?", re.IGNORECASE)


@dataclass
class ScanOptions:
    excludes: Sequence[str] = ()
    min_severity: Severity = Severity.INFO
    min_confidence: Confidence = Confidence.LOW
    rule_ids: Optional[Sequence[str]] = None  # only run these rules (prefix match)
    engines: Optional[Sequence[str]] = None  # only run these engines
    engine_objects: Optional[List[Engine]] = field(default=None, repr=False)


def _excluded(rel: str, patterns: Sequence[str]) -> bool:
    for pat in patterns:
        pat = pat.rstrip("/")
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, f"{pat}/*") or fnmatch.fnmatch(rel, f"*/{pat}") \
                or fnmatch.fnmatch(rel, f"*/{pat}/*"):
            return True
    return False


def discover(root: Path, targets: Sequence[Path], excludes: Sequence[str]) -> List[SourceFile]:
    """Collect files under ``targets`` (files or dirs), relative to ``root``."""
    seen: Dict[str, SourceFile] = {}

    def add(path: Path) -> None:
        try:
            rel = path.resolve().relative_to(root).as_posix()
        except ValueError:
            rel = path.as_posix()
        if rel in seen or _excluded(rel, excludes):
            return
        if not path.is_file() or path.is_symlink():
            return
        seen[rel] = SourceFile(abs_path=path.resolve(), rel_path=rel, language=LANGUAGE_BY_SUFFIX.get(path.suffix.lower()))

    for target in targets:
        if target.is_file():
            add(target)
            continue
        for dirpath, dirnames, filenames in os.walk(target):
            dirnames[:] = sorted(d for d in dirnames if d not in DEFAULT_EXCLUDED_DIRS and not d.endswith(".egg-info"))
            for name in sorted(filenames):
                add(Path(dirpath) / name)
    return [seen[k] for k in sorted(seen)]


def _suppressed(finding: Finding, sources: Dict[str, SourceFile]) -> bool:
    src = sources.get(finding.path)
    if src is None:
        return False
    for lineno in {finding.line, finding.line - 1}:
        text = src.line(lineno)
        m = _SUPPRESS.search(text)
        if not m:
            continue
        # A marker on the previous line only counts if that line is just a comment.
        if lineno != finding.line and not text.strip().startswith(("#", "//", "/*", "*")):
            continue
        ids = m.group("ids")
        if not ids:
            return True
        wanted = {i.strip().upper() for i in ids.split(",") if i.strip()}
        if finding.rule_id.upper() in wanted:
            return True
    return False


def _rule_selected(rule_id: str, prefixes: Optional[Sequence[str]]) -> bool:
    if not prefixes:
        return True
    return any(rule_id.upper().startswith(p.upper()) for p in prefixes)


def _assign_fingerprints(findings: List[Finding]) -> None:
    counters: Dict[Tuple[str, str, Optional[str], str], int] = defaultdict(int)
    for f in findings:
        key = (f.rule_id, f.path, f.function, " ".join(f.snippet.split()))
        f.fingerprint = f.compute_fingerprint(counters[key])
        counters[key] += 1


def scan(root: Path, targets: Optional[Iterable[Path]] = None, options: Optional[ScanOptions] = None) -> ScanResult:
    started = time.monotonic()
    options = options or ScanOptions()
    root = root.resolve()
    target_list = [Path(t).resolve() for t in (targets or [root])]
    files = discover(root, target_list, options.excludes)
    by_rel = {f.rel_path: f for f in files}

    engines = options.engine_objects if options.engine_objects is not None else default_engines()
    if options.engines:
        wanted = {e.lower() for e in options.engines}
        engines = [e for e in engines if e.name in wanted]

    runs: List[EngineRun] = []
    findings: List[Finding] = []
    errors: List[str] = []
    for engine in engines:
        ok, detail = engine.available()
        chosen = [f for f in files if engine.wants(f)]
        if not ok:
            runs.append(EngineRun(engine.name, "skipped", detail, files=len(chosen)))
            continue
        try:
            found, errs = engine.scan(chosen)
        except Exception as exc:  # an engine bug must not kill the whole scan
            runs.append(EngineRun(engine.name, "error", f"{exc.__class__.__name__}: {exc}", files=len(chosen)))
            errors.append(f"{engine.name}: {exc.__class__.__name__}: {exc}")
            continue
        runs.append(EngineRun(engine.name, "ok", getattr(engine, "scan_detail", "") or detail, files=len(chosen)))
        findings.extend(found)
        errors.extend(errs)

    # Filter, de-duplicate (same rule on the same line), suppress.
    unique: Dict[Tuple[str, str, int], Finding] = {}
    filtered_keys = set()
    for f in findings:
        if not _rule_selected(f.rule_id, options.rule_ids) or \
                f.severity.rank < options.min_severity.rank or f.confidence.rank < options.min_confidence.rank:
            filtered_keys.add((f.rule_id, f.path, f.line))
            continue
        key = (f.rule_id, f.path, f.line)
        prev = unique.get(key)
        if prev is not None:
            # Keep the most confident variant (it usually carries a trace).
            if (f.confidence.rank, len(f.trace)) > (prev.confidence.rank, len(prev.trace)):
                unique[key] = f
            continue
        unique[key] = f
    # Filters the user asked for are counted (and the count is reported), never silent.
    filtered = len(filtered_keys - set(unique))
    kept: List[Finding] = []
    suppressed: List[Finding] = []
    for f in unique.values():
        if _suppressed(f, by_rel):
            f.status = Status.SUPPRESSED
            suppressed.append(f)
        else:
            kept.append(f)
    # Fingerprints are assigned over both lists so suppressing a finding does not
    # renumber its identical neighbours.
    everything = sorted(kept + suppressed, key=Finding.sort_key)
    _assign_fingerprints(everything)
    kept.sort(key=Finding.sort_key)
    suppressed.sort(key=Finding.sort_key)

    return ScanResult(
        root=str(root),
        findings=kept,
        engines=runs,
        files_scanned=len(files),
        suppressed_findings=suppressed,
        filtered=filtered,
        errors=sorted(set(errors)),
        duration_s=time.monotonic() - started,
    )
