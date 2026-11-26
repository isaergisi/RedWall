"""Scoring for the real-world benchmarks (phase 2 dev set and phase 3 held-out set).

Pure functions, standard library only, so the tests can import them without a checkout.

A case is scored at four levels, from the most lenient to the strictest. Every level needs a finding
whose CWE matches the case:

``file``
    the finding is in one of the case's sink files (any line).
``vuln``
    the finding is on one of the case's sink lines or ranges, generic ``shared`` helpers included
    (this is the "detected" number of the phase 2 report).
``exact``
    the finding is on an advisory-specific (not ``shared``) sink line or range.
``flow``
    an ``exact`` finding whose trace has a step in one of the case's source files on a source line or
    range. A trace step without a ``path`` is taken to be in the finding's own file, which is what
    every RedWall release before phase 3 emits.

Positives are the vulnerable trees (``ref``). When a case has a ``fixed_ref``, the fixed tree is the
matching negative: the case's lines are mapped onto the fixed files with a line diff and the same
level checks are run on the fixed tree's findings. A hit there is a false positive at that level, no
hit a true negative. Precision computed this way is case-level precision against the fixed release,
not the precision of all findings in the project: the reports name it that way.
"""

from __future__ import annotations

import difflib
import hashlib
import json
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

LEVELS = ("file", "vuln", "exact", "flow")
EQUIV = [{"94", "95", "1336"}, {"327", "328"}]

Range = Tuple[int, int]


def manifest_digest(manifest: dict) -> str:
    """sha256 of the parts of a manifest that define the ground truth (comments excluded)."""
    core = {"projects": manifest["projects"], "cases": manifest["cases"]}
    text = json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def cwe_ok(found: Optional[str], wanted: str) -> bool:
    if not found:
        return False
    n = found.upper().replace("CWE-", "")
    for group in EQUIV:
        if wanted in group:
            return n in group
    return n == wanted


def strip_scope(path: str, scope: str) -> str:
    """Repository-relative path -> path relative to the scanned directory."""
    prefix = "" if scope in (".", "") else scope.rstrip("/") + "/"
    return path[len(prefix):] if prefix and path.startswith(prefix) else path


def _within(line: int, rng: Sequence[int]) -> bool:
    return rng[0] <= line <= rng[1]


def _trace_points(finding: dict) -> Iterable[Tuple[str, int]]:
    for step in finding.get("trace") or []:
        yield step.get("path") or finding["path"], step["line"]


def case_levels(findings: List[dict], case: dict, scope: str,
                remap: Optional[Callable[[str, Sequence[int]], Range]] = None) -> Dict[str, object]:
    """Which levels a case reaches on one tree's findings, plus the hits that got it there.

    ``remap(file, lines)`` maps a ground-truth range onto another version of the file (used for the
    fixed tree); by default ranges are taken as they are.
    """
    remap = remap or (lambda _f, lines: (lines[0], lines[1]))
    sinks = [(strip_scope(s["file"], scope), remap(s["file"], s["lines"]), bool(s.get("shared")))
             for s in case["sinks"]]
    sources = [(strip_scope(s["file"], scope), remap(s["file"], s["lines"])) for s in case.get("sources", [])]
    sink_files = {f for f, _r, _s in sinks}
    relevant = [f for f in findings if cwe_ok(f.get("cwe"), case["cwe"])]

    file_hits = [f for f in relevant if f["path"] in sink_files]
    vuln_hits, exact_hits = [], []
    for f in file_hits:
        for path, rng, shared in sinks:
            if f["path"] == path and _within(f["line"], rng):
                vuln_hits.append(f)
                if not shared:
                    exact_hits.append(f)
                break
    flow_hits = [f for f in exact_hits
                 if any(p == sp and _within(ln, sr) for p, ln in _trace_points(f) for sp, sr in sources)]
    hits = {"file": file_hits, "vuln": vuln_hits, "exact": exact_hits, "flow": flow_hits}
    return {"levels": {lvl: bool(hits[lvl]) for lvl in LEVELS}, "hits": hits}


def line_map(old_text: str, new_text: str) -> Callable[[Sequence[int]], Range]:
    """Map 1-based line ranges of ``old_text`` onto ``new_text``.

    Unchanged lines move with the diff. A line inside a replaced block maps to the whole replacement
    block, a deleted line to the line the deletion collapsed onto, so a check that was fixed in place
    still lands on the fixed code.
    """
    old, new = old_text.splitlines(), new_text.splitlines()
    ops = difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes()

    def one(line: int) -> Range:
        i = line - 1
        for tag, i1, i2, j1, j2 in ops:
            if i1 <= i < i2 or (i1 == i2 == i):
                if tag == "equal":
                    n = j1 + (i - i1) + 1
                    return n, n
                if j2 > j1:
                    return j1 + 1, j2
                return max(1, j1), max(1, j1)
        return max(1, len(new)), max(1, len(new))

    def rng(lines: Sequence[int]) -> Range:
        lo, hi = one(lines[0]), one(lines[1])
        return min(lo[0], hi[0]), max(lo[1], hi[1])

    return rng


def confusion(rows: List[dict], tool: str) -> Dict[str, dict]:
    """TP/FN from vulnerable trees and FP/TN from fixed trees, per level, for one tool."""
    out = {}
    for lvl in LEVELS:
        tp = fn = fp = tn = 0
        for row in rows:
            r = row["tools"].get(tool)
            if not r:
                continue
            if r["vulnerable"][lvl]:
                tp += 1
            else:
                fn += 1
            fixed = r.get("fixed")
            if fixed is not None:
                if fixed[lvl]:
                    fp += 1
                else:
                    tn += 1
        out[lvl] = {"tp": tp, "fp": fp, "tn": tn, "fn": fn, **ratios(tp, fp, fn)}
    return out


def ratios(tp: int, fp: int, fn: int) -> Dict[str, Optional[float]]:
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall)) if precision and recall else (
        0.0 if precision is not None and recall is not None else None)
    return {"precision": _r(precision), "recall": _r(recall), "f1": _r(f1)}


def _r(x: Optional[float]) -> Optional[float]:
    return None if x is None else round(x, 3)
