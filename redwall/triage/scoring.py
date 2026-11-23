"""Deterministic risk score: what to look at first.

The score is a sum of a few documented terms, so every rank can be explained
and reproduced by hand:

* **impact** - what an attacker gets if the finding is real (remote code
  execution > data access > browser-side script > weak configuration ...),
  taken from the CWE.
* **evidence** - how sure stage 1 is: a traced path from user input to the
  sink, a string built from non-constant parts, or a value of unknown origin.
* **exposure** - where the data comes from: an HTTP request is reachable by
  anyone, ``input()``/``sys.argv`` only by the local user.
* **context** - test, example and documentation code is ranked lower (but
  still listed).

Nothing here removes or hides a finding; it only orders them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Dict, List, Optional, Tuple

from ..models import Confidence, Finding, ScoreFactor, Severity

# rule id -> sink kind. Kinds drive both the impact class and the explanation.
RULE_KIND: Dict[str, str] = {
    "RW-PY-SQLI": "sqli", "RW-JS-SQLI": "sqli",
    "RW-PY-CMDI": "cmdi", "RW-JS-CMDI": "cmdi",
    "RW-PY-CODEI": "code", "RW-JS-CODEI": "code",
    "RW-PY-DESER": "deser",
    "RW-PY-SSTI": "ssti",
    "RW-PY-XSS": "xss", "RW-PY-XSS-RESPONSE": "xss", "RW-JS-XSS": "xss",
    "RW-PY-PATH": "path",
    "RW-PY-SSRF": "ssrf",
    "RW-PY-LDAPI": "ldap",
    "RW-PY-XPATHI": "xpath",
    "RW-PY-XXE": "xxe",
    "RW-PY-OPENREDIRECT": "redirect",
    "RW-PY-TRUSTBOUND": "trustbound",
    "RW-PY-TLS": "tls", "RW-JS-TLS": "tls",
    "RW-PY-DEBUG": "debug",
    "RW-PY-COOKIE": "cookie",
    "RW-PY-WEAKRAND": "weakrand",
    "RW-PY-WEAKHASH": "weakhash", "RW-JS-WEAKHASH": "weakhash",
    "RW-PY-TEMPFILE": "tempfile",
}

# Kinds whose finding is about data reaching a sink (taint rules).
DATAFLOW_KINDS = frozenset({
    "sqli", "cmdi", "code", "deser", "ssti", "xss", "path", "ssrf", "ldap", "xpath", "xxe",
    "redirect", "trustbound",
})

# Impact classes: (points, class id). Class ids are translated in explain.py.
_IMPACT_BY_KIND: Dict[str, Tuple[int, str]] = {
    "cmdi": (50, "rce"), "code": (50, "rce"), "deser": (50, "rce"), "ssti": (50, "rce"),
    "sqli": (42, "data"), "path": (40, "data"), "secret": (40, "credential"),
    "xxe": (38, "data"), "ssrf": (38, "internal"), "ldap": (36, "data"), "xpath": (34, "data"),
    "xss": (30, "browser"),
    "tls": (22, "transport"), "debug": (22, "debugger"),
    "redirect": (20, "phishing"),
    "cookie": (15, "transport"), "weakrand": (15, "predictable"), "trustbound": (12, "integrity"),
    "weakhash": (10, "crypto"), "tempfile": (10, "race"),
}
_IMPACT_BY_SEVERITY = {
    Severity.CRITICAL: 45, Severity.HIGH: 38, Severity.MEDIUM: 25, Severity.LOW: 12, Severity.INFO: 5,
}

_EVIDENCE = {Confidence.HIGH: 30, Confidence.MEDIUM: 15, Confidence.LOW: 0}
# For data-flow rules the evidence is how sure we are that attacker data reaches the sink,
# which the Python engine records as the flow level of the value at the sink.
_FLOW_EVIDENCE = {"traced": 30, "built": 15, "unknown": 0}


def _evidence(f: Finding, kind: str) -> Tuple[int, str]:
    flow = f.context.get("flow")
    if kind in DATAFLOW_KINDS and flow is not None:
        if f.trace and flow == "tainted":
            code = "traced"
        elif flow == "built":
            code = "built"
        else:
            code = "unknown"  # unknown origin, or a dangerous call whose input was not traced
        return _FLOW_EVIDENCE[code], code
    return _EVIDENCE[f.confidence], f.confidence.value

REMOTE, LOCAL, ROUTE, REPO, NONE = "remote", "local", "route", "repo", "none"
_EXPOSURE = {REMOTE: 15, ROUTE: 5, REPO: 10, LOCAL: -10, NONE: 0}

_LOCAL_SOURCE = re.compile(r"`(?:input|raw_input)\(\)`|`sys\.(?:argv|stdin)`")
_REMOTE_SOURCE = re.compile(r"`request\.|route parameter `")

_NON_PRODUCTION_DIRS = {
    "test", "tests", "testing", "unittests", "example", "examples", "sample", "samples", "demo", "demos",
    "doc", "docs", "fixtures", "benchmark", "benchmarks", "e2e",
}
CONTEXT_PENALTY = -20

TIERS = ((80, "P1"), (60, "P2"), (40, "P3"), (0, "P4"))


def kind_of(f: Finding) -> str:
    if f.rule_id.startswith("RW-SECRET-"):
        return "secret"
    return RULE_KIND.get(f.rule_id, "other")


def tier_of(score: int) -> str:
    for floor, name in TIERS:
        if score >= floor:
            return name
    return "P4"


def source_kind(f: Finding) -> str:
    """Where the data that reaches the sink comes from, judged from the trace."""
    notes = " ".join(step.note for step in f.trace)
    if _REMOTE_SOURCE.search(notes):
        return REMOTE
    if _LOCAL_SOURCE.search(notes):
        return LOCAL
    if "enters via" in notes:
        return REMOTE  # project helper that returns request data
    return NONE


def is_non_production(path: str) -> bool:
    p = PurePosixPath(path)
    name = p.name.lower()
    if name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py" \
            or re.search(r"\.(test|spec)\.[jt]sx?$", name):
        return True
    return any(part.lower() in _NON_PRODUCTION_DIRS for part in p.parts[:-1])


@dataclass
class Score:
    total: int
    factors: List[ScoreFactor]
    kind: str
    impact_class: str
    exposure: str
    non_production: bool


def score(f: Finding, reason: Optional[Dict[str, str]] = None) -> Score:
    """Compute the deterministic score. ``reason`` maps factor keys to text (filled by explain)."""
    kind = kind_of(f)
    points, impact_class = _IMPACT_BY_KIND.get(kind, (_IMPACT_BY_SEVERITY[f.severity], "other"))
    factors = [ScoreFactor("impact", points, impact_class)]
    factors.append(ScoreFactor("evidence", *_evidence(f, kind)))

    if kind == "secret":
        exposure = REPO
    elif kind in DATAFLOW_KINDS:
        exposure = source_kind(f)
        if exposure == NONE and f.context.get("in_route"):
            exposure = ROUTE
    else:
        exposure = NONE
    if _EXPOSURE[exposure]:
        factors.append(ScoreFactor("exposure", _EXPOSURE[exposure], exposure))

    non_prod = is_non_production(f.path)
    if non_prod:
        factors.append(ScoreFactor("context", CONTEXT_PENALTY, "non-production"))

    total = max(0, min(100, sum(x.points for x in factors)))
    return Score(total, factors, kind, impact_class, exposure, non_prod)


def sort_key(f: Finding, total: int) -> tuple:
    return (-total, -f.severity.rank, -f.confidence.rank, f.path, f.line, f.column, f.rule_id)
