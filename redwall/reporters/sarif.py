"""SARIF 2.1.0, readable by GitHub code scanning, GitLab and most editors."""

from __future__ import annotations

import json
from typing import Dict, List

from .. import INFO_URI, TOOL_NAME, __version__
from ..engines import all_rules
from ..models import Finding, Rule, ScanResult, Severity

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub uses properties.security-severity (0-10) to bucket alerts.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def _rule_descriptor(rule: Rule) -> dict:
    tags = ["security"]
    if rule.cwe:
        tags.append(f"external/cwe/{rule.cwe.lower()}")
    help_text = rule.description + (f"\n\nFix: {rule.remediation}" if rule.remediation else "")
    return {
        "id": rule.id,
        "name": rule.title.replace(" ", ""),
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.description},
        "help": {"text": help_text},
        "defaultConfiguration": {"level": _LEVEL[rule.severity]},
        "properties": {"tags": tags, "security-severity": _SECURITY_SEVERITY[rule.severity]},
    }


def _location(f: Finding, line: int, message: str = "") -> dict:
    loc: dict = {
        "physicalLocation": {
            "artifactLocation": {"uri": f.path, "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": line},
        }
    }
    if message:
        loc["message"] = {"text": message}
    return loc


def _result(f: Finding, index: Dict[str, int]) -> dict:
    region: dict = {"startLine": f.line, "startColumn": f.column, "endLine": f.end_line or f.line}
    if f.snippet:
        region["snippet"] = {"text": f.snippet}
    res: dict = {
        "ruleId": f.rule_id,
        "level": _LEVEL[f.severity],
        "message": {"text": f.message},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f.path, "uriBaseId": "%SRCROOT%"},
                "region": region,
            }
        }],
        "partialFingerprints": {"redwall/v1": f.fingerprint},
        "properties": {
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "status": f.status.value,
            "engine": f.engine,
        },
    }
    if f.rule_id in index:
        res["ruleIndex"] = index[f.rule_id]
    if f.triage is not None:
        # SARIF `rank` (0-100) orders results in viewers; the rest is RedWall-specific.
        res["rank"] = float(f.triage.score)
        res["properties"]["priority"] = f.triage.tier
        res["properties"]["priorityRank"] = f.triage.rank
        res["properties"]["whyOpen"] = list(f.triage.why_open)
        if f.triage.llm is not None:
            res["properties"]["llm"] = f.triage.llm
    if f.status.value == "suppressed":
        res["suppressions"] = [{"kind": "inSource", "justification": f.snippet}]
    if f.cwe:
        res["properties"]["cwe"] = f.cwe
    if f.trace:
        res["codeFlows"] = [{
            "threadFlows": [{
                "locations": [{"location": _location(f, s.line, s.note)} for s in f.trace]
            }]
        }]
    return res


def render_sarif(result: ScanResult, **_) -> str:
    known = {r.id: r for r in all_rules()}
    everything = result.findings + result.suppressed_findings
    used_ids = sorted({f.rule_id for f in everything})
    rules: List[Rule] = [known[i] for i in sorted(known)]
    # Rules reported by an engine but missing from the catalogue still get a descriptor.
    for rid in used_ids:
        if rid not in known:
            sample = next(f for f in everything if f.rule_id == rid)
            rules.append(Rule(rid, sample.title, sample.severity, sample.cwe, sample.message, sample.engine))
    index = {r.id: i for i, r in enumerate(rules)}
    notifications = [{"level": "warning", "message": {"text": e}} for e in result.errors]
    doc = {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": __version__,
                "informationUri": INFO_URI,
                "rules": [_rule_descriptor(r) for r in rules],
            }},
            "invocations": [{
                "executionSuccessful": True,
                "toolExecutionNotifications": notifications,
            }],
            "results": [_result(f, index) for f in result.findings + result.suppressed_findings],
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
