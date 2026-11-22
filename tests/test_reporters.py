import json

import pytest

from conftest import FIXTURES
from redwall.reporters import FORMATS, render
from redwall.scanner import ScanOptions, scan


@pytest.fixture(scope="module")
def result():
    return scan(FIXTURES / "python", options=ScanOptions(engines=["python-ast"]))


def test_sarif_structure(result):
    doc = json.loads(render(result, "sarif"))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids))
    assert len(run["results"]) == len(result.findings)
    for res in run["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["level"] in ("error", "warning", "note")
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] in ("vulnerable.py", "safe.py")
        assert res["partialFingerprints"]["redwall/v1"]
    sqli = next(r for r in rules if r["id"] == "RW-PY-SQLI")
    assert "external/cwe/cwe-89" in sqli["properties"]["tags"]
    assert sqli["properties"]["security-severity"] == "8.0"
    flows = [r for r in run["results"] if "codeFlows" in r]
    assert flows, "tainted findings should carry a code flow"


def test_jsonl_one_finding_per_line(result):
    lines = render(result, "jsonl").splitlines()
    assert len(lines) == len(result.findings)
    first = json.loads(lines[0])
    assert {"fingerprint", "rule_id", "severity", "confidence", "status", "path", "line", "trace"} <= set(first)
    assert first["status"] == "candidate"


def test_json_has_summary_and_no_timing(result):
    doc = json.loads(render(result, "json"))
    assert doc["summary"]["findings"] == len(result.findings)
    assert "duration" not in json.dumps(doc)


def test_markdown_and_text(result):
    md = render(result, "markdown")
    assert md.startswith("# RedWall report")
    assert "| high |" in md and "Data flow:" in md
    text = render(result, "text")
    assert "RW-PY-SQLI" in text and "findings" in text and "\033[" not in text
    assert "\033[" in render(result, "text", color=True)


def test_all_formats_render_empty_results(tmp_path):
    empty = scan(tmp_path, options=ScanOptions(engines=["python-ast"]))
    for fmt in FORMATS:
        assert render(empty, fmt) is not None
    assert "No findings." in render(empty, "markdown")
