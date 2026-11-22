import json
import stat
import sys

import pytest

from conftest import FIXTURES, expectations
from redwall.engines.opengrep import OpengrepEngine
from redwall.scanner import ScanOptions, scan

JS = FIXTURES / "js"
HAVE_BINARY = OpengrepEngine().binary() is not None


def test_rule_metadata_is_loaded_from_yaml():
    rules = {r.id: r for r in OpengrepEngine().rules()}
    assert {"RW-JS-CODEI", "RW-JS-CMDI", "RW-JS-SQLI", "RW-JS-XSS", "RW-JS-TLS", "RW-JS-WEAKHASH"} <= set(rules)
    assert rules["RW-JS-SQLI"].cwe == "CWE-89"
    assert rules["RW-JS-SQLI"].severity.value == "high"


def test_missing_binary_is_reported_as_skipped(tmp_path):
    (tmp_path / "a.js").write_text("eval(x)\n")
    engine = OpengrepEngine(binary="definitely-not-installed-redwall")
    result = scan(tmp_path, options=ScanOptions(engine_objects=[engine]))
    [run] = result.engines
    assert run.status == "skipped" and run.files == 1
    assert result.findings == []


def test_output_is_converted_with_a_fake_binary(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    target = src / "app.js"
    target.write_text("const a = 1;\neval(userInput);\n")
    payload = {
        "results": [{
            "check_id": "rules.js-code-injection",
            "path": str(target),
            "start": {"line": 2, "col": 1},
            "end": {"line": 2, "col": 16},
            "extra": {"message": "Non-constant data is evaluated as code.", "severity": "ERROR",
                      "metadata": {"redwall_id": "RW-JS-CODEI"}},
        }],
        "errors": [{"message": "partial parse in other.js"}],
    }
    fake = tmp_path / "fake-opengrep"
    fake.write_text(f"#!{sys.executable}\nimport sys\nsys.stdout.write({json.dumps(json.dumps(payload))})\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)

    result = scan(src, options=ScanOptions(engine_objects=[OpengrepEngine(binary=str(fake))]))
    [f] = result.findings
    assert (f.rule_id, f.path, f.line, f.cwe, f.severity.value) == ("RW-JS-CODEI", "app.js", 2, "CWE-95", "high")
    assert f.snippet == "eval(userInput);"
    assert result.errors == ["opengrep: partial parse in other.js"]


@pytest.mark.skipif(not HAVE_BINARY, reason="opengrep/semgrep not installed")
def test_js_fixtures_match_expectations():
    result = scan(JS, options=ScanOptions(engines=["opengrep"]))
    assert [e.status for e in result.engines] == ["ok"]
    got = {(f.path, f.rule_id, f.line) for f in result.findings}
    want = {("vulnerable.js", r, l) for r, l in expectations(JS / "vulnerable.js")} | \
           {("react.tsx", r, l) for r, l in expectations(JS / "react.tsx")}
    assert got == want
