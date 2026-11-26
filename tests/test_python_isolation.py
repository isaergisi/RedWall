"""Phase 3 D2: an analyser failure stays local, traces carry their file, SARIF code flows can span files."""

import json
import textwrap
import warnings
from pathlib import Path

from redwall.engines import python_ast
from redwall.models import Confidence, Finding, ScanResult, Severity, TraceStep
from redwall.reporters import render
from redwall.scanner import ScanOptions, scan

VULN = """
    import os
    from flask import request

    def {name}():
        os.system(request.args["c"])
"""


def _write(tmp_path: Path, files: dict) -> None:
    for rel, code in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(code))


def _scan(tmp_path: Path):
    return scan(tmp_path, options=ScanOptions(engines=["python-ast"]))


def _explode_in(monkeypatch, function_name: str, exc: type = KeyError) -> None:
    """Make the analyser crash on every call inside one function, the way an engine bug would."""
    original = python_ast._ModuleAnalyzer._check_call

    def check_call(self, call, scope):
        if function_name in self.func_stack:
            raise exc("simulated analyser bug")
        return original(self, call, scope)

    monkeypatch.setattr(python_ast._ModuleAnalyzer, "_check_call", check_call)


def test_crash_in_one_function_keeps_other_functions_and_files(tmp_path, monkeypatch):
    _write(tmp_path, {
        "a.py": VULN.format(name="boom") + VULN.format(name="fine_a").replace("import os\n    from flask import request\n", ""),
        "b.py": VULN.format(name="fine_b"),
    })
    _explode_in(monkeypatch, "boom")
    result = _scan(tmp_path)
    found = sorted((f.path, f.function) for f in result.findings)
    assert found == [("a.py", "fine_a"), ("b.py", "fine_b")]
    engine = next(e for e in result.engines if e.name == "python-ast")
    assert engine.status == "ok"
    assert any("a.py:5 in `boom`" in e and "KeyError" in e and "rest of the function skipped" in e
               for e in result.errors), result.errors


def test_crash_at_module_level_keeps_the_rest_of_the_file(tmp_path, monkeypatch):
    _write(tmp_path, {"app.py": """
        import os
        from flask import request
        os.system(request.args["x"])
        def later():
            os.system(request.args["y"])
    """})
    original = python_ast._ModuleAnalyzer._check_call

    def check_call(self, call, scope):
        if not self.func_stack:
            raise ValueError("simulated")
        return original(self, call, scope)

    monkeypatch.setattr(python_ast._ModuleAnalyzer, "_check_call", check_call)
    result = _scan(tmp_path)
    assert [(f.line, f.function) for f in result.findings] == [(6, "later")]
    assert any("app.py:4" in e and "statement skipped" in e for e in result.errors)


def test_crash_while_summarising_a_helper_falls_back_to_the_default(tmp_path, monkeypatch):
    _write(tmp_path, {
        "helpers.py": """
            def passthrough(x):
                y = x.strip()
                return y
        """,
        "app.py": """
            import os
            import helpers
            from flask import request

            def f():
                os.system(helpers.passthrough(request.args["a"]))
        """,
    })
    original = python_ast._Project._summarise

    def summarise(self, module, fn):
        if fn.name == "passthrough":
            raise RuntimeError("simulated")
        return original(self, module, fn)

    monkeypatch.setattr(python_ast._Project, "_summarise", summarise)
    result = _scan(tmp_path)
    # Without a summary an unknown call passes taint through (the documented default), so it is still found.
    assert [(f.path, f.line) for f in result.findings] == [("app.py", 7)]
    assert any("helpers.py:2 in `passthrough`" in e and "summary skipped" in e for e in result.errors)


def test_unparsable_files_and_syntax_warnings_do_not_stop_the_scan(tmp_path):
    _write(tmp_path, {
        "broken.py": "def oops(:\n    return 1\n",
        "py2.py": 'print "hello"\n',
        "regex.py": 'import re\nPAT = re.compile("\\d+")\n',  # invalid escape: SyntaxWarning on 3.12+
        "app.py": VULN.format(name="run"),
    })
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # any warning leaking out of the parser fails the test
        result = _scan(tmp_path)
    assert [(f.path, f.rule_id) for f in result.findings] == [("app.py", "RW-PY-CMDI")]
    assert sum("could not parse" in e for e in result.errors) == 2


def test_trace_steps_carry_file_function_and_kind(tmp_path):
    _write(tmp_path, {"pkg/views.py": """
        import os
        from flask import Flask, request
        app = Flask(__name__)

        @app.route("/r/<name>")
        def show(name):
            cmd = "ls " + name
            os.system(cmd)
    """})
    (f,) = _scan(tmp_path).findings
    assert f.confidence is Confidence.HIGH
    assert [(s.path, s.kind) for s in f.trace] == [
        ("pkg/views.py", "source"), ("pkg/views.py", "propagation"), ("pkg/views.py", "sink")]
    assert {s.function for s in f.trace} == {"show"}
    as_json = f.to_dict()["trace"][0]
    assert as_json["path"] == "pkg/views.py" and as_json["kind"] == "source" and as_json["line"] == 7


def test_trace_step_json_stays_backward_compatible():
    assert TraceStep(3, "x").to_dict() == {"line": 3, "note": "x"}
    assert TraceStep(3, "x").where("a.py") == "line 3"
    assert TraceStep(3, "x", path="a.py").where("a.py") == "line 3"
    assert TraceStep(3, "x", path="b.py").where("a.py") == "b.py:3"


def _cross_file_result() -> ScanResult:
    f = Finding(
        rule_id="RW-PY-SQLI", title="SQL injection", message="m", severity=Severity.HIGH,
        confidence=Confidence.HIGH, path="shop/service.py", line=6, cwe="CWE-89", engine="python-ast",
        function="find_user",
        trace=[TraceStep(10, "user input enters via `request.args`", path="shop/routes.py", function="user", kind="source"),
               TraceStep(6, "reaches sink `cursor.execute()`", path="shop/service.py", function="find_user", kind="sink")],
    )
    f.fingerprint = f.compute_fingerprint()
    return ScanResult(root=".", findings=[f], engines=[], files_scanned=2)


def test_sarif_code_flow_spans_files():
    doc = json.loads(render(_cross_file_result(), "sarif"))
    steps = doc["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]
    uris = [s["location"]["physicalLocation"]["artifactLocation"]["uri"] for s in steps]
    assert uris == ["shop/routes.py", "shop/service.py"]
    assert steps[0]["kinds"] == ["taint", "source"] and steps[1]["kinds"] == ["taint", "sink"]
    assert steps[0]["location"]["logicalLocations"][0]["fullyQualifiedName"] == "user"


def test_text_and_markdown_name_the_other_file():
    result = _cross_file_result()
    for fmt in ("text", "markdown"):
        out = render(result, fmt)
        assert "shop/routes.py:10" in out and "line 6" in out
