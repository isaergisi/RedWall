import textwrap
from pathlib import Path

from conftest import FIXTURES, expectations
from redwall.models import Confidence
from redwall.scanner import ScanOptions, scan

PY = FIXTURES / "python"


def _scan_dir(path: Path):
    return scan(path, options=ScanOptions(engines=["python-ast"]))


def _scan_code(tmp_path: Path, code: str):
    (tmp_path / "app.py").write_text(textwrap.dedent(code))
    return _scan_dir(tmp_path).findings


def test_vulnerable_fixture_matches_expectations():
    result = _scan_dir(PY)
    got = {(f.rule_id, f.line) for f in result.findings if f.path == "vulnerable.py"}
    assert got == expectations(PY / "vulnerable.py")


def test_safe_fixture_has_no_findings():
    result = _scan_dir(PY)
    assert [f for f in result.findings if f.path == "safe.py"] == []
    assert result.suppressed == 1  # the inline `redwall: ignore[...]`


def test_taint_trace_runs_from_source_to_sink(tmp_path):
    findings = _scan_code(tmp_path, """
        from flask import request
        def view(db):
            uid = request.args.get("id")
            q = "SELECT * FROM t WHERE id = " + uid
            db.execute(q)
    """)
    [f] = findings
    assert f.rule_id == "RW-PY-SQLI"
    assert f.confidence is Confidence.HIGH
    assert f.function == "view"
    notes = [s.note for s in f.trace]
    assert "request.args" in notes[0]
    assert notes[-1].startswith("reaches sink")
    assert [s.line for s in f.trace] == [4, 4, 5, 6]


def test_built_string_without_user_input_is_medium_confidence(tmp_path):
    [f] = _scan_code(tmp_path, """
        def report(db, table):
            db.execute(f"SELECT count(*) FROM {table}")
    """)
    assert f.rule_id == "RW-PY-SQLI"
    assert f.confidence is Confidence.MEDIUM
    assert f.trace == []


def test_unknown_variable_alone_is_not_reported_for_sql(tmp_path):
    assert _scan_code(tmp_path, """
        def run(db, query):
            db.execute(query)
    """) == []


def test_import_aliases_are_resolved(tmp_path):
    findings = _scan_code(tmp_path, """
        import subprocess as sp
        from os import system as run_cmd
        from pickle import loads
        def f(x, data):
            sp.check_output("echo " + x, shell=True)
            run_cmd(x)
            loads(data)
    """)
    assert {f.rule_id for f in findings} == {"RW-PY-CMDI", "RW-PY-DESER"}
    assert len(findings) == 3


def test_branch_keeps_the_riskier_value(tmp_path):
    [f] = _scan_code(tmp_path, """
        import os
        from flask import request
        def f(flag):
            cmd = "ls"
            if flag:
                cmd = request.args["c"]
            os.system(cmd)
    """)
    assert f.confidence is Confidence.HIGH


def test_straight_line_reassignment_clears_taint(tmp_path):
    findings = _scan_code(tmp_path, """
        import os
        from flask import request
        def f():
            cmd = request.args["c"]
            cmd = "ls"
            os.system(cmd)
    """)
    assert findings == []


def test_route_parameters_are_user_input(tmp_path):
    [f] = _scan_code(tmp_path, """
        from flask import Flask
        app = Flask(__name__)
        @app.get("/f/<name>")
        def get(name):
            return open(name).read()
    """)
    assert f.rule_id == "RW-PY-PATH"
    assert "route parameter" in f.trace[0].note


def test_sanitizers_stop_taint(tmp_path):
    assert _scan_code(tmp_path, """
        import os, shlex
        from flask import request
        def f():
            os.system("ping " + shlex.quote(request.args["h"]))
            n = int(request.args["n"])
            return open("/data/%d.txt" % n).read()
    """) == []


def test_syntax_error_is_reported_not_raised(tmp_path):
    (tmp_path / "broken.py").write_text("def f(:\n")
    (tmp_path / "ok.py").write_text("eval(input())\n")
    result = _scan_dir(tmp_path)
    assert any("broken.py" in e for e in result.errors)
    assert [f.rule_id for f in result.findings] == ["RW-PY-CODEI"]


def test_nested_function_and_method_names(tmp_path):
    [f] = _scan_code(tmp_path, """
        class Repo:
            def find(self, db, name):
                db.execute("SELECT * FROM t WHERE n = '%s'" % name)
    """)
    assert f.function == "Repo.find"
