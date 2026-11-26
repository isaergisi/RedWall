"""Phase 3 D5 (Summary v2): parameters that reach a sink inside a project function, which parameters reach
the return value, project validator functions, and recursion."""

import textwrap
from pathlib import Path

from redwall.models import Confidence
from redwall.scanner import ScanOptions, scan

def _write(root: Path, files: dict) -> None:
    for rel, code in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(code))


def _scan(tmp_path, files):
    _write(tmp_path, files)
    result = scan(tmp_path, options=ScanOptions(engines=["python-ast"]))
    assert not result.errors, result.errors  # a test file that does not parse would pass vacuously
    return result.findings


def _tainted(findings):
    """Findings with a data-flow trace (the ones a parameter summary can produce)."""
    return sorted((f.path, f.line, f.rule_id, f.confidence) for f in findings if f.trace)


def _view(imp, body):
    """A Flask view: the source is on line 9 and ``body`` starts on line 10 when ``imp`` is one line."""
    body = textwrap.indent(textwrap.dedent(body).strip("\n"), "    ")
    return (f"from flask import Flask, request\n{imp}\n\napp = Flask(__name__)\n\n\n@app.route('/x')\n"
            f"def view():\n    value = request.args['v']\n{body}\n")


def test_parameter_reaches_a_sink_in_another_file(tmp_path):
    findings = _scan(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/store.py": """
            import os

            def read(name):
                path = os.path.join("/srv/data", name)
                with open(path) as fh:
                    return fh.read()
        """,
        "pkg/views.py": _view("from pkg.store import read", "return read(value)"),
    })
    (f,) = [f for f in findings if f.trace]
    assert (f.path, f.line, f.rule_id, f.confidence) == ("pkg/store.py", 6, "RW-PY-PATH", Confidence.HIGH)
    # The trace starts at the source in the caller's file and crosses into the callee.
    assert (f.trace[0].path, f.trace[0].line, f.trace[0].kind) == ("pkg/views.py", 9, "source")
    assert any(s.kind == "call" and s.path == "pkg/views.py" and "`read()` as `name`" in s.note for s in f.trace)
    assert (f.trace[-1].path, f.trace[-1].line, f.trace[-1].kind) == ("pkg/store.py", 6, "sink")
    assert f.context["via"]["exact"] is True


def test_thin_wrapper_is_reported_where_it_is_called(tmp_path):
    findings = _scan(tmp_path, {
        "run.py": "import subprocess\n\ndef run(cmd):\n    return subprocess.check_output(cmd, shell=True)\n",
        "app.py": _view("from run import run", 'return run("convert " + value)'),
    })
    assert ("app.py", 10, "RW-PY-CMDI", Confidence.HIGH) in _tainted(findings)
    assert not [f for f in findings if f.path == "run.py" and f.trace]


def test_two_level_chain(tmp_path):
    findings = _scan(tmp_path, {
        "db.py": """
            import sqlite3

            def fetch(sql):
                cur = sqlite3.connect("x.db").cursor()
                cur.execute(sql)
                return cur.fetchall()
        """,
        "repo.py": """
            from db import fetch

            def find_user(name):
                return fetch("SELECT * FROM users WHERE name = '%s'" % name)
        """,
        "app.py": _view("from repo import find_user", "return {'u': find_user(value)}"),
    })
    # The query is built in repo.py; db.fetch() is a thin wrapper, so the finding is at the building call.
    assert _tainted(findings) == [("repo.py", 5, "RW-PY-SQLI", Confidence.HIGH)]


def test_sanitised_in_the_caller_or_the_callee(tmp_path):
    files = {
        "run.py": "import os\n\ndef ping(host):\n    os.system('ping -c 1 ' + host)\n",
        "safe_run.py": "import os, shlex\n\ndef ping(host):\n    os.system('ping -c 1 ' + shlex.quote(host))\n",
    }
    caller = _scan(tmp_path / "a", {**files, "app.py": _view("import shlex\nfrom run import ping",
                                                              "ping(shlex.quote(value))")})
    callee = _scan(tmp_path / "b", {**files, "app.py": _view("from safe_run import ping", "ping(value)")})
    assert _tainted(caller) == [] and _tainted(callee) == []
    found = _scan(tmp_path / "c", {**files, "app.py": _view("from run import ping", "ping(value)")})
    assert _tainted(found) == [("run.py", 4, "RW-PY-CMDI", Confidence.HIGH)]


def test_only_parameters_that_reach_the_return_taint_the_result(tmp_path):
    helper = "def label(prefix, item):\n    print(item.strip())\n    return prefix.strip() + ':'\n"
    quiet = _scan(tmp_path / "a", {"h.py": helper,
                                   "app.py": _view("import os\nfrom h import label", "os.system(label('x', value))")})
    loud = _scan(tmp_path / "b", {"h.py": helper,
                                  "app.py": _view("import os\nfrom h import label", "os.system(label(value, 'x'))")})
    assert _tainted(quiet) == []
    assert [(p, r) for p, _, r, _ in _tainted(loud)] == [("app.py", "RW-PY-CMDI")]


def test_project_validator_function(tmp_path):
    checks = """
        import re
        KNOWN = {"orders", "customers"}

        def is_known_table(name):
            return name in KNOWN

        def is_slug(text):
            if not re.fullmatch(r"[a-z0-9-]+", text):
                return False
            return True
    """
    body = """
        if not is_known_table(value):
            abort(400)
        cur = sqlite3.connect("r.db").cursor()
        cur.execute(f"SELECT COUNT(*) FROM {value}")
    """
    files = {"checks.py": checks,
             "app.py": _view("import sqlite3\nfrom flask import abort\nfrom checks import is_known_table", body)}
    assert _tainted(_scan(tmp_path / "a", files)) == []
    slug = {"checks.py": checks,
            "app.py": _view("import os\nfrom checks import is_slug",
                            "if is_slug(value):\n    os.system('git checkout ' + value)")}
    assert _tainted(_scan(tmp_path / "b", slug)) == []
    unchecked = {"checks.py": checks,
                 "app.py": _view("import sqlite3\nfrom checks import is_known_table",
                                 "is_known_table(value)\nsqlite3.connect('r').execute(f'SELECT {value}')")}
    assert len(_tainted(_scan(tmp_path / "c", unchecked))) == 1


def test_inline_abort_guard_now_ends_the_branch(tmp_path):
    body = """
        if value not in ("a", "b"):
            abort(400)
        os.system("echo " + value)
    """
    findings = _scan(tmp_path, {"app.py": _view("import os\nfrom flask import abort", body)})
    assert _tainted(findings) == []


def test_project_method_named_like_a_library_sink(tmp_path):
    findings = _scan(tmp_path, {"jobs.py": """
        import subprocess
        from flask import request

        class Runner:
            def execute(self, cmd):
                return subprocess.check_output(cmd, shell=True)

        class Job(Runner):
            def post(self):
                return self.execute("systemctl restart " + request.form["job"])
    """})
    # `self.execute` is the project's own method: a command injection, not a SQL `cursor.execute()`.
    assert [(f.line, f.rule_id) for f in findings if f.trace] == [(11, "RW-PY-CMDI")]


def test_override_candidates_lower_the_confidence(tmp_path):
    findings = _scan(tmp_path, {"svc.py": """
        import os
        from flask import request

        class Base:
            def handle(self, arg):
                return arg

            def post(self):
                return self.handle(request.args["a"])

        class Shell(Base):
            def handle(self, arg):
                os.system(arg)
    """})
    (f,) = [f for f in findings if f.trace]
    # Shell.handle passes `arg` straight to the sink: reported at the call, as a possible target only.
    assert (f.line, f.rule_id, f.confidence) == (10, "RW-PY-CMDI", Confidence.MEDIUM)
    assert f.context["via"]["exact"] is False


def test_recursive_helper_reaches_a_fixed_point(tmp_path):
    paths = """
        def join_parts(parts, acc="/srv/data"):
            if not parts:
                return acc
            return join_parts(parts[1:], acc + "/" + {piece})

        def read_nested(parts):
            with open(join_parts(parts)) as fh:
                return fh.read()
    """
    view = _view("from paths import read_nested", "return read_nested(request.args.getlist('p'))")
    vuln = _scan(tmp_path / "a", {"paths.py": paths.format(piece="parts[0]"), "app.py": view})
    safe = _scan(tmp_path / "b", {"paths.py": paths.format(piece="str(int(parts[0]))"), "app.py": view})
    assert _tainted(vuln) == [("paths.py", 8, "RW-PY-PATH", Confidence.HIGH)]
    assert _tainted(safe) == []


def test_explanation_names_the_source_file():
    from redwall.models import Finding, Severity, TraceStep
    from redwall.triage.explain import why_open
    from redwall.triage.scoring import score

    f = Finding(rule_id="RW-PY-PATH", title="t", message="m", severity=Severity.HIGH, confidence=Confidence.HIGH,
                path="pkg/store.py", line=6, cwe="CWE-22", engine="python-ast",
                trace=[TraceStep(9, "user input enters via `request.args`", path="pkg/views.py", kind="source"),
                       TraceStep(6, "reaches sink `open()`", path="pkg/store.py", kind="sink")],
                context={"sink": "open()", "flow": "tainted"})
    text = " ".join(why_open(f, score(f), "en"))
    assert "pkg/views.py:9" in text
