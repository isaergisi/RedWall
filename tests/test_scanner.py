import textwrap

from redwall.models import Confidence, Severity
from redwall.reporters import render
from redwall.scanner import ScanOptions, scan

VULN = textwrap.dedent("""
    import os, hashlib
    def f(x):
        os.system(x)
        os.system(x)
        return hashlib.md5(x)
""")


def _opts(**kw):
    return ScanOptions(engines=["python-ast", "secrets"], **kw)


def test_scan_is_deterministic(tmp_path):
    (tmp_path / "a.py").write_text(VULN)
    (tmp_path / "b.py").write_text(VULN)
    first = render(scan(tmp_path, options=_opts()), "json")
    second = render(scan(tmp_path, options=_opts()), "json")
    assert first == second
    assert render(scan(tmp_path, options=_opts()), "sarif") == render(scan(tmp_path, options=_opts()), "sarif")


def test_fingerprints_survive_line_shifts_and_are_unique(tmp_path):
    (tmp_path / "a.py").write_text(VULN)
    before = [f.fingerprint for f in scan(tmp_path, options=_opts()).findings]
    (tmp_path / "a.py").write_text("# a new comment\n\n" + VULN)
    after = [f.fingerprint for f in scan(tmp_path, options=_opts()).findings]
    assert before == after
    assert len(set(before)) == len(before) == 3  # identical lines still get distinct ids


def test_suppression_comments(tmp_path):
    (tmp_path / "a.py").write_text(textwrap.dedent("""
        import os
        def f(x):
            os.system(x)  # redwall: ignore
            # redwall: ignore[RW-PY-CMDI]
            os.system(x)
            os.system(x)  # redwall: ignore[RW-PY-SQLI]
    """))
    result = scan(tmp_path, options=_opts())
    assert [f.line for f in result.findings] == [7]
    assert result.suppressed == 2


def test_default_and_custom_excludes(tmp_path):
    for d in ("node_modules/pkg", "venv/lib", "src", "tests/data"):
        (tmp_path / d).mkdir(parents=True)
        (tmp_path / d / "m.py").write_text("eval(input())\n")
    paths = {f.path for f in scan(tmp_path, options=_opts(excludes=["tests/data"])).findings}
    assert paths == {"src/m.py"}


def test_severity_confidence_and_rule_filters(tmp_path):
    (tmp_path / "a.py").write_text(VULN)
    assert {f.rule_id for f in scan(tmp_path, options=_opts(min_severity=Severity.HIGH)).findings} == {"RW-PY-CMDI"}
    assert [f.rule_id for f in scan(tmp_path, options=_opts(min_confidence=Confidence.MEDIUM)).findings] == ["RW-PY-WEAKHASH"]
    assert {f.rule_id for f in scan(tmp_path, options=_opts(rule_ids=["rw-py-weak"])).findings} == {"RW-PY-WEAKHASH"}


def test_engine_crash_does_not_kill_the_scan(tmp_path):
    from redwall.engines import PythonAstEngine
    from redwall.engines.base import Engine

    class Broken(Engine):
        name = "broken"

        def scan(self, files):
            raise RuntimeError("boom")

    (tmp_path / "a.py").write_text("eval(input())\n")
    result = scan(tmp_path, options=ScanOptions(engine_objects=[Broken(), PythonAstEngine()]))
    assert [e.status for e in result.engines] == ["error", "ok"]
    assert len(result.findings) == 1
