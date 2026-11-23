import json

from conftest import FIXTURES
from redwall.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main

PY = str(FIXTURES / "python")


def test_exit_codes(capsys):
    assert main(["scan", PY, "--engine", "python-ast"]) == EXIT_FINDINGS
    assert main(["scan", PY, "--engine", "python-ast", "--fail-on", "none"]) == EXIT_OK
    assert main(["scan", str(FIXTURES / "python" / "safe.py"), "--engine", "python-ast"]) == EXIT_OK
    assert main(["scan", "does/not/exist"]) == EXIT_ERROR
    capsys.readouterr()


def test_output_file_and_out_dir(tmp_path, capsys):
    out = tmp_path / "r.sarif"
    code = main(["scan", PY, "--engine", "python-ast", "-f", "sarif", "-o", str(out),
                 "--out-dir", str(tmp_path / "results"), "--fail-on", "none"])
    assert code == EXIT_OK
    assert capsys.readouterr().out == ""
    assert json.loads(out.read_text())["version"] == "2.1.0"
    assert {p.name for p in (tmp_path / "results").iterdir()} == {"report.md", "findings.jsonl", "results.sarif"}


def test_json_format_to_stdout(capsys):
    main(["scan", PY, "--engine", "python-ast", "-f", "json", "--fail-on", "none", "--rules", "RW-PY-SQLI"])
    doc = json.loads(capsys.readouterr().out)
    assert {f["rule_id"] for f in doc["findings"]} == {"RW-PY-SQLI"}


def test_rules_command(capsys):
    assert main(["rules", "-f", "json"]) == EXIT_OK
    ids = [r["id"] for r in json.loads(capsys.readouterr().out)]
    assert "RW-PY-SQLI" in ids and "RW-SECRET-AWS" in ids and ids == sorted(ids)


def test_bad_severity_is_a_usage_error(capsys):
    import pytest
    with pytest.raises(SystemExit) as exc:
        main(["scan", PY, "--fail-on", "urgent"])
    assert exc.value.code == 2
    capsys.readouterr()


def test_no_command_prints_help(capsys):
    assert main([]) == EXIT_ERROR
    assert "scan" in capsys.readouterr().out
