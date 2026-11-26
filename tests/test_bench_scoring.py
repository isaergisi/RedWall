"""Benchmark scoring (phase 3): four levels, fixed-tree negatives, the held-out seal, synthetic ground truth."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "benchmarks" / "realworld"))

import score  # noqa: E402

CASE = {
    "cwe": "89",
    "sources": [{"file": "pkg/views.py", "lines": [10, 10]}],
    "sinks": [{"file": "pkg/service.py", "lines": [20, 22]},
              {"file": "pkg/db.py", "lines": [5, 5], "shared": True}],
}


def finding(path, line, cwe="CWE-89", trace=(), confidence="high"):
    return {"path": path, "line": line, "cwe": cwe, "trace": list(trace), "confidence": confidence}


def levels(findings, case=CASE, scope="."):
    return score.case_levels(findings, case, scope)["levels"]


def test_levels_are_nested_from_file_to_flow():
    assert levels([]) == {"file": False, "vuln": False, "exact": False, "flow": False}
    assert levels([finding("pkg/service.py", 99)]) == {"file": True, "vuln": False, "exact": False, "flow": False}
    assert levels([finding("pkg/db.py", 5)]) == {"file": True, "vuln": True, "exact": False, "flow": False}
    assert levels([finding("pkg/service.py", 21)]) == {"file": True, "vuln": True, "exact": True, "flow": False}
    traced = finding("pkg/service.py", 21, trace=[{"path": "pkg/views.py", "line": 10, "note": "src"},
                                                  {"line": 21, "note": "sink"}])
    assert levels([traced]) == {"file": True, "vuln": True, "exact": True, "flow": True}


def test_flow_needs_the_trace_to_start_at_the_source():
    # A step without a path is in the finding's own file: a same-file line 10 is not the source.
    same_file = finding("pkg/service.py", 21, trace=[{"line": 10, "note": "src"}])
    assert not levels([same_file])["flow"]
    # The source appearing later in the trace (not where the value enters) does not count.
    late = finding("pkg/service.py", 21, trace=[{"line": 3, "note": "x"}, {"path": "pkg/views.py", "line": 10, "note": "y"}])
    assert not levels([late])["flow"]


def test_cwe_must_match_and_equivalents_are_accepted():
    assert not levels([finding("pkg/service.py", 21, cwe="CWE-78")])["file"]
    code_case = {**CASE, "cwe": "94"}
    assert levels([finding("pkg/service.py", 21, cwe="CWE-95")], code_case)["exact"]


def test_scope_prefix_is_stripped():
    case = {**CASE, "sinks": [{"file": "web/pkg/service.py", "lines": [20, 22]}], "sources": []}
    assert levels([finding("pkg/service.py", 20)], case, scope="web")["exact"]


def test_line_map_follows_the_fix():
    old = "a\nb\nsql = '%s' % x\ncur.execute(sql)\nz\n"
    new = "header\na\nb\nsql = '?'\ncur.execute(sql, (x,))\nz\n"
    m = score.line_map(old, new)
    assert m([1, 1]) == (2, 2)          # unchanged line moved down by one
    assert m([3, 4]) == (4, 5)          # replaced block maps to the replacement
    assert m([5, 5]) == (6, 6)


def test_confusion_counts_vulnerable_and_fixed_trees():
    rows = [
        {"tools": {"t": {"vulnerable": {"file": 1, "vuln": 1, "exact": 1, "flow": 0},
                         "fixed": {"file": 1, "vuln": 0, "exact": 0, "flow": 0}}}},
        {"tools": {"t": {"vulnerable": {"file": 0, "vuln": 0, "exact": 0, "flow": 0}}}},
    ]
    m = score.confusion(rows, "t")
    assert (m["vuln"]["tp"], m["vuln"]["fn"], m["vuln"]["fp"], m["vuln"]["tn"]) == (1, 1, 0, 1)
    assert m["vuln"]["precision"] == 1.0 and m["vuln"]["recall"] == 0.5
    assert (m["file"]["fp"], m["file"]["precision"]) == (1, 0.5)
    assert m["flow"]["recall"] == 0.0 and m["flow"]["precision"] is None


def test_heldout_manifest_is_sealed():
    manifest = json.loads((ROOT / "benchmarks" / "heldout" / "cases.json").read_text(encoding="utf-8"))
    seal = (ROOT / "benchmarks" / "heldout" / "SEAL").read_text(encoding="utf-8").strip()
    assert score.manifest_digest(manifest) == seal, "the held-out manifest changed after it was sealed"
    for case in manifest["cases"]:
        assert case["sources"] and case["sinks"] and case["project"] in manifest["projects"]


def test_dev_manifest_has_sources_for_every_case():
    manifest = json.loads((ROOT / "benchmarks" / "realworld" / "cves.json").read_text(encoding="utf-8"))
    assert all(case.get("sources") for case in manifest["cases"])


def test_synthetic_scenarios_have_twins_and_markers():
    import importlib.util

    spec = importlib.util.spec_from_file_location("synthetic_run", ROOT / "benchmarks" / "synthetic" / "run.py")
    synthetic = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(synthetic)

    manifest = json.loads((ROOT / "benchmarks" / "synthetic" / "cases.json").read_text(encoding="utf-8"))
    for case in manifest["cases"]:
        for variant in ("vuln", "safe"):
            gt = synthetic.ground_truth(ROOT / "benchmarks" / "synthetic" / "cases" / case["id"] / variant)
            assert gt["sources"], (case["id"], variant)
            assert any(not s["shared"] for s in gt["sinks"]), (case["id"], variant)
