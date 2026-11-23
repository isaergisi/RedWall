from pathlib import Path

from redwall.bench import load_expected, run_benchmark

MINI = Path(__file__).resolve().parent.parent / "benchmarks" / "mini"


def test_expected_csv_parsing():
    rows = load_expected(MINI / "expectedresults-mini.csv")
    assert len(rows) == 20
    assert rows[0] == ("BenchmarkTest00001", "sqli", True, "89")


def test_mini_benchmark_score_does_not_regress():
    report = run_benchmark(MINI / "testcode", MINI / "expectedresults-mini.csv")
    assert report.tests == 20 and not report.missing_files
    cats = {c.category: c for c in report.categories}
    # The allow-list guard (00019) and the `sh -c` list (00020) are handled since phase 1.
    assert (cats["sqli"].tp, cats["sqli"].fp) == (3, 0)
    assert (cats["cmdi"].tp, cats["cmdi"].fn) == (3, 0)
    assert report.avg_score == 1.0
