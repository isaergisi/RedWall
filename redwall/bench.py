"""Benchmark scoring, compatible with the OWASP Benchmark expected-results CSV.

CSV rows look like ``BenchmarkTest00001,sqli,true,89`` (test name, category,
real vulnerability, CWE). A test case is the file whose name (without
extension) equals the test name. A test counts as *flagged* when RedWall
reports a finding with a matching CWE in that file.

Scores follow OWASP's method: per category true positive rate (TPR), false
positive rate (FPR) and Youden index (TPR - FPR), then their averages.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set

from .models import ScanResult
from .scanner import ScanOptions, scan

# CWEs that RedWall and benchmarks label differently but mean the same thing.
_EQUIVALENT = [{"94", "95", "1336"}, {"327", "328"}]


def _cwe_number(value: str) -> str:
    return value.strip().upper().replace("CWE-", "")


def _equivalents(cwe: str) -> Set[str]:
    for group in _EQUIVALENT:
        if cwe in group:
            return group
    return {cwe}


@dataclass
class CategoryScore:
    category: str
    cwe: str
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def tpr(self) -> float:
        real = self.tp + self.fn
        return self.tp / real if real else 0.0

    @property
    def fpr(self) -> float:
        fake = self.fp + self.tn
        return self.fp / fake if fake else 0.0

    @property
    def precision(self) -> float:
        flagged = self.tp + self.fp
        return self.tp / flagged if flagged else 0.0

    @property
    def score(self) -> float:
        return self.tpr - self.fpr

    def to_dict(self) -> dict:
        return {
            "category": self.category, "cwe": self.cwe,
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "tpr": round(self.tpr, 4), "fpr": round(self.fpr, 4),
            "precision": round(self.precision, 4), "score": round(self.score, 4),
        }


@dataclass
class BenchReport:
    categories: List[CategoryScore]
    tests: int
    missing_files: List[str] = field(default_factory=list)

    @property
    def avg_tpr(self) -> float:
        return sum(c.tpr for c in self.categories) / len(self.categories) if self.categories else 0.0

    @property
    def avg_fpr(self) -> float:
        return sum(c.fpr for c in self.categories) / len(self.categories) if self.categories else 0.0

    @property
    def avg_score(self) -> float:
        return self.avg_tpr - self.avg_fpr

    def to_dict(self) -> dict:
        return {
            "tests": self.tests,
            "avg_tpr": round(self.avg_tpr, 4),
            "avg_fpr": round(self.avg_fpr, 4),
            "avg_score": round(self.avg_score, 4),
            "categories": [c.to_dict() for c in self.categories],
            "missing_files": self.missing_files,
        }


def load_expected(path: Path) -> List[tuple]:
    rows = []
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if not row or row[0].lstrip().startswith("#"):
                continue
            name, category, real, cwe = (c.strip() for c in row[:4])
            rows.append((name, category, real.lower() == "true", _cwe_number(cwe)))
    return rows


def score(result: ScanResult, expected: List[tuple]) -> BenchReport:
    flagged: Dict[str, Set[str]] = defaultdict(set)  # test name -> CWEs reported
    files: Set[str] = set()
    for f in result.findings:
        stem = Path(f.path).stem
        if f.cwe:
            flagged[stem].add(_cwe_number(f.cwe))
    for p in Path(result.root).rglob("*"):
        if p.is_file():
            files.add(p.stem)

    cats: Dict[str, CategoryScore] = {}
    missing: List[str] = []
    for name, category, real, cwe in expected:
        if name not in files:
            missing.append(name)
            continue
        cs = cats.setdefault(category, CategoryScore(category, cwe))
        hit = bool(flagged.get(name, set()) & _equivalents(cwe))
        if real and hit:
            cs.tp += 1
        elif real:
            cs.fn += 1
        elif hit:
            cs.fp += 1
        else:
            cs.tn += 1
    return BenchReport(sorted(cats.values(), key=lambda c: c.category), len(expected) - len(missing), missing)


def run_benchmark(path: Path, expected_csv: Path) -> BenchReport:
    result = scan(path, options=ScanOptions(engines=["python-ast", "opengrep"]))
    return score(result, load_expected(expected_csv))


def format_report(report: BenchReport) -> str:
    lines = [f"{'category':14} {'CWE':>5} {'TP':>4} {'FN':>4} {'FP':>4} {'TN':>4} {'TPR':>6} {'FPR':>6} {'score':>6}"]
    for c in report.categories:
        lines.append(f"{c.category:14} {c.cwe:>5} {c.tp:4} {c.fn:4} {c.fp:4} {c.tn:4} "
                     f"{c.tpr:6.0%} {c.fpr:6.0%} {c.score:+6.2f}")
    lines.append("")
    lines.append(f"{report.tests} test cases. Average TPR {report.avg_tpr:.0%}, FPR {report.avg_fpr:.0%}, "
                 f"score (TPR - FPR) {report.avg_score:+.2f}")
    if report.missing_files:
        lines.append(f"warning: {len(report.missing_files)} expected test files were not found")
    return "\n".join(lines)
