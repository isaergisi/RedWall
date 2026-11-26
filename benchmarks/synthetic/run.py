#!/usr/bin/env python3
"""Synthetic multi-file suite: vulnerable variants vs safe twins, scored at the four real-world levels.

Usage:
    python benchmarks/synthetic/run.py [--redwall-src LABEL=DIR ...] [--out FILE]

Every scenario directory under cases/ has ``vuln/`` and ``safe/``. Ground truth comes from ``# gt:``
markers in the code (see cases.json). Vulnerable variants give TP/FN, safe twins FP/TN, per level
(file, vuln, exact, flow; see benchmarks/realworld/score.py). Scenarios marked ``uncertain`` are kept
out of the confusion matrix and reported on their own: a finding there must not claim high confidence.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Dict, List

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
sys.path.insert(0, str(REPO_ROOT / "benchmarks" / "realworld"))
import score  # noqa: E402


def redwall_scan(src: Path, target: Path) -> dict:
    spec = importlib.util.spec_from_file_location("realworld_run", REPO_ROOT / "benchmarks" / "realworld" / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod.redwall_scan(src, target)

MARK = re.compile(r"#\s*gt:(source|sink-shared|sink)\b")


def ground_truth(variant_dir: Path) -> Dict[str, list]:
    sources, sinks = [], []
    for path in sorted(variant_dir.rglob("*.py")):
        rel = path.relative_to(variant_dir).as_posix()
        for no, text in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for kind in MARK.findall(text):
                entry = {"file": rel, "lines": [no, no]}
                if kind == "source":
                    sources.append(entry)
                else:
                    sinks.append({**entry, "shared": kind == "sink-shared"})
    return {"sources": sources, "sinks": sinks}


def run(tools: Dict[str, Path]) -> dict:
    manifest = json.loads((HERE / "cases.json").read_text(encoding="utf-8"))
    rows: List[dict] = []
    uncertain: List[dict] = []
    for case in manifest["cases"]:
        row = {"id": case["id"], "cwe": case["cwe"], "expect": case["expect"], "tools": {}}
        for label, src in tools.items():
            entry: dict = {}
            for variant in ("vuln", "safe"):
                vdir = HERE / "cases" / case["id"] / variant
                gt = {**ground_truth(vdir), "cwe": case["cwe"]}
                doc = redwall_scan(src, vdir)
                scored = score.case_levels(doc["findings"], gt, ".")
                key = "vulnerable" if variant == "vuln" else "fixed"
                entry[key] = scored["levels"]
                entry[f"{variant}_engines"] = [e.get("status") for e in doc.get("engines", [])]
                if variant == "vuln":
                    entry["certain_claim"] = any(h.get("confidence") == "high" for h in scored["hits"]["vuln"])
            row["tools"][label] = entry
        (uncertain if case["expect"] == "uncertain" else rows).append(row)
    labels = list(tools)
    return {"cases": rows, "uncertain": uncertain,
            "metrics": {label: score.confusion(rows, label) for label in labels}}


def render(results: dict, labels: List[str]) -> str:
    lines = ["| scenario | " + " | ".join(f"{lbl} vuln (file/vuln/exact/flow) | {lbl} safe" for lbl in labels) + " |",
             "|---|" + "---|---|" * len(labels)]
    mark = lambda lv: "".join("x" if lv[k] else "." for k in score.LEVELS)  # noqa: E731
    for row in results["cases"]:
        cells = []
        for lbl in labels:
            e = row["tools"][lbl]
            cells += [mark(e["vulnerable"]), "quiet" if not e["fixed"]["vuln"] else "FLAGGED"]
        lines.append(f"| {row['id']} | " + " | ".join(cells) + " |")
    lines += ["", "| tool | level | TP | FN | FP | TN | precision | recall | F1 |",
              "|---|---|---|---|---|---|---|---|---|"]
    fmt = lambda x: "n/a" if x is None else f"{x:.2f}"  # noqa: E731
    for lbl in labels:
        for lvl in score.LEVELS:
            c = results["metrics"][lbl][lvl]
            lines.append(f"| {lbl} | {lvl} | {c['tp']} | {c['fn']} | {c['fp']} | {c['tn']} | "
                         f"{fmt(c['precision'])} | {fmt(c['recall'])} | {fmt(c['f1'])} |")
    for row in results["uncertain"]:
        for lbl in labels:
            e = row["tools"][lbl]
            verdict = "claims certainty (wrong)" if e["certain_claim"] else (
                "reported without certainty" if e["vulnerable"]["vuln"] else "not reported")
            lines.append(f"\n{row['id']} ({lbl}): {verdict}; safe twin "
                         + ("flagged" if e["fixed"]["vuln"] else "quiet"))
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--redwall-src", action="append", metavar="LABEL=DIR")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    tools = {}
    for spec in args.redwall_src or [f"current={REPO_ROOT}"]:
        label, _, path = spec.partition("=")
        tools[label] = Path(path).resolve()
    results = run(tools)
    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(render(results, list(tools)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
