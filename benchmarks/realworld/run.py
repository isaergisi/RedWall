#!/usr/bin/env python3
"""Real-world check: does RedWall find published vulnerabilities, and stay quiet once they are fixed?

Usage:
    python benchmarks/realworld/run.py [--manifest FILE] [--cache DIR] [--redwall-src LABEL=DIR ...]
                                       [--bandit] [--out FILE] [--show-cases]

For every project in the manifest (default: the phase 2 set, cves.json) the script checks out the
vulnerable ref (shallow), scans the project scope with the RedWall source tree(s) given (default: this
checkout), and scores every case at four levels (file, vuln, exact, flow; see score.py). When a
``fixed_ref`` exists it also scans the fixed tree, maps the case's lines onto it, and counts a hit there
as a false positive. It prints TP/FP/TN/FN, precision, recall and F1 per level.

A manifest with a ``SEAL`` file next to it is a held-out set: the script refuses to score it if its
digest changed (unless --allow-unsealed) and prints only aggregate numbers (unless --show-cases).
Standard library only; needs ``git`` and network access to GitHub.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import score  # noqa: E402
from score import LEVELS, cwe_ok  # noqa: E402,F401


def checkout(repo: str, ref: str, dest: Path) -> Path:
    if (dest / ".git").is_dir():
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    run = lambda *a: subprocess.run(["git", *a], cwd=dest, check=True, capture_output=True, text=True)  # noqa: E731
    run("init", "-q")
    run("remote", "add", "origin", f"https://github.com/{repo}.git")
    try:
        run("fetch", "-q", "--depth", "1", "origin", ref)
    except subprocess.CalledProcessError:
        run("fetch", "-q", "--depth", "1", "origin", f"refs/tags/{ref}")
    run("-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD")
    return dest


def redwall_scan(src: Path, target: Path) -> dict:
    """Run a given RedWall source tree in an isolated interpreter (scanned code never on sys.path)."""
    code = ("import sys; sys.path.insert(0, sys.argv[1]); from redwall.cli import main; "
            "sys.exit(main(sys.argv[2:]))")
    started = time.monotonic()
    proc = subprocess.run([sys.executable, "-I", "-c", code, str(src), "scan", str(target), "-f", "json",
                           "--engine", "python-ast", "--fail-on", "none"],
                          capture_output=True, text=True, cwd=str(target))
    if proc.returncode != 0:
        raise RuntimeError(f"redwall failed on {target}: {proc.stderr[-500:]}")
    doc = json.loads(proc.stdout)
    doc["_seconds"] = round(time.monotonic() - started, 1)
    return doc


def bandit_scan(target: Path) -> Optional[dict]:
    exe = shutil.which("bandit")
    if not exe:
        return None
    proc = subprocess.run([exe, "-r", "-q", "-f", "json", "."], capture_output=True, text=True, cwd=str(target))
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    findings = []
    for r in doc.get("results", []):
        cwe = (r.get("issue_cwe") or {}).get("id")
        findings.append({"path": r["filename"].lstrip("./"), "line": r["line_number"],
                         "cwe": f"CWE-{cwe}" if cwe else None, "rule_id": r["test_id"],
                         "severity": r["issue_severity"].lower(), "confidence": r["issue_confidence"].lower()})
    return {"findings": findings}


def match(findings: List[dict], case: dict, scope: str) -> List[dict]:
    """Findings on a sink line with the right CWE (``_shared`` set for generic helper sinks)."""
    hits = score.case_levels(findings, case, scope)["hits"]
    exact = {id(f) for f in hits["exact"]}
    return [{**f, "_shared": id(f) not in exact} for f in hits["vuln"]]


def fixed_remap(vuln_dir: Path, fixed_dir: Path):
    """Ground-truth range at ``ref`` -> the same code in the fixed tree (line diff per file)."""
    cache: dict = {}

    def remap(file: str, lines):
        if file not in cache:
            old, new = vuln_dir / file, fixed_dir / file
            if old.is_file() and new.is_file():
                cache[file] = score.line_map(old.read_text(encoding="utf-8", errors="replace"),
                                             new.read_text(encoding="utf-8", errors="replace"))
            else:
                cache[file] = None
        fn = cache[file]
        return fn(lines) if fn else (-1, -1)  # file gone after the fix: nothing can match there
    return remap


def summarise_hit(hits: List[dict], total: int) -> dict:
    if not hits:
        return {"detected": False}
    specific = [h for h in hits if not h["_shared"]]
    best = min(specific or hits, key=lambda h: (h.get("triage", {}).get("rank", 10 ** 6), -_conf(h)))
    out = {"detected": True, "only_shared_sink": not specific, "rule": best.get("rule_id"),
           "line": best["line"], "confidence": best.get("confidence"), "of": total}
    tri = best.get("triage")
    if tri:
        out.update(rank=tri["rank"], tier=tri["tier"], score=tri["score"])
    return out


def _conf(h: dict) -> int:
    return {"high": 2, "medium": 1, "low": 0}.get(h.get("confidence", "low"), 0)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--manifest", default=str(HERE / "cves.json"))
    ap.add_argument("--cache", default=str(REPO_ROOT / ".cache" / "realworld"))
    ap.add_argument("--redwall-src", action="append", metavar="LABEL=DIR",
                    help="RedWall source tree(s) to compare, e.g. before=/tmp/rw-main (default: current=<repo>)")
    ap.add_argument("--bandit", action="store_true", help="also run Bandit (if installed) as a reference")
    ap.add_argument("--only", action="append", help="only these projects")
    ap.add_argument("--no-fixed", action="store_true", help="skip the fixed trees (no FP/TN numbers)")
    ap.add_argument("--show-cases", action="store_true", help="print per-case rows even for a sealed set")
    ap.add_argument("--allow-unsealed", action="store_true", help="score a sealed set whose digest changed")
    ap.add_argument("--out", default=None, help="write the full JSON results here")
    args = ap.parse_args()

    manifest_path = Path(args.manifest).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    seal_file = manifest_path.parent / "SEAL"
    sealed = seal_file.is_file()
    seal_ok = None
    if sealed:
        seal_ok = seal_file.read_text(encoding="utf-8").strip() == score.manifest_digest(manifest)
        if not seal_ok and not args.allow_unsealed:
            print(f"{manifest_path}: digest does not match {seal_file}; the held-out set was modified. "
                  "Pass --allow-unsealed to score it anyway (the run is then marked unsealed).", file=sys.stderr)
            return 2
    tools: Dict[str, Path] = {}
    for spec in args.redwall_src or [f"current={REPO_ROOT}"]:
        label, _, path = spec.partition("=")
        tools[label] = Path(path).resolve()
    cache = Path(args.cache)
    cache_key = "" if manifest_path.name == "cves.json" else f"{manifest_path.parent.name}-"
    results: dict = {"manifest": str(manifest_path.relative_to(REPO_ROOT) if manifest_path.is_relative_to(REPO_ROOT)
                                     else manifest_path),
                     "sealed": sealed, "seal_ok": seal_ok, "projects": {}, "cases": []}

    for name, proj in manifest["projects"].items():
        if args.only and name not in args.only:
            continue
        print(f"== {name} ({proj['repo']}@{proj['ref'][:12]})", file=sys.stderr)
        vuln_dir = checkout(proj["repo"], proj["ref"], cache / f"{cache_key}{name}-vuln")
        target = vuln_dir / proj["scope"]
        scans = {label: redwall_scan(src, target) for label, src in tools.items()}
        if args.bandit:
            b = bandit_scan(target)
            if b is not None:
                scans["bandit"] = b
        fixed, remap = {}, None
        if proj.get("fixed_ref") and not args.no_fixed:
            fixed_dir = checkout(proj["repo"], proj["fixed_ref"], cache / f"{cache_key}{name}-fixed")
            fixed = {label: redwall_scan(src, fixed_dir / proj["scope"]) for label, src in tools.items()}
            if "bandit" in scans:
                b = bandit_scan(fixed_dir / proj["scope"])
                if b is not None:
                    fixed["bandit"] = b
            remap = fixed_remap(vuln_dir, fixed_dir)
        results["projects"][name] = {
            label: {"findings": len(s["findings"]), "seconds": s.get("_seconds"),
                    "fixed_findings": len(fixed[label]["findings"]) if label in fixed else None,
                    "by_priority": s.get("summary", {}).get("by_priority"),
                    "engines": s.get("engines")}
            for label, s in scans.items()}
        for case in manifest["cases"]:
            if case["project"] != name:
                continue
            row = {"id": case["id"], "project": name, "advisory": case["advisory"], "cwe": case["cwe"], "tools": {}}
            for label, s in scans.items():
                scored = score.case_levels(s["findings"], case, proj["scope"])
                hits = match(s["findings"], case, proj["scope"])
                entry = summarise_hit(hits, len(s["findings"]))
                entry["vulnerable"] = scored["levels"]
                if label in fixed:
                    entry["fixed"] = score.case_levels(fixed[label]["findings"], case, proj["scope"], remap)["levels"]
                    entry["fixed_release_still_flagged"] = _still_flagged(hits, fixed[label]["findings"], case)
                row["tools"][label] = entry
            results["cases"].append(row)

    labels = list(scans) if results["cases"] else list(tools)
    results["metrics"] = {label: score.confusion(results["cases"], label) for label in labels}
    text = json.dumps(results, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    show_cases = args.show_cases or not sealed
    print(render(results, labels, show_cases))
    return 0


def _still_flagged(hits: List[dict], fixed_findings: List[dict], case: dict) -> Optional[bool]:
    """Same rule in the same function of the same file after the fix? (lines move, functions rarely do)."""
    if not hits:
        return None
    keys = {(h["path"], h.get("function"), h["rule_id"]) for h in hits}
    return any((f["path"], f.get("function"), f["rule_id"]) in keys for f in fixed_findings)


def render(results: dict, labels: List[str], show_cases: bool = True) -> str:
    lines = []
    if results.get("sealed"):
        lines.append("held-out set, " + ("seal verified" if results.get("seal_ok") else "UNSEALED (manifest modified)"))
        lines.append("")
    lines += render_metrics(results, labels)
    if not show_cases:
        return "\n".join(lines)
    lines += ["", "| case | advisory | CWE | " + " | ".join(labels) + " |",
              "|---|---|---|" + "---|" * len(labels)]
    for row in results["cases"]:
        cells = []
        for label in labels:
            r = row["tools"].get(label)
            if r is None:
                cells.append("n/a")
            elif not r["detected"]:
                cells.append("missed")
            else:
                cell = f"{r.get('confidence', '')}"
                if "rank" in r:
                    cell += f", #{r['rank']}/{r['of']} {r['tier']}"
                if r.get("only_shared_sink"):
                    cell += ", shared sink only"
                if r.get("fixed_release_still_flagged") is True:
                    cell += ", still flagged after fix"
                elif r.get("fixed_release_still_flagged") is False:
                    cell += ", cleared after fix"
                cells.append(cell)
        lines.append(f"| {row['id']} | {row['advisory']} | {row['cwe']} | " + " | ".join(cells) + " |")
    totals = []
    for label in labels:
        rows = [r["tools"].get(label) for r in results["cases"] if r["tools"].get(label)]
        det = sum(1 for r in rows if r["detected"])
        strict = sum(1 for r in rows if r["detected"] and not r.get("only_shared_sink"))
        totals.append(f"{label}: {det}/{len(rows)} detected ({strict} at an advisory-specific sink)")
    lines += ["", "; ".join(totals)]
    return "\n".join(lines)


def render_metrics(results: dict, labels: List[str]) -> List[str]:
    """Per tool and level: TP/FN on vulnerable trees, FP/TN on fixed trees, precision/recall/F1."""
    def pct(x):
        return "n/a" if x is None else f"{x:.2f}"
    lines = ["| tool | level | TP | FN | FP | TN | precision | recall | F1 |", "|---|---|---|---|---|---|---|---|---|"]
    for label in labels:
        m = results["metrics"].get(label, {})
        for lvl in LEVELS:
            c = m.get(lvl)
            if c:
                lines.append(f"| {label} | {lvl} | {c['tp']} | {c['fn']} | {c['fp']} | {c['tn']} | "
                             f"{pct(c['precision'])} | {pct(c['recall'])} | {pct(c['f1'])} |")
    totals = []
    for label in labels:
        n = sum(p[label]["findings"] for p in results["projects"].values() if label in p)
        secs = sum(p[label].get("seconds") or 0 for p in results["projects"].values() if label in p)
        totals.append(f"{label}: {n} findings on the vulnerable trees" + (f", {secs:.0f} s" if secs else ""))
    return lines + ["", "; ".join(totals),
                    "FP/TN come from the fixed trees: precision here is case-level against the fixed release."]


if __name__ == "__main__":
    raise SystemExit(main())
