#!/usr/bin/env python3
"""Held-out real-world check: does RedWall find published vulnerabilities in projects it never saw?

Usage:
    python benchmarks/realworld/run.py [--cache DIR] [--redwall-src DIR ...] [--bandit] [--out FILE]

For every project in cves.json the script checks out the vulnerable ref (shallow), scans the
project scope with the RedWall source tree(s) given (default: this checkout), and reports for every
case whether a finding with the right CWE lands on a ground-truth sink, with its confidence and its
rank in the prioritised list. When a ``fixed_ref`` exists it also scans the fixed release and reports
whether the finding went away. Standard library only; needs ``git`` and network access to GitHub.
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
EQUIV = [{"94", "95", "1336"}, {"327", "328"}]


def cwe_ok(found: Optional[str], wanted: str) -> bool:
    if not found:
        return False
    n = found.upper().replace("CWE-", "")
    for group in EQUIV:
        if wanted in group:
            return n in group
    return n == wanted


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
    prefix = "" if scope in (".", "") else scope.rstrip("/") + "/"
    hits = []
    for sink in case["sinks"]:
        rel = sink["file"][len(prefix):] if sink["file"].startswith(prefix) else sink["file"]
        lo, hi = sink["lines"]
        for f in findings:
            if f["path"] == rel and lo <= f["line"] <= hi and cwe_ok(f.get("cwe"), case["cwe"]):
                hits.append({**f, "_shared": bool(sink.get("shared"))})
    return hits


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
    ap.add_argument("--cache", default=str(REPO_ROOT / ".cache" / "realworld"))
    ap.add_argument("--redwall-src", action="append", metavar="LABEL=DIR",
                    help="RedWall source tree(s) to compare, e.g. faz0=/tmp/rw-faz0 (default: current=<repo>)")
    ap.add_argument("--bandit", action="store_true", help="also run Bandit (if installed) as a reference")
    ap.add_argument("--only", action="append", help="only these projects")
    ap.add_argument("--out", default=None, help="write the full JSON results here")
    args = ap.parse_args()

    manifest = json.loads((HERE / "cves.json").read_text(encoding="utf-8"))
    tools: Dict[str, Path] = {}
    for spec in args.redwall_src or [f"current={REPO_ROOT}"]:
        label, _, path = spec.partition("=")
        tools[label] = Path(path).resolve()
    cache = Path(args.cache)
    results: dict = {"projects": {}, "cases": []}

    for name, proj in manifest["projects"].items():
        if args.only and name not in args.only:
            continue
        print(f"== {name} ({proj['repo']}@{proj['ref']})", file=sys.stderr)
        vuln_dir = checkout(proj["repo"], proj["ref"], cache / f"{name}-vuln")
        target = vuln_dir / proj["scope"]
        scans = {label: redwall_scan(src, target) for label, src in tools.items()}
        if args.bandit:
            b = bandit_scan(target)
            if b is not None:
                scans["bandit"] = b
        fixed = {}
        if proj.get("fixed_ref"):
            fixed_dir = checkout(proj["repo"], proj["fixed_ref"], cache / f"{name}-fixed")
            fixed = {label: redwall_scan(src, fixed_dir / proj["scope"]) for label, src in tools.items()}
        results["projects"][name] = {
            label: {"findings": len(s["findings"]), "seconds": s.get("_seconds"),
                    "by_priority": s.get("summary", {}).get("by_priority")}
            for label, s in scans.items()}
        for case in manifest["cases"]:
            if case["project"] != name:
                continue
            row = {"id": case["id"], "project": name, "advisory": case["advisory"], "cwe": case["cwe"], "tools": {}}
            for label, s in scans.items():
                hits = match(s["findings"], case, proj["scope"])
                row["tools"][label] = summarise_hit(hits, len(s["findings"]))
                if label in fixed:
                    row["tools"][label]["fixed_release_still_flagged"] = _still_flagged(
                        hits, fixed[label]["findings"], case)
            results["cases"].append(row)

    text = json.dumps(results, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    print(render(results, list(tools) + (["bandit"] if args.bandit else [])))
    return 0


def _still_flagged(hits: List[dict], fixed_findings: List[dict], case: dict) -> Optional[bool]:
    """Same rule in the same function of the same file after the fix? (lines move, functions rarely do)."""
    if not hits:
        return None
    keys = {(h["path"], h.get("function"), h["rule_id"]) for h in hits}
    return any((f["path"], f.get("function"), f["rule_id"]) in keys for f in fixed_findings)


def render(results: dict, labels: List[str]) -> str:
    lines = ["| case | advisory | CWE | " + " | ".join(labels) + " |",
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


if __name__ == "__main__":
    raise SystemExit(main())
