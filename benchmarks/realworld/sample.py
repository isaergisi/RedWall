#!/usr/bin/env python3
"""Draw a reproducible random sample of high-priority (P1/P2) findings from the held-out projects.

The sample is labelled by hand (true / false positive, with a one-line reason) in
precision-sample.json. Usage, after run.py has filled the cache:

    python benchmarks/realworld/sample.py --cache DIR [--n 40] > /tmp/sample.json
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from run import REPO_ROOT, match, redwall_scan  # noqa: E402

SEED = 20261123


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", required=True)
    ap.add_argument("--n", type=int, default=40)
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--exclude", help="JSON file of an earlier sample whose findings are left out")
    args = ap.parse_args()
    manifest = json.loads((HERE / "cves.json").read_text(encoding="utf-8"))
    pool = []
    for name, proj in manifest["projects"].items():
        target = Path(args.cache) / f"{name}-vuln" / proj["scope"]
        doc = redwall_scan(REPO_ROOT, target)
        known = set()
        for case in manifest["cases"]:
            if case["project"] == name:
                known |= {(h["path"], h["line"]) for h in match(doc["findings"], case, proj["scope"])}
        for f in doc["findings"]:
            if f["triage"]["tier"] in ("P1", "P2") and (f["path"], f["line"]) not in known:
                pool.append({"project": name, "path": f["path"], "line": f["line"], "rule_id": f["rule_id"],
                             "tier": f["triage"]["tier"], "score": f["triage"]["score"],
                             "confidence": f["confidence"], "snippet": f["snippet"],
                             "trace": [s["note"] for s in f["trace"]]})
    if args.exclude:
        old = json.loads(Path(args.exclude).read_text(encoding="utf-8"))["sample"]
        seen = {(f["project"], f["path"], f["line"], f["rule_id"]) for f in old}
        pool = [f for f in pool if (f["project"], f["path"], f["line"], f["rule_id"]) not in seen]
    pool.sort(key=lambda f: (f["project"], f["path"], f["line"], f["rule_id"]))
    sample = random.Random(args.seed).sample(pool, min(args.n, len(pool)))
    sample.sort(key=lambda f: (f["project"], f["path"], f["line"]))
    json.dump({"seed": args.seed, "pool_size": len(pool), "sample": sample}, sys.stdout, indent=1, ensure_ascii=False)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
