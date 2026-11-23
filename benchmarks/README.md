# Benchmarks

RedWall measures every change. Two suites are wired in today; both use the
OWASP Benchmark expected-results CSV format (`test name, category, real, cwe`).

| Suite | What it is | Command |
|---|---|---|
| `mini/` | 20 small Flask handlers written for RedWall's own tests, including a few traps. Useful as a regression check, **not** a real measurement. | `redwall bench benchmarks/mini/testcode --expected benchmarks/mini/expectedresults-mini.csv` |
| OWASP BenchmarkPython | The public, labelled Python benchmark. This is the number to publish. | `benchmarks/owasp_python.sh` |

Scores follow OWASP's method: per category true positive rate (TPR), false
positive rate (FPR) and their difference (Youden index), then the averages.
A tool that flags everything scores 0, a perfect tool scores 1.

The two known misses of phase 0 in `mini/` are handled since phase 1:
`BenchmarkTest00019` (a value checked against an allow-list) is no longer
reported, and `BenchmarkTest00020` (a command list run through `sh -c`) is.

## OWASP BenchmarkPython results

`benchmarks/owasp_python.sh` scans the whole checkout, not only `testcode/`, so
the helper modules (`helpers/separate_request.py`, `helpers/utils.py` ...) are
summarised the way they would be in a real application. Scanning `testcode/`
alone scores +0.89 instead, because the request wrapper is then invisible.

| Category | Phase 0 | Phase 1 |
|---|---|---|
| cmdi | -0.25 | +0.71 |
| codeinj | +0.03 | +1.00 |
| deserialization | +0.67 | +0.94 |
| hash | +1.00 | +1.00 |
| ldapi | 0 (no rule) | +1.00 |
| pathtraver | +0.03 | +1.00 |
| redirect | 0 (no rule) | +1.00 |
| securecookie | 0 (no rule) | +1.00 |
| sqli | +0.60 | +1.00 |
| trustbound | 0 (no rule) | +1.00 |
| weakrand | 0 (no rule) | +1.00 |
| xpathi | 0 (no rule) | +1.00 |
| xss | 0 (no rule) | +1.00 |
| xxe | 0 (no rule) | +0.95 |
| **Average** | **+0.15** | **+0.97** |

The phase 1 rules were designed after reading the benchmark's test patterns,
so this is an in-sample number. The techniques are generic (no benchmark file
names, helper names or constants are special-cased), and real projects were
checked for lost findings and noise before the change was merged. The
remaining false positives come from `request.path.split("/")[1]`, which is the
constant route segment `benchmark` in this suite; RedWall treats it as an
unknown value on purpose.

## Held-out real-world projects (phase 2)

`realworld/cves.json` lists 17 published vulnerabilities (7 CVEs, 2 more fixed in the same Gerapy security
release, 8 GitHub Security Lab advisories for Archery) in 8 projects that were never looked at while the phase
0/1 rules were written. `realworld/run.py` checks out each vulnerable (and, when there is one, fixed) release,
scans it with one or more RedWall source trees and optionally Bandit, and reports whether a finding with the
right CWE lands on the ground-truth sink, with its confidence and priority rank:

```bash
python benchmarks/realworld/run.py --bandit \
    --redwall-src faz1=/path/to/old/checkout --redwall-src current=.
python benchmarks/realworld/sample.py --cache .cache/realworld --n 40   # random P1/P2 sample to label by hand
```

`realworld/results/` holds the numbers and the hand labels behind the phase 2 report
(`docs/arastirma/faz2-genelleme-raporu.md`). Four generic engine bugs were fixed after this check, so the set is
no longer held-out for the current rules: the next generalisation check needs new projects.
