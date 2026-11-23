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

Known misses in `mini/` (on purpose, documented so they stay visible):

* `BenchmarkTest00019`: a value checked against an allow-list is still reported
  (RedWall does not reason about guards yet). Phase 2's LLM verification is
  meant to catch this kind of false positive.
* `BenchmarkTest00020`: a command list passed to `sh -c` is not recognised as
  shell execution.
