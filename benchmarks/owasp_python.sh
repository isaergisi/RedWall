#!/usr/bin/env bash
# Score RedWall on OWASP BenchmarkPython (https://github.com/OWASP-Benchmark/BenchmarkPython).
# Usage: benchmarks/owasp_python.sh [checkout-dir]
set -euo pipefail
DIR="${1:-.cache/BenchmarkPython}"
if [ ! -d "$DIR/.git" ]; then
  git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkPython.git "$DIR"
fi
CSV="$(ls "$DIR"/expectedresults-*.csv | head -n 1)"
CODE="$DIR/testcode"
[ -d "$CODE" ] || CODE="$DIR"
echo "Expected results: $CSV"
redwall bench "$CODE" --expected "$CSV" "${@:2}"
