"""Command line interface: ``redwall scan``, ``redwall rules``, ``redwall bench``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
from .engines import all_rules
from .models import Confidence, Severity
from .reporters import FORMATS, render
from .scanner import ScanOptions, scan
from .triage import prioritize

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _fail_on(value: str) -> Optional[Severity]:
    return None if value.lower() == "none" else _severity(value)


def _confidence(value: str) -> Confidence:
    try:
        return Confidence(value.lower())
    except ValueError:
        raise argparse.ArgumentTypeError("confidence must be low, medium or high") from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redwall",
        description="RedWall: open-source, local-first security scanner (SAST).",
    )
    parser.add_argument("--version", action="version", version=f"redwall {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p = sub.add_parser("scan", help="scan files or directories")
    p.add_argument("paths", nargs="*", default=["."], help="files or directories to scan (default: .)")
    p.add_argument("-f", "--format", choices=FORMATS, default="text", help="output format (default: text)")
    p.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")
    p.add_argument("--out-dir", metavar="DIR",
                   help="also write report.md, findings.jsonl and results.sarif into DIR (e.g. .redwall/results)")
    p.add_argument("--fail-on", type=_fail_on, default=Severity.HIGH, metavar="SEVERITY",
                   help="exit with code 1 if a finding is at least this severe; 'none' never fails (default: high)")
    p.add_argument("--min-severity", type=_severity, default=Severity.INFO, metavar="SEVERITY",
                   help="hide findings below this severity (default: info)")
    p.add_argument("--min-confidence", type=_confidence, default=Confidence.LOW, metavar="LEVEL",
                   help="hide findings below this confidence: low, medium, high (default: low)")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="skip paths matching GLOB (repeatable), e.g. --exclude 'tests/*'")
    p.add_argument("--rules", action="append", default=None, metavar="ID",
                   help="only report rules whose id starts with ID (repeatable), e.g. --rules RW-PY")
    p.add_argument("--engine", action="append", default=None, choices=["python-ast", "opengrep", "secrets"],
                   help="only run this engine (repeatable)")
    p.add_argument("--no-color", action="store_true", help="disable colours in text output")
    p.add_argument("--lang", choices=["en", "tr"], default="en",
                   help="language of the triage explanations in text/markdown/json (default: en)")
    p.add_argument("--brief", action="store_true",
                   help="text output: leave out the 'why it is still open' explanations")
    g = p.add_argument_group("optional LLM second opinion (re-orders and explains, never hides)")
    g.add_argument("--llm", metavar="PROVIDER:MODEL",
                   help="e.g. ollama:qwen2.5-coder:7b or openai:<model> (any OpenAI-compatible server)")
    g.add_argument("--llm-url", metavar="URL", default="",
                   help="chat endpoint (default: local Ollama or http://127.0.0.1:8080/v1/chat/completions); "
                        "API key from REDWALL_LLM_API_KEY")
    g.add_argument("--llm-max", type=int, default=25, metavar="N",
                   help="ask about at most N findings, highest priority first (default: 25)")
    g.add_argument("--llm-timeout", type=float, default=120.0, metavar="SECONDS", help="per request (default: 120)")
    g.add_argument("--llm-cache", metavar="FILE", help="reuse answers across runs (JSON file)")
    g.add_argument("--llm-allow-remote", action="store_true",
                   help="allow a non-localhost endpoint (code slices will leave this machine)")

    r = sub.add_parser("rules", help="list the built-in rules")
    r.add_argument("-f", "--format", choices=["text", "json"], default="text")

    b = sub.add_parser("bench", help="score RedWall against a labelled benchmark (OWASP Benchmark CSV format)")
    b.add_argument("path", help="directory with the benchmark test files")
    b.add_argument("--expected", required=True, metavar="CSV", help="expected results CSV")
    b.add_argument("-f", "--format", choices=["text", "json"], default="text")
    return parser


def _cmd_scan(args: argparse.Namespace) -> int:
    targets = [Path(p) for p in args.paths]
    missing = [str(t) for t in targets if not t.exists()]
    if missing:
        print(f"redwall: no such file or directory: {', '.join(missing)}", file=sys.stderr)
        return EXIT_ERROR
    root = targets[0].resolve() if len(targets) == 1 and targets[0].is_dir() else Path.cwd()

    options = ScanOptions(
        excludes=args.exclude,
        min_severity=args.min_severity,
        min_confidence=args.min_confidence,
        rule_ids=args.rules,
        engines=args.engine,
    )
    llm_cfg = None
    if args.llm:
        from .triage.llm import LLMConfig
        llm_cfg = LLMConfig.parse(
            args.llm, url=args.llm_url, api_key=os.environ.get("REDWALL_LLM_API_KEY") or None,
            timeout=args.llm_timeout, max_findings=args.llm_max, allow_remote=args.llm_allow_remote,
            cache_path=Path(args.llm_cache) if args.llm_cache else None, lang=args.lang)
        llm_cfg.check()  # refuse a remote endpoint before scanning, not after
    result = prioritize(scan(root, targets, options), lang=args.lang)
    if llm_cfg is not None:
        from .triage.llm import review
        review(result, llm_cfg)

    color = (args.format == "text" and not args.output and not args.no_color
             and sys.stdout.isatty() and "NO_COLOR" not in os.environ)
    report = render(result, args.format, color=color, lang=args.lang, brief=args.brief)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)
    if args.out_dir:
        out = Path(args.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "report.md").write_text(render(result, "markdown", lang=args.lang), encoding="utf-8")
        (out / "findings.jsonl").write_text(render(result, "jsonl"), encoding="utf-8")
        (out / "results.sarif").write_text(render(result, "sarif"), encoding="utf-8")

    if args.fail_on is not None and any(f.severity.rank >= args.fail_on.rank for f in result.findings):
        return EXIT_FINDINGS
    return EXIT_OK


def _cmd_rules(args: argparse.Namespace) -> int:
    rules = all_rules()
    if args.format == "json":
        print(json.dumps([r.to_dict() for r in rules], indent=2, ensure_ascii=False))
        return EXIT_OK
    for r in rules:
        print(f"{r.id:24} {r.severity.value:8} {r.cwe or '':9} {r.engine:11} {r.title}")
    return EXIT_OK


def _cmd_bench(args: argparse.Namespace) -> int:
    from .bench import format_report, run_benchmark

    report = run_benchmark(Path(args.path), Path(args.expected))
    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_report(report))
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return EXIT_ERROR
    try:
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "rules":
            return _cmd_rules(args)
        if args.command == "bench":
            return _cmd_bench(args)
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError) as exc:
        print(f"redwall: {exc}", file=sys.stderr)
        return EXIT_ERROR
    parser.print_help()
    return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
