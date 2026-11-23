"""Adapter for Opengrep (or Semgrep CE), used for JavaScript / TypeScript.

RedWall ships its own rules in ``redwall/rules/opengrep``. The engine binary is
optional: if neither ``opengrep`` nor ``semgrep`` is on PATH, the engine is
reported as *skipped* and the rest of the scan still runs.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from ..models import Confidence, Finding, Rule, Severity
from .base import Engine, SourceFile

ENGINE = "opengrep"
RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "opengrep"
BINARIES = ("opengrep", "semgrep")
_SEVERITY_FALLBACK = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
_BATCH = 200  # files per invocation, keeps the command line short
TIMEOUT_S = 600


def _load_rules() -> Tuple[Rule, ...]:
    """Read rule metadata from the YAML files without a YAML dependency.

    Only the flat ``metadata`` keys RedWall writes are needed, so a tiny line
    parser is enough; the binary does the real parsing.
    """
    rules: Dict[str, Rule] = {}
    for path in sorted(RULES_DIR.glob("*.y*ml")):
        meta: Dict[str, str] = {}
        message = ""
        in_meta = False

        def flush() -> None:
            rid = meta.get("redwall_id")
            if rid and rid not in rules:
                rules[rid] = Rule(
                    id=rid,
                    title=meta.get("title", rid),
                    severity=Severity.parse(meta.get("redwall_severity", "medium")),
                    cwe=meta.get("cwe"),
                    description=message,
                    engine=ENGINE,
                    languages=("javascript", "typescript"),
                    remediation=meta.get("remediation", ""),
                )

        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.rstrip()
            if line.startswith("  - id:"):
                flush()
                meta, message, in_meta = {}, "", False
            elif line.startswith("    message:"):
                message = line.split(":", 1)[1].strip()
            elif line.startswith("    metadata:"):
                in_meta = True
            elif in_meta and line.startswith("      ") and not line.startswith("       ") and ":" in line:
                key, value = line.strip().split(":", 1)
                meta[key.strip()] = value.strip()
            elif line.startswith("    ") and not line.startswith("     "):
                in_meta = False
        flush()
    return tuple(rules.values())


class OpengrepEngine(Engine):
    name = ENGINE

    def __init__(self, binary: Optional[str] = None, rules_dir: Path = RULES_DIR):
        self._binary = binary
        self.rules_dir = rules_dir
        self._rules = _load_rules()
        self._by_id = {r.id: r for r in self._rules}

    def rules(self) -> Sequence[Rule]:
        return self._rules

    def binary(self) -> Optional[str]:
        if self._binary:
            return self._binary if (os.path.sep in self._binary or shutil.which(self._binary)) else None
        env = os.environ.get("REDWALL_OPENGREP")
        if env:
            return env
        for name in BINARIES:
            found = shutil.which(name)
            if found:
                return found
        return None

    def available(self) -> Tuple[bool, str]:
        binary = self.binary()
        if binary is None:
            return False, "opengrep/semgrep not found on PATH; JavaScript/TypeScript rules were not run"
        return True, Path(binary).name

    def wants(self, source: SourceFile) -> bool:
        return source.language in ("javascript", "typescript")

    def _command(self, binary: str, targets: List[str]) -> List[str]:
        cmd = [binary, "scan", "--config", str(self.rules_dir), "--json", "--quiet"]
        if Path(binary).name.startswith("semgrep"):
            cmd += ["--metrics=off", "--disable-version-check"]
        return cmd + ["--"] + targets

    def scan(self, files: List[SourceFile]) -> Tuple[List[Finding], List[str]]:
        binary = self.binary()
        if binary is None or not files:
            return [], []
        by_abs = {str(f.abs_path): f for f in files}
        findings: List[Finding] = []
        errors: List[str] = []
        paths = sorted(by_abs)
        for i in range(0, len(paths), _BATCH):
            batch = paths[i:i + _BATCH]
            try:
                proc = subprocess.run(self._command(binary, batch), capture_output=True, text=True,
                                      timeout=TIMEOUT_S, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                errors.append(f"{ENGINE}: failed to run {binary}: {exc}")
                continue
            try:
                payload = json.loads(proc.stdout or "{}")
            except json.JSONDecodeError:
                errors.append(f"{ENGINE}: exit {proc.returncode}, unreadable output: {proc.stderr.strip()[:300]}")
                continue
            for err in payload.get("errors", []):
                msg = err.get("message") or err.get("type") or str(err)
                errors.append(f"{ENGINE}: {str(msg).strip()[:300]}")
            for result in payload.get("results", []):
                finding = self._convert(result, by_abs)
                if finding is not None:
                    findings.append(finding)
        return findings, errors

    def _convert(self, result: dict, by_abs: Dict[str, SourceFile]) -> Optional[Finding]:
        raw_path = result.get("path", "")
        source = by_abs.get(raw_path) or by_abs.get(str(Path(raw_path).resolve()))
        if source is None:
            return None
        extra = result.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        rule_id = meta.get("redwall_id") or str(result.get("check_id", "")).rsplit(".", 1)[-1]
        rule = self._by_id.get(rule_id)
        severity = rule.severity if rule else _SEVERITY_FALLBACK.get(str(extra.get("severity", "")).upper(), Severity.MEDIUM)
        start = result.get("start", {}) or {}
        end = result.get("end", {}) or {}
        line = int(start.get("line", 1))
        return Finding(
            rule_id=rule_id,
            title=(rule.title if rule else meta.get("title", rule_id)),
            message=str(extra.get("message", "")).strip(),
            severity=severity,
            confidence=Confidence.MEDIUM,
            path=source.rel_path,
            line=line,
            column=int(start.get("col", 1)),
            end_line=int(end.get("line", line)),
            snippet=source.line(line).strip(),
            cwe=(rule.cwe if rule else meta.get("cwe")),
            engine=ENGINE,
        )
