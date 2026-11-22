"""Hard-coded secret detection (regex + entropy), language independent.

Patterns follow the spirit of Gitleaks' rules, written from scratch so RedWall
stays MIT-clean. Matched values are always redacted in snippets: a scanner must
never copy a secret into reports, logs or (later) LLM prompts.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import List, Optional, Sequence, Tuple

from ..models import Confidence, Finding, Rule, Severity
from .base import Engine, SourceFile

ENGINE = "secrets"

_RULES: Tuple[Rule, ...] = (
    Rule("RW-SECRET-PRIVATE-KEY", "Private key", Severity.CRITICAL, "CWE-798",
         "A PEM private key is committed to the repository.", ENGINE, ("*",),
         "Remove the key, rotate it, and load it from a secret store or environment variable."),
    Rule("RW-SECRET-AWS", "AWS access key", Severity.CRITICAL, "CWE-798",
         "An AWS access key id is committed to the repository.", ENGINE, ("*",),
         "Deactivate the key in IAM and use role credentials or environment variables."),
    Rule("RW-SECRET-GITHUB", "GitHub token", Severity.CRITICAL, "CWE-798",
         "A GitHub personal access or app token is committed to the repository.", ENGINE, ("*",),
         "Revoke the token on GitHub and read it from the environment."),
    Rule("RW-SECRET-SLACK", "Slack token", Severity.HIGH, "CWE-798",
         "A Slack token is committed to the repository.", ENGINE, ("*",),
         "Revoke the token and read it from the environment."),
    Rule("RW-SECRET-STRIPE", "Stripe live key", Severity.CRITICAL, "CWE-798",
         "A Stripe live secret key is committed to the repository.", ENGINE, ("*",),
         "Roll the key in the Stripe dashboard and read it from the environment."),
    Rule("RW-SECRET-GOOGLE", "Google API key", Severity.HIGH, "CWE-798",
         "A Google API key is committed to the repository.", ENGINE, ("*",),
         "Restrict or regenerate the key and read it from the environment."),
    Rule("RW-SECRET-GENERIC", "Hard-coded credential", Severity.HIGH, "CWE-798",
         "A password, token or API key appears to be hard-coded.", ENGINE, ("*",),
         "Read credentials from environment variables or a secret manager."),
)
RULES = {r.id: r for r in _RULES}

_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("RW-SECRET-PRIVATE-KEY", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
    ("RW-SECRET-AWS", re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b")),
    ("RW-SECRET-GITHUB", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{82})\b")),
    ("RW-SECRET-SLACK", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b")),
    ("RW-SECRET-STRIPE", re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{24,})\b")),
    ("RW-SECRET-GOOGLE", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b")),
)

# password = "s3cr3t!", "apiKey": "...", API_TOKEN: '...'
_GENERIC = re.compile(
    r"""(?ix)
    (?P<name>[a-z0-9_.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|auth[_\-]?key|private[_\-]?key|client[_\-]?secret)[a-z0-9_\-]*)
    ["']?\s*(?:=|:|:=|=>)\s*
    (?P<q>["'`])(?P<value>[^"'`\s]{8,})(?P=q)
    """
)
_PLACEHOLDER = re.compile(
    r"(?i)(changeme|change_me|example|placeholder|dummy|sample|your[_\-]|xxx+|\*{3,}|<.*>|\$\{|\{\{|%\(|^test|fake|redacted|none|null|todo)"
)

SKIP_SUFFIXES = {
    ".lock", ".min.js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip",
    ".gz", ".tar", ".woff", ".woff2", ".ttf", ".eot", ".so", ".dll", ".exe", ".pyc", ".svg",
}
SKIP_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "uv.lock"}
MAX_BYTES = 1_000_000


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def redact(value: str) -> str:
    keep = 4 if len(value) > 12 else 2
    return value[:keep] + "*" * min(8, max(3, len(value) - keep))


class SecretsEngine(Engine):
    name = ENGINE

    def rules(self) -> Sequence[Rule]:
        return _RULES

    def wants(self, source: SourceFile) -> bool:
        name = source.abs_path.name
        if name in SKIP_NAMES or any(name.endswith(s) for s in SKIP_SUFFIXES):
            return False
        try:
            return source.abs_path.stat().st_size <= MAX_BYTES
        except OSError:
            return False

    def scan(self, files: List[SourceFile]) -> Tuple[List[Finding], List[str]]:
        findings: List[Finding] = []
        errors: List[str] = []
        for source in files:
            try:
                text = source.text
            except OSError as exc:
                errors.append(f"{source.rel_path}: {exc}")
                continue
            if "\x00" in text[:8192]:
                continue  # binary
            for lineno, line in enumerate(text.splitlines(), start=1):
                findings.extend(self._scan_line(source, lineno, line))
        return findings, errors

    def _scan_line(self, source: SourceFile, lineno: int, line: str) -> List[Finding]:
        out: List[Finding] = []
        hit_specific = False
        for rule_id, pattern in _PATTERNS:
            m = pattern.search(line)
            if m:
                value = m.group(1) if m.groups() else m.group(0)
                out.append(self._finding(source, lineno, line, rule_id, m.start(), value, Confidence.HIGH,
                                         f"{RULES[rule_id].title} found."))
                hit_specific = True
        if not hit_specific:
            m = _GENERIC.search(line)
            if m:
                value = m.group("value")
                if not _PLACEHOLDER.search(value) and not value.startswith(("os.", "process.env")):
                    entropy = shannon_entropy(value)
                    if entropy >= 3.0:
                        conf = Confidence.MEDIUM if entropy >= 3.5 else Confidence.LOW
                        out.append(self._finding(
                            source, lineno, line, "RW-SECRET-GENERIC", m.start("value"), value, conf,
                            f"`{m.group('name')}` is assigned a hard-coded value (entropy {entropy:.1f})."))
        return out

    @staticmethod
    def _finding(source: SourceFile, lineno: int, line: str, rule_id: str, col: int, value: str,
                 confidence: Confidence, message: str, function: Optional[str] = None) -> Finding:
        rule = RULES[rule_id]
        snippet = line.strip()
        if value and rule_id != "RW-SECRET-PRIVATE-KEY":
            snippet = snippet.replace(value, redact(value))
        return Finding(
            rule_id=rule_id,
            title=rule.title,
            message=message,
            severity=rule.severity,
            confidence=confidence,
            path=source.rel_path,
            line=lineno,
            column=col + 1,
            snippet=snippet[:300],
            cwe=rule.cwe,
            engine=ENGINE,
            function=function,
        )
