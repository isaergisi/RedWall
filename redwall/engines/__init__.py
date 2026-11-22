"""Stage-1 engines. Each one is fast, deterministic and needs no LLM."""

from __future__ import annotations

from typing import List

from .base import Engine, SourceFile
from .opengrep import OpengrepEngine
from .python_ast import PythonAstEngine
from .secrets import SecretsEngine


def default_engines() -> List[Engine]:
    return [PythonAstEngine(), OpengrepEngine(), SecretsEngine()]


def all_rules():
    rules = []
    for engine in default_engines():
        rules.extend(engine.rules())
    return sorted(rules, key=lambda r: r.id)


__all__ = ["Engine", "SourceFile", "PythonAstEngine", "OpengrepEngine", "SecretsEngine", "default_engines", "all_rules"]
