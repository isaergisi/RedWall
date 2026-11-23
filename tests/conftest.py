import re
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
_EXPECT = re.compile(r"expect:\s*(RW-[A-Z0-9-]+)")


def expectations(path: Path):
    """{(rule_id, line)} declared with `expect: RULE` comments in a fixture."""
    found = set()
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        for m in _EXPECT.finditer(line):
            found.add((m.group(1), lineno))
    return found


@pytest.fixture
def fixtures_dir():
    return FIXTURES
