"""Phase 3 D4: call sites resolve to the project definition they reach (typed receivers, inheritance,
super(), factories, annotations), not to every method that happens to share the name."""

import ast
import textwrap
from pathlib import Path

from redwall.engines import python_ast
from redwall.models import Confidence
from redwall.scanner import ScanOptions, scan

# Two unrelated classes with a method of the same name: one returns request data, one a constant.
TWO_COMMANDS = """
    from flask import request

    class Fixed:
        def command(self):
            return "uptime"

    class FromUser:
        def command(self):
            return request.args["c"]
"""


def _write(root: Path, files: dict) -> None:
    for rel, code in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(code))


def _findings(tmp_path, files):
    _write(tmp_path, files)
    return [(f.path, f.line, f.rule_id, f.confidence)
            for f in scan(tmp_path, options=ScanOptions(engines=["python-ast"])).findings]


def test_factory_return_type_picks_the_right_method(tmp_path):
    found = _findings(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/commands.py": TWO_COMMANDS,
        "pkg/factory.py": "from pkg.commands import Fixed\n\ndef make():\n    return Fixed()\n",
        "pkg/views.py": """
            import os
            from pkg.factory import make

            def run():
                os.system(make().command())
        """,
    })
    # Before D4 `command` resolved by name to both classes and the source won.
    assert found == []


def test_factory_returning_the_tainted_class_is_still_found(tmp_path):
    found = _findings(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/commands.py": TWO_COMMANDS,
        "pkg/factory.py": "from pkg.commands import FromUser\n\ndef make():\n    return FromUser()\n",
        "pkg/views.py": """
            import os
            from pkg.factory import make

            def run():
                os.system(make().command())
        """,
    })
    assert found == [("pkg/views.py", 6, "RW-PY-CMDI", Confidence.HIGH)]


def test_self_method_resolves_to_its_own_class(tmp_path):
    found = _findings(tmp_path, {"app.py": TWO_COMMANDS + """
    import os

    class Job(Fixed):
        def run(self):
            os.system(self.command())
    """})
    assert found == []


def test_self_method_considers_subclass_overrides(tmp_path):
    found = _findings(tmp_path, {"app.py": """
        import os
        from flask import request

        class Base:
            def command(self):
                return "uptime"

            def run(self):
                os.system(self.command())

        class Custom(Base):
            def command(self):
                return request.args["c"]
    """})
    assert [(line, rule) for _, line, rule, _ in found] == [(10, "RW-PY-CMDI")]


def test_inherited_method_found_through_the_mro_across_files(tmp_path):
    files = {
        "eng/__init__.py": "",
        "eng/base.py": TWO_COMMANDS,
        "eng/child.py": "from eng.base import Fixed, FromUser\n\nclass Safe(Fixed):\n    pass\n\n"
                        "class Unsafe(FromUser):\n    pass\n",
        "views.py": """
            import os
            from eng.child import Safe, Unsafe

            def a():
                os.system(Safe().command())

            def b():
                os.system(Unsafe().command())
        """,
    }
    found = _findings(tmp_path, files)
    assert [(path, line) for path, line, _, _ in found] == [("views.py", 9)]


def test_super_call_inside_a_summary(tmp_path):
    found = _findings(tmp_path, {"app.py": TWO_COMMANDS + """
    import os

    class Trimmed(FromUser):
        def command(self):
            return super().command().strip()

    def run():
        os.system(Trimmed().command())
    """})
    assert [(rule, conf) for _, _, rule, conf in found] == [("RW-PY-CMDI", Confidence.HIGH)]


def test_parameter_annotation_types_the_receiver(tmp_path):
    found = _findings(tmp_path, {"app.py": TWO_COMMANDS + """
    import os

    def run(job: Fixed):
        os.system(job.command())

    def run_quoted(job: "Fixed"):
        os.system(job.command())
    """})
    assert found == []


def test_static_and_class_level_calls(tmp_path):
    found = _findings(tmp_path, {"app.py": TWO_COMMANDS + """
    import os

    class Tools:
        @staticmethod
        def arg():
            return request.args["x"]

    def run():
        os.system(Tools.arg())

    def run2():
        os.system(FromUser.command(None))
    """})
    assert sorted(line for _, line, _, _ in found) == [20, 23]


# --------------------------------------------------------------------------
# The resolver itself
# --------------------------------------------------------------------------


def _targets(tmp_path, files: dict, function: str):
    """Resolve every call in ``function`` of the last file; returns {call text: (exact, labels)}."""
    _write(tmp_path, files)
    seen = {}
    original = python_ast._ModuleAnalyzer.resolve_call

    def spy(self, node, name, method, scope):
        target = original(self, node, name, method, scope)
        if self.func_stack and self.func_stack[-1] == function and not self.quiet:
            seen[ast.unparse(node)] = None if target is None else (target.exact, len(target.defs))
        return target

    python_ast._ModuleAnalyzer.resolve_call = spy
    try:
        scan(tmp_path, options=ScanOptions(engines=["python-ast"]))
    finally:
        python_ast._ModuleAnalyzer.resolve_call = original
    return seen


def test_resolution_exactness(tmp_path):
    seen = _targets(tmp_path, {"app.py": TWO_COMMANDS + """
    class Base:
        def hook(self):
            return 1

        def go(self, obj, name, unknown):
            return [self.hook(), Fixed().command(), getattr(obj, name)(), unknown.command(), unknown.strip()]

    class Sub(Base):
        def hook(self):
            return 2
    """}, "go")
    assert seen["self.hook()"] == (False, 2)          # Base.hook or the Sub override
    assert seen["Fixed().command()"] == (True, 1)
    assert seen["getattr(obj, name)()"] is None       # dynamic dispatch: not resolved
    assert seen["unknown.command()"] == (False, 2)    # untyped receiver: every `command`, approximate
    assert seen["unknown.strip()"] is None            # a str method, not a project method
