"""Phase 3 D3: module names from the package root, relative imports, re-exports, the import graph."""

import ast
import textwrap
from pathlib import Path

from redwall.analysis import ProjectIndex, build_index
from redwall.models import Confidence
from redwall.scanner import ScanOptions, scan


def _write(root: Path, files: dict) -> None:
    for rel, code in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(code))


def _index(files: dict, root: Path = None) -> ProjectIndex:
    return build_index([(rel, ast.parse(textwrap.dedent(code))) for rel, code in files.items()], root)


# --------------------------------------------------------------------------
# Naming
# --------------------------------------------------------------------------


def test_names_follow_the_init_chain():
    idx = ProjectIndex(["src/pinger/__init__.py", "src/pinger/net/__init__.py", "src/pinger/net/ping.py",
                        "app.py", "scripts/tool.py", "sql/engines/mysql.py"])
    assert idx.name_of("src/pinger/net/ping.py") == "pinger.net.ping"
    assert idx.name_of("src/pinger/net/__init__.py") == "pinger.net"
    assert idx.info("src/pinger/net/ping.py").aliases == ("src.pinger.net.ping",)  # old name still works
    assert idx.name_of("app.py") == "app"
    # Directories without __init__.py keep the scan-root-relative name (namespace packages).
    assert idx.name_of("scripts/tool.py") == "scripts.tool"
    assert idx.name_of("sql/engines/mysql.py") == "sql.engines.mysql"
    assert idx.lookup("pinger.net.ping") == idx.lookup("src.pinger.net.ping") == "src/pinger/net/ping.py"


def test_scan_root_inside_a_package_uses_the_outer_names(tmp_path):
    _write(tmp_path, {"web/pgadmin/__init__.py": "", "web/pgadmin/misc/__init__.py": "",
                      "web/pgadmin/misc/bgjob.py": ""})
    root = tmp_path / "web" / "pgadmin"
    idx = ProjectIndex(["__init__.py", "misc/__init__.py", "misc/bgjob.py"], root)
    assert idx.name_of("misc/bgjob.py") == "pgadmin.misc.bgjob"
    assert idx.name_of("__init__.py") == "pgadmin"
    assert idx.lookup("misc.bgjob") == "misc/bgjob.py"  # scan-root name kept as an alias


def test_shared_alias_is_dropped_not_guessed():
    idx = ProjectIndex(["a/src/util/__init__.py", "a/src/util/x.py", "b/src/util/__init__.py", "b/src/util/x.py"])
    assert idx.lookup("util.x") in ("a/src/util/x.py", "b/src/util/x.py")  # canonical names collide: first wins
    assert idx.lookup("a.src.util.x") == "a/src/util/x.py" and idx.lookup("b.src.util.x") == "b/src/util/x.py"


# --------------------------------------------------------------------------
# Relative imports and the graph
# --------------------------------------------------------------------------


def test_relative_imports_resolve_against_the_package():
    idx = ProjectIndex(["app/__init__.py", "app/api/__init__.py", "app/api/views.py", "app/core/__init__.py",
                        "app/core/reports.py", "top.py"])
    assert idx.resolve_relative("app/api/views.py", 1, "helpers") == "app.api.helpers"
    assert idx.resolve_relative("app/api/views.py", 2, "core.reports") == "app.core.reports"
    assert idx.resolve_relative("app/api/__init__.py", 1, None) == "app.api"   # a package is its own base
    assert idx.resolve_relative("app/api/views.py", 4, "x") is None           # above the top-level package


def test_import_graph_cycles_and_statistics():
    idx = _index({
        "cyc/__init__.py": "",
        "cyc/a.py": "from . import b\nimport os\n",
        "cyc/b.py": "from cyc import a\nfrom .c import f\n",
        "cyc/c.py": "def f(): pass\nfrom .missing import g\n",
        "cyc/d.py": "from .e import h\n",
        "cyc/e.py": "from . import d\n",
    })
    assert idx.cycles() == [["cyc/a.py", "cyc/b.py"], ["cyc/d.py", "cyc/e.py"]]
    assert idx.graph["cyc/b.py"] == {"cyc/a.py", "cyc/c.py"}
    st = idx.stats
    assert (st.relative, st.relative_resolved) == (5, 4)    # `.missing` is not in the project
    assert (st.absolute, st.absolute_resolved) == (1, 1)    # `import os` is not a project import
    assert any("missing" in u for u in st.unresolved)


def test_tarjan_handles_long_chains_without_recursion():
    n = 5000
    files = {"p/__init__.py": ""}
    files.update({f"p/m{i}.py": f"from . import m{i + 1}\n" for i in range(n)})
    files[f"p/m{n}.py"] = "from . import m0\n"
    idx = _index(files)
    (cycle,) = idx.cycles()
    assert len(cycle) == n + 1


def test_outer_package_prefix_when_the_scan_root_is_a_subpackage(tmp_path):
    # Scanning `dashboard/` of a monorepo whose code imports itself as `ray.dashboard...`.
    _write(tmp_path, {"dashboard/__init__.py": "", "dashboard/utils.py": "def f(): pass\n",
                      "dashboard/head.py": "import ray.dashboard.utils as u\nimport ray._private.x\n"})
    root = tmp_path / "dashboard"
    idx = build_index([(rel, ast.parse((root / rel).read_text())) for rel in ("__init__.py", "utils.py", "head.py")],
                      root)
    assert idx.lookup("ray.dashboard.utils") == "utils.py"
    assert idx.graph["head.py"] == {"utils.py"}
    assert (idx.stats.absolute, idx.stats.absolute_resolved) == (1, 1)  # ray._private is outside the scan


# --------------------------------------------------------------------------
# The engine uses the index
# --------------------------------------------------------------------------


HELPER = """
    from flask import request

    def get_arg():
        return request.args.get("cmd")
"""
USE = """
    import os
    {imp}

    def handler():
        os.system({call})
"""


def _findings(tmp_path, files):
    _write(tmp_path, files)
    return scan(tmp_path, options=ScanOptions(engines=["python-ast"])).findings


def test_relative_import_reaches_the_helper_summary(tmp_path):
    findings = _findings(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/helpers.py": HELPER,
        "pkg/views.py": USE.format(imp="from .helpers import get_arg", call="get_arg()"),
    })
    assert [(f.path, f.confidence) for f in findings] == [("pkg/views.py", Confidence.HIGH)]


def test_src_layout_import_reaches_the_helper_summary(tmp_path):
    findings = _findings(tmp_path, {
        "pyproject.toml": "[project]\nname = 'tool'\n",
        "src/tool/__init__.py": "",
        "src/tool/helpers.py": HELPER,
        "src/tool/views.py": USE.format(imp="from tool import helpers", call="helpers.get_arg()"),
    })
    assert [(f.path, f.confidence) for f in findings] == [("src/tool/views.py", Confidence.HIGH)]


def test_package_reexport_reaches_the_helper_summary(tmp_path):
    findings = _findings(tmp_path, {
        "pkg/__init__.py": "from .impl import get_arg\n",
        "pkg/impl.py": HELPER,
        "views.py": USE.format(imp="import pkg", call="pkg.get_arg()"),
    })
    assert [(f.path, f.confidence) for f in findings] == [("views.py", Confidence.HIGH)]


def test_engine_reports_import_resolution_and_cycles(tmp_path):
    _write(tmp_path, {"cyc/__init__.py": "", "cyc/a.py": "from . import b\n", "cyc/b.py": "from . import a\n"})
    result = scan(tmp_path, options=ScanOptions(engines=["python-ast"]))
    (engine,) = result.engines
    assert engine.detail == "project imports resolved: 2/2, 1 import cycle"


def test_helper_returning_a_closure_call_is_not_called_clean(tmp_path):
    # Once the helper resolves, its summary must not claim the result is clean: the closure reads `path`.
    findings = _findings(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/paths.py": """
            import os

            def full_path(path):
                def short():
                    return os.path.normpath(path)
                return short()
        """,
        "pkg/views.py": """
            from flask import request
            from pkg.paths import full_path

            def view():
                return open(full_path(request.args["f"])).read()
        """,
    })
    assert [(f.path, f.rule_id, f.confidence) for f in findings] == [("pkg/views.py", "RW-PY-PATH", Confidence.HIGH)]
