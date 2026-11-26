"""Project index: the name every Python module is imported as, relative imports and the import graph.

RedWall used to name a module after its path relative to the scan root. That breaks as soon as the scan
root is not the directory the code imports itself from: a ``src/`` layout (``src/pkg/mod.py`` is imported
as ``pkg.mod``), a scan of a subdirectory that is itself a package (``web/pgadmin`` imported as
``pgadmin``), or relative imports, which were ignored altogether. The index fixes the names:

* The canonical name follows the chain of ``__init__.py`` files upwards from the module, the way Python
  itself finds the top-level package. The chain may continue above the scan root (only the existence of
  ``__init__.py`` files is checked there, nothing is read).
* A module in a directory without ``__init__.py`` (a namespace package or a plain directory) keeps the
  old scan-root-relative name.
* The old scan-root-relative name, and the name after a ``src/`` directory, stay available as aliases
  when they differ, so nothing that resolved before stops resolving. An alias two modules share is
  dropped rather than guessed.

The import graph links modules of the project; its strongly connected components (Tarjan, iterative)
are the import cycles. Standard library only.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


@dataclass
class ModuleInfo:
    rel_path: str                  # POSIX, relative to the scan root
    name: str                      # canonical dotted name
    is_package: bool               # an __init__.py
    aliases: Tuple[str, ...] = ()  # other names it may be imported as

    @property
    def package(self) -> str:
        """The package relative imports in this module start from."""
        if self.is_package:
            return self.name
        return self.name.rpartition(".")[0]

    @property
    def names(self) -> Tuple[str, ...]:
        return (self.name,) + self.aliases


@dataclass
class ImportStats:
    """How many of a project's own imports the index can resolve (reported, and used by the tests)."""

    absolute: int = 0
    absolute_resolved: int = 0
    relative: int = 0
    relative_resolved: int = 0
    unresolved: List[str] = field(default_factory=list)


class ProjectIndex:
    def __init__(self, rel_paths: Iterable[str], scan_root: Optional[Path] = None):
        self.scan_root = scan_root
        paths = sorted(p for p in rel_paths if p.endswith(".py"))
        self._present = set(paths)
        self._init_cache: Dict[str, bool] = {}
        self.modules: Dict[str, ModuleInfo] = {}
        for rel in paths:
            self.modules[rel] = self._describe(rel)
        self.by_name: Dict[str, str] = {}
        self._build_name_table()
        self._tops = {n.split(".")[0] for n in self.by_name}  # before any outer-package alias
        self.graph: Dict[str, Set[str]] = {rel: set() for rel in self.modules}
        self.stats = ImportStats()
        self._pending: List[Tuple[str, int, Optional[str], Tuple[str, ...]]] = []

    # -- naming --------------------------------------------------------------

    def _has_init(self, directory: str) -> bool:
        """Is ``directory`` (relative to the scan root, may climb above it with ``..``) a regular package?"""
        hit = self._init_cache.get(directory)
        if hit is None:
            rel = f"{directory}/__init__.py" if directory else "__init__.py"
            hit = rel in self._present
            if not hit and self.scan_root is not None and (directory == "" or directory.startswith("..")):
                hit = (self.scan_root / directory / "__init__.py").is_file()
            self._init_cache[directory] = hit
        return hit

    def _describe(self, rel: str) -> ModuleInfo:
        parts = rel[:-3].split("/")
        is_package = parts[-1] == "__init__"
        if is_package:
            parts = parts[:-1]
        legacy = ".".join(parts) if parts else ""
        # Directories that contain the module, innermost first (a package's own directory included).
        dirs = ["/".join(parts[:i]) for i in range(len(parts) - (0 if is_package else 1), 0, -1)]
        chain = 0
        for d in dirs:
            if not self._has_init(d):
                break
            chain += 1
        if dirs and chain == 0:
            name = legacy  # plain directory or namespace package: keep the scan-root-relative name
        else:
            keep = chain + (0 if is_package else 1)
            name_parts = parts[len(parts) - keep:]
            if chain == len(dirs):
                name_parts = self._above_root() + name_parts
            name = ".".join(name_parts)
        aliases = []
        if legacy and legacy != name:
            aliases.append(legacy)
        if "src" in parts[:-1]:
            after = ".".join(parts[len(parts) - 1 - parts[::-1].index("src") + 1:])
            if after and after not in (name, legacy):
                aliases.append(after)
        return ModuleInfo(rel, name or legacy, is_package, tuple(aliases))

    def _above_root(self) -> List[str]:
        """Package names above the scan root, when the scan root itself sits inside a package."""
        if self.scan_root is None or not self._has_init(""):
            return []
        names: List[str] = []
        here = self.scan_root.resolve()
        up = ""
        while True:
            names.insert(0, here.name)
            up = f"{up}/.." if up else ".."
            if not here.parent or here.parent == here or not self._has_init(up):
                break
            here = here.parent
        return names

    def _build_name_table(self) -> None:
        primary: Dict[str, str] = {}
        for rel, info in self.modules.items():
            # Two files with one canonical name (a stray copy, foo.py next to foo/): keep the first.
            primary.setdefault(info.name, rel)
        alias_owner: Dict[str, Optional[str]] = {}
        for rel, info in self.modules.items():
            for a in info.aliases:
                if a in primary:
                    continue
                alias_owner[a] = rel if a not in alias_owner else None  # shared alias: ambiguous
        self.by_name = dict(primary)
        self.by_name.update({a: rel for a, rel in alias_owner.items() if rel is not None})

    def name_of(self, rel: str) -> str:
        return self.modules[rel].name

    def info(self, rel: str) -> ModuleInfo:
        return self.modules[rel]

    def lookup(self, dotted: str) -> Optional[str]:
        """rel_path of the module ``dotted`` names, if it is part of the project."""
        return self.by_name.get(dotted)

    def lookup_prefix(self, dotted: str) -> Optional[Tuple[str, str]]:
        """Longest module prefix of ``dotted``: (rel_path, remainder after the module name)."""
        parts = dotted.split(".")
        for i in range(len(parts), 0, -1):
            rel = self.by_name.get(".".join(parts[:i]))
            if rel is not None:
                return rel, ".".join(parts[i:])
        return None

    # -- imports -------------------------------------------------------------

    def resolve_relative(self, rel: str, level: int, module: Optional[str]) -> Optional[str]:
        """Absolute dotted name of ``from <level dots><module> import ...`` written in ``rel``."""
        info = self.modules.get(rel)
        if info is None or level <= 0:
            return module
        base = info.package.split(".") if info.package else []
        if level - 1 > len(base):
            return None  # climbs above the top-level package
        base = base[: len(base) - (level - 1)]
        if module:
            base = base + module.split(".")
        return ".".join(base) or None

    def add_imports(self, rel: str, tree: ast.AST) -> None:
        """Collect ``rel``'s imports. Call :meth:`finish` once every file is added."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self._pending.append((rel, 0, None, tuple(a.name for a in node.names)))
            elif isinstance(node, ast.ImportFrom):
                self._pending.append((rel, node.level, node.module, tuple(a.name for a in node.names)))

    def finish(self) -> None:
        """Resolve the collected imports: graph edges and statistics."""
        pending, self._pending = self._pending, []
        self._learn_outer_prefixes(pending)
        for rel, level, module, names in pending:
            if module is None and level == 0:
                for name in names:
                    self._edge(rel, name, relative=False)
                continue
            relative = level > 0
            base = self.resolve_relative(rel, level, module) if relative else module
            if base is None:
                self.stats.relative += 1
                self.stats.unresolved.append(f"{rel}: {'.' * level}{module or ''}")
                continue
            targets = [f"{base}.{n}" for n in names if n != "*"]
            if not any(self.lookup(t) for t in targets):
                targets = [base]
            for t in targets:
                self._edge(rel, t, relative=relative)

    def _learn_outer_prefixes(self, pending: List[Tuple[str, int, Optional[str], Tuple[str, ...]]]) -> None:
        """When the scan root is a package that the code imports through an outer package the scan
        cannot see (``ray.dashboard.x`` while scanning ``dashboard/``, a monorepo or symlinked layout),
        accept ``<outer>.<root package>.x`` as another name of ``<root package>.x``."""
        roots = {info.name.split(".")[0] for info in self.modules.values() if self._has_init("")}
        if not roots:
            return
        outer: Set[str] = set()
        for _rel, level, module, names in pending:
            for dotted in ([module] if module else list(names)) if level == 0 else []:
                if not dotted or self.lookup(dotted):
                    continue
                parts = dotted.split(".")
                for i in range(1, len(parts)):
                    if parts[i] in roots and self.lookup(".".join(parts[i:])):
                        outer.add(".".join(parts[:i]))
                        break
        if not outer:
            return
        for rel, info in self.modules.items():
            if info.name.split(".")[0] not in roots:
                continue
            extra = tuple(f"{o}.{info.name}" for o in sorted(outer) if f"{o}.{info.name}" not in self.by_name)
            if extra:
                info.aliases = info.aliases + extra
                for a in extra:
                    self.by_name[a] = rel

    def _edge(self, rel: str, dotted: str, relative: bool) -> None:
        # The imported module itself must exist: a missing submodule does not resolve to its package.
        target = self.lookup(dotted)
        hit = (target, "") if target is not None else None
        internal = hit is not None or relative or self._looks_internal(dotted)
        if relative:
            self.stats.relative += 1
        elif internal:
            self.stats.absolute += 1
        if hit is None:
            if internal:
                self.stats.unresolved.append(f"{rel}: {dotted}")
            return
        if relative:
            self.stats.relative_resolved += 1
        else:
            self.stats.absolute_resolved += 1
        if hit[0] != rel:
            self.graph[rel].add(hit[0])

    def _looks_internal(self, dotted: str) -> bool:
        """An absolute import whose top-level name is one of the project's own top-level names."""
        return dotted.split(".")[0] in self._tops

    # -- import graph ----------------------------------------------------------

    def sccs(self) -> List[List[str]]:
        """Strongly connected components of the import graph (Tarjan's algorithm, without recursion)."""
        index: Dict[str, int] = {}
        low: Dict[str, int] = {}
        on_stack: Set[str] = set()
        stack: List[str] = []
        out: List[List[str]] = []
        counter = 0
        for start in sorted(self.graph):
            if start in index:
                continue
            work: List[Tuple[str, Iterable[str]]] = [(start, iter(sorted(self.graph[start])))]
            index[start] = low[start] = counter
            counter += 1
            stack.append(start)
            on_stack.add(start)
            while work:
                node, children = work[-1]
                advanced = False
                for child in children:
                    if child not in index:
                        index[child] = low[child] = counter
                        counter += 1
                        stack.append(child)
                        on_stack.add(child)
                        work.append((child, iter(sorted(self.graph.get(child, ())))))
                        advanced = True
                        break
                    if child in on_stack:
                        low[node] = min(low[node], index[child])
                if advanced:
                    continue
                work.pop()
                if work:
                    parent = work[-1][0]
                    low[parent] = min(low[parent], low[node])
                if low[node] == index[node]:
                    comp = []
                    while True:
                        w = stack.pop()
                        on_stack.discard(w)
                        comp.append(w)
                        if w == node:
                            break
                    out.append(sorted(comp))
        return out

    def cycles(self) -> List[List[str]]:
        """Import cycles: components with more than one module (self-imports are not edges)."""
        return [c for c in self.sccs() if len(c) > 1]


def build_index(files: Sequence[Tuple[str, ast.AST]], scan_root: Optional[Path] = None) -> ProjectIndex:
    """Index for already-parsed files: ``[(rel_path, tree), ...]``."""
    index = ProjectIndex([rel for rel, _ in files], scan_root)
    for rel, tree in files:
        index.add_imports(rel, tree)
    index.finish()
    return index
