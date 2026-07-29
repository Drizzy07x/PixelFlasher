"""Shared definition of the 9.x modules the modern artifact must never import.

Naming the forbidden modules by hand let the guard cover three of them while the
tree held thirty. The set is derived from the tree instead: every root-level
module is legacy unless it is on the reviewed allow list, so adding a module to
the 9.x application cannot silently widen what the modern surface may reach.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

# Root-level modules the modern entrypoint, core and bridge legitimately use.
# Every one is free of wx and of the 9.x application graph.
MODERN_ROOT_MODULES = frozenset(
    {
        "PixelFlasher",
        "avbtool",
        "constants",
        "diagnostics",
        "firmware_smoke_contract",
        "legacy_raw_smoke_contract",
        "platform_utils",
        "pty_smoke_contract",
        "self_test",
        "smoke_receipt_schema",
        "support_smoke_contract",
        "ui_smoke_contract",
    }
)

DYNAMIC_IMPORTERS = frozenset({"import_module", "__import__"})


def legacy_root_modules(root: Path = REPOSITORY_ROOT) -> frozenset[str]:
    """Root-level modules that belong to the wxPython 9.x application."""

    return frozenset(
        path.stem
        for path in root.glob("*.py")
        if path.stem not in MODERN_ROOT_MODULES
    )


def forbidden_roots(root: Path = REPOSITORY_ROOT) -> frozenset[str]:
    return legacy_root_modules(root) | {"wx"}


def _dynamic_import_target(node: ast.Call) -> str | None:
    function = node.func
    if isinstance(function, ast.Attribute):
        name = function.attr
    elif isinstance(function, ast.Name):
        name = function.id
    else:
        return None
    if name not in DYNAMIC_IMPORTERS or not node.args:
        return None
    first = node.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return None


def forbidden_imports(path: Path, forbidden: frozenset[str]) -> tuple[tuple[int, str], ...]:
    """Static and dynamic imports of a forbidden module, with line numbers.

    Lazy imports inside a function body and `importlib.import_module("phone")`
    reach the same module a top-level import would, so both are reported.
    """

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    violations: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        roots: set[str] = set()
        if isinstance(node, ast.Import):
            roots = {alias.name.split(".", 1)[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                roots = {node.module.split(".", 1)[0]}
        elif isinstance(node, ast.Call):
            target = _dynamic_import_target(node)
            if target:
                roots = {target.split(".", 1)[0]}
        for name in sorted(roots & forbidden):
            violations.append((node.lineno, name))
    return tuple(violations)
