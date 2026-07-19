#!/usr/bin/env python3
"""Verify React emissions use the generated canonical host command constants."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from ui.command_registry import ALLOWED_COMMANDS  # noqa: E402

DEFAULT_COMMAND_SOURCE = Path("ui/web/src/commands.ts")
DEFAULT_REACT_SOURCE_DIR = Path("ui/web/src")

_COMMAND_BLOCK = re.compile(
    r"export\s+const\s+commands\s*=\s*\{(?P<body>.*?)\}\s*as\s+const\s*;",
    re.DOTALL,
)
_COMMAND_ENTRY = re.compile(
    r"^\s*(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*"
    r"(?P<quote>['\"])(?P<command>[^'\"]+)(?P=quote)\s*,?\s*$"
)
_RAW_EMISSION_PATTERNS = (
    re.compile(
        r"\b(?:bridge|this)\.command\s*(?:<[^;()]*>)?\s*\(\s*(['\"])(?P<command>[^'\"]+)\1"
    ),
    re.compile(
        r"\b(?:onCommand|runCommand)\s*\(\s*(['\"])(?P<command>[^'\"]+)\1"
    ),
    re.compile(r"\bcommand\s*:\s*(['\"])(?P<command>[^'\"]+)\1"),
)


def load_react_commands(path: Path = DEFAULT_COMMAND_SOURCE) -> dict[str, str]:
    source = Path(path).read_text(encoding="utf-8")
    match = _COMMAND_BLOCK.search(source)
    if match is None:
        raise ValueError(f"generated React commands object was not found in {path}")

    commands: dict[str, str] = {}
    unparsed: list[str] = []
    for line in match.group("body").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        entry = _COMMAND_ENTRY.match(line)
        if entry is None:
            unparsed.append(stripped)
            continue
        name, command = entry.group("name"), entry.group("command")
        if name in commands:
            raise ValueError(f"duplicate React command key {name!r}")
        commands[name] = command
    if unparsed:
        raise ValueError(f"unparsed React command entries in {path}: {unparsed[:5]!r}")
    if not commands:
        raise ValueError(f"no React command values were found in {path}")
    if len(commands.values()) != len(set(commands.values())):
        raise ValueError("React command values must not be duplicated")
    return commands


def raw_command_emissions(
    source_dir: Path = DEFAULT_REACT_SOURCE_DIR,
) -> tuple[tuple[Path, int, str], ...]:
    """Find literals that bypass commands.ts in runtime React sources."""

    source_dir = Path(source_dir)
    findings: list[tuple[Path, int, str]] = []
    for path in sorted(source_dir.rglob("*"), key=lambda item: item.as_posix()):
        if path.suffix not in {".ts", ".tsx"}:
            continue
        relative = path.relative_to(source_dir)
        if relative == Path("commands.ts") or "test" in relative.parts or path.name == "mockBridge.ts":
            continue
        source = path.read_text(encoding="utf-8")
        for pattern in _RAW_EMISSION_PATTERNS:
            for match in pattern.finditer(source):
                line = source.count("\n", 0, match.start()) + 1
                findings.append((relative, line, match.group("command")))
    return tuple(sorted(set(findings), key=lambda item: (item[0].as_posix(), item[1], item[2])))


def verify_react_commands(
    command_source: Path = DEFAULT_COMMAND_SOURCE,
    source_dir: Path = DEFAULT_REACT_SOURCE_DIR,
    allowed_commands: Iterable[str] = ALLOWED_COMMANDS,
) -> tuple[str, ...]:
    commands = load_react_commands(command_source)
    allowed = frozenset(allowed_commands)
    unknown = sorted(set(commands.values()) - allowed)
    if unknown:
        raise ValueError(
            "React commands are absent from ui.command_registry.ALLOWED_COMMANDS: "
            + ", ".join(unknown)
        )
    raw = raw_command_emissions(source_dir)
    if raw:
        details = ", ".join(f"{path}:{line}:{command}" for path, line, command in raw[:10])
        raise ValueError(
            "Runtime React command literals must be declared in commands.ts: " + details
        )
    return tuple(sorted(commands.values()))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--command-source", type=Path, default=DEFAULT_COMMAND_SOURCE)
    parser.add_argument("--source-dir", type=Path, default=DEFAULT_REACT_SOURCE_DIR)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        commands = verify_react_commands(args.command_source, args.source_dir)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"error: {error}")
        return 1
    print(
        f"Verified {len(commands)} React commands against "
        "ui.command_registry.ALLOWED_COMMANDS"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
