#!/usr/bin/env python3
"""Audit or append React source messages to the canonical gettext catalogs.

This is a maintenance helper, not part of the frontend build.  The PO files
remain the only translation source: the normal build exports them to JSON and
fails if a React message is absent.  ``--write`` only appends missing contextual
entries and preserves every existing byte in each catalog.
"""

from __future__ import annotations

import argparse
import ast
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import polib

EXPECTED_LOCALES = ("en", "es", "fr", "it", "zh_CN", "zh_TW")
DEFAULT_REACT_SOURCE = Path("ui/web/src/i18n.tsx")
DEFAULT_LOCALE_DIR = Path("locale")
DEFAULT_DOMAIN = "pixelflasher"
SECTION_TITLE = "React Web UI source messages 2026-07-18"

_SOURCE_BLOCK = re.compile(
    r"export\s+const\s+sourceMessages\s*=\s*\{(?P<body>.*?)\}\s*as\s+const\s*;",
    re.DOTALL,
)
_SOURCE_PROPERTY = re.compile(
    r"^\s*(?P<key>'(?:\\.|[^'])*')\s*:\s*"
    r"(?P<msgid>'(?:\\.|[^'])*')\s*,?\s*$",
    re.MULTILINE,
)


@dataclass(frozen=True)
class ReactMessage:
    key: str
    msgid: str

    @property
    def context(self) -> str:
        return f"web.{self.key}"


@dataclass(frozen=True)
class ReactTranslationCoverage:
    message_count: int
    translated_count: int

    @property
    def fallback_count(self) -> int:
        return self.message_count - self.translated_count


def load_react_messages(path: Path = DEFAULT_REACT_SOURCE) -> tuple[ReactMessage, ...]:
    source = Path(path).read_text(encoding="utf-8")
    block_match = _SOURCE_BLOCK.search(source)
    if block_match is None:
        raise ValueError(f"sourceMessages object was not found in {path}")

    messages: list[ReactMessage] = []
    keys: set[str] = set()
    for match in _SOURCE_PROPERTY.finditer(block_match.group("body")):
        key = ast.literal_eval(match.group("key"))
        msgid = ast.literal_eval(match.group("msgid"))
        if not isinstance(key, str) or not key or not isinstance(msgid, str) or not msgid:
            raise ValueError(f"React message keys and msgids must be non-empty strings: {match.group(0)!r}")
        if key in keys:
            raise ValueError(f"Duplicate React message key {key!r} in {path}")
        keys.add(key)
        messages.append(ReactMessage(key, msgid))

    if not messages:
        raise ValueError(f"No React source messages were parsed from {path}")
    return tuple(messages)


def catalog_paths(
    locale_dir: Path = DEFAULT_LOCALE_DIR,
    domain: str = DEFAULT_DOMAIN,
) -> tuple[tuple[str, Path], ...]:
    root = Path(locale_dir)
    paths = tuple(
        (locale, root / locale / "LC_MESSAGES" / f"{domain}.po")
        for locale in EXPECTED_LOCALES
    )
    missing = [str(path) for _locale, path in paths if not path.is_file()]
    if missing:
        raise FileNotFoundError("Missing gettext catalogs: " + ", ".join(missing))
    return paths


def missing_react_messages(
    path: Path,
    messages: Sequence[ReactMessage],
) -> tuple[ReactMessage, ...]:
    catalog = polib.pofile(str(path), encoding="utf-8", wrapwidth=0)
    entries = tuple(entry for entry in catalog if not entry.obsolete)
    plain_msgids = {entry.msgid for entry in entries if not entry.msgctxt}
    contextual = {(entry.msgctxt, entry.msgid) for entry in entries if entry.msgctxt}
    msgids_by_context: dict[str, set[str]] = {}
    for entry in entries:
        if entry.msgctxt:
            msgids_by_context.setdefault(entry.msgctxt, set()).add(entry.msgid)

    missing: list[ReactMessage] = []
    for message in messages:
        known_for_context = msgids_by_context.get(message.context, set())
        if known_for_context and message.msgid not in known_for_context:
            raise ValueError(
                f"{path}: context {message.context!r} already has a different msgid: "
                f"{sorted(known_for_context)!r}"
            )
        if message.msgid in plain_msgids or (message.context, message.msgid) in contextual:
            continue
        missing.append(message)
    return tuple(missing)


def react_translation_coverage(
    path: Path,
    messages: Sequence[ReactMessage],
) -> ReactTranslationCoverage:
    """Count real React translations, excluding empty/fuzzy source fallbacks."""

    catalog = polib.pofile(str(path), encoding="utf-8", wrapwidth=0)
    entries = {
        (entry.msgctxt, entry.msgid): entry
        for entry in catalog
        if not entry.obsolete
    }
    translated = 0
    for message in messages:
        candidates = (
            entries.get((message.context, message.msgid)),
            entries.get((message.key, message.msgid)),
            entries.get((None, message.msgid)),
        )
        if any(entry and entry.msgstr and not entry.fuzzy for entry in candidates):
            translated += 1
    return ReactTranslationCoverage(len(messages), translated)


def _render_entries(messages: Sequence[ReactMessage], newline: bytes) -> bytes:
    marker = "#" * 78
    header = "\n".join((marker, f"# {SECTION_TITLE}", marker))
    entries = (
        str(polib.POEntry(msgctxt=message.context, msgid=message.msgid, msgstr="")).rstrip()
        for message in messages
    )
    rendered = header + "\n\n" + "\n\n".join(entries) + "\n"
    return rendered.replace("\n", newline.decode("ascii")).encode("utf-8")


def append_missing_messages(path: Path, messages: Sequence[ReactMessage]) -> int:
    missing = missing_react_messages(path, messages)
    if not missing:
        return 0
    original = Path(path).read_bytes()
    newline = b"\r\n" if b"\r\n" in original else b"\n"
    separator = b"" if original.endswith(newline * 2) else newline
    addition = _render_entries(missing, newline)
    Path(path).write_bytes(original + separator + addition)
    return len(missing)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit React source-message coverage in PixelFlasher PO catalogs."
    )
    parser.add_argument("--react-source", type=Path, default=DEFAULT_REACT_SOURCE)
    parser.add_argument("--locale-dir", type=Path, default=DEFAULT_LOCALE_DIR)
    parser.add_argument("--domain", default=DEFAULT_DOMAIN)
    parser.add_argument(
        "--write",
        action="store_true",
        help="Append missing web.<key> contextual entries with empty translations.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        messages = load_react_messages(args.react_source)
        missing_total = 0
        for locale, path in catalog_paths(args.locale_dir, args.domain):
            if args.write:
                added = append_missing_messages(path, messages)
                print(f"{locale}: appended {added} contextual messages")
                missing_total += added
            else:
                missing = missing_react_messages(path, messages)
                if missing:
                    print(
                        f"{locale}: {len(missing)} missing "
                        f"({', '.join(message.key for message in missing[:5])})"
                    )
                    missing_total += len(missing)
                coverage = react_translation_coverage(path, messages)
                print(
                    f"{locale}: {coverage.translated_count}/{coverage.message_count} "
                    f"translated, {coverage.fallback_count} source fallbacks"
                )
        if missing_total and not args.write:
            print(f"error: React gettext coverage is incomplete ({missing_total} entries)")
            return 1
    except (FileNotFoundError, OSError, SyntaxError, UnicodeError, ValueError) as error:
        print(f"error: {error}")
        return 1

    action = "Synchronized" if args.write else "Verified"
    print(
        f"{action} {len(messages)} React source messages across "
        f"{len(EXPECTED_LOCALES)} gettext catalogs"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
