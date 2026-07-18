#!/usr/bin/env python3
"""Apply a reviewed React translation map without reformatting a PO catalog."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Mapping, Sequence

import polib

try:
    from scripts.sync_react_gettext import (
        DEFAULT_DOMAIN,
        DEFAULT_LOCALE_DIR,
        EXPECTED_LOCALES,
        load_react_messages,
    )
except ModuleNotFoundError:  # Direct ``python scripts/apply_...py`` execution.
    from sync_react_gettext import (  # type: ignore[no-redef]
        DEFAULT_DOMAIN,
        DEFAULT_LOCALE_DIR,
        EXPECTED_LOCALES,
        load_react_messages,
    )


PLACEHOLDER_PATTERN = re.compile(r"\{[A-Za-z][A-Za-z0-9_]*\}")
TRANSLATED_LOCALES = tuple(locale for locale in EXPECTED_LOCALES if locale != "en")


def load_translation_map(path: Path) -> dict[str, str]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(translation, str)
        for key, translation in value.items()
    ):
        raise ValueError("translation input must be a JSON object of string keys and values")
    return value


def validate_translation_map(translations: Mapping[str, str]) -> None:
    messages = {message.key: message for message in load_react_messages()}
    # The catalog itself determines which React strings use web context; the
    # apply step below enforces exact coverage for that locale.
    unknown = sorted(set(translations) - set(messages))
    if unknown:
        raise ValueError(f"unknown React message keys: {unknown[:5]!r}")
    for key, translation in translations.items():
        if not translation.strip():
            raise ValueError(f"translation for {key!r} is empty")
        source = messages[key].msgid
        if Counter(PLACEHOLDER_PATTERN.findall(source)) != Counter(
            PLACEHOLDER_PATTERN.findall(translation)
        ):
            raise ValueError(f"placeholder mismatch for {key!r}")
        if "\n" in translation or "\r" in translation:
            raise ValueError(f"translation for {key!r} must be a single logical line")


def apply_translation_map(path: Path, translations: Mapping[str, str]) -> int:
    validate_translation_map(translations)
    messages = {message.key: message for message in load_react_messages()}
    catalog = polib.pofile(str(path), encoding="utf-8", wrapwidth=0)
    contextual = {
        entry.msgctxt: entry
        for entry in catalog
        if entry.msgctxt and entry.msgctxt.startswith("web.") and not entry.obsolete
    }
    expected_keys = {context.removeprefix("web.") for context in contextual}
    missing = sorted(expected_keys - set(translations))
    extra = sorted(set(translations) - expected_keys)
    if missing or extra:
        raise ValueError(
            f"translation map must cover every web context: missing={missing[:5]!r}, "
            f"extra={extra[:5]!r}"
        )

    with Path(path).open("r", encoding="utf-8", newline="") as stream:
        source = stream.read()
    for key in sorted(expected_keys):
        entry = contextual[f"web.{key}"]
        if entry.msgid != messages[key].msgid:
            raise ValueError(f"catalog/source msgid mismatch for {key!r}")
        context = re.escape(polib.escape(entry.msgctxt))
        pattern = re.compile(
            rf'(?ms)(^msgctxt "{context}"\r?\n.*?^msgstr )'
            r'"(?:\\.|[^"\\])*"(?=\r?$)'
        )
        escaped_translation = polib.escape(translations[key])
        source, count = pattern.subn(
            lambda match: f'{match.group(1)}"{escaped_translation}"',
            source,
            count=1,
        )
        if count != 1:
            raise ValueError(f"could not update exactly one PO entry for web.{key}")

    with Path(path).open("w", encoding="utf-8", newline="") as stream:
        stream.write(source)
    updated = polib.pofile(str(path), encoding="utf-8", wrapwidth=0)
    by_context = {entry.msgctxt: entry for entry in updated if entry.msgctxt}
    for key, translation in translations.items():
        if by_context[f"web.{key}"].msgstr != translation:
            raise ValueError(f"round-trip verification failed for web.{key}")
    return len(translations)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--locale", choices=TRANSLATED_LOCALES, required=True)
    parser.add_argument("--translations", type=Path, required=True)
    parser.add_argument("--locale-dir", type=Path, default=DEFAULT_LOCALE_DIR)
    parser.add_argument("--domain", default=DEFAULT_DOMAIN)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    path = args.locale_dir / args.locale / "LC_MESSAGES" / f"{args.domain}.po"
    try:
        translations = load_translation_map(args.translations)
        count = apply_translation_map(path, translations)
    except (FileNotFoundError, KeyError, OSError, UnicodeError, ValueError) as error:
        print(f"error: {error}")
        return 1
    print(f"Applied {count} reviewed React translations to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
