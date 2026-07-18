#!/usr/bin/env python3
"""Export PixelFlasher gettext catalogs as deterministic React JSON assets.

The generated locale files are deliberately plain ``{msgid: translation}``
objects so they can be consumed without a gettext runtime.  Empty, fuzzy, or
otherwise untranslated entries fall back to their source ``msgid``, matching
the behavior of the existing Python UI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

import polib


SCHEMA_VERSION = 1
DEFAULT_DOMAIN = "pixelflasher"
DEFAULT_FALLBACK_LOCALE = "en"
DEFAULT_LOCALE_DIR = Path("locale")
DEFAULT_OUTPUT_DIR = Path("build/react-i18n")


@dataclass(frozen=True)
class CatalogExport:
    locale: str
    messages: Mapping[str, str]
    translated_count: int
    web_message_count: int
    web_translated_count: int
    source: Path


def discover_catalogs(
    locale_dir: Path, domain: str = DEFAULT_DOMAIN
) -> tuple[tuple[str, Path], ...]:
    """Return locale/catalog pairs in a platform-independent stable order."""

    locale_dir = Path(locale_dir)
    discovered: list[tuple[str, Path]] = []
    for path in locale_dir.glob(f"*/LC_MESSAGES/{domain}.po"):
        locale = path.parent.parent.name
        discovered.append((locale, path))
    discovered.sort(key=lambda item: (item[0], item[1].as_posix()))
    return tuple(discovered)


def _entry_key(entry: polib.POEntry) -> str:
    # GNU gettext uses EOT to disambiguate contextual keys.  React messages use
    # ``web.<key>`` contexts so UI keys can evolve without duplicating a second
    # translation source outside the PO catalogs.
    return f"{entry.msgctxt}\x04{entry.msgid}" if entry.msgctxt else entry.msgid


def load_catalog(locale: str, path: Path) -> CatalogExport:
    """Load one PO file and apply the Python UI's source-string fallback."""

    po = polib.pofile(str(path), encoding="utf-8", wrapwidth=0)
    messages: dict[str, str] = {}
    translated_count = 0
    web_message_count = 0
    web_translated_count = 0

    for entry in po:
        if entry.obsolete:
            continue
        if entry.msgid_plural:
            raise ValueError(
                f"Plural entry {entry.msgid!r} in {path} requires a schema upgrade"
            )
        key = _entry_key(entry)
        if key in messages:
            raise ValueError(f"Duplicate gettext key {key!r} in {path}")
        translated = entry.msgstr if entry.msgstr and not entry.fuzzy else entry.msgid
        if entry.msgstr and not entry.fuzzy:
            translated_count += 1
        if entry.msgctxt and entry.msgctxt.startswith("web."):
            web_message_count += 1
            if entry.msgstr and not entry.fuzzy:
                web_translated_count += 1
        messages[key] = translated

    return CatalogExport(
        locale=locale,
        messages=dict(sorted(messages.items())),
        translated_count=translated_count,
        web_message_count=web_message_count,
        web_translated_count=web_translated_count,
        source=Path(path),
    )


def _json_bytes(value: object) -> bytes:
    text = json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        separators=(",", ": "),
    )
    return f"{text}\n".encode("utf-8")


def build_export_files(
    locale_dir: Path,
    *,
    domain: str = DEFAULT_DOMAIN,
    fallback_locale: str = DEFAULT_FALLBACK_LOCALE,
) -> dict[str, bytes]:
    """Build all output bytes in memory without timestamps or absolute paths."""

    discovered = discover_catalogs(locale_dir, domain)
    if not discovered:
        raise FileNotFoundError(
            f"No {domain}.po catalogs found below {Path(locale_dir).as_posix()}"
        )

    catalogs = [load_catalog(locale, path) for locale, path in discovered]
    locales = {catalog.locale for catalog in catalogs}
    if fallback_locale not in locales:
        raise ValueError(f"Fallback locale {fallback_locale!r} is not present")

    output: dict[str, bytes] = {}
    manifest_locales: list[dict[str, object]] = []
    expected_keys: set[str] | None = None

    for catalog in catalogs:
        keys = set(catalog.messages)
        if expected_keys is None:
            expected_keys = keys
        elif keys != expected_keys:
            missing = sorted(expected_keys - keys)
            extra = sorted(keys - expected_keys)
            raise ValueError(
                f"Catalog key mismatch for {catalog.locale}: "
                f"missing={missing[:5]!r}, extra={extra[:5]!r}"
            )

        filename = f"{catalog.locale}.json"
        content = _json_bytes(catalog.messages)
        output[filename] = content
        manifest_locales.append(
            {
                "file": filename,
                "locale": catalog.locale,
                "messageCount": len(catalog.messages),
                "sha256": hashlib.sha256(content).hexdigest(),
                "translatedCount": catalog.translated_count,
                "webMessageCount": catalog.web_message_count,
                "webTranslatedCount": catalog.web_translated_count,
            }
        )

    output["manifest.json"] = _json_bytes(
        {
            "domain": domain,
            "fallbackLocale": fallback_locale,
            "locales": manifest_locales,
            "schemaVersion": SCHEMA_VERSION,
        }
    )
    return output


def _write_if_changed(path: Path, content: bytes) -> None:
    if path.exists() and path.read_bytes() == content:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def export_catalogs(
    locale_dir: Path,
    output_dir: Path,
    *,
    domain: str = DEFAULT_DOMAIN,
    fallback_locale: str = DEFAULT_FALLBACK_LOCALE,
    check: bool = False,
) -> tuple[str, ...]:
    """Write or verify the deterministic export and return its file names."""

    output_dir = Path(output_dir)
    generated = build_export_files(
        Path(locale_dir), domain=domain, fallback_locale=fallback_locale
    )

    if check:
        mismatches: list[str] = []
        for filename, expected in generated.items():
            path = output_dir / filename
            if not path.is_file() or path.read_bytes() != expected:
                mismatches.append(filename)
        if output_dir.is_dir():
            extras = sorted(
                path.name
                for path in output_dir.glob("*.json")
                if path.name not in generated
            )
            mismatches.extend(f"unexpected:{name}" for name in extras)
        if mismatches:
            raise RuntimeError(
                "Gettext JSON export is stale or incomplete: " + ", ".join(mismatches)
            )
    else:
        output_dir.mkdir(parents=True, exist_ok=True)
        for filename, content in generated.items():
            _write_if_changed(output_dir / filename, content)

    return tuple(sorted(generated))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export gettext PO catalogs as deterministic React JSON files."
    )
    parser.add_argument("--locale-dir", type=Path, default=DEFAULT_LOCALE_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--domain", default=DEFAULT_DOMAIN)
    parser.add_argument("--fallback-locale", default=DEFAULT_FALLBACK_LOCALE)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail unless output-dir already contains exactly the current export.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        files = export_catalogs(
            args.locale_dir,
            args.output_dir,
            domain=args.domain,
            fallback_locale=args.fallback_locale,
            check=args.check,
        )
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}")
        return 1

    verb = "Verified" if args.check else "Exported"
    print(f"{verb} {len(files) - 1} locale catalogs to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
