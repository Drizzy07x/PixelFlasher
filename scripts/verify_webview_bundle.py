#!/usr/bin/env python3
"""Verify that the packaged React UI is safe to load from a desktop WebView.

The desktop host opens ``index.html`` through ``file://``.  That environment
cannot rely on Vite's development server, module-script loading, or remote
assets.  This verifier intentionally uses only the Python standard library so
the exact same release gate can run on every packaging runner.
"""

from __future__ import annotations

import argparse
import re
from collections.abc import Sequence
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

_IMPORT_META = re.compile(r"\bimport\s*\.\s*meta\b")
_CSS_URL = re.compile(r"url\(\s*([\"']?)(.*?)\1\s*\)", re.IGNORECASE)
_TEXT_ASSET_SUFFIXES = frozenset({".css", ".html", ".js", ".mjs"})


@dataclass(frozen=True)
class AssetReference:
    source: Path
    attribute: str
    value: str


class _IndexParser(HTMLParser):
    def __init__(self, source: Path) -> None:
        super().__init__(convert_charrefs=True)
        self.source = source
        self.references: list[AssetReference] = []
        self.external_scripts = 0
        self.module_scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.casefold(): value or "" for name, value in attrs}
        tag = tag.casefold()
        if tag == "script":
            if values.get("type", "").strip().casefold() == "module":
                self.module_scripts.append(values.get("src") or "inline script")
            if values.get("src"):
                self.external_scripts += 1
                self.references.append(AssetReference(self.source, "src", values["src"]))
        elif tag == "link" and values.get("href"):
            self.references.append(AssetReference(self.source, "href", values["href"]))
        elif tag in {"img", "source"} and values.get("src"):
            self.references.append(AssetReference(self.source, "src", values["src"]))


def _resolve_local_reference(root: Path, reference: AssetReference) -> Path | None:
    raw = reference.value.strip()
    if not raw or raw.startswith("#") or raw.casefold().startswith("data:"):
        return None
    parsed = urlsplit(raw)
    if parsed.scheme or parsed.netloc or raw.startswith(("/", "\\")):
        raise ValueError(
            f"{reference.source}: {reference.attribute} must be a local relative asset, got {raw!r}"
        )
    relative = Path(unquote(parsed.path.replace("/", str(Path('/')))))
    candidate = (reference.source.parent / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise ValueError(
            f"{reference.source}: asset escapes the bundle root: {raw!r}"
        ) from error
    if not candidate.is_file():
        raise ValueError(f"{reference.source}: referenced asset is missing: {raw!r}")
    return candidate


def verify_bundle(bundle_dir: Path) -> tuple[Path, ...]:
    """Validate a classic, local-only bundle and return checked text assets."""

    root = Path(bundle_dir).resolve()
    index = root / "index.html"
    if not index.is_file():
        raise ValueError(f"Static WebView entrypoint is missing: {index}")

    parser = _IndexParser(index)
    parser.feed(index.read_text(encoding="utf-8"))
    parser.close()
    if parser.module_scripts:
        raise ValueError(
            "Static WebView entrypoint must not use type=module: "
            + ", ".join(parser.module_scripts)
        )
    if not parser.external_scripts:
        raise ValueError("Static WebView entrypoint must load a local classic script")
    for reference in parser.references:
        _resolve_local_reference(root, reference)

    checked: list[Path] = []
    for path in sorted(
        (candidate for candidate in root.rglob("*") if candidate.is_file()),
        key=lambda item: item.relative_to(root).as_posix(),
    ):
        if path.suffix.casefold() not in _TEXT_ASSET_SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8")
        checked.append(path)
        if _IMPORT_META.search(text):
            raise ValueError(f"Static WebView bundle contains import.meta: {path}")
        if path.suffix.casefold() == ".mjs":
            raise ValueError(f"Static WebView bundle contains an ES module asset: {path}")
        if path.suffix.casefold() == ".css":
            for match in _CSS_URL.finditer(text):
                _resolve_local_reference(
                    root,
                    AssetReference(path, "url()", match.group(2)),
                )

    return tuple(checked)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify a classic, self-contained file:// WebView bundle."
    )
    parser.add_argument("bundle_dir", nargs="?", type=Path, default=Path("ui/web/dist"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        checked = verify_bundle(args.bundle_dir)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"error: {error}")
        return 1
    print(
        f"Verified classic self-contained WebView bundle at {args.bundle_dir} "
        f"({len(checked)} text assets)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
