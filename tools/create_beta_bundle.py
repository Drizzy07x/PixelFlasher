#!/usr/bin/env python
"""Create a source beta bundle and SHA256 checksum.

This does not replace platform-specific PyInstaller/AppImage builds. It gives
maintainers a reproducible source bundle for testers/developers and CI artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import zipfile
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from constants import APPNAME, VERSION

EXCLUDE_DIRS = {".git", "__pycache__", ".pytest_cache", "build", "dist", "myenv", "venv", ".venv"}
EXCLUDE_SUFFIXES = {".pyc", ".pyo", ".log"}


def should_include(path: Path, root: Path) -> bool:
    rel = path.relative_to(root)
    if any(part in EXCLUDE_DIRS for part in rel.parts):
        return False
    if path.suffix in EXCLUDE_SUFFIXES:
        return False
    return path.is_file()


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def create_bundle(output_dir: str | Path = "dist-beta", label: str | None = None) -> Path:
    root = ROOT
    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    version_label = label or VERSION
    archive = out_dir / f"{APPNAME}-{version_label}-source.zip"

    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zipf:
        for path in sorted(root.rglob("*")):
            if should_include(path, root):
                zipf.write(path, Path(f"{APPNAME}-{version_label}") / path.relative_to(root))

    checksum = sha256(archive)
    checksum_file = archive.with_suffix(archive.suffix + ".sha256")
    checksum_file.write_text(f"{checksum}  {archive.name}\n", encoding="utf-8")
    return archive


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a PixelFlasher beta source bundle")
    parser.add_argument("--output-dir", default="dist-beta")
    parser.add_argument("--label", help="version label, e.g. 9.2.0-beta.1")
    args = parser.parse_args()
    archive = create_bundle(args.output_dir, args.label)
    print(f"Created {archive}")
    print(f"Checksum {archive}.sha256")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
