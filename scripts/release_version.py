"""Validate and apply a tag-derived PixelFlasher release version."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

SEMVER = re.compile(
    r"^v?(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)"
    r"(?P<prerelease>-rc\.(?P<rc>[1-9][0-9]*))?$"
)


@dataclass(frozen=True, slots=True)
class ReleaseVersion:
    major: int
    minor: int
    patch: int
    rc: int | None = None

    @classmethod
    def parse(cls, value: str) -> ReleaseVersion:
        match = SEMVER.fullmatch(str(value).strip())
        if match is None:
            raise ValueError("version must be X.Y.Z or X.Y.Z-rc.N")
        return cls(
            int(match.group("major")),
            int(match.group("minor")),
            int(match.group("patch")),
            int(match.group("rc")) if match.group("rc") else None,
        )

    @property
    def text(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        return f"{base}-rc.{self.rc}" if self.rc is not None else base

    @property
    def windows_tuple(self) -> str:
        return f"({self.major},{self.minor},{self.patch},0)"


def _replace_exact(source: str, pattern: str, replacement: str, *, label: str) -> str:
    updated, count = re.subn(pattern, replacement, source, flags=re.MULTILINE)
    if count != 1:
        raise RuntimeError(f"expected exactly one {label} field, found {count}")
    return updated


def _atomic_write(path: Path, content: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def rendered_files(root: Path, version: ReleaseVersion) -> dict[Path, str]:
    constants = root / "constants.py"
    mac_arm = root / "build-on-mac.spec"
    mac_intel = root / "build-on-mac-intel-only.spec"
    windows = root / "windows-version-info.txt"
    package = root / "ui" / "web" / "package.json"
    required = (constants, mac_arm, mac_intel, windows, package)
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"release version targets are missing: {', '.join(missing)}")

    rendered: dict[Path, str] = {}
    rendered[constants] = _replace_exact(
        constants.read_text(encoding="utf-8"),
        r"^VERSION\s*=\s*['\"][^'\"]+['\"]\s*$",
        f"VERSION = '{version.text}'",
        label="constants VERSION",
    )
    for path in (mac_arm, mac_intel):
        rendered[path] = _replace_exact(
            path.read_text(encoding="utf-8"),
            r"^\s*version=['\"][^'\"]+['\"],\s*$",
            f"             version='{version.text}',",
            label=f"{path.name} bundle version",
        )

    windows_source = windows.read_text(encoding="utf-8")
    windows_source = _replace_exact(
        windows_source,
        r"^\s*filevers=\([^\n]+\),\s*$",
        f"    filevers={version.windows_tuple},",
        label="Windows filevers",
    )
    windows_source = _replace_exact(
        windows_source,
        r"^\s*prodvers=\([^\n]+\),\s*$",
        f"    prodvers={version.windows_tuple},",
        label="Windows prodvers",
    )
    windows_source, file_count = re.subn(
        r"StringStruct\(u'(FileVersion|ProductVersion)', u'[^']+'\)",
        lambda match: f"StringStruct(u'{match.group(1)}', u'{version.text}')",
        windows_source,
    )
    if file_count != 2:
        raise RuntimeError(f"expected two Windows string versions, found {file_count}")
    rendered[windows] = windows_source

    package_document = json.loads(package.read_text(encoding="utf-8"))
    if not isinstance(package_document, dict) or "version" not in package_document:
        raise RuntimeError("frontend package.json has no version field")
    package_document["version"] = version.text
    rendered[package] = json.dumps(package_document, ensure_ascii=False, indent=2) + "\n"
    return rendered


def apply_version(root: Path, version: ReleaseVersion) -> None:
    for path, content in rendered_files(root.resolve(), version).items():
        _atomic_write(path, content)


def check_version(root: Path, version: ReleaseVersion) -> None:
    mismatches = [
        str(path.relative_to(root.resolve()))
        for path, expected in rendered_files(root.resolve(), version).items()
        if path.read_text(encoding="utf-8") != expected
    ]
    if mismatches:
        raise RuntimeError(
            f"version {version.text} is not synchronized in: {', '.join(mismatches)}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--apply", metavar="VERSION")
    mode.add_argument("--check", metavar="VERSION")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args(argv)
    value = arguments.apply or arguments.check
    version = ReleaseVersion.parse(value)
    if arguments.apply:
        apply_version(arguments.root, version)
    else:
        check_version(arguments.root, version)
    print(version.text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
