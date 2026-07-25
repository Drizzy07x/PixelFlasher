#!/usr/bin/env python3
"""Build or verify the reproducible, architecture-neutral OTA fallback DEX."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RESOURCE_ROOT = ROOT / "resources" / "ota-runner"
LOCK_PATH = RESOURCE_ROOT / "toolchain-lock.json"
OUTPUT_PATH = RESOURCE_ROOT / "runtime" / "pf-ota-runner.dex"


class OtaRunnerBuildError(RuntimeError):
    """The locked OTA runner could not be built or verified."""


def _load_lock() -> dict[str, Any]:
    try:
        document = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OtaRunnerBuildError(f"invalid toolchain lock: {LOCK_PATH}") from exc
    if (
        not isinstance(document, dict)
        or document.get("schemaVersion") != 1
        or document.get("minimumAndroidApi") != 26
        or document.get("javaRelease") != 8
    ):
        raise OtaRunnerBuildError("unsupported OTA runner toolchain lock")
    r8 = document.get("r8")
    if not isinstance(r8, dict) or set(r8) != {"version", "url", "size", "sha256"}:
        raise OtaRunnerBuildError("invalid locked R8 descriptor")
    return document


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verified_r8(lock: dict[str, Any], supplied: Path | None, cache: Path) -> Path:
    r8 = lock["r8"]
    path = supplied or cache / f"r8-{r8['version']}.jar"
    if not path.is_file():
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".download")
        try:
            with urllib.request.urlopen(r8["url"], timeout=60) as response:
                with temporary.open("wb") as output:
                    shutil.copyfileobj(response, output)
            os.replace(temporary, path)
        except (OSError, ValueError) as exc:
            temporary.unlink(missing_ok=True)
            raise OtaRunnerBuildError("failed to download the locked R8 artifact") from exc
    if path.stat().st_size != r8["size"] or _sha256(path) != r8["sha256"]:
        raise OtaRunnerBuildError("the R8 artifact does not match the toolchain lock")
    return path


def _tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise OtaRunnerBuildError(f"required tool is unavailable: {name}")
    return path


def _run(argv: list[str]) -> None:
    completed = subprocess.run(argv, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise OtaRunnerBuildError(f"{Path(argv[0]).name} failed: {detail}")


def build(*, r8_path: Path | None = None, cache: Path | None = None) -> bytes:
    lock = _load_lock()
    cache_root = cache or Path(tempfile.gettempdir()) / "pixelflasher-ota-runner"
    r8 = _verified_r8(lock, r8_path, cache_root)
    javac = _tool("javac")
    java = _tool("java")
    with tempfile.TemporaryDirectory(prefix="pf-ota-runner-build-") as directory:
        temporary = Path(directory)
        stub_classes = temporary / "stubs"
        runner_classes = temporary / "runner"
        dex_output = temporary / "dex"
        stub_classes.mkdir()
        runner_classes.mkdir()
        dex_output.mkdir()
        stubs = sorted((RESOURCE_ROOT / "stubs").rglob("*.java"))
        sources = sorted((RESOURCE_ROOT / "src").rglob("*.java"))
        if not stubs or not sources:
            raise OtaRunnerBuildError("OTA runner sources or compile-only stubs are missing")
        java_release = str(lock["javaRelease"])
        _run(
            [
                javac,
                "-encoding",
                "UTF-8",
                "-source",
                java_release,
                "-target",
                java_release,
                "-g:none",
                "-d",
                str(stub_classes),
                *(str(path) for path in stubs),
            ]
        )
        _run(
            [
                javac,
                "-encoding",
                "UTF-8",
                "-source",
                java_release,
                "-target",
                java_release,
                "-g:none",
                "-classpath",
                str(stub_classes),
                "-d",
                str(runner_classes),
                *(str(path) for path in sources),
            ]
        )
        runner_input = runner_classes / "com" / "pixelflasher" / "ota"
        _run(
            [
                java,
                "-cp",
                str(r8),
                "com.android.tools.r8.D8",
                "--release",
                "--min-api",
                str(lock["minimumAndroidApi"]),
                "--output",
                str(dex_output),
                *(str(path) for path in sorted(runner_input.glob("*.class"))),
            ]
        )
        dex = dex_output / "classes.dex"
        if not dex.is_file() or dex.stat().st_size == 0:
            raise OtaRunnerBuildError("D8 did not produce classes.dex")
        return dex.read_bytes()


def _write_atomic(path: Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(contents)
    os.replace(temporary, path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--r8", type=Path)
    parser.add_argument("--cache", type=Path)
    arguments = parser.parse_args(argv)
    try:
        contents = build(r8_path=arguments.r8, cache=arguments.cache)
        digest = hashlib.sha256(contents).hexdigest()
        if arguments.check:
            if not OUTPUT_PATH.is_file() or OUTPUT_PATH.read_bytes() != contents:
                raise OtaRunnerBuildError(
                    "committed OTA runner differs from the reproducible build; "
                    "run scripts/build_ota_runner.py"
                )
        else:
            _write_atomic(OUTPUT_PATH, contents)
            _write_atomic(OUTPUT_PATH.with_suffix(".sha256"), f"{digest}\n".encode("ascii"))
        print(f"{OUTPUT_PATH.relative_to(ROOT).as_posix()} sha256={digest}")
        return 0
    except OtaRunnerBuildError as exc:
        print(f"OTA runner build failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
