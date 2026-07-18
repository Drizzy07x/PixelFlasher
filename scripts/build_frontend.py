#!/usr/bin/env python3
"""Build or verify the locked React WebView assets before desktop packaging."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
WEB_ROOT = REPOSITORY_ROOT / "ui" / "web"
EXPECTED_NODE_VERSION = "v24.14.0"
EXPECTED_PNPM_VERSION = "11.9.0"


def _run(
    argv: Sequence[str],
    *,
    cwd: Path = REPOSITORY_ROOT,
    env: dict[str, str] | None = None,
) -> None:
    print("+ " + " ".join(argv), flush=True)
    subprocess.run(tuple(argv), cwd=cwd, env=env, check=True)


def _executable(name: str) -> str:
    executable = shutil.which(name)
    if not executable:
        raise RuntimeError(f"required frontend executable is unavailable: {name}")
    return executable


def _version(executable: str, expected: str) -> None:
    result = subprocess.run(
        (executable, "--version"),
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    actual = result.stdout.strip()
    if actual != expected:
        raise RuntimeError(
            f"locked frontend runtime mismatch for {Path(executable).name}: "
            f"expected {expected}, got {actual or '<empty>'}"
        )


def verify_frontend() -> None:
    _run((sys.executable, "scripts/verify_react_bridge_commands.py"))
    _run(
        (
            sys.executable,
            "scripts/export_gettext_json.py",
            "--output-dir",
            "ui/web/public/i18n",
            "--check",
        )
    )
    _run(
        (
            sys.executable,
            "scripts/export_gettext_json.py",
            "--output-dir",
            "ui/web/dist/i18n",
            "--check",
        )
    )
    _run((sys.executable, "scripts/verify_webview_bundle.py", "ui/web/dist"))


def build_frontend() -> None:
    node = _executable("node")
    pnpm = _executable("pnpm")
    _version(node, EXPECTED_NODE_VERSION)
    _version(pnpm, EXPECTED_PNPM_VERSION)
    _run((sys.executable, "scripts/verify_react_bridge_commands.py"))

    environment = os.environ.copy()
    environment["PIXELFLASHER_PYTHON"] = sys.executable
    _run((pnpm, "install", "--frozen-lockfile"), cwd=WEB_ROOT, env=environment)
    _run((pnpm, "build"), cwd=WEB_ROOT, env=environment)
    verify_frontend()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Verify a frontend built earlier in the same packaging job.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.check_only:
            verify_frontend()
        else:
            build_frontend()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print("Frontend packaging contract passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
