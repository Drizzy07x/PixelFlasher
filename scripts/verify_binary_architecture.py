#!/usr/bin/env python3
"""Verify an executable's native architecture from its binary header."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pixelflasher_core.platform_tools import binary_architectures  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument(
        "--platform",
        choices=("windows", "linux", "macos"),
        required=True,
    )
    parser.add_argument(
        "--architecture",
        choices=("x86", "x86_64", "arm", "arm64"),
        required=True,
    )
    arguments = parser.parse_args()

    if not arguments.binary.is_file():
        parser.error(f"binary does not exist: {arguments.binary}")

    observed = binary_architectures(arguments.binary, platform=arguments.platform)
    expected = frozenset((arguments.architecture,))
    if observed != expected:
        rendered = ", ".join(sorted(observed)) or "unrecognized"
        parser.error(
            f"expected {arguments.platform}/{arguments.architecture}, found {rendered}: "
            f"{arguments.binary}"
        )
    print(
        f"Verified {arguments.platform}/{arguments.architecture} binary: "
        f"{arguments.binary}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
