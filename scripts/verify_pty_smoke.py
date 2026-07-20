#!/usr/bin/env python3
"""Verify a closed PixelFlasher packaged-PTY smoke receipt."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pty_smoke_contract import (  # noqa: E402
    PtySmokeError,
    load_pty_smoke_receipt,
    validate_pty_smoke_receipt,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--expect-platform", choices=("windows", "macos", "linux"), required=True)
    parser.add_argument("--expect-architecture", choices=("x86_64", "arm64"), required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        receipt = validate_pty_smoke_receipt(
            load_pty_smoke_receipt(args.report),
            expected_platform=args.expect_platform,
            expected_architecture=args.expect_architecture,
        )
    except PtySmokeError as exc:
        print(f"Packaged PTY smoke verification failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
