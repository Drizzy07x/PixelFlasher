#!/usr/bin/env python3
"""Verify one closed PixelFlasher packaged-firmware smoke receipt."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from firmware_smoke_contract import (  # noqa: E402
    FirmwareSmokeError,
    validate_firmware_smoke_receipt,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument(
        "--expect-platform",
        choices=("windows", "macos", "linux"),
        required=True,
    )
    parser.add_argument(
        "--expect-architecture",
        choices=("x86_64", "arm64"),
        required=True,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        raw: object = json.loads(args.report.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise FirmwareSmokeError("firmware smoke receipt must be an object")
        source = cast(dict[object, object], raw)
        if any(not isinstance(key, str) for key in source):
            raise FirmwareSmokeError("firmware smoke receipt keys must be strings")
        payload = cast(dict[str, Any], source)
        receipt = validate_firmware_smoke_receipt(
            payload,
            expected_platform=args.expect_platform,
            expected_architecture=args.expect_architecture,
        )
    except (FirmwareSmokeError, OSError, json.JSONDecodeError) as exc:
        print(f"Packaged firmware smoke verification failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
