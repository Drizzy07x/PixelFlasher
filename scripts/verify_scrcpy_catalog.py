#!/usr/bin/env python3
"""Verify the packaged signed Scrcpy matrix without network access."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pixelflasher_core.scrcpy_distribution import (  # noqa: E402
    ScrcpyDistributionError,
    load_optional_scrcpy_distribution,
)

REQUIRED_TARGETS = frozenset(
    {
        ("windows", "x86_64"),
        ("windows", "arm64"),
        ("darwin", "x86_64"),
        ("darwin", "arm64"),
        ("linux", "x86_64"),
    }
)


def verify(
    root: Path,
    *,
    allow_missing: bool = False,
    trusted_public_keys: Mapping[str, bytes] | None = None,
) -> str:
    distribution = load_optional_scrcpy_distribution(
        root,
        trusted_public_keys=trusted_public_keys,
    )
    if distribution is None:
        if allow_missing:
            return "Signed Scrcpy catalog is not provisioned in this migration build."
        raise ScrcpyDistributionError(
            "scrcpy_catalog_required",
            "Signed Scrcpy catalog is required for this build.",
        )
    if distribution.targets != REQUIRED_TARGETS:
        raise ScrcpyDistributionError(
            "scrcpy_catalog_matrix_incomplete",
            "Signed Scrcpy catalog does not cover the release matrix.",
        )
    if not distribution.key_ids:
        raise ScrcpyDistributionError(
            "scrcpy_catalog_keys_missing",
            "Signed Scrcpy catalog has no pinned public key.",
        )
    return f"Verified {len(distribution.targets)} signed Scrcpy targets with {len(distribution.key_ids)} pinned key(s)."


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--allow-missing", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        message = verify(args.root, allow_missing=args.allow_missing)
    except ScrcpyDistributionError as exc:
        print(f"Scrcpy catalog verification failed: {exc}", file=sys.stderr)
        return 1
    print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
