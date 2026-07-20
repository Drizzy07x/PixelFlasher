#!/usr/bin/env python3
"""Verify the packaged signed Platform Tools matrix without network access."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pixelflasher_core.platform_tools_distribution import (  # noqa: E402
    PlatformToolsDistributionError,
    load_optional_platform_tools_distribution,
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
    distribution = load_optional_platform_tools_distribution(
        root,
        trusted_public_keys=trusted_public_keys,
    )
    if distribution is None:
        if allow_missing:
            return "Signed Platform Tools catalog is not provisioned in this migration build."
        raise PlatformToolsDistributionError(
            "platform_tools_catalog_required",
            "Signed Platform Tools catalog is required for this build.",
        )
    if distribution.targets != REQUIRED_TARGETS:
        raise PlatformToolsDistributionError(
            "platform_tools_catalog_matrix_incomplete",
            "Signed Platform Tools catalog does not cover the release matrix.",
        )
    if not distribution.key_ids:
        raise PlatformToolsDistributionError(
            "platform_tools_catalog_keys_missing",
            "Signed Platform Tools catalog has no pinned public key.",
        )
    return (
        f"Verified {len(distribution.targets)} signed Platform Tools targets "
        f"with {len(distribution.key_ids)} pinned key(s)."
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--allow-missing", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        message = verify(args.root, allow_missing=args.allow_missing)
    except PlatformToolsDistributionError as exc:
        print(f"Platform Tools catalog verification failed: {exc}", file=sys.stderr)
        return 1
    print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
