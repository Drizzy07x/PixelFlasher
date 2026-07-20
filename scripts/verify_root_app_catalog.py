#!/usr/bin/env python3
"""Verify the packaged signed root-app matrix without network access."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pixelflasher_core.root_app_distribution import (  # noqa: E402
    RootAppDistributionError,
    load_optional_root_app_distribution,
)

REQUIRED_TARGETS = frozenset(
    {
        ("magisk", "stable", "universal"),
        ("apatch", "stable", "universal"),
        ("kernelsu", "stable", "arm64"),
        ("kernelsu", "stable", "x86_64"),
        ("kernelsu-next", "stable", "arm64"),
        ("kernelsu-next", "stable", "x86_64"),
        ("sukisu", "stable", "arm64"),
        ("sukisu", "stable", "arm"),
        ("sukisu", "stable", "x86_64"),
        ("wild-ksu", "stable", "arm64"),
        ("wild-ksu", "stable", "x86_64"),
        ("legacy", "stable", "arm64"),
        ("legacy", "stable", "arm"),
    }
)


def verify(
    root: Path,
    *,
    allow_missing: bool = False,
    trusted_public_keys: Mapping[str, bytes] | None = None,
) -> str:
    distribution = load_optional_root_app_distribution(
        root,
        trusted_public_keys=trusted_public_keys,
    )
    if distribution is None:
        if allow_missing:
            return "Signed root-app catalog is not provisioned in this migration build."
        raise RootAppDistributionError(
            "root_app_catalog_required",
            "Signed root-app catalog is required for this build.",
        )
    if distribution.targets != REQUIRED_TARGETS:
        raise RootAppDistributionError(
            "root_app_catalog_matrix_incomplete",
            "Signed root-app catalog does not cover the audited stable matrix.",
        )
    if not distribution.key_ids:
        raise RootAppDistributionError(
            "root_app_catalog_keys_missing",
            "Signed root-app catalog has no pinned public key.",
        )
    return (
        f"Verified {len(distribution.targets)} signed root-app targets with {len(distribution.key_ids)} pinned key(s)."
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
    except RootAppDistributionError as exc:
        print(f"Root-app catalog verification failed: {exc}", file=sys.stderr)
        return 1
    print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
