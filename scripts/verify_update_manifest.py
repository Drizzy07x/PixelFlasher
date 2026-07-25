#!/usr/bin/env python3
"""Verify the packaged signed application-update manifest."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pixelflasher_core.update_distribution import (  # noqa: E402
    UpdateDistributionError,
    load_optional_update_distribution,
)
from pixelflasher_core.updates import UpdateCheckError  # noqa: E402


def verify(
    path: Path,
    *,
    allow_missing: bool = False,
    trusted_public_keys: Mapping[str, bytes] | None = None,
) -> str:
    distribution = load_optional_update_distribution(
        path,
        trusted_public_keys=trusted_public_keys,
    )
    if distribution is None:
        if allow_missing:
            return "Signed update manifest is not provisioned in this migration build."
        raise UpdateDistributionError(
            "update_manifest_required",
            "Signed update manifest is required for this build.",
        )
    try:
        manifest = distribution.verifier.verify(distribution.document)
    except UpdateCheckError as exc:
        raise UpdateDistributionError(exc.code, str(exc)) from exc
    if not distribution.key_ids:
        raise UpdateDistributionError(
            "update_manifest_keys_missing",
            "Signed update manifest has no pinned public key.",
        )
    return (
        f"Verified signed {manifest.channel} update {manifest.version} at "
        f"sequence {manifest.sequence} with {len(distribution.key_ids)} pinned key(s)."
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", type=Path, required=True)
    parser.add_argument("--allow-missing", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        message = verify(args.path, allow_missing=args.allow_missing)
    except UpdateDistributionError as exc:
        print(f"Update manifest verification failed: {exc}", file=sys.stderr)
        return 1
    print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
