#!/usr/bin/env python3
"""Verify the packaged signed keybox-revocation snapshot."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pixelflasher_core.keybox_distribution import (  # noqa: E402
    KeyboxDistributionError,
    load_optional_keybox_revocations,
)
from pixelflasher_core.keybox_validation import KeyboxRevocationError  # noqa: E402


def verify(
    path: Path,
    *,
    allow_missing: bool = False,
    trusted_public_keys: Mapping[str, bytes] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> str:
    distribution = load_optional_keybox_revocations(
        path,
        trusted_public_keys=trusted_public_keys,
    )
    if distribution is None:
        if allow_missing:
            return "Signed keybox revocation evidence is not provisioned."
        raise KeyboxDistributionError(
            "keybox_revocations_required",
            "Signed keybox revocation evidence is required for this build.",
        )
    try:
        evidence = distribution.provider.load(now=(clock or (lambda: datetime.now(UTC)))())
    except (KeyboxRevocationError, OSError, ValueError) as exc:
        raise KeyboxDistributionError(
            "keybox_revocations_verification_failed",
            "Packaged keybox revocation evidence could not be authenticated.",
        ) from exc
    return (
        f"Verified {len(evidence.revoked_serials)} keybox revocation serial(s) "
        f"from {evidence.source_id} with key {evidence.key_id}."
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
    except KeyboxDistributionError as exc:
        print(f"Keybox revocation verification failed: {exc}", file=sys.stderr)
        return 1
    print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
