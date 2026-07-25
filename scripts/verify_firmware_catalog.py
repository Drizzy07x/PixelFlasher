#!/usr/bin/env python3
"""Verify the packaged signed firmware catalog without network access."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pixelflasher_core.firmware_distribution import (  # noqa: E402
    FirmwareDistributionError,
    load_optional_firmware_distribution,
)

REQUIRED_CHANNELS = frozenset({"stable", "beta", "canary"})
REQUIRED_KINDS = frozenset({"factory", "ota"})


def verify(
    root: Path,
    *,
    allow_missing: bool = False,
    trusted_public_keys: Mapping[str, bytes] | None = None,
) -> str:
    distribution = load_optional_firmware_distribution(
        root,
        trusted_public_keys=trusted_public_keys,
    )
    if distribution is None:
        if allow_missing:
            return "Signed firmware catalog is not provisioned in this migration build."
        raise FirmwareDistributionError(
            "firmware_catalog_required",
            "Signed firmware catalog is required for this build.",
        )
    channels = frozenset(channel for _device, channel, _kind in distribution.targets)
    kinds = frozenset(kind for _device, _channel, kind in distribution.targets)
    if channels != REQUIRED_CHANNELS or kinds != REQUIRED_KINDS:
        raise FirmwareDistributionError(
            "firmware_catalog_matrix_incomplete",
            "Signed firmware catalog must cover stable, beta, canary, factory, and OTA.",
        )
    if not distribution.key_ids:
        raise FirmwareDistributionError(
            "firmware_catalog_keys_missing",
            "Signed firmware catalog has no pinned public key.",
        )
    devices = {device for device, _channel, _kind in distribution.targets}
    return (
        f"Verified {len(distribution.targets)} signed firmware targets for "
        f"{len(devices)} device(s) with {len(distribution.key_ids)} pinned key(s)."
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
    except FirmwareDistributionError as exc:
        print(f"Firmware catalog verification failed: {exc}", file=sys.stderr)
        return 1
    print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
