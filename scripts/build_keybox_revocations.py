#!/usr/bin/env python3
"""Sign a keybox revocation snapshot from Google's attestation status list.

Google publishes revoked attestation keys keyed by decimal serial number, while
a certificate serial is matched as lowercase hex, so every entry is converted
rather than copied. The snapshot carries its own validity window, which the
runtime caps at 31 days, so this has to be re-run before the current one lapses.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import urllib.request
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from pixelflasher_core.artifact_trust import (  # noqa: E402
    KEYBOX_REVOCATION_ED25519_PUBLIC_KEYS,
)

STATUS_URL = "https://android.googleapis.com/attestation/status"
SOURCE_ID = "android-attestation-status"
MAXIMUM_WINDOW_DAYS = 31
KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class RevocationBuildError(RuntimeError):
    """The snapshot cannot be produced from the supplied inputs."""


def _private_key(path: Path, key_id: str) -> Ed25519PrivateKey:
    loaded = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise RevocationBuildError("the signing key must be an Ed25519 private key")
    pinned = KEYBOX_REVOCATION_ED25519_PUBLIC_KEYS.get(key_id)
    if pinned is None:
        raise RevocationBuildError(f"signing key ID is not pinned in artifact_trust: {key_id}")
    raw = loaded.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if raw != pinned:
        raise RevocationBuildError(f"the private key does not match the pinned key for {key_id}")
    return loaded


def _status_document(source: Path | None) -> dict[str, object]:
    if source is not None:
        raw = source.read_bytes()
    else:
        request = urllib.request.Request(  # noqa: S310 - fixed https endpoint
            STATUS_URL,
            headers={"Cache-Control": "no-cache"},
        )
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
            raw = response.read()
    document = json.loads(raw.decode("utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("entries"), dict):
        raise RevocationBuildError("the attestation status document is malformed")
    return document


def revoked_serials(document: dict[str, object]) -> list[str]:
    """Normalize every revoked serial to the lowercase hex form used for lookup.

    Google keys the status list by hexadecimal serial number. Many entries
    contain only decimal digits, which makes them easy to mistake for base-ten
    values, so the whole set is validated as hex rather than parsed leniently.
    """

    entries = document["entries"]
    assert isinstance(entries, dict)
    serials: set[str] = set()
    for serial, detail in entries.items():
        if not isinstance(detail, dict) or detail.get("status") != "REVOKED":
            continue
        candidate = str(serial).strip().casefold()
        if re.fullmatch(r"[0-9a-f]{1,40}", candidate) is None:
            raise RevocationBuildError(f"unparsable attestation serial: {serial!r}")
        serials.add(candidate.lstrip("0") or "0")
    return sorted(serials)


def build_snapshot(
    *,
    private_key: Path,
    key_id: str,
    output: Path,
    valid_days: int,
    status_file: Path | None,
    now: datetime | None = None,
) -> int:
    if KEY_ID.fullmatch(key_id) is None:
        raise RevocationBuildError(f"invalid key id: {key_id!r}")
    if not 1 <= valid_days <= MAXIMUM_WINDOW_DAYS:
        raise RevocationBuildError(f"valid-days must be between 1 and {MAXIMUM_WINDOW_DAYS}")

    private = _private_key(private_key, key_id)
    serials = revoked_serials(_status_document(status_file))
    issued = (now or datetime.now(UTC)).replace(microsecond=0)
    document: dict[str, object] = {
        "schemaVersion": 1,
        "sourceId": SOURCE_ID,
        "keyId": key_id,
        "issuedAt": issued.isoformat(),
        "expiresAt": (issued + timedelta(days=valid_days)).isoformat(),
        "entries": serials,
    }
    canonical = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    document["signature"] = base64.b64encode(private.sign(canonical)).decode("ascii")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return len(serials)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--valid-days", type=int, default=30)
    parser.add_argument(
        "--status-file",
        type=Path,
        help="use a previously downloaded status document instead of fetching it",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        count = build_snapshot(
            private_key=args.private_key,
            key_id=args.key_id,
            output=args.output,
            valid_days=args.valid_days,
            status_file=args.status_file,
        )
    except (RevocationBuildError, OSError, ValueError, KeyError) as error:
        print(f"error: {error}")
        return 1
    print(f"Signed a revocation snapshot with {count} revoked serial(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
