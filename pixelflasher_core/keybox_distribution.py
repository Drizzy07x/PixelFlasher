"""Load signed keybox-revocation evidence with compiled trust roots."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

from .artifact_trust import KEYBOX_REVOCATION_ED25519_PUBLIC_KEYS
from .keybox_validation import SignedKeyboxRevocationProvider


class KeyboxDistributionError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class PackagedKeyboxRevocations:
    provider: SignedKeyboxRevocationProvider
    key_ids: frozenset[str]


def load_optional_keybox_revocations(
    path: str | Path,
    *,
    trusted_public_keys: Mapping[str, bytes] | None = None,
) -> PackagedKeyboxRevocations | None:
    candidate = Path(path)
    if not candidate.exists():
        return None
    return load_keybox_revocations(
        candidate,
        trusted_public_keys=trusted_public_keys,
    )


def load_keybox_revocations(
    path: str | Path,
    *,
    trusted_public_keys: Mapping[str, bytes] | None = None,
) -> PackagedKeyboxRevocations:
    candidate = Path(path)
    try:
        resolved = candidate.expanduser().resolve(strict=True)
    except OSError as exc:
        raise KeyboxDistributionError(
            "keybox_revocations_missing",
            "Packaged keybox revocation evidence is missing.",
        ) from exc
    if candidate.is_symlink() or candidate.is_junction() or not resolved.is_file():
        raise KeyboxDistributionError(
            "keybox_revocations_path_invalid",
            "Packaged keybox revocation evidence path is invalid.",
        )
    raw_keys = KEYBOX_REVOCATION_ED25519_PUBLIC_KEYS if trusted_public_keys is None else trusted_public_keys
    keys: dict[str, ed25519.Ed25519PublicKey] = {}
    try:
        for key_id, encoded in raw_keys.items():
            if not isinstance(key_id, str) or not key_id:
                raise ValueError("invalid key ID")
            keys[key_id] = ed25519.Ed25519PublicKey.from_public_bytes(encoded)
        provider = SignedKeyboxRevocationProvider(resolved, keys)
    except (TypeError, ValueError) as exc:
        raise KeyboxDistributionError(
            "keybox_revocations_policy_invalid",
            "Packaged keybox revocation trust policy is invalid.",
        ) from exc
    return PackagedKeyboxRevocations(provider, frozenset(keys))


__all__ = [
    "KeyboxDistributionError",
    "PackagedKeyboxRevocations",
    "load_keybox_revocations",
    "load_optional_keybox_revocations",
]
