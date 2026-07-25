"""Load the packaged RSA recipient used by encrypted support bundles."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_MAXIMUM_KEY_BYTES = 64 * 1024


class SupportDistributionError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class PackagedSupportRecipient:
    public_key_pem: bytes
    key_id: str


def load_optional_support_recipient(
    path: str | Path,
) -> PackagedSupportRecipient | None:
    candidate = Path(path)
    if not candidate.exists():
        return None
    return load_support_recipient(candidate)


def load_support_recipient(path: str | Path) -> PackagedSupportRecipient:
    candidate = Path(path)
    try:
        resolved = candidate.expanduser().resolve(strict=True)
    except OSError as exc:
        raise SupportDistributionError(
            "support_recipient_missing",
            "Packaged support recipient public key is missing.",
        ) from exc
    if candidate.is_symlink() or candidate.is_junction() or not resolved.is_file():
        raise SupportDistributionError(
            "support_recipient_path_invalid",
            "Packaged support recipient public key path is invalid.",
        )
    try:
        encoded = resolved.read_bytes()
    except OSError as exc:
        raise SupportDistributionError(
            "support_recipient_unreadable",
            "Packaged support recipient public key is unreadable.",
        ) from exc
    if not encoded or len(encoded) > _MAXIMUM_KEY_BYTES:
        raise SupportDistributionError(
            "support_recipient_size_invalid",
            "Packaged support recipient public key size is invalid.",
        )
    try:
        key = serialization.load_pem_public_key(encoded)
    except (TypeError, ValueError) as exc:
        raise SupportDistributionError(
            "support_recipient_key_invalid",
            "Packaged support recipient public key is invalid.",
        ) from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
        raise SupportDistributionError(
            "support_recipient_key_invalid",
            "Packaged support recipient public key must be RSA-2048 or stronger.",
        )
    subject_public_key = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_id = f"support-rsa-{hashlib.sha256(subject_public_key).hexdigest()[:16]}"
    return PackagedSupportRecipient(encoded, key_id)


__all__ = [
    "PackagedSupportRecipient",
    "SupportDistributionError",
    "load_optional_support_recipient",
    "load_support_recipient",
]
