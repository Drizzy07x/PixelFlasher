"""Load packaged application-update metadata with compiled trust roots."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .artifact_downloads import PinnedEd25519Keyring
from .artifact_trust import UPDATE_ED25519_PUBLIC_KEYS
from .updates import (
    UpdateCancellation,
    UpdateManifestSource,
    UpdateManifestVerifier,
)

_MAX_MANIFEST_BYTES = 64 * 1024


class UpdateDistributionError(RuntimeError):
    """Packaged update metadata or its trust policy is unavailable."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class PackagedUpdateManifestSource(UpdateManifestSource):
    document: bytes

    def load(self, cancellation: UpdateCancellation) -> bytes:
        del cancellation
        return bytes(self.document)


@dataclass(frozen=True, slots=True)
class PackagedUpdateDistribution:
    source: PackagedUpdateManifestSource
    verifier: UpdateManifestVerifier
    key_ids: frozenset[str]
    document: bytes


def load_optional_update_distribution(
    manifest_path: str | Path,
    *,
    trusted_public_keys: Mapping[str, bytes] | None = None,
) -> PackagedUpdateDistribution | None:
    path = Path(manifest_path)
    if not path.exists():
        return None
    return load_update_distribution(
        path,
        trusted_public_keys=trusted_public_keys,
    )


def load_update_distribution(
    manifest_path: str | Path,
    *,
    trusted_public_keys: Mapping[str, bytes] | None = None,
) -> PackagedUpdateDistribution:
    path = Path(manifest_path)
    try:
        resolved = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise UpdateDistributionError(
            "update_manifest_missing",
            "Packaged update manifest is missing.",
        ) from exc
    if path.is_symlink() or path.is_junction() or not resolved.is_file():
        raise UpdateDistributionError(
            "update_manifest_path_invalid",
            "Packaged update manifest path is invalid.",
        )
    try:
        document = resolved.read_bytes()
    except OSError as exc:
        raise UpdateDistributionError(
            "update_manifest_unreadable",
            "Packaged update manifest is unreadable.",
        ) from exc
    if not document or len(document) > _MAX_MANIFEST_BYTES:
        raise UpdateDistributionError(
            "update_manifest_size_invalid",
            "Packaged update manifest size is invalid.",
        )
    public_keys = UPDATE_ED25519_PUBLIC_KEYS if trusted_public_keys is None else trusted_public_keys
    try:
        keyring = PinnedEd25519Keyring(public_keys)
        verifier = UpdateManifestVerifier(keyring)
    except (TypeError, ValueError) as exc:
        raise UpdateDistributionError(
            "update_manifest_policy_invalid",
            "Packaged update trust policy is invalid.",
        ) from exc
    return PackagedUpdateDistribution(
        source=PackagedUpdateManifestSource(document),
        verifier=verifier,
        key_ids=keyring.key_ids,
        document=document,
    )


__all__ = [
    "PackagedUpdateDistribution",
    "PackagedUpdateManifestSource",
    "UpdateDistributionError",
    "load_optional_update_distribution",
    "load_update_distribution",
]
