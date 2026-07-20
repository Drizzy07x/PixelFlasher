"""Load an authenticated, packaged root-application distribution catalog."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, cast

from .artifact_downloads import (
    ArtifactDownloader,
    ArtifactDownloadPolicy,
    ArtifactManifestVerifier,
    PinnedEd25519Keyring,
)
from .artifact_trust import ROOT_APP_ED25519_PUBLIC_KEYS
from .root_app_catalog import (
    MappingRootAppManifestCatalog,
    RootAppCatalogSource,
)

_CATALOG_NAME = "catalog.json"
_MAX_CATALOG_BYTES = 128 * 1024
_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_ENTRIES = 64
_MAX_APK_BYTES = 64 * 1024 * 1024
_SAFE_MANIFEST_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}\.json$")
_PACKAGE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_METADATA = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. +()-]{0,63}$")
_PROVIDERS = frozenset({"magisk", "apatch", "kernelsu", "kernelsu-next", "sukisu", "wild-ksu", "legacy"})
_CHANNELS = frozenset({"stable", "beta", "canary"})
_ARCHITECTURES = frozenset({"universal", "arm64", "arm", "x86_64", "x86"})
_APPROVED_HOSTS = frozenset({"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"})


class RootAppDistributionError(RuntimeError):
    """A packaged root-app catalog is absent, malformed or unauthenticated."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class PackagedRootAppDistribution:
    catalog: MappingRootAppManifestCatalog
    downloader: ArtifactDownloader
    targets: frozenset[tuple[str, str, str]]
    key_ids: frozenset[str]


def load_optional_root_app_distribution(
    resource_root: str | Path,
    *,
    trusted_public_keys: Mapping[str, bytes] | None = None,
) -> PackagedRootAppDistribution | None:
    """Return ``None`` only when the whole runtime catalog is absent."""

    root = Path(resource_root)
    if not root.exists():
        return None
    return load_root_app_distribution(root, trusted_public_keys=trusted_public_keys)


def load_root_app_distribution(
    resource_root: str | Path,
    *,
    trusted_public_keys: Mapping[str, bytes] | None = None,
) -> PackagedRootAppDistribution:
    root = _real_directory(Path(resource_root))
    document = _load_json_object(_resource_file(root, _CATALOG_NAME), _MAX_CATALOG_BYTES)
    if set(document) != {"schemaVersion", "allowedHosts", "entries"}:
        raise RootAppDistributionError(
            "root_app_catalog_fields_invalid",
            "Packaged root-app catalog fields are invalid.",
        )
    if document.get("schemaVersion") != 1:
        raise RootAppDistributionError(
            "root_app_catalog_schema_unsupported",
            "Packaged root-app catalog schema is unsupported.",
        )
    allowed_hosts = _allowed_hosts(document.get("allowedHosts"))
    public_keys = ROOT_APP_ED25519_PUBLIC_KEYS if trusted_public_keys is None else trusted_public_keys
    try:
        keyring = PinnedEd25519Keyring(public_keys)
        verifier = ArtifactManifestVerifier(
            keyring,
            ArtifactDownloadPolicy(
                frozenset(allowed_hosts),
                maximum_artifact_bytes=_MAX_APK_BYTES,
            ),
        )
    except (TypeError, ValueError) as exc:
        raise RootAppDistributionError(
            "root_app_catalog_policy_invalid",
            "Packaged root-app trust policy is invalid.",
        ) from exc

    raw_entries = document.get("entries")
    entries = cast(list[object], raw_entries) if isinstance(raw_entries, list) else []
    if not entries or len(entries) > _MAX_ENTRIES:
        raise RootAppDistributionError(
            "root_app_catalog_entries_invalid",
            "Packaged root-app entries are invalid.",
        )

    by_channel: dict[str, list[RootAppCatalogSource]] = {}
    targets: set[tuple[str, str, str]] = set()
    for raw_entry in entries:
        entry = _catalog_entry(raw_entry)
        provider = _choice(entry, "provider", _PROVIDERS)
        channel = _choice(entry, "channel", _CHANNELS)
        architecture = _choice(entry, "architecture", _ARCHITECTURES)
        target = (provider, channel, architecture)
        if target in targets:
            raise RootAppDistributionError(
                "root_app_catalog_target_duplicate",
                "Packaged root-app target is duplicated.",
            )
        targets.add(target)
        flavor = _metadata(entry, "flavor")
        package_name = _required_string(entry, "packageName")
        if _PACKAGE.fullmatch(package_name) is None:
            raise RootAppDistributionError(
                "root_app_catalog_package_invalid",
                "Packaged root-app package name is invalid.",
            )
        signers = _signers(entry.get("signerSha256"))
        name = _required_string(entry, "manifest")
        if not _SAFE_MANIFEST_NAME.fullmatch(name) or PurePosixPath(name).name != name:
            raise RootAppDistributionError(
                "root_app_catalog_path_invalid",
                "Packaged root-app manifest path is invalid.",
            )
        encoded = _manifest_bytes(_resource_file(root, name))
        try:
            verifier.verify(
                encoded,
                expected_platform="android",
                expected_arch=architecture,
            )
        except Exception as exc:
            raise RootAppDistributionError(
                "root_app_manifest_verification_failed",
                "Packaged root-app manifest could not be authenticated.",
            ) from exc
        by_channel.setdefault(channel, []).append(
            RootAppCatalogSource(
                provider=provider,
                channel=channel,
                flavor=flavor,
                package_name=package_name,
                signer_sha256=signers,
                manifest_document=encoded,
            )
        )

    return PackagedRootAppDistribution(
        catalog=MappingRootAppManifestCatalog(by_channel),
        downloader=ArtifactDownloader(verifier),
        targets=frozenset(targets),
        key_ids=keyring.key_ids,
    )


def _catalog_entry(raw: object) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise RootAppDistributionError("root_app_catalog_entry_invalid", "Catalog entry is invalid.")
    entry = cast(dict[str, object], raw)
    if set(entry) != {
        "provider",
        "channel",
        "flavor",
        "packageName",
        "signerSha256",
        "architecture",
        "manifest",
    }:
        raise RootAppDistributionError("root_app_catalog_entry_invalid", "Catalog entry is invalid.")
    return entry


def _real_directory(path: Path) -> Path:
    try:
        root = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise RootAppDistributionError("root_app_catalog_missing", "Packaged root-app catalog is missing.") from exc
    if path.is_symlink() or path.is_junction() or not root.is_dir():
        raise RootAppDistributionError("root_app_catalog_root_invalid", "Packaged root-app catalog root is invalid.")
    return root


def _resource_file(root: Path, name: str) -> Path:
    candidate = root / name
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise RootAppDistributionError("root_app_catalog_file_missing", "Packaged root-app file is missing.") from exc
    if candidate.is_symlink() or candidate.is_junction() or resolved.parent != root or not resolved.is_file():
        raise RootAppDistributionError("root_app_catalog_path_invalid", "Packaged root-app path is invalid.")
    return resolved


def _load_json_object(path: Path, maximum_bytes: int) -> dict[str, Any]:
    try:
        encoded = path.read_bytes()
        if not encoded or len(encoded) > maximum_bytes:
            raise ValueError("size")
        decoded = cast(
            object,
            json.loads(encoded.decode("utf-8", "strict"), object_pairs_hook=_reject_duplicate_keys),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise RootAppDistributionError(
            "root_app_catalog_json_invalid", "Packaged root-app catalog is not valid JSON."
        ) from exc
    if not isinstance(decoded, dict):
        raise RootAppDistributionError("root_app_catalog_json_invalid", "Packaged root-app catalog must be an object.")
    return cast(dict[str, Any], decoded)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    values: dict[str, object] = {}
    for key, value in pairs:
        if key in values:
            raise RootAppDistributionError(
                "root_app_catalog_field_duplicate", "Packaged root-app catalog contains a duplicate field."
            )
        values[key] = value
    return values


def _allowed_hosts(raw: object) -> tuple[str, ...]:
    items = cast(list[object], raw) if isinstance(raw, list) else []
    if not items or len(items) > len(_APPROVED_HOSTS):
        raise RootAppDistributionError("root_app_catalog_hosts_invalid", "Packaged root-app hosts are invalid.")
    values: list[str] = []
    for value in items:
        if not isinstance(value, str) or value not in _APPROVED_HOSTS or value in values:
            raise RootAppDistributionError("root_app_catalog_hosts_invalid", "Packaged root-app hosts are invalid.")
        values.append(value)
    if "github.com" not in values:
        raise RootAppDistributionError("root_app_catalog_hosts_invalid", "Packaged root-app hosts are invalid.")
    return tuple(values)


def _choice(values: Mapping[str, object], key: str, allowed: frozenset[str]) -> str:
    value = _required_string(values, key).casefold()
    if value not in allowed:
        raise RootAppDistributionError("root_app_catalog_entry_invalid", f"Catalog {key} is invalid.")
    return value


def _metadata(values: Mapping[str, object], key: str) -> str:
    value = _required_string(values, key)
    if _METADATA.fullmatch(value) is None:
        raise RootAppDistributionError("root_app_catalog_entry_invalid", f"Catalog {key} is invalid.")
    return value


def _required_string(values: Mapping[str, object], key: str) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value:
        raise RootAppDistributionError("root_app_catalog_entry_invalid", f"Catalog {key} is invalid.")
    return value


def _signers(raw: object) -> tuple[str, ...]:
    items = cast(list[object], raw) if isinstance(raw, list) else []
    values = tuple(value for value in items if isinstance(value, str))
    if (
        not values
        or len(values) != len(items)
        or len(values) != len(set(values))
        or any(_SHA256.fullmatch(value) is None for value in values)
    ):
        raise RootAppDistributionError("root_app_catalog_signer_invalid", "Catalog signer identity is invalid.")
    return values


def _manifest_bytes(path: Path) -> bytes:
    try:
        encoded = path.read_bytes()
    except OSError as exc:
        raise RootAppDistributionError(
            "root_app_manifest_unreadable", "Packaged root-app manifest is unreadable."
        ) from exc
    if not encoded or len(encoded) > _MAX_MANIFEST_BYTES:
        raise RootAppDistributionError("root_app_manifest_size_invalid", "Packaged root-app manifest size is invalid.")
    return encoded


__all__ = [
    "PackagedRootAppDistribution",
    "RootAppDistributionError",
    "load_optional_root_app_distribution",
    "load_root_app_distribution",
]
