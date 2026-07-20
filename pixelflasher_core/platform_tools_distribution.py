"""Load an authenticated, packaged Platform Tools distribution catalog."""

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
from .artifact_trust import PLATFORM_TOOLS_ED25519_PUBLIC_KEYS
from .platform_tools import architecture_key, platform_key
from .platform_tools_setup import MappingPlatformToolsManifestCatalog

_CATALOG_NAME = "catalog.json"
_MAX_CATALOG_BYTES = 64 * 1024
_MAX_MANIFEST_BYTES = 64 * 1024
_SAFE_MANIFEST_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}\.json$")


class PlatformToolsDistributionError(RuntimeError):
    """A packaged catalog is absent, malformed or unauthenticated."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class PackagedPlatformToolsDistribution:
    catalog: MappingPlatformToolsManifestCatalog
    downloader: ArtifactDownloader
    targets: frozenset[tuple[str, str]]
    key_ids: frozenset[str]


def load_optional_platform_tools_distribution(
    resource_root: str | Path,
    *,
    trusted_public_keys: Mapping[str, bytes] | None = None,
) -> PackagedPlatformToolsDistribution | None:
    """Return ``None`` only when no catalog was packaged at all.

    A partially present or malformed distribution is never downgraded to an
    optional absence, because that would hide release-engineering corruption.
    """

    root = Path(resource_root)
    if not root.exists():
        return None
    return load_platform_tools_distribution(
        root,
        trusted_public_keys=trusted_public_keys,
    )


def load_platform_tools_distribution(
    resource_root: str | Path,
    *,
    trusted_public_keys: Mapping[str, bytes] | None = None,
) -> PackagedPlatformToolsDistribution:
    root = _real_directory(Path(resource_root))
    catalog_path = _resource_file(root, _CATALOG_NAME)
    document = _load_json_object(catalog_path, maximum_bytes=_MAX_CATALOG_BYTES)
    if set(document) != {"schemaVersion", "allowedHosts", "manifests"}:
        raise PlatformToolsDistributionError(
            "platform_tools_catalog_fields_invalid",
            "Packaged Platform Tools catalog fields are invalid.",
        )
    if document.get("schemaVersion") != 1:
        raise PlatformToolsDistributionError(
            "platform_tools_catalog_schema_unsupported",
            "Packaged Platform Tools catalog schema is unsupported.",
        )
    allowed_hosts = _allowed_hosts(document.get("allowedHosts"))
    public_keys = (
        PLATFORM_TOOLS_ED25519_PUBLIC_KEYS
        if trusted_public_keys is None
        else trusted_public_keys
    )
    raw_entries = document.get("manifests")
    if not isinstance(raw_entries, list):
        entries: list[object] = []
    else:
        entries = cast(list[object], raw_entries)
    if not entries or len(entries) > 16:
        raise PlatformToolsDistributionError(
            "platform_tools_catalog_targets_invalid",
            "Packaged Platform Tools targets are invalid.",
        )

    try:
        keyring = PinnedEd25519Keyring(public_keys)
        verifier = ArtifactManifestVerifier(
            keyring,
            ArtifactDownloadPolicy(frozenset(allowed_hosts)),
        )
    except (TypeError, ValueError) as exc:
        raise PlatformToolsDistributionError(
            "platform_tools_catalog_policy_invalid",
            "Packaged Platform Tools trust policy is invalid.",
        ) from exc

    manifests: dict[tuple[str, str], bytes] = {}
    for raw_entry in entries:
        if not isinstance(raw_entry, dict):
            raise PlatformToolsDistributionError(
                "platform_tools_catalog_target_invalid",
                "Packaged Platform Tools target entry is invalid.",
            )
        entry = cast(dict[str, object], raw_entry)
        if set(entry) != {
            "platform",
            "architecture",
            "manifest",
        }:
            raise PlatformToolsDistributionError(
                "platform_tools_catalog_target_invalid",
                "Packaged Platform Tools target entry is invalid.",
            )
        try:
            target_platform = platform_key(_required_string(entry, "platform"))
            target_arch = architecture_key(_required_string(entry, "architecture"))
        except (AttributeError, ValueError, RuntimeError) as exc:
            raise PlatformToolsDistributionError(
                "platform_tools_catalog_target_invalid",
                "Packaged Platform Tools target entry is invalid.",
            ) from exc
        name = _required_string(entry, "manifest")
        if not _SAFE_MANIFEST_NAME.fullmatch(name) or PurePosixPath(name).name != name:
            raise PlatformToolsDistributionError(
                "platform_tools_catalog_path_invalid",
                "Packaged Platform Tools manifest path is invalid.",
            )
        target = (target_platform, target_arch)
        if target in manifests:
            raise PlatformToolsDistributionError(
                "platform_tools_catalog_target_duplicate",
                "Packaged Platform Tools target is duplicated.",
            )
        manifest_path = _resource_file(root, name)
        try:
            encoded = manifest_path.read_bytes()
        except OSError as exc:
            raise PlatformToolsDistributionError(
                "platform_tools_manifest_unreadable",
                "Packaged Platform Tools manifest is unreadable.",
            ) from exc
        if not encoded or len(encoded) > _MAX_MANIFEST_BYTES:
            raise PlatformToolsDistributionError(
                "platform_tools_manifest_size_invalid",
                "Packaged Platform Tools manifest size is invalid.",
            )
        try:
            verifier.verify(
                encoded,
                expected_platform=target_platform,
                expected_arch=target_arch,
            )
        except Exception as exc:
            raise PlatformToolsDistributionError(
                "platform_tools_manifest_verification_failed",
                "Packaged Platform Tools manifest could not be authenticated.",
            ) from exc
        manifests[target] = encoded

    return PackagedPlatformToolsDistribution(
        catalog=MappingPlatformToolsManifestCatalog(manifests),
        downloader=ArtifactDownloader(verifier),
        targets=frozenset(manifests),
        key_ids=keyring.key_ids,
    )


def _real_directory(path: Path) -> Path:
    try:
        root = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise PlatformToolsDistributionError(
            "platform_tools_catalog_missing",
            "Packaged Platform Tools catalog is missing.",
        ) from exc
    if path.is_symlink() or path.is_junction() or not root.is_dir():
        raise PlatformToolsDistributionError(
            "platform_tools_catalog_root_invalid",
            "Packaged Platform Tools catalog root is invalid.",
        )
    return root


def _resource_file(root: Path, name: str) -> Path:
    candidate = root / name
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise PlatformToolsDistributionError(
            "platform_tools_catalog_file_missing",
            "Packaged Platform Tools catalog file is missing.",
        ) from exc
    if (
        candidate.is_symlink()
        or candidate.is_junction()
        or resolved.parent != root
        or not resolved.is_file()
    ):
        raise PlatformToolsDistributionError(
            "platform_tools_catalog_path_invalid",
            "Packaged Platform Tools catalog path is invalid.",
        )
    return resolved


def _load_json_object(path: Path, *, maximum_bytes: int) -> dict[str, Any]:
    try:
        encoded = path.read_bytes()
        if not encoded or len(encoded) > maximum_bytes:
            raise ValueError("size")
        decoded = cast(
            object,
            json.loads(
                encoded.decode("utf-8", "strict"),
                object_pairs_hook=_reject_duplicate_keys,
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise PlatformToolsDistributionError(
            "platform_tools_catalog_json_invalid",
            "Packaged Platform Tools catalog is not valid JSON.",
        ) from exc
    if not isinstance(decoded, dict):
        raise PlatformToolsDistributionError(
            "platform_tools_catalog_json_invalid",
            "Packaged Platform Tools catalog must be an object.",
        )
    return cast(dict[str, Any], decoded)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    values: dict[str, object] = {}
    for key, value in pairs:
        if key in values:
            raise PlatformToolsDistributionError(
                "platform_tools_catalog_field_duplicate",
                "Packaged Platform Tools catalog contains a duplicate field.",
            )
        values[key] = value
    return values


def _allowed_hosts(raw: object) -> tuple[str, ...]:
    if not isinstance(raw, list):
        items: list[object] = []
    else:
        items = cast(list[object], raw)
    if not items or len(items) > 16:
        raise PlatformToolsDistributionError(
            "platform_tools_catalog_hosts_invalid",
            "Packaged Platform Tools download hosts are invalid.",
        )
    values: list[str] = []
    for value in items:
        if not isinstance(value, str) or not value or value in values:
            raise PlatformToolsDistributionError(
                "platform_tools_catalog_hosts_invalid",
                "Packaged Platform Tools download hosts are invalid.",
            )
        values.append(value)
    return tuple(values)


def _required_string(values: Mapping[str, object], key: str) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a non-empty string")
    return value


__all__ = [
    "PackagedPlatformToolsDistribution",
    "PlatformToolsDistributionError",
    "load_optional_platform_tools_distribution",
    "load_platform_tools_distribution",
]
