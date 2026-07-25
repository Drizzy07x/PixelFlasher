"""Load an authenticated, packaged Scrcpy distribution catalog."""

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
from .artifact_trust import SCRCPY_ED25519_PUBLIC_KEYS
from .platform_tools import architecture_key, platform_key
from .scrcpy_setup import MappingScrcpyManifestCatalog

_CATALOG_NAME = "catalog.json"
_MAX_CATALOG_BYTES = 64 * 1024
_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
_SAFE_MANIFEST_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}\.json$")
_APPROVED_HOSTS = frozenset(
    {
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    }
)


class ScrcpyDistributionError(RuntimeError):
    """A packaged Scrcpy catalog is absent, malformed, or unauthenticated."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class PackagedScrcpyDistribution:
    catalog: MappingScrcpyManifestCatalog
    downloader: ArtifactDownloader
    targets: frozenset[tuple[str, str]]
    key_ids: frozenset[str]


def load_optional_scrcpy_distribution(
    resource_root: str | Path,
    *,
    trusted_public_keys: Mapping[str, bytes] | None = None,
) -> PackagedScrcpyDistribution | None:
    root = Path(resource_root)
    if not root.exists():
        return None
    return load_scrcpy_distribution(root, trusted_public_keys=trusted_public_keys)


def load_scrcpy_distribution(
    resource_root: str | Path,
    *,
    trusted_public_keys: Mapping[str, bytes] | None = None,
) -> PackagedScrcpyDistribution:
    root = _real_directory(Path(resource_root))
    document = _load_json_object(_resource_file(root, _CATALOG_NAME))
    if set(document) != {"schemaVersion", "allowedHosts", "manifests"}:
        raise ScrcpyDistributionError(
            "scrcpy_catalog_fields_invalid",
            "Packaged Scrcpy catalog fields are invalid.",
        )
    if document.get("schemaVersion") != 1:
        raise ScrcpyDistributionError(
            "scrcpy_catalog_schema_unsupported",
            "Packaged Scrcpy catalog schema is unsupported.",
        )
    allowed_hosts = _allowed_hosts(document.get("allowedHosts"))
    raw_entries = document.get("manifests")
    entries = cast(list[object], raw_entries) if isinstance(raw_entries, list) else []
    if not entries or len(entries) > 16:
        raise ScrcpyDistributionError(
            "scrcpy_catalog_targets_invalid",
            "Packaged Scrcpy targets are invalid.",
        )

    public_keys = SCRCPY_ED25519_PUBLIC_KEYS if trusted_public_keys is None else trusted_public_keys
    try:
        keyring = PinnedEd25519Keyring(public_keys)
        verifier = ArtifactManifestVerifier(
            keyring,
            ArtifactDownloadPolicy(
                frozenset(allowed_hosts),
                maximum_artifact_bytes=_MAX_ARTIFACT_BYTES,
            ),
        )
    except (TypeError, ValueError) as exc:
        raise ScrcpyDistributionError(
            "scrcpy_catalog_policy_invalid",
            "Packaged Scrcpy trust policy is invalid.",
        ) from exc

    manifests: dict[tuple[str, str], bytes] = {}
    for raw_entry in entries:
        if not isinstance(raw_entry, dict):
            raise ScrcpyDistributionError(
                "scrcpy_catalog_target_invalid",
                "Packaged Scrcpy target is invalid.",
            )
        entry = cast(dict[str, object], raw_entry)
        if set(entry) != {"platform", "architecture", "manifest"}:
            raise ScrcpyDistributionError(
                "scrcpy_catalog_target_invalid",
                "Packaged Scrcpy target is invalid.",
            )
        try:
            target_platform = platform_key(_required_string(entry, "platform"))
            target_arch = architecture_key(_required_string(entry, "architecture"))
        except (AttributeError, ValueError, RuntimeError) as exc:
            raise ScrcpyDistributionError(
                "scrcpy_catalog_target_invalid",
                "Packaged Scrcpy target is invalid.",
            ) from exc
        target = (target_platform, target_arch)
        if target in manifests:
            raise ScrcpyDistributionError(
                "scrcpy_catalog_target_duplicate",
                "Packaged Scrcpy target is duplicated.",
            )
        name = _manifest_name(entry.get("manifest"))
        encoded = _manifest_bytes(_resource_file(root, name))
        try:
            verifier.verify(
                encoded,
                expected_platform=target_platform,
                expected_arch=target_arch,
            )
        except Exception as exc:
            raise ScrcpyDistributionError(
                "scrcpy_manifest_verification_failed",
                "Packaged Scrcpy manifest could not be authenticated.",
            ) from exc
        manifests[target] = encoded

    return PackagedScrcpyDistribution(
        catalog=MappingScrcpyManifestCatalog(manifests),
        downloader=ArtifactDownloader(verifier),
        targets=frozenset(manifests),
        key_ids=keyring.key_ids,
    )


def _real_directory(path: Path) -> Path:
    try:
        root = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise ScrcpyDistributionError(
            "scrcpy_catalog_missing",
            "Packaged Scrcpy catalog is missing.",
        ) from exc
    if path.is_symlink() or path.is_junction() or not root.is_dir():
        raise ScrcpyDistributionError(
            "scrcpy_catalog_root_invalid",
            "Packaged Scrcpy catalog root is invalid.",
        )
    return root


def _resource_file(root: Path, name: str) -> Path:
    candidate = root / name
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ScrcpyDistributionError(
            "scrcpy_catalog_file_missing",
            "Packaged Scrcpy catalog file is missing.",
        ) from exc
    if candidate.is_symlink() or candidate.is_junction() or resolved.parent != root or not resolved.is_file():
        raise ScrcpyDistributionError(
            "scrcpy_catalog_path_invalid",
            "Packaged Scrcpy catalog path is invalid.",
        )
    return resolved


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        encoded = path.read_bytes()
        if not encoded or len(encoded) > _MAX_CATALOG_BYTES:
            raise ValueError("size")
        decoded = cast(
            object,
            json.loads(
                encoded.decode("utf-8", "strict"),
                object_pairs_hook=_reject_duplicate_keys,
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ScrcpyDistributionError(
            "scrcpy_catalog_json_invalid",
            "Packaged Scrcpy catalog is not valid JSON.",
        ) from exc
    if not isinstance(decoded, dict):
        raise ScrcpyDistributionError(
            "scrcpy_catalog_json_invalid",
            "Packaged Scrcpy catalog must be an object.",
        )
    return cast(dict[str, Any], decoded)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    values: dict[str, object] = {}
    for key, value in pairs:
        if key in values:
            raise ScrcpyDistributionError(
                "scrcpy_catalog_field_duplicate",
                "Packaged Scrcpy catalog contains a duplicate field.",
            )
        values[key] = value
    return values


def _allowed_hosts(raw: object) -> tuple[str, ...]:
    items = cast(list[object], raw) if isinstance(raw, list) else []
    if not items or len(items) > len(_APPROVED_HOSTS):
        raise ScrcpyDistributionError(
            "scrcpy_catalog_hosts_invalid",
            "Packaged Scrcpy download hosts are invalid.",
        )
    values: list[str] = []
    for value in items:
        if not isinstance(value, str) or value not in _APPROVED_HOSTS or value in values:
            raise ScrcpyDistributionError(
                "scrcpy_catalog_hosts_invalid",
                "Packaged Scrcpy download hosts are invalid.",
            )
        values.append(value)
    if "github.com" not in values:
        raise ScrcpyDistributionError(
            "scrcpy_catalog_hosts_invalid",
            "Packaged Scrcpy download hosts are invalid.",
        )
    return tuple(values)


def _required_string(values: Mapping[str, object], key: str) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _manifest_name(raw: object) -> str:
    value = raw if isinstance(raw, str) else ""
    if not _SAFE_MANIFEST_NAME.fullmatch(value) or PurePosixPath(value).name != value:
        raise ScrcpyDistributionError(
            "scrcpy_catalog_path_invalid",
            "Packaged Scrcpy manifest path is invalid.",
        )
    return value


def _manifest_bytes(path: Path) -> bytes:
    try:
        encoded = path.read_bytes()
    except OSError as exc:
        raise ScrcpyDistributionError(
            "scrcpy_manifest_unreadable",
            "Packaged Scrcpy manifest is unreadable.",
        ) from exc
    if not encoded or len(encoded) > _MAX_MANIFEST_BYTES:
        raise ScrcpyDistributionError(
            "scrcpy_manifest_size_invalid",
            "Packaged Scrcpy manifest size is invalid.",
        )
    return encoded


__all__ = [
    "PackagedScrcpyDistribution",
    "ScrcpyDistributionError",
    "load_optional_scrcpy_distribution",
    "load_scrcpy_distribution",
]
