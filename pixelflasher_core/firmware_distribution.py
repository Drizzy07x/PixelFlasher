"""Load an authenticated, packaged firmware distribution catalog."""

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
from .artifact_trust import FIRMWARE_ED25519_PUBLIC_KEYS
from .firmware_catalog import (
    FirmwareCatalogSource,
    MappingFirmwareManifestCatalog,
)

_CATALOG_NAME = "catalog.json"
_MAX_CATALOG_BYTES = 512 * 1024
_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_ENTRIES = 512
_SAFE_MANIFEST_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}\.json$")
_DEVICE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_CHANNELS = frozenset({"stable", "beta", "canary"})
_KINDS = frozenset({"factory", "ota"})
_APPROVED_HOSTS = frozenset({"dl.google.com", "storage.googleapis.com"})


class FirmwareDistributionError(RuntimeError):
    """A packaged firmware catalog is absent, malformed, or unauthenticated."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class PackagedFirmwareDistribution:
    catalog: MappingFirmwareManifestCatalog
    downloader: ArtifactDownloader
    targets: frozenset[tuple[str, str, str]]
    key_ids: frozenset[str]


def load_optional_firmware_distribution(
    resource_root: str | Path,
    *,
    trusted_public_keys: Mapping[str, bytes] | None = None,
) -> PackagedFirmwareDistribution | None:
    root = Path(resource_root)
    if not root.exists():
        return None
    return load_firmware_distribution(
        root,
        trusted_public_keys=trusted_public_keys,
    )


def load_firmware_distribution(
    resource_root: str | Path,
    *,
    trusted_public_keys: Mapping[str, bytes] | None = None,
) -> PackagedFirmwareDistribution:
    root = _real_directory(Path(resource_root))
    document = _load_json_object(
        _resource_file(root, _CATALOG_NAME),
        maximum_bytes=_MAX_CATALOG_BYTES,
    )
    if set(document) != {"schemaVersion", "allowedHosts", "entries"}:
        raise FirmwareDistributionError(
            "firmware_catalog_fields_invalid",
            "Packaged firmware catalog fields are invalid.",
        )
    if document.get("schemaVersion") != 1:
        raise FirmwareDistributionError(
            "firmware_catalog_schema_unsupported",
            "Packaged firmware catalog schema is unsupported.",
        )
    allowed_hosts = _allowed_hosts(document.get("allowedHosts"))
    raw_entries = document.get("entries")
    entries = cast(list[object], raw_entries) if isinstance(raw_entries, list) else []
    if not entries or len(entries) > _MAX_ENTRIES:
        raise FirmwareDistributionError(
            "firmware_catalog_entries_invalid",
            "Packaged firmware entries are invalid.",
        )

    public_keys = FIRMWARE_ED25519_PUBLIC_KEYS if trusted_public_keys is None else trusted_public_keys
    try:
        keyring = PinnedEd25519Keyring(public_keys)
        verifier = ArtifactManifestVerifier(
            keyring,
            ArtifactDownloadPolicy(frozenset(allowed_hosts)),
        )
    except (TypeError, ValueError) as exc:
        raise FirmwareDistributionError(
            "firmware_catalog_policy_invalid",
            "Packaged firmware trust policy is invalid.",
        ) from exc

    grouped: dict[tuple[str, str], list[FirmwareCatalogSource]] = {}
    targets: set[tuple[str, str, str]] = set()
    for raw_entry in entries:
        entry = _catalog_entry(raw_entry)
        device = _device(entry.get("device"))
        channel = _choice(entry.get("channel"), _CHANNELS)
        kind = _choice(entry.get("kind"), _KINDS)
        target = (device, channel, kind)
        if target in targets:
            raise FirmwareDistributionError(
                "firmware_catalog_target_duplicate",
                "Packaged firmware target is duplicated.",
            )
        targets.add(target)
        name = _manifest_name(entry.get("manifest"))
        encoded = _manifest_bytes(_resource_file(root, name))
        try:
            verifier.verify(
                encoded,
                expected_platform="android",
                expected_arch=device,
            )
        except Exception as exc:
            raise FirmwareDistributionError(
                "firmware_manifest_verification_failed",
                "Packaged firmware manifest could not be authenticated.",
            ) from exc
        grouped.setdefault((device, channel), []).append(
            FirmwareCatalogSource(
                device=device,
                channel=channel,
                kind=kind,
                manifest_document=encoded,
            )
        )

    return PackagedFirmwareDistribution(
        catalog=MappingFirmwareManifestCatalog(grouped),
        downloader=ArtifactDownloader(verifier),
        targets=frozenset(targets),
        key_ids=keyring.key_ids,
    )


def _catalog_entry(raw: object) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise FirmwareDistributionError(
            "firmware_catalog_entry_invalid",
            "Packaged firmware entry is invalid.",
        )
    entry = cast(dict[str, object], raw)
    if set(entry) != {"device", "channel", "kind", "manifest"}:
        raise FirmwareDistributionError(
            "firmware_catalog_entry_invalid",
            "Packaged firmware entry is invalid.",
        )
    return entry


def _real_directory(path: Path) -> Path:
    try:
        root = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise FirmwareDistributionError(
            "firmware_catalog_missing",
            "Packaged firmware catalog is missing.",
        ) from exc
    if path.is_symlink() or path.is_junction() or not root.is_dir():
        raise FirmwareDistributionError(
            "firmware_catalog_root_invalid",
            "Packaged firmware catalog root is invalid.",
        )
    return root


def _resource_file(root: Path, name: str) -> Path:
    candidate = root / name
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise FirmwareDistributionError(
            "firmware_catalog_file_missing",
            "Packaged firmware catalog file is missing.",
        ) from exc
    if candidate.is_symlink() or candidate.is_junction() or resolved.parent != root or not resolved.is_file():
        raise FirmwareDistributionError(
            "firmware_catalog_path_invalid",
            "Packaged firmware catalog path is invalid.",
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
        raise FirmwareDistributionError(
            "firmware_catalog_json_invalid",
            "Packaged firmware catalog is not valid JSON.",
        ) from exc
    if not isinstance(decoded, dict):
        raise FirmwareDistributionError(
            "firmware_catalog_json_invalid",
            "Packaged firmware catalog must be an object.",
        )
    return cast(dict[str, Any], decoded)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    values: dict[str, object] = {}
    for key, value in pairs:
        if key in values:
            raise FirmwareDistributionError(
                "firmware_catalog_field_duplicate",
                "Packaged firmware catalog contains a duplicate field.",
            )
        values[key] = value
    return values


def _allowed_hosts(raw: object) -> tuple[str, ...]:
    items = cast(list[object], raw) if isinstance(raw, list) else []
    if not items or len(items) > len(_APPROVED_HOSTS):
        raise FirmwareDistributionError(
            "firmware_catalog_hosts_invalid",
            "Packaged firmware hosts are invalid.",
        )
    values: list[str] = []
    for value in items:
        if not isinstance(value, str) or value not in _APPROVED_HOSTS or value in values:
            raise FirmwareDistributionError(
                "firmware_catalog_hosts_invalid",
                "Packaged firmware hosts are invalid.",
            )
        values.append(value)
    return tuple(values)


def _device(raw: object) -> str:
    value = raw.strip().casefold() if isinstance(raw, str) else ""
    if _DEVICE.fullmatch(value) is None:
        raise FirmwareDistributionError(
            "firmware_catalog_device_invalid",
            "Packaged firmware device is invalid.",
        )
    return value


def _choice(raw: object, allowed: frozenset[str]) -> str:
    value = raw.strip().casefold() if isinstance(raw, str) else ""
    if value not in allowed:
        raise FirmwareDistributionError(
            "firmware_catalog_entry_invalid",
            "Packaged firmware entry is invalid.",
        )
    return value


def _manifest_name(raw: object) -> str:
    value = raw if isinstance(raw, str) else ""
    if not _SAFE_MANIFEST_NAME.fullmatch(value) or PurePosixPath(value).name != value:
        raise FirmwareDistributionError(
            "firmware_catalog_path_invalid",
            "Packaged firmware manifest path is invalid.",
        )
    return value


def _manifest_bytes(path: Path) -> bytes:
    try:
        encoded = path.read_bytes()
    except OSError as exc:
        raise FirmwareDistributionError(
            "firmware_manifest_unreadable",
            "Packaged firmware manifest is unreadable.",
        ) from exc
    if not encoded or len(encoded) > _MAX_MANIFEST_BYTES:
        raise FirmwareDistributionError(
            "firmware_manifest_size_invalid",
            "Packaged firmware manifest size is invalid.",
        )
    return encoded


__all__ = [
    "FirmwareDistributionError",
    "PackagedFirmwareDistribution",
    "load_firmware_distribution",
    "load_optional_firmware_distribution",
]
