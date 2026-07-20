"""Authenticated application update checks with persistent rollback protection."""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Protocol, cast
from urllib.parse import urlsplit

from .artifact_downloads import PinnedEd25519Keyring

_MAX_MANIFEST_BYTES = 64 * 1024
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_SIGNED_FIELDS = frozenset(
    {
        "schemaVersion",
        "keyId",
        "sequence",
        "version",
        "channel",
        "releaseUrl",
        "publishedAt",
        "expiresAt",
    }
)
_MANIFEST_FIELDS = _SIGNED_FIELDS | {"signature"}


class UpdateCheckError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class UpdateStatus(StrEnum):
    SUCCESS = "success"
    CANCELLED = "cancelled"
    FAILED = "failed"


class UpdateCancellation(Protocol):
    @property
    def cancelled(self) -> bool: ...


class UpdateManifestSource(Protocol):
    def load(self, cancellation: UpdateCancellation) -> bytes: ...


@dataclass(frozen=True, slots=True)
class UpdateManifest:
    key_id: str
    sequence: int
    version: str
    channel: str
    release_url: str
    published_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class UpdateCheckResult:
    status: UpdateStatus
    code: str
    message: str
    current_version: str
    latest_version: str = ""
    channel: str = "stable"
    update_available: bool = False
    release_target: str = "releases"

    @property
    def ok(self) -> bool:
        return self.status is UpdateStatus.SUCCESS

    def to_public_dict(self) -> dict[str, object]:
        return {
            "currentVersion": self.current_version,
            "latestVersion": self.latest_version,
            "channel": self.channel,
            "updateAvailable": self.update_available,
            "releaseTarget": self.release_target,
        }


def _duplicates_rejected(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise UpdateCheckError("update_manifest_duplicate_field", "Update manifest contains a duplicate field.")
        result[key] = value
    return result


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise UpdateCheckError("update_manifest_timestamp_invalid", f"Update manifest {field} is invalid.")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise UpdateCheckError("update_manifest_timestamp_invalid", f"Update manifest {field} is invalid.") from error


def _semver_parts(value: str) -> tuple[int, int, int, tuple[str, ...] | None]:
    match = _SEMVER.fullmatch(value)
    if match is None:
        raise UpdateCheckError("update_version_invalid", "Update manifest version is not strict semantic versioning.")
    prerelease = match.group(4)
    identifiers = tuple(prerelease.split(".")) if prerelease else None
    if identifiers is not None and any(identifier.isdigit() and len(identifier) > 1 and identifier[0] == "0" for identifier in identifiers):
        raise UpdateCheckError("update_version_invalid", "Update manifest prerelease version is invalid.")
    return int(match.group(1)), int(match.group(2)), int(match.group(3)), identifiers


def version_is_newer(candidate: str, current: str) -> bool:
    candidate_base = _semver_parts(candidate)
    current_base = _semver_parts(current)
    if candidate_base[:3] != current_base[:3]:
        return candidate_base[:3] > current_base[:3]
    candidate_pre = candidate_base[3]
    current_pre = current_base[3]
    if candidate_pre is None or current_pre is None:
        return candidate_pre is None and current_pre is not None
    for left, right in zip(candidate_pre, current_pre, strict=False):
        if left == right:
            continue
        left_number = left.isdigit()
        right_number = right.isdigit()
        if left_number and right_number:
            return int(left) > int(right)
        if left_number != right_number:
            return not left_number
        return left > right
    return len(candidate_pre) > len(current_pre)


class UpdateManifestVerifier:
    def __init__(
        self,
        keyring: PinnedEd25519Keyring,
        *,
        allowed_hosts: frozenset[str] = frozenset({"github.com"}),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(keyring, PinnedEd25519Keyring):
            raise TypeError("keyring must be a PinnedEd25519Keyring")
        if not allowed_hosts or any(not isinstance(host, str) or host != host.casefold() for host in allowed_hosts):
            raise ValueError("allowed update hosts must be normalized")
        self.keyring = keyring
        self.allowed_hosts = allowed_hosts
        self.clock = clock or (lambda: datetime.now(UTC))

    def verify(self, document: bytes) -> UpdateManifest:
        if not isinstance(document, bytes) or not document or len(document) > _MAX_MANIFEST_BYTES:
            raise UpdateCheckError("update_manifest_size_invalid", "Update manifest is empty or exceeds its limit.")
        try:
            decoded = cast(
                object,
                json.loads(document.decode("utf-8", "strict"), object_pairs_hook=_duplicates_rejected),
            )
        except UpdateCheckError:
            raise
        except (UnicodeError, json.JSONDecodeError) as error:
            raise UpdateCheckError("update_manifest_json_invalid", "Update manifest is not valid UTF-8 JSON.") from error
        if not isinstance(decoded, dict):
            raise UpdateCheckError("update_manifest_fields_invalid", "Update manifest fields do not match the contract.")
        raw = cast(dict[str, object], decoded)
        if set(raw) != _MANIFEST_FIELDS:
            raise UpdateCheckError("update_manifest_fields_invalid", "Update manifest fields do not match the contract.")
        if raw["schemaVersion"] != 1:
            raise UpdateCheckError("update_manifest_schema_invalid", "Update manifest schema is unsupported.")
        key_id = raw["keyId"]
        sequence = raw["sequence"]
        version = raw["version"]
        channel = raw["channel"]
        release_url = raw["releaseUrl"]
        if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
            raise UpdateCheckError("update_manifest_key_invalid", "Update manifest signing key ID is invalid.")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or not 0 <= sequence <= 2**63 - 1:
            raise UpdateCheckError("update_manifest_sequence_invalid", "Update manifest sequence is invalid.")
        if not isinstance(version, str):
            raise UpdateCheckError("update_version_invalid", "Update manifest version is invalid.")
        _semver_parts(version)
        if channel not in {"stable", "rc"}:
            raise UpdateCheckError("update_channel_invalid", "Update manifest channel is invalid.")
        if not isinstance(release_url, str) or len(release_url) > 2048:
            raise UpdateCheckError("update_release_url_invalid", "Update release URL is invalid.")
        try:
            parsed = urlsplit(release_url)
            port = parsed.port
        except ValueError as error:
            raise UpdateCheckError("update_release_url_invalid", "Update release URL is invalid.") from error
        if (
            parsed.scheme != "https"
            or parsed.hostname not in self.allowed_hosts
            or port not in {None, 443}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or not parsed.path.startswith("/badabing2005/PixelFlasher/releases/")
        ):
            raise UpdateCheckError("update_release_url_invalid", "Update release URL is not allow-listed.")
        published_at = _timestamp(raw["publishedAt"], "publishedAt")
        expires_at = _timestamp(raw["expiresAt"], "expiresAt")
        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise RuntimeError("update verifier clock must be timezone-aware")
        current = now.astimezone(UTC)
        if published_at > current + timedelta(minutes=5):
            raise UpdateCheckError("update_manifest_not_yet_valid", "Update manifest publication time is in the future.")
        if expires_at <= current:
            raise UpdateCheckError("update_manifest_expired", "Update manifest has expired.")
        if expires_at <= published_at or expires_at - published_at > timedelta(days=31):
            raise UpdateCheckError("update_manifest_validity_invalid", "Update manifest validity window is invalid.")
        signature = raw["signature"]
        if not isinstance(signature, str) or len(signature) > 128:
            raise UpdateCheckError("update_signature_invalid", "Update manifest signature is invalid.")
        try:
            signature_bytes = base64.b64decode(signature, validate=True)
        except (ValueError, binascii.Error) as error:
            raise UpdateCheckError("update_signature_invalid", "Update manifest signature is invalid.") from error
        if len(signature_bytes) != 64:
            raise UpdateCheckError("update_signature_invalid", "Update manifest signature is invalid.")
        payload = {field: raw[field] for field in _SIGNED_FIELDS}
        canonical = json.dumps(payload, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        try:
            self.keyring.verify(key_id, signature_bytes, canonical)
        except Exception as error:
            code = getattr(error, "code", "update_signature_invalid")
            raise UpdateCheckError(str(code).replace("manifest_", "update_"), "Update manifest signature is invalid.") from error
        return UpdateManifest(key_id, sequence, version, cast(str, channel), release_url, published_at, expires_at)


class UpdateSequenceStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser().absolute()
        self._lock = threading.RLock()

    def accept(self, manifest: UpdateManifest) -> None:
        with self._lock:
            previous_sequence = -1
            previous_version = ""
            if self.path.exists():
                try:
                    loaded = cast(object, json.loads(self.path.read_text(encoding="utf-8")))
                except (OSError, UnicodeError, json.JSONDecodeError) as error:
                    raise UpdateCheckError("update_state_invalid", "Update rollback state is invalid.") from error
                if not isinstance(loaded, dict):
                    raise UpdateCheckError("update_state_invalid", "Update rollback state is invalid.")
                value = cast(dict[str, object], loaded)
                if set(value) != {"schemaVersion", "highestSequence", "version"} or value.get("schemaVersion") != 1:
                    raise UpdateCheckError("update_state_invalid", "Update rollback state is invalid.")
                previous_sequence = value.get("highestSequence")
                previous_version = value.get("version")
                if isinstance(previous_sequence, bool) or not isinstance(previous_sequence, int) or not isinstance(previous_version, str):
                    raise UpdateCheckError("update_state_invalid", "Update rollback state is invalid.")
            if manifest.sequence < previous_sequence:
                raise UpdateCheckError("update_manifest_rollback", "Update manifest sequence is older than the accepted sequence.")
            if manifest.sequence == previous_sequence and manifest.version != previous_version:
                raise UpdateCheckError("update_manifest_equivocation", "Update manifest sequence changed version.")
            if manifest.sequence == previous_sequence:
                return
            payload = json.dumps(
                {"schemaVersion": 1, "highestSequence": manifest.sequence, "version": manifest.version},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            self.path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary_name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
            temporary = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.path)
                if os.name != "nt":
                    directory_fd = os.open(self.path.parent, os.O_RDONLY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
            except OSError as error:
                temporary.unlink(missing_ok=True)
                raise UpdateCheckError("update_state_write_failed", "Update rollback state could not be persisted.") from error


class UpdateService:
    def __init__(
        self,
        current_version: str,
        source: UpdateManifestSource | None,
        verifier: UpdateManifestVerifier | None,
        sequence_store: UpdateSequenceStore,
    ) -> None:
        _semver_parts(current_version)
        self.current_version = current_version
        self.source = source
        self.verifier = verifier
        self.sequence_store = sequence_store

    def check(self, cancellation: UpdateCancellation) -> UpdateCheckResult:
        if cancellation.cancelled:
            return UpdateCheckResult(UpdateStatus.CANCELLED, "update_check_cancelled", "Update check was cancelled.", self.current_version)
        if self.source is None or self.verifier is None:
            return UpdateCheckResult(UpdateStatus.FAILED, "update_manifest_unavailable", "Signed application update metadata is not provisioned.", self.current_version)
        try:
            document = self.source.load(cancellation)
            if cancellation.cancelled:
                return UpdateCheckResult(UpdateStatus.CANCELLED, "update_check_cancelled", "Update check was cancelled.", self.current_version)
            manifest = self.verifier.verify(document)
            self.sequence_store.accept(manifest)
            available = version_is_newer(manifest.version, self.current_version)
            return UpdateCheckResult(
                UpdateStatus.SUCCESS,
                "update_available" if available else "application_current",
                "A newer PixelFlasher release is available." if available else "PixelFlasher is up to date.",
                self.current_version,
                manifest.version,
                manifest.channel,
                available,
            )
        except UpdateCheckError as error:
            return UpdateCheckResult(UpdateStatus.FAILED, error.code, str(error), self.current_version)
        except (OSError, TimeoutError):
            return UpdateCheckResult(UpdateStatus.FAILED, "update_check_offline", "Application update metadata could not be reached.", self.current_version)
        except (TypeError, ValueError):
            return UpdateCheckResult(UpdateStatus.FAILED, "update_manifest_invalid", "Application update metadata is invalid.", self.current_version)


__all__ = [
    "UpdateCheckError",
    "UpdateCheckResult",
    "UpdateManifest",
    "UpdateManifestSource",
    "UpdateManifestVerifier",
    "UpdateSequenceStore",
    "UpdateService",
    "UpdateStatus",
    "version_is_newer",
]
