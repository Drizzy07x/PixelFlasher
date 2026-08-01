"""Signed manifests and fail-closed, atomic artifact downloads.

The manifest signature covers the RFC-8785-compatible subset used here:
UTF-8 JSON with sorted keys, no insignificant whitespace, and values limited to
strings and integers.  The transport never follows redirects implicitly and
never promotes bytes until their signed size and SHA-256 both match.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, cast
from urllib.parse import urljoin, urlsplit

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SIGNED_MANIFEST_FIELDS = frozenset(
    {
        "keyId",
        "version",
        "platform",
        "arch",
        "license",
        "provenance",
        "url",
        "sha256",
        "size",
        "expiresAt",
    }
)
MANIFEST_FIELDS = SIGNED_MANIFEST_FIELDS | {"signature"}
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_TARGET_VALUE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_CONTENT_RANGE = re.compile(r"^bytes (\d+)-(\d+)/(\d+)$")
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
# Statuses that mean the resume request itself was refused. Retaining the
# partial for these would replay the identical rejection on every retry.
_RANGE_REFUSED_STATUSES = frozenset({400, 416, 501})
_MAX_MANIFEST_BYTES = 64 * 1024


class ArtifactDownloadError(RuntimeError):
    """Base error with a stable machine-readable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ArtifactManifestError(ArtifactDownloadError):
    pass


class ArtifactSignatureError(ArtifactManifestError):
    pass


class ArtifactPolicyError(ArtifactDownloadError):
    pass


class ArtifactTransportError(ArtifactDownloadError):
    pass


class ArtifactIntegrityError(ArtifactDownloadError):
    pass


class ArtifactCancelledError(ArtifactDownloadError):
    """Explicit cancellation that never promotes unverified bytes."""

    def __init__(self) -> None:
        super().__init__(
            "artifact_download_cancelled",
            "artifact download was cancelled",
        )


def canonical_manifest_bytes(fields: Mapping[str, object]) -> bytes:
    """Return the one canonical byte representation covered by Ed25519."""

    if set(fields) != SIGNED_MANIFEST_FIELDS:
        missing = sorted(SIGNED_MANIFEST_FIELDS - set(fields))
        extra = sorted(set(fields) - SIGNED_MANIFEST_FIELDS)
        raise ArtifactManifestError(
            "manifest_fields_invalid",
            f"manifest payload fields are invalid (missing={missing}, extra={extra})",
        )
    try:
        return json.dumps(
            dict(fields),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ArtifactManifestError(
            "manifest_canonicalization_failed",
            "manifest cannot be represented as canonical JSON",
        ) from error


class PinnedEd25519Keyring:
    """Immutable public-key set; multiple key IDs provide explicit rotation."""

    __slots__ = ("_keys",)

    def __init__(self, public_keys: Mapping[str, bytes]) -> None:
        if not public_keys:
            raise ValueError("at least one pinned Ed25519 public key is required")
        loaded: dict[str, Ed25519PublicKey] = {}
        for key_id, raw_key in public_keys.items():
            if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
                raise ValueError("pinned key IDs must use safe ASCII identifiers")
            if not isinstance(raw_key, (bytes, bytearray, memoryview)):
                raise TypeError("pinned Ed25519 public keys must be raw bytes")
            raw = bytes(raw_key)
            if len(raw) != 32:
                raise ValueError("pinned Ed25519 public keys must contain 32 bytes")
            loaded[key_id] = Ed25519PublicKey.from_public_bytes(raw)
        self._keys = MappingProxyType(loaded)

    @property
    def key_ids(self) -> frozenset[str]:
        return frozenset(self._keys)

    def verify(self, key_id: str, signature: bytes, payload: bytes) -> None:
        key = self._keys.get(key_id)
        if key is None:
            raise ArtifactSignatureError(
                "manifest_key_unknown",
                "manifest references an unknown signing key",
            )
        try:
            key.verify(signature, payload)
        except (InvalidSignature, ValueError) as error:
            raise ArtifactSignatureError(
                "manifest_signature_invalid",
                "manifest Ed25519 signature is invalid",
            ) from error


def _normalize_host(host: str) -> str:
    if not isinstance(host, str) or not host or any(value in host for value in "/:@"):
        raise ValueError("allow-listed hosts must be bare DNS names")
    if host.endswith("."):
        raise ValueError("allow-listed hosts must not use a trailing dot")
    try:
        normalized = host.encode("idna").decode("ascii").casefold()
    except UnicodeError as error:
        raise ValueError("allow-listed host is not a valid DNS name") from error
    labels = normalized.split(".")
    if (
        not normalized
        or len(normalized) > 253
        or any(not _DNS_LABEL.fullmatch(label) for label in labels)
    ):
        raise ValueError("allow-listed host is not a valid DNS name")
    return normalized


@dataclass(frozen=True, slots=True)
class ArtifactDownloadPolicy:
    allowed_hosts: frozenset[str]
    maximum_artifact_bytes: int = 16 * 1024 * 1024 * 1024
    maximum_redirects: int = 5
    chunk_size: int = 1024 * 1024
    connect_timeout: float = 10.0
    read_timeout: float = 60.0

    def __post_init__(self) -> None:
        try:
            hosts = frozenset(_normalize_host(host) for host in self.allowed_hosts)
        except TypeError as error:
            raise TypeError("allowed_hosts must be an iterable of host names") from error
        if not hosts:
            raise ValueError("at least one download host must be allow-listed")
        object.__setattr__(self, "allowed_hosts", hosts)
        if self.maximum_artifact_bytes <= 0:
            raise ValueError("maximum_artifact_bytes must be positive")
        if not 0 <= self.maximum_redirects <= 10:
            raise ValueError("maximum_redirects must be between zero and ten")
        if self.chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        if self.connect_timeout <= 0 or self.read_timeout <= 0:
            raise ValueError("download timeouts must be positive")

    def validate_url(self, value: str) -> str:
        if not isinstance(value, str) or not value or len(value) > 4096:
            raise ArtifactPolicyError("artifact_url_invalid", "artifact URL is invalid")
        try:
            parsed = urlsplit(value)
            port = parsed.port
            hostname = parsed.hostname
        except ValueError as error:
            raise ArtifactPolicyError("artifact_url_invalid", "artifact URL is invalid") from error
        if parsed.scheme != "https" or not hostname:
            raise ArtifactPolicyError(
                "artifact_url_not_https",
                "artifact URL must use HTTPS",
            )
        if parsed.username is not None or parsed.password is not None:
            raise ArtifactPolicyError(
                "artifact_url_credentials_forbidden",
                "artifact URL must not contain credentials",
            )
        if port not in (None, 443) or parsed.fragment or not parsed.path.startswith("/"):
            raise ArtifactPolicyError("artifact_url_invalid", "artifact URL is invalid")
        try:
            normalized_host = _normalize_host(hostname)
        except ValueError as error:
            raise ArtifactPolicyError("artifact_url_invalid", "artifact URL is invalid") from error
        if normalized_host not in self.allowed_hosts:
            raise ArtifactPolicyError(
                "artifact_host_not_allowed",
                "artifact URL host is not allow-listed",
            )
        return value


@dataclass(frozen=True, slots=True)
class ArtifactManifest:
    key_id: str
    version: str
    platform: str
    arch: str
    license: str
    provenance: str
    url: str
    sha256: str
    size: int
    expires_at: datetime
    signature: bytes

    def payload(self) -> dict[str, object]:
        return {
            "keyId": self.key_id,
            "version": self.version,
            "platform": self.platform,
            "arch": self.arch,
            "license": self.license,
            "provenance": self.provenance,
            "url": self.url,
            "sha256": self.sha256,
            "size": self.size,
            "expiresAt": self.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactManifestError(
                "manifest_duplicate_field",
                "manifest contains a duplicate field",
            )
        result[key] = value
    return result


class ArtifactManifestVerifier:
    """Parse, authenticate, and apply platform/network policy to a manifest."""

    def __init__(
        self,
        keyring: PinnedEd25519Keyring,
        policy: ArtifactDownloadPolicy,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(keyring, PinnedEd25519Keyring):
            raise TypeError("keyring must be a PinnedEd25519Keyring")
        if not isinstance(policy, ArtifactDownloadPolicy):
            raise TypeError("policy must be an ArtifactDownloadPolicy")
        self.keyring = keyring
        self.policy = policy
        self.clock = clock or (lambda: datetime.now(UTC))

    def verify(
        self,
        document: str | bytes,
        *,
        expected_platform: str | None = None,
        expected_arch: str | None = None,
    ) -> ArtifactManifest:
        if isinstance(document, str):
            encoded = document.encode("utf-8")
        elif isinstance(document, bytes):
            encoded = document
        else:
            raise TypeError("manifest document must be UTF-8 text or bytes")
        if not encoded or len(encoded) > _MAX_MANIFEST_BYTES:
            raise ArtifactManifestError(
                "manifest_size_invalid",
                "manifest document is empty or exceeds its size limit",
            )
        try:
            decoded = encoded.decode("utf-8", "strict")
            decoded_json = cast(
                object,
                json.loads(decoded, object_pairs_hook=_reject_duplicate_keys),
            )
        except ArtifactManifestError:
            raise
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ArtifactManifestError(
                "manifest_json_invalid",
                "manifest is not valid UTF-8 JSON",
            ) from error
        if not isinstance(decoded_json, dict):
            raise ArtifactManifestError(
                "manifest_fields_invalid",
                "manifest must contain exactly the supported fields",
            )
        raw = cast(dict[str, object], decoded_json)
        if set(raw) != MANIFEST_FIELDS:
            raise ArtifactManifestError(
                "manifest_fields_invalid",
                "manifest must contain exactly the supported fields",
            )

        payload = {field: raw[field] for field in SIGNED_MANIFEST_FIELDS}
        key_id = self._safe_string(payload["keyId"], "keyId", 64)
        if not _KEY_ID.fullmatch(key_id):
            raise ArtifactManifestError("manifest_key_id_invalid", "manifest keyId is invalid")
        version = self._safe_string(payload["version"], "version", 128)
        platform = self._target(payload["platform"], "platform")
        arch = self._target(payload["arch"], "arch")
        license_value = self._safe_string(payload["license"], "license", 256)
        provenance = self._safe_string(payload["provenance"], "provenance", 512)
        url = self._safe_string(payload["url"], "url", 4096)
        digest = self._safe_string(payload["sha256"], "sha256", 64)
        if not _SHA256.fullmatch(digest):
            raise ArtifactManifestError(
                "manifest_sha256_invalid",
                "manifest SHA-256 must be 64 lowercase hexadecimal characters",
            )
        size = payload["size"]
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ArtifactManifestError("manifest_size_invalid", "manifest size is invalid")
        if size > self.policy.maximum_artifact_bytes:
            raise ArtifactPolicyError(
                "artifact_size_limit_exceeded",
                "signed artifact size exceeds the configured download limit",
            )
        expires_text = self._safe_string(payload["expiresAt"], "expiresAt", 20)
        if not _UTC_TIMESTAMP.fullmatch(expires_text):
            raise ArtifactManifestError(
                "manifest_expiry_invalid",
                "manifest expiresAt must be an RFC 3339 UTC timestamp",
            )
        try:
            expires_at = datetime.strptime(expires_text, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=UTC
            )
        except ValueError as error:
            raise ArtifactManifestError(
                "manifest_expiry_invalid",
                "manifest expiresAt is invalid",
            ) from error

        signature_text = self._safe_string(raw["signature"], "signature", 128)
        try:
            signature = base64.b64decode(signature_text, validate=True)
        except (ValueError, binascii.Error) as error:
            raise ArtifactSignatureError(
                "manifest_signature_encoding_invalid",
                "manifest signature is not valid base64",
            ) from error
        if len(signature) != 64:
            raise ArtifactSignatureError(
                "manifest_signature_encoding_invalid",
                "manifest Ed25519 signature must contain 64 bytes",
            )

        canonical = canonical_manifest_bytes(payload)
        self.keyring.verify(key_id, signature, canonical)
        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise RuntimeError("manifest verifier clock must return a timezone-aware datetime")
        if expires_at <= now.astimezone(UTC):
            raise ArtifactManifestError("manifest_expired", "manifest has expired")
        self.policy.validate_url(url)
        if expected_platform is not None and platform != expected_platform.casefold():
            raise ArtifactPolicyError(
                "artifact_platform_mismatch",
                "manifest platform does not match the requested platform",
            )
        if expected_arch is not None and arch != expected_arch.casefold():
            raise ArtifactPolicyError(
                "artifact_arch_mismatch",
                "manifest architecture does not match the requested architecture",
            )
        return ArtifactManifest(
            key_id=key_id,
            version=version,
            platform=platform,
            arch=arch,
            license=license_value,
            provenance=provenance,
            url=url,
            sha256=digest,
            size=size,
            expires_at=expires_at,
            signature=signature,
        )

    @staticmethod
    def _safe_string(value: object, field: str, maximum: int) -> str:
        if (
            not isinstance(value, str)
            or not value
            or len(value) > maximum
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        ):
            raise ArtifactManifestError(
                f"manifest_{field}_invalid",
                f"manifest {field} is invalid",
            )
        return value

    @classmethod
    def _target(cls, value: object, field: str) -> str:
        target = cls._safe_string(value, field, 64)
        if not _TARGET_VALUE.fullmatch(target):
            raise ArtifactManifestError(
                f"manifest_{field}_invalid",
                f"manifest {field} is invalid",
            )
        return target


@dataclass(frozen=True, slots=True)
class ArtifactDownloadResult:
    path: str
    sha256: str
    size: int
    cache_hit: bool
    resumed: bool
    etag: str | None
    final_url: str
    redirects: int


class _Response(Protocol):
    status_code: int
    headers: Mapping[str, str]

    def iter_content(self, chunk_size: int) -> Iterable[bytes]: ...

    def close(self) -> None: ...


class _Session(Protocol):
    def get(self, url: str, **kwargs: object) -> _Response: ...


class _HashWriter(Protocol):
    def update(self, value: bytes, /) -> None: ...


@dataclass(frozen=True, slots=True)
class _ResumeState:
    etag: str
    offset: int


class ArtifactDownloader:
    """Requests-backed downloader with verified cache and ETag-bound resume."""

    def __init__(
        self,
        verifier: ArtifactManifestVerifier,
        *,
        session: _Session | None = None,
    ) -> None:
        if not isinstance(verifier, ArtifactManifestVerifier):
            raise TypeError("verifier must be an ArtifactManifestVerifier")
        self.verifier = verifier
        self.policy = verifier.policy
        self.session = cast(_Session, session or requests.Session())

    def download(
        self,
        manifest_document: str | bytes,
        destination: str | os.PathLike[str],
        *,
        expected_platform: str | None = None,
        expected_arch: str | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> ArtifactDownloadResult:
        manifest = self.verifier.verify(
            manifest_document,
            expected_platform=expected_platform,
            expected_arch=expected_arch,
        )
        self._raise_if_cancelled(cancelled)
        target = Path(destination).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        self._validate_destination(target)
        if self._file_matches(target, manifest):
            return self._result(target, manifest, cache_hit=True)

        partial, metadata = self._partial_paths(target, manifest)
        self._raise_if_cancelled(cancelled)
        completed = self._promote_complete_partial(partial, metadata, target, manifest)
        if completed is not None:
            return completed
        resume = self._load_resume(partial, metadata, manifest)
        if resume is None:
            self._discard_partial(partial, metadata)

        request_headers = {
            "Accept": "application/octet-stream",
            "Accept-Encoding": "identity",
            "User-Agent": "PixelFlasher-artifact-downloader/1",
        }
        if resume is not None:
            request_headers["Range"] = f"bytes={resume.offset}-"
            request_headers["If-Range"] = resume.etag

        response: _Response | None = None
        final_url = manifest.url
        redirects = 0
        append = False
        try:
            response, final_url, redirects = self._open_response(
                manifest.url,
                request_headers,
                cancelled=cancelled,
            )
            if resume is not None and response.status_code == 206:
                observed_etag = self._strong_etag(self._header(response, "ETag"))
                if observed_etag != resume.etag or not self._valid_content_range(
                    response,
                    resume.offset,
                    manifest.size,
                ):
                    response.close()
                    response = None
                    self._discard_partial(partial, metadata)
                    response, final_url, fallback_redirects = self._open_response(
                        manifest.url,
                        request_headers={
                            key: value
                            for key, value in request_headers.items()
                            if key not in {"Range", "If-Range"}
                        },
                        cancelled=cancelled,
                    )
                    redirects += fallback_redirects
                    if response.status_code != 200:
                        raise ArtifactTransportError(
                            "artifact_http_status_invalid",
                            "artifact server did not provide a complete response",
                        )
                else:
                    append = True
            elif response.status_code == 200:
                self._discard_partial(partial, metadata)
            elif resume is not None and response.status_code in _RANGE_REFUSED_STATUSES:
                response.close()
                response = None
                self._discard_partial(partial, metadata)
                response, final_url, fallback_redirects = self._open_response(
                    manifest.url,
                    request_headers={
                        key: value
                        for key, value in request_headers.items()
                        if key not in {"Range", "If-Range"}
                    },
                    cancelled=cancelled,
                )
                redirects += fallback_redirects
                if response.status_code != 200:
                    raise ArtifactTransportError(
                        "artifact_http_status_invalid",
                        "artifact server did not provide a complete response",
                    )
            else:
                raise ArtifactTransportError(
                    "artifact_http_status_invalid",
                    f"artifact server returned HTTP {response.status_code}",
                )

            observed_etag = self._strong_etag(self._header(response, "ETag"))
            offset = resume.offset if append and resume is not None else 0
            self._validate_response_headers(response, manifest, offset)
            if observed_etag is not None:
                self._write_resume_metadata(metadata, manifest, observed_etag, final_url)
            else:
                self._safe_unlink(metadata)

            digest = hashlib.sha256()
            downloaded = 0
            if append:
                downloaded = self._hash_existing_partial(partial, digest, manifest)
            mode = "ab" if append else "wb"
            try:
                self._raise_if_cancelled(cancelled)
                with self._open_output(partial, mode) as stream:
                    try:
                        for chunk in response.iter_content(chunk_size=self.policy.chunk_size):
                            self._raise_if_cancelled(cancelled)
                            if not chunk:
                                continue
                            if not isinstance(chunk, bytes):
                                raise ArtifactTransportError(
                                    "artifact_stream_invalid",
                                    "artifact response yielded non-byte content",
                                )
                            downloaded += len(chunk)
                            if (
                                downloaded > manifest.size
                                or downloaded > self.policy.maximum_artifact_bytes
                            ):
                                raise ArtifactIntegrityError(
                                    "artifact_size_mismatch",
                                    "artifact response exceeded its signed size",
                                )
                            stream.write(chunk)
                            digest.update(chunk)
                    except requests.RequestException:
                        stream.flush()
                        os.fsync(stream.fileno())
                        raise
                    except ArtifactCancelledError:
                        stream.flush()
                        os.fsync(stream.fileno())
                        raise
                    stream.flush()
                    os.fsync(stream.fileno())
            except requests.RequestException as error:
                if observed_etag is None:
                    self._discard_partial(partial, metadata)
                raise ArtifactTransportError(
                    "artifact_stream_failed",
                    "artifact stream ended with a transport error",
                ) from error
            except ArtifactCancelledError:
                if observed_etag is None:
                    self._discard_partial(partial, metadata)
                raise
            except ArtifactDownloadError:
                self._discard_partial(partial, metadata)
                raise
            except OSError as error:
                self._discard_partial(partial, metadata)
                raise ArtifactTransportError(
                    "artifact_write_failed",
                    "artifact temporary file could not be written",
                ) from error

            if downloaded != manifest.size:
                self._discard_partial(partial, metadata)
                raise ArtifactIntegrityError(
                    "artifact_size_mismatch",
                    "downloaded artifact size does not match the signed manifest",
                )
            if digest.hexdigest() != manifest.sha256:
                self._discard_partial(partial, metadata)
                raise ArtifactIntegrityError(
                    "artifact_sha256_mismatch",
                    "downloaded artifact SHA-256 does not match the signed manifest",
                )
            self._raise_if_cancelled(cancelled)
            try:
                self._validate_destination(target)
                os.replace(partial, target)
                self._safe_unlink(metadata)
                self._fsync_directory(target.parent)
            except OSError as error:
                raise ArtifactTransportError(
                    "artifact_commit_failed",
                    "verified artifact could not be atomically committed",
                ) from error
            return self._result(
                target,
                manifest,
                cache_hit=False,
                resumed=append,
                etag=observed_etag,
                final_url=final_url,
                redirects=redirects,
            )
        finally:
            if response is not None:
                response.close()

    def _open_response(
        self,
        url: str,
        request_headers: Mapping[str, str],
        *,
        cancelled: Callable[[], bool] | None,
    ) -> tuple[_Response, str, int]:
        current = self.policy.validate_url(url)
        redirects = 0
        while True:
            self._raise_if_cancelled(cancelled)
            try:
                response = self.session.get(
                    current,
                    headers=dict(request_headers),
                    stream=True,
                    timeout=(self.policy.connect_timeout, self.policy.read_timeout),
                    allow_redirects=False,
                )
            except requests.RequestException as error:
                raise ArtifactTransportError(
                    "artifact_request_failed",
                    "artifact request failed",
                ) from error
            if response.status_code not in _REDIRECT_STATUSES:
                try:
                    self._raise_if_cancelled(cancelled)
                except ArtifactCancelledError:
                    response.close()
                    raise
                return response, current, redirects
            location = self._header(response, "Location")
            response.close()
            if not location:
                raise ArtifactTransportError(
                    "artifact_redirect_invalid",
                    "artifact redirect is missing its destination",
                )
            if redirects >= self.policy.maximum_redirects:
                raise ArtifactTransportError(
                    "artifact_redirect_limit_exceeded",
                    "artifact response exceeded the redirect limit",
                )
            current = self.policy.validate_url(urljoin(current, location))
            redirects += 1

    @staticmethod
    def _raise_if_cancelled(cancelled: Callable[[], bool] | None) -> None:
        if cancelled is None:
            return
        try:
            requested = cancelled()
        except Exception as error:
            raise ArtifactTransportError(
                "artifact_cancellation_check_failed",
                "artifact cancellation state could not be read",
            ) from error
        if requested:
            raise ArtifactCancelledError

    def _load_resume(
        self,
        partial: Path,
        metadata: Path,
        manifest: ArtifactManifest,
    ) -> _ResumeState | None:
        if not partial.exists() or not metadata.exists():
            return None
        if partial.is_symlink() or metadata.is_symlink():
            return None
        try:
            if not partial.is_file() or not metadata.is_file():
                return None
            decoded_json = cast(
                object,
                json.loads(metadata.read_text(encoding="utf-8")),
            )
            offset = partial.stat().st_size
        except (OSError, UnicodeError, json.JSONDecodeError):
            return None
        expected = {
            "schemaVersion": 1,
            "url": manifest.url,
            "sha256": manifest.sha256,
            "size": manifest.size,
        }
        if not isinstance(decoded_json, dict):
            return None
        raw = cast(dict[str, object], decoded_json)
        if any(raw.get(key) != value for key, value in expected.items()):
            return None
        raw_etag = raw.get("etag")
        etag = self._strong_etag(raw_etag if isinstance(raw_etag, str) else None)
        if etag is None or offset <= 0 or offset >= manifest.size:
            return None
        return _ResumeState(etag, offset)

    def _write_resume_metadata(
        self,
        metadata: Path,
        manifest: ArtifactManifest,
        etag: str,
        final_url: str,
    ) -> None:
        document = json.dumps(
            {
                "schemaVersion": 1,
                "url": manifest.url,
                "finalUrl": final_url,
                "sha256": manifest.sha256,
                "size": manifest.size,
                "etag": etag,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{metadata.name}.",
            suffix=".tmp",
            dir=metadata.parent,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(document)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, metadata)
            self._fsync_directory(metadata.parent)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    def _promote_complete_partial(
        self,
        partial: Path,
        metadata: Path,
        target: Path,
        manifest: ArtifactManifest,
    ) -> ArtifactDownloadResult | None:
        if not self._file_matches(partial, manifest):
            return None
        self._validate_destination(target)
        os.replace(partial, target)
        self._safe_unlink(metadata)
        self._fsync_directory(target.parent)
        return self._result(target, manifest, cache_hit=True, resumed=True)

    @staticmethod
    def _partial_paths(target: Path, manifest: ArtifactManifest) -> tuple[Path, Path]:
        stem = f".{target.name}.{manifest.sha256[:16]}"
        return target.with_name(f"{stem}.part"), target.with_name(f"{stem}.resume.json")

    @staticmethod
    def _validate_destination(target: Path) -> None:
        if os.path.lexists(target):
            if target.is_symlink() or not target.is_file():
                raise ArtifactPolicyError(
                    "artifact_destination_invalid",
                    "artifact destination must be a regular file",
                )

    @staticmethod
    def _open_output(path: Path, mode: str):
        if os.path.lexists(path) and (path.is_symlink() or not path.is_file()):
            raise ArtifactPolicyError(
                "artifact_temporary_path_invalid",
                "artifact temporary path must be a regular file",
            )
        flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_BINARY", 0)
        flags |= os.O_APPEND if mode == "ab" else os.O_TRUNC
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            os.close(descriptor)
            raise ArtifactPolicyError(
                "artifact_temporary_path_invalid",
                "artifact temporary path must be a regular file",
            )
        return os.fdopen(descriptor, mode)

    @staticmethod
    def _hash_existing_partial(
        partial: Path,
        digest: _HashWriter,
        manifest: ArtifactManifest,
    ) -> int:
        size = 0
        with partial.open("rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size >= manifest.size:
                    raise ArtifactIntegrityError(
                        "artifact_resume_invalid",
                        "artifact partial file exceeds its resumable bounds",
                    )
                digest.update(chunk)
        return size

    @staticmethod
    def _file_matches(path: Path, manifest: ArtifactManifest) -> bool:
        if not os.path.lexists(path) or path.is_symlink() or not path.is_file():
            return False
        try:
            if path.stat().st_size != manifest.size:
                return False
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
            return digest.hexdigest() == manifest.sha256
        except OSError:
            return False

    @staticmethod
    def _header(response: _Response, name: str) -> str | None:
        for key, value in response.headers.items():
            if key.casefold() == name.casefold():
                return str(value).strip()
        return None

    @staticmethod
    def _strong_etag(value: str | None) -> str | None:
        if (
            not value
            or value.startswith("W/")
            or len(value) > 512
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        ):
            return None
        return value

    def _validate_response_headers(
        self,
        response: _Response,
        manifest: ArtifactManifest,
        offset: int,
    ) -> None:
        encoding = self._header(response, "Content-Encoding")
        if encoding and encoding.casefold() != "identity":
            raise ArtifactTransportError(
                "artifact_content_encoding_invalid",
                "artifact response must use identity content encoding",
            )
        length = self._header(response, "Content-Length")
        if length is not None:
            try:
                parsed = int(length, 10)
            except ValueError as error:
                raise ArtifactTransportError(
                    "artifact_content_length_invalid",
                    "artifact response Content-Length is invalid",
                ) from error
            if parsed != manifest.size - offset:
                raise ArtifactIntegrityError(
                    "artifact_size_mismatch",
                    "artifact response length does not match the signed size",
                )

    def _valid_content_range(self, response: _Response, offset: int, total: int) -> bool:
        value = self._header(response, "Content-Range")
        if not value:
            return False
        match = _CONTENT_RANGE.fullmatch(value)
        return bool(
            match
            and int(match.group(1)) == offset
            and int(match.group(2)) == total - 1
            and int(match.group(3)) == total
        )

    @staticmethod
    def _safe_unlink(path: Path) -> None:
        if not os.path.lexists(path):
            return
        if path.is_dir() and not path.is_symlink():
            raise ArtifactPolicyError(
                "artifact_temporary_path_invalid",
                "artifact temporary path must not be a directory",
            )
        path.unlink(missing_ok=True)

    def _discard_partial(self, partial: Path, metadata: Path) -> None:
        self._safe_unlink(partial)
        self._safe_unlink(metadata)

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        if os.name == "nt":
            return
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _result(
        target: Path,
        manifest: ArtifactManifest,
        *,
        cache_hit: bool,
        resumed: bool = False,
        etag: str | None = None,
        final_url: str | None = None,
        redirects: int = 0,
    ) -> ArtifactDownloadResult:
        return ArtifactDownloadResult(
            path=str(target.resolve()),
            sha256=manifest.sha256,
            size=manifest.size,
            cache_hit=cache_hit,
            resumed=resumed,
            etag=etag,
            final_url=final_url or manifest.url,
            redirects=redirects,
        )


__all__ = [
    "SIGNED_MANIFEST_FIELDS",
    "ArtifactDownloadError",
    "ArtifactDownloadPolicy",
    "ArtifactDownloadResult",
    "ArtifactDownloader",
    "ArtifactCancelledError",
    "ArtifactIntegrityError",
    "ArtifactManifest",
    "ArtifactManifestError",
    "ArtifactManifestVerifier",
    "ArtifactPolicyError",
    "ArtifactSignatureError",
    "ArtifactTransportError",
    "PinnedEd25519Keyring",
    "canonical_manifest_bytes",
]
