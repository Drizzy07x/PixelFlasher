"""Offline, redacted and authenticated PixelFlasher support packages.

Version 2 packages contain a bounded ZIP payload encrypted with a fresh
AES-256-GCM key.  That key is wrapped for the support recipient with
RSA-OAEP/SHA-256.  The authenticated envelope pins the SHA-256 of the inner
manifest, while the manifest pins every allow-listed entry.

The writer has no version switch and therefore can only emit version 2.  The
reader also understands the schema-1 redacted ZIP produced by ``support.py``
and the older ``support.pf``/``pf.dat`` Fernet wrapper.  Nothing in this module
uploads data or performs network I/O.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import io
import json
import math
import os
import re
import secrets
import sqlite3
import struct
import tempfile
import zipfile
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import cast

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SUPPORT_V2_MAGIC = b"PFSPV2\x00\x01"
SUPPORT_V2_FORMAT = "pixelflasher-support-package"
SUPPORT_V2_REDACTION_POLICY = "pixelflasher-support-redaction-v2"
SUPPORT_V2_SCHEMA = 2

_ENVELOPE_FIELDS = frozenset(
    {
        "format",
        "schemaVersion",
        "keyId",
        "keyWrapAlgorithm",
        "contentEncryption",
        "nonce",
        "wrappedKey",
        "plaintextBytes",
        "ciphertextBytes",
        "manifestSha256",
    }
)
_MANIFEST_FIELDS = frozenset(
    {
        "schemaVersion",
        "format",
        "createdUtc",
        "applicationVersion",
        "redaction",
        "included",
        "omitted",
        "manifestEntry",
    }
)
_MANIFEST_ENTRY_FIELDS = frozenset(
    {
        "entry",
        "category",
        "mediaType",
        "bytes",
        "sha256",
        "redacted",
        "truncated",
        "redactionProofSha256",
    }
)
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LOG_ENTRY = re.compile(r"^logs/log_[0-9]{3}\.(?:json|txt)$")
_DIAGRAM_ENTRY = re.compile(r"^diagrams/trace_[0-9]{3}\.puml$")
_LEGACY_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. ()-]{0,159}$")
_LEGACY_LOG = re.compile(
    r"^(?:logs|puml)/[A-Za-z0-9][A-Za-z0-9_. ()-]{0,159}\.(?:json|log|puml|txt)$",
    re.IGNORECASE,
)
_SECRET_KEY = re.compile(
    r"(?:access|api|auth|private|refresh|session)[_-]?key|"
    r"(?:access|api|auth|bearer|refresh|session)?[_-]?token|"
    r"cookie|credential|pass(?:word|wd)?|secret|superkey",
    re.IGNORECASE,
)
_SERIAL_KEY = re.compile(
    r"(?:selected[_-]?)?serial(?:s|no|number)?|device[_-]?id|device",
    re.IGNORECASE,
)
_PATH_KEY = re.compile(
    r"(?:file[_-]?)?path|directory|folder|home|cwd|executable|workspace|root",
    re.IGNORECASE,
)
_PII_KEY = re.compile(
    r"e[-_]?mail|host(?:name)?|computer[_-]?name|owner|user(?:name)?",
    re.IGNORECASE,
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?"
    r"-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
    re.DOTALL,
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?key|auth(?:orization)?|bearer|cookie|"
    r"credential|password|passwd|refresh[_-]?token|secret|session[_-]?token|"
    r"superkey|token)([\"']?)(\s*[:=]\s*)(?:Bearer\s+)?"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])")
_MAC = re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
_IPV4 = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"
)
_IPV6 = re.compile(
    r"(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])"
)
_WINDOWS_USER_PATH = re.compile(r"(?i)\b[A-Z]:[\\/](?:Users|Documents and Settings)[\\/][^\s\"'<>]+")
_WINDOWS_ABSOLUTE_PATH = re.compile(r"(?i)\b[A-Z]:[\\/][^\r\n\"'<>|]+")
_UNIX_PRIVATE_PATH = re.compile(
    r"(?i)(?<![:\w])/(?:Users|home|data/user|sdcard|storage|tmp|var/tmp)/[^\s\"'<>]+"
)
_ADB_DEVICE_LINE = re.compile(
    r"(?im)^(\s*)(\S+)(\s+(?:device|offline|unauthorized|recovery|sideload|fastboot)\b)"
)
_ADB_SERIAL_ARG = re.compile(r"(?i)(\b(?:adb|fastboot)(?:\.exe)?\b[^\r\n]*?\s-s\s+)(\S+)")
_SERIAL_FIELD = re.compile(
    r"(?i)(\b(?:device[_-]?id|serial(?:no|number)?|serial)\b\s*[:=]\s*)([^\s,;]+)"
)
_JWT = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])")

_EXACT_ENTRY_POLICIES = {
    "config/PixelFlasher.json": ("configuration", "application/json"),
    "config/labels.json": ("configuration", "application/json"),
    "state/app_snapshot.json": ("state", "application/json"),
    "system/system_info.json": ("system", "application/json"),
    "database/PixelFlasher.sqlite3": ("database", "application/vnd.sqlite3"),
}
_SQLITE_TABLES: Mapping[str, tuple[tuple[str, str], ...]] = {
    "PACKAGE": (
        ("id", "INTEGER"),
        ("boot_hash", "TEXT"),
        ("type", "TEXT"),
        ("package_sig", "TEXT"),
        ("file_path", "TEXT"),
        ("epoch", "INTEGER"),
        ("full_ota", "INTEGER"),
    ),
    "BOOT": (
        ("id", "INTEGER"),
        ("boot_hash", "TEXT"),
        ("file_path", "TEXT"),
        ("is_patched", "INTEGER"),
        ("magisk_version", "TEXT"),
        ("hardware", "TEXT"),
        ("epoch", "INTEGER"),
        ("patch_method", "TEXT"),
        ("is_odin", "INTEGER"),
        ("is_stock_boot", "INTEGER"),
        ("is_init_boot", "INTEGER"),
        ("patch_source_sha1", "TEXT"),
    ),
    "PACKAGE_BOOT": (
        ("package_id", "INTEGER"),
        ("boot_id", "INTEGER"),
        ("epoch", "INTEGER"),
    ),
}


class SupportV2Error(RuntimeError):
    """Fail-closed support-package error with a stable public code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class SupportEntryMedia(StrEnum):
    JSON = "application/json"
    TEXT = "text/plain"
    SQLITE = "application/vnd.sqlite3"


@dataclass(frozen=True, slots=True)
class SupportV2Limits:
    max_entries: int = 64
    max_entry_bytes: int = 1_000_000
    max_total_entry_bytes: int = 8_000_000
    max_manifest_bytes: int = 512_000
    max_archive_bytes: int = 12_000_000
    max_container_bytes: int = 16_000_000
    max_database_source_bytes: int = 64_000_000
    max_database_bytes: int = 4_000_000
    max_database_rows: int = 20_000
    max_sensitive_values: int = 256

    def __post_init__(self) -> None:
        values = (
            self.max_entries,
            self.max_entry_bytes,
            self.max_total_entry_bytes,
            self.max_manifest_bytes,
            self.max_archive_bytes,
            self.max_container_bytes,
            self.max_database_source_bytes,
            self.max_database_bytes,
            self.max_database_rows,
            self.max_sensitive_values,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in values):
            raise ValueError("support v2 limits must be positive integers")
        if self.max_container_bytes <= len(SUPPORT_V2_MAGIC) + 4:
            raise ValueError("support v2 container limit is too small")


@dataclass(frozen=True, slots=True)
class SupportSourceEntry:
    archive_name: str
    category: str
    media_type: SupportEntryMedia
    content: object
    logical_source: str = "application"
    truncated: bool = False

    @classmethod
    def json(
        cls,
        archive_name: str,
        category: str,
        content: object,
        *,
        logical_source: str = "application",
        truncated: bool = False,
    ) -> SupportSourceEntry:
        return cls(
            archive_name,
            category,
            SupportEntryMedia.JSON,
            content,
            logical_source,
            truncated,
        )

    @classmethod
    def text(
        cls,
        archive_name: str,
        category: str,
        content: str | bytes,
        *,
        logical_source: str = "application",
        truncated: bool = False,
    ) -> SupportSourceEntry:
        return cls(
            archive_name,
            category,
            SupportEntryMedia.TEXT,
            content,
            logical_source,
            truncated,
        )

    @classmethod
    def sqlite(
        cls,
        source: str | os.PathLike[str],
        *,
        logical_source: str = "legacy-database",
    ) -> SupportSourceEntry:
        return cls(
            "database/PixelFlasher.sqlite3",
            "database",
            SupportEntryMedia.SQLITE,
            Path(source),
            logical_source,
            False,
        )


@dataclass(frozen=True, slots=True)
class SupportPackageOmission:
    source: str
    category: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"source": self.source, "category": self.category, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class SupportV2WriteResult:
    path: str
    schema_version: int
    key_id: str
    sha256: str
    size: int
    manifest_sha256: str
    included_count: int
    omitted_count: int
    redaction_verified: bool

    def to_dict(self) -> dict[str, object]:
        """Return the bridge-safe result; the native destination stays private."""

        return {
            "fileName": Path(self.path).name,
            "schemaVersion": self.schema_version,
            "keyId": self.key_id,
            "sha256": self.sha256,
            "size": self.size,
            "manifestSha256": self.manifest_sha256,
            "includedCount": self.included_count,
            "omittedCount": self.omitted_count,
            "redactionVerified": self.redaction_verified,
        }


@dataclass(frozen=True, slots=True)
class SupportReadEntry:
    archive_name: str
    category: str
    media_type: str
    payload: bytes
    sha256: str
    redaction_verified: bool


@dataclass(frozen=True, slots=True)
class SupportPackageReadResult:
    schema_version: int
    format: str
    application_version: str
    key_id: str
    manifest_sha256: str
    entries: tuple[SupportReadEntry, ...]
    omissions: tuple[SupportPackageOmission, ...]
    redaction_verified: bool
    legacy_encrypted: bool

    def entry(self, archive_name: str) -> SupportReadEntry:
        for item in self.entries:
            if item.archive_name == archive_name:
                return item
        raise SupportV2Error("support_entry_not_found", "support package entry was not found")


@dataclass(frozen=True, slots=True)
class _PreparedEntry:
    archive_name: str
    category: str
    media_type: str
    payload: bytes
    logical_source: str
    truncated: bool
    proof: str


@dataclass(frozen=True, slots=True)
class _SQLiteCopy:
    payload: bytes
    truncated: bool


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise SupportV2Error(
            "support_json_invalid",
            "support package data cannot be represented as canonical JSON",
        ) from error


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SupportV2Error(
                "support_json_duplicate_field",
                "support package JSON contains a duplicate field",
            )
        result[key] = value
    return result


def _parse_json(document: bytes, code: str) -> object:
    try:
        text = document.decode("utf-8", "strict")
        return cast(object, json.loads(text, object_pairs_hook=_reject_duplicates))
    except SupportV2Error:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise SupportV2Error(code, "support package contains invalid UTF-8 JSON") from error


def _safe_text(value: object, field: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise SupportV2Error("support_manifest_invalid", f"support {field} is invalid")
    return value


def _b64decode(value: object, field: str, maximum: int) -> bytes:
    text = _safe_text(value, field, maximum)
    try:
        return base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as error:
        raise SupportV2Error("support_envelope_invalid", f"support {field} is invalid") from error


def _entry_policy(name: object) -> tuple[str, str]:
    if not isinstance(name, str) or len(name) > 200:
        raise SupportV2Error("support_entry_not_allowed", "support entry name is invalid")
    exact = _EXACT_ENTRY_POLICIES.get(name)
    if exact is not None:
        return exact
    if _LOG_ENTRY.fullmatch(name):
        return "logs", "application/json" if name.endswith(".json") else "text/plain"
    if _DIAGRAM_ENTRY.fullmatch(name):
        return "diagrams", "text/plain"
    raise SupportV2Error(
        "support_entry_not_allowed",
        f"support entry is not allow-listed: {name!r}",
    )


def _redaction_proof(name: str, payload: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(SUPPORT_V2_REDACTION_POLICY.encode("ascii"))
    digest.update(b"\x00")
    digest.update(name.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(payload)
    return digest.hexdigest()


class _Redactor:
    def __init__(self, sensitive_values: Iterable[str], maximum_values: int) -> None:
        try:
            values = tuple(sensitive_values)
        except TypeError as error:
            raise SupportV2Error(
                "support_sensitive_value_invalid",
                "sensitive values must be an iterable of strings",
            ) from error
        if len(values) > maximum_values:
            raise SupportV2Error(
                "support_sensitive_values_limit",
                "too many explicit sensitive values were supplied",
            )
        normalized: list[str] = []
        automatic = (str(Path.home()), os.environ.get("USERNAME", ""), os.environ.get("USER", ""))
        for value in (*values, *automatic):
            if not isinstance(value, str):
                raise SupportV2Error(
                    "support_sensitive_value_invalid",
                    "sensitive values must be strings",
                )
            if value and value not in normalized:
                if len(value) > 4096:
                    raise SupportV2Error(
                        "support_sensitive_value_invalid",
                        "a sensitive value exceeds its limit",
                    )
                normalized.append(value)
        self._sensitive = tuple(normalized)
        self._patterns = tuple(
            re.compile(re.escape(value), re.IGNORECASE)
            for value in self._sensitive
            if len(value) >= 3
        )

    def text(self, value: str) -> str:
        redacted = _PRIVATE_KEY.sub("<private-key-redacted>", value)
        redacted = _SECRET_ASSIGNMENT.sub(
            lambda match: (
                f"{match.group(1)}{match.group(2)}{match.group(3)}\"<redacted>\""
            ),
            redacted,
        )
        for pattern in self._patterns:
            redacted = pattern.sub("<sensitive-redacted>", redacted)
        redacted = _WINDOWS_USER_PATH.sub("<path-redacted>", redacted)
        redacted = _WINDOWS_ABSOLUTE_PATH.sub("<path-redacted>", redacted)
        redacted = _UNIX_PRIVATE_PATH.sub("<path-redacted>", redacted)
        redacted = _ADB_DEVICE_LINE.sub(r"\1<serial-redacted>\3", redacted)
        redacted = _ADB_SERIAL_ARG.sub(r"\1<serial-redacted>", redacted)
        redacted = _SERIAL_FIELD.sub(r"\1<serial-redacted>", redacted)
        redacted = _EMAIL.sub("<email-redacted>", redacted)
        redacted = _MAC.sub("<mac-redacted>", redacted)
        redacted = _IPV4.sub("<ip-redacted>", redacted)
        redacted = _IPV6.sub("<ip-redacted>", redacted)
        redacted = _JWT.sub("<token-redacted>", redacted)
        return redacted

    def json_value(self, value: object, *, key: str = "", depth: int = 0) -> object:
        if depth > 40:
            return "<depth-redacted>"
        if key and _SECRET_KEY.search(key):
            return "<redacted>"
        if key and _SERIAL_KEY.fullmatch(key.strip()):
            return "<serial-redacted>"
        if key and _PATH_KEY.search(key):
            return "<path-redacted>"
        if key and _PII_KEY.fullmatch(key.strip()):
            return "<pii-redacted>"
        if isinstance(value, Mapping):
            result: dict[str, object] = {}
            mapping_value = cast(Mapping[object, object], value)
            for raw_key, item in mapping_value.items():
                safe_key = self.text(str(raw_key))
                if safe_key in result:
                    suffix = 2
                    candidate = f"{safe_key}#{suffix}"
                    while candidate in result:
                        suffix += 1
                        candidate = f"{safe_key}#{suffix}"
                    safe_key = candidate
                result[safe_key] = self.json_value(item, key=str(raw_key), depth=depth + 1)
            return result
        if isinstance(value, (list, tuple)):
            sequence_value = cast(list[object] | tuple[object, ...], value)
            return [self.json_value(item, depth=depth + 1) for item in sequence_value]
        if isinstance(value, str):
            return self.text(value)
        if value is None or isinstance(value, (bool, int)):
            return value
        if isinstance(value, float):
            return value if math.isfinite(value) else "<non-finite-redacted>"
        return self.text(str(value))

    def verify_text(self, value: str) -> bool:
        if self.text(value) != value:
            return False
        folded = value.casefold()
        return all(
            len(item) < 3 or item.casefold() not in folded
            for item in self._sensitive
        )


def _load_public_key(value: bytes | rsa.RSAPublicKey) -> rsa.RSAPublicKey:
    if isinstance(value, rsa.RSAPublicKey):
        key = value
    elif isinstance(value, bytes):
        try:
            loaded = serialization.load_pem_public_key(value)
        except (TypeError, ValueError) as error:
            raise SupportV2Error("support_public_key_invalid", "support public key is invalid") from error
        if not isinstance(loaded, rsa.RSAPublicKey):
            raise SupportV2Error("support_public_key_invalid", "support public key must use RSA")
        key = loaded
    else:
        raise SupportV2Error("support_public_key_invalid", "support public key must use RSA")
    if key.key_size < 2048:
        raise SupportV2Error("support_public_key_invalid", "support RSA key must be at least 2048 bits")
    return key


def _load_private_key(value: bytes | rsa.RSAPrivateKey | None) -> rsa.RSAPrivateKey | None:
    if value is None:
        return None
    if isinstance(value, rsa.RSAPrivateKey):
        key = value
    elif isinstance(value, bytes):
        try:
            loaded = serialization.load_pem_private_key(value, password=None)
        except (TypeError, ValueError) as error:
            raise SupportV2Error("support_private_key_invalid", "support private key is invalid") from error
        if not isinstance(loaded, rsa.RSAPrivateKey):
            raise SupportV2Error("support_private_key_invalid", "support private key must use RSA")
        key = loaded
    else:
        raise SupportV2Error("support_private_key_invalid", "support private key must use RSA")
    if key.key_size < 2048:
        raise SupportV2Error("support_private_key_invalid", "support RSA key must be at least 2048 bits")
    return key


class SupportPackageV2Writer:
    """Write one atomic, encrypted version-2 support package."""

    def __init__(
        self,
        recipient_public_key: bytes | rsa.RSAPublicKey,
        *,
        key_id: str,
        limits: SupportV2Limits | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
            raise SupportV2Error("support_key_id_invalid", "support recipient key ID is invalid")
        if limits is not None and not isinstance(limits, SupportV2Limits):
            raise TypeError("limits must be SupportV2Limits")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        self.public_key = _load_public_key(recipient_public_key)
        self.key_id = key_id
        self.limits = limits or SupportV2Limits()
        self.clock = clock or (lambda: datetime.now(UTC))

    def write(
        self,
        destination: str | os.PathLike[str],
        entries: Sequence[SupportSourceEntry] | Iterable[SupportSourceEntry],
        *,
        application_version: str,
        sensitive_values: Iterable[str] = (),
        omissions: Sequence[SupportPackageOmission] = (),
        allow_overwrite: bool = False,
        cancellation_check: Callable[[], bool] | None = None,
    ) -> SupportV2WriteResult:
        if not isinstance(allow_overwrite, bool):
            raise SupportV2Error(
                "support_destination_invalid",
                "support overwrite authorization must be a boolean",
            )
        if cancellation_check is not None and not callable(cancellation_check):
            raise TypeError("cancellation_check must be callable")
        self._check_cancelled(cancellation_check)
        target = self._destination(destination, allow_overwrite=allow_overwrite)
        redactor = _Redactor(sensitive_values, self.limits.max_sensitive_values)
        prepared = self._prepare_entries(entries, redactor, cancellation_check)
        safe_omissions = self._omissions(omissions, redactor)
        version = _safe_text(application_version, "application version", 128)
        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise SupportV2Error(
                "support_clock_invalid",
                "support package clock must return a timezone-aware datetime",
            )
        created = now.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
        self._check_cancelled(cancellation_check)
        archive, manifest_digest = self._archive(
            prepared,
            safe_omissions,
            version,
            created,
            cancellation_check,
        )
        self._check_cancelled(cancellation_check)
        container = self._encrypt(archive, manifest_digest)
        digest = hashlib.sha256(container).hexdigest()
        self._write_atomic(
            target,
            container,
            allow_overwrite=allow_overwrite,
            cancellation_check=cancellation_check,
        )
        return SupportV2WriteResult(
            path=str(target),
            schema_version=SUPPORT_V2_SCHEMA,
            key_id=self.key_id,
            sha256=digest,
            size=len(container),
            manifest_sha256=manifest_digest,
            included_count=len(prepared),
            omitted_count=len(safe_omissions),
            redaction_verified=True,
        )

    def _prepare_entries(
        self,
        entries: Sequence[SupportSourceEntry] | Iterable[SupportSourceEntry],
        redactor: _Redactor,
        cancellation_check: Callable[[], bool] | None,
    ) -> tuple[_PreparedEntry, ...]:
        values: list[SupportSourceEntry] = []
        try:
            for entry in entries:
                if len(values) >= self.limits.max_entries:
                    raise SupportV2Error(
                        "support_entry_count_limit",
                        "support package exceeds its allow-listed entry count",
                    )
                if not isinstance(entry, SupportSourceEntry):
                    raise SupportV2Error("support_entry_invalid", "support source entry is invalid")
                values.append(entry)
        except TypeError as error:
            raise SupportV2Error(
                "support_entry_invalid",
                "support entries must be an iterable of typed source entries",
            ) from error
        if not values:
            raise SupportV2Error("support_entries_required", "support package requires at least one entry")
        seen: set[str] = set()
        prepared: list[_PreparedEntry] = []
        total = 0
        for source in values:
            self._check_cancelled(cancellation_check)
            if not isinstance(source.media_type, SupportEntryMedia):
                raise SupportV2Error("support_entry_invalid", "support entry media type is invalid")
            if not isinstance(source.truncated, bool):
                raise SupportV2Error("support_entry_invalid", "support entry truncation flag is invalid")
            if source.archive_name in seen:
                raise SupportV2Error("support_entry_duplicate", "support entry names must be unique")
            seen.add(source.archive_name)
            expected_category, expected_media = _entry_policy(source.archive_name)
            if source.category != expected_category or source.media_type.value != expected_media:
                raise SupportV2Error(
                    "support_entry_policy_mismatch",
                    "support entry category or media type does not match the allow-list",
                )
            _safe_text(source.logical_source, "logical source", 128)
            truncated = source.truncated
            if source.media_type is SupportEntryMedia.JSON:
                payload = self._json_payload(source.content, redactor)
            elif source.media_type is SupportEntryMedia.TEXT:
                payload = self._text_payload(source.content, redactor)
            else:
                database = self._sqlite_payload(source.content, redactor)
                payload = database.payload
                truncated = truncated or database.truncated
            entry_limit = (
                self.limits.max_database_bytes
                if source.media_type is SupportEntryMedia.SQLITE
                else self.limits.max_entry_bytes
            )
            if len(payload) > entry_limit:
                raise SupportV2Error(
                    "support_entry_size_limit",
                    "support entry exceeds its configured size limit",
                )
            total += len(payload)
            if total > self.limits.max_total_entry_bytes:
                raise SupportV2Error(
                    "support_total_size_limit",
                    "support package entries exceed their total size limit",
                )
            prepared.append(
                _PreparedEntry(
                    source.archive_name,
                    source.category,
                    source.media_type.value,
                    payload,
                    source.logical_source,
                    truncated,
                    _redaction_proof(source.archive_name, payload),
                )
            )
        return tuple(prepared)

    def _json_payload(self, content: object, redactor: _Redactor) -> bytes:
        if isinstance(content, bytes):
            raw = content
        elif isinstance(content, str):
            try:
                raw = content.encode("utf-8")
            except UnicodeError as error:
                raise SupportV2Error("support_json_invalid", "support JSON is not valid UTF-8") from error
        else:
            raw = _canonical_json(content)
        if len(raw) > self.limits.max_entry_bytes:
            raise SupportV2Error("support_entry_size_limit", "support JSON exceeds its source limit")
        value = _parse_json(raw, "support_json_invalid")
        safe = redactor.json_value(value)
        payload = _canonical_json(safe)
        decoded = payload.decode("utf-8")
        if not redactor.verify_text(decoded):
            raise SupportV2Error(
                "support_redaction_verification_failed",
                "support JSON failed mandatory redaction verification",
            )
        return payload

    def _text_payload(self, content: object, redactor: _Redactor) -> bytes:
        if isinstance(content, bytes):
            raw = content
        elif isinstance(content, str):
            try:
                raw = content.encode("utf-8")
            except UnicodeError as error:
                raise SupportV2Error("support_text_invalid", "support text is not valid UTF-8") from error
        else:
            raise SupportV2Error("support_text_invalid", "support text entry must contain text")
        if len(raw) > self.limits.max_entry_bytes:
            raise SupportV2Error("support_entry_size_limit", "support text exceeds its source limit")
        if b"\x00" in raw:
            raise SupportV2Error("support_text_invalid", "binary support content is not allowed")
        try:
            decoded = raw.decode("utf-8", "strict")
        except UnicodeError as error:
            raise SupportV2Error("support_text_invalid", "support text is not valid UTF-8") from error
        safe = redactor.text(decoded)
        if not redactor.verify_text(safe):
            raise SupportV2Error(
                "support_redaction_verification_failed",
                "support text failed mandatory redaction verification",
            )
        return safe.encode("utf-8")

    def _sqlite_payload(self, content: object, redactor: _Redactor) -> _SQLiteCopy:
        if not isinstance(content, (str, os.PathLike)):
            raise SupportV2Error(
                "support_database_invalid",
                "support database source must be a filesystem path",
            )
        source_value = cast(str | os.PathLike[str], content)
        source = Path(source_value).expanduser()
        if not source.is_absolute() or not os.path.lexists(source) or source.is_symlink() or not source.is_file():
            raise SupportV2Error(
                "support_database_invalid",
                "support database source must be an existing regular file",
            )
        try:
            source_size = source.stat().st_size
        except OSError as error:
            raise SupportV2Error("support_database_read_failed", "support database cannot be read") from error
        if source_size > self.limits.max_database_source_bytes:
            raise SupportV2Error("support_database_size_limit", "support database exceeds its source limit")

        with tempfile.TemporaryDirectory(prefix="pixelflasher-support-db-") as directory:
            output = Path(directory) / "sanitized.sqlite3"
            source_connection: sqlite3.Connection | None = None
            output_connection: sqlite3.Connection | None = None
            total_rows = 0
            truncated = False
            try:
                uri = source.resolve(strict=True).as_uri() + "?mode=ro"
                source_connection = sqlite3.connect(uri, uri=True)
                source_connection.execute("PRAGMA query_only = ON")
                source_connection.execute("PRAGMA trusted_schema = OFF")
                output_connection = sqlite3.connect(output)
                output_connection.execute("PRAGMA secure_delete = ON")
                present_rows = source_connection.execute(
                    "SELECT name, sql FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
                present = {
                    str(name): str(sql or "")
                    for name, sql in present_rows
                    if isinstance(name, str)
                }
                for table, allowed_columns in _SQLITE_TABLES.items():
                    schema = present.get(table, "")
                    if not schema or "VIRTUAL TABLE" in schema.upper():
                        continue
                    source_columns = {
                        str(row[1])
                        for row in source_connection.execute(f'PRAGMA table_info("{table}")')
                    }
                    selected = tuple(item for item in allowed_columns if item[0] in source_columns)
                    if not selected:
                        continue
                    definitions = ", ".join(f'"{name}" {kind}' for name, kind in selected)
                    output_connection.execute(f'CREATE TABLE "{table}" ({definitions})')
                    remaining = self.limits.max_database_rows - total_rows
                    if remaining <= 0:
                        truncated = True
                        continue
                    columns_sql = ", ".join(f'"{name}"' for name, _kind in selected)
                    rows = source_connection.execute(
                        f'SELECT {columns_sql} FROM "{table}" LIMIT ?',
                        (remaining + 1,),
                    ).fetchall()
                    if len(rows) > remaining:
                        rows = rows[:remaining]
                        truncated = True
                    placeholders = ", ".join("?" for _item in selected)
                    insert_sql = f'INSERT INTO "{table}" ({columns_sql}) VALUES ({placeholders})'
                    for row in rows:
                        safe_row = tuple(
                            self._sqlite_value(value, column, redactor)
                            for value, (column, _kind) in zip(row, selected, strict=True)
                        )
                        output_connection.execute(insert_sql, safe_row)
                    total_rows += len(rows)
                output_connection.commit()
                output_connection.execute("VACUUM")
                output_connection.close()
                output_connection = None
                source_connection.close()
                source_connection = None
                payload = output.read_bytes()
            except (OSError, sqlite3.Error, RuntimeError, ValueError) as error:
                raise SupportV2Error(
                    "support_database_sanitization_failed",
                    "support database could not be copied into the safe schema",
                ) from error
            finally:
                if output_connection is not None:
                    output_connection.close()
                if source_connection is not None:
                    source_connection.close()
            if len(payload) > self.limits.max_database_bytes:
                raise SupportV2Error(
                    "support_database_size_limit",
                    "sanitized support database exceeds its size limit",
                )
            self._verify_sqlite_payload(payload, redactor)
            return _SQLiteCopy(payload, truncated)

    @staticmethod
    def _sqlite_value(value: object, column: str, redactor: _Redactor) -> object:
        if value is None or isinstance(value, (int, float)):
            return value
        if _PATH_KEY.search(column):
            return "<path-redacted>"
        if _SERIAL_KEY.search(column):
            return "<serial-redacted>"
        if _SECRET_KEY.search(column):
            return "<redacted>"
        if _PII_KEY.search(column):
            return "<pii-redacted>"
        if isinstance(value, bytes):
            return "<binary-redacted>"
        return redactor.text(str(value))

    def _verify_sqlite_payload(self, payload: bytes, redactor: _Redactor) -> None:
        folded = payload.lower()
        for sensitive in redactor._sensitive:
            encoded = sensitive.encode("utf-8", errors="ignore").lower()
            if len(encoded) >= 3 and encoded in folded:
                raise SupportV2Error(
                    "support_redaction_verification_failed",
                    "sanitized support database still contains a sensitive value",
                )
        with tempfile.TemporaryDirectory(prefix="pixelflasher-support-db-verify-") as directory:
            path = Path(directory) / "verified.sqlite3"
            path.write_bytes(payload)
            connection = sqlite3.connect(path)
            try:
                connection.execute("PRAGMA query_only = ON")
                tables = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                    )
                }
                if not tables.issubset(_SQLITE_TABLES):
                    raise SupportV2Error(
                        "support_database_verification_failed",
                        "sanitized support database contains a non-allow-listed table",
                    )
                checked_rows = 0
                for table in sorted(tables):
                    allowed = {name for name, _kind in _SQLITE_TABLES[table]}
                    columns = tuple(
                        str(row[1]) for row in connection.execute(f'PRAGMA table_info("{table}")')
                    )
                    if not columns or not set(columns).issubset(allowed):
                        raise SupportV2Error(
                            "support_database_verification_failed",
                            "sanitized support database contains a non-allow-listed column",
                        )
                    columns_sql = ", ".join(f'"{column}"' for column in columns)
                    for row in connection.execute(f'SELECT {columns_sql} FROM "{table}"'):
                        checked_rows += 1
                        if checked_rows > self.limits.max_database_rows:
                            raise SupportV2Error(
                                "support_database_verification_failed",
                                "sanitized support database exceeds its row limit",
                            )
                        for column, value in zip(columns, row, strict=True):
                            if _PATH_KEY.search(column) and value not in (None, "<path-redacted>"):
                                raise SupportV2Error(
                                    "support_redaction_verification_failed",
                                    "sanitized support database contains an exposed path",
                                )
                            if isinstance(value, str) and not redactor.verify_text(value):
                                raise SupportV2Error(
                                    "support_redaction_verification_failed",
                                    "sanitized support database failed redaction verification",
                                )
            finally:
                connection.close()

    def _archive(
        self,
        entries: tuple[_PreparedEntry, ...],
        omissions: tuple[SupportPackageOmission, ...],
        application_version: str,
        created_utc: str,
        cancellation_check: Callable[[], bool] | None,
    ) -> tuple[bytes, str]:
        included = [
            {
                "entry": entry.archive_name,
                "category": entry.category,
                "mediaType": entry.media_type,
                "bytes": len(entry.payload),
                "sha256": hashlib.sha256(entry.payload).hexdigest(),
                "redacted": True,
                "truncated": entry.truncated,
                "redactionProofSha256": entry.proof,
            }
            for entry in entries
        ]
        overall_proof = hashlib.sha256(
            _canonical_json(
                [
                    {
                        "entry": item["entry"],
                        "sha256": item["sha256"],
                        "redactionProofSha256": item["redactionProofSha256"],
                    }
                    for item in included
                ]
            )
        ).hexdigest()
        manifest = {
            "schemaVersion": SUPPORT_V2_SCHEMA,
            "format": SUPPORT_V2_FORMAT,
            "createdUtc": created_utc,
            "applicationVersion": application_version,
            "redaction": {
                "policyId": SUPPORT_V2_REDACTION_POLICY,
                "mandatory": True,
                "verified": True,
                "proofSha256": overall_proof,
            },
            "included": included,
            "omitted": [item.to_dict() for item in omissions],
            "manifestEntry": "manifest.json",
        }
        manifest_bytes = _canonical_json(manifest)
        if len(manifest_bytes) > self.limits.max_manifest_bytes:
            raise SupportV2Error("support_manifest_size_limit", "support manifest exceeds its size limit")
        buffer = io.BytesIO()
        with zipfile.ZipFile(
            buffer,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=True,
        ) as archive:
            for entry in entries:
                self._check_cancelled(cancellation_check)
                self._zip_write(archive, entry.archive_name, entry.payload)
            self._check_cancelled(cancellation_check)
            self._zip_write(archive, "manifest.json", manifest_bytes)
        payload = buffer.getvalue()
        if len(payload) > self.limits.max_archive_bytes:
            raise SupportV2Error("support_archive_size_limit", "support archive exceeds its size limit")
        with zipfile.ZipFile(io.BytesIO(payload), "r") as verified:
            expected = {entry.archive_name for entry in entries} | {"manifest.json"}
            if len(verified.infolist()) != len(expected) or set(verified.namelist()) != expected:
                raise SupportV2Error(
                    "support_archive_verification_failed",
                    "support archive entries changed during creation",
                )
            if verified.testzip() is not None:
                raise SupportV2Error(
                    "support_archive_verification_failed",
                    "support archive failed integrity verification",
                )
        return payload, hashlib.sha256(manifest_bytes).hexdigest()

    @staticmethod
    def _zip_write(archive: zipfile.ZipFile, name: str, payload: bytes) -> None:
        info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.create_system = 0
        info.external_attr = 0o600 << 16
        archive.writestr(info, payload)

    def _encrypt(self, plaintext: bytes, manifest_sha256: str) -> bytes:
        key = AESGCM.generate_key(bit_length=256)
        nonce = secrets.token_bytes(12)
        try:
            wrapped = self.public_key.encrypt(
                key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except ValueError as error:
            raise SupportV2Error(
                "support_key_wrap_failed",
                "support content key could not be wrapped",
            ) from error
        envelope = {
            "format": SUPPORT_V2_FORMAT,
            "schemaVersion": SUPPORT_V2_SCHEMA,
            "keyId": self.key_id,
            "keyWrapAlgorithm": "RSA-OAEP-SHA256",
            "contentEncryption": "AES-256-GCM",
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "wrappedKey": base64.b64encode(wrapped).decode("ascii"),
            "plaintextBytes": len(plaintext),
            "ciphertextBytes": len(plaintext) + 16,
            "manifestSha256": manifest_sha256,
        }
        header = _canonical_json(envelope)
        if len(header) > self.limits.max_manifest_bytes:
            raise SupportV2Error("support_envelope_size_limit", "support envelope exceeds its size limit")
        aad = SUPPORT_V2_MAGIC + header
        try:
            ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        except (OverflowError, ValueError) as error:
            raise SupportV2Error(
                "support_encryption_failed",
                "support archive could not be encrypted",
            ) from error
        container = SUPPORT_V2_MAGIC + struct.pack(">I", len(header)) + header + ciphertext
        if len(container) > self.limits.max_container_bytes:
            raise SupportV2Error("support_container_size_limit", "support container exceeds its size limit")
        return container

    @staticmethod
    def _omissions(
        values: Sequence[SupportPackageOmission],
        redactor: _Redactor,
    ) -> tuple[SupportPackageOmission, ...]:
        try:
            omission_count = len(values)
        except TypeError as error:
            raise SupportV2Error(
                "support_omission_invalid",
                "support omissions must be a bounded sequence",
            ) from error
        if omission_count > 256:
            raise SupportV2Error("support_omission_count_limit", "too many support omissions were supplied")
        safe: list[SupportPackageOmission] = []
        for value in values:
            if not isinstance(value, SupportPackageOmission):
                raise SupportV2Error("support_omission_invalid", "support omission is invalid")
            source = redactor.text(_safe_text(value.source, "omission source", 128))
            category = redactor.text(_safe_text(value.category, "omission category", 64))
            reason = redactor.text(_safe_text(value.reason, "omission reason", 128))
            if not all(redactor.verify_text(item) for item in (source, category, reason)):
                raise SupportV2Error(
                    "support_redaction_verification_failed",
                    "support omission failed mandatory redaction verification",
                )
            safe.append(SupportPackageOmission(source, category, reason))
        return tuple(safe)

    @staticmethod
    def _destination(
        destination: str | os.PathLike[str],
        *,
        allow_overwrite: bool,
    ) -> Path:
        try:
            raw = Path(destination)
        except (TypeError, ValueError) as error:
            raise SupportV2Error("support_destination_invalid", "support destination is invalid") from error
        if not raw.is_absolute() or ".." in raw.parts or raw.suffix.casefold() not in {".zip", ".pfsupport"}:
            raise SupportV2Error(
                "support_destination_invalid",
                "support destination must be an absolute .zip or .pfsupport path",
            )
        if len(raw.name) > 180 or any(ord(character) < 0x20 for character in raw.name):
            raise SupportV2Error("support_destination_invalid", "support destination name is invalid")
        try:
            parent = raw.parent.resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as error:
            raise SupportV2Error("support_destination_invalid", "support destination parent is invalid") from error
        target = parent / raw.name
        if os.path.lexists(target):
            if target.is_symlink() or not target.is_file():
                raise SupportV2Error("support_destination_invalid", "support destination is not a regular file")
            if not allow_overwrite:
                raise SupportV2Error("support_destination_exists", "support destination already exists")
        return target

    def _write_atomic(
        self,
        target: Path,
        payload: bytes,
        *,
        allow_overwrite: bool,
        cancellation_check: Callable[[], bool] | None,
    ) -> None:
        self._check_cancelled(cancellation_check)
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{target.name}.",
                suffix=".tmp",
                dir=target.parent,
            )
        except OSError as error:
            raise SupportV2Error(
                "support_write_failed",
                "support package temporary file could not be created",
            ) from error
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            self._check_cancelled(cancellation_check)
            if os.path.lexists(target):
                if target.is_symlink() or not target.is_file():
                    raise SupportV2Error(
                        "support_destination_invalid",
                        "support destination changed before commit",
                    )
                if not allow_overwrite:
                    raise SupportV2Error("support_destination_exists", "support destination already exists")
            if allow_overwrite:
                os.replace(temporary, target)
            else:
                try:
                    os.link(temporary, target, follow_symlinks=False)
                except FileExistsError as error:
                    raise SupportV2Error(
                        "support_destination_exists",
                        "support destination appeared before commit",
                    ) from error
                temporary.unlink()
            self._fsync_directory(target.parent)
        except SupportV2Error:
            temporary.unlink(missing_ok=True)
            raise
        except OSError as error:
            temporary.unlink(missing_ok=True)
            raise SupportV2Error(
                "support_write_failed",
                "support package could not be atomically committed",
            ) from error

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
    def _check_cancelled(cancellation_check: Callable[[], bool] | None) -> None:
        if cancellation_check is not None and cancellation_check():
            raise SupportV2Error(
                "support_package_cancelled",
                "support package creation was cancelled",
            )


class SupportPackageReader:
    """Read bounded v2 packages and the two existing v1 representations."""

    def __init__(
        self,
        recipient_private_key: bytes | rsa.RSAPrivateKey | None = None,
        *,
        limits: SupportV2Limits | None = None,
    ) -> None:
        self.private_key = _load_private_key(recipient_private_key)
        if limits is not None and not isinstance(limits, SupportV2Limits):
            raise TypeError("limits must be SupportV2Limits")
        self.limits = limits or SupportV2Limits()

    def read(
        self,
        source: bytes | str | os.PathLike[str],
        *,
        sensitive_values: Iterable[str] = (),
    ) -> SupportPackageReadResult:
        document = self._document(source)
        redactor = _Redactor(sensitive_values, self.limits.max_sensitive_values)
        if document.startswith(SUPPORT_V2_MAGIC):
            return self._read_v2(document, redactor)
        if document.startswith(b"PK"):
            return self._read_v1_outer(document, redactor)
        raise SupportV2Error("support_format_unknown", "support package format is not recognized")

    def _document(self, source: bytes | str | os.PathLike[str]) -> bytes:
        if isinstance(source, bytes):
            document = source
        else:
            try:
                path = Path(source).expanduser()
            except (TypeError, ValueError) as error:
                raise SupportV2Error("support_source_invalid", "support package source is invalid") from error
            if not path.is_absolute() or not os.path.lexists(path) or path.is_symlink() or not path.is_file():
                raise SupportV2Error("support_source_invalid", "support package source must be a regular file")
            try:
                with path.open("rb") as stream:
                    document = stream.read(self.limits.max_container_bytes + 1)
            except OSError as error:
                raise SupportV2Error("support_source_read_failed", "support package cannot be read") from error
        if not document or len(document) > self.limits.max_container_bytes:
            raise SupportV2Error("support_container_size_limit", "support package exceeds its size limit")
        return document

    def _read_v2(self, document: bytes, redactor: _Redactor) -> SupportPackageReadResult:
        if self.private_key is None:
            raise SupportV2Error(
                "support_private_key_required",
                "an RSA private key is required to read a v2 support package",
            )
        prefix = len(SUPPORT_V2_MAGIC)
        if len(document) < prefix + 4:
            raise SupportV2Error("support_envelope_invalid", "support v2 envelope is truncated")
        header_size = struct.unpack(">I", document[prefix : prefix + 4])[0]
        if header_size <= 0 or header_size > self.limits.max_manifest_bytes:
            raise SupportV2Error("support_envelope_size_limit", "support v2 envelope header is invalid")
        header_start = prefix + 4
        header_end = header_start + header_size
        if header_end > len(document):
            raise SupportV2Error("support_envelope_invalid", "support v2 envelope is truncated")
        header_bytes = document[header_start:header_end]
        raw_value = _parse_json(header_bytes, "support_envelope_invalid")
        if not isinstance(raw_value, dict):
            raise SupportV2Error("support_envelope_invalid", "support v2 envelope fields are invalid")
        raw = cast(dict[str, object], raw_value)
        if set(raw) != _ENVELOPE_FIELDS:
            raise SupportV2Error("support_envelope_invalid", "support v2 envelope fields are invalid")
        if raw.get("format") != SUPPORT_V2_FORMAT or raw.get("schemaVersion") != SUPPORT_V2_SCHEMA:
            raise SupportV2Error("support_schema_unsupported", "support package schema is unsupported")
        key_id = _safe_text(raw.get("keyId"), "key ID", 64)
        if not _KEY_ID.fullmatch(key_id):
            raise SupportV2Error("support_envelope_invalid", "support key ID is invalid")
        if raw.get("keyWrapAlgorithm") != "RSA-OAEP-SHA256" or raw.get("contentEncryption") != "AES-256-GCM":
            raise SupportV2Error("support_algorithm_unsupported", "support encryption algorithm is unsupported")
        nonce = _b64decode(raw.get("nonce"), "nonce", 64)
        wrapped = _b64decode(raw.get("wrappedKey"), "wrapped key", 2048)
        if len(nonce) != 12 or len(wrapped) != self.private_key.key_size // 8:
            raise SupportV2Error("support_envelope_invalid", "support encryption parameters are invalid")
        plaintext_bytes = raw.get("plaintextBytes")
        ciphertext_bytes = raw.get("ciphertextBytes")
        if (
            isinstance(plaintext_bytes, bool)
            or not isinstance(plaintext_bytes, int)
            or plaintext_bytes <= 0
            or plaintext_bytes > self.limits.max_archive_bytes
            or isinstance(ciphertext_bytes, bool)
            or not isinstance(ciphertext_bytes, int)
            or ciphertext_bytes != plaintext_bytes + 16
        ):
            raise SupportV2Error("support_envelope_invalid", "support encrypted sizes are invalid")
        ciphertext = document[header_end:]
        if len(ciphertext) != ciphertext_bytes:
            raise SupportV2Error("support_envelope_invalid", "support encrypted payload size is invalid")
        manifest_digest = raw.get("manifestSha256")
        if not isinstance(manifest_digest, str) or not _SHA256.fullmatch(manifest_digest):
            raise SupportV2Error("support_envelope_invalid", "support manifest digest is invalid")
        try:
            key = self.private_key.decrypt(
                wrapped,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except ValueError as error:
            raise SupportV2Error("support_key_unwrap_failed", "support content key could not be unwrapped") from error
        if len(key) != 32:
            raise SupportV2Error("support_key_unwrap_failed", "support content key has an invalid size")
        try:
            plaintext = AESGCM(key).decrypt(
                nonce,
                ciphertext,
                SUPPORT_V2_MAGIC + header_bytes,
            )
        except (InvalidTag, ValueError) as error:
            raise SupportV2Error(
                "support_authentication_failed",
                "support package authentication failed",
            ) from error
        if len(plaintext) != plaintext_bytes:
            raise SupportV2Error("support_envelope_invalid", "support plaintext size is invalid")
        return self._read_v2_archive(plaintext, manifest_digest, key_id, redactor)

    def _read_v2_archive(
        self,
        document: bytes,
        expected_manifest_sha256: str,
        key_id: str,
        redactor: _Redactor,
    ) -> SupportPackageReadResult:
        try:
            archive = zipfile.ZipFile(io.BytesIO(document), "r")
        except (OSError, zipfile.BadZipFile) as error:
            raise SupportV2Error("support_archive_invalid", "support payload is not a valid ZIP") from error
        with archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(infos) > self.limits.max_entries + 1 or len(names) != len(set(names)):
                raise SupportV2Error("support_entry_count_limit", "support archive entry count is invalid")
            if "manifest.json" not in names:
                raise SupportV2Error("support_manifest_missing", "support manifest is missing")
            manifest_bytes = self._read_member(archive, "manifest.json", self.limits.max_manifest_bytes)
            actual_manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
            if not hmac.compare_digest(actual_manifest_digest, expected_manifest_sha256):
                raise SupportV2Error("support_manifest_hash_mismatch", "support manifest SHA-256 is invalid")
            manifest_value = _parse_json(manifest_bytes, "support_manifest_invalid")
            if not isinstance(manifest_value, dict):
                raise SupportV2Error("support_manifest_invalid", "support manifest fields are invalid")
            manifest = cast(dict[str, object], manifest_value)
            if set(manifest) != _MANIFEST_FIELDS:
                raise SupportV2Error("support_manifest_invalid", "support manifest fields are invalid")
            if manifest.get("schemaVersion") != SUPPORT_V2_SCHEMA or manifest.get("format") != SUPPORT_V2_FORMAT:
                raise SupportV2Error("support_schema_unsupported", "support manifest schema is unsupported")
            if manifest.get("manifestEntry") != "manifest.json":
                raise SupportV2Error("support_manifest_invalid", "support manifest entry is invalid")
            application_version = _safe_text(
                manifest.get("applicationVersion"), "application version", 128
            )
            _safe_text(manifest.get("createdUtc"), "creation time", 64)
            included_value = manifest.get("included")
            if not isinstance(included_value, list):
                raise SupportV2Error("support_manifest_invalid", "support included entries are invalid")
            included = cast(list[object], included_value)
            if len(included) > self.limits.max_entries:
                raise SupportV2Error("support_manifest_invalid", "support included entries are invalid")
            expected_names = {"manifest.json"}
            entries: list[SupportReadEntry] = []
            proof_items: list[dict[str, str]] = []
            total = 0
            for raw_item in included:
                if not isinstance(raw_item, dict):
                    raise SupportV2Error("support_manifest_invalid", "support entry manifest is invalid")
                item = cast(dict[str, object], raw_item)
                if set(item) != _MANIFEST_ENTRY_FIELDS:
                    raise SupportV2Error("support_manifest_invalid", "support entry manifest is invalid")
                name = _safe_text(item.get("entry"), "entry name", 200)
                category, media_type = _entry_policy(name)
                if item.get("category") != category or item.get("mediaType") != media_type:
                    raise SupportV2Error("support_entry_policy_mismatch", "support entry violates its policy")
                if item.get("redacted") is not True or not isinstance(item.get("truncated"), bool):
                    raise SupportV2Error(
                        "support_redaction_verification_failed",
                        "support entry does not declare mandatory redaction",
                    )
                size = item.get("bytes")
                digest = item.get("sha256")
                proof = item.get("redactionProofSha256")
                if (
                    isinstance(size, bool)
                    or not isinstance(size, int)
                    or size < 0
                    or not isinstance(digest, str)
                    or not _SHA256.fullmatch(digest)
                    or not isinstance(proof, str)
                    or not _SHA256.fullmatch(proof)
                ):
                    raise SupportV2Error("support_manifest_invalid", "support entry integrity fields are invalid")
                limit = self.limits.max_database_bytes if media_type == "application/vnd.sqlite3" else self.limits.max_entry_bytes
                if size > limit:
                    raise SupportV2Error("support_entry_size_limit", "support entry exceeds its size limit")
                if name in expected_names:
                    raise SupportV2Error("support_entry_duplicate", "support entry names must be unique")
                expected_names.add(name)
                payload = self._read_member(archive, name, limit)
                total += len(payload)
                if total > self.limits.max_total_entry_bytes or len(payload) != size:
                    raise SupportV2Error("support_total_size_limit", "support entry sizes are invalid")
                actual_digest = hashlib.sha256(payload).hexdigest()
                actual_proof = _redaction_proof(name, payload)
                if not hmac.compare_digest(actual_digest, digest) or not hmac.compare_digest(actual_proof, proof):
                    raise SupportV2Error("support_entry_hash_mismatch", "support entry SHA-256 is invalid")
                verified = self._verify_entry_payload(name, media_type, payload, redactor)
                if not verified:
                    raise SupportV2Error(
                        "support_redaction_verification_failed",
                        "support entry failed mandatory redaction verification",
                    )
                entries.append(SupportReadEntry(name, category, media_type, payload, digest, True))
                proof_items.append(
                    {"entry": name, "sha256": digest, "redactionProofSha256": proof}
                )
            if set(names) != expected_names:
                raise SupportV2Error("support_entry_not_allowed", "support archive contains an undeclared entry")
            redaction_value = manifest.get("redaction")
            if not isinstance(redaction_value, dict):
                raise SupportV2Error("support_manifest_invalid", "support redaction manifest is invalid")
            redaction = cast(dict[str, object], redaction_value)
            if set(redaction) != {
                "policyId", "mandatory", "verified", "proofSha256"
            }:
                raise SupportV2Error("support_manifest_invalid", "support redaction manifest is invalid")
            overall = hashlib.sha256(_canonical_json(proof_items)).hexdigest()
            if (
                redaction.get("policyId") != SUPPORT_V2_REDACTION_POLICY
                or redaction.get("mandatory") is not True
                or redaction.get("verified") is not True
                or not hmac.compare_digest(str(redaction.get("proofSha256", "")), overall)
            ):
                raise SupportV2Error(
                    "support_redaction_verification_failed",
                    "support redaction proof is invalid",
                )
            omissions = self._read_omissions(manifest.get("omitted"))
            return SupportPackageReadResult(
                SUPPORT_V2_SCHEMA,
                SUPPORT_V2_FORMAT,
                application_version,
                key_id,
                actual_manifest_digest,
                tuple(entries),
                omissions,
                True,
                False,
            )

    def _verify_entry_payload(
        self,
        name: str,
        media_type: str,
        payload: bytes,
        redactor: _Redactor,
    ) -> bool:
        if media_type == "application/vnd.sqlite3":
            writer_verifier = object.__new__(SupportPackageV2Writer)
            writer_verifier.limits = self.limits
            writer_verifier._verify_sqlite_payload(payload, redactor)
            return True
        try:
            text = payload.decode("utf-8", "strict")
        except UnicodeError:
            return False
        if not redactor.verify_text(text):
            return False
        if media_type == "application/json":
            value = _parse_json(payload, "support_json_invalid")
            return _canonical_json(value) == payload
        return b"\x00" not in payload

    def _read_v1_outer(
        self,
        document: bytes,
        redactor: _Redactor,
    ) -> SupportPackageReadResult:
        try:
            with zipfile.ZipFile(io.BytesIO(document), "r") as archive:
                infos = archive.infolist()
                names = [info.filename for info in infos]
                if len(names) != len(set(names)) or len(infos) > self.limits.max_entries + 1:
                    raise SupportV2Error("support_entry_count_limit", "support v1 entry count is invalid")
                if set(names) == {"support.pf", "pf.dat"}:
                    return self._read_legacy_encrypted(archive, redactor)
                return self._read_v1_manifest_archive(archive, redactor)
        except SupportV2Error:
            raise
        except (OSError, zipfile.BadZipFile) as error:
            raise SupportV2Error("support_archive_invalid", "support v1 archive is invalid") from error

    def _read_v1_manifest_archive(
        self,
        archive: zipfile.ZipFile,
        redactor: _Redactor,
    ) -> SupportPackageReadResult:
        names = set(archive.namelist())
        if "manifest.json" not in names:
            raise SupportV2Error("support_manifest_missing", "support v1 manifest is missing")
        manifest_bytes = self._read_member(archive, "manifest.json", self.limits.max_manifest_bytes)
        manifest_value = _parse_json(manifest_bytes, "support_manifest_invalid")
        if not isinstance(manifest_value, dict):
            raise SupportV2Error("support_schema_unsupported", "support v1 manifest is unsupported")
        manifest = cast(dict[str, object], manifest_value)
        if manifest.get("schemaVersion") != 1:
            raise SupportV2Error("support_schema_unsupported", "support v1 manifest is unsupported")
        included_value = manifest.get("included")
        if not isinstance(included_value, list):
            raise SupportV2Error("support_manifest_invalid", "support v1 entries are invalid")
        included = cast(list[object], included_value)
        if len(included) > self.limits.max_entries:
            raise SupportV2Error("support_manifest_invalid", "support v1 entries are invalid")
        expected = {"manifest.json"}
        entries: list[SupportReadEntry] = []
        total = 0
        all_redacted = manifest.get("redaction") == "mandatory"
        for raw_item in included:
            if not isinstance(raw_item, dict):
                raise SupportV2Error("support_manifest_invalid", "support v1 entry is invalid")
            item = cast(dict[str, object], raw_item)
            name = _safe_text(item.get("entry"), "entry name", 200)
            category, media_type = _entry_policy(name)
            if name in expected:
                raise SupportV2Error("support_entry_duplicate", "support v1 entries must be unique")
            expected.add(name)
            limit = self.limits.max_database_bytes if media_type == "application/vnd.sqlite3" else self.limits.max_entry_bytes
            payload = self._read_member(archive, name, limit)
            total += len(payload)
            if total > self.limits.max_total_entry_bytes:
                raise SupportV2Error("support_total_size_limit", "support v1 entries exceed their limit")
            digest = hashlib.sha256(payload).hexdigest()
            if item.get("bytes") != len(payload) or item.get("sha256") != digest:
                raise SupportV2Error("support_entry_hash_mismatch", "support v1 entry hash is invalid")
            verified = bool(item.get("redacted")) and self._verify_entry_payload(
                name, media_type, payload, redactor
            )
            all_redacted = all_redacted and verified
            entries.append(SupportReadEntry(name, category, media_type, payload, digest, verified))
        if names != expected:
            raise SupportV2Error("support_entry_not_allowed", "support v1 archive contains an undeclared entry")
        omissions = self._read_omissions(manifest.get("omitted", []))
        application_version = str(manifest.get("applicationVersion", "unknown"))[:128]
        return SupportPackageReadResult(
            1,
            str(manifest.get("format", "pixelflasher-redacted-support")),
            application_version,
            "",
            hashlib.sha256(manifest_bytes).hexdigest(),
            tuple(entries),
            omissions,
            all_redacted,
            False,
        )

    def _read_legacy_encrypted(
        self,
        archive: zipfile.ZipFile,
        redactor: _Redactor,
    ) -> SupportPackageReadResult:
        if self.private_key is None:
            raise SupportV2Error(
                "support_private_key_required",
                "an RSA private key is required to read an encrypted v1 support package",
            )
        wrapped = self._read_member(archive, "pf.dat", 1024)
        encrypted = self._read_member(archive, "support.pf", self.limits.max_container_bytes)
        try:
            fernet_key = self.private_key.decrypt(
                wrapped,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            plaintext = Fernet(fernet_key).decrypt(encrypted)
        except (ValueError, InvalidToken) as error:
            raise SupportV2Error(
                "support_v1_decryption_failed",
                "encrypted v1 support package could not be decrypted",
            ) from error
        if len(plaintext) > self.limits.max_archive_bytes:
            raise SupportV2Error("support_archive_size_limit", "support v1 archive exceeds its limit")
        try:
            inner = zipfile.ZipFile(io.BytesIO(plaintext), "r")
        except (OSError, zipfile.BadZipFile) as error:
            raise SupportV2Error("support_archive_invalid", "encrypted v1 payload is invalid") from error
        with inner:
            infos = [info for info in inner.infolist() if not info.is_dir()]
            if len(infos) > self.limits.max_entries or len({info.filename for info in infos}) != len(infos):
                raise SupportV2Error("support_entry_count_limit", "encrypted v1 entries exceed their limit")
            entries: list[SupportReadEntry] = []
            total = 0
            for info in infos:
                category, media_type = self._legacy_policy(info.filename)
                limit = self.limits.max_database_bytes if media_type == "application/vnd.sqlite3" else self.limits.max_entry_bytes
                payload = self._read_member(inner, info.filename, limit)
                total += len(payload)
                if total > self.limits.max_total_entry_bytes:
                    raise SupportV2Error("support_total_size_limit", "encrypted v1 entries exceed their limit")
                digest = hashlib.sha256(payload).hexdigest()
                verified = False
                if media_type != "application/vnd.sqlite3":
                    try:
                        verified = redactor.verify_text(payload.decode("utf-8", "strict"))
                    except UnicodeError:
                        verified = False
                entries.append(
                    SupportReadEntry(info.filename, category, media_type, payload, digest, verified)
                )
        return SupportPackageReadResult(
            1,
            "pixelflasher-legacy-fernet-support",
            "legacy",
            "",
            "",
            tuple(entries),
            (),
            all(item.redaction_verified for item in entries),
            True,
        )

    @staticmethod
    def _legacy_policy(name: str) -> tuple[str, str]:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or "\\" in name or len(path.parts) > 2:
            raise SupportV2Error("support_entry_not_allowed", "encrypted v1 entry path is unsafe")
        if name in {"PixelFlasher.json", "PixelFlasher_Custom.json", "labels.json"}:
            return "configuration", "application/json"
        if name == "PixelFlasher.db":
            return "database", "application/vnd.sqlite3"
        if name == "files.txt":
            return "legacy", "text/plain"
        if _LEGACY_LOG.fullmatch(name):
            category = "logs" if name.startswith("logs/") else "diagrams"
            return category, "application/json" if name.casefold().endswith(".json") else "text/plain"
        if len(path.parts) == 1 and _LEGACY_FILE.fullmatch(name) and name.casefold().endswith((".json", ".txt", ".log", ".puml")):
            return "legacy", "application/json" if name.casefold().endswith(".json") else "text/plain"
        raise SupportV2Error("support_entry_not_allowed", "encrypted v1 entry is not allow-listed")

    def _read_member(self, archive: zipfile.ZipFile, name: str, limit: int) -> bytes:
        try:
            info = archive.getinfo(name)
        except KeyError as error:
            raise SupportV2Error("support_entry_missing", "support archive entry is missing") from error
        if info.is_dir() or info.flag_bits & 0x1 or info.file_size > limit:
            raise SupportV2Error("support_entry_size_limit", "support archive entry is invalid or too large")
        chunks: list[bytes] = []
        total = 0
        try:
            with archive.open(info, "r") as stream:
                while True:
                    chunk = stream.read(min(1024 * 1024, limit + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise SupportV2Error(
                            "support_entry_size_limit",
                            "support archive entry exceeds its size limit",
                        )
                    chunks.append(chunk)
        except SupportV2Error:
            raise
        except (OSError, RuntimeError, zipfile.BadZipFile) as error:
            raise SupportV2Error("support_archive_invalid", "support archive entry cannot be read") from error
        payload = b"".join(chunks)
        if len(payload) != info.file_size:
            raise SupportV2Error("support_archive_invalid", "support archive entry size is inconsistent")
        return payload

    @staticmethod
    def _read_omissions(value: object) -> tuple[SupportPackageOmission, ...]:
        if not isinstance(value, list):
            raise SupportV2Error("support_manifest_invalid", "support omissions are invalid")
        values = cast(list[object], value)
        if len(values) > 256:
            raise SupportV2Error("support_manifest_invalid", "support omissions are invalid")
        omissions: list[SupportPackageOmission] = []
        for raw_item in values:
            if not isinstance(raw_item, dict):
                raise SupportV2Error("support_manifest_invalid", "support omission is invalid")
            item = cast(dict[str, object], raw_item)
            if set(item) != {"source", "category", "reason"}:
                raise SupportV2Error("support_manifest_invalid", "support omission is invalid")
            omissions.append(
                SupportPackageOmission(
                    _safe_text(item.get("source"), "omission source", 128),
                    _safe_text(item.get("category"), "omission category", 64),
                    _safe_text(item.get("reason"), "omission reason", 128),
                )
            )
        return tuple(omissions)


__all__ = [
    "SUPPORT_V2_FORMAT",
    "SUPPORT_V2_MAGIC",
    "SUPPORT_V2_REDACTION_POLICY",
    "SUPPORT_V2_SCHEMA",
    "SupportEntryMedia",
    "SupportPackageOmission",
    "SupportPackageReadResult",
    "SupportPackageReader",
    "SupportPackageV2Writer",
    "SupportReadEntry",
    "SupportSourceEntry",
    "SupportV2Error",
    "SupportV2Limits",
    "SupportV2WriteResult",
]
