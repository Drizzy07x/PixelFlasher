"""Redacted, atomic support-package creation for the headless core.

The WebView never supplies an output path.  A native host first grants one
canonical destination and receives a short-lived opaque identifier.  The
``support.create`` command can consume that identifier exactly once.

Only the explicitly enumerated text sources below are considered.  Legacy
database capture, recursive directory listings, and the encrypted legacy
wrapper intentionally remain out of this service until they can be migrated
without weakening redaction or path confinement.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import secrets
import socket
import sys
import tempfile
import threading
import time
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol, cast

from .path_compat import is_reserved_path

SUPPORT_COMMAND = "support.create"
SUPPORT_PAYLOAD_FIELDS = frozenset(
    {
        "destinationId",
        "includeConfig",
        "includeLogs",
        "includeState",
        "includeSystemInfo",
    }
)

_DESTINATION_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_SAFE_ZIP_NAME_PATTERN = re.compile(r"^[^\\/\x00-\x1f\x7f]{1,160}\.zip$", re.IGNORECASE)
_ALLOWED_LOG_SUFFIXES = frozenset({".json", ".log", ".puml", ".txt"})
_SECRET_KEY_PATTERN = re.compile(
    r"(?:access|api|auth|private|refresh|session)[_-]?key|"
    r"(?:access|api|auth|bearer|refresh|session)?[_-]?token|"
    r"cookie|credential|pass(?:word|wd)?|secret|superkey",
    re.IGNORECASE,
)
_SERIAL_KEY_PATTERN = re.compile(
    r"(?:selected[_-]?)?serial(?:s|no|number)?|device[_-]?id|device",
    re.IGNORECASE,
)
_PII_KEY_PATTERN = re.compile(
    r"e[-_]?mail|host(?:name)?|computer[_-]?name|owner|user(?:name)?",
    re.IGNORECASE,
)
_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?key|auth(?:orization)?|bearer|cookie|"
    r"credential|password|passwd|refresh[_-]?token|secret|session[_-]?token|"
    r"superkey|token)([\"']?)(\s*[:=]\s*)(?:Bearer\s+)?"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?"
    r"-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
    re.DOTALL,
)
_EMAIL_PATTERN = re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])")
_MAC_PATTERN = re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
_IPV4_PATTERN = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"
)
_IPV6_PATTERN = re.compile(
    r"(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])"
)
_WINDOWS_USER_PATH_PATTERN = re.compile(r"(?i)(\b[A-Z]:\\Users\\)[^\\/\s\"']+")
_UNIX_USER_PATH_PATTERN = re.compile(r"(?i)(/(?:Users|home)/)[^/\s\"']+")
_ADB_DEVICE_LINE_PATTERN = re.compile(
    r"(?im)^(\s*)(\S+)(\s+(?:device|offline|unauthorized|recovery|sideload)\b)"
)
_ADB_SERIAL_ARG_PATTERN = re.compile(r"(?i)(\b(?:adb|fastboot)\b[^\r\n]*?\s-s\s+)(\S+)")
_SERIAL_FIELD_PATTERN = re.compile(
    r"(?i)(\b(?:device[_-]?id|serial(?:no|number)?|serial)\b\s*[:=]\s*)([^\s,;]+)"
)


class CancellationProbe(Protocol):
    @property
    def cancelled(self) -> bool: ...


class SupportPackageError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class SupportPackageStatus(StrEnum):
    SUCCESS = "success"
    CANCELLED = "cancelled"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class SupportPackageLimits:
    max_config_bytes: int = 1_000_000
    max_log_bytes: int = 600_000
    max_log_files: int = 48
    max_total_bytes: int = 8_000_000
    max_log_depth: int = 3

    def __post_init__(self) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
            for value in (
                self.max_config_bytes,
                self.max_log_bytes,
                self.max_log_files,
                self.max_total_bytes,
                self.max_log_depth,
            )
        ):
            raise ValueError("support package limits must be positive integers")


@dataclass(frozen=True, slots=True)
class SupportDestinationGrant:
    token: str
    path: Path
    allow_overwrite: bool
    expires_at: float


class SupportDestinationRegistry:
    """Hold short-lived, one-use destinations selected by the native host."""

    def __init__(self, *, lifetime_seconds: float = 600.0) -> None:
        if lifetime_seconds <= 0:
            raise ValueError("destination lifetime must be positive")
        self._lifetime_seconds = float(lifetime_seconds)
        self._grants: dict[str, SupportDestinationGrant] = {}
        self._lock = threading.RLock()
        self._closed = False

    def grant(
        self,
        destination: str | os.PathLike[str],
        *,
        allow_overwrite: bool = False,
    ) -> str:
        path = self._canonical_destination(destination)
        if os.path.lexists(path):
            if path.is_symlink() or not path.is_file():
                raise SupportPackageError(
                    "support_destination_invalid",
                    "support destination cannot be a symlink or directory",
                )
            if not allow_overwrite:
                raise SupportPackageError(
                    "support_destination_exists",
                    "support destination already exists",
                )
        token = secrets.token_urlsafe(32)
        grant = SupportDestinationGrant(
            token,
            path,
            bool(allow_overwrite),
            time.monotonic() + self._lifetime_seconds,
        )
        with self._lock:
            if self._closed:
                raise SupportPackageError(
                    "support_destination_registry_closed",
                    "support destination registry is closed",
                )
            self._purge_expired_locked()
            self._grants[token] = grant
        return token

    def consume(self, token: object) -> SupportDestinationGrant:
        if not isinstance(token, str) or not _DESTINATION_ID_PATTERN.fullmatch(token):
            raise SupportPackageError(
                "support_destination_not_granted",
                "a valid native destination grant is required",
            )
        with self._lock:
            self._purge_expired_locked()
            grant = self._grants.pop(token, None)
        if grant is None:
            raise SupportPackageError(
                "support_destination_not_granted",
                "support destination grant is unknown, expired, or already used",
            )
        return grant

    def revoke(self, token: str) -> bool:
        with self._lock:
            return self._grants.pop(token, None) is not None

    def shutdown(self) -> None:
        with self._lock:
            self._closed = True
            self._grants.clear()

    def _purge_expired_locked(self) -> None:
        now = time.monotonic()
        expired = [token for token, grant in self._grants.items() if grant.expires_at <= now]
        for token in expired:
            self._grants.pop(token, None)

    @staticmethod
    def _canonical_destination(destination: str | os.PathLike[str]) -> Path:
        try:
            raw = Path(destination)
        except (TypeError, ValueError) as error:
            raise SupportPackageError(
                "support_destination_invalid",
                "support destination is invalid",
            ) from error
        if not raw.is_absolute() or ".." in raw.parts:
            raise SupportPackageError(
                "support_destination_invalid",
                "support destination must be an absolute path without traversal",
            )
        if not _SAFE_ZIP_NAME_PATTERN.fullmatch(raw.name) or is_reserved_path(raw):
            raise SupportPackageError(
                "support_destination_invalid",
                "support destination must use a safe .zip file name",
            )
        try:
            parent = raw.parent.resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as error:
            raise SupportPackageError(
                "support_destination_invalid",
                "support destination parent does not exist",
            ) from error
        if not parent.is_dir() or not os.access(parent, os.W_OK):
            raise SupportPackageError(
                "support_destination_invalid",
                "support destination parent is not writable",
            )
        return parent / raw.name


@dataclass(frozen=True, slots=True)
class SupportPackageResult:
    status: SupportPackageStatus
    code: str
    message: str
    file_name: str = ""
    sha256: str = ""
    size: int = 0
    included_count: int = 0
    omitted_count: int = 0

    @property
    def ok(self) -> bool:
        return self.status is SupportPackageStatus.SUCCESS

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "code": self.code,
            "message": self.message,
            "fileName": self.file_name,
            "sha256": self.sha256,
            "size": self.size,
            "includedCount": self.included_count,
            "omittedCount": self.omitted_count,
        }


@dataclass(frozen=True, slots=True)
class _Entry:
    archive_name: str
    category: str
    logical_source: str
    payload: bytes
    truncated: bool = False


class _Redactor:
    def __init__(self, serials: tuple[str, ...]) -> None:
        home = str(Path.home())
        user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
        host = socket.gethostname()
        self._literal_replacements = tuple(
            (value, replacement)
            for value, replacement in (
                (home, "<home>"),
                (user if len(user) >= 3 else "", "<user>"),
                (host if len(host) >= 3 else "", "<host>"),
            )
            if value
        )
        self._serial_patterns = tuple(
            re.compile(re.escape(serial), re.IGNORECASE)
            for serial in dict.fromkeys(serials)
            if serial
        )

    def text(self, value: str) -> str:
        redacted = value
        redacted = _PRIVATE_KEY_PATTERN.sub("<private-key-redacted>", redacted)
        redacted = _SECRET_ASSIGNMENT_PATTERN.sub(
            lambda match: f"{match.group(1)}{match.group(2)}{match.group(3)}<redacted>",
            redacted,
        )
        for needle, replacement in self._literal_replacements:
            redacted = re.sub(re.escape(needle), replacement, redacted, flags=re.IGNORECASE)
        for pattern in self._serial_patterns:
            redacted = pattern.sub("<serial-redacted>", redacted)
        redacted = _WINDOWS_USER_PATH_PATTERN.sub(r"\1<user>", redacted)
        redacted = _UNIX_USER_PATH_PATTERN.sub(r"\1<user>", redacted)
        redacted = _ADB_DEVICE_LINE_PATTERN.sub(r"\1<serial-redacted>\3", redacted)
        redacted = _ADB_SERIAL_ARG_PATTERN.sub(r"\1<serial-redacted>", redacted)
        redacted = _SERIAL_FIELD_PATTERN.sub(r"\1<serial-redacted>", redacted)
        redacted = _EMAIL_PATTERN.sub("<email-redacted>", redacted)
        redacted = _MAC_PATTERN.sub("<mac-redacted>", redacted)
        redacted = _IPV4_PATTERN.sub("<ip-redacted>", redacted)
        redacted = _IPV6_PATTERN.sub("<ip-redacted>", redacted)
        return redacted

    def json_value(self, value: object, *, key: str = "", depth: int = 0) -> object:
        if depth > 40:
            return "<depth-redacted>"
        if key and _SECRET_KEY_PATTERN.fullmatch(key.strip()):
            return "<redacted>"
        if key and _SERIAL_KEY_PATTERN.fullmatch(key.strip()):
            return "<serial-redacted>"
        if key and _PII_KEY_PATTERN.fullmatch(key.strip()):
            return "<pii-redacted>"
        if isinstance(value, Mapping):
            items = cast(Mapping[object, object], value)
            return {
                str(item_key): self.json_value(
                    item,
                    key=str(item_key),
                    depth=depth + 1,
                )
                for item_key, item in items.items()
            }
        if isinstance(value, (list, tuple)):
            items = cast(Sequence[object], value)
            return [self.json_value(item, depth=depth + 1) for item in items]
        if isinstance(value, str):
            return self.text(value)
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return self.text(str(value))


class SupportPackageService:
    """Create one mandatory-redacted ZIP from bounded, allow-listed sources."""

    def __init__(
        self,
        config_path: str | os.PathLike[str],
        destination_registry: SupportDestinationRegistry | None = None,
        *,
        app_version: str = "unknown",
        limits: SupportPackageLimits | None = None,
    ) -> None:
        self.config_path = Path(config_path).expanduser().resolve()
        self.config_root = self.config_path.parent
        self.destination_registry = destination_registry or SupportDestinationRegistry()
        self.app_version = str(app_version or "unknown")
        self.limits = limits or SupportPackageLimits()

    def register_destination(
        self,
        destination: str | os.PathLike[str],
        *,
        allow_overwrite: bool = False,
    ) -> str:
        return self.destination_registry.grant(
            destination,
            allow_overwrite=allow_overwrite,
        )

    def create(
        self,
        payload: Mapping[str, object],
        *,
        snapshot: object,
        cancellation: CancellationProbe | None = None,
    ) -> SupportPackageResult:
        try:
            options = self._options(payload)
            self._check_cancelled(cancellation)
            grant = self.destination_registry.consume(payload.get("destinationId"))
            self._check_cancelled(cancellation)
            if os.path.lexists(grant.path):
                if grant.path.is_symlink() or not grant.path.is_file():
                    raise SupportPackageError(
                        "support_destination_invalid",
                        "support destination changed after native selection",
                    )
                if not grant.allow_overwrite:
                    raise SupportPackageError(
                        "support_destination_exists",
                        "support destination already exists",
                    )
            serials = self._snapshot_serials(snapshot)
            redactor = _Redactor(serials)
            entries, omitted = self._collect_entries(
                options,
                snapshot,
                redactor,
                cancellation,
            )
            digest, size = self._write_atomic_archive(
                grant,
                options,
                entries,
                omitted,
                cancellation,
            )
            return SupportPackageResult(
                SupportPackageStatus.SUCCESS,
                "support_package_created",
                "Redacted support package created.",
                file_name=grant.path.name,
                sha256=digest,
                size=size,
                included_count=len(entries) + 1,
                omitted_count=len(omitted),
            )
        except SupportPackageError as error:
            if error.code == "support_package_cancelled":
                return SupportPackageResult(
                    SupportPackageStatus.CANCELLED,
                    error.code,
                    str(error),
                )
            return SupportPackageResult(
                SupportPackageStatus.FAILED,
                error.code,
                str(error),
            )
        except Exception:
            return SupportPackageResult(
                SupportPackageStatus.FAILED,
                "support_package_failed",
                "Support package creation failed.",
            )

    def shutdown(self) -> None:
        self.destination_registry.shutdown()

    @staticmethod
    def _options(payload: Mapping[str, object]) -> dict[str, bool]:
        unknown = set(payload) - SUPPORT_PAYLOAD_FIELDS
        if unknown:
            raise SupportPackageError(
                "invalid_support_payload",
                f"unsupported support option: {sorted(unknown)[0]}",
            )
        destination_id = payload.get("destinationId")
        if not isinstance(destination_id, str) or not destination_id:
            raise SupportPackageError(
                "support_destination_not_granted",
                "destinationId is required",
            )
        options: dict[str, bool] = {}
        for key in (
            "includeConfig",
            "includeLogs",
            "includeState",
            "includeSystemInfo",
        ):
            value = payload.get(key, True)
            if not isinstance(value, bool):
                raise SupportPackageError(
                    "invalid_support_payload",
                    f"{key} must be a boolean",
                )
            options[key] = value
        if not any(options.values()):
            raise SupportPackageError(
                "invalid_support_payload",
                "at least one support category must be selected",
            )
        return options

    def _collect_entries(
        self,
        options: Mapping[str, bool],
        snapshot: object,
        redactor: _Redactor,
        cancellation: CancellationProbe | None,
    ) -> tuple[list[_Entry], list[dict[str, str]]]:
        entries: list[_Entry] = []
        omitted: list[dict[str, str]] = []
        total = 0

        def add(entry: _Entry) -> None:
            nonlocal total
            if total + len(entry.payload) > self.limits.max_total_bytes:
                omitted.append(
                    self._omitted(entry.logical_source, entry.category, "total_size_limit")
                )
                return
            entries.append(entry)
            total += len(entry.payload)

        if options["includeConfig"]:
            entry, reason = self._json_entry(
                self.config_path,
                "config/PixelFlasher.json",
                "configuration",
                "active-configuration",
                redactor,
                cancellation,
            )
            if entry is not None:
                add(entry)
            else:
                omitted.append(self._omitted("active-configuration", "configuration", reason))
            labels = self.config_root / "labels.json"
            entry, reason = self._json_entry(
                labels,
                "config/labels.json",
                "configuration",
                "labels",
                redactor,
                cancellation,
            )
            if entry is not None:
                add(entry)
            else:
                omitted.append(self._omitted("labels", "configuration", reason))
        else:
            omitted.append(self._omitted("configuration", "configuration", "not_selected"))

        if options["includeState"]:
            self._check_cancelled(cancellation)
            raw_state = self._support_snapshot(snapshot)
            safe_state = redactor.json_value(raw_state)
            payload = self._json_bytes(safe_state)
            if len(payload) <= self.limits.max_config_bytes:
                add(_Entry("state/app_snapshot.json", "state", "canonical-state", payload))
            else:
                omitted.append(self._omitted("canonical-state", "state", "size_limit"))
        else:
            omitted.append(self._omitted("canonical-state", "state", "not_selected"))

        if options["includeSystemInfo"]:
            self._check_cancelled(cancellation)
            system_info = {
                "application": "PixelFlasher",
                "version": self.app_version,
                "python": platform.python_version(),
                "platform": platform.platform(),
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "executable": redactor.text(sys.executable),
            }
            add(
                _Entry(
                    "system/system_info.json",
                    "system",
                    "system-information",
                    self._json_bytes(system_info),
                )
            )
        else:
            omitted.append(self._omitted("system-information", "system", "not_selected"))

        if options["includeLogs"]:
            log_entries, log_omissions = self._log_entries(redactor, cancellation)
            for entry in log_entries:
                add(entry)
            omitted.extend(log_omissions)
        else:
            omitted.append(self._omitted("runtime-logs", "logs", "not_selected"))

        # These useful legacy sources are deliberately named in the manifest so
        # a support package can never imply parity that the modern service lacks.
        omitted.extend(
            (
                self._omitted("legacy-database", "legacy", "not_safely_migrated"),
                self._omitted("recursive-file-listing", "legacy", "pii_risk_not_included"),
                self._omitted("legacy-encrypted-wrapper", "legacy", "not_migrated"),
            )
        )
        return entries, omitted

    def _json_entry(
        self,
        path: Path,
        archive_name: str,
        category: str,
        logical_source: str,
        redactor: _Redactor,
        cancellation: CancellationProbe | None,
    ) -> tuple[_Entry | None, str]:
        if not path.exists():
            return None, "not_found"
        if path.is_symlink() or not path.is_file():
            return None, "non_regular_file"
        if not self._confined(path):
            return None, "outside_config_root"
        self._check_cancelled(cancellation)
        try:
            raw = path.read_bytes()
        except OSError:
            return None, "read_failed"
        if len(raw) > self.limits.max_config_bytes:
            return None, "size_limit"
        text = raw.decode("utf-8-sig", errors="replace")
        try:
            value = json.loads(text)
        except (ValueError, RecursionError):
            safe = redactor.text(text).encode("utf-8")
        else:
            safe = self._json_bytes(redactor.json_value(value))
        self._check_cancelled(cancellation)
        return _Entry(archive_name, category, logical_source, safe), ""

    def _log_entries(
        self,
        redactor: _Redactor,
        cancellation: CancellationProbe | None,
    ) -> tuple[list[_Entry], list[dict[str, str]]]:
        candidates: list[tuple[str, Path]] = []
        omitted: list[dict[str, str]] = []
        scanned = 0
        scanned_directories = 0
        scan_limit = self.limits.max_log_files * 8
        scan_limited = False
        roots = (("logs", self.config_root / "logs"), ("diagrams", self.config_root / "puml"))
        for label, root in roots:
            if scan_limited:
                omitted.append(self._omitted(label, "logs", "scan_limit"))
                continue
            if not root.exists():
                omitted.append(self._omitted(label, "logs", "not_found"))
                continue
            if root.is_symlink() or not root.is_dir() or not self._confined(root):
                omitted.append(self._omitted(label, "logs", "unsafe_source_root"))
                continue
            root_resolved = root.resolve()
            for current, directories, files in os.walk(root_resolved, followlinks=False):
                self._check_cancelled(cancellation)
                current_path = Path(current)
                depth = len(current_path.relative_to(root_resolved).parts)
                safe_directories: list[str] = []
                for directory in sorted(directories):
                    scanned_directories += 1
                    logical_directory = f"{label}-directory-{scanned_directories:03d}"
                    if (current_path / directory).is_symlink():
                        omitted.append(
                            self._omitted(logical_directory, "logs", "symlink_not_allowed")
                        )
                    elif depth >= self.limits.max_log_depth:
                        omitted.append(
                            self._omitted(logical_directory, "logs", "depth_limit")
                        )
                    else:
                        safe_directories.append(directory)
                directories[:] = safe_directories
                for filename in sorted(files):
                    scanned += 1
                    if scanned > scan_limit:
                        omitted.append(self._omitted("remaining-log-sources", "logs", "scan_limit"))
                        directories[:] = []
                        scan_limited = True
                        break
                    source = current_path / filename
                    logical = f"{label}-{len(candidates) + 1:03d}"
                    if source.suffix.casefold() not in _ALLOWED_LOG_SUFFIXES:
                        omitted.append(self._omitted(logical, "logs", "file_type_not_allowed"))
                        continue
                    if source.is_symlink() or not source.is_file() or not self._confined(source):
                        omitted.append(self._omitted(logical, "logs", "non_regular_file"))
                        continue
                    candidates.append((logical, source))
                if scan_limited:
                    break

        entries: list[_Entry] = []
        for index, (logical, source) in enumerate(candidates, start=1):
            if len(entries) >= self.limits.max_log_files:
                omitted.append(self._omitted(logical, "logs", "file_count_limit"))
                continue
            self._check_cancelled(cancellation)
            if source.is_symlink() or not source.is_file() or not self._confined(source):
                omitted.append(self._omitted(logical, "logs", "source_changed"))
                continue
            try:
                with source.open("rb") as stream:
                    raw = stream.read(self.limits.max_log_bytes + 1)
            except OSError:
                omitted.append(self._omitted(logical, "logs", "read_failed"))
                continue
            if b"\x00" in raw[:8192]:
                omitted.append(self._omitted(logical, "logs", "binary_not_allowed"))
                continue
            truncated = len(raw) > self.limits.max_log_bytes
            raw = raw[: self.limits.max_log_bytes]
            decoded = raw.decode("utf-8", errors="replace")
            if source.suffix.casefold() == ".json":
                try:
                    parsed = json.loads(decoded)
                except (ValueError, RecursionError):
                    text = redactor.text(decoded)
                else:
                    text = self._json_bytes(redactor.json_value(parsed)).decode("utf-8")
            else:
                text = redactor.text(decoded)
            if truncated:
                text += "\n[truncated by PixelFlasher support package limits]\n"
            suffix = ".json" if source.suffix.casefold() == ".json" else ".txt"
            entries.append(
                _Entry(
                    f"logs/log_{index:03d}{suffix}",
                    "logs",
                    logical,
                    text.encode("utf-8"),
                    truncated,
                )
            )
        return entries, omitted

    def _write_atomic_archive(
        self,
        grant: SupportDestinationGrant,
        options: Mapping[str, bool],
        entries: list[_Entry],
        omitted: list[dict[str, str]],
        cancellation: CancellationProbe | None,
    ) -> tuple[str, int]:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{grant.path.name}.",
            suffix=".tmp",
            dir=grant.path.parent,
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            manifest_entries: list[dict[str, object]] = []
            with zipfile.ZipFile(
                temporary,
                "w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
                strict_timestamps=True,
            ) as archive:
                for entry in entries:
                    self._check_cancelled(cancellation)
                    archive.writestr(entry.archive_name, entry.payload)
                    manifest_entries.append(
                        {
                            "entry": entry.archive_name,
                            "category": entry.category,
                            "source": entry.logical_source,
                            "bytes": len(entry.payload),
                            "sha256": hashlib.sha256(entry.payload).hexdigest(),
                            "redacted": True,
                            "truncated": entry.truncated,
                        }
                    )
                manifest = {
                    "schemaVersion": 1,
                    "format": "pixelflasher-redacted-support",
                    "createdUtc": datetime.now(UTC).isoformat(),
                    "applicationVersion": self.app_version,
                    "redaction": "mandatory",
                    "options": dict(options),
                    "included": manifest_entries,
                    "omitted": omitted,
                    "manifestEntry": "manifest.json",
                }
                self._check_cancelled(cancellation)
                archive.writestr("manifest.json", self._json_bytes(manifest))
            self._check_cancelled(cancellation)
            expected_names = {entry.archive_name for entry in entries} | {"manifest.json"}
            with zipfile.ZipFile(temporary, "r") as verified_archive:
                if set(verified_archive.namelist()) != expected_names:
                    raise SupportPackageError(
                        "support_archive_verification_failed",
                        "support archive entries changed during creation",
                    )
                corrupt_entry = verified_archive.testzip()
                if corrupt_entry is not None:
                    raise SupportPackageError(
                        "support_archive_verification_failed",
                        "support archive failed integrity verification",
                    )
            # Windows requires a writable descriptor for ``fsync`` even though
            # the archive contents are already complete.
            with temporary.open("r+b") as stream:
                os.fsync(stream.fileno())
            if os.path.lexists(grant.path):
                if grant.path.is_symlink() or not grant.path.is_file():
                    raise SupportPackageError(
                        "support_destination_invalid",
                        "support destination changed before atomic commit",
                    )
                if not grant.allow_overwrite:
                    raise SupportPackageError(
                        "support_destination_exists",
                        "support destination already exists",
                    )
            self._check_cancelled(cancellation)
            digest = self._sha256(temporary)
            size = temporary.stat().st_size
            os.replace(temporary, grant.path)
            self._fsync_directory(grant.path.parent)
            return digest, size
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    def _confined(self, path: Path) -> bool:
        try:
            path.resolve(strict=True).relative_to(self.config_root.resolve(strict=False))
            return True
        except (OSError, RuntimeError, ValueError):
            return False

    @staticmethod
    def _support_snapshot(snapshot: object) -> dict[str, object]:
        """Project canonical state onto bounded support-safe diagnostic fields."""

        converter = getattr(snapshot, "to_dict", None)
        raw_value: object = converter() if callable(converter) else {}
        if not isinstance(raw_value, Mapping):
            return {}
        raw = cast(Mapping[object, object], raw_value)
        projected: dict[str, object] = {}
        for key in (
            "revision",
            "devices",
            "selected_serials",
            "selected_serial",
            "firmware",
            "boot",
            "plan",
            "toolchain",
            "active_operation",
        ):
            projected[key] = raw.get(key)
        devices = projected.get("devices")
        if isinstance(devices, list):
            projected["devices"] = cast(list[object], devices)[:64]
        serials = projected.get("selected_serials")
        if isinstance(serials, list):
            projected["selected_serials"] = cast(list[object], serials)[:64]
        last_result_value = raw.get("last_result")
        if isinstance(last_result_value, Mapping):
            last_result = cast(Mapping[object, object], last_result_value)
            projected["last_result"] = {
                key: last_result.get(key)
                for key in ("operation_id", "status", "code", "message", "exit_code")
            }
        else:
            projected["last_result"] = None
        return projected

    @staticmethod
    def _snapshot_serials(snapshot: object) -> tuple[str, ...]:
        values: list[str] = []
        serials_value: object = getattr(snapshot, "selected_serials", ())
        if isinstance(serials_value, (tuple, list)):
            serials = cast(Sequence[object], serials_value)
            values.extend(item for item in serials if isinstance(item, str) and item)
        devices_value: object = getattr(snapshot, "devices", ())
        if isinstance(devices_value, (tuple, list)):
            devices = cast(Sequence[object], devices_value)
            values.extend(
                serial
                for device in devices
                for serial in (getattr(device, "serial", None),)
                if isinstance(serial, str) and serial
            )
        return tuple(dict.fromkeys(values))

    @staticmethod
    def _json_bytes(value: object) -> bytes:
        return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )

    @staticmethod
    def _omitted(source: str, category: str, reason: str) -> dict[str, str]:
        return {"source": source, "category": category, "reason": reason}

    @staticmethod
    def _check_cancelled(cancellation: CancellationProbe | None) -> None:
        if cancellation is not None and cancellation.cancelled:
            raise SupportPackageError(
                "support_package_cancelled",
                "support package creation was cancelled",
            )

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        if os.name == "nt":
            return
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


__all__ = [
    "SUPPORT_COMMAND",
    "SUPPORT_PAYLOAD_FIELDS",
    "SupportDestinationGrant",
    "SupportDestinationRegistry",
    "SupportPackageError",
    "SupportPackageLimits",
    "SupportPackageResult",
    "SupportPackageService",
    "SupportPackageStatus",
]
