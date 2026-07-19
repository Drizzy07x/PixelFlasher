"""Backend-compatible collection service for encrypted support packages.

The browser supplies only an opaque, one-use ``destinationId``.  This service
collects a closed set of local diagnostics and delegates mandatory redaction,
SQLite reconstruction, hashing and encryption to :mod:`support_v2`.
"""

from __future__ import annotations

import json
import os
import platform
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol, cast

from cryptography.hazmat.primitives.asymmetric import rsa

from .support import (
    SUPPORT_PAYLOAD_FIELDS,
    SupportDestinationRegistry,
    SupportPackageError,
    SupportPackageLimits,
    SupportPackageResult,
    SupportPackageStatus,
)
from .support_v2 import (
    SUPPORT_V2_SCHEMA,
    SupportEntryMedia,
    SupportPackageOmission,
    SupportPackageV2Writer,
    SupportSourceEntry,
    SupportV2Error,
    SupportV2Limits,
)

_ALLOWED_LOG_SUFFIXES = frozenset({".json", ".log", ".txt"})
_ALLOWED_DIAGRAM_SUFFIXES = frozenset({".puml"})
_MAX_OMISSIONS = 256


class CancellationProbe(Protocol):
    @property
    def cancelled(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class SupportPackageV2Result(SupportPackageResult):
    """Existing support result contract plus non-sensitive v2 metadata."""

    schema_version: int = SUPPORT_V2_SCHEMA
    key_id: str = ""

    def to_dict(self) -> dict[str, object]:
        result = SupportPackageResult.to_dict(self)
        result["schemaVersion"] = self.schema_version
        result["keyId"] = self.key_id
        return result


class UnavailableSupportPackageV2Service:
    """Fail closed when no production support-package recipient is configured."""

    error_code = "support_encryption_key_missing"
    error_message = (
        "support package encryption requires an injected recipient public key and key id"
    )

    def register_destination(
        self,
        destination: str | os.PathLike[str],
        *,
        allow_overwrite: bool = False,
    ) -> str:
        del destination
        if not isinstance(allow_overwrite, bool):
            raise SupportPackageError(
                "support_destination_invalid",
                "support overwrite authorization must be a boolean",
            )
        raise SupportPackageError(self.error_code, self.error_message)

    def create(
        self,
        payload: Mapping[str, Any],
        *,
        snapshot: object,
        cancellation: CancellationProbe | None = None,
    ) -> SupportPackageResult:
        del payload, snapshot, cancellation
        return SupportPackageV2Result(
            SupportPackageStatus.FAILED,
            self.error_code,
            self.error_message,
        )

    def shutdown(self) -> None:
        """No resources exist when encryption is unavailable."""


class SupportPackageV2Service:
    """Collect bounded diagnostics and write exclusively encrypted v2 packages."""

    def __init__(
        self,
        config_path: str | os.PathLike[str],
        recipient_public_key: bytes | rsa.RSAPublicKey,
        *,
        key_id: str,
        destination_registry: SupportDestinationRegistry | None = None,
        app_version: str = "unknown",
        collection_limits: SupportPackageLimits | None = None,
        package_limits: SupportV2Limits | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if collection_limits is not None and not isinstance(collection_limits, SupportPackageLimits):
            raise TypeError("collection_limits must be SupportPackageLimits")
        if package_limits is not None and not isinstance(package_limits, SupportV2Limits):
            raise TypeError("package_limits must be SupportV2Limits")
        self.config_path = Path(config_path).expanduser().resolve()
        self.config_root = self.config_path.parent
        self.destination_registry = destination_registry or SupportDestinationRegistry()
        self.app_version = str(app_version or "unknown")
        self.collection_limits = collection_limits or SupportPackageLimits()
        self.writer = SupportPackageV2Writer(
            recipient_public_key,
            key_id=key_id,
            limits=package_limits,
            clock=clock,
        )
        self.key_id = self.writer.key_id

    def register_destination(
        self,
        destination: str | os.PathLike[str],
        *,
        allow_overwrite: bool = False,
    ) -> str:
        if not isinstance(allow_overwrite, bool):
            raise SupportPackageError(
                "support_destination_invalid",
                "support overwrite authorization must be a boolean",
            )
        return self.destination_registry.grant(
            destination,
            allow_overwrite=allow_overwrite,
        )

    def create(
        self,
        payload: Mapping[str, Any],
        *,
        snapshot: object,
        cancellation: CancellationProbe | None = None,
    ) -> SupportPackageResult:
        try:
            options = self._options(payload)
            self._check_cancelled(cancellation)
            grant = self.destination_registry.consume(payload.get("destinationId"))
            self._check_cancelled(cancellation)
            entries, omissions = self._collect_entries(options, snapshot, cancellation)
            sensitive_values = self._snapshot_serials(snapshot)
            cancellation_check = self._cancellation_check(cancellation)
            try:
                written = self.writer.write(
                    grant.path,
                    entries,
                    application_version=self.app_version,
                    sensitive_values=sensitive_values,
                    omissions=omissions,
                    allow_overwrite=grant.allow_overwrite,
                    cancellation_check=cancellation_check,
                )
            except SupportV2Error as error:
                if not error.code.startswith("support_database_"):
                    raise
                database_free = tuple(
                    entry for entry in entries if entry.media_type is not SupportEntryMedia.SQLITE
                )
                safe_omissions = self._append_omission(
                    omissions,
                    SupportPackageOmission("legacy-database", "database", error.code),
                )
                self._check_cancelled(cancellation)
                written = self.writer.write(
                    grant.path,
                    database_free,
                    application_version=self.app_version,
                    sensitive_values=sensitive_values,
                    omissions=safe_omissions,
                    allow_overwrite=grant.allow_overwrite,
                    cancellation_check=cancellation_check,
                )
                omissions = safe_omissions
            return SupportPackageV2Result(
                SupportPackageStatus.SUCCESS,
                "support_package_created",
                "Encrypted and redacted support package created.",
                file_name=grant.path.name,
                sha256=written.sha256,
                size=written.size,
                included_count=written.included_count,
                omitted_count=len(omissions),
                schema_version=written.schema_version,
                key_id=written.key_id,
            )
        except (SupportPackageError, SupportV2Error) as error:
            status = (
                SupportPackageStatus.CANCELLED
                if error.code == "support_package_cancelled"
                else SupportPackageStatus.FAILED
            )
            return SupportPackageV2Result(
                status,
                error.code,
                str(error),
                schema_version=SUPPORT_V2_SCHEMA,
                key_id=self.key_id,
            )
        except Exception:
            return SupportPackageV2Result(
                SupportPackageStatus.FAILED,
                "support_package_failed",
                "Support package creation failed.",
                schema_version=SUPPORT_V2_SCHEMA,
                key_id=self.key_id,
            )

    def shutdown(self) -> None:
        self.destination_registry.shutdown()

    @staticmethod
    def _options(payload: Mapping[str, Any]) -> dict[str, bool]:
        if not isinstance(payload, Mapping):
            raise SupportPackageError(
                "invalid_support_payload",
                "support payload must be an object",
            )
        unknown = set(payload) - SUPPORT_PAYLOAD_FIELDS
        if unknown:
            raise SupportPackageError(
                "invalid_support_payload",
                f"unsupported support option: {sorted(str(item) for item in unknown)[0]}",
            )
        destination_id = payload.get("destinationId")
        if not isinstance(destination_id, str) or not destination_id:
            raise SupportPackageError(
                "support_destination_not_granted",
                "destinationId is required",
            )
        options: dict[str, bool] = {}
        for key in ("includeConfig", "includeLogs", "includeState", "includeSystemInfo"):
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
        cancellation: CancellationProbe | None,
    ) -> tuple[tuple[SupportSourceEntry, ...], tuple[SupportPackageOmission, ...]]:
        entries: list[SupportSourceEntry] = []
        omissions: list[SupportPackageOmission] = []
        estimated_total = 0
        total_limit = min(
            self.collection_limits.max_total_bytes,
            self.writer.limits.max_total_entry_bytes,
        )

        def omit(source: str, category: str, reason: str) -> None:
            if len(omissions) < _MAX_OMISSIONS - 1:
                omissions.append(SupportPackageOmission(source, category, reason))
            elif len(omissions) == _MAX_OMISSIONS - 1:
                omissions.append(
                    SupportPackageOmission(
                        "additional-sources",
                        "collection",
                        "omission_count_limit",
                    )
                )

        def add(entry: SupportSourceEntry, estimated_size: int) -> bool:
            nonlocal estimated_total
            if len(entries) >= self.writer.limits.max_entries:
                omit(entry.logical_source, entry.category, "entry_count_limit")
                return False
            entry_limit = (
                self.writer.limits.max_database_bytes
                if entry.media_type is SupportEntryMedia.SQLITE
                else self.writer.limits.max_entry_bytes
            )
            if estimated_size > entry_limit:
                omit(entry.logical_source, entry.category, "size_limit")
                return False
            if estimated_total + estimated_size > total_limit:
                omit(entry.logical_source, entry.category, "total_size_limit")
                return False
            entries.append(entry)
            estimated_total += estimated_size
            return True

        if options["includeConfig"]:
            for path, name, source in (
                (self.config_path, "config/PixelFlasher.json", "active-configuration"),
                (self.config_root / "labels.json", "config/labels.json", "labels"),
            ):
                self._check_cancelled(cancellation)
                entry, reason, size = self._json_file_entry(path, name, source)
                if entry is None:
                    omit(source, "configuration", reason)
                else:
                    add(entry, size)
        else:
            omit("configuration", "configuration", "not_selected")

        if options["includeState"]:
            self._check_cancelled(cancellation)
            state = self._support_snapshot(snapshot)
            size = self._json_size(state)
            if size > min(
                self.collection_limits.max_config_bytes,
                self.writer.limits.max_entry_bytes,
            ):
                omit("canonical-state", "state", "size_limit")
            else:
                add(
                    SupportSourceEntry.json(
                        "state/app_snapshot.json",
                        "state",
                        state,
                        logical_source="canonical-state",
                    ),
                    size,
                )
        else:
            omit("canonical-state", "state", "not_selected")

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
                "executable": sys.executable,
            }
            size = self._json_size(system_info)
            add(
                SupportSourceEntry.json(
                    "system/system_info.json",
                    "system",
                    system_info,
                    logical_source="system-information",
                ),
                size,
            )
        else:
            omit("system-information", "system", "not_selected")

        if options["includeLogs"]:
            log_entries, log_omissions = self._log_entries(cancellation)
            for entry, size in log_entries:
                add(entry, size)
            for omission in log_omissions:
                omit(omission.source, omission.category, omission.reason)
        else:
            omit("runtime-logs", "logs", "not_selected")

        database = self.config_root / "PixelFlasher.db"
        self._check_cancelled(cancellation)
        if not database.exists():
            omit("legacy-database", "database", "not_found")
        elif database.is_symlink() or not database.is_file() or not self._confined(database):
            omit("legacy-database", "database", "unsafe_source")
        else:
            try:
                database_size = database.stat().st_size
            except OSError:
                omit("legacy-database", "database", "read_failed")
            else:
                if database_size > self.writer.limits.max_database_source_bytes:
                    omit("legacy-database", "database", "size_limit")
                else:
                    add(SupportSourceEntry.sqlite(database), 0)

        return tuple(entries), tuple(omissions)

    def _json_file_entry(
        self,
        path: Path,
        archive_name: str,
        logical_source: str,
    ) -> tuple[SupportSourceEntry | None, str, int]:
        if not path.exists():
            return None, "not_found", 0
        if path.is_symlink() or not path.is_file() or not self._confined(path):
            return None, "unsafe_source", 0
        read_limit = min(
            self.collection_limits.max_config_bytes,
            self.writer.limits.max_entry_bytes,
        )
        try:
            with path.open("rb") as stream:
                raw = stream.read(read_limit + 1)
        except OSError:
            return None, "read_failed", 0
        if len(raw) > read_limit:
            return None, "size_limit", 0
        try:
            text = raw.decode("utf-8-sig", "strict")
            value = json.loads(text, object_pairs_hook=self._reject_duplicate_json)
        except (UnicodeError, ValueError, RecursionError, SupportPackageError):
            return None, "invalid_json", 0
        return (
            SupportSourceEntry.json(
                archive_name,
                "configuration",
                value,
                logical_source=logical_source,
            ),
            "",
            len(raw),
        )

    def _log_entries(
        self,
        cancellation: CancellationProbe | None,
    ) -> tuple[
        list[tuple[SupportSourceEntry, int]],
        list[SupportPackageOmission],
    ]:
        candidates: list[tuple[str, Path]] = []
        omissions: list[SupportPackageOmission] = []
        scan_limit = self.collection_limits.max_log_files * 8
        scanned = 0
        roots = (
            ("logs", self.config_root / "logs", _ALLOWED_LOG_SUFFIXES),
            ("diagrams", self.config_root / "puml", _ALLOWED_DIAGRAM_SUFFIXES),
        )
        for category, root, suffixes in roots:
            self._check_cancelled(cancellation)
            if not root.exists():
                omissions.append(SupportPackageOmission(category, category, "not_found"))
                continue
            if root.is_symlink() or not root.is_dir() or not self._confined(root):
                omissions.append(SupportPackageOmission(category, category, "unsafe_source_root"))
                continue
            resolved = root.resolve()
            for current, directories, files in os.walk(resolved, followlinks=False):
                self._check_cancelled(cancellation)
                current_path = Path(current)
                depth = len(current_path.relative_to(resolved).parts)
                directories[:] = [
                    name
                    for name in sorted(directories)
                    if depth < self.collection_limits.max_log_depth
                    and not (current_path / name).is_symlink()
                ]
                for filename in sorted(files):
                    scanned += 1
                    logical = f"{category}-source-{scanned:03d}"
                    if scanned > scan_limit:
                        omissions.append(
                            SupportPackageOmission("remaining-sources", category, "scan_limit")
                        )
                        directories[:] = []
                        break
                    source = current_path / filename
                    if source.suffix.casefold() not in suffixes:
                        omissions.append(
                            SupportPackageOmission(logical, category, "file_type_not_allowed")
                        )
                        continue
                    if source.is_symlink() or not source.is_file() or not self._confined(source):
                        omissions.append(
                            SupportPackageOmission(logical, category, "unsafe_source")
                        )
                        continue
                    candidates.append((category, source))
                if scanned > scan_limit:
                    break

        entries: list[tuple[SupportSourceEntry, int]] = []
        log_index = 0
        diagram_index = 0
        log_byte_limit = min(
            self.collection_limits.max_log_bytes,
            self.writer.limits.max_entry_bytes,
        )
        for source_index, (category, source) in enumerate(candidates, start=1):
            self._check_cancelled(cancellation)
            logical = f"{category}-source-{source_index:03d}"
            if len(entries) >= self.collection_limits.max_log_files:
                omissions.append(SupportPackageOmission(logical, category, "file_count_limit"))
                continue
            try:
                with source.open("rb") as stream:
                    raw = stream.read(log_byte_limit + 1)
            except OSError:
                omissions.append(SupportPackageOmission(logical, category, "read_failed"))
                continue
            if b"\x00" in raw[:8192]:
                omissions.append(SupportPackageOmission(logical, category, "binary_not_allowed"))
                continue
            truncated = len(raw) > log_byte_limit
            raw = raw[:log_byte_limit]
            text = raw.decode("utf-8", "replace")
            if truncated:
                text += "\n[truncated by PixelFlasher support package limits]\n"
            if category == "diagrams":
                diagram_index += 1
                entry = SupportSourceEntry.text(
                    f"diagrams/trace_{diagram_index:03d}.puml",
                    "diagrams",
                    text,
                    logical_source=logical,
                    truncated=truncated,
                )
            else:
                log_index += 1
                parsed: object = text
                is_json = False
                if source.suffix.casefold() == ".json":
                    try:
                        parsed = json.loads(text, object_pairs_hook=self._reject_duplicate_json)
                        is_json = True
                    except (ValueError, RecursionError, SupportPackageError):
                        parsed = text
                if is_json:
                    entry = SupportSourceEntry.json(
                        f"logs/log_{log_index:03d}.json",
                        "logs",
                        parsed,
                        logical_source=logical,
                        truncated=truncated,
                    )
                else:
                    entry = SupportSourceEntry.text(
                        f"logs/log_{log_index:03d}.txt",
                        "logs",
                        str(parsed),
                        logical_source=logical,
                        truncated=truncated,
                    )
            entries.append((entry, len(text.encode("utf-8"))))
        return entries, omissions

    @staticmethod
    def _support_snapshot(snapshot: object) -> dict[str, object]:
        converter = getattr(snapshot, "to_dict", None)
        raw_value: object = converter() if callable(converter) else {}
        if not isinstance(raw_value, Mapping):
            return {}
        raw = cast(Mapping[str, object], raw_value)
        projected: dict[str, object] = {
            key: raw.get(key)
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
            )
        }
        devices = projected.get("devices")
        if isinstance(devices, list):
            projected["devices"] = devices[:64]
        serials = projected.get("selected_serials")
        if isinstance(serials, list):
            projected["selected_serials"] = serials[:64]
        last_result = raw.get("last_result")
        if isinstance(last_result, Mapping):
            last_result_mapping = cast(Mapping[str, object], last_result)
            projected["last_result"] = {
                key: last_result_mapping.get(key)
                for key in ("operation_id", "status", "code", "message", "exit_code")
            }
        else:
            projected["last_result"] = None
        return projected

    @staticmethod
    def _snapshot_serials(snapshot: object) -> tuple[str, ...]:
        values: list[str] = []
        serials = cast(object, getattr(snapshot, "selected_serials", ()))
        if isinstance(serials, (tuple, list)):
            serial_values = cast(tuple[object, ...] | list[object], serials)
            values.extend(item for item in serial_values if isinstance(item, str) and item)
        devices = cast(object, getattr(snapshot, "devices", ()))
        if isinstance(devices, (tuple, list)):
            device_values = cast(tuple[object, ...] | list[object], devices)
            values.extend(
                serial
                for device in device_values
                for serial in (getattr(device, "serial", ""),)
                if isinstance(serial, str) and serial
            )
        return tuple(dict.fromkeys(values))

    def _confined(self, path: Path) -> bool:
        try:
            path.resolve(strict=True).relative_to(self.config_root.resolve(strict=False))
            return True
        except (OSError, RuntimeError, ValueError):
            return False

    @staticmethod
    def _json_size(value: object) -> int:
        try:
            return len(
                json.dumps(
                    value,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
        except (TypeError, ValueError, UnicodeError, RecursionError) as error:
            raise SupportPackageError(
                "support_state_invalid",
                "support diagnostic state is not serializable",
            ) from error

    @staticmethod
    def _reject_duplicate_json(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise SupportPackageError(
                    "support_json_duplicate_field",
                    "support JSON contains a duplicate field",
                )
            result[key] = value
        return result

    @staticmethod
    def _append_omission(
        omissions: tuple[SupportPackageOmission, ...],
        omission: SupportPackageOmission,
    ) -> tuple[SupportPackageOmission, ...]:
        if len(omissions) < _MAX_OMISSIONS:
            return (*omissions, omission)
        return (*omissions[:-1], omission)

    @staticmethod
    def _cancellation_check(
        cancellation: CancellationProbe | None,
    ) -> Callable[[], bool]:
        return lambda: cancellation is not None and cancellation.cancelled

    @staticmethod
    def _check_cancelled(cancellation: CancellationProbe | None) -> None:
        if cancellation is not None and cancellation.cancelled:
            raise SupportPackageError(
                "support_package_cancelled",
                "support package creation was cancelled",
            )


__all__ = [
    "SupportPackageV2Result",
    "SupportPackageV2Service",
    "UnavailableSupportPackageV2Service",
]
