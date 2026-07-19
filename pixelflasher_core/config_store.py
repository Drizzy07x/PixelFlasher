"""Durable schema-v2 JSON configuration with 9.x compatibility mirrors."""

from __future__ import annotations

import json
import math
import os
import shutil
import tempfile
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import cast

from .contracts import JSONValue, SensitiveText

CURRENT_SCHEMA_VERSION = 2
SCHEMA_KEY = "_pixelflasher_core_schema"
MODERN_KEY = "modern"
MAX_CONFIG_BYTES = 16 * 1024 * 1024


class ConfigError(RuntimeError):
    """Stable configuration failure with explicit recovery semantics."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "config_error",
        recoverable: bool = True,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.recoverable = recoverable


def _empty_values() -> Mapping[str, object]:
    return {}


def _config_json(value: object) -> JSONValue:
    if isinstance(value, SensitiveText):
        raise ConfigError(
            "secrets cannot be persisted in configuration",
            code="config_secret_forbidden",
            recoverable=False,
        )
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ConfigError(
                "configuration numbers must be finite",
                code="config_number_invalid",
                recoverable=False,
            )
        return value
    if isinstance(value, Mapping):
        mapping = cast(Mapping[object, object], value)
        if any(not isinstance(key, str) for key in mapping):
            raise ConfigError(
                "configuration object keys must be strings",
                code="config_key_invalid",
                recoverable=False,
            )
        return {
            key: _config_json(item)
            for key, item in mapping.items()
            if isinstance(key, str)
        }
    if isinstance(value, (tuple, list)):
        sequence = cast(tuple[object, ...] | list[object], value)
        return [_config_json(item) for item in sequence]
    raise ConfigError(
        "configuration values must contain only JSON data",
        code="config_value_invalid",
        recoverable=False,
    )


@dataclass(frozen=True, slots=True)
class ConfigDocument:
    schema_version: int = CURRENT_SCHEMA_VERSION
    values: Mapping[str, object] = field(default_factory=_empty_values)
    modern_extras: Mapping[str, object] = field(default_factory=_empty_values)

    def __post_init__(self) -> None:
        if self.schema_version != CURRENT_SCHEMA_VERSION:
            raise ConfigError(
                f"unsupported configuration schema {self.schema_version}; "
                f"expected {CURRENT_SCHEMA_VERSION}",
                code="config_schema_unsupported",
                recoverable=False,
            )
        if any(not isinstance(key, str) for key in self.values):
            raise ConfigError(
                "configuration keys must be strings",
                code="config_key_invalid",
                recoverable=False,
            )
        reserved = set(self.values) & {SCHEMA_KEY, MODERN_KEY}
        if reserved:
            raise ConfigError(
                f"configuration value uses reserved key {min(reserved)}",
                code="config_reserved_key",
                recoverable=False,
            )
        if any(not isinstance(key, str) for key in self.modern_extras):
            raise ConfigError(
                "modern namespace keys must be strings",
                code="config_key_invalid",
                recoverable=False,
            )
        if any(key.startswith("_pixelflasher_") for key in self.modern_extras):
            raise ConfigError(
                "canonical modern keys cannot be stored as namespace extras",
                code="config_modern_key_conflict",
                recoverable=False,
            )
        # Validate eagerly so a document cannot enter the runtime and fail only
        # during shutdown persistence.
        _config_json(self.values)
        _config_json(self.modern_extras)
        object.__setattr__(self, "values", MappingProxyType(dict(self.values)))
        object.__setattr__(
            self,
            "modern_extras",
            MappingProxyType(dict(self.modern_extras)),
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result = {
            key: _config_json(value)
            for key, value in self.values.items()
        }
        modern = {
            key: _config_json(value)
            for key, value in self.modern_extras.items()
        }
        modern.update(
            {
                key: _config_json(value)
                for key, value in self.values.items()
                if key.startswith("_pixelflasher_")
            }
        )
        # Schema 2 makes modern state canonical under one namespace while
        # retaining flat mirrors for the complete 10.x compatibility cycle.
        result[MODERN_KEY] = modern
        result[SCHEMA_KEY] = self.schema_version
        return result

    def with_values(self, **updates: object) -> ConfigDocument:
        values = dict(self.values)
        values.update(updates)
        return ConfigDocument(
            values=values,
            modern_extras=self.modern_extras,
        )


@dataclass(frozen=True, slots=True)
class _DecodedConfig:
    document: ConfigDocument
    source_version: int


class ConfigStore:
    """Migrate, recover, and atomically persist one configuration document."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self.backup_path = self.path.with_name(f"{self.path.name}.bak")
        self.migration_backup_path = self.path.with_name(
            f"{self.path.name}.v9.bak"
        )
        self.corrupt_backup_path = self.path.with_name(
            f"{self.path.name}.corrupt.bak"
        )
        self._lock = threading.RLock()

    def load(self) -> ConfigDocument:
        with self._lock:
            if not self.path.exists():
                if not (
                    self.backup_path.exists()
                    or self.migration_backup_path.exists()
                ):
                    return ConfigDocument()
                decoded = self._recover_from_backup(
                    ConfigError(
                        "configuration is missing",
                        code="config_missing",
                    )
                )
            else:
                try:
                    decoded = self._load_candidate(self.path)
                except ConfigError as error:
                    if not error.recoverable:
                        raise
                    decoded = self._recover_from_backup(error)

            if decoded.source_version < CURRENT_SCHEMA_VERSION:
                self._migrate_legacy(decoded.document)
            return decoded.document

    def save(self, document: ConfigDocument) -> None:
        if not isinstance(document, ConfigDocument):
            raise TypeError("document must be a ConfigDocument")
        with self._lock:
            existing_values: dict[str, object] = {}
            existing_extras: dict[str, object] = {}
            if self.path.exists():
                existing = self._load_candidate(self.path)
                if existing.source_version < CURRENT_SCHEMA_VERSION:
                    self._migrate_legacy(existing.document)
                existing_values.update(existing.document.values)
                existing_extras.update(existing.document.modern_extras)
            # ConfigStore is deliberately lossless for keys it does not own.
            # Callers update values with nulls; absence is never interpreted as
            # permission to erase an unknown 9.x or future field.
            existing_values.update(document.values)
            existing_extras.update(document.modern_extras)
            payload = ConfigDocument(
                values=existing_values,
                modern_extras=existing_extras,
            ).to_dict()
            self._write_payload(payload, backup_existing=True)

    def _load_candidate(self, path: Path) -> _DecodedConfig:
        try:
            raw = self._read_json(path)
        except ConfigError:
            raise
        except OSError as error:
            raise ConfigError(
                f"could not read configuration: {error}",
                code="config_read_failed",
            ) from error
        return self._decode_document(raw)

    def _decode_document(self, raw: object) -> _DecodedConfig:
        if not isinstance(raw, dict):
            raise ConfigError(
                "configuration root must be a JSON object",
                code="config_root_invalid",
            )
        raw_mapping = cast(dict[object, object], raw)
        if any(not isinstance(key, str) for key in raw_mapping):
            raise ConfigError(
                "configuration keys must be strings",
                code="config_key_invalid",
            )
        raw_values = {
            key: value
            for key, value in raw_mapping.items()
            if isinstance(key, str)
        }
        source_version = raw_values.pop(SCHEMA_KEY, 0)
        if not isinstance(source_version, int) or isinstance(source_version, bool):
            raise ConfigError(
                "configuration schema marker must be an integer",
                code="config_schema_invalid",
            )
        if source_version > CURRENT_SCHEMA_VERSION:
            raise ConfigError(
                f"configuration schema {source_version} is newer than supported "
                f"schema {CURRENT_SCHEMA_VERSION}",
                code="config_schema_newer",
                recoverable=False,
            )
        if source_version < 0:
            raise ConfigError(
                "configuration schema cannot be negative",
                code="config_schema_invalid",
            )

        modern_extras: dict[str, object] = {}
        if source_version >= CURRENT_SCHEMA_VERSION:
            modern = raw_values.pop(MODERN_KEY, {})
            if not isinstance(modern, dict):
                raise ConfigError(
                    "modern configuration namespace must be a JSON object",
                    code="config_modern_invalid",
                )
            modern_mapping = cast(dict[object, object], modern)
            if any(not isinstance(key, str) for key in modern_mapping):
                raise ConfigError(
                    "modern namespace keys must be strings",
                    code="config_modern_invalid",
                )
            for raw_key, value in modern_mapping.items():
                if not isinstance(raw_key, str):
                    continue
                if raw_key.startswith("_pixelflasher_"):
                    raw_values[raw_key] = value
                else:
                    modern_extras[raw_key] = value
        elif MODERN_KEY in raw_values:
            # The v2 namespace is reserved. Refuse the migration instead of
            # silently destroying an unrelated 9.x key with the same name.
            raise ConfigError(
                "legacy configuration uses the reserved modern key",
                code="config_legacy_reserved_key",
                recoverable=False,
            )

        return _DecodedConfig(
            ConfigDocument(
                values=raw_values,
                modern_extras=modern_extras,
            ),
            source_version,
        )

    def _migrate_legacy(self, document: ConfigDocument) -> None:
        try:
            # The immutable migration backup survives later rolling .bak updates.
            if not self.migration_backup_path.exists():
                self._atomic_copy(self.path, self.migration_backup_path)
            else:
                migration_backup = self._load_candidate(
                    self.migration_backup_path
                )
                if migration_backup.source_version >= CURRENT_SCHEMA_VERSION:
                    raise ConfigError(
                        "migration backup is not a legacy configuration",
                        code="config_migration_backup_invalid",
                        recoverable=False,
                    )
            # Keep the long-standing .bak contract recoverable immediately too.
            self._atomic_copy(self.path, self.backup_path)
            self._write_payload(document.to_dict(), backup_existing=False)
        except ConfigError:
            raise
        except OSError as error:
            raise ConfigError(
                f"could not migrate legacy configuration: {error}",
                code="config_migration_failed",
                recoverable=False,
            ) from error

    def _recover_from_backup(self, primary_error: ConfigError) -> _DecodedConfig:
        backup_errors: list[str] = []
        for candidate in (self.backup_path, self.migration_backup_path):
            if not candidate.exists():
                continue
            try:
                decoded = self._load_candidate(candidate)
            except ConfigError as error:
                backup_errors.append(f"{candidate.name}: {error}")
                continue
            try:
                if self.path.exists():
                    self._atomic_copy(self.path, self.corrupt_backup_path)
                self._atomic_copy(candidate, self.path)
            except OSError as error:
                raise ConfigError(
                    f"could not restore configuration backup: {error}",
                    code="config_recovery_failed",
                    recoverable=False,
                ) from error
            return decoded
        detail = (
            f"; backups failed: {'; '.join(backup_errors)}"
            if backup_errors
            else ""
        )
        raise ConfigError(
            f"could not recover configuration: {primary_error}{detail}",
            code="config_recovery_unavailable",
            recoverable=False,
        ) from primary_error

    def _write_payload(
        self,
        payload: Mapping[str, JSONValue],
        *,
        backup_existing: bool,
    ) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if backup_existing and self.path.exists():
                # Never replace a known-good backup with corrupt bytes.
                self._load_candidate(self.path)
                self._atomic_copy(self.path, self.backup_path)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                dir=self.path.parent,
            )
        except (ConfigError, OSError) as error:
            if isinstance(error, ConfigError):
                raise
            raise ConfigError(
                f"could not prepare atomic configuration save: {error}",
                code="config_save_prepare_failed",
                recoverable=False,
            ) from error

        temporary_path = Path(temporary_name)
        descriptor_open = True
        try:
            with os.fdopen(
                descriptor,
                "w",
                encoding="utf-8",
                newline="\n",
            ) as stream:
                descriptor_open = False
                json.dump(
                    payload,
                    stream,
                    allow_nan=False,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, self.path)
            self._fsync_directory(self.path.parent)
        except Exception as error:
            temporary_path.unlink(missing_ok=True)
            if isinstance(error, ConfigError):
                raise
            raise ConfigError(
                f"could not atomically save configuration: {error}",
                code="config_save_failed",
                recoverable=False,
            ) from error
        finally:
            if descriptor_open:
                os.close(descriptor)

    @staticmethod
    def _read_json(path: Path) -> object:
        size = path.stat().st_size
        if size > MAX_CONFIG_BYTES:
            raise ConfigError(
                "configuration exceeds the maximum supported size",
                code="config_too_large",
            )
        payload = path.read_bytes()
        if len(payload) > MAX_CONFIG_BYTES:
            raise ConfigError(
                "configuration exceeds the maximum supported size",
                code="config_too_large",
            )
        last_error: UnicodeDecodeError | json.JSONDecodeError | None = None
        for encoding in ("utf-8", "utf-8-sig", "latin-1"):
            try:
                text = payload.decode(encoding)
            except UnicodeDecodeError as error:
                last_error = error
                continue
            try:
                return cast(
                    object,
                    json.loads(
                        text,
                        object_pairs_hook=ConfigStore._unique_object,
                        parse_constant=ConfigStore._reject_json_constant,
                    ),
                )
            except json.JSONDecodeError as error:
                last_error = error
            except RecursionError as error:
                raise ConfigError(
                    "configuration nesting is too deep",
                    code="config_nesting_invalid",
                ) from error
        assert last_error is not None
        raise ConfigError(
            f"configuration is not valid JSON: {last_error}",
            code="config_json_invalid",
        ) from last_error

    @staticmethod
    def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ConfigError(
                    f"configuration contains duplicate key {key!r}",
                    code="config_duplicate_key",
                )
            result[key] = value
        return result

    @staticmethod
    def _reject_json_constant(value: str) -> object:
        raise ConfigError(
            f"configuration contains non-finite number {value}",
            code="config_number_invalid",
        )

    @staticmethod
    def _atomic_copy(source: Path, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
        )
        temporary = Path(temporary_name)
        descriptor_open = True
        try:
            with (
                source.open("rb") as input_stream,
                os.fdopen(descriptor, "wb") as output_stream,
            ):
                descriptor_open = False
                shutil.copyfileobj(
                    input_stream,
                    output_stream,
                    length=1024 * 1024,
                )
                output_stream.flush()
                os.fsync(output_stream.fileno())
            os.replace(temporary, destination)
            ConfigStore._fsync_directory(destination.parent)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        finally:
            if descriptor_open:
                os.close(descriptor)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        # Windows does not expose POSIX directory descriptors. File contents
        # are still flushed before ReplaceFile/MoveFileEx semantics in
        # os.replace; POSIX additionally persists the directory entry here.
        if os.name == "nt":
            return
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "MAX_CONFIG_BYTES",
    "MODERN_KEY",
    "SCHEMA_KEY",
    "ConfigDocument",
    "ConfigError",
    "ConfigStore",
]
