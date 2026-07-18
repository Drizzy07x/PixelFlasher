"""Versioned JSON configuration with legacy compatibility and atomic saves."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .contracts import JSONValue, _json_value


CURRENT_SCHEMA_VERSION = 1
SCHEMA_KEY = "_pixelflasher_core_schema"


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ConfigDocument:
    schema_version: int = CURRENT_SCHEMA_VERSION
    values: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.schema_version != CURRENT_SCHEMA_VERSION:
            raise ConfigError(
                f"unsupported configuration schema {self.schema_version}; "
                f"expected {CURRENT_SCHEMA_VERSION}"
            )
        object.__setattr__(self, "values", MappingProxyType(dict(self.values)))

    def to_dict(self) -> dict[str, JSONValue]:
        result = {str(key): _json_value(value) for key, value in self.values.items()}
        result[SCHEMA_KEY] = self.schema_version
        return result

    def with_values(self, **updates: Any) -> "ConfigDocument":
        values = dict(self.values)
        values.update(updates)
        return ConfigDocument(values=values)


class ConfigStore:
    """Load a legacy flat config and save it without discarding unknown fields."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self.backup_path = self.path.with_name(f"{self.path.name}.bak")
        self._lock = threading.RLock()

    def load(self) -> ConfigDocument:
        with self._lock:
            if not self.path.exists():
                return ConfigDocument()
            loaded_path = self.path
            try:
                raw = self._read_json(self.path)
            except (OSError, json.JSONDecodeError) as error:
                if self.backup_path.exists():
                    try:
                        raw = self._read_json(self.backup_path)
                        loaded_path = self.backup_path
                    except (OSError, json.JSONDecodeError) as backup_error:
                        raise ConfigError(
                            f"could not read configuration or backup: {backup_error}"
                        ) from error
                else:
                    raise ConfigError(f"could not read configuration: {error}") from error

            if not isinstance(raw, dict):
                raise ConfigError("configuration root must be a JSON object")
            source_version = raw.pop(SCHEMA_KEY, 0)
            if not isinstance(source_version, int) or isinstance(source_version, bool):
                raise ConfigError("configuration schema marker must be an integer")
            if source_version > CURRENT_SCHEMA_VERSION:
                raise ConfigError(
                    f"configuration schema {source_version} is newer than supported "
                    f"schema {CURRENT_SCHEMA_VERSION}"
                )
            if source_version < 0:
                raise ConfigError("configuration schema cannot be negative")
            if (
                source_version == 0
                and loaded_path == self.path
                and not self.backup_path.exists()
            ):
                try:
                    shutil.copy2(self.path, self.backup_path)
                except OSError as error:
                    raise ConfigError(
                        f"could not back up legacy configuration before migration: {error}"
                    ) from error
            # Schema 0 is the existing flat PixelFlasher JSON. Schema 1 keeps
            # that shape and adds only the marker, preserving every legacy key.
            return ConfigDocument(values=raw)

    def save(self, document: ConfigDocument) -> None:
        payload = document.to_dict()
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists():
                shutil.copy2(self.path, self.backup_path)

            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                dir=self.path.parent,
            )
            temporary_path = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                    json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
                    stream.write("\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary_path, self.path)
            except Exception:
                try:
                    temporary_path.unlink(missing_ok=True)
                finally:
                    raise

    @staticmethod
    def _read_json(path: Path) -> Any:
        payload = path.read_bytes()
        last_error: UnicodeDecodeError | json.JSONDecodeError | None = None
        for encoding in ("utf-8", "utf-8-sig", "latin-1"):
            try:
                return json.loads(payload.decode(encoding))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                last_error = error
        assert last_error is not None
        raise last_error
