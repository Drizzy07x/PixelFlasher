"""Versioned, shell-free personal tool profiles.

The browser never supplies host paths.  New executables enter through a
purpose-bound native grant and are pinned by SHA-256 before they may run.
Legacy 9.x command strings are imported for visibility only and remain
non-executable.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from .cancellation import CancellationToken
from .contracts import AppCommand, OperationPlan, OperationResult, ProcessRequest
from .executor import CommandExecutor
from .grants import BoundReadFile, GrantError

MY_TOOLS_SCHEMA_VERSION = 1
MAX_TOOLS = 128
MAX_ARGUMENTS = 128
MAX_ARGUMENT_BYTES = 16_384
MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
_TOOL_ID = re.compile(r"[0-9a-f]{32}")


class MyToolsError(ValueError):
    """Stable validation/storage error suitable for an OperationResult code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _clean_title(value: object) -> str:
    if not isinstance(value, str):
        raise MyToolsError("my_tool_title_invalid", "Tool title must be text.")
    title = value.strip()
    if not title or len(title) > 96 or not title.isprintable():
        raise MyToolsError(
            "my_tool_title_invalid",
            "Tool title must contain 1 to 96 printable characters.",
        )
    return title


def _clean_arguments(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise MyToolsError("my_tool_arguments_invalid", "Arguments must be an array.")
    arguments = cast(Sequence[object], value)
    if len(arguments) > MAX_ARGUMENTS:
        raise MyToolsError("my_tool_arguments_invalid", "Too many tool arguments.")
    normalized: list[str] = []
    total = 0
    for argument in arguments:
        if not isinstance(argument, str) or "\x00" in argument or len(argument) > 2_048:
            raise MyToolsError(
                "my_tool_arguments_invalid",
                "Each argument must be NUL-free text up to 2048 characters.",
            )
        total += len(argument.encode("utf-8"))
        normalized.append(argument)
    if total > MAX_ARGUMENT_BYTES:
        raise MyToolsError("my_tool_arguments_invalid", "Tool arguments are too large.")
    return tuple(normalized)


def _timestamp(value: object) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(value)
        or value < 0
    ):
        raise MyToolsError("my_tools_store_invalid", "Personal tool timestamp is invalid.")
    return float(value)


def _sha256_stream(stream: Any) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while True:
        block = stream.read(1024 * 1024)
        if not block:
            break
        size += len(block)
        if size > MAX_EXECUTABLE_BYTES:
            raise MyToolsError("my_tool_executable_too_large", "Executable exceeds 512 MiB.")
        digest.update(block)
    return digest.hexdigest(), size


def _validate_executable_path(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise MyToolsError(
            "my_tool_executable_unavailable", "Selected executable is unavailable."
        ) from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise MyToolsError(
            "my_tool_executable_invalid", "Selected executable must be a regular file."
        )
    if os.name == "nt":
        if path.suffix.casefold() not in {".exe", ".com"}:
            raise MyToolsError(
                "my_tool_executable_invalid",
                "Windows safe profiles accept only .exe or .com executables.",
            )
    elif not os.access(path, os.X_OK):
        raise MyToolsError(
            "my_tool_executable_invalid", "Selected file is not executable."
        )


@dataclass(frozen=True, slots=True)
class MyToolSpec:
    tool_id: str
    title: str
    executable: Path
    executable_sha256: str
    executable_size: int
    arguments: tuple[str, ...] = ()
    enabled: bool = True
    created_at: float = 0.0
    updated_at: float = 0.0

    def __post_init__(self) -> None:
        if _TOOL_ID.fullmatch(self.tool_id) is None:
            raise MyToolsError("my_tool_id_invalid", "Tool id is invalid.")
        object.__setattr__(self, "title", _clean_title(self.title))
        object.__setattr__(self, "executable", Path(self.executable).expanduser().resolve(strict=False))
        if re.fullmatch(r"[0-9a-f]{64}", self.executable_sha256) is None:
            raise MyToolsError("my_tool_digest_invalid", "Executable digest is invalid.")
        if not isinstance(self.executable_size, int) or not 0 < self.executable_size <= MAX_EXECUTABLE_BYTES:
            raise MyToolsError("my_tool_executable_invalid", "Executable size is invalid.")
        object.__setattr__(self, "arguments", _clean_arguments(self.arguments))
        if not isinstance(self.enabled, bool):
            raise MyToolsError("my_tool_enabled_invalid", "Enabled must be a boolean.")

    @property
    def display_name(self) -> str:
        return self.executable.name

    def to_storage_dict(self) -> dict[str, object]:
        return {
            "id": self.tool_id,
            "title": self.title,
            "executable": str(self.executable),
            "sha256": self.executable_sha256,
            "size": self.executable_size,
            "arguments": list(self.arguments),
            "enabled": self.enabled,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
        }

    def to_public_dict(self) -> dict[str, object]:
        return {
            "id": self.tool_id,
            "title": self.title,
            "mode": "safeArgv",
            "displayName": self.display_name,
            "sha256": self.executable_sha256,
            "arguments": list(self.arguments),
            "enabled": self.enabled,
        }


@dataclass(frozen=True, slots=True)
class LegacyRawTool:
    legacy_id: str
    title: str
    enabled: bool

    def to_public_dict(self) -> dict[str, object]:
        return {
            "id": self.legacy_id,
            "title": self.title,
            "mode": "legacyRaw",
            "displayName": "Legacy 9.x",
            "sha256": "",
            "arguments": [],
            "enabled": self.enabled,
            "permissionGranted": False,
            "blockedReason": "legacy_raw_permission_required",
        }


class MyToolsRepository:
    """Atomic JSON repository with one-time, fail-closed 9.x discovery."""

    def __init__(self, path: str | Path, *, legacy_path: str | Path | None = None) -> None:
        self.path = Path(path).expanduser().resolve(strict=False)
        self.legacy_path = (
            Path(legacy_path).expanduser().resolve(strict=False)
            if legacy_path is not None
            else None
        )
        self._safe: dict[str, MyToolSpec] = {}
        self._legacy: tuple[LegacyRawTool, ...] = ()
        self._load()

    def inventory(self) -> dict[str, object]:
        return {
            "schemaVersion": MY_TOOLS_SCHEMA_VERSION,
            "tools": [item.to_public_dict() for item in self._safe.values()],
            "legacyRaw": [item.to_public_dict() for item in self._legacy],
        }

    def get(self, tool_id: str) -> MyToolSpec:
        if _TOOL_ID.fullmatch(tool_id) is None or tool_id not in self._safe:
            raise MyToolsError("my_tool_not_found", "Personal tool was not found.")
        return self._safe[tool_id]

    def save(
        self,
        *,
        title: object,
        executable: BoundReadFile | None,
        arguments: object,
        enabled: object,
        tool_id: str | None = None,
    ) -> MyToolSpec:
        if tool_id is None and len(self._safe) >= MAX_TOOLS:
            raise MyToolsError("my_tools_limit_reached", "Personal tool limit reached.")
        existing = self.get(tool_id) if tool_id is not None else None
        if not isinstance(enabled, bool):
            raise MyToolsError("my_tool_enabled_invalid", "Enabled must be a boolean.")
        now = time.time()
        if executable is None:
            if existing is None:
                raise MyToolsError(
                    "my_tool_executable_required", "Choose an executable for the new tool."
                )
            path = existing.executable
            digest = existing.executable_sha256
            size = existing.executable_size
        else:
            path = executable.path.resolve(strict=False)
            _validate_executable_path(path)
            try:
                with executable.open_verified() as stream:
                    digest, size = _sha256_stream(stream)
            except GrantError as error:
                raise MyToolsError(error.code, str(error)) from error
        spec = MyToolSpec(
            tool_id=existing.tool_id if existing else uuid4().hex,
            title=_clean_title(title),
            executable=path,
            executable_sha256=digest,
            executable_size=size,
            arguments=_clean_arguments(arguments),
            enabled=enabled,
            created_at=existing.created_at if existing else now,
            updated_at=now,
        )
        self._safe[spec.tool_id] = spec
        self._write()
        return spec

    def delete(self, tool_id: str) -> None:
        self.get(tool_id)
        del self._safe[tool_id]
        self._write()

    def revalidate(self, tool_id: str) -> MyToolSpec:
        spec = self.get(tool_id)
        if not spec.enabled:
            raise MyToolsError("my_tool_disabled", "Personal tool is disabled.")
        _validate_executable_path(spec.executable)
        try:
            with spec.executable.open("rb") as stream:
                digest, size = _sha256_stream(stream)
        except OSError as error:
            raise MyToolsError(
                "my_tool_executable_unavailable", "Personal tool executable is unavailable."
            ) from error
        if digest != spec.executable_sha256 or size != spec.executable_size:
            raise MyToolsError(
                "my_tool_executable_changed",
                "Personal tool executable changed and must be selected again.",
            )
        return spec

    def _load(self) -> None:
        if not self.path.exists():
            self._legacy = self._read_legacy()
            self._write()
            return
        try:
            raw_object = cast(object, json.loads(self.path.read_text(encoding="utf-8")))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise MyToolsError("my_tools_store_invalid", "Personal tools store is invalid.") from error
        if not isinstance(raw_object, Mapping):
            raise MyToolsError("my_tools_store_invalid", "Personal tools store is invalid.")
        raw = cast(Mapping[object, object], raw_object)
        if raw.get("schemaVersion") != MY_TOOLS_SCHEMA_VERSION:
            raise MyToolsError("my_tools_store_invalid", "Personal tools schema is unsupported.")
        tools_object = raw.get("tools")
        legacy_object = raw.get("legacyRaw", [])
        if (
            not isinstance(tools_object, list)
            or not isinstance(legacy_object, list)
            or len(cast(list[object], tools_object)) > MAX_TOOLS
        ):
            raise MyToolsError("my_tools_store_invalid", "Personal tools store is invalid.")
        tools = cast(list[object], tools_object)
        legacy = cast(list[object], legacy_object)
        parsed: dict[str, MyToolSpec] = {}
        try:
            for item in tools:
                values = cast(Mapping[str, object], item)
                spec = MyToolSpec(
                    tool_id=cast(str, values["id"]),
                    title=cast(str, values["title"]),
                    executable=Path(cast(str, values["executable"])),
                    executable_sha256=cast(str, values["sha256"]),
                    executable_size=cast(int, values["size"]),
                    arguments=tuple(cast(list[str], values.get("arguments", []))),
                    enabled=cast(bool, values.get("enabled", True)),
                    created_at=_timestamp(values.get("createdAt", 0.0)),
                    updated_at=_timestamp(values.get("updatedAt", 0.0)),
                )
                if spec.tool_id in parsed:
                    raise MyToolsError("my_tools_store_invalid", "Duplicate personal tool id.")
                parsed[spec.tool_id] = spec
            parsed_legacy = tuple(
                LegacyRawTool(
                    str(cast(Mapping[str, object], item)["id"]),
                    _clean_title(cast(Mapping[str, object], item)["title"]),
                    bool(cast(Mapping[str, object], item).get("enabled", False)),
                )
                for item in legacy
            )
        except (KeyError, TypeError, ValueError, MyToolsError) as error:
            raise MyToolsError("my_tools_store_invalid", "Personal tools store is invalid.") from error
        self._safe = parsed
        self._legacy = parsed_legacy

    def _read_legacy(self) -> tuple[LegacyRawTool, ...]:
        path = self.legacy_path
        if path is None or not path.is_file():
            return ()
        try:
            raw_object = cast(
                object,
                json.loads(path.read_text(encoding="iso-8859-1", errors="replace")),
            )
            if not isinstance(raw_object, Mapping):
                return ()
            raw = cast(Mapping[object, object], raw_object)
            tools_object = raw.get("tools", {})
            if not isinstance(tools_object, Mapping):
                return ()
            tools = cast(Mapping[object, object], tools_object)
            migrated: list[LegacyRawTool] = []
            for key, item in list(tools.items())[:MAX_TOOLS]:
                if not isinstance(item, Mapping):
                    continue
                values = cast(Mapping[object, object], item)
                if values.get("title") == "---":
                    continue
                title = _clean_title(values.get("title"))
                migrated.append(
                    LegacyRawTool(
                        f"legacy:{key}", title, bool(values.get("enabled", False))
                    )
                )
            return tuple(migrated)
        except (OSError, UnicodeError, json.JSONDecodeError, MyToolsError):
            return ()

    def _write(self) -> None:
        payload = {
            "schemaVersion": MY_TOOLS_SCHEMA_VERSION,
            "tools": [item.to_storage_dict() for item in self._safe.values()],
            "legacyRaw": [
                {"id": item.legacy_id, "title": item.title, "enabled": item.enabled}
                for item in self._legacy
            ],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            if os.name != "nt":
                directory = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise


class MyToolsService:
    def __init__(self, repository: MyToolsRepository, executor: CommandExecutor) -> None:
        self.repository = repository
        self.executor = executor

    def run(
        self,
        command: AppCommand,
        tool_id: str,
        cancellation: CancellationToken,
    ) -> OperationResult:
        spec = self.repository.revalidate(tool_id)
        request = ProcessRequest(
            (str(spec.executable), *spec.arguments),
            timeout_seconds=command.execution_timeout_seconds or 300.0,
            output_limit_bytes=4 * 1024 * 1024,
        )
        result = self.executor.execute(
            command,
            OperationPlan(
                request,
                label=f"Personal tool: {spec.title}",
                snapshot_revision=command.expected_revision,
                postconditions=("process_exit_zero",),
            ),
            cancellation,
        )
        if not result.ok:
            return result
        return replace(
            result,
            code="my_tool_completed",
            message="Personal tool completed successfully.",
            value={"tool": spec.to_public_dict()},
        )


__all__ = [
    "MY_TOOLS_SCHEMA_VERSION",
    "LegacyRawTool",
    "MyToolSpec",
    "MyToolsError",
    "MyToolsRepository",
    "MyToolsService",
]
