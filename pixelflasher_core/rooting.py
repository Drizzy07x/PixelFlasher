"""Headless, fail-closed planning for root apps and Magisk modules.

Root-app inventory is supplied by backend-owned sources and is never populated
from browser metadata.  Device operations compile exact, serial-bound ADB argv
and attach canonical SHA-256 artifacts.  Module management accepts only fixed
Magisk operations and validated module IDs; no caller-provided shell text can
cross the process boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol

from .apk_inspection import (
    ApkIdentity,
    ApkInspectionCode,
    ApkInspectionError,
    ApkInspector,
    CancellationProbe,
)
from .contracts import (
    AppCommand,
    AppSnapshot,
    DeviceInfo,
    FileArtifact,
    OperationPlan,
    OperationPostcondition,
    OperationRisk,
    ProcessRequest,
)

ROOTING_COMMANDS = frozenset(
    {
        "root.apps.list",
        "root.apps.install",
        "root.modules.list",
        "root.modules.action",
    }
)

_PROVENANCE = frozenset({"official", "verified-download", "bundled", "user-import"})
_VERIFIED_PROVENANCE = frozenset({"official", "verified-download", "bundled"})
_METADATA_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. +()-]{0,63}$")
_MODULE_ID_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
_PACKAGE_NAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MODULE_ACTIONS = frozenset({"install", "enable", "disable", "remove"})
_MODULE_REMOTE_ROOT = "/data/local/tmp/"
_MAX_ZIP_ENTRIES = 4096
_MAX_ZIP_UNCOMPRESSED = 512 * 1024 * 1024


class RootApkInspector(Protocol):
    """Narrow injectable boundary for cryptographic APK inspection."""

    def inspect(
        self,
        path: str | os.PathLike[str],
        *,
        cancellation: CancellationProbe | None = None,
    ) -> ApkIdentity: ...


class RootingPlanningError(ValueError):
    """Stable validation failure raised before a root operation can execute."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class RootAppSource:
    """Backend-owned metadata for one locally available rooting APK."""

    path: str
    provider: str
    flavor: str
    version: str
    provenance: str
    expected_sha256: str = ""
    package_name: str = ""


@dataclass(frozen=True, slots=True)
class RootAppInfo:
    id: str
    path: str
    provider: str
    flavor: str
    version: str
    sha256: str
    provenance: str
    package_name: str = ""
    signer_sha256: tuple[str, ...] = ()
    schemes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "signer_sha256", tuple(self.signer_sha256))
        object.__setattr__(self, "schemes", tuple(self.schemes))

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "provider": self.provider,
            "flavor": self.flavor,
            "version": self.version,
            "sha256": self.sha256,
            "provenance": self.provenance,
            "packageName": self.package_name,
            "signerSha256": list(self.signer_sha256),
            "schemes": list(self.schemes),
        }


@dataclass(frozen=True, slots=True)
class RootModuleInfo:
    id: str

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id}


@dataclass(frozen=True, slots=True)
class RootingCompilation:
    """A local result or process plan plus backend-owned safety metadata."""

    action: str
    plan: OperationPlan | None = None
    root_apps: tuple[RootAppInfo, ...] = ()
    module_id: str | None = None
    device_write: bool = False
    destructive: bool = False
    requires_confirmation: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "plan": self.plan.to_dict() if self.plan is not None else None,
            "root_apps": [item.to_dict() for item in self.root_apps],
            "module_id": self.module_id,
            "device_write": self.device_write,
            "destructive": self.destructive,
            "requires_confirmation": self.requires_confirmation,
        }


class RootingService:
    """Compile bounded root-app and Magisk-module operations."""

    def __init__(
        self,
        root_app_sources: Sequence[RootAppSource] = (),
        *,
        hash_chunk_size: int = 1024 * 1024,
        apk_inspector: RootApkInspector | None = None,
    ) -> None:
        if isinstance(root_app_sources, (str, bytes)) or not isinstance(
            root_app_sources,
            Sequence,
        ):
            raise TypeError("root_app_sources must be a sequence")
        if any(not isinstance(source, RootAppSource) for source in root_app_sources):
            raise TypeError("root_app_sources must contain only RootAppSource values")
        if not isinstance(hash_chunk_size, int) or isinstance(hash_chunk_size, bool):
            raise TypeError("hash_chunk_size must be an integer")
        if hash_chunk_size <= 0:
            raise ValueError("hash_chunk_size must be positive")
        self.root_app_sources = tuple(root_app_sources)
        self.hash_chunk_size = hash_chunk_size
        self.apk_inspector = apk_inspector or ApkInspector()

    def compile(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        cancellation: CancellationProbe | None = None,
    ) -> RootingCompilation:
        self._check_cancelled(cancellation)
        if command.kind not in ROOTING_COMMANDS:
            raise RootingPlanningError(
                "rooting_command_unsupported",
                f"unsupported rooting command: {command.kind}",
            )
        self._revision(command, snapshot)
        if command.kind == "root.apps.list":
            self._validate_payload(command, {"serial"})
            self._validate_optional_serial(command)
            return RootingCompilation(
                "apps.list",
                root_apps=self.root_app_inventory(cancellation),
            )

        device = self._adb_device(command, snapshot)
        adb = self._adb(snapshot)
        if command.kind == "root.apps.install":
            return self._compile_root_app_install(
                command,
                snapshot,
                device,
                adb,
                cancellation,
            )
        if not device.root:
            raise RootingPlanningError(
                "root_access_required",
                "Magisk module operations require a device reporting root access",
            )
        if command.kind == "root.modules.list":
            return self._compile_module_list(command, snapshot, device, adb)
        return self._compile_module_action(
            command,
            snapshot,
            device,
            adb,
            cancellation,
        )

    def root_app_inventory(
        self,
        cancellation: CancellationProbe | None = None,
    ) -> tuple[RootAppInfo, ...]:
        inventory: list[RootAppInfo] = []
        seen_paths: set[str] = set()
        seen_identities: set[tuple[str, str, str]] = set()
        seen_ids: set[str] = set()
        for source in self.root_app_sources:
            self._check_cancelled(cancellation)
            provider = self._metadata(source.provider, "provider")
            flavor = self._metadata(source.flavor, "flavor")
            version = self._metadata(source.version, "version")
            provenance = source.provenance.strip().casefold()
            if provenance not in _PROVENANCE:
                raise RootingPlanningError(
                    "root_app_provenance_invalid",
                    f"unsupported root-app provenance: {source.provenance}",
                )
            path = self._input_file(
                source.path,
                suffix=".apk",
                missing_code="root_app_path_invalid",
            )
            declared_package_name = source.package_name.strip()
            if declared_package_name and _PACKAGE_NAME_PATTERN.fullmatch(declared_package_name) is None:
                raise RootingPlanningError(
                    "root_app_package_name_invalid",
                    "root-app package name is invalid",
                )
            expected = source.expected_sha256.strip().casefold()
            if expected and not _SHA256_PATTERN.fullmatch(expected):
                raise RootingPlanningError(
                    "root_app_expected_hash_invalid",
                    "expected root-app SHA-256 must contain 64 hexadecimal characters",
                )
            if provenance in _VERIFIED_PROVENANCE and not expected:
                raise RootingPlanningError(
                    "root_app_expected_hash_required",
                    f"{provenance} root apps require a backend-provided expected SHA-256",
                )
            canonical_key = os.path.normcase(str(path))
            if canonical_key in seen_paths:
                raise RootingPlanningError(
                    "root_app_inventory_ambiguous",
                    f"duplicate canonical root-app path: {path}",
                )
            identity = (provider.casefold(), flavor.casefold(), version.casefold())
            if identity in seen_identities:
                raise RootingPlanningError(
                    "root_app_inventory_ambiguous",
                    "provider, flavor and version must identify one local APK",
                )
            self._check_cancelled(cancellation)
            try:
                apk_identity = self.apk_inspector.inspect(
                    path,
                    cancellation=cancellation,
                )
            except ApkInspectionError as error:
                self._check_cancelled(cancellation)
                if error.code is ApkInspectionCode.CANCELLED:
                    raise RootingPlanningError(
                        "rooting_cancelled",
                        "root operation planning was cancelled",
                    ) from error
                raise RootingPlanningError(error.code.value, str(error)) from error
            except (OSError, TypeError, ValueError) as error:
                self._check_cancelled(cancellation)
                raise RootingPlanningError(
                    "apk_inspection_failed",
                    "root-app APK identity verification failed",
                ) from error
            self._check_cancelled(cancellation)
            if not isinstance(apk_identity, ApkIdentity) or not apk_identity.verified:
                raise RootingPlanningError(
                    "apk_identity_unverified",
                    "root-app APK inspection did not return a verified identity",
                )
            digest = apk_identity.sha256
            if expected and not hmac.compare_digest(digest, expected):
                raise RootingPlanningError(
                    "root_app_hash_mismatch",
                    f"root-app hash does not match its {provenance} provenance: {path}",
                )
            if declared_package_name and apk_identity.package_name != declared_package_name:
                raise RootingPlanningError(
                    "root_app_package_mismatch",
                    "root-app package name does not match its verified APK identity",
                )
            app_id = hashlib.sha256(f"{provider.casefold()}\0{flavor.casefold()}\0{digest}".encode()).hexdigest()
            if app_id in seen_ids:
                raise RootingPlanningError(
                    "root_app_inventory_ambiguous",
                    f"duplicate root-app identity: {app_id}",
                )
            seen_paths.add(canonical_key)
            seen_identities.add(identity)
            seen_ids.add(app_id)
            inventory.append(
                RootAppInfo(
                    app_id,
                    str(path),
                    provider,
                    flavor,
                    version,
                    digest,
                    provenance,
                    apk_identity.package_name,
                    apk_identity.signer_sha256,
                    apk_identity.schemes,
                )
            )
        return tuple(
            sorted(
                inventory,
                key=lambda item: (
                    item.provider.casefold(),
                    item.flavor.casefold(),
                    item.version.casefold(),
                    item.id,
                ),
            )
        )

    def _compile_root_app_install(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
        cancellation: CancellationProbe | None,
    ) -> RootingCompilation:
        self._validate_payload(command, {"serial", "appId"})
        raw_app_id = command.payload.get("appId")
        if not isinstance(raw_app_id, str) or not _SHA256_PATTERN.fullmatch(raw_app_id.strip().casefold()):
            raise RootingPlanningError(
                "root_app_id_invalid",
                "appId must be a backend-issued 64-character identifier",
            )
        app_id = raw_app_id.strip().casefold()
        app = next(
            (item for item in self.root_app_inventory(cancellation) if item.id == app_id),
            None,
        )
        if app is None:
            raise RootingPlanningError(
                "root_app_not_found",
                "selected root app is no longer present in the backend inventory",
            )
        artifact = FileArtifact(
            app.path,
            app.sha256,
            f"root-app:{app.provider}:{app.flavor}",
        )
        request = ProcessRequest(
            (adb, "-s", device.serial, "install", "-r", app.path),
            timeout_seconds=600.0,
        )
        plan = self._base_plan(
            snapshot,
            device,
            (request,),
            label=f"Install {app.provider} {app.flavor} on {device.serial}",
            data_behavior="root_app_install",
            artifacts=(artifact,),
            risk=OperationRisk.MUTATING,
            postconditions=(
                OperationPostcondition(
                    "root_app_installed",
                    {
                        "appId": app.id,
                        "apkSha256": artifact.sha256,
                        "provider": app.provider,
                        "flavor": app.flavor,
                        "packageName": app.package_name,
                    },
                    "the selected root application is installed on the device",
                ),
            ),
        )
        return RootingCompilation(
            "apps.install",
            plan,
            root_apps=(app,),
            device_write=True,
            requires_confirmation=True,
        )

    def _compile_module_list(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
    ) -> RootingCompilation:
        self._validate_payload(command, {"serial"})
        # Magisk exposes module directories at this documented fixed path.  The
        # command text is backend-owned and contains no caller-controlled data.
        request = ProcessRequest(
            (
                adb,
                "-s",
                device.serial,
                "shell",
                "su",
                "-c",
                "ls -1 /data/adb/modules",
            ),
            timeout_seconds=30.0,
        )
        return RootingCompilation(
            "modules.list",
            self._base_plan(
                snapshot,
                device,
                (request,),
                label=f"List Magisk modules on {device.serial}",
            ),
        )

    def _compile_module_action(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
        cancellation: CancellationProbe | None,
    ) -> RootingCompilation:
        self._validate_payload(command, {"serial", "action", "moduleId", "path"})
        raw_action = command.payload.get("action")
        if not isinstance(raw_action, str) or raw_action not in _MODULE_ACTIONS:
            raise RootingPlanningError(
                "root_module_action_invalid",
                "action must be install, enable, disable or remove",
            )
        action = raw_action
        if action == "install":
            if "moduleId" in command.payload:
                raise RootingPlanningError(
                    "root_module_target_ambiguous",
                    "module install accepts a ZIP path, not a module ID",
                )
            return self._compile_module_install(
                command,
                snapshot,
                device,
                adb,
                cancellation,
            )
        if "path" in command.payload:
            raise RootingPlanningError(
                "root_module_target_ambiguous",
                f"module {action} accepts a module ID, not a ZIP path",
            )
        module_id = self._module_id(command.payload.get("moduleId"))
        module_root = f"/data/adb/modules/{module_id}"
        if action == "enable":
            remote_command = f"rm -f {module_root}/disable {module_root}/remove"
        elif action == "disable":
            remote_command = f"touch {module_root}/disable"
        else:
            remote_command = f"touch {module_root}/remove"
        request = ProcessRequest(
            (adb, "-s", device.serial, "shell", "su", "-c", remote_command),
            timeout_seconds=30.0,
        )
        destructive = action == "remove"
        return RootingCompilation(
            f"modules.{action}",
            self._base_plan(
                snapshot,
                device,
                (request,),
                label=f"{action} Magisk module {module_id} on {device.serial}",
                data_behavior=("root_module_remove" if destructive else "root_module_state_write"),
                risk=(OperationRisk.DESTRUCTIVE if destructive else OperationRisk.MUTATING),
                postconditions=(
                    OperationPostcondition(
                        "root_module_state",
                        {
                            "moduleId": module_id,
                            "state": {
                                "enable": "enabled",
                                "disable": "disabled",
                                "remove": "pending_remove",
                            }[action],
                        },
                        "the Magisk module reports the requested state",
                    ),
                ),
            ),
            module_id=module_id,
            device_write=True,
            destructive=destructive,
            requires_confirmation=True,
        )

    def _compile_module_install(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
        cancellation: CancellationProbe | None,
    ) -> RootingCompilation:
        path = self._input_file(
            command.payload.get("path"),
            suffix=".zip",
            missing_code="root_module_zip_invalid",
        )
        module_id = self._validate_module_zip(path, cancellation)
        digest = self._sha256(path, cancellation)
        artifact = FileArtifact(str(path), digest, f"root-module-zip:{module_id}")
        remote_path = f"{_MODULE_REMOTE_ROOT}pixelflasher-module-{digest[:16]}.zip"
        requests = (
            ProcessRequest(
                (adb, "-s", device.serial, "push", str(path), remote_path),
                timeout_seconds=600.0,
            ),
            ProcessRequest(
                (
                    adb,
                    "-s",
                    device.serial,
                    "shell",
                    "su",
                    "-c",
                    f"magisk --install-module {remote_path}",
                ),
                timeout_seconds=600.0,
            ),
            ProcessRequest(
                (adb, "-s", device.serial, "shell", "rm", "-f", remote_path),
                timeout_seconds=30.0,
            ),
        )
        return RootingCompilation(
            "modules.install",
            self._base_plan(
                snapshot,
                device,
                requests,
                label=f"Install Magisk module {module_id} on {device.serial}",
                data_behavior="root_module_install",
                artifacts=(artifact,),
                risk=OperationRisk.DESTRUCTIVE,
                postconditions=(
                    OperationPostcondition(
                        "root_module_state",
                        {
                            "moduleId": module_id,
                            "state": "installed",
                            "zipSha256": artifact.sha256,
                        },
                        "the verified Magisk module is present after installation",
                    ),
                ),
            ),
            module_id=module_id,
            device_write=True,
            destructive=True,
            requires_confirmation=True,
        )

    def _validate_module_zip(
        self,
        path: Path,
        cancellation: CancellationProbe | None,
    ) -> str:
        module_prop: bytes | None = None
        try:
            with zipfile.ZipFile(path) as archive:
                entries = archive.infolist()
                if not entries or len(entries) > _MAX_ZIP_ENTRIES:
                    raise RootingPlanningError(
                        "root_module_zip_invalid",
                        f"module ZIP must contain between 1 and {_MAX_ZIP_ENTRIES} entries",
                    )
                seen: set[str] = set()
                total_size = 0
                has_module_prop = False
                for entry in entries:
                    self._check_cancelled(cancellation)
                    name = entry.filename
                    if (
                        not name
                        or "\\" in name
                        or ":" in name
                        or name.startswith("/")
                        or "\x00" in name
                        or any(ord(character) < 32 for character in name)
                    ):
                        raise RootingPlanningError(
                            "root_module_zip_unsafe",
                            f"unsafe module ZIP member: {name!r}",
                        )
                    member = PurePosixPath(name)
                    raw_parts = name.rstrip("/").split("/")
                    if (
                        member.is_absolute()
                        or ".." in member.parts
                        or any(part in {"", ".", ".."} for part in raw_parts)
                    ):
                        raise RootingPlanningError(
                            "root_module_zip_unsafe",
                            f"module ZIP contains path traversal: {name}",
                        )
                    key = name.rstrip("/").casefold()
                    if key in seen:
                        raise RootingPlanningError(
                            "root_module_zip_unsafe",
                            f"module ZIP contains an ambiguous duplicate: {name}",
                        )
                    seen.add(key)
                    if entry.flag_bits & 0x1:
                        raise RootingPlanningError(
                            "root_module_zip_unsafe",
                            f"encrypted module ZIP entries are not supported: {name}",
                        )
                    entry_mode = (entry.external_attr >> 16) & 0o170000
                    if entry_mode == stat.S_IFLNK:
                        raise RootingPlanningError(
                            "root_module_zip_unsafe",
                            f"symbolic links are not accepted in module ZIPs: {name}",
                        )
                    total_size += entry.file_size
                    if total_size > _MAX_ZIP_UNCOMPRESSED:
                        raise RootingPlanningError(
                            "root_module_zip_too_large",
                            "module ZIP uncompressed size exceeds 512 MiB",
                        )
                    if name == "module.prop" and not entry.is_dir():
                        if entry.file_size > 64 * 1024:
                            raise RootingPlanningError(
                                "root_module_zip_invalid",
                                "module.prop exceeds the 64 KiB metadata limit",
                            )
                        module_prop = archive.read(entry)
                        has_module_prop = True
        except RootingPlanningError:
            raise
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
            raise RootingPlanningError("root_module_zip_invalid", str(error)) from error
        if not has_module_prop:
            raise RootingPlanningError(
                "root_module_zip_invalid",
                "Magisk module ZIP must contain module.prop at its root",
            )
        assert module_prop is not None
        try:
            metadata = module_prop.decode("utf-8")
        except UnicodeDecodeError as error:
            raise RootingPlanningError(
                "root_module_zip_invalid",
                "module.prop must be valid UTF-8",
            ) from error
        declared_ids = [
            line.partition("=")[2].strip() for line in metadata.splitlines() if line.partition("=")[0].strip() == "id"
        ]
        if len(declared_ids) != 1 or not _MODULE_ID_PATTERN.fullmatch(declared_ids[0]):
            raise RootingPlanningError(
                "root_module_zip_invalid",
                "module.prop must declare exactly one safe Magisk module id",
            )
        return declared_ids[0]

    def _sha256(
        self,
        path: Path,
        cancellation: CancellationProbe | None,
    ) -> str:
        self._check_cancelled(cancellation)
        try:
            before = path.stat()
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                while chunk := stream.read(self.hash_chunk_size):
                    self._check_cancelled(cancellation)
                    digest.update(chunk)
            after = path.stat()
        except RootingPlanningError:
            raise
        except OSError as error:
            raise RootingPlanningError("rooting_artifact_read_failed", str(error)) from error
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_after:
            raise RootingPlanningError(
                "rooting_artifact_changed",
                f"local artifact changed while it was being hashed: {path}",
            )
        return digest.hexdigest()

    @staticmethod
    def _metadata(value: object, field: str) -> str:
        if not isinstance(value, str) or not _METADATA_PATTERN.fullmatch(value.strip()):
            raise RootingPlanningError(
                "root_app_metadata_invalid",
                f"root-app {field} is missing or invalid",
            )
        return value.strip()

    @staticmethod
    def _module_id(raw_module_id: object) -> str:
        if not isinstance(raw_module_id, str):
            raise RootingPlanningError(
                "root_module_id_required",
                "moduleId must be a string",
            )
        module_id = raw_module_id.strip()
        if not _MODULE_ID_PATTERN.fullmatch(module_id):
            raise RootingPlanningError(
                "root_module_id_invalid",
                f"invalid Magisk module ID: {module_id}",
            )
        return module_id

    @staticmethod
    def _input_file(raw_path: object, *, suffix: str, missing_code: str) -> Path:
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise RootingPlanningError(missing_code, "an absolute local path is required")
        try:
            raw = Path(raw_path)
            expanded = raw.expanduser()
        except (OSError, RuntimeError, ValueError) as error:
            raise RootingPlanningError(missing_code, str(error)) from error
        if not expanded.is_absolute():
            raise RootingPlanningError(missing_code, "relative paths are not accepted")
        if ".." in raw.parts:
            raise RootingPlanningError(
                "rooting_path_traversal",
                "parent-directory traversal is not accepted in rooting paths",
            )
        try:
            path = expanded.resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as error:
            raise RootingPlanningError(missing_code, str(error)) from error
        if not path.is_file() or path.suffix.casefold() != suffix:
            raise RootingPlanningError(
                missing_code,
                f"selected path must be an existing {suffix} regular file",
            )
        return path

    @staticmethod
    def _check_cancelled(cancellation: CancellationProbe | None) -> None:
        if cancellation is not None and cancellation.cancelled:
            raise RootingPlanningError(
                "rooting_cancelled",
                "root operation planning was cancelled",
            )

    @staticmethod
    def _validate_optional_serial(command: AppCommand) -> None:
        raw_serial = command.payload.get("serial")
        if raw_serial is not None and (not isinstance(raw_serial, str) or not raw_serial.strip()):
            raise RootingPlanningError(
                "target_serial_invalid",
                "payload.serial must be a non-empty string",
            )
        payload_serial = raw_serial.strip() if isinstance(raw_serial, str) else None
        if command.target_serial and payload_serial and command.target_serial != payload_serial:
            raise RootingPlanningError(
                "ambiguous_target_serial",
                "command and payload target different devices",
            )

    @staticmethod
    def _revision(command: AppCommand, snapshot: AppSnapshot) -> None:
        if command.expected_revision is None:
            raise RootingPlanningError("revision_required", "expected_revision is required")
        if command.expected_revision != snapshot.revision:
            raise RootingPlanningError(
                "stale_revision",
                (f"state revision changed: expected {command.expected_revision}, current {snapshot.revision}"),
            )

    @staticmethod
    def _adb_device(command: AppCommand, snapshot: AppSnapshot) -> DeviceInfo:
        raw_serial = command.payload.get("serial")
        if raw_serial is not None and (not isinstance(raw_serial, str) or not raw_serial.strip()):
            raise RootingPlanningError(
                "target_serial_invalid",
                "payload.serial must be a non-empty string",
            )
        payload_serial = raw_serial.strip() if isinstance(raw_serial, str) else None
        if command.target_serial and payload_serial and command.target_serial != payload_serial:
            raise RootingPlanningError(
                "ambiguous_target_serial",
                "command and payload target different devices",
            )
        serial = command.target_serial or payload_serial or snapshot.selected_serial
        if not serial:
            raise RootingPlanningError(
                "target_serial_required",
                "one selected device is required",
            )
        if serial not in snapshot.selected_serials:
            raise RootingPlanningError(
                "target_serial_changed",
                "target serial is no longer selected",
            )
        device = next((item for item in snapshot.devices if item.serial == serial), None)
        if device is None or not device.online:
            raise RootingPlanningError(
                "device_disconnected",
                "target device is not online",
            )
        if device.mode != "adb":
            raise RootingPlanningError(
                "adb_device_required",
                "rooting operations require a device in adb mode",
            )
        return device

    @staticmethod
    def _adb(snapshot: AppSnapshot) -> str:
        if not snapshot.toolchain.ready or not snapshot.toolchain.adb:
            raise RootingPlanningError(
                "toolchain_not_ready",
                "validated adb is required",
            )
        return snapshot.toolchain.adb

    @staticmethod
    def _base_plan(
        snapshot: AppSnapshot,
        device: DeviceInfo,
        requests: tuple[ProcessRequest, ...],
        *,
        label: str,
        data_behavior: str = "preserve",
        artifacts: tuple[FileArtifact, ...] = (),
        risk: OperationRisk = OperationRisk.READ_ONLY,
        postconditions: tuple[OperationPostcondition, ...] = (),
    ) -> OperationPlan:
        return OperationPlan(
            requests=requests,
            label=label,
            snapshot_revision=snapshot.revision,
            target_serial=device.serial,
            expected_codename=device.codename,
            expected_device_state=device.mode,
            firmware_hash=snapshot.firmware.hash,
            boot_hash=snapshot.boot.hash,
            data_behavior=data_behavior,
            plan_revision=snapshot.plan.revision,
            fingerprint=snapshot.plan.fingerprint,
            artifacts=artifacts,
            risk=risk,
            postconditions=postconditions,
        )

    @staticmethod
    def _validate_payload(command: AppCommand, allowed: set[str]) -> None:
        unknown = set(command.payload) - allowed
        if unknown:
            raise RootingPlanningError(
                "invalid_rooting_payload",
                f"unsupported semantic field: {sorted(unknown)[0]}",
            )


def parse_root_module_list(stdout: str) -> tuple[RootModuleInfo, ...]:
    """Parse fixed ``ls`` output without promoting malformed names to IDs."""

    modules = {line.strip() for line in stdout.splitlines() if _MODULE_ID_PATTERN.fullmatch(line.strip())}
    return tuple(RootModuleInfo(module_id) for module_id in sorted(modules, key=str.casefold))


__all__ = [
    "ROOTING_COMMANDS",
    "RootApkInspector",
    "RootAppInfo",
    "RootAppSource",
    "RootModuleInfo",
    "RootingCompilation",
    "RootingPlanningError",
    "RootingService",
    "parse_root_module_list",
]
