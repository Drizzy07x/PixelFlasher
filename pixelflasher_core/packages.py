"""Headless Android package management with shell-free, typed plans.

The browser can express a package-management intent, but it can never provide
an executable command line.  This module validates package names and options,
then compiles exact ``adb`` argv tuples which are still evaluated by
``SafetyPolicy`` and revalidated immediately before execution by the engine.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

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

PACKAGE_COMMANDS = frozenset({"apps.list", "apps.action"})

_PACKAGE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$")
_LIST_SCOPES = {
    "all": (),
    "user": ("-3",),
    "system": ("-s",),
    "enabled": ("-e",),
    "disabled": ("-d",),
}
_PACKAGE_ACTIONS = frozenset(
    {
        "enable",
        "disable",
        "uninstall",
        "clearData",
        "forceStop",
        "launch",
        "permissions",
        "install",
    }
)
_DESTRUCTIVE_ACTIONS = frozenset({"uninstall", "clearData"})
_INSTALL_OPTIONS = {
    "replace": "-r",
    "grantPermissions": "-g",
    "allowDowngrade": "-d",
    "allowTest": "-t",
    "forceQueryable": "--force-queryable",
    "bypassLowTargetSdk": "--bypass-low-target-sdk-block",
}


class PackagePlanningError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class PackageResultError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ApkIdentityInspector(Protocol):
    def inspect(
        self,
        path: str | os.PathLike[str],
        *,
        cancellation: CancellationProbe | None = None,
    ) -> ApkIdentity: ...

@dataclass(frozen=True, slots=True)
class PackageInfo:
    package: str
    apk_path: str = ""
    uid: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "package": self.package,
            "apk_path": self.apk_path,
            "uid": self.uid,
        }


@dataclass(frozen=True, slots=True)
class PackageCompilation:
    plan: OperationPlan
    action: str
    destructive: bool = False
    requires_confirmation: bool = False
    apk_identity: ApkIdentity | None = None
    packages: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        value: dict[str, object] = {
            "action": self.action,
            "destructive": self.destructive,
            "requires_confirmation": self.requires_confirmation,
            "plan": self.plan.to_dict(),
        }
        if self.apk_identity is not None:
            value["apkIdentity"] = {
                "packageName": self.apk_identity.package_name,
                "sha256": self.apk_identity.sha256,
                "signerSha256": list(self.apk_identity.signer_sha256),
                "schemes": list(self.apk_identity.schemes),
                "verified": self.apk_identity.verified,
            }
        return value


class PackageService:
    """Compile modern package commands from canonical state and typed intent."""

    def __init__(
        self,
        *,
        hash_chunk_size: int = 1024 * 1024,
        apk_inspector: ApkIdentityInspector | None = None,
    ) -> None:
        if hash_chunk_size <= 0:
            raise ValueError("hash_chunk_size must be positive")
        self.hash_chunk_size = hash_chunk_size
        self.apk_inspector = apk_inspector or ApkInspector()

    def compile(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        cancellation: CancellationProbe | None = None,
    ) -> PackageCompilation:
        self._check_cancelled(cancellation)
        if command.kind not in PACKAGE_COMMANDS:
            raise PackagePlanningError(
                "package_command_unsupported",
                f"unsupported package command: {command.kind}",
            )
        device = self._device(command, snapshot)
        adb = self._adb(snapshot)
        if command.kind == "apps.list":
            return self._compile_list(command, snapshot, device, adb)
        return self._compile_action(
            command,
            snapshot,
            device,
            adb,
            cancellation,
        )

    def _compile_list(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
    ) -> PackageCompilation:
        self._validate_payload(command, {"serial", "scope"})
        raw_scope = command.payload.get("scope", "all")
        if not isinstance(raw_scope, str):
            raise PackagePlanningError("package_scope_invalid", "scope must be a string")
        scope = raw_scope.strip()
        if scope not in _LIST_SCOPES:
            raise PackagePlanningError(
                "package_scope_invalid",
                f"unsupported package scope: {scope}",
            )
        argv = (
            adb,
            "-s",
            device.serial,
            "shell",
            "pm",
            "list",
            "packages",
            "-f",
            "-U",
            *_LIST_SCOPES[scope],
        )
        plan = self._base_plan(
            snapshot,
            device,
            (ProcessRequest(argv, timeout_seconds=30.0),),
            label=f"List {scope} packages on {device.serial}",
        )
        return PackageCompilation(plan, "list")

    def _compile_action(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
        cancellation: CancellationProbe | None,
    ) -> PackageCompilation:
        self._validate_payload(
            command,
            {"serial", "action", "package", "packages", "path", "options"},
        )
        raw_action = command.payload.get("action")
        if not isinstance(raw_action, str) or raw_action not in _PACKAGE_ACTIONS:
            raise PackagePlanningError(
                "package_action_invalid",
                "action is not a supported package operation",
            )
        action = raw_action
        if action == "install":
            return self._compile_install(
                command,
                snapshot,
                device,
                adb,
                cancellation,
            )

        options = self._options(command.payload.get("options"))
        allowed_options: set[str] = {"keepData"} if action == "uninstall" else set()
        unknown_options = set(options) - allowed_options
        if unknown_options:
            raise PackagePlanningError(
                "package_option_invalid",
                f"unsupported option for {action}: {sorted(unknown_options)[0]}",
            )
        packages = self._packages(command.payload)
        if action == "permissions" and len(packages) != 1:
            raise PackagePlanningError(
                "package_permissions_target_invalid",
                "permission inspection requires exactly one package",
            )
        requests = tuple(
            ProcessRequest(
                self._package_argv(adb, device.serial, action, package, options),
                timeout_seconds=120.0 if action in _DESTRUCTIVE_ACTIONS else 30.0,
            )
            for package in packages
        )
        destructive = action in _DESTRUCTIVE_ACTIONS
        state_by_action = {
            "enable": "enabled",
            "disable": "disabled",
            "uninstall": "absent",
            "forceStop": "stopped",
            "launch": "running",
        }
        risk = (
            OperationRisk.READ_ONLY
            if action == "permissions"
            else OperationRisk.DESTRUCTIVE
            if destructive
            else OperationRisk.MUTATING
        )
        if action == "permissions":
            postconditions: tuple[OperationPostcondition, ...] = ()
        elif action == "clearData":
            postconditions = (
                OperationPostcondition(
                    "package_data_cleared",
                    {"packages": packages, "successCount": len(packages)},
                    "pm clear reports one exact success record per selected package",
                ),
                OperationPostcondition(
                    "package_state",
                    {"packages": packages, "state": "installed"},
                    "every cleared package remains installed after the mutation",
                ),
            )
        else:
            postconditions = (
                OperationPostcondition(
                    "package_state",
                    {"packages": packages, "state": state_by_action[action]},
                    "every selected package reports the requested lifecycle state",
                ),
            )
        plan = self._base_plan(
            snapshot,
            device,
            requests,
            label=f"{action} {len(packages)} package(s) on {device.serial}",
            data_behavior=action if destructive else "preserve",
            risk=risk,
            postconditions=postconditions,
        )
        return PackageCompilation(
            plan,
            action,
            destructive=destructive,
            requires_confirmation=action != "permissions",
            packages=packages,
        )

    def _compile_install(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
        cancellation: CancellationProbe | None,
    ) -> PackageCompilation:
        if "package" in command.payload or "packages" in command.payload:
            raise PackagePlanningError(
                "package_install_target_invalid",
                "APK install accepts a canonical file path, not a package name",
            )
        raw_path = command.payload.get("path")
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise PackagePlanningError("apk_path_required", "an APK path is required")
        try:
            path = Path(raw_path).expanduser().resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as error:
            raise PackagePlanningError("apk_path_invalid", str(error)) from error
        if not path.is_file() or path.suffix.casefold() != ".apk":
            raise PackagePlanningError(
                "apk_path_invalid",
                "the selected path must be an existing .apk file",
            )
        options = self._options(command.payload.get("options"))
        unknown_options = set(options) - set(_INSTALL_OPTIONS)
        if unknown_options:
            raise PackagePlanningError(
                "package_option_invalid",
                f"unsupported install option: {sorted(unknown_options)[0]}",
            )
        for key, value in options.items():
            if not isinstance(value, bool):
                raise PackagePlanningError(
                    "package_option_invalid",
                    f"install option {key} must be a boolean",
                )

        self._check_cancelled(cancellation)
        try:
            identity = self.apk_inspector.inspect(
                path,
                cancellation=cancellation,
            )
        except ApkInspectionError as error:
            self._check_cancelled(cancellation)
            if error.code is ApkInspectionCode.CANCELLED:
                raise PackagePlanningError(
                    "package_cancelled",
                    "package planning was cancelled",
                ) from error
            raise PackagePlanningError(error.code.value, str(error)) from error
        except (OSError, TypeError, ValueError) as error:
            self._check_cancelled(cancellation)
            raise PackagePlanningError(
                "apk_inspection_failed",
                "APK identity verification failed",
            ) from error
        self._check_cancelled(cancellation)
        if not isinstance(identity, ApkIdentity) or not identity.verified:
            raise PackagePlanningError(
                "apk_identity_unverified",
                "APK inspection did not return a verified identity",
            )
        artifact = FileArtifact(str(path), identity.sha256, "apk")
        flags = tuple(flag for key, flag in _INSTALL_OPTIONS.items() if options.get(key) is True)
        request = ProcessRequest(
            (adb, "-s", device.serial, "install", *flags, str(path)),
            timeout_seconds=600.0,
        )
        plan = self._base_plan(
            snapshot,
            device,
            (request,),
            label=f"Install {identity.package_name} on {device.serial}",
            artifacts=(artifact,),
            risk=OperationRisk.MUTATING,
            postconditions=(
                OperationPostcondition(
                    "package_state",
                    {"packages": (identity.package_name,), "state": "installed"},
                    "the cryptographically verified APK package is installed on the device",
                ),
            ),
        )
        return PackageCompilation(
            plan,
            "install",
            requires_confirmation=True,
            apk_identity=identity,
            packages=(identity.package_name,),
        )

    @staticmethod
    def _check_cancelled(cancellation: CancellationProbe | None) -> None:
        if cancellation is not None and cancellation.cancelled:
            raise PackagePlanningError(
                "package_cancelled",
                "package planning was cancelled",
            )

    @staticmethod
    def _package_argv(
        adb: str,
        serial: str,
        action: str,
        package: str,
        options: Mapping[str, object],
    ) -> tuple[str, ...]:
        prefix = (adb, "-s", serial, "shell")
        if action == "enable":
            return (*prefix, "pm", "enable", "--user", "0", package)
        if action == "disable":
            return (*prefix, "pm", "disable-user", "--user", "0", package)
        if action == "uninstall":
            keep_data = ("-k",) if options.get("keepData") is True else ()
            return (*prefix, "pm", "uninstall", *keep_data, "--user", "0", package)
        if action == "clearData":
            return (*prefix, "pm", "clear", "--user", "0", package)
        if action == "forceStop":
            return (*prefix, "am", "force-stop", "--user", "0", package)
        if action == "launch":
            return (
                *prefix,
                "monkey",
                "-p",
                package,
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            )
        if action == "permissions":
            return (*prefix, "dumpsys", "package", package)
        raise AssertionError(f"unhandled package action: {action}")

    @staticmethod
    def _options(raw_options: object) -> Mapping[str, object]:
        if raw_options is None:
            return {}
        if not isinstance(raw_options, Mapping):
            raise PackagePlanningError("package_option_invalid", "options must be an object")
        values = cast(Mapping[object, object], raw_options)
        if any(not isinstance(key, str) for key in values):
            raise PackagePlanningError("package_option_invalid", "option names must be strings")
        return {cast(str, key): value for key, value in values.items()}

    @staticmethod
    def _packages(payload: Mapping[str, object]) -> tuple[str, ...]:
        raw_package = payload.get("package")
        raw_packages = payload.get("packages")
        if raw_package is not None and raw_packages is not None:
            raise PackagePlanningError(
                "package_target_ambiguous",
                "provide package or packages, not both",
            )
        if raw_package is not None:
            values: Sequence[object] = (raw_package,)
        elif isinstance(raw_packages, Sequence) and not isinstance(raw_packages, (str, bytes)):
            values = cast(Sequence[object], raw_packages)
        else:
            raise PackagePlanningError(
                "package_target_required",
                "one or more package names are required",
            )
        if not values or len(values) > 100:
            raise PackagePlanningError(
                "package_target_invalid",
                "between 1 and 100 package names are required",
            )
        normalized: list[str] = []
        for raw_value in values:
            if not isinstance(raw_value, str):
                raise PackagePlanningError(
                    "package_name_invalid",
                    "package names must be strings",
                )
            package = raw_value.strip()
            if not _PACKAGE_PATTERN.fullmatch(package):
                raise PackagePlanningError(
                    "package_name_invalid",
                    f"invalid Android package name: {package}",
                )
            if package not in normalized:
                normalized.append(package)
        return tuple(normalized)

    @staticmethod
    def _device(command: AppCommand, snapshot: AppSnapshot) -> DeviceInfo:
        raw_serial = command.payload.get("serial")
        if raw_serial is not None and (not isinstance(raw_serial, str) or not raw_serial.strip()):
            raise PackagePlanningError(
                "target_serial_invalid",
                "payload.serial must be a non-empty string",
            )
        serial = command.target_serial or (
            raw_serial.strip() if isinstance(raw_serial, str) else snapshot.selected_serial
        )
        if not serial:
            raise PackagePlanningError(
                "target_serial_required",
                "one selected device is required",
            )
        if command.target_serial and raw_serial and command.target_serial != raw_serial.strip():
            raise PackagePlanningError(
                "ambiguous_target_serial",
                "command and payload target different devices",
            )
        if serial not in snapshot.selected_serials:
            raise PackagePlanningError(
                "target_serial_changed",
                "target serial is no longer selected",
            )
        device = next((item for item in snapshot.devices if item.serial == serial), None)
        if device is None or not device.online:
            raise PackagePlanningError(
                "device_disconnected",
                "target device is not online",
            )
        if device.mode != "adb":
            raise PackagePlanningError(
                "adb_device_required",
                "package operations require a device in adb mode",
            )
        return device

    @staticmethod
    def _adb(snapshot: AppSnapshot) -> str:
        if not snapshot.toolchain.ready or not snapshot.toolchain.adb:
            raise PackagePlanningError(
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
            raise PackagePlanningError(
                "invalid_package_payload",
                f"unsupported semantic field: {sorted(unknown)[0]}",
            )


def parse_package_list(stdout: str) -> tuple[PackageInfo, ...]:
    """Parse ``pm list packages -f -U`` without trusting malformed rows."""

    packages: dict[str, PackageInfo] = {}
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line.startswith("package:"):
            continue
        body = line.removeprefix("package:").strip()
        uid: int | None = None
        uid_match = re.search(r"(?:^|\s)uid:(\d+)(?:\s|$)", body)
        if uid_match:
            try:
                uid = int(uid_match.group(1))
            except ValueError:
                uid = None
            body = (body[: uid_match.start()] + body[uid_match.end() :]).strip()
        if "=" in body:
            apk_path, package = body.rsplit("=", 1)
            apk_path = apk_path.strip()
            package = package.strip()
        else:
            apk_path = ""
            package = body.strip()
        if not _PACKAGE_PATTERN.fullmatch(package):
            continue
        packages[package] = PackageInfo(package, apk_path, uid)
    return tuple(packages[key] for key in sorted(packages, key=str.casefold))


_PERMISSION_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_.]{1,255}$")
_RUNTIME_PERMISSION = re.compile(
    r"^([A-Za-z][A-Za-z0-9_.]{1,255}):\s+granted=(true|false)(?:,.*)?$"
)


def parse_package_permissions(stdout: str, package: str) -> dict[str, object]:
    """Return a bounded permission report from one exact dumpsys package result."""

    if not _PACKAGE_PATTERN.fullmatch(package):
        raise PackageResultError(
            "package_name_invalid", "permission report package name is invalid"
        )
    if len(stdout.encode("utf-8", errors="replace")) > 512 * 1024:
        raise PackageResultError(
            "package_permissions_oversized", "permission report exceeds its byte limit"
        )
    if re.search(rf"(?m)^\s*Package \[{re.escape(package)}\]", stdout) is None:
        raise PackageResultError(
            "package_permissions_unverified",
            "dumpsys output does not identify the requested package",
        )

    requested: set[str] = set()
    runtime_granted: set[str] = set()
    runtime_denied: set[str] = set()
    in_requested = False
    requested_header = False
    for raw_line in stdout.splitlines():
        stripped = raw_line.strip()
        if stripped == "requested permissions:":
            requested_header = True
            in_requested = True
            continue
        if in_requested:
            if raw_line.startswith(("      ", "\t")) and _PERMISSION_PATTERN.fullmatch(
                stripped
            ):
                requested.add(stripped)
                if len(requested) > 512:
                    raise PackageResultError(
                        "package_permissions_oversized",
                        "permission report contains too many requested permissions",
                    )
                continue
            if stripped:
                in_requested = False
        match = _RUNTIME_PERMISSION.fullmatch(stripped)
        if match:
            target = runtime_granted if match.group(2) == "true" else runtime_denied
            target.add(match.group(1))
            if len(runtime_granted) + len(runtime_denied) > 512:
                raise PackageResultError(
                    "package_permissions_oversized",
                    "permission report contains too many runtime permissions",
                )
    if not requested_header:
        raise PackageResultError(
            "package_permissions_unverified",
            "dumpsys output has no requested-permissions section",
        )
    granted = tuple(sorted(runtime_granted, key=str.casefold))
    denied = tuple(sorted(runtime_denied - runtime_granted, key=str.casefold))
    requested_values = tuple(sorted(requested, key=str.casefold))
    return {
        "package": package,
        "requested": requested_values,
        "runtimeGranted": granted,
        "runtimeDenied": denied,
        "requestedCount": len(requested_values),
        "runtimeCount": len(granted) + len(denied),
        "bounded": True,
    }


__all__ = [
    "PACKAGE_COMMANDS",
    "PackageCompilation",
    "PackageInfo",
    "ApkIdentityInspector",
    "PackagePlanningError",
    "PackageResultError",
    "PackageService",
    "parse_package_list",
    "parse_package_permissions",
]
