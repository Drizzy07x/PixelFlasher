"""Headless, fail-closed planning for root apps and Magisk modules.

Root-app inventory is supplied by backend-owned sources and is never populated
from browser metadata.  Device operations compile exact, serial-bound ADB argv
and attach canonical SHA-256 artifacts.  Module management accepts only fixed
Magisk operations and validated module IDs; no caller-provided shell text can
cross the process boundary.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import stat
import threading
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Protocol
from urllib.parse import urlsplit

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
        "root.pif.inventory",
        "tools.pif",
        "tools.piAnalysis",
        "tools.shizuku",
        "tools.sos",
    }
)

_PROVENANCE = frozenset({"official", "verified-download", "bundled", "user-import"})
_VERIFIED_PROVENANCE = frozenset({"official", "verified-download", "bundled"})
_METADATA_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. +()-]{0,63}$")
_MODULE_ID_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
_PACKAGE_NAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_ARCHITECTURE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_MODULE_ACTIONS = frozenset({"install", "enable", "disable", "remove"})
_MODULE_REMOTE_ROOT = "/data/local/tmp/"
_MAX_ZIP_ENTRIES = 4096
_MAX_ZIP_UNCOMPRESSED = 512 * 1024 * 1024
_MODULE_LIST_PREFIX = "PF_RM"
_MAX_MODULES = 256
_MAX_MODULE_LIST_BYTES = 256 * 1024
_PI_ANALYSIS_PREFIX = "PF_PI"
_MAX_PI_ANALYSIS_BYTES = 256 * 1024
_MAX_PI_MODULES = 256
_PI_CONFIG_KINDS = (
    "pif_custom_json",
    "pif_custom_prop",
    "pif_module_json",
    "pif_legacy_json",
    "pif_app_replace",
    "pif_scripts_only",
    "tricky_spoof",
    "tricky_target",
    "tricky_security_patch",
    "tricky_tee",
    "targeted_targets",
    "keybox",
)
_PI_PACKAGE_IDS = frozenset({"gms", "play_store"})
_PI_MODULE_STATE = frozenset({"enabled", "disabled", "pending_remove", "corrupt"})
_PI_WITHHELD = (
    "android_ids",
    "device_serial",
    "keybox_material",
    "raw_config_contents",
    "raw_logs",
    "target_package_names",
)
_PIF_INVENTORY_PREFIX = "PF_PIF"
_MAX_PIF_INVENTORY_BYTES = 128 * 1024
_MAX_PIF_TARGETS = 256
_PIF_PROFILE_SPECS = (
    ("pif.custom_json", "playintegrityfix", "json"),
    ("pif.custom_prop", "playintegrityfix", "prop"),
    ("pif.module_json", "playintegrityfix", "json"),
    ("pif.legacy_json", "playintegrityfix", "json"),
    ("pif.app_replace", "playintegrityfix", "list"),
    ("pif.scripts_only", "playintegrityfix", "marker"),
    ("tricky.spoof", "tricky_store", "prop"),
    ("tricky.target", "tricky_store", "list"),
    ("tricky.security_patch", "tricky_store", "text"),
    ("tricky.tee", "tricky_store", "text"),
    ("targeted.targets", "targetedfix", "list"),
)
_PIF_PROFILE_ID_PATTERN = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
_PIF_PROFILE_PATHS = {
    "pif.custom_json": "/data/adb/modules/playintegrityfix/custom.pif.json",
    "pif.custom_prop": "/data/adb/modules/playintegrityfix/custom.pif.prop",
    "pif.module_json": "/data/adb/modules/playintegrityfix/pif.json",
    "pif.legacy_json": "/data/adb/pif.json",
    "pif.app_replace": "/data/adb/modules/playintegrityfix/custom.app_replace.list",
    "pif.scripts_only": "/data/adb/modules/playintegrityfix/scripts-only-mode",
    "tricky.spoof": "/data/adb/tricky_store/spoof_build_vars",
    "tricky.target": "/data/adb/tricky_store/target.txt",
    "tricky.security_patch": "/data/adb/tricky_store/security_patch.txt",
    "tricky.tee": "/data/adb/tricky_store/tee_status",
    "targeted.targets": "/data/adb/modules/targetedfix/config/target.txt",
}
_MAX_PIF_IMPORT_BYTES = 1024 * 1024
_PIF_PROPERTY_KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")


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
    expected_signer_sha256: tuple[str, ...] = ()
    architecture: str = "universal"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "expected_signer_sha256",
            tuple(self.expected_signer_sha256),
        )


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
    architecture: str = "universal"

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
            "architecture": self.architecture,
        }


@dataclass(frozen=True, slots=True)
class RootModuleInfo:
    id: str
    name: str
    version: str
    version_code: int | None
    author: str
    description: str
    state: str
    update_url: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "versionCode": self.version_code,
            "author": self.author,
            "description": self.description,
            "state": self.state,
            "updateMetadata": (
                "available" if self.update_url else "absent"
            ),
        }


@dataclass(frozen=True, slots=True)
class PifProfileInfo:
    id: str
    module: str
    format: str
    present: bool
    size: int
    sha256: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "module": self.module,
            "format": self.format,
            "present": self.present,
            "size": self.size,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class PifTargetInfo:
    package_name: str
    present: bool
    size: int
    sha256: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "packageName": self.package_name,
            "format": "json",
            "present": self.present,
            "size": self.size,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class PifImportInspection:
    profile_id: str
    format: str
    size: int
    sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "profileId": self.profile_id,
            "format": self.format,
            "size": self.size,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class RootingCompilation:
    """A local result or process plan plus backend-owned safety metadata."""

    action: str
    plan: OperationPlan | None = None
    root_apps: tuple[RootAppInfo, ...] = ()
    module_id: str | None = None
    pif_profile_id: str | None = None
    pif_target_package: str | None = None
    pif_sha256: str | None = None
    pif_size: int | None = None
    device_build: str | None = None
    device_write: bool = False
    destructive: bool = False
    requires_confirmation: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "plan": self.plan.to_dict() if self.plan is not None else None,
            "root_apps": [item.to_dict() for item in self.root_apps],
            "module_id": self.module_id,
            "pif_profile_id": self.pif_profile_id,
            "pif_target_package": self.pif_target_package,
            "pif_sha256": self.pif_sha256,
            "pif_size": self.pif_size,
            "device_build": self.device_build,
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
        self._root_app_sources = tuple(root_app_sources)
        self._root_app_sources_lock = threading.RLock()
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
        if command.kind == "tools.shizuku":
            return self._compile_shizuku(command, snapshot, device, adb)
        if command.kind == "tools.sos":
            if not device.root:
                raise RootingPlanningError(
                    "root_access_required",
                    "SOS module recovery requires a device reporting root access",
                )
            return self._compile_sos(command, snapshot, device, adb)
        if command.kind == "tools.piAnalysis":
            if not device.root:
                raise RootingPlanningError(
                    "root_access_required",
                    "Play Integrity analysis requires a device reporting root access",
                )
            return self._compile_pi_analysis(command, snapshot, device, adb)
        if command.kind == "root.pif.inventory":
            if not device.root:
                raise RootingPlanningError(
                    "root_access_required",
                    "PIF inventory requires a device reporting root access",
                )
            return self._compile_pif_inventory(command, snapshot, device, adb)
        if command.kind == "tools.pif":
            if not device.root:
                raise RootingPlanningError(
                    "root_access_required",
                    "PIF profile changes require a device reporting root access",
                )
            return self._compile_pif_action(command, snapshot, device, adb)
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

    def _compile_pif_inventory(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
    ) -> RootingCompilation:
        self._validate_payload(command, {"serial"})
        file_specs = (
            ("pif.custom_json", "/data/adb/modules/playintegrityfix/custom.pif.json", "playintegrityfix", "json"),
            ("pif.custom_prop", "/data/adb/modules/playintegrityfix/custom.pif.prop", "playintegrityfix", "prop"),
            ("pif.module_json", "/data/adb/modules/playintegrityfix/pif.json", "playintegrityfix", "json"),
            ("pif.legacy_json", "/data/adb/pif.json", "playintegrityfix", "json"),
            ("pif.app_replace", "/data/adb/modules/playintegrityfix/custom.app_replace.list", "playintegrityfix", "list"),
            ("pif.scripts_only", "/data/adb/modules/playintegrityfix/scripts-only-mode", "playintegrityfix", "marker"),
            ("tricky.spoof", "/data/adb/tricky_store/spoof_build_vars", "tricky_store", "prop"),
            ("tricky.target", "/data/adb/tricky_store/target.txt", "tricky_store", "list"),
            ("tricky.security_patch", "/data/adb/tricky_store/security_patch.txt", "tricky_store", "text"),
            ("tricky.tee", "/data/adb/tricky_store/tee_status", "tricky_store", "text"),
            ("targeted.targets", "/data/adb/modules/targetedfix/config/target.txt", "targetedfix", "list"),
        )
        fixed_calls = " ".join(
            f"pf_profile {profile_id} {path} {module} {profile_format};"
            for profile_id, path, module, profile_format in file_specs
        )
        script = (
            f"printf '{_PIF_INVENTORY_PREFIX}|schema|1\\n'; "
            "uid=$(id -u 2>/dev/null); [ \"$uid\" = 0 ] || { "
            f"printf '{_PIF_INVENTORY_PREFIX}|root|missing\\n'; exit 71; }}; "
            f"printf '{_PIF_INVENTORY_PREFIX}|root|verified\\n'; "
            "pf_b64() { printf '%s' \"$1\" | base64 | tr -d '\\r\\n'; }; "
            "pf_profile() { key=$1; file=$2; module=$3; format=$4; "
            "if [ -f \"$file\" ]; then size=$(wc -c < \"$file\" 2>/dev/null | tr -d ' '); "
            "case \"$size\" in ''|*[!0-9]*) size=0;; esac; "
            "digest=$(sha256sum \"$file\" 2>/dev/null | cut -d ' ' -f 1); "
            "case \"$digest\" in [0-9a-f][0-9a-f][0-9a-f]*) ;; *) digest=-;; esac; "
            f"printf '{_PIF_INVENTORY_PREFIX}|profile|%s|%s|%s|present|%s|%s\\n' \"$key\" \"$module\" \"$format\" \"$size\" \"$digest\"; "
            f"else printf '{_PIF_INVENTORY_PREFIX}|profile|%s|%s|%s|absent|0|-\\n' \"$key\" \"$module\" \"$format\"; fi; }}; "
            f"{fixed_calls} "
            "target_file=/data/adb/modules/targetedfix/config/target.txt; count=0; "
            "if [ -f \"$target_file\" ]; then while IFS= read -r target; do "
            "case \"$target\" in ''|*[!A-Za-z0-9_.]*) continue;; esac; "
            "case \"$target\" in [A-Za-z]*) ;; *) continue;; esac; "
            "[ \"${#target}\" -le 255 ] || continue; file=/data/adb/modules/targetedfix/config/$target.json; "
            "if [ -f \"$file\" ]; then size=$(wc -c < \"$file\" 2>/dev/null | tr -d ' '); "
            "case \"$size\" in ''|*[!0-9]*) size=0;; esac; digest=$(sha256sum \"$file\" 2>/dev/null | cut -d ' ' -f 1); "
            "case \"$digest\" in [0-9a-f][0-9a-f][0-9a-f]*) ;; *) digest=-;; esac; status=present; "
            "else size=0; digest=-; status=absent; fi; "
            f"printf '{_PIF_INVENTORY_PREFIX}|target|%s|json|%s|%s|%s\\n' \"$(pf_b64 \"$target\")\" \"$status\" \"$size\" \"$digest\"; "
            f"count=$((count + 1)); [ \"$count\" -lt {_MAX_PIF_TARGETS} ] || break; done < \"$target_file\"; fi; "
            f"printf '{_PIF_INVENTORY_PREFIX}|complete|1\\n'"
        )
        request = ProcessRequest(
            (adb, "-s", device.serial, "shell", "su", "-c", script),
            timeout_seconds=60.0,
            output_limit_bytes=_MAX_PIF_INVENTORY_BYTES,
        )
        return RootingCompilation(
            "pif.inventory",
            self._base_plan(
                snapshot,
                device,
                (request,),
                label=f"List PIF and TargetedFix profiles on {device.serial}",
            ),
        )

    def _compile_pif_action(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
    ) -> RootingCompilation:
        self._validate_payload(
            command,
            {"serial", "action", "profileId", "targetPackage", "confirmationText", "path"},
        )
        action = command.payload.get("action")
        if action not in {"deleteProfile", "importProfile", "addTarget", "deleteTarget"}:
            raise RootingPlanningError(
                "pif_action_invalid",
                "PIF action is not supported",
            )
        assert isinstance(action, str)
        if action in {"addTarget", "deleteTarget"}:
            return self._compile_targeted_fix_action(command, snapshot, device, adb, action)
        profile_id = command.payload.get("profileId")
        if not isinstance(profile_id, str) or profile_id not in _PIF_PROFILE_PATHS:
            raise RootingPlanningError("pif_profile_invalid", "PIF profile ID is not canonical")
        verb = "DELETE" if action == "deleteProfile" else "IMPORT"
        required = f"{verb} PIF {profile_id} {device.serial[-6:].upper()}"
        if command.payload.get("confirmationText") != required:
            raise RootingPlanningError(
                "pif_confirmation_required",
                f"confirmationText must be exactly {required}",
            )
        path = _PIF_PROFILE_PATHS[profile_id]
        if action == "importProfile":
            source = self._input_file(
                command.payload.get("path"),
                suffix="",
                missing_code="pif_import_source_invalid",
            )
            try:
                with source.open("rb") as stream:
                    inspection = inspect_pif_profile_stream(profile_id, stream)
            except OSError as error:
                raise RootingPlanningError(
                    "pif_import_source_invalid",
                    "PIF import source could not be read",
                ) from error
            artifact = FileArtifact(str(source), inspection.sha256, f"pif-profile:{profile_id}")
            remote = f"/data/local/tmp/pixelflasher-pif-{inspection.sha256[:16]}.tmp"
            parent = path.rsplit("/", 1)[0]
            install_script = (
                f"mkdir -p {parent} && cp {remote} {path} && chmod 0600 {path}; "
                f"status=$?; rm -f -- {remote}; exit $status"
            )
            requests = (
                ProcessRequest((adb, "-s", device.serial, "push", str(source), remote), timeout_seconds=120.0),
                ProcessRequest(
                    (adb, "-s", device.serial, "shell", "su", "-c", install_script),
                    timeout_seconds=30.0,
                    output_limit_bytes=16 * 1024,
                ),
            )
            return RootingCompilation(
                "pif.import_profile",
                self._base_plan(
                    snapshot,
                    device,
                    requests,
                    label=f"Import PIF profile {profile_id} on {device.serial}",
                    data_behavior="pif_profile_import",
                    artifacts=(artifact,),
                    risk=OperationRisk.DESTRUCTIVE,
                    postconditions=(
                        OperationPostcondition(
                            "pif_profile_hash",
                            {"profileId": profile_id, "sha256": inspection.sha256},
                            "the imported PIF profile matches the granted source",
                        ),
                    ),
                ),
                pif_profile_id=profile_id,
                pif_sha256=inspection.sha256,
                pif_size=inspection.size,
                device_write=True,
                destructive=True,
                requires_confirmation=True,
            )
        if "path" in command.payload:
            raise RootingPlanningError("pif_import_source_ambiguous", "PIF deletion does not accept a source")
        request = ProcessRequest(
            (adb, "-s", device.serial, "shell", "su", "-c", f"rm -f -- {path}"),
            timeout_seconds=30.0,
            output_limit_bytes=16 * 1024,
        )
        return RootingCompilation(
            "pif.delete_profile",
            self._base_plan(
                snapshot,
                device,
                (request,),
                label=f"Delete PIF profile {profile_id} on {device.serial}",
                data_behavior="pif_profile_delete",
                risk=OperationRisk.DESTRUCTIVE,
                postconditions=(
                    OperationPostcondition(
                        "pif_profile_state",
                        {"profileId": profile_id, "present": False},
                        "the selected PIF profile is absent",
                    ),
                ),
            ),
            pif_profile_id=profile_id,
            device_write=True,
            destructive=True,
            requires_confirmation=True,
        )

    def _compile_targeted_fix_action(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
        action: str,
    ) -> RootingCompilation:
        if "profileId" in command.payload or "path" in command.payload:
            raise RootingPlanningError(
                "targeted_fix_payload_ambiguous",
                "TargetedFix target changes do not accept a profile or source path",
            )
        package = command.payload.get("targetPackage")
        if not isinstance(package, str) or _PACKAGE_NAME_PATTERN.fullmatch(package) is None:
            raise RootingPlanningError(
                "targeted_fix_package_invalid",
                "TargetedFix package ID is invalid",
            )
        verb = "ADD" if action == "addTarget" else "DELETE"
        required = f"{verb} TARGET {package} {device.serial[-6:].upper()}"
        if command.payload.get("confirmationText") != required:
            raise RootingPlanningError(
                "targeted_fix_confirmation_required",
                f"confirmationText must be exactly {required}",
            )
        config = "/data/adb/modules/targetedfix/config"
        target_file = f"{config}/target.txt"
        nonce = hashlib.sha256(package.encode("utf-8")).hexdigest()[:16]
        temporary = f"{config}/.pixelflasher-targets-{nonce}.tmp"
        if action == "addTarget":
            script = (
                "[ -d /data/adb/modules/targetedfix ] || exit 72; "
                f"pm path {package} >/dev/null 2>&1 || exit 73; "
                f"mkdir -p {config} || exit 74; "
                f"if [ -f {target_file} ]; then "
                f"size=$(wc -c < {target_file} 2>/dev/null | tr -d ' '); "
                "case \"$size\" in ''|*[!0-9]*) exit 75;; esac; "
                f"[ \"$size\" -le {_MAX_PIF_IMPORT_BYTES} ] || exit 76; "
                f"cp -- {target_file} {temporary} || exit 77; "
                f"else : > {temporary} || exit 77; fi; "
                f"grep -Fxq -- {package} {temporary} || printf '%s\\n' {package} >> {temporary} || "
                f"{{ rm -f -- {temporary}; exit 78; }}; "
                f"chmod 0600 {temporary} && mv -f -- {temporary} {target_file}"
            )
            risk = OperationRisk.MUTATING
            behavior = "targeted_fix_target_add"
            present = True
            label = f"Add TargetedFix target {package} on {device.serial}"
        else:
            script = (
                "[ -d /data/adb/modules/targetedfix ] || exit 72; "
                f"if [ -f {target_file} ]; then "
                f"size=$(wc -c < {target_file} 2>/dev/null | tr -d ' '); "
                "case \"$size\" in ''|*[!0-9]*) exit 75;; esac; "
                f"[ \"$size\" -le {_MAX_PIF_IMPORT_BYTES} ] || exit 76; "
                f"grep -Fxv -- {package} {target_file} > {temporary}; status=$?; "
                f"[ \"$status\" -le 1 ] || {{ rm -f -- {temporary}; exit 77; }}; "
                f"chmod 0600 {temporary} && mv -f -- {temporary} {target_file} || exit 78; fi; "
                f"rm -f -- {config}/{package}.json {config}/{package}.prop"
            )
            risk = OperationRisk.DESTRUCTIVE
            behavior = "targeted_fix_target_delete"
            present = False
            label = f"Delete TargetedFix target {package} on {device.serial}"
        request = ProcessRequest(
            (adb, "-s", device.serial, "shell", "su", "-c", script),
            timeout_seconds=30.0,
            output_limit_bytes=16 * 1024,
        )
        return RootingCompilation(
            "pif.add_target" if action == "addTarget" else "pif.delete_target",
            self._base_plan(
                snapshot,
                device,
                (request,),
                label=label,
                data_behavior=behavior,
                risk=risk,
                postconditions=(
                    OperationPostcondition(
                        "targeted_fix_target_state",
                        {"packageName": package, "present": present},
                        "the TargetedFix target list matches the requested state",
                    ),
                ),
            ),
            pif_target_package=package,
            device_write=True,
            destructive=action == "deleteTarget",
            requires_confirmation=True,
        )

    def _compile_pi_analysis(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
    ) -> RootingCompilation:
        """Compile one fixed, read-only and privacy-bounded integrity probe."""

        self._validate_payload(command, {"serial", "action"})
        if command.payload.get("action") != "analyze":
            raise RootingPlanningError(
                "pi_analysis_action_invalid",
                "Play Integrity analysis action must be exactly analyze",
            )
        # Browser input never enters this script.  Raw configuration contents,
        # Android identifiers, target package names, keybox certificates and
        # logcat are deliberately excluded at the collection boundary.
        config_specs = (
            ("pif_custom_json", "/data/adb/modules/playintegrityfix/custom.pif.json", True),
            ("pif_custom_prop", "/data/adb/modules/playintegrityfix/custom.pif.prop", True),
            ("pif_module_json", "/data/adb/modules/playintegrityfix/pif.json", True),
            ("pif_legacy_json", "/data/adb/pif.json", True),
            ("pif_app_replace", "/data/adb/modules/playintegrityfix/custom.app_replace.list", True),
            ("pif_scripts_only", "/data/adb/modules/playintegrityfix/scripts-only-mode", True),
            ("tricky_spoof", "/data/adb/tricky_store/spoof_build_vars", True),
            ("tricky_target", "/data/adb/tricky_store/target.txt", True),
            ("tricky_security_patch", "/data/adb/tricky_store/security_patch.txt", True),
            ("tricky_tee", "/data/adb/tricky_store/tee_status", True),
            ("targeted_targets", "/data/adb/modules/targetedfix/config/target.txt", True),
            # Even a keybox digest can identify privately shared material, so
            # only presence and bounded size are returned for this entry.
            ("keybox", "/data/adb/tricky_store/keybox.xml", False),
        )
        config_commands = " ".join(
            f"pf_file {kind} {path} {'1' if include_hash else '0'};"
            for kind, path, include_hash in config_specs
        )
        script = (
            f"printf '{_PI_ANALYSIS_PREFIX}|schema|1\\n'; "
            "uid=$(id -u 2>/dev/null); [ \"$uid\" = 0 ] || { "
            f"printf '{_PI_ANALYSIS_PREFIX}|root|missing\\n'; exit 71; }}; "
            f"printf '{_PI_ANALYSIS_PREFIX}|root|verified\\n'; "
            "tags=$(getprop ro.build.tags 2>/dev/null | head -c 128); "
            "case \"$tags\" in *test-keys*) test_keys=true;; *) test_keys=false;; esac; "
            f"printf '{_PI_ANALYSIS_PREFIX}|testKeys|%s\\n' \"$test_keys\"; "
            "if [ -r /debug_ramdisk/.magisk/rootdir/system/etc/hosts ] || "
            "[ -r /debug_ramdisk/.magisk/rootdir ]; then overlay=true; else overlay=false; fi; "
            f"printf '{_PI_ANALYSIS_PREFIX}|overlayVisible|%s\\n' \"$overlay\"; "
            "pf_b64() { printf '%s' \"$1\" | base64 | tr -d '\\r\\n'; }; "
            "pf_pkg() { key=$1; pkg=$2; "
            "dump=$(dumpsys package \"$pkg\" 2>/dev/null | head -c 262144); "
            "version=$(printf '%s\\n' \"$dump\" | sed -n 's/^[[:space:]]*versionName=//p' | head -n 1 | head -c 128); "
            "code=$(printf '%s\\n' \"$dump\" | sed -n 's/^[[:space:]]*versionCode=\\([0-9]*\\).*/\\1/p' | head -n 1); "
            "case \"$code\" in ''|*[!0-9]*) code=0;; esac; "
            "if [ -n \"$version\" ] || [ \"$code\" != 0 ]; then installed=true; else installed=false; fi; "
            f"printf '{_PI_ANALYSIS_PREFIX}|package|%s|%s|%s|%s\\n' \"$key\" \"$installed\" \"$(pf_b64 \"$version\")\" \"$code\"; }}; "
            "pf_pkg gms com.google.android.gms; pf_pkg play_store com.android.vending; "
            "count=0; for dir in /data/adb/modules/*; do [ -d \"$dir\" ] || continue; "
            "id=${dir##*/}; case \"$id\" in *[!A-Za-z0-9._-]*|'') continue;; esac; "
            "[ \"${#id}\" -le 64 ] || continue; "
            "if [ -f \"$dir/remove\" ]; then state=pending_remove; "
            "elif [ -f \"$dir/disable\" ]; then state=disabled; "
            "elif [ -f \"$dir/module.prop\" ]; then state=enabled; else state=corrupt; fi; "
            f"printf '{_PI_ANALYSIS_PREFIX}|module|%s|%s\\n' \"$(pf_b64 \"$id\")\" \"$state\"; "
            f"count=$((count + 1)); [ \"$count\" -lt {_MAX_PI_MODULES} ] || break; done; "
            "pf_file() { key=$1; file=$2; hash_allowed=$3; "
            "if [ -f \"$file\" ]; then size=$(wc -c < \"$file\" 2>/dev/null | tr -d ' '); "
            "case \"$size\" in ''|*[!0-9]*) size=0;; esac; digest=-; "
            "if [ \"$hash_allowed\" = 1 ]; then digest=$(sha256sum \"$file\" 2>/dev/null | cut -d ' ' -f 1); "
            "case \"$digest\" in [0-9a-f][0-9a-f][0-9a-f]*) ;; *) digest=-;; esac; fi; "
            f"printf '{_PI_ANALYSIS_PREFIX}|config|%s|present|%s|%s\\n' \"$key\" \"$size\" \"$digest\"; "
            f"else printf '{_PI_ANALYSIS_PREFIX}|config|%s|absent|0|-\\n' \"$key\"; fi; }}; "
            f"{config_commands} "
            "targets=0; if [ -f /data/adb/modules/targetedfix/config/target.txt ]; then "
            "targets=$(sed -n '/^[A-Za-z][A-Za-z0-9_.]*$/p' /data/adb/modules/targetedfix/config/target.txt 2>/dev/null | head -n 256 | wc -l | tr -d ' '); fi; "
            "case \"$targets\" in ''|*[!0-9]*) targets=0;; esac; "
            f"printf '{_PI_ANALYSIS_PREFIX}|targetCount|%s\\n' \"$targets\"; "
            "deny=0; if command -v magisk >/dev/null 2>&1; then deny=$(magisk --denylist ls 2>/dev/null | head -n 2048 | wc -l | tr -d ' '); fi; "
            "case \"$deny\" in ''|*[!0-9]*) deny=0;; esac; "
            f"printf '{_PI_ANALYSIS_PREFIX}|denylistCount|%s\\n' \"$deny\"; "
            "droid=0; if [ -d /data/data/com.google.android.gms/app_dg_cache ]; then "
            "droid=$(find /data/data/com.google.android.gms/app_dg_cache -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -n 512 | wc -l | tr -d ' '); fi; "
            "case \"$droid\" in ''|*[!0-9]*) droid=0;; esac; "
            f"printf '{_PI_ANALYSIS_PREFIX}|droidGuardVmCount|%s\\n' \"$droid\"; "
            f"printf '{_PI_ANALYSIS_PREFIX}|complete|1\\n'"
        )
        request = ProcessRequest(
            (adb, "-s", device.serial, "shell", "su", "-c", script),
            timeout_seconds=120.0,
            output_limit_bytes=_MAX_PI_ANALYSIS_BYTES,
        )
        return RootingCompilation(
            "pi_analysis",
            self._base_plan(
                snapshot,
                device,
                (request,),
                label=f"Generate redacted Play Integrity analysis for {device.serial}",
            ),
            device_build=device.build,
        )

    def _compile_shizuku(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
    ) -> RootingCompilation:
        self._validate_payload(command, {"serial", "action"})
        if command.payload.get("action") != "start":
            raise RootingPlanningError(
                "shizuku_action_invalid",
                "Shizuku action must be exactly start",
            )
        # The package and both executable locations are backend-owned.  The
        # package-manager result is accepted only under Android's /data/app
        # root before it can become an executable path.
        script = (
            "primary=/storage/emulated/0/Android/data/moe.shizuku.privileged.api/start.sh; "
            'if [ -f "$primary" ]; then sh "$primary" || exit 71; else '
            "apk=$(pm path moe.shizuku.privileged.api 2>/dev/null | head -n 1); "
            'apk=${apk#package:}; case "$apk" in /data/app/*/base.apk) ;; *) exit 72;; esac; '
            "abi=$(getprop ro.product.cpu.abi); case \"$abi\" in "
            "arm64-v8a) native_dir=arm64;; armeabi-v7a|armeabi) native_dir=arm;; "
            "x86_64) native_dir=x86_64;; x86) native_dir=x86;; *) exit 73;; esac; "
            'native=${apk%/base.apk}/lib/$native_dir/libshizuku.so; '
            '[ -x "$native" ] || exit 74; "$native" || exit 75; fi'
        )
        request = ProcessRequest(
            (adb, "-s", device.serial, "shell", "sh", "-c", script),
            timeout_seconds=120.0,
            output_limit_bytes=64 * 1024,
        )
        return RootingCompilation(
            "recovery.shizuku",
            self._base_plan(
                snapshot,
                device,
                (request,),
                label=f"Start Shizuku on {device.serial}",
                data_behavior="shizuku_start",
                risk=OperationRisk.MUTATING,
                postconditions=(
                    OperationPostcondition(
                        "shizuku_state",
                        {"running": True},
                        "the Shizuku server process is running",
                    ),
                ),
            ),
            device_write=True,
            requires_confirmation=True,
        )

    def _compile_sos(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
    ) -> RootingCompilation:
        self._validate_payload(command, {"serial", "action", "confirmationText"})
        if command.payload.get("action") != "disableModules":
            raise RootingPlanningError(
                "sos_action_invalid",
                "SOS action must be exactly disableModules",
            )
        required = self.required_sos_confirmation(device.serial)
        if command.payload.get("confirmationText") != required:
            raise RootingPlanningError(
                "sos_confirmation_required",
                f"type {required} to disable every Magisk module",
            )
        # This intentionally creates only Magisk's documented disable marker;
        # it never removes a module directory or invokes a browser-provided
        # path.  A separate aggregate observer proves that no enabled module
        # remains after the command.
        script = (
            "for dir in /data/adb/modules/*; do "
            '[ -d "$dir" ] || continue; touch "$dir/disable" || exit 76; '
            "done; exit 0"
        )
        request = ProcessRequest(
            (adb, "-s", device.serial, "shell", "su", "-c", script),
            timeout_seconds=120.0,
            output_limit_bytes=64 * 1024,
        )
        return RootingCompilation(
            "recovery.sos",
            self._base_plan(
                snapshot,
                device,
                (request,),
                label=f"Disable every Magisk module on {device.serial}",
                data_behavior="root_modules_disable_all",
                risk=OperationRisk.MUTATING,
                postconditions=(
                    OperationPostcondition(
                        "magisk_modules_state",
                        {"allDisabled": True},
                        "every installed Magisk module has a disable marker",
                    ),
                ),
            ),
            device_write=True,
            requires_confirmation=True,
        )

    @staticmethod
    def required_sos_confirmation(serial: str) -> str:
        if not isinstance(serial, str) or not serial.strip():
            raise RootingPlanningError(
                "target_serial_invalid",
                "target serial is required for SOS recovery",
            )
        return f"SOS {serial.strip()[-6:].upper()}"

    def root_app_inventory(
        self,
        cancellation: CancellationProbe | None = None,
    ) -> tuple[RootAppInfo, ...]:
        with self._root_app_sources_lock:
            sources = self._root_app_sources
        return self._root_app_inventory(sources, cancellation)

    @property
    def root_app_sources(self) -> tuple[RootAppSource, ...]:
        with self._root_app_sources_lock:
            return self._root_app_sources

    def register_verified_source(
        self,
        source: RootAppSource,
        cancellation: CancellationProbe | None = None,
    ) -> RootAppInfo:
        """Atomically add one backend-verified download to the live inventory."""

        if not isinstance(source, RootAppSource):
            raise TypeError("source must be a RootAppSource")
        if source.provenance.strip().casefold() != "verified-download":
            raise RootingPlanningError(
                "root_app_registration_untrusted",
                "dynamic root-app registration requires verified-download provenance",
            )
        with self._root_app_sources_lock:
            current = self._root_app_sources
            identity = (
                source.provider.strip().casefold(),
                source.flavor.strip().casefold(),
                source.version.strip().casefold(),
                source.architecture.strip().casefold(),
            )
            retained = tuple(
                candidate
                for candidate in current
                if (
                    candidate.provider.strip().casefold(),
                    candidate.flavor.strip().casefold(),
                    candidate.version.strip().casefold(),
                    candidate.architecture.strip().casefold(),
                )
                != identity
            )
            candidates = (*retained, source)
            inventory = self._root_app_inventory(candidates, cancellation)
            canonical = os.path.normcase(
                str(Path(source.path).expanduser().resolve(strict=True))
            )
            registered = next(
                (
                    app
                    for app in inventory
                    if os.path.normcase(app.path) == canonical
                ),
                None,
            )
            if registered is None:  # pragma: no cover - inventory invariant
                raise RootingPlanningError(
                    "root_app_registration_failed",
                    "verified root app did not enter the canonical inventory",
                )
            self._root_app_sources = candidates
            return registered

    def restore_root_app_sources(
        self,
        sources: Sequence[RootAppSource],
    ) -> None:
        """Restore a backend-captured inventory after failed state promotion."""

        values = tuple(sources)
        if any(not isinstance(source, RootAppSource) for source in values):
            raise TypeError("sources must contain only RootAppSource values")
        with self._root_app_sources_lock:
            self._root_app_sources = values

    def _root_app_inventory(
        self,
        sources: Sequence[RootAppSource],
        cancellation: CancellationProbe | None = None,
    ) -> tuple[RootAppInfo, ...]:
        inventory: list[RootAppInfo] = []
        seen_paths: set[str] = set()
        seen_identities: set[tuple[str, str, str]] = set()
        seen_ids: set[str] = set()
        for source in sources:
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
            expected_signers = tuple(
                signer.strip().casefold()
                for signer in source.expected_signer_sha256
            )
            if (
                len(expected_signers) != len(set(expected_signers))
                or any(_SHA256_PATTERN.fullmatch(signer) is None for signer in expected_signers)
            ):
                raise RootingPlanningError(
                    "root_app_expected_signer_invalid",
                    "expected root-app signer digests are invalid",
                )
            if provenance == "verified-download" and not expected_signers:
                raise RootingPlanningError(
                    "root_app_expected_signer_required",
                    "verified downloads require backend-pinned APK signer digests",
                )
            architecture = source.architecture.strip().casefold()
            if _ARCHITECTURE_PATTERN.fullmatch(architecture) is None:
                raise RootingPlanningError(
                    "root_app_architecture_invalid",
                    "root-app architecture is invalid",
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
            actual_signers = tuple(sorted(signer.casefold() for signer in apk_identity.signer_sha256))
            if expected_signers and not hmac.compare_digest(
                "\0".join(sorted(expected_signers)),
                "\0".join(actual_signers),
            ):
                raise RootingPlanningError(
                    "root_app_signer_mismatch",
                    "root-app signer does not match the backend-pinned identity",
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
                    architecture,
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
        # Magisk exposes module directories at this documented fixed path. The
        # backend-owned script emits bounded base64 metadata, so module.prop
        # text can never create records or cross the argv boundary.
        script = (
            "count=0; encode_prop() { key=$1; limit=$2; "
            'sed -n "s/^${key}=//p" "$prop" 2>/dev/null | head -n 1 | '
            'head -c "$limit" | base64 | tr -d "\\n"; }; '
            "for dir in /data/adb/modules/*; do [ -d \"$dir\" ] || continue; "
            'id=${dir##*/}; case "$id" in *[!A-Za-z0-9._-]*|\'\') continue;; esac; '
            '[ "${#id}" -le 64 ] || continue; prop="$dir/module.prop"; '
            'if [ -f "$dir/remove" ]; then state=pending_remove; '
            'elif [ -f "$dir/disable" ]; then state=disabled; '
            'elif [ -f "$prop" ]; then state=enabled; else state=corrupt; fi; '
            'name=$(encode_prop name 512); version=$(encode_prop version 256); '
            'version_code=$(sed -n "s/^versionCode=//p" "$prop" 2>/dev/null | head -n 1 | head -c 16); '
            'author=$(encode_prop author 512); description=$(encode_prop description 2048); '
            'update_json=$(encode_prop updateJson 4096); '
            f'printf "{_MODULE_LIST_PREFIX}|%s|%s|%s|%s|%s|%s|%s|%s\\n" '
            '"$id" "$state" "$name" "$version" "$version_code" "$author" "$description" "$update_json"; '
            f'count=$((count + 1)); [ "$count" -lt {_MAX_MODULES} ] || break; done'
        )
        request = ProcessRequest(
            (
                adb,
                "-s",
                device.serial,
                "shell",
                "su",
                "-c",
                script,
            ),
            timeout_seconds=30.0,
            output_limit_bytes=_MAX_MODULE_LIST_BYTES,
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
        if not path.is_file() or (suffix and path.suffix.casefold() != suffix):
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
    """Parse bounded module records without exposing device-controlled URLs."""

    if not isinstance(stdout, str):
        raise RootingPlanningError("root_module_list_invalid", "module inventory must be text")
    if len(stdout.encode("utf-8", errors="replace")) > _MAX_MODULE_LIST_BYTES:
        raise RootingPlanningError("root_module_list_oversized", "module inventory is oversized")
    lines = tuple(line.strip() for line in stdout.splitlines() if line.strip())
    if len(lines) > _MAX_MODULES:
        raise RootingPlanningError("root_module_list_oversized", "too many modules were reported")
    modules: list[RootModuleInfo] = []
    seen: set[str] = set()
    for line in lines:
        fields = line.split("|")
        if len(fields) != 9 or fields[0] != _MODULE_LIST_PREFIX:
            raise RootingPlanningError("root_module_list_malformed", "module inventory record is invalid")
        module_id, state = fields[1:3]
        if (
            _MODULE_ID_PATTERN.fullmatch(module_id) is None
            or module_id.casefold() in seen
            or state not in {"enabled", "disabled", "pending_remove", "corrupt"}
        ):
            raise RootingPlanningError("root_module_list_malformed", "module identity or state is invalid")
        name = _module_property(fields[3], "name", 256)
        version = _module_property(fields[4], "version", 128)
        raw_version_code = fields[5]
        if raw_version_code:
            if not raw_version_code.isascii() or not raw_version_code.isdecimal():
                raise RootingPlanningError("root_module_list_malformed", "module version code is invalid")
            version_code: int | None = int(raw_version_code, 10)
            if not 0 <= version_code <= 2_147_483_647:
                raise RootingPlanningError("root_module_list_malformed", "module version code is out of bounds")
        else:
            version_code = None
        author = _module_property(fields[6], "author", 256)
        description = _module_property(fields[7], "description", 1024)
        update_url = _module_property(fields[8], "updateJson", 2048)
        if update_url:
            parsed = urlsplit(update_url)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.fragment
            ):
                raise RootingPlanningError("root_module_list_malformed", "module update URL is unsafe")
        modules.append(
            RootModuleInfo(
                module_id,
                name or module_id,
                version,
                version_code,
                author,
                description,
                state,
                update_url,
            )
        )
        seen.add(module_id.casefold())
    return tuple(sorted(modules, key=lambda item: item.id.casefold()))


def _module_property(encoded: str, label: str, maximum: int) -> str:
    try:
        raw = base64.b64decode(encoded, validate=True)
        value = raw.decode("utf-8", errors="strict").strip()
    except (ValueError, UnicodeDecodeError) as error:
        raise RootingPlanningError(
            "root_module_list_malformed",
            f"module {label} metadata is invalid",
        ) from error
    if len(value) > maximum or any(ord(character) < 32 for character in value):
        raise RootingPlanningError(
            "root_module_list_malformed",
            f"module {label} metadata is outside its bounds",
        )
    return value


def parse_pif_inventory(stdout: str) -> dict[str, object]:
    """Parse bounded PIF metadata without accepting paths or file contents."""

    if not isinstance(stdout, str):
        raise RootingPlanningError("pif_inventory_invalid", "PIF inventory output must be text")
    if len(stdout.encode("utf-8", errors="replace")) > _MAX_PIF_INVENTORY_BYTES:
        raise RootingPlanningError("pif_inventory_oversized", "PIF inventory output is oversized")
    lines = tuple(line.strip() for line in stdout.splitlines() if line.strip())
    if (
        len(lines) < len(_PIF_PROFILE_SPECS) + 3
        or lines[0] != f"{_PIF_INVENTORY_PREFIX}|schema|1"
        or lines[-1] != f"{_PIF_INVENTORY_PREFIX}|complete|1"
    ):
        raise RootingPlanningError(
            "pif_inventory_incomplete",
            "PIF inventory is missing its schema or completion boundary",
        )

    root_verified = False
    profiles: list[PifProfileInfo] = []
    targets: dict[str, PifTargetInfo] = {}
    for line in lines[1:-1]:
        fields = line.split("|")
        if not fields or fields[0] != _PIF_INVENTORY_PREFIX:
            raise RootingPlanningError("pif_inventory_malformed", "PIF inventory prefix is invalid")
        record_type = fields[1] if len(fields) > 1 else ""
        if record_type == "root" and len(fields) == 3:
            if root_verified or fields[2] != "verified":
                raise RootingPlanningError(
                    "pif_inventory_root_unverified",
                    "PIF inventory root access was not verified",
                )
            root_verified = True
            continue
        if record_type == "profile" and len(fields) == 8:
            profile_id, module, profile_format, state, raw_size, digest = fields[2:]
            index = len(profiles)
            if index >= len(_PIF_PROFILE_SPECS) or (
                profile_id,
                module,
                profile_format,
            ) != _PIF_PROFILE_SPECS[index]:
                raise RootingPlanningError(
                    "pif_inventory_malformed",
                    "PIF profile identity or order is invalid",
                )
            if _PIF_PROFILE_ID_PATTERN.fullmatch(profile_id) is None:
                raise RootingPlanningError("pif_inventory_malformed", "PIF profile id is invalid")
            present, size, public_digest = _parse_pif_file_evidence(state, raw_size, digest)
            profiles.append(
                PifProfileInfo(
                    profile_id,
                    module,
                    profile_format,
                    present,
                    size,
                    public_digest,
                )
            )
            continue
        if record_type == "target" and len(fields) == 7:
            package_name = _decode_pi_text(fields[2], "target package", 255)
            identity = package_name.casefold()
            if (
                fields[3] != "json"
                or _PACKAGE_NAME_PATTERN.fullmatch(package_name) is None
                or identity in targets
                or len(targets) >= _MAX_PIF_TARGETS
            ):
                raise RootingPlanningError("pif_inventory_malformed", "PIF target record is invalid")
            present, size, public_digest = _parse_pif_file_evidence(*fields[4:])
            targets[identity] = PifTargetInfo(package_name, present, size, public_digest)
            continue
        raise RootingPlanningError("pif_inventory_malformed", "PIF inventory contains an unknown record")

    if not root_verified or len(profiles) != len(_PIF_PROFILE_SPECS):
        raise RootingPlanningError("pif_inventory_incomplete", "PIF inventory evidence is incomplete")
    return {
        "schemaVersion": 1,
        "rootAccess": "verified",
        "bounded": True,
        "count": len(profiles),
        "profiles": [profile.to_dict() for profile in profiles],
        "targetCount": len(targets),
        "targets": [targets[key].to_dict() for key in sorted(targets)],
    }


def inspect_pif_profile_stream(profile_id: str, stream: BinaryIO) -> PifImportInspection:
    """Validate a granted PIF source while returning metadata only."""

    formats = {item[0]: item[2] for item in _PIF_PROFILE_SPECS}
    profile_format = formats.get(profile_id)
    if profile_format is None:
        raise RootingPlanningError("pif_profile_invalid", "PIF profile ID is not canonical")
    if not hasattr(stream, "read"):
        raise RootingPlanningError("pif_import_invalid", "PIF import source is not readable")
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    size = 0
    while chunk := stream.read(64 * 1024):
        if not isinstance(chunk, bytes):
            raise RootingPlanningError("pif_import_invalid", "PIF import source must be binary")
        size += len(chunk)
        if size > _MAX_PIF_IMPORT_BYTES:
            raise RootingPlanningError("pif_import_oversized", "PIF import exceeds 1 MiB")
        digest.update(chunk)
        chunks.append(chunk)
    raw = b"".join(chunks)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise RootingPlanningError("pif_import_encoding_invalid", "PIF import must be UTF-8") from error
    if "\x00" in text or any(
        ord(character) < 32 and character not in {"\n", "\r", "\t"}
        for character in text
    ):
        raise RootingPlanningError("pif_import_controls_invalid", "PIF import contains control bytes")
    normalized_lines = tuple(line.strip() for line in text.splitlines())
    if profile_format == "json":
        try:
            value = json.loads(text)
        except (json.JSONDecodeError, RecursionError) as error:
            raise RootingPlanningError("pif_import_json_invalid", "PIF import JSON is invalid") from error
        if not isinstance(value, dict) or not value:
            raise RootingPlanningError("pif_import_json_invalid", "PIF import JSON must be a non-empty object")
    elif profile_format in {"list"}:
        entries = tuple(line for line in normalized_lines if line and not line.startswith("#"))
        if not entries or len(entries) > 1024 or any(
            _PACKAGE_NAME_PATTERN.fullmatch(entry) is None for entry in entries
        ):
            raise RootingPlanningError("pif_import_list_invalid", "PIF import list has invalid package IDs")
        identities = tuple(entry.casefold() for entry in entries)
        if len(set(identities)) != len(identities):
            raise RootingPlanningError("pif_import_list_invalid", "PIF import list contains duplicates")
    elif profile_format == "prop":
        entries = tuple(line for line in normalized_lines if line and not line.startswith("#"))
        if not entries or len(entries) > 1024:
            raise RootingPlanningError("pif_import_prop_invalid", "PIF property file is empty or oversized")
        for entry in entries:
            key, separator, _value = entry.partition("=")
            if not separator or _PIF_PROPERTY_KEY_PATTERN.fullmatch(key.strip()) is None:
                raise RootingPlanningError("pif_import_prop_invalid", "PIF property entry is invalid")
    elif profile_format == "marker":
        if raw:
            raise RootingPlanningError("pif_import_marker_invalid", "PIF marker profile must be empty")
    elif profile_format == "text":
        if not text.strip() or len(normalized_lines) > 1024:
            raise RootingPlanningError("pif_import_text_invalid", "PIF text profile is empty or oversized")
    else:
        raise RootingPlanningError("pif_import_format_invalid", "PIF profile format is unsupported")
    return PifImportInspection(profile_id, profile_format, size, digest.hexdigest())


def _parse_pif_file_evidence(state: str, raw_size: str, digest: str) -> tuple[bool, int, str | None]:
    if state not in {"present", "absent"}:
        raise RootingPlanningError("pif_inventory_malformed", "PIF file state is invalid")
    size = _pi_count(raw_size, "PIF file size", 4 * 1024 * 1024)
    if state == "absent":
        if size != 0 or digest != "-":
            raise RootingPlanningError("pif_inventory_malformed", "absent PIF file has metadata")
        return False, 0, None
    if _SHA256_PATTERN.fullmatch(digest) is None:
        raise RootingPlanningError("pif_inventory_unverified", "PIF file hash is unavailable")
    return True, size, digest


def parse_pi_analysis(
    stdout: str,
    *,
    device_codename: str,
    build: str,
) -> dict[str, object]:
    """Parse the fixed probe into a share-safe, closed analysis report."""

    if not isinstance(stdout, str):
        raise RootingPlanningError("pi_analysis_invalid", "analysis output must be text")
    if len(stdout.encode("utf-8", errors="replace")) > _MAX_PI_ANALYSIS_BYTES:
        raise RootingPlanningError("pi_analysis_oversized", "analysis output is oversized")
    lines = tuple(line.strip() for line in stdout.splitlines() if line.strip())
    if (
        len(lines) < 10
        or lines[0] != f"{_PI_ANALYSIS_PREFIX}|schema|1"
        or lines[-1] != f"{_PI_ANALYSIS_PREFIX}|complete|1"
    ):
        raise RootingPlanningError(
            "pi_analysis_incomplete",
            "analysis output is missing its schema or completion boundary",
        )
    codename = _pi_public_text(device_codename, "device codename", 64)
    build_value = _pi_public_text(build, "device build", 256)
    singletons: dict[str, object] = {}
    packages: dict[str, dict[str, object]] = {}
    modules: dict[str, dict[str, object]] = {}
    configs: dict[str, dict[str, object]] = {}

    for line in lines[1:-1]:
        fields = line.split("|")
        if not fields or fields[0] != _PI_ANALYSIS_PREFIX:
            raise RootingPlanningError("pi_analysis_malformed", "analysis record prefix is invalid")
        record_type = fields[1] if len(fields) > 1 else ""
        if record_type == "root" and len(fields) == 3:
            if "rootAccess" in singletons or fields[2] != "verified":
                raise RootingPlanningError("pi_analysis_root_unverified", "root analysis was not verified")
            singletons["rootAccess"] = "verified"
        elif record_type in {"testKeys", "overlayVisible"} and len(fields) == 3:
            key = "testKeys" if record_type == "testKeys" else "overlayVisible"
            if key in singletons or fields[2] not in {"true", "false"}:
                raise RootingPlanningError("pi_analysis_malformed", f"{record_type} record is invalid")
            singletons[key] = fields[2] == "true"
        elif record_type == "package" and len(fields) == 6:
            package_id = fields[2]
            if package_id not in _PI_PACKAGE_IDS or package_id in packages:
                raise RootingPlanningError("pi_analysis_malformed", "package record identity is invalid")
            if fields[3] not in {"true", "false"}:
                raise RootingPlanningError("pi_analysis_malformed", "package state is invalid")
            version = _decode_pi_text(fields[4], "package version", 128)
            version_code = _pi_count(fields[5], "package version code", 9_223_372_036_854_775_807)
            installed = fields[3] == "true"
            if not installed and (version or version_code):
                raise RootingPlanningError("pi_analysis_malformed", "absent package has version metadata")
            packages[package_id] = {
                "id": package_id,
                "installed": installed,
                "version": version,
                "versionCode": version_code,
            }
        elif record_type == "module" and len(fields) == 4:
            module_id = _decode_pi_text(fields[2], "module id", 64)
            identity = module_id.casefold()
            if (
                _MODULE_ID_PATTERN.fullmatch(module_id) is None
                or identity in modules
                or fields[3] not in _PI_MODULE_STATE
                or len(modules) >= _MAX_PI_MODULES
            ):
                raise RootingPlanningError("pi_analysis_malformed", "module record is invalid")
            modules[identity] = {"id": module_id, "state": fields[3]}
        elif record_type == "config" and len(fields) == 6:
            kind, state, raw_size, digest = fields[2:]
            if kind not in _PI_CONFIG_KINDS or kind in configs or state not in {"present", "absent"}:
                raise RootingPlanningError("pi_analysis_malformed", "configuration record is invalid")
            size = _pi_count(raw_size, "configuration size", 4 * 1024 * 1024)
            if state == "absent":
                if size != 0 or digest != "-":
                    raise RootingPlanningError("pi_analysis_malformed", "absent configuration has metadata")
                public_digest: str | None = None
            elif kind == "keybox":
                if digest != "-":
                    raise RootingPlanningError("pi_analysis_secret_exposed", "keybox fingerprint must be withheld")
                public_digest = None
            else:
                if _SHA256_PATTERN.fullmatch(digest) is None:
                    raise RootingPlanningError("pi_analysis_unverified", "configuration hash is unavailable")
                public_digest = digest
            configs[kind] = {
                "kind": kind,
                "present": state == "present",
                "size": size,
                "sha256": public_digest,
            }
        elif record_type in {"targetCount", "denylistCount", "droidGuardVmCount"} and len(fields) == 3:
            key = {
                "targetCount": "targetedFixTargetCount",
                "denylistCount": "magiskDenylistCount",
                "droidGuardVmCount": "droidGuardVmCount",
            }[record_type]
            if key in singletons:
                raise RootingPlanningError("pi_analysis_malformed", f"duplicate {record_type} record")
            singletons[key] = _pi_count(fields[2], record_type, 4096)
        else:
            raise RootingPlanningError("pi_analysis_malformed", "analysis contains an unknown record")

    required_singletons = {
        "rootAccess",
        "testKeys",
        "overlayVisible",
        "targetedFixTargetCount",
        "magiskDenylistCount",
        "droidGuardVmCount",
    }
    if set(singletons) != required_singletons:
        raise RootingPlanningError("pi_analysis_incomplete", "analysis signals are incomplete")
    if set(packages) != _PI_PACKAGE_IDS:
        raise RootingPlanningError("pi_analysis_incomplete", "package signals are incomplete")
    if tuple(configs) != _PI_CONFIG_KINDS:
        raise RootingPlanningError("pi_analysis_incomplete", "configuration signals are incomplete")
    return {
        "schemaVersion": 1,
        "redacted": True,
        "complete": True,
        "device": {
            "codename": codename,
            "build": build_value,
            "rootAccess": singletons["rootAccess"],
            "testKeys": singletons["testKeys"],
            "overlayVisible": singletons["overlayVisible"],
        },
        "packages": [packages[key] for key in sorted(packages)],
        "modules": [modules[key] for key in sorted(modules)],
        "configs": [configs[key] for key in _PI_CONFIG_KINDS],
        "signals": {
            "targetedFixTargetCount": singletons["targetedFixTargetCount"],
            "magiskDenylistCount": singletons["magiskDenylistCount"],
            "droidGuardVmCount": singletons["droidGuardVmCount"],
        },
        "withheld": list(_PI_WITHHELD),
    }


def _decode_pi_text(encoded: str, label: str, maximum: int) -> str:
    try:
        raw = base64.b64decode(encoded, validate=True)
        value = raw.decode("utf-8", errors="strict").strip()
    except (ValueError, UnicodeDecodeError) as error:
        raise RootingPlanningError("pi_analysis_malformed", f"{label} is invalid") from error
    return _pi_public_text(value, label, maximum)


def _pi_public_text(value: str, label: str, maximum: int) -> str:
    if not isinstance(value, str) or len(value) > maximum or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise RootingPlanningError("pi_analysis_malformed", f"{label} is outside its bounds")
    return value


def _pi_count(value: str, label: str, maximum: int) -> int:
    if not value or not value.isascii() or not value.isdecimal():
        raise RootingPlanningError("pi_analysis_malformed", f"{label} is invalid")
    parsed = int(value, 10)
    if parsed > maximum:
        raise RootingPlanningError("pi_analysis_malformed", f"{label} is outside its bounds")
    return parsed


__all__ = [
    "ROOTING_COMMANDS",
    "PifProfileInfo",
    "PifImportInspection",
    "PifTargetInfo",
    "RootApkInspector",
    "RootAppInfo",
    "RootAppSource",
    "RootModuleInfo",
    "RootingCompilation",
    "RootingPlanningError",
    "RootingService",
    "inspect_pif_profile_stream",
    "parse_pif_inventory",
    "parse_pi_analysis",
    "parse_root_module_list",
]
