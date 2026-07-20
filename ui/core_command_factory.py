"""Translate trusted bridge-v2 requests into typed core commands.

Risk metadata and native-resource resolution live on this backend boundary.
The browser can provide only opaque, purpose-bound grant tokens; filesystem
paths are introduced here after the native selection is revalidated.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    BoundReadFile,
    BoundWriteFile,
    GrantAccess,
    GrantError,
    GrantTarget,
    PathGrant,
    PathGrantStore,
    SecretGrantStore,
)
from ui.bridge_contract import BRIDGE_VERSION, BridgeRequest
from ui.command_registry import (
    COMMAND_REGISTRY,
    CONFIRMATION_COMMANDS,
    DESTRUCTIVE_COMMANDS,
    DEVICE_SCOPED_COMMANDS,
)

SnapshotProvider = Callable[[], AppSnapshot]


class SupportDestinationRegistrar(Protocol):
    def __call__(
        self,
        destination: str | Path,
        *,
        allow_overwrite: bool = False,
    ) -> str: ...


class CommandFactoryError(ValueError):
    """Stable, non-sensitive failure raised at the trusted command boundary."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class NativeGrantSpec:
    picker_command: str
    purpose: str
    consumer_command: str
    target: GrantTarget
    access: GrantAccess
    multiple: bool = False
    max_selections: int = 1

    def __post_init__(self) -> None:
        if not 1 <= self.max_selections <= 64:
            raise ValueError("native grant selection limit is invalid")
        if not self.multiple and self.max_selections != 1:
            raise ValueError("single native grants must accept exactly one selection")


_NATIVE_GRANT_SPECS = (
    NativeGrantSpec(
        "native.pickDirectory",
        "platformTools.setup.directory",
        "platformTools.setup",
        GrantTarget.DIRECTORY,
        GrantAccess.READ,
    ),
    NativeGrantSpec(
        "native.pickFile",
        "firmware.select",
        "firmware.select",
        GrantTarget.FILE,
        GrantAccess.READ,
    ),
    NativeGrantSpec(
        "native.pickFile",
        "root.modules.install",
        "root.modules.action",
        GrantTarget.FILE,
        GrantAccess.READ,
    ),
    NativeGrantSpec(
        "native.pickFile",
        "root.pif.import",
        "tools.pif",
        GrantTarget.FILE,
        GrantAccess.READ,
    ),
    NativeGrantSpec(
        "native.pickFile",
        "backups.restore.source",
        "backups.restore",
        GrantTarget.FILE,
        GrantAccess.READ,
    ),
    NativeGrantSpec(
        "native.pickFile",
        "backups.magisk.import.source",
        "backups.magisk.import",
        GrantTarget.FILE,
        GrantAccess.READ,
    ),
    NativeGrantSpec(
        "native.pickFile",
        "partitions.write.source",
        "partitions.write",
        GrantTarget.FILE,
        GrantAccess.READ,
    ),
    NativeGrantSpec(
        "native.pickFile",
        "apps.install.source",
        "apps.action",
        GrantTarget.FILE,
        GrantAccess.READ,
    ),
    NativeGrantSpec(
        "native.pickFile",
        "boot.select.source",
        "boot.select",
        GrantTarget.FILE,
        GrantAccess.READ,
    ),
    NativeGrantSpec(
        "native.pickFile",
        "tools.avb.currentBoot",
        "tools.avb",
        GrantTarget.FILE,
        GrantAccess.READ,
    ),
    NativeGrantSpec(
        "native.pickFile",
        "tools.xml.source",
        "tools.xml",
        GrantTarget.FILE,
        GrantAccess.READ,
    ),
    NativeGrantSpec(
        "native.pickFile",
        "root.dataAdb.restore.source",
        "root.dataAdb.restore",
        GrantTarget.FILE,
        GrantAccess.READ,
    ),
    NativeGrantSpec(
        "native.pickFiles",
        "tools.keybox.sources",
        "tools.keybox",
        GrantTarget.FILE,
        GrantAccess.READ,
        multiple=True,
        max_selections=32,
    ),
    NativeGrantSpec(
        "native.pickFiles",
        "tools.pushFiles.sources",
        "tools.pushFiles",
        GrantTarget.FILE,
        GrantAccess.READ,
        multiple=True,
        max_selections=32,
    ),
    NativeGrantSpec(
        "native.saveFile",
        "apps.export.destination",
        "apps.action",
        GrantTarget.FILE,
        GrantAccess.WRITE,
    ),
    NativeGrantSpec(
        "native.saveFile",
        "tools.logcat.export",
        "tools.logcat",
        GrantTarget.FILE,
        GrantAccess.WRITE,
    ),
    NativeGrantSpec(
        "native.saveFile",
        "boot.patch.destination",
        "boot.patch",
        GrantTarget.FILE,
        GrantAccess.WRITE,
    ),
    NativeGrantSpec(
        "native.saveFile",
        "backups.create.destination",
        "backups.create",
        GrantTarget.FILE,
        GrantAccess.WRITE,
    ),
    NativeGrantSpec(
        "native.saveFile",
        "partitions.read.destination",
        "partitions.read",
        GrantTarget.FILE,
        GrantAccess.WRITE,
    ),
    NativeGrantSpec(
        "native.saveFile",
        "support.create.destination",
        "support.create",
        GrantTarget.FILE,
        GrantAccess.WRITE,
    ),
    NativeGrantSpec(
        "native.saveFile",
        "root.dataAdb.backup.destination",
        "root.dataAdb.backup",
        GrantTarget.FILE,
        GrantAccess.WRITE,
    ),
)

_SPECS_BY_PICKER = {
    (spec.picker_command, spec.purpose): spec for spec in _NATIVE_GRANT_SPECS
}
_SPECS_BY_PURPOSE = {spec.purpose: spec for spec in _NATIVE_GRANT_SPECS}
_SECRET_PURPOSES = frozenset({"wifi.pairingCode", "apatch.superkey"})


class CoreCommandFactory:
    """Session-owned bridge command factory and native grant authority."""

    def __init__(
        self,
        snapshot_provider: SnapshotProvider,
        *,
        path_grants: PathGrantStore | None = None,
        secret_grants: SecretGrantStore | None = None,
    ) -> None:
        self._snapshot_provider = snapshot_provider
        self.path_grants = path_grants or PathGrantStore()
        self.secret_grants = secret_grants or SecretGrantStore()
        self._support_destination_registrar: SupportDestinationRegistrar | None = None

    def bind_support_destination_registrar(
        self,
        registrar: SupportDestinationRegistrar,
    ) -> None:
        if self._support_destination_registrar is not None:
            raise RuntimeError("support destination registrar is already bound")
        self._support_destination_registrar = registrar

    def validate_native_request(self, request: BridgeRequest) -> NativeGrantSpec:
        request.validate()
        purpose = request.payload.get("purpose")
        spec = _SPECS_BY_PICKER.get(
            (request.command, purpose if isinstance(purpose, str) else "")
        )
        if spec is None:
            raise CommandFactoryError(
                "native_purpose_not_allowed",
                "The native picker purpose is not allow-listed for this picker.",
            )
        snapshot = self._snapshot_provider()
        if request.expected_revision != snapshot.revision:
            raise CommandFactoryError(
                "revision_conflict",
                "Application state changed before the native selection.",
            )
        return spec

    def issue_native_grants(
        self,
        request: BridgeRequest,
        selections: Sequence[str | Path],
    ) -> dict[str, Any]:
        spec = self.validate_native_request(request)
        paths = tuple(Path(selection) for selection in selections)
        if not paths or (not spec.multiple and len(paths) != 1):
            raise CommandFactoryError(
                "native_selection_invalid",
                "The native picker returned an invalid selection count.",
            )
        if spec.multiple and len(paths) > spec.max_selections:
            raise CommandFactoryError(
                "native_selection_invalid",
                "The native picker returned too many selections.",
            )

        # A new picker result supersedes the prior result for this exact
        # purpose. This preserves manual retry until the user chooses again
        # without leaking reusable grants until the session capacity is full.
        self.path_grants.revoke_purpose(spec.purpose)
        issued: list[PathGrant] = []
        try:
            for path in paths:
                if spec.target is GrantTarget.DIRECTORY:
                    grant = self.path_grants.issue_directory(
                        path,
                        purpose=spec.purpose,
                        access=spec.access,
                    )
                else:
                    grant = self.path_grants.issue_file(
                        path,
                        purpose=spec.purpose,
                        access=spec.access,
                    )
                issued.append(grant)
        except Exception:
            for grant in issued:
                self.path_grants.revoke(grant.token)
            raise

        public = [
            {**grant.to_public_dict(), "displayName": path.name}
            for grant, path in zip(issued, paths, strict=True)
        ]
        if spec.multiple:
            return {"grants": public, "purpose": spec.purpose}
        return public[0]

    def validate_secret_issue_request(self, request: BridgeRequest) -> str:
        request.validate()
        purpose = request.payload.get("purpose")
        if request.command != "secret.issue" or purpose not in _SECRET_PURPOSES:
            raise CommandFactoryError(
                "native_purpose_not_allowed",
                "The secret purpose is not allow-listed.",
            )
        if request.expected_revision != self._snapshot_provider().revision:
            raise CommandFactoryError(
                "revision_conflict",
                "Application state changed before secret issuance.",
            )
        return str(purpose)

    def issue_secret(self, request: BridgeRequest) -> dict[str, Any]:
        purpose = self.validate_secret_issue_request(request)
        secret = request.payload.get("secret")
        if not isinstance(secret, str):
            raise CommandFactoryError("secret_invalid", "The secret value is invalid.")
        if purpose == "wifi.pairingCode" and (
            len(secret) != 6 or not secret.isascii() or not secret.isdecimal()
        ):
            raise CommandFactoryError(
                "native_secret_invalid", "The Wi-Fi pairing code must contain six digits."
            )
        if purpose == "apatch.superkey" and not 8 <= len(secret) <= 128:
            raise CommandFactoryError(
                "native_secret_invalid", "The APatch superkey length is invalid."
            )
        return self.secret_grants.issue(secret, purpose=purpose).to_public_dict()

    def __call__(self, request: BridgeRequest) -> AppCommand:
        accepted_monotonic = time.monotonic()
        # Defence in depth for direct Python callers that bypass from_json().
        request.validate()
        if request.version != BRIDGE_VERSION:  # explicit for static audits
            raise CommandFactoryError("unsupported_version", "Bridge v2 is required.")

        snapshot = self._snapshot_provider()
        payload = dict(request.payload)
        self._resolve_native_resources(request.command, payload)
        target_serial = _target_serial(payload, snapshot, request.command)
        return AppCommand(
            kind=request.command,
            expected_revision=request.expected_revision,
            target_serial=target_serial,
            payload=payload,
            destructive=request.command in DESTRUCTIVE_COMMANDS,
            requires_confirmation=request.command in CONFIRMATION_COMMANDS,
            operation_id=request.request_id,
            # Reserve five percent for the host to serialize the terminal
            # bridge response.  The absolute budget starts here, before the
            # command can wait in the native FIFO.
            execution_timeout_seconds=(
                COMMAND_REGISTRY[request.command].timeout_ms / 1000.0 * 0.95
            ),
            _accepted_monotonic=accepted_monotonic,
        )

    def _resolve_native_resources(self, command: str, payload: dict[str, Any]) -> None:
        if command == "platformTools.setup":
            source = payload.get("source")
            if source == "official":
                if "grant" in payload:
                    raise CommandFactoryError(
                        "grant_not_applicable",
                        "Official Platform Tools setup does not accept a directory grant.",
                    )
            elif source == "directory":
                self._resolve_one(payload, "platformTools.setup.directory", "path")
            else:
                raise CommandFactoryError(
                    "platform_tools_source_invalid",
                    "Platform Tools source must be official or directory.",
                )
        elif command == "firmware.select":
            if "grant" in payload:
                self._resolve_one(payload, "firmware.select", "path")
        elif command == "boot.select" and "grant" in payload:
            if "bootId" in payload:
                raise CommandFactoryError(
                    "resource_target_ambiguous", "Choose a boot ID or a native file, not both."
                )
            self._resolve_one(payload, "boot.select.source", "path")
        elif command == "boot.patch":
            self._resolve_one(payload, "boot.patch.destination", "destination")
            secret_token = payload.pop("secretGrant", None)
            if secret_token is not None:
                if payload.get("flavor", payload.get("method")) != "apatch":
                    raise CommandFactoryError(
                        "secret_grant_not_applicable",
                        "An APatch secret grant is valid only for APatch patching.",
                    )
                try:
                    payload["superKey"] = self.secret_grants.consume(
                        str(secret_token), purpose="apatch.superkey"
                    )
                except GrantError as exc:
                    raise CommandFactoryError(exc.code, str(exc)) from exc
        elif command == "root.modules.action":
            if payload.get("action") == "install":
                self._resolve_one(payload, "root.modules.install", "path")
            elif "grant" in payload:
                raise CommandFactoryError(
                    "grant_not_applicable", "This module action does not accept a file grant."
                )
        elif command == "tools.pif":
            if payload.get("action") == "importProfile":
                self._resolve_one(payload, "root.pif.import", "path")
            elif "grant" in payload:
                raise CommandFactoryError(
                    "grant_not_applicable", "PIF deletion does not accept a file grant."
                )
        elif command == "apps.action":
            if payload.get("action") == "install":
                self._resolve_one(payload, "apps.install.source", "path")
            elif payload.get("action") == "export":
                token = payload.pop("grant", None)
                if not isinstance(token, str):
                    raise CommandFactoryError(
                        "grant_required",
                        "A native APK export grant is required.",
                    )
                spec = _SPECS_BY_PURPOSE["apps.export.destination"]
                try:
                    payload["exportDestination"] = (
                        self.path_grants.resolve_bound_write_file(
                            token,
                            purpose=spec.purpose,
                        )
                    )
                except GrantError as exc:
                    raise CommandFactoryError(exc.code, str(exc)) from exc
            elif "grant" in payload:
                raise CommandFactoryError(
                    "grant_not_applicable", "This package action does not accept a file grant."
                )
        elif command == "backups.create":
            self._resolve_one(payload, "backups.create.destination", "destination")
        elif command == "backups.restore":
            if "backupId" not in payload:
                self._resolve_one(payload, "backups.restore.source", "path")
        elif command == "backups.magisk.import":
            self._resolve_one(payload, "backups.magisk.import.source", "path")
        elif command == "root.dataAdb.backup":
            token = payload.pop("grant", None)
            if not isinstance(token, str):
                raise CommandFactoryError(
                    "grant_required", "A native /data/adb backup destination is required."
                )
            spec = _SPECS_BY_PURPOSE["root.dataAdb.backup.destination"]
            try:
                payload["destination"] = self.path_grants.resolve_bound_write_file(
                    token,
                    purpose=spec.purpose,
                )
            except GrantError as exc:
                raise CommandFactoryError(exc.code, str(exc)) from exc
        elif command == "root.dataAdb.restore":
            token = payload.pop("grant", None)
            if not isinstance(token, str):
                raise CommandFactoryError(
                    "grant_required", "A native /data/adb restore source is required."
                )
            spec = _SPECS_BY_PURPOSE["root.dataAdb.restore.source"]
            try:
                payload["source"] = self.path_grants.resolve_bound_file(
                    token,
                    purpose=spec.purpose,
                )
            except GrantError as exc:
                raise CommandFactoryError(exc.code, str(exc)) from exc
        elif command == "partitions.read":
            self._resolve_one(payload, "partitions.read.destination", "destination")
        elif command == "partitions.write":
            self._resolve_one(payload, "partitions.write.source", "path")
        elif command == "tools.pushFiles":
            raw_grants = payload.pop("grants", None)
            if not isinstance(raw_grants, list):
                raise CommandFactoryError(
                    "grant_required", "Native file grants are required for this command."
                )
            grants = cast("list[object]", raw_grants)
            if (
                not 1 <= len(grants) <= 32
                or any(not isinstance(token, str) or not token for token in grants)
            ):
                raise CommandFactoryError(
                    "grant_required", "Native file grants are required for this command."
                )
            spec = _SPECS_BY_PURPOSE["tools.pushFiles.sources"]
            try:
                bound_paths: list[BoundReadFile] = [
                    self.path_grants.resolve_bound_file(
                        token,
                        purpose=spec.purpose,
                    )
                    for token in cast("list[str]", grants)
                ]
            except GrantError as exc:
                raise CommandFactoryError(exc.code, str(exc)) from exc
            payload["paths"] = bound_paths
        elif command == "tools.logcat":
            token = payload.pop("grant", None)
            if token is not None:
                if not isinstance(token, str):
                    raise CommandFactoryError(
                        "grant_required", "A native export grant is required."
                    )
                spec = _SPECS_BY_PURPOSE["tools.logcat.export"]
                try:
                    destination: BoundWriteFile = (
                        self.path_grants.resolve_bound_write_file(
                            token,
                            purpose=spec.purpose,
                        )
                    )
                except GrantError as exc:
                    raise CommandFactoryError(exc.code, str(exc)) from exc
                payload["exportDestination"] = destination
        elif command == "tools.avb":
            token = payload.pop("grant", None)
            if token is not None:
                if not isinstance(token, str):
                    raise CommandFactoryError(
                        "grant_required", "A native current-boot grant is required."
                    )
                spec = _SPECS_BY_PURPOSE["tools.avb.currentBoot"]
                try:
                    payload["currentBoot"] = self.path_grants.resolve_bound_file(
                        token,
                        purpose=spec.purpose,
                    )
                except GrantError as exc:
                    raise CommandFactoryError(exc.code, str(exc)) from exc
        elif command == "tools.xml":
            token = payload.pop("grant", None)
            if not isinstance(token, str):
                raise CommandFactoryError(
                    "grant_required", "A native binary-XML grant is required."
                )
            spec = _SPECS_BY_PURPOSE["tools.xml.source"]
            try:
                payload["source"] = self.path_grants.resolve_bound_file(
                    token,
                    purpose=spec.purpose,
                )
            except GrantError as exc:
                raise CommandFactoryError(exc.code, str(exc)) from exc
        elif command == "tools.keybox":
            raw_grants = payload.pop("grants", None)
            if not isinstance(raw_grants, list):
                raise CommandFactoryError(
                    "grant_required", "Native keybox file grants are required."
                )
            grants = cast("list[object]", raw_grants)
            if (
                not 1 <= len(grants) <= 32
                or any(not isinstance(token, str) or not token for token in grants)
            ):
                raise CommandFactoryError(
                    "grant_required", "Native keybox file grants are required."
                )
            spec = _SPECS_BY_PURPOSE["tools.keybox.sources"]
            try:
                payload["sources"] = [
                    self.path_grants.resolve_bound_file(token, purpose=spec.purpose)
                    for token in cast("list[str]", grants)
                ]
            except GrantError as exc:
                raise CommandFactoryError(exc.code, str(exc)) from exc
        elif command == "tools.wifi":
            secret_token = payload.pop("secretGrant", None)
            if payload.get("action") == "pair":
                if not isinstance(secret_token, str):
                    raise CommandFactoryError(
                        "secret_grant_required",
                        "A native Wi-Fi pairing-code grant is required.",
                    )
                try:
                    payload["pairingCode"] = self.secret_grants.consume(
                        secret_token,
                        purpose="wifi.pairingCode",
                    )
                except GrantError as exc:
                    raise CommandFactoryError(exc.code, str(exc)) from exc
            elif secret_token is not None:
                raise CommandFactoryError(
                    "secret_grant_not_applicable",
                    "This Wi-Fi action does not accept a secret grant.",
                )
        elif command == "support.create":
            registrar = self._support_destination_registrar
            if registrar is None:
                raise CommandFactoryError(
                    "support_destination_unavailable",
                    "Support destination registration is unavailable.",
                )
            path = self._pop_and_resolve(payload, "support.create.destination")
            try:
                destination_id = registrar(path, allow_overwrite=path.exists())
            except Exception as exc:
                raise CommandFactoryError(
                    "support_destination_invalid",
                    "The selected support destination is invalid.",
                ) from exc
            payload["destinationId"] = destination_id

    def _resolve_one(self, payload: dict[str, Any], purpose: str, field: str) -> None:
        payload[field] = str(self._pop_and_resolve(payload, purpose))

    def _pop_and_resolve(self, payload: dict[str, Any], purpose: str) -> Path:
        token = payload.pop("grant", None)
        if not isinstance(token, str):
            raise CommandFactoryError(
                "grant_required", "A native resource grant is required for this command."
            )
        spec = _SPECS_BY_PURPOSE[purpose]
        try:
            return self.path_grants.resolve(
                token,
                purpose=spec.purpose,
                target=spec.target,
                access=spec.access,
            )
        except GrantError as exc:
            raise CommandFactoryError(exc.code, str(exc)) from exc


def create_command_factory(
    snapshot_provider: SnapshotProvider,
    *,
    path_grants: PathGrantStore | None = None,
    secret_grants: SecretGrantStore | None = None,
) -> CoreCommandFactory:
    return CoreCommandFactory(
        snapshot_provider,
        path_grants=path_grants,
        secret_grants=secret_grants,
    )


def _target_serial(
    payload: Mapping[str, Any],
    snapshot: AppSnapshot,
    command: str,
) -> str | None:
    if command not in DEVICE_SCOPED_COMMANDS:
        return None
    raw = payload.get("serial")
    if raw is not None and (not isinstance(raw, str) or not raw.strip()):
        raise CommandFactoryError("target_serial_invalid", "payload.serial must be a non-empty string")
    if (
        raw is None
        and command in {"flash.plan.preview", "flash.execute"}
        and len(snapshot.selected_serials) > 1
    ):
        return None
    serial = raw.strip() if isinstance(raw, str) else snapshot.selected_serial
    if not serial:
        raise CommandFactoryError(
            "target_serial_required", "A target serial is required for this command"
        )
    return serial


__all__ = [
    "CommandFactoryError",
    "CoreCommandFactory",
    "NativeGrantSpec",
    "create_command_factory",
]
