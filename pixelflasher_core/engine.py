"""Synchronous command boundary for the UI-independent application core."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import threading
from collections.abc import Callable, Generator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any, Protocol, cast
from uuid import uuid4

from .avb_downgrade import (
    DowngradePatchResult,
    DowngradePatchService,
    DowngradePatchStatus,
)
from .backup_repository import (
    BackupDeletionReceipt,
    BackupProvenance,
    BackupRepository,
    BackupRepositoryError,
)
from .backups import (
    BACKUP_COMMANDS,
    BackupCompilation,
    BackupPlanningError,
    BackupService,
    parse_magisk_backup_list,
)
from .binary_xml import BinaryXmlService, BinaryXmlStatus
from .boot_inventory import (
    BOOT_DELETE_COMMAND,
    BOOT_INVENTORY_COMMAND,
    BOOT_SELECT_COMMAND,
    BootDeletionReceipt,
    BootInventoryError,
    BootInventoryService,
    BootSelection,
)
from .boot_patch import (
    BOOT_PATCH_COMMAND,
    BootPatchCompilation,
    BootPatchPlanningError,
    BootPatchService,
)
from .cancellation import CancellationReason, CancellationToken
from .contracts import (
    AppCommand,
    AppEvent,
    AppSnapshot,
    BootInfo,
    BootloaderLockEvidence,
    CommandAck,
    CommandKind,
    DeviceInfo,
    DeviceManagementState,
    FileArtifact,
    FirmwareInfo,
    FlashPlan,
    InteractionDecision,
    InteractionRequest,
    InteractionResponse,
    OperationFinished,
    OperationPlan,
    OperationResult,
    OperationStatus,
    ProgressEvent,
    ProgressPhase,
    SnapshotChanged,
    ToolchainInfo,
)
from .data_adb import (
    DATA_ADB_COMMANDS,
    DataAdbCompilation,
    DataAdbError,
    DataAdbService,
)
from .device_management import DeviceManagementError, reconcile_device_management
from .device_tools import (
    DEVICE_TOOL_COMMANDS,
    DeviceToolCompilation,
    DeviceToolPlanningError,
    DeviceToolsService,
)
from .devices import DeviceScanResult, DeviceService
from .executor import CommandExecutor
from .firmware import FirmwareInspector
from .firmware_artifacts import (
    FirmwareArtifactService,
    FirmwareProcessingResult,
    FirmwareProcessingStatus,
)
from .firmware_catalog import (
    FirmwareCatalogService,
    FirmwareCatalogStatus,
)
from .grants import BoundReadFile, GrantError
from .interaction import InteractionTimeoutError
from .keybox_validation import (
    KeyboxAnalysisStatus,
    KeyboxStatus,
    KeyboxValidationService,
)
from .module_updates import (
    ModuleUpdateStatus,
    RootModuleUpdateService,
)
from .my_tools import MyToolsError, MyToolsService
from .operation_runner import (
    CancellationCleanup,
    ExecutionBoundaryAck,
    OperationExecutor,
    OperationRunner,
    PostconditionObserverLike,
    SnapshotProvider,
)
from .ota_diagnostics import (
    OTA_DIAGNOSTIC_COMMANDS,
    OtaDiagnosticCompilation,
    OtaDiagnosticPlanningError,
    OtaDiagnosticsService,
)
from .packages import (
    PACKAGE_COMMANDS,
    PackageCompilation,
    PackagePlanningError,
    PackageResultError,
    PackageService,
    parse_package_list,
    parse_package_permissions,
)
from .partitions import (
    PARTITION_COMMANDS,
    PartitionCompilation,
    PartitionPlanningError,
    PartitionReadEvidence,
    PartitionService,
    parse_fastboot_partition_list,
)
from .planner import PLANNED_COMMANDS, OperationPlanner
from .platform_tools import PlatformToolsStatus
from .platform_tools_setup import PlatformToolsSetupService
from .repositories import ArtifactProvenance, FirmwareRepository, RepositoryError
from .root_app_catalog import (
    RootAppCatalogService,
    RootAppCatalogStatus,
    RootAppDownloadResult,
)
from .rooting import (
    ROOTING_COMMANDS,
    PreparedRootModuleUpdate,
    RootingCompilation,
    RootingPlanningError,
    RootingService,
    parse_pi_analysis,
    parse_pif_document,
    parse_pif_inventory,
    parse_root_module_list,
)
from .safety import SafetyPolicy
from .scrcpy_artifacts import ScrcpyStatus
from .scrcpy_setup import ScrcpySetupService
from .store import AppStateStore, StaleRevisionError, Subscription
from .support import (
    SUPPORT_COMMAND,
    SupportPackageResult,
    SupportPackageStatus,
)
from .support_v2_service import (
    CancellationProbe as SupportCancellationProbe,
)
from .toolchain import ToolchainService
from .updates import UpdateService, UpdateStatus

InteractionHandler = Callable[[InteractionRequest], InteractionDecision | bool]
EngineListener = Callable[[AppEvent], None]
EngineSubscriber = Callable[[EngineListener, bool], Callable[[], None]]
EnginePublisher = Callable[[AppEvent], None]
CommandHandler = Callable[[AppCommand], OperationResult]
CancellationHandler = Callable[[str], CommandAck]
InteractionResponder = Callable[[str, InteractionResponse], CommandAck]
ShutdownHandler = Callable[[], None]
ResultParser = Callable[[OperationResult], OperationResult]
ResultFinalizer = Callable[[OperationResult, CancellationToken], OperationResult]
ExecutionPreflight = Callable[
    [AppCommand, OperationPlan, AppSnapshot, CancellationToken],
    ExecutionBoundaryAck,
]
CompletionBoot = Callable[[OperationResult], BootInfo | None]
ToolchainStateUpdater = Callable[[AppCommand, ToolchainInfo], OperationResult]
ScrcpyStateUpdater = Callable[[AppCommand, Path], OperationResult]
DeviceScanStateUpdater = Callable[
    [AppCommand, tuple[DeviceInfo, ...], DeviceManagementState, ToolchainInfo],
    OperationResult,
]


class SupportPackageBackend(Protocol):
    def register_destination(
        self,
        destination: str | Path,
        *,
        allow_overwrite: bool = False,
    ) -> str: ...

    def create(
        self,
        payload: Mapping[str, Any],
        *,
        snapshot: object,
        cancellation: SupportCancellationProbe | None = None,
    ) -> SupportPackageResult: ...

    def shutdown(self) -> None: ...


_SERVICE_COMMANDS = (
    PACKAGE_COMMANDS
    | PARTITION_COMMANDS
    | DEVICE_TOOL_COMMANDS
    | OTA_DIAGNOSTIC_COMMANDS
    | BACKUP_COMMANDS
    | DATA_ADB_COMMANDS
    | ROOTING_COMMANDS
    | frozenset({BOOT_PATCH_COMMAND})
)
_ServiceCompilation = (
    PackageCompilation
    | PartitionCompilation
    | DeviceToolCompilation
    | OtaDiagnosticCompilation
    | BackupCompilation
    | DataAdbCompilation
    | RootingCompilation
    | BootPatchCompilation
)


def deny_interaction(_request: InteractionRequest) -> InteractionDecision:
    """Safe default for a headless process with no confirmation channel."""

    return InteractionDecision.CANCELLED


class CommandEngine:
    """Compile and execute typed commands below the public application facade."""

    def __init__(
        self,
        *,
        store: AppStateStore,
        executor: CommandExecutor,
        safety_policy: SafetyPolicy,
        interaction_handler: InteractionHandler,
        toolchain_service: ToolchainService,
        platform_tools_setup_service: PlatformToolsSetupService,
        scrcpy_setup_service: ScrcpySetupService,
        device_service: DeviceService,
        firmware_inspector: FirmwareInspector,
        operation_planner: OperationPlanner,
        package_service: PackageService,
        partition_service: PartitionService,
        device_tools_service: DeviceToolsService,
        ota_diagnostics_service: OtaDiagnosticsService,
        backup_service: BackupService,
        backup_repository: BackupRepository,
        data_adb_service: DataAdbService,
        rooting_service: RootingService,
        boot_patch_service: BootPatchService,
        firmware_artifact_service: FirmwareArtifactService,
        support_package_service: SupportPackageBackend,
        operation_runner: OperationRunner,
        snapshot_provider: SnapshotProvider,
        postcondition_observer: PostconditionObserverLike,
        boot_inventory_service: BootInventoryService | None,
        firmware_repository: FirmwareRepository | None,
        toolchain_state_updater: ToolchainStateUpdater | None,
        scrcpy_state_updater: ScrcpyStateUpdater | None,
        device_scan_state_updater: DeviceScanStateUpdater | None,
        firmware_catalog_service: FirmwareCatalogService,
        root_app_catalog_service: RootAppCatalogService,
        root_module_update_service: RootModuleUpdateService,
        avb_downgrade_service: DowngradePatchService,
        binary_xml_service: BinaryXmlService,
        keybox_validation_service: KeyboxValidationService,
        my_tools_service: MyToolsService,
        update_service: UpdateService | None,
    ) -> None:
        if firmware_artifact_service.repository is not operation_planner.artifact_repository:
            raise ValueError("firmware artifact service and operation planner must share one repository")
        if avb_downgrade_service.repository is not operation_planner.artifact_repository:
            raise ValueError("AVB downgrade service and operation planner must share one repository")
        if operation_runner.executor is not executor:
            raise ValueError("operation runner and command engine must share one executor")
        if operation_runner.safety_policy is not safety_policy:
            raise ValueError("operation runner and command engine must share one safety policy")
        if operation_runner.snapshot_provider is not snapshot_provider:
            raise ValueError("operation runner and command engine must share one snapshot provider")
        if operation_runner.postcondition_observer is not postcondition_observer:
            raise ValueError("operation runner and command engine must share one postcondition observer")
        if toolchain_service.transport is not executor.transport:
            raise ValueError("toolchain service and command engine must share one process transport")
        if platform_tools_setup_service.toolchain_service is not toolchain_service:
            raise ValueError("Platform Tools setup and command engine must share one toolchain service")
        if device_service.transport is not executor.transport:
            raise ValueError("device service and command engine must share one process transport")
        if boot_patch_service.rooting_service is not rooting_service:
            raise ValueError("boot patch service and command engine must share one rooting service")
        if root_app_catalog_service.rooting_service is not rooting_service:
            raise ValueError("root-app catalog and command engine must share one rooting service")
        self.store = store
        self.executor = executor
        self.safety_policy = safety_policy
        self.interaction_handler = interaction_handler
        self.toolchain_service = toolchain_service
        self.platform_tools_setup_service = platform_tools_setup_service
        self.scrcpy_setup_service = scrcpy_setup_service
        self.toolchain_state_updater = toolchain_state_updater
        self.scrcpy_state_updater = scrcpy_state_updater
        self.device_scan_state_updater = device_scan_state_updater
        self.device_service = device_service
        self.firmware_inspector = firmware_inspector
        self.operation_planner = operation_planner
        self.firmware_artifact_service = firmware_artifact_service
        self.package_service = package_service
        self.partition_service = partition_service
        self.device_tools_service = device_tools_service
        self.ota_diagnostics_service = ota_diagnostics_service
        self.backup_service = backup_service
        self.backup_repository = backup_repository
        self.data_adb_service = data_adb_service
        self.rooting_service = rooting_service
        self.boot_patch_service = boot_patch_service
        self.boot_inventory_service = boot_inventory_service
        self.firmware_repository = firmware_repository
        self.firmware_catalog_service = firmware_catalog_service
        self.root_app_catalog_service = root_app_catalog_service
        self.root_module_update_service = root_module_update_service
        self.avb_downgrade_service = avb_downgrade_service
        self.binary_xml_service = binary_xml_service
        self.keybox_validation_service = keybox_validation_service
        self.my_tools_service = my_tools_service
        self.support_package_service = support_package_service
        self.update_service = update_service
        self.snapshot_provider = snapshot_provider
        self.postcondition_observer = postcondition_observer
        self.operation_runner = operation_runner
        # The canonical snapshot exposes one active operation, so process-backed
        # operations share this lock. In particular, destructive operations can
        # never overlap.
        self._operation_lock = threading.Lock()
        self._lifecycle_lock = threading.RLock()
        self._cancellation_lock = threading.RLock()
        self._cancellations: dict[str, CancellationToken] = {}
        self._shutdown = False

    def execute(self, command: AppCommand) -> OperationResult:
        """Execute synchronously; this method never returns an implicit ``None``."""

        with self._lifecycle_lock:
            if self._shutdown:
                return OperationResult.failed(
                    command.operation_id,
                    code="engine_shutdown",
                    message="the application engine has shut down",
                )

        if command.kind == CommandKind.SNAPSHOT_GET.value:
            return OperationResult.success(
                command.operation_id,
                code="snapshot",
                value=self.store.snapshot().to_dict(),
            )

        if command.kind in _SERVICE_COMMANDS:
            return self._compile_service_command(command)

        if command.kind in PLANNED_COMMANDS:
            if command.operation_plan is not None:
                return self._execute_process(command)
            return self._plan_and_execute(command)

        if command.kind == CommandKind.DEVICE_SELECT.value:
            return self._select_device(command)
        if command.kind == "platformTools.setup":
            return self._setup_platform_tools(command)
        if command.kind == "tools.scrcpy.setup":
            return self._setup_scrcpy(command)
        if command.kind in {"firmware.catalog.refresh", "firmware.download"}:
            return self._firmware_catalog_command(command)
        if command.kind in {"root.apps.catalog.refresh", "root.apps.download"}:
            return self._root_app_catalog_command(command)
        if command.kind == "updates.check":
            return self._check_updates(command)
        if command.kind == CommandKind.DEVICE_SCAN.value:
            # Compatibility for milestone-1 callers that inject an already
            # reviewed plan. Browser commands never provide operation plans.
            if command.operation_plan is not None:
                return self._execute_process(command)
            return self._scan_devices(command)
        if command.kind == CommandKind.FIRMWARE_SELECT.value:
            return self._inspect_firmware(command)
        if command.kind == BOOT_INVENTORY_COMMAND:
            return self._list_boot_inventory(command)
        if command.kind == BOOT_SELECT_COMMAND:
            return self._select_boot(command)
        if command.kind == BOOT_DELETE_COMMAND:
            return self._delete_boot(command)
        if command.kind == "backups.list":
            return self._list_backups(command)
        if command.kind == "backups.delete":
            return self._delete_backup(command)
        if command.kind == "firmware.process":
            return self._process_firmware(command)
        if command.kind == SUPPORT_COMMAND:
            return self._create_support_package(command)
        if command.kind == CommandKind.FLASH_PLAN_UPDATE.value:
            return self._update_flash_plan(command)
        if command.kind == "flash.plan.preview":
            return self._preview_flash_plan(command)
        if command.kind == "tools.avb":
            return self._prepare_avb_downgrade(command)
        if command.kind == "tools.xml":
            return self._decode_binary_xml(command)
        if command.kind == "tools.keybox":
            return self._analyze_keyboxes(command)
        if command.kind == "tools.myTools":
            return self._my_tools_command(command)
        return OperationResult.failed(
            command.operation_id,
            code="command_unknown",
            message=f"unsupported command kind: {command.kind}",
        )

    def _my_tools_command(self, command: AppCommand) -> OperationResult:
        payload = command.payload
        action = payload.get("action")
        allowed = {"action", "toolId", "title", "grant", "arguments", "enabled"}
        if set(payload) - allowed or action not in {"list", "save", "delete", "run"}:
            return self._invalid(command, "Personal tools payload is invalid.")
        if command.target_serial is not None or command.operation_plan is not None:
            return self._invalid(command, "Personal tools are local and do not accept a target or plan.")
        decision = self.safety_policy.evaluate(command, self.store.snapshot())
        if not decision.allowed:
            return self._denied(command, decision.code, decision.message)
        tool_id = payload.get("toolId")
        try:
            if action == "list":
                if len(payload) != 1:
                    return self._invalid(command, "Listing personal tools accepts no extra fields.")
                return OperationResult.success(
                    command.operation_id,
                    code="my_tools_listed",
                    value={
                        **self.my_tools_service.repository.inventory(),
                        "revision": self.store.snapshot().revision,
                    },
                )
            if action == "save":
                required = {"action", "title", "arguments", "enabled"}
                if not required.issubset(payload):
                    return self._invalid(command, "Saving a personal tool requires title, arguments, and enabled.")
                grant = payload.get("grant")
                if grant is not None and not isinstance(grant, BoundReadFile):
                    return self._invalid(command, "Personal tool executable must use a native grant.")
                if tool_id is not None and not isinstance(tool_id, str):
                    return self._invalid(command, "Personal tool id is invalid.")
                saved = self.my_tools_service.repository.save(
                    title=payload["title"],
                    executable=grant,
                    arguments=payload["arguments"],
                    enabled=payload["enabled"],
                    tool_id=tool_id,
                )
                return OperationResult.success(
                    command.operation_id,
                    code="my_tool_saved",
                    message="Personal tool saved.",
                    value={"tool": saved.to_public_dict(), "revision": self.store.snapshot().revision},
                )
            if not isinstance(tool_id, str) or set(payload) != {"action", "toolId"}:
                return self._invalid(command, "This action requires exactly one personal tool id.")
            if action == "delete":
                self.my_tools_service.repository.delete(tool_id)
                return OperationResult.success(
                    command.operation_id,
                    code="my_tool_deleted",
                    message="Personal tool deleted.",
                    value={"toolId": tool_id, "revision": self.store.snapshot().revision},
                )
            token = self._register_cancellation(command)
            if token is None:
                return self._denied(command, "operation_busy", "operation id is already active")
            try:
                with self._operation_guard(token) as acquired:
                    if not acquired or token.cancelled:
                        return self._stopped_result(
                            command,
                            token,
                            cancelled_code="my_tool_cancelled",
                            cancelled_message="Personal tool was cancelled before it started.",
                            timeout_message="Personal tool timed out before it started.",
                        )
                    current = self.store.snapshot()
                    decision = self.safety_policy.evaluate(command, current)
                    if not decision.allowed:
                        return self._denied(command, decision.code, decision.message)
                    result = self.my_tools_service.run(command, tool_id, token)
                    if not result.ok:
                        return result
                    raw_value = cast(object, result.value)
                    value: Mapping[str, object]
                    if isinstance(raw_value, Mapping):
                        value = cast(Mapping[str, object], raw_value)
                    else:
                        value = {}
                    return replace(
                        result,
                        value={**value, "revision": self.store.snapshot().revision},
                    )
            finally:
                self._unregister_cancellation(command.operation_id)
        except MyToolsError as error:
            return OperationResult.failed(command.operation_id, code=error.code, message=str(error))

    def _check_updates(self, command: AppCommand) -> OperationResult:
        if command.payload or command.target_serial is not None or command.operation_plan is not None:
            return self._invalid(command, "Application update checks accept no payload or target.")
        snapshot = self.store.snapshot()
        decision = self.safety_policy.evaluate(command, snapshot)
        if not decision.allowed:
            return self._denied(command, decision.code, decision.message)
        service = self.update_service
        if service is None:
            return OperationResult.failed(
                command.operation_id,
                code="update_manifest_unavailable",
                message="Signed application update metadata is not provisioned.",
            )
        token = self._register_cancellation(command)
        if token is None:
            return self._denied(command, "operation_busy", "operation id is already active")
        try:
            with self._operation_guard(token) as acquired:
                if not acquired or token.cancelled:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="update_check_cancelled",
                        cancelled_message="Application update check was cancelled.",
                        timeout_message="Application update check timed out.",
                    )
                current = self.store.snapshot()
                decision = self.safety_policy.evaluate(command, current)
                if not decision.allowed:
                    return self._denied(command, decision.code, decision.message)
                checked = service.check(token)
                if checked.status is UpdateStatus.CANCELLED:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code=checked.code,
                        cancelled_message=checked.message,
                        timeout_message="Application update check timed out.",
                    )
                if not checked.ok:
                    return OperationResult.failed(
                        command.operation_id,
                        code=checked.code,
                        message=checked.message,
                    )
                return OperationResult.success(
                    command.operation_id,
                    code=checked.code,
                    message=checked.message,
                    value={**checked.to_public_dict(), "revision": current.revision},
                )
        finally:
            self._unregister_cancellation(command.operation_id)

    def _prepare_avb_downgrade(self, command: AppCommand) -> OperationResult:
        allowed_fields = {
            "action",
            "currentBoot",
            "currentSecurityPatch",
            "patchFingerprint",
        }
        if set(command.payload) - allowed_fields or command.payload.get("action") != "prepareDowngrade":
            return OperationResult.failed(
                command.operation_id,
                code="avb_downgrade_payload_invalid",
                message="tools.avb requires the canonical prepareDowngrade payload",
            )
        current_resource = command.payload.get("currentBoot")
        current_security_patch = command.payload.get("currentSecurityPatch", "")
        patch_fingerprint = command.payload.get("patchFingerprint", False)
        if not isinstance(patch_fingerprint, bool):
            return OperationResult.failed(
                command.operation_id,
                code="avb_downgrade_payload_invalid",
                message="patchFingerprint must be a boolean",
            )
        if not isinstance(current_security_patch, str):
            return OperationResult.failed(
                command.operation_id,
                code="avb_downgrade_source_invalid",
                message="current security patch must be a string",
            )
        has_current_resource = isinstance(current_resource, BoundReadFile)
        has_security_patch = bool(current_security_patch)
        if has_current_resource == has_security_patch:
            return OperationResult.failed(
                command.operation_id,
                code="avb_downgrade_source_invalid",
                message="choose exactly one verified current boot image or security patch",
            )
        if current_resource is not None and not isinstance(current_resource, BoundReadFile):
            return OperationResult.failed(
                command.operation_id,
                code="avb_downgrade_source_invalid",
                message="current boot must be a purpose-bound native file grant",
            )
        if patch_fingerprint and current_resource is None:
            return OperationResult.failed(
                command.operation_id,
                code="current_fingerprint_unavailable",
                message="fingerprint patching requires a verified current boot image",
            )
        initial = self.store.snapshot()
        decision = self.safety_policy.evaluate(command, initial)
        if not decision.allowed:
            return self._denied(command, decision.code, decision.message)
        if (
            initial.firmware.type.casefold() != "factory"
            or not initial.firmware.verified
            or not initial.firmware.processed
            or not initial.firmware.hash
        ):
            return OperationResult.failed(
                command.operation_id,
                code="processed_factory_firmware_required",
                message="select and process verified factory firmware before preparing downgrade boot",
            )

        token = self._register_cancellation(command)
        if token is None:
            return self._denied(command, "operation_busy", "operation id is already active")
        processing: DowngradePatchResult | None = None
        try:
            with self._operation_guard(token) as acquired:
                if not acquired or token.cancelled:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="downgrade_patch_cancelled",
                        cancelled_message="downgrade patch creation was cancelled before it started",
                        timeout_message="downgrade patch creation timed out before it started",
                    )
                snapshot = self.store.snapshot()
                decision = self.safety_policy.evaluate(command, snapshot)
                if not decision.allowed:
                    return self._denied(command, decision.code, decision.message)
                if snapshot.firmware != initial.firmware or snapshot.plan != initial.plan:
                    return self._denied(
                        command,
                        "avb_downgrade_context_changed",
                        "firmware or flash plan changed before downgrade preparation",
                    )
                try:
                    active = self.store.begin_operation(
                        command.operation_id,
                        expected_revision=snapshot.revision,
                        kind="tools.avb",
                        label="Prepare AVB downgrade boot",
                    )
                except StaleRevisionError as error:
                    return self._denied(command, "stale_revision", str(error))
                except ValueError as error:
                    return self._denied(command, "operation_busy", str(error))

                current_artifact: FileArtifact | None = None
                try:
                    if isinstance(current_resource, BoundReadFile):
                        current_artifact = self._materialize_avb_current_boot(
                            current_resource,
                            token,
                        )
                    processing = self.avb_downgrade_service.create(
                        firmware_hash=snapshot.firmware.hash,
                        plan_fingerprint=snapshot.plan.fingerprint,
                        current_boot=current_artifact,
                        current_security_patch=(
                            current_security_patch if isinstance(current_security_patch, str) else ""
                        ),
                        patch_fingerprint=patch_fingerprint,
                        cancellation=token,
                    )
                except (GrantError, OSError, ValueError) as error:
                    processing = None
                    result = (
                        self._stopped_result(
                            command,
                            token,
                            cancelled_code="downgrade_patch_cancelled",
                            cancelled_message="downgrade patch creation was cancelled",
                            timeout_message="downgrade patch creation timed out",
                        )
                        if token.cancelled
                        else OperationResult.failed(
                            command.operation_id,
                            code="current_boot_materialization_failed",
                            message=str(error),
                        )
                    )
                else:
                    if processing.status is DowngradePatchStatus.CANCELLED:
                        result = self._stopped_result(
                            command,
                            token,
                            cancelled_code=processing.code.value,
                            cancelled_message=processing.message,
                            timeout_message="downgrade patch creation timed out",
                        )
                    elif not processing.ok or processing.artifact is None:
                        result = OperationResult.failed(
                            command.operation_id,
                            code=processing.code.value,
                            message=processing.message,
                        )
                    else:
                        result = OperationResult.success(
                            command.operation_id,
                            code=processing.code.value,
                            message=processing.message,
                            value={
                                "artifact": {
                                    "sha256": processing.artifact.sha256,
                                    "role": processing.artifact.role,
                                },
                                "currentSecurityPatch": processing.current_security_patch,
                                "targetSecurityPatch": processing.target_security_patch,
                                "verified": True,
                            },
                        )
                finally:
                    if current_artifact is not None:
                        shutil.rmtree(Path(current_artifact.path).parent, ignore_errors=True)

                current = self.store.snapshot()
                context_changed = (
                    current.revision != active.revision
                    or current.active_operation is None
                    or current.active_operation.operation_id != command.operation_id
                    or current.firmware != snapshot.firmware
                    or current.plan != snapshot.plan
                )
                if result.ok and (token.cancelled or context_changed):
                    result = (
                        self._stopped_result(
                            command,
                            token,
                            cancelled_code="downgrade_patch_cancelled",
                            cancelled_message="downgrade patch creation was cancelled before promotion",
                            timeout_message="downgrade patch creation timed out before promotion",
                        )
                        if token.cancelled
                        else OperationResult.failed(
                            command.operation_id,
                            code="avb_downgrade_context_changed",
                            message="firmware or flash plan changed while preparing downgrade boot",
                        )
                    )
                if processing is not None and processing.ok and not result.ok:
                    result = self._rollback_avb_downgrade(command, processing, result)
                try:
                    self.store.complete_operation(
                        result,
                        expected_revision=active.revision if result.ok else None,
                    )
                except (StaleRevisionError, TypeError, ValueError) as error:
                    fallback = OperationResult.failed(
                        command.operation_id,
                        code="avb_downgrade_state_promotion_failed",
                        message=str(error),
                    )
                    if processing is not None and processing.ok and result.ok:
                        fallback = self._rollback_avb_downgrade(command, processing, fallback)
                    self._abort_operation_safely(fallback)
                    return fallback
                return result
        finally:
            self._unregister_cancellation(command.operation_id)

    def _decode_binary_xml(self, command: AppCommand) -> OperationResult:
        if (
            set(command.payload) != {"action", "source"}
            or command.payload.get("action") != "decodeBinary"
            or not isinstance(command.payload.get("source"), BoundReadFile)
        ):
            return OperationResult.failed(
                command.operation_id,
                code="binary_xml_payload_invalid",
                message="tools.xml requires one purpose-bound binary XML grant",
            )
        source = cast(BoundReadFile, command.payload["source"])
        initial = self.store.snapshot()
        decision = self.safety_policy.evaluate(command, initial)
        if not decision.allowed:
            return self._denied(command, decision.code, decision.message)
        token = self._register_cancellation(command)
        if token is None:
            return self._denied(command, "operation_busy", "operation id is already active")
        try:
            with self._operation_guard(token) as acquired:
                if not acquired or token.cancelled:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="binary_xml_cancelled",
                        cancelled_message="binary XML decoding was cancelled before it started",
                        timeout_message="binary XML decoding timed out before it started",
                    )
                snapshot = self.store.snapshot()
                decision = self.safety_policy.evaluate(command, snapshot)
                if not decision.allowed:
                    return self._denied(command, decision.code, decision.message)
                try:
                    active = self.store.begin_operation(
                        command.operation_id,
                        expected_revision=snapshot.revision,
                        kind="tools.xml",
                        label="Decode Android binary XML",
                    )
                except StaleRevisionError as error:
                    return self._denied(command, "stale_revision", str(error))
                except ValueError as error:
                    return self._denied(command, "operation_busy", str(error))
                try:
                    with source.open_verified() as input_stream:
                        decoded = self.binary_xml_service.decode(
                            input_stream,
                            cancellation=token,
                        )
                except (GrantError, OSError) as error:
                    result = OperationResult.failed(
                        command.operation_id,
                        code="binary_xml_source_unavailable",
                        message=str(error),
                    )
                else:
                    if decoded.status is BinaryXmlStatus.CANCELLED:
                        result = self._stopped_result(
                            command,
                            token,
                            cancelled_code=decoded.code.value,
                            cancelled_message=decoded.message,
                            timeout_message="binary XML decoding timed out",
                        )
                    elif not decoded.ok:
                        result = OperationResult.failed(
                            command.operation_id,
                            code=decoded.code.value,
                            message=decoded.message,
                        )
                    else:
                        result = OperationResult.success(
                            command.operation_id,
                            code=decoded.code.value,
                            message=decoded.message,
                            value={
                                "format": "android-binary-xml",
                                "xml": decoded.xml,
                                "sha256": decoded.sha256,
                                "sizeBytes": decoded.size_bytes,
                                "elementCount": decoded.element_count,
                                "attributeCount": decoded.attribute_count,
                                "bounded": True,
                            },
                        )
                current = self.store.snapshot()
                if result.ok and (
                    token.cancelled
                    or current.revision != active.revision
                    or current.active_operation is None
                    or current.active_operation.operation_id != command.operation_id
                ):
                    result = (
                        self._stopped_result(
                            command,
                            token,
                            cancelled_code="binary_xml_cancelled",
                            cancelled_message="binary XML decoding was cancelled before completion",
                            timeout_message="binary XML decoding timed out before completion",
                        )
                        if token.cancelled
                        else OperationResult.failed(
                            command.operation_id,
                            code="binary_xml_context_changed",
                            message="application state changed while decoding binary XML",
                        )
                    )
                try:
                    self.store.complete_operation(
                        result,
                        expected_revision=active.revision if result.ok else None,
                    )
                except (StaleRevisionError, TypeError, ValueError) as error:
                    fallback = OperationResult.failed(
                        command.operation_id,
                        code="binary_xml_state_promotion_failed",
                        message=str(error),
                    )
                    self._abort_operation_safely(fallback)
                    return fallback
                return result
        finally:
            self._unregister_cancellation(command.operation_id)

    def _analyze_keyboxes(self, command: AppCommand) -> OperationResult:
        raw_sources = command.payload.get("sources")
        if (
            set(command.payload) != {"action", "sources"}
            or command.payload.get("action") != "analyze"
            or not isinstance(raw_sources, Sequence)
            or isinstance(raw_sources, (str, bytes))
        ):
            return OperationResult.failed(
                command.operation_id,
                code="keybox_payload_invalid",
                message="tools.keybox requires one to 32 purpose-bound keybox grants",
            )
        source_values = cast("Sequence[object]", raw_sources)
        if not 1 <= len(source_values) <= 32 or any(not isinstance(source, BoundReadFile) for source in source_values):
            return OperationResult.failed(
                command.operation_id,
                code="keybox_payload_invalid",
                message="tools.keybox requires one to 32 purpose-bound keybox grants",
            )
        sources = cast("Sequence[BoundReadFile]", source_values)
        initial = self.store.snapshot()
        decision = self.safety_policy.evaluate(command, initial)
        if not decision.allowed:
            return self._denied(command, decision.code, decision.message)
        token = self._register_cancellation(command)
        if token is None:
            return self._denied(command, "operation_busy", "operation id is already active")
        try:
            with self._operation_guard(token) as acquired:
                if not acquired or token.cancelled:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="keybox_analysis_cancelled",
                        cancelled_message="keybox analysis was cancelled before it started",
                        timeout_message="keybox analysis timed out before it started",
                    )
                snapshot = self.store.snapshot()
                decision = self.safety_policy.evaluate(command, snapshot)
                if not decision.allowed:
                    return self._denied(command, decision.code, decision.message)
                try:
                    active = self.store.begin_operation(
                        command.operation_id,
                        expected_revision=snapshot.revision,
                        kind="tools.keybox",
                        label="Analyze Android keyboxes",
                    )
                except StaleRevisionError as error:
                    return self._denied(command, "stale_revision", str(error))
                except ValueError as error:
                    return self._denied(command, "operation_busy", str(error))

                evidence, revocation_issue = self.keybox_validation_service.revocation_evidence()
                reports: list[dict[str, object]] = []
                result: OperationResult
                try:
                    for source in sources:
                        if token.cancelled:
                            break
                        with source.open_verified() as input_stream:
                            analyzed = self.keybox_validation_service.analyze(
                                source.path.name,
                                input_stream,
                                evidence=evidence,
                                revocation_issue=revocation_issue,
                                cancellation=token,
                            )
                        if analyzed.status is KeyboxAnalysisStatus.CANCELLED:
                            break
                        if not analyzed.ok or analyzed.report is None:
                            raise OSError("keybox analysis failed without a bounded report")
                        reports.append(analyzed.report.to_public_dict())
                except (GrantError, OSError, ValueError) as error:
                    result = OperationResult.failed(
                        command.operation_id,
                        code="keybox_source_unavailable",
                        message=str(error),
                    )
                else:
                    if token.cancelled:
                        result = self._stopped_result(
                            command,
                            token,
                            cancelled_code="keybox_analysis_cancelled",
                            cancelled_message="keybox analysis was cancelled",
                            timeout_message="keybox analysis timed out",
                        )
                    else:
                        status_counts = {
                            status.value: sum(report.get("status") == status.value for report in reports)
                            for status in KeyboxStatus
                        }
                        result = OperationResult.success(
                            command.operation_id,
                            code="keybox_analyzed",
                            message="keybox analysis completed",
                            value={
                                "reports": reports,
                                "count": len(reports),
                                "summary": {
                                    "valid": status_counts[KeyboxStatus.VALID.value],
                                    "unverified": status_counts[KeyboxStatus.UNVERIFIED.value],
                                    "revoked": status_counts[KeyboxStatus.REVOKED.value],
                                    "expired": status_counts[KeyboxStatus.EXPIRED.value],
                                    "softwareAttestation": status_counts[KeyboxStatus.SOFTWARE_ATTESTATION.value],
                                    "invalid": status_counts[KeyboxStatus.INVALID.value],
                                },
                                "revocationEvidence": (
                                    {
                                        "sourceId": evidence.source_id,
                                        "keyId": evidence.key_id,
                                        "issuedAt": evidence.issued_at.isoformat(),
                                        "expiresAt": evidence.expires_at.isoformat(),
                                        "authenticated": True,
                                    }
                                    if evidence is not None
                                    else None
                                ),
                                "bounded": True,
                            },
                        )
                current = self.store.snapshot()
                if result.ok and (
                    token.cancelled
                    or current.revision != active.revision
                    or current.active_operation is None
                    or current.active_operation.operation_id != command.operation_id
                ):
                    result = (
                        self._stopped_result(
                            command,
                            token,
                            cancelled_code="keybox_analysis_cancelled",
                            cancelled_message="keybox analysis was cancelled before completion",
                            timeout_message="keybox analysis timed out before completion",
                        )
                        if token.cancelled
                        else OperationResult.failed(
                            command.operation_id,
                            code="keybox_context_changed",
                            message="application state changed while analyzing keyboxes",
                        )
                    )
                try:
                    self.store.complete_operation(
                        result,
                        expected_revision=active.revision if result.ok else None,
                    )
                except (StaleRevisionError, TypeError, ValueError) as error:
                    fallback = OperationResult.failed(
                        command.operation_id,
                        code="keybox_state_promotion_failed",
                        message=str(error),
                    )
                    self._abort_operation_safely(fallback)
                    return fallback
                return result
        finally:
            self._unregister_cancellation(command.operation_id)

    def _materialize_avb_current_boot(
        self,
        resource: BoundReadFile,
        cancellation: CancellationToken,
    ) -> FileArtifact:
        root = self.avb_downgrade_service.output_root
        root.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix="current-boot-", dir=root))
        destination = staging / "current-boot.img"
        digest = hashlib.sha256()
        size = 0
        try:
            with resource.open_verified() as source, destination.open("xb") as output:
                while chunk := source.read(1024 * 1024):
                    if cancellation.cancelled:
                        raise OSError("current boot materialization was cancelled")
                    size += len(chunk)
                    if size > self.avb_downgrade_service.maximum_image_bytes:
                        raise ValueError("current boot image exceeds the configured size limit")
                    digest.update(chunk)
                    output.write(chunk)
            return FileArtifact(str(destination), digest.hexdigest(), "partition:boot")
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise

    def _rollback_avb_downgrade(
        self,
        command: AppCommand,
        processing: DowngradePatchResult,
        intended: OperationResult,
    ) -> OperationResult:
        try:
            self.avb_downgrade_service.rollback(processing)
        except Exception:
            return OperationResult.failed(
                command.operation_id,
                code="avb_downgrade_rollback_failed",
                message="downgrade artifact could not be rolled back safely",
            )
        return intended

    def _compile_service_command(self, command: AppCommand) -> OperationResult:
        """Compile one bounded domain intent, then use the common safe executor."""

        snapshot = self.store.snapshot()
        if command.expected_revision is None:
            return self._denied(
                command,
                "revision_required",
                "expected_revision is required",
            )
        if command.expected_revision != snapshot.revision:
            return self._denied(
                command,
                "stale_revision",
                (f"state revision changed: expected {command.expected_revision}, current {snapshot.revision}"),
            )

        # Register before any service performs filesystem I/O or hashing.  The
        # same token was created when the bridge request was accepted, so its
        # deadline includes queueing, planning, confirmation and execution.
        planning_token = self._register_cancellation(command)
        if planning_token is None:
            return self._denied(
                command,
                "operation_busy",
                "operation id is already active",
            )

        compilation: _ServiceCompilation
        try:
            if command.kind == BOOT_PATCH_COMMAND:
                assert planning_token is not None
                compilation = self.boot_patch_service.compile(
                    command,
                    snapshot,
                    planning_token,
                )
            elif command.kind in PACKAGE_COMMANDS:
                compilation = self.package_service.compile(
                    command,
                    snapshot,
                    planning_token,
                )
            elif command.kind in PARTITION_COMMANDS:
                partition_command = command
                if command.kind == "partitions.erase" and "confirmationText" in command.payload:
                    partition_command = replace(
                        command,
                        payload={key: value for key, value in command.payload.items() if key != "confirmationText"},
                    )
                compilation = self.partition_service.compile(
                    partition_command,
                    snapshot,
                    planning_token,
                )
            elif command.kind in BACKUP_COMMANDS:
                backup_command = command
                inventory_id = command.payload.get("backupId")
                inventory_backup_id: str | None = None
                if command.kind == "backups.restore" and inventory_id is not None:
                    if not isinstance(inventory_id, str):
                        raise BackupRepositoryError("backup_id_invalid", "backup ID must be a string")
                    record, artifact = self.backup_repository.resolve_verified(
                        inventory_id,
                        cancellation=planning_token,
                    )
                    inventory_backup_id = record.backup_id
                    backup_command = replace(
                        command,
                        payload={key: value for key, value in command.payload.items() if key != "backupId"}
                        | {"path": artifact.path},
                    )
                compilation = self.backup_service.compile(
                    backup_command,
                    snapshot,
                    planning_token,
                )
                if command.kind == "backups.restore" and inventory_id is not None:
                    compilation = replace(compilation, backup_id=inventory_backup_id)
            elif command.kind in DATA_ADB_COMMANDS:
                compilation = self.data_adb_service.compile(
                    command,
                    snapshot,
                    planning_token,
                )
            elif command.kind in ROOTING_COMMANDS:
                if command.kind == "root.modules.action" and command.payload.get("action") == "update":
                    artifact_id = command.payload.get("artifactId")
                    module_id = command.payload.get("moduleId")
                    resolved = self.root_module_update_service.resolve(
                        artifact_id,
                        module_id,
                        target_serial=command.target_serial,
                    )
                    entry = resolved.entry
                    command = replace(
                        command,
                        payload={
                            key: value
                            for key, value in command.payload.items()
                            if key != "artifactId"
                        }
                        | {
                            "preparedUpdate": PreparedRootModuleUpdate(
                                entry.artifact_id,
                                entry.module_id,
                                resolved.path,
                                entry.version,
                                entry.installed_version_code,
                                entry.version_code,
                                entry.sha256,
                                entry.size,
                            )
                        },
                    )
                compilation = self.rooting_service.compile(
                    command,
                    snapshot,
                    planning_token,
                )
            elif command.kind in OTA_DIAGNOSTIC_COMMANDS:
                compilation = self.ota_diagnostics_service.compile(command, snapshot)
            elif command.kind == "tools.pushFiles":
                compilation = self.device_tools_service.compile(
                    command,
                    snapshot,
                    cancellation=planning_token,
                    progress=(
                        lambda phase, message, percent, current, total, item: self._publish_progress(
                            command,
                            phase,
                            message,
                            percent,
                            current=current,
                            total=total,
                            item=item,
                        )
                    ),
                )
            else:
                compilation = self.device_tools_service.compile(
                    command,
                    snapshot,
                    cancellation=planning_token,
                )
        except BootPatchPlanningError as error:
            if planning_token is not None:
                self._unregister_cancellation(command.operation_id)
            if error.code == "boot_patch_cancelled":
                return self._stopped_result(
                    command,
                    planning_token,
                    cancelled_code=error.code,
                    cancelled_message=str(error),
                )
            return OperationResult.failed(
                command.operation_id,
                code=error.code,
                message=str(error),
            )
        except (
            PackagePlanningError,
            PartitionPlanningError,
            DeviceToolPlanningError,
            OtaDiagnosticPlanningError,
            BackupPlanningError,
            BackupRepositoryError,
            DataAdbError,
            RootingPlanningError,
        ) as error:
            if planning_token is not None:
                self._unregister_cancellation(command.operation_id)
            if error.code in {
                "backup_cancelled",
                "backup_import_cancelled",
                "device_tool_cancelled",
                "package_cancelled",
                "partition_cancelled",
                "push_cancelled",
                "rooting_cancelled",
            }:
                return self._stopped_result(
                    command,
                    planning_token,
                    cancelled_code=error.code,
                    cancelled_message=str(error),
                )
            if isinstance(error, DeviceToolPlanningError) and error.code == "push_timed_out":
                return OperationResult.failed(
                    command.operation_id,
                    code="timed_out",
                    message=str(error),
                )
            return OperationResult.failed(
                command.operation_id,
                code=error.code,
                message=str(error),
            )
        except Exception as error:
            if planning_token is not None:
                self._unregister_cancellation(command.operation_id)
            if planning_token is not None and planning_token.cancelled:
                return self._stopped_result(
                    command,
                    planning_token,
                    cancelled_code="service_planning_cancelled",
                    cancelled_message="service planning was cancelled",
                    timeout_message="service planning timed out",
                )
            return OperationResult.failed(
                command.operation_id,
                code="service_planning_error",
                message=str(error),
            )

        if compilation.plan is None:
            if command.kind != "root.apps.list" or not isinstance(
                compilation,
                RootingCompilation,
            ):
                self._unregister_cancellation(command.operation_id)
                return OperationResult.failed(
                    command.operation_id,
                    code="service_plan_missing",
                    message=f"{command.kind} did not produce an executable plan",
                )
            try:
                if planning_token.cancelled:
                    return self._stopped_result(
                        command,
                        planning_token,
                        cancelled_code="rooting_cancelled",
                        cancelled_message="root app inventory was cancelled",
                        timeout_message="root app inventory timed out",
                    )
                current = self.store.snapshot()
                if current.revision != snapshot.revision:
                    return self._denied(
                        command,
                        "stale_revision",
                        (f"state revision changed: expected {snapshot.revision}, current {current.revision}"),
                    )
                result = OperationResult.success(
                    command.operation_id,
                    code="root_apps_list_succeeded",
                    message=f"found {len(compilation.root_apps)} local root app(s)",
                    value={
                        "count": len(compilation.root_apps),
                        "apps": [app.to_dict() for app in compilation.root_apps],
                    },
                )
                if planning_token.cancelled:
                    return self._stopped_result(
                        command,
                        planning_token,
                        cancelled_code="rooting_cancelled",
                        cancelled_message="root app inventory was cancelled",
                        timeout_message="root app inventory timed out",
                    )
                self.store.complete_operation(result)
                return result
            finally:
                self._unregister_cancellation(command.operation_id)

        execution_plan = compilation.plan
        if isinstance(compilation, PartitionCompilation) and compilation.reinforced_confirmation:
            reinforced = self.operation_planner.bind_reinforced_confirmation(
                command,
                snapshot,
                execution_plan,
                destructive=compilation.destructive,
                requires_confirmation=compilation.requires_confirmation,
            )
            if not reinforced.ok or reinforced.plan is None:
                self._unregister_cancellation(command.operation_id)
                return replace(
                    OperationResult.failed(
                        command.operation_id,
                        code=reinforced.code,
                        message=reinforced.message,
                    ),
                    value=reinforced.to_dict(),
                )
            execution_plan = reinforced.plan

        if isinstance(compilation, OtaDiagnosticCompilation):
            destructive = False
            requires_confirmation = compilation.requires_confirmation
        else:
            destructive = compilation.destructive
            requires_confirmation = compilation.requires_confirmation
        planned = replace(
            command,
            target_serial=execution_plan.target_serial,
            operation_plan=execution_plan,
            destructive=destructive,
            requires_confirmation=requires_confirmation,
        )
        if command.kind == BOOT_PATCH_COMMAND:
            if not isinstance(compilation, BootPatchCompilation):
                self._unregister_cancellation(command.operation_id)
                return OperationResult.failed(
                    command.operation_id,
                    code="boot_patch_compilation_invalid",
                    message="boot patching returned an unexpected compilation type",
                )
            assert planning_token is not None
            return self._execute_process(
                planned,
                result_finalizer=(
                    lambda result, cancellation: self.boot_patch_service.finalize_result(
                        compilation, result, cancellation
                    )
                ),
                completion_boot=self._boot_info_from_patch_result,
                cancellation=planning_token,
            )
        if isinstance(compilation, RootingCompilation) and compilation.action == "modules.updates":
            return self._execute_process(
                planned,
                lambda result: self._prepare_root_module_updates(
                    command,
                    result,
                    planning_token,
                ),
                cancellation=planning_token,
            )
        if isinstance(compilation, PartitionCompilation) and compilation.action == "read":
            read_evidence: PartitionReadEvidence | None = None

            def partition_read_preflight(
                _command: AppCommand,
                boundary_plan: OperationPlan,
                _boundary_snapshot: AppSnapshot,
                boundary_token: CancellationToken,
            ) -> ExecutionBoundaryAck:
                nonlocal read_evidence
                self._publish_progress(
                    command,
                    ProgressPhase.STARTED,
                    "Fetching the selected partition into private staging.",
                    0,
                )
                try:
                    outcome = self.executor.transport.run(
                        boundary_plan.requests[0],
                        boundary_token,
                    )
                except Exception:
                    return ExecutionBoundaryAck.rejected(
                        "partition_read_preflight_cancelled"
                        if boundary_token.cancelled
                        else "partition_read_preflight_failed",
                        "partition read stopped before destination publication"
                        if boundary_token.cancelled
                        else "partition read staging could not be verified",
                    )
                decision = self.partition_service.validate_read_preflight(
                    compilation,
                    outcome,
                    boundary_token,
                )
                if not decision.allowed or decision.evidence is None:
                    return ExecutionBoundaryAck.rejected(
                        decision.code,
                        decision.message,
                    )
                read_evidence = decision.evidence
                self._publish_progress(
                    command,
                    ProgressPhase.RUNNING,
                    "Partition staging was hashed; publishing atomically.",
                    75,
                )
                return ExecutionBoundaryAck.accepted()

            def publish_partition_read(
                _command: AppCommand,
                _plan: OperationPlan,
                cancellation: CancellationToken,
            ) -> OperationResult:
                if read_evidence is None:
                    return OperationResult.failed(
                        command.operation_id,
                        code="partition_read_evidence_missing",
                        message="partition read publication lacks verified staging evidence",
                    )
                return self.partition_service.publish_read(
                    compilation,
                    read_evidence,
                    command.operation_id,
                    cancellation,
                )

            try:
                result = self._execute_process(
                    planned,
                    self._strip_closed_execution_metadata,
                    cancellation=planning_token,
                    execution_preflight=partition_read_preflight,
                    operation_executor=publish_partition_read,
                    request_start_index=1,
                )
            finally:
                self.partition_service.cleanup_read(compilation)
            if result.code == "partition_read_preflight_cancelled":
                result = OperationResult.cancelled(
                    command.operation_id,
                    code=result.code,
                    message=result.message,
                )
            self._publish_progress(
                command,
                ProgressPhase.COMPLETED
                if result.ok
                else ProgressPhase.CANCELLED
                if result.status is OperationStatus.CANCELLED
                else ProgressPhase.FAILED,
                result.message or "partition read finished",
                100 if result.ok else None,
            )
            return result
        if isinstance(compilation, OtaDiagnosticCompilation):
            if compilation.mutating:
                mutation_index = compilation.mutation_request_index
                assert mutation_index is not None

                def ota_reset_preflight(
                    _command: AppCommand,
                    boundary_plan: OperationPlan,
                    boundary_snapshot: AppSnapshot,
                    boundary_token: CancellationToken,
                ) -> ExecutionBoundaryAck:
                    current_device = next(
                        (
                            device
                            for device in boundary_snapshot.devices
                            if device.serial == boundary_plan.target_serial
                        ),
                        None,
                    )
                    if current_device is None or not current_device.root:
                        return ExecutionBoundaryAck.rejected(
                            "root_state_changed",
                            "OTA cancel/reset requires current root evidence at execution time",
                        )
                    try:
                        outcome = self.executor.transport.run(
                            boundary_plan.requests[0],
                            boundary_token,
                        )
                    except Exception:
                        return ExecutionBoundaryAck.rejected(
                            "ota_reset_preflight_failed",
                            "OTA reset status could not be verified before mutation",
                        )
                    decision = self.ota_diagnostics_service.validate_reset_preflight(
                        compilation,
                        outcome,
                    )
                    return (
                        ExecutionBoundaryAck.accepted()
                        if decision.allowed
                        else ExecutionBoundaryAck.rejected(
                            decision.code,
                            decision.message,
                        )
                    )

                result = self._execute_process(
                    planned,
                    result_finalizer=(
                        lambda process_result, _cancellation: self.ota_diagnostics_service.finalize(
                            compilation,
                            process_result,
                        )
                    ),
                    cancellation=planning_token,
                    execution_preflight=ota_reset_preflight,
                    request_start_index=mutation_index,
                )
                if result.code == "ota_reset_preflight_cancelled":
                    return OperationResult.cancelled(
                        command.operation_id,
                        code=result.code,
                        message=result.message,
                    )
                return result
            return self._execute_process(
                planned,
                result_finalizer=(
                    lambda result, _cancellation: self.ota_diagnostics_service.finalize(
                        compilation,
                        result,
                    )
                ),
                cancellation=planning_token,
            )
        if isinstance(compilation, DeviceToolCompilation) and compilation.execution != "process":
            return self._execute_process(
                planned,
                result_parser=(self._strip_logcat_execution_metadata if compilation.action == "logcat" else None),
                operation_executor=(
                    lambda _command, _plan, cancellation: (
                        self.device_tools_service.execute_special(
                            compilation,
                            command.operation_id,
                            cancellation,
                            progress=(
                                lambda phase, message, percent, current, total, item: self._publish_progress(
                                    command,
                                    phase,
                                    message,
                                    percent,
                                    current=current,
                                    total=total,
                                    item=item,
                                )
                            ),
                        )
                        if compilation.action == "logcat"
                        else self.device_tools_service.execute_special(
                            compilation,
                            command.operation_id,
                            cancellation,
                        )
                    )
                ),
                cancellation_cleanup=(
                    lambda result, cancellation: self.device_tools_service.cleanup_cancelled_special(
                        compilation,
                        result,
                        cancellation,
                    )
                ),
                cancellation=planning_token,
            )
        if isinstance(compilation, DeviceToolCompilation) and compilation.action.startswith("inspect."):
            return self._execute_process(
                planned,
                result_finalizer=(
                    lambda result, _cancellation: self.device_tools_service.finalize_inspection(
                        compilation,
                        result,
                    )
                ),
                cancellation=planning_token,
            )
        if isinstance(compilation, DeviceToolCompilation) and compilation.action == "openUrl":
            return self._execute_process(
                planned,
                self._strip_closed_execution_metadata,
                result_finalizer=(
                    lambda result, _cancellation: self.device_tools_service.finalize_open_url(
                        compilation,
                        result,
                    )
                ),
                cancellation=planning_token,
            )
        if isinstance(compilation, DeviceToolCompilation) and compilation.action.startswith("wifi."):
            return self._execute_process(
                planned,
                result_finalizer=(
                    lambda result, _cancellation: self.device_tools_service.finalize_result(compilation, result)
                ),
                cancellation=planning_token,
            )
        if isinstance(compilation, DeviceToolCompilation) and compilation.action == "logcat":
            return self._execute_process(
                planned,
                self._strip_logcat_execution_metadata,
                result_finalizer=(
                    lambda result, cancellation: self.device_tools_service.finalize_logcat(
                        compilation,
                        result,
                        cancellation,
                    )
                ),
                cancellation=planning_token,
            )
        if isinstance(compilation, PackageCompilation) and compilation.action == "export":
            return self._execute_process(
                planned,
                cancellation=planning_token,
                operation_executor=(
                    lambda command, _plan, cancellation: self.package_service.execute_export(
                        compilation,
                        command,
                        self.executor,
                        cancellation,
                    )
                ),
            )
        if isinstance(compilation, DataAdbCompilation):
            return self._execute_process(
                planned,
                cancellation=planning_token,
                operation_executor=(
                    lambda app_command, _plan, cancellation: self.data_adb_service.execute(
                        compilation,
                        app_command,
                        self.executor,
                        cancellation,
                    )
                ),
            )
        return self._execute_process(
            planned,
            lambda result: self._parse_service_result(
                command.kind,
                compilation,
                result,
            ),
            cancellation=planning_token,
        )

    @staticmethod
    def _strip_logcat_execution_metadata(result: OperationResult) -> OperationResult:
        """Keep runner-only plan evidence out of the closed Logcat DTO."""

        raw_value = cast(object, result.value)
        if not result.ok or not isinstance(raw_value, dict):
            return result
        source = cast(dict[str, object], raw_value)
        value = source.copy()
        value.pop("planId", None)
        value.pop("postconditions", None)
        return replace(result, value=value)

    @staticmethod
    def _strip_closed_execution_metadata(result: OperationResult) -> OperationResult:
        """Remove runner-only proof fields from a domain-owned closed DTO."""

        raw_value = cast(object, result.value)
        if not result.ok or not isinstance(raw_value, dict):
            return result
        source = cast(dict[str, object], raw_value)
        value = {key: item for key, item in source.items() if key not in {"planId", "postconditions"}}
        return replace(result, value=value)

    def _parse_service_result(
        self,
        kind: str,
        compilation: _ServiceCompilation,
        result: OperationResult,
    ) -> OperationResult:
        """Convert successful process output into bridge-safe domain values."""

        plan = compilation.plan
        if not result.ok:
            return result
        if plan is None:
            return OperationResult.failed(
                result.operation_id,
                code="service_plan_missing",
                message=f"{kind} has no executable plan",
            )

        if kind == "apps.list":
            packages = parse_package_list(result.stdout)
            return replace(
                result,
                code="apps_list_succeeded",
                message=f"found {len(packages)} package(s)",
                value={
                    "count": len(packages),
                    "packages": [package.to_dict() for package in packages],
                },
            )
        if kind == "apps.action" and isinstance(compilation, PackageCompilation):
            if compilation.action == "permissions":
                if len(compilation.packages) != 1:
                    return OperationResult.failed(
                        result.operation_id,
                        code="package_permissions_target_invalid",
                        message="permission inspection has no exact package target",
                    )
                try:
                    report = parse_package_permissions(
                        result.stdout,
                        compilation.packages[0],
                    )
                except PackageResultError as error:
                    return OperationResult.failed(
                        result.operation_id,
                        code=error.code,
                        message=str(error),
                    )
                return replace(
                    result,
                    code="package_permissions_returned",
                    message="bounded package permission report returned",
                    value={"action": "permissions", "report": report},
                    stdout="",
                    stderr="",
                )
            value: dict[str, object] = {"action": compilation.action}
            if compilation.apk_identity is not None:
                identity = compilation.apk_identity
                value["apkIdentity"] = {
                    "packageName": identity.package_name,
                    "sha256": identity.sha256,
                    "signerSha256": list(identity.signer_sha256),
                    "schemes": list(identity.schemes),
                    "verified": identity.verified,
                }
            return replace(
                result,
                code="apps_action_succeeded",
                message=f"package action {compilation.action} succeeded",
                value=value,
            )
        if kind == "partitions.list":
            partitions = parse_fastboot_partition_list(result.stdout, result.stderr)
            return replace(
                result,
                code="partitions_list_succeeded",
                message=f"found {len(partitions)} allow-listed partition(s)",
                value={
                    "count": len(partitions),
                    "partitions": [partition.to_dict() for partition in partitions],
                },
            )
        if kind == "partitions.write" and isinstance(
            compilation,
            PartitionCompilation,
        ):
            if (
                compilation.action != "write"
                or len(plan.artifacts) != 1
                or len(plan.postconditions) != 1
                or plan.postconditions[0].kind != "partition_written"
            ):
                return OperationResult.failed(
                    result.operation_id,
                    code="partition_write_receipt_unverified",
                    message="partition write lacks its immutable hash proof",
                )
            return replace(
                result,
                code="partition_write_verified",
                message="partition write and device-side hash were verified",
                value={
                    "action": "write",
                    "targetSerial": plan.target_serial,
                    "partition": compilation.partition,
                    "sha256": plan.artifacts[0].sha256,
                    "verified": True,
                },
                stdout="",
                stderr="",
            )
        if kind == "partitions.erase" and isinstance(
            compilation,
            PartitionCompilation,
        ):
            if (
                compilation.action != "erase"
                or len(plan.postconditions) != 1
                or plan.postconditions[0].kind != "partition_erased"
            ):
                return OperationResult.failed(
                    result.operation_id,
                    code="partition_erase_receipt_unverified",
                    message="partition erase lacks its device-side proof",
                )
            return replace(
                result,
                code="partition_erase_verified",
                message="partition erase was verified by bounded readback",
                value={
                    "action": "erase",
                    "targetSerial": plan.target_serial,
                    "partition": compilation.partition,
                    "erased": True,
                    "verified": True,
                },
                stdout="",
                stderr="",
            )
        if kind == "tools.pushFiles":
            if not isinstance(compilation, DeviceToolCompilation):
                return OperationResult.failed(
                    result.operation_id,
                    code="device_tool_compilation_invalid",
                    message="push files returned an unexpected compilation type",
                )
            files = [receipt.to_dict() for receipt in compilation.push_files]
            return replace(
                result,
                code="files_pushed",
                message=f"pushed {len(files)} file(s)",
                value={
                    "targetSerial": plan.target_serial,
                    "count": len(files),
                    "files": files,
                },
                stdout="",
                stderr="",
            )
        if kind == "tools.logcat.clear":
            if (
                not isinstance(compilation, DeviceToolCompilation)
                or compilation.action != "logcat.clear"
                or tuple(item.kind for item in plan.postconditions) != ("logcat_buffers_cleared",)
            ):
                return OperationResult.failed(
                    result.operation_id,
                    code="logcat_clear_compilation_invalid",
                    message="Logcat clear returned an invalid verified plan",
                )
            return replace(
                result,
                code="logcat_buffers_cleared",
                message=("the all-buffer clear control completed and main-buffer sentinel removal was verified"),
                value={
                    "targetSerial": plan.target_serial,
                    "buffers": ["all"],
                    "clearCommandCompleted": True,
                    "controlCommandVerified": True,
                    "mainBufferSentinelVerified": True,
                    "verificationEntryRetained": True,
                },
                stdout="",
                stderr="",
            )
        if kind == "tools.wifi":
            if not isinstance(compilation, DeviceToolCompilation):
                return OperationResult.failed(
                    result.operation_id,
                    code="device_tool_compilation_invalid",
                    message="Wi-Fi returned an unexpected compilation type",
                    exit_code=result.exit_code,
                    stdout=result.stdout,
                    stderr=result.stderr,
                )
            return self.device_tools_service.finalize_result(compilation, result)
        if kind == "backups.magisk.list":
            if not isinstance(compilation, BackupCompilation):
                return OperationResult.failed(
                    result.operation_id,
                    code="magisk_backup_compilation_invalid",
                    message="Magisk backup listing returned an invalid compilation",
                )
            try:
                backups = parse_magisk_backup_list(result.stdout)
            except BackupPlanningError as error:
                return OperationResult.failed(
                    result.operation_id,
                    code=error.code,
                    message=str(error),
                )
            return replace(
                result,
                code="magisk_backups_listed",
                message=f"found {len(backups)} Magisk backup(s)",
                value={
                    "action": "list",
                    "targetSerial": plan.target_serial,
                    "count": len(backups),
                    "backups": [backup.to_dict() for backup in backups],
                    "bounded": True,
                },
                stdout="",
                stderr="",
            )
        if kind in {"backups.magisk.import", "backups.magisk.delete"}:
            if not isinstance(compilation, BackupCompilation) or compilation.magisk_sha1 is None:
                return OperationResult.failed(
                    result.operation_id,
                    code="magisk_backup_compilation_invalid",
                    message="Magisk backup mutation has no validated SHA-1",
                )
            action = "import" if kind.endswith(".import") else "delete"
            return replace(
                result,
                code=f"magisk_backup_{'imported' if action == 'import' else 'deleted'}",
                message=f"Magisk backup {compilation.magisk_sha1[:12]} {action} completed",
                value={
                    "action": action,
                    "targetSerial": plan.target_serial,
                    "sha1": compilation.magisk_sha1,
                    "verified": True,
                },
                stdout="",
                stderr="",
            )
        if kind == "backups.create":
            if not isinstance(compilation, BackupCompilation):
                return OperationResult.failed(
                    result.operation_id,
                    code="backup_compilation_invalid",
                    message="backup create returned an unexpected compilation type",
                    exit_code=result.exit_code,
                    stdout=result.stdout,
                    stderr=result.stderr,
                )
            try:
                artifact = self.backup_service.finalize_created_backup(compilation)
            except BackupPlanningError as error:
                return OperationResult.failed(
                    result.operation_id,
                    code=error.code,
                    message=str(error),
                    exit_code=result.exit_code,
                    stdout=result.stdout,
                    stderr=result.stderr,
                )
            try:
                backup = self.backup_repository.import_file(
                    artifact.path,
                    expected_sha256=artifact.sha256,
                    target_serial=plan.target_serial or "",
                    device_codename=plan.expected_codename or "unknown",
                    partition=compilation.partition,
                    slot=plan.slots[0],
                    provenance=BackupProvenance.CREATED,
                )
            except BackupRepositoryError as error:
                return OperationResult.failed(
                    result.operation_id,
                    code="backup_created_inventory_failed",
                    message=(
                        f"the raw backup was created, but its managed inventory registration failed: {error.code}"
                    ),
                )
            return replace(
                result,
                code="backup_created",
                message=f"created and verified backup of {plan.partitions[0]}",
                value={
                    "action": "create",
                    "targetSerial": plan.target_serial,
                    "partition": plan.partitions[0],
                    "slot": plan.slots[0],
                    "backup": backup.to_public_dict(available=True),
                    "inventoryRegistered": True,
                },
                stdout="",
                stderr="",
            )
        if kind == "backups.restore":
            if not isinstance(compilation, BackupCompilation) or not plan.artifacts:
                return OperationResult.failed(
                    result.operation_id,
                    code="backup_compilation_invalid",
                    message="backup restore has no verified source artifact",
                    exit_code=result.exit_code,
                    stdout=result.stdout,
                    stderr=result.stderr,
                )
            artifact = plan.artifacts[0]
            inventory_registered = True
            inventory_issue: str | None = None
            if compilation.backup_id is not None:
                backup = self.backup_repository.get(compilation.backup_id)
                if backup is None:
                    return OperationResult.failed(
                        result.operation_id,
                        code="backup_inventory_changed",
                        message="managed backup disappeared during restore",
                    )
            else:
                try:
                    backup = self.backup_repository.import_file(
                        artifact.path,
                        expected_sha256=artifact.sha256,
                        target_serial=plan.target_serial or "",
                        device_codename=plan.expected_codename or "unknown",
                        partition=compilation.partition,
                        slot=plan.slots[0],
                        provenance=BackupProvenance.USER_SUPPLIED,
                    )
                except BackupRepositoryError as error:
                    backup = None
                    inventory_registered = False
                    inventory_issue = error.code
            return replace(
                result,
                code="backup_restored",
                message=f"restored {plan.partitions[0]}",
                value={
                    "action": "restore",
                    "targetSerial": plan.target_serial,
                    "partition": plan.partitions[0],
                    "slot": plan.slots[0],
                    "backup": (
                        backup.to_public_dict(available=self.backup_repository.is_available(backup))
                        if backup is not None
                        else None
                    ),
                    "inventoryRegistered": inventory_registered,
                    "inventoryIssue": inventory_issue,
                },
                stdout="",
                stderr="",
            )
        if kind == "root.apps.install":
            if not isinstance(compilation, RootingCompilation) or not compilation.root_apps:
                return OperationResult.failed(
                    result.operation_id,
                    code="root_app_compilation_invalid",
                    message="root-app install has no verified inventory entry",
                    exit_code=result.exit_code,
                    stdout=result.stdout,
                    stderr=result.stderr,
                )
            app = compilation.root_apps[0]
            return replace(
                result,
                code="root_app_installed",
                message=f"installed {app.provider} {app.flavor}",
                value={
                    "action": "install",
                    "targetSerial": plan.target_serial,
                    "app": app.to_dict(),
                },
            )
        if kind == "root.modules.list":
            modules = parse_root_module_list(result.stdout)
            return replace(
                result,
                code="root_modules_list_succeeded",
                message=f"found {len(modules)} Magisk module(s)",
                value={
                    "count": len(modules),
                    "modules": [module.to_dict() for module in modules],
                },
            )
        if kind == "root.pif.inventory":
            if not isinstance(compilation, RootingCompilation) or compilation.action != "pif.inventory":
                return OperationResult.failed(
                    result.operation_id,
                    code="pif_inventory_compilation_invalid",
                    message="PIF inventory returned an invalid compilation",
                )
            try:
                inventory = parse_pif_inventory(result.stdout)
            except RootingPlanningError as error:
                return OperationResult.failed(
                    result.operation_id,
                    code=error.code,
                    message=str(error),
                )
            return replace(
                result,
                code="pif_inventory_listed",
                message="verified PIF and TargetedFix inventory completed",
                value=inventory,
                stdout="",
                stderr="",
            )
        if kind == "root.pif.document":
            if (
                not isinstance(compilation, RootingCompilation)
                or compilation.action != "pif.document"
                or compilation.pif_profile_id is None
            ):
                return OperationResult.failed(
                    result.operation_id,
                    code="pif_document_compilation_invalid",
                    message="PIF document returned an invalid compilation",
                )
            try:
                document = parse_pif_document(
                    result.stdout,
                    expected_profile_id=compilation.pif_profile_id,
                )
            except RootingPlanningError as error:
                return OperationResult.failed(
                    result.operation_id,
                    code=error.code,
                    message=str(error),
                )
            return replace(
                result,
                code="pif_document_loaded",
                message="verified bounded PIF document loaded",
                value=document.to_dict(),
                stdout="",
                stderr="",
            )
        if kind == "tools.pif":
            if not isinstance(compilation, RootingCompilation) or compilation.action not in {
                "pif.delete_profile",
                "pif.import_profile",
                "pif.update_profile",
                "pif.add_target",
                "pif.delete_target",
                "pif.import_target_profile",
                "pif.cleanup_droidguard",
                "pif.launch_integrity_check",
            }:
                return OperationResult.failed(
                    result.operation_id,
                    code="pif_action_compilation_invalid",
                    message="PIF action returned an invalid compilation",
                )
            if compilation.action == "pif.cleanup_droidguard":
                return replace(
                    result,
                    code="droidguard_cache_cleaned",
                    message="DroidGuard cache absence was independently verified",
                    value={"action": "cleanupDroidGuard", "verified": True},
                    stdout="",
                    stderr="",
                )
            if compilation.action == "pif.launch_integrity_check":
                if compilation.pi_checker_id is None:
                    return OperationResult.failed(
                        result.operation_id,
                        code="pif_action_compilation_invalid",
                        message="integrity checker launch is missing its identity",
                    )
                return replace(
                    result,
                    code="integrity_checker_opened",
                    message="integrity checker process launch was verified",
                    value={
                        "action": "launchIntegrityCheck",
                        "checker": compilation.pi_checker_id,
                        "verified": True,
                    },
                    stdout="",
                    stderr="",
                )
            action_names = {
                "pif.delete_profile": "deleteProfile",
                "pif.import_profile": "importProfile",
                "pif.update_profile": "updateProfile",
                "pif.add_target": "addTarget",
                "pif.delete_target": "deleteTarget",
                "pif.import_target_profile": "importTargetProfile",
            }
            public_action = action_names[compilation.action]
            imported = compilation.action in {"pif.import_profile", "pif.update_profile"}
            target_action = compilation.action in {
                "pif.add_target",
                "pif.delete_target",
                "pif.import_target_profile",
            }
            if target_action:
                if compilation.pif_target_package is None:
                    return OperationResult.failed(
                        result.operation_id,
                        code="pif_action_compilation_invalid",
                        message="TargetedFix action is missing its package identity",
                    )
                value: dict[str, object] = {
                    "action": public_action,
                    "targetPackage": compilation.pif_target_package,
                }
                if compilation.action == "pif.import_target_profile":
                    if (
                        compilation.pif_target_format not in {"json", "prop"}
                        or compilation.pif_sha256 is None
                        or compilation.pif_size is None
                    ):
                        return OperationResult.failed(
                            result.operation_id,
                            code="pif_action_compilation_invalid",
                            message="TargetedFix profile import is missing verified metadata",
                        )
                    value["targetFormat"] = compilation.pif_target_format
                    value["sha256"] = compilation.pif_sha256
                    value["size"] = compilation.pif_size
            else:
                if compilation.pif_profile_id is None:
                    return OperationResult.failed(
                        result.operation_id,
                        code="pif_action_compilation_invalid",
                        message="PIF action is missing its profile identity",
                    )
                value = {
                    "action": public_action,
                    "profileId": compilation.pif_profile_id,
                }
            if imported:
                if compilation.pif_sha256 is None or compilation.pif_size is None:
                    return OperationResult.failed(
                        result.operation_id,
                        code="pif_action_compilation_invalid",
                        message="PIF import is missing its verified hash",
                    )
                value["sha256"] = compilation.pif_sha256
                value["size"] = compilation.pif_size
            return replace(
                result,
                code={
                    "importProfile": "pif_profile_imported",
                    "updateProfile": "pif_profile_updated",
                    "deleteProfile": "pif_profile_deleted",
                    "addTarget": "targeted_fix_target_added",
                    "deleteTarget": "targeted_fix_target_deleted",
                    "importTargetProfile": "targeted_fix_profile_imported",
                }[public_action],
                message={
                    "importProfile": "PIF profile import hash was independently verified",
                    "updateProfile": "PIF profile update hash was independently verified",
                    "deleteProfile": "PIF profile deletion was independently verified",
                    "addTarget": "TargetedFix target addition was independently verified",
                    "deleteTarget": "TargetedFix target deletion was independently verified",
                    "importTargetProfile": "TargetedFix profile hash was independently verified",
                }[public_action],
                value=value,
                stdout="",
                stderr="",
            )
        if kind == "tools.piAnalysis":
            if (
                not isinstance(compilation, RootingCompilation)
                or compilation.action != "pi_analysis"
                or compilation.device_build is None
                or plan.expected_codename is None
            ):
                return OperationResult.failed(
                    result.operation_id,
                    code="pi_analysis_compilation_invalid",
                    message="Play Integrity analysis returned an invalid compilation",
                )
            try:
                report = parse_pi_analysis(
                    result.stdout,
                    device_codename=plan.expected_codename,
                    build=compilation.device_build,
                )
            except RootingPlanningError as error:
                return OperationResult.failed(
                    result.operation_id,
                    code=error.code,
                    message=str(error),
                )
            return replace(
                result,
                code="pi_analysis_completed",
                message="redacted Play Integrity analysis completed",
                value=report,
                stdout="",
                stderr="",
            )
        if kind == "root.modules.action":
            if not isinstance(compilation, RootingCompilation) or not compilation.module_id:
                return OperationResult.failed(
                    result.operation_id,
                    code="root_module_compilation_invalid",
                    message="root module action has no validated module ID",
                    exit_code=result.exit_code,
                    stdout=result.stdout,
                    stderr=result.stderr,
                )
            action = compilation.action.removeprefix("modules.")
            result_codes = {
                "install": "root_module_installed",
                "update": "root_module_updated",
                "enable": "root_module_enabled",
                "disable": "root_module_disabled",
                "remove": "root_module_removed",
            }
            result_code = result_codes.get(action)
            if result_code is None:
                return OperationResult.failed(
                    result.operation_id,
                    code="root_module_compilation_invalid",
                    message=f"unsupported compiled module action: {action}",
                    exit_code=result.exit_code,
                    stdout=result.stdout,
                    stderr=result.stderr,
                )
            artifact = plan.artifacts[0].to_dict() if plan.artifacts else None
            return replace(
                result,
                code=result_code,
                message=f"{action} Magisk module {compilation.module_id}",
                value={
                    "action": action,
                    "targetSerial": plan.target_serial,
                    "moduleId": compilation.module_id,
                    "artifact": artifact,
                    "verified": True,
                },
            )
        if kind in {"tools.shizuku", "tools.sos"}:
            if not isinstance(compilation, RootingCompilation):
                return OperationResult.failed(
                    result.operation_id,
                    code="root_recovery_compilation_invalid",
                    message="root recovery returned an invalid compilation",
                    exit_code=result.exit_code,
                    stdout=result.stdout,
                    stderr=result.stderr,
                )
            action = "startShizuku" if kind == "tools.shizuku" else "disableModules"
            return replace(
                result,
                code=("shizuku_started" if kind == "tools.shizuku" else "sos_modules_disabled"),
                message=("Shizuku is running" if kind == "tools.shizuku" else "every Magisk module is disabled"),
                value={
                    "action": action,
                    "targetSerial": plan.target_serial,
                    "verified": True,
                },
                stdout="",
                stderr="",
            )
        if isinstance(compilation, BootPatchCompilation):
            return OperationResult.failed(
                result.operation_id,
                code="boot_patch_result_unexpected",
                message="boot patch results require their dedicated finalizer",
            )
        return replace(
            result,
            code=f"{kind.replace('.', '_')}_succeeded",
            value={
                "action": compilation.action,
                "targetSerial": plan.target_serial,
            },
        )

    def cancel(self, operation_id: str) -> bool:
        """Request cooperative cancellation of a currently running operation."""

        with self._cancellation_lock:
            token = self._cancellations.get(operation_id)
        if token is None:
            return False
        token.cancel()
        return True

    def shutdown(self) -> None:
        with self._lifecycle_lock:
            self._shutdown = True
        with self._cancellation_lock:
            tokens = tuple(self._cancellations.values())
        for token in tokens:
            token.cancel()
        self.package_service.shutdown()
        self.partition_service.shutdown()
        self.data_adb_service.shutdown()
        self.device_tools_service.shutdown()
        self.support_package_service.shutdown()

    def register_support_destination(
        self,
        destination: str | Path,
        *,
        allow_overwrite: bool = False,
    ) -> str:
        """Register a destination chosen by trusted native UI, never WebView JSON."""

        with self._lifecycle_lock:
            if self._shutdown:
                raise RuntimeError("the application engine has shut down")
        return self.support_package_service.register_destination(
            destination,
            allow_overwrite=allow_overwrite,
        )

    def register_processed_artifacts(
        self,
        artifacts: Sequence[FileArtifact],
        *,
        firmware_hash: str = "",
        plan_fingerprint: str = "",
    ) -> None:
        """Register backend-produced artifacts; this is not a bridge command."""

        self.operation_planner.artifact_repository.register(
            artifacts,
            firmware_hash=firmware_hash,
            plan_fingerprint=plan_fingerprint,
        )

    def _select_device(self, command: AppCommand) -> OperationResult:
        serial: object = command.payload.get("serial")
        if serial is not None and not isinstance(serial, str):
            return self._invalid(command, "payload.serial must be a string or null")
        if isinstance(serial, str) and not serial.strip():
            return self._invalid(command, "payload.serial must not be blank")
        raw_serials: object = command.payload.get("serials")
        if raw_serials is None:
            serials = (serial,) if serial else ()
        elif isinstance(raw_serials, (list, tuple)):
            serial_items = cast(list[object] | tuple[object, ...], raw_serials)
            if not all(isinstance(item, str) and item.strip() for item in serial_items):
                return self._invalid(
                    command,
                    "payload.serials must be an array of strings",
                )
            serials = tuple(dict.fromkeys(item.strip() for item in serial_items if isinstance(item, str)))
        else:
            return self._invalid(command, "payload.serials must be an array of strings")
        serials = tuple(dict.fromkeys(item.strip() for item in serials if isinstance(item, str) and item.strip()))
        primary = serial.strip() if isinstance(serial, str) and serial.strip() else (serials[0] if serials else None)
        inventory = {device.serial for device in self.store.snapshot().devices}
        desired = tuple(dict.fromkeys(((primary,) if primary else ()) + serials))
        missing = tuple(item for item in desired if item not in inventory)
        if missing:
            return OperationResult.failed(
                command.operation_id,
                code="device_not_found",
                message=f"device serial is not in the current scan: {missing[0]}",
            )
        return self._update_state(
            command,
            selected_serials=serials,
            selected_serial=primary,
        )

    def _firmware_catalog_command(self, command: AppCommand) -> OperationResult:
        service = self.firmware_catalog_service
        snapshot = self.store.snapshot()
        decision = self.safety_policy.evaluate(command, snapshot)
        if not decision.allowed:
            return self._denied(command, decision.code, decision.message)
        token = self._register_cancellation(command)
        if token is None:
            return self._denied(command, "operation_busy", "operation id is already active")
        try:
            with self._operation_guard(token) as acquired:
                if not acquired or token.cancelled:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="firmware_catalog_cancelled",
                        cancelled_message="Firmware catalog operation was cancelled.",
                        timeout_message="Firmware catalog operation timed out.",
                    )
                current = self.store.snapshot()
                decision = self.safety_policy.evaluate(command, current)
                if not decision.allowed:
                    return self._denied(command, decision.code, decision.message)
                if current.revision != snapshot.revision:
                    return self._denied(
                        command,
                        "stale_revision",
                        "Canonical state changed before the firmware catalog operation.",
                    )
                if command.kind == "firmware.catalog.refresh":
                    unknown = set(command.payload) - {"device", "channel"}
                    device = command.payload.get("device")
                    channel = command.payload.get("channel", "stable")
                    if unknown or not isinstance(device, str) or not isinstance(channel, str):
                        return self._invalid(command, "Firmware catalog payload is invalid.")
                    refreshed = service.refresh(
                        device=device,
                        channel=channel,
                        cancellation=token,
                    )
                    if refreshed.status is FirmwareCatalogStatus.CANCELLED:
                        return self._stopped_result(
                            command,
                            token,
                            cancelled_code=refreshed.code,
                            cancelled_message=refreshed.message,
                            timeout_message="Firmware catalog refresh timed out.",
                        )
                    if not refreshed.ok:
                        return OperationResult.failed(
                            command.operation_id,
                            code=refreshed.code,
                            message=refreshed.message,
                        )
                    return OperationResult.success(
                        command.operation_id,
                        code=refreshed.code,
                        message=refreshed.message,
                        value={
                            **refreshed.to_public_dict(),
                            "device": device.strip().casefold(),
                            "channel": channel.strip().casefold(),
                            "revision": current.revision,
                        },
                    )

                unknown = set(command.payload) - {"artifactId"}
                artifact_id = command.payload.get("artifactId")
                if unknown or not isinstance(artifact_id, str):
                    return self._invalid(command, "Firmware download payload is invalid.")
                downloaded = service.download(
                    artifact_id,
                    cancellation=token,
                    progress=lambda phase, message, percent: self._publish_progress(
                        command,
                        phase,
                        message,
                        percent,
                    ),
                )
                if downloaded.status is FirmwareCatalogStatus.CANCELLED:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code=downloaded.code,
                        cancelled_message=downloaded.message,
                        timeout_message="Firmware download timed out.",
                    )
                if not downloaded.ok or downloaded.path is None or downloaded.entry is None:
                    return OperationResult.failed(
                        command.operation_id,
                        code=downloaded.code,
                        message=downloaded.message,
                    )
                inspected = self._inspect_and_promote_firmware(
                    command,
                    current,
                    str(downloaded.path),
                    (downloaded.entry.device,),
                    token,
                    provenance=ArtifactProvenance.OFFICIAL,
                    expected_kind="stock",
                )
                if not inspected.ok:
                    return inspected
                inspected_value = cast(Mapping[str, object], inspected.value)
                return replace(
                    inspected,
                    code="firmware_download_selected",
                    message="Official firmware was downloaded, verified, and selected.",
                    value={
                        "artifact": downloaded.entry.to_public_dict(),
                        "cacheHit": downloaded.cache_hit,
                        "resumed": downloaded.resumed,
                        "revision": self.store.snapshot().revision,
                        "inspection": inspected_value["inspection"],
                    },
                )
        finally:
            self._unregister_cancellation(command.operation_id)

    def _root_app_catalog_command(self, command: AppCommand) -> OperationResult:
        service = self.root_app_catalog_service
        snapshot = self.store.snapshot()
        decision = self.safety_policy.evaluate(command, snapshot)
        if not decision.allowed:
            return self._denied(command, decision.code, decision.message)
        token = self._register_cancellation(command)
        if token is None:
            return self._denied(command, "operation_busy", "operation id is already active")
        try:
            with self._operation_guard(token) as acquired:
                if not acquired or token.cancelled:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="root_app_catalog_cancelled",
                        cancelled_message="Root-app catalog operation was cancelled.",
                        timeout_message="Root-app catalog operation timed out.",
                    )
                current = self.store.snapshot()
                decision = self.safety_policy.evaluate(command, current)
                if not decision.allowed:
                    return self._denied(command, decision.code, decision.message)
                if current.revision != snapshot.revision:
                    return self._denied(
                        command,
                        "stale_revision",
                        "Canonical state changed before the root-app catalog operation.",
                    )
                if command.kind == "root.apps.catalog.refresh":
                    unknown = set(command.payload) - {"channel"}
                    channel = command.payload.get("channel", "stable")
                    if unknown or not isinstance(channel, str):
                        return self._invalid(command, "Root-app catalog payload is invalid.")
                    refreshed = service.refresh(
                        channel=channel,
                        cancellation=token,
                    )
                    if refreshed.status is RootAppCatalogStatus.CANCELLED:
                        return self._stopped_result(
                            command,
                            token,
                            cancelled_code=refreshed.code,
                            cancelled_message=refreshed.message,
                            timeout_message="Root-app catalog refresh timed out.",
                        )
                    if not refreshed.ok:
                        return OperationResult.failed(
                            command.operation_id,
                            code=refreshed.code,
                            message=refreshed.message,
                        )
                    return OperationResult.success(
                        command.operation_id,
                        code=refreshed.code,
                        message=refreshed.message,
                        value={
                            **refreshed.to_public_dict(),
                            "channel": channel.strip().casefold(),
                            "revision": current.revision,
                        },
                    )

                unknown = set(command.payload) - {"artifactId"}
                artifact_id = command.payload.get("artifactId")
                if unknown or not isinstance(artifact_id, str):
                    return self._invalid(command, "Root-app download payload is invalid.")
                downloaded = service.download(
                    artifact_id,
                    cancellation=token,
                    progress=lambda phase, message, percent: self._publish_progress(
                        command,
                        phase,
                        message,
                        percent,
                    ),
                )
                if downloaded.status is RootAppCatalogStatus.CANCELLED:
                    return self._rollback_root_app_download(
                        service,
                        downloaded,
                        command,
                        self._stopped_result(
                            command,
                            token,
                            cancelled_code=downloaded.code,
                            cancelled_message=downloaded.message,
                            timeout_message="Root-app download timed out.",
                        ),
                    )
                if not downloaded.ok or downloaded.entry is None or downloaded.app is None:
                    return OperationResult.failed(
                        command.operation_id,
                        code=downloaded.code,
                        message=downloaded.message,
                    )
                if token.cancelled:
                    return self._rollback_root_app_download(
                        service,
                        downloaded,
                        command,
                        self._stopped_result(
                            command,
                            token,
                            cancelled_code="root_app_download_cancelled",
                            cancelled_message="Root-app download was cancelled before promotion.",
                            timeout_message="Root-app download timed out before promotion.",
                        ),
                    )
                try:
                    updated = self.store.update(
                        expected_revision=current.revision,
                        preferences=current.preferences,
                    )
                except StaleRevisionError as error:
                    return self._rollback_root_app_download(
                        service,
                        downloaded,
                        command,
                        self._denied(command, "stale_revision", str(error)),
                    )
                return OperationResult.success(
                    command.operation_id,
                    code="root_app_download_registered",
                    message="Root application was downloaded, verified, and registered.",
                    value={
                        "artifact": downloaded.entry.to_public_dict(),
                        "app": downloaded.app.to_dict(),
                        "cacheHit": downloaded.cache_hit,
                        "resumed": downloaded.resumed,
                        "revision": updated.revision,
                    },
                )
        finally:
            self._unregister_cancellation(command.operation_id)

    @staticmethod
    def _rollback_root_app_download(
        service: RootAppCatalogService,
        downloaded: RootAppDownloadResult,
        command: AppCommand,
        intended: OperationResult,
    ) -> OperationResult:
        if not downloaded.previous_sources and downloaded.app is None:
            return intended
        try:
            service.rooting_service.restore_root_app_sources(downloaded.previous_sources)
        except (TypeError, ValueError, RootingPlanningError) as error:
            return OperationResult.failed(
                command.operation_id,
                code="root_app_download_rollback_failed",
                message=str(error),
            )
        return intended

    def _inspect_firmware(
        self,
        command: AppCommand,
    ) -> OperationResult:
        unknown = set(command.payload) - {"path", "expectedKind"}
        if unknown:
            return self._invalid(
                command,
                f"unsupported firmware.select field: {sorted(unknown)[0]}",
            )
        snapshot = self.store.snapshot()
        path = command.payload.get("path")
        if not isinstance(path, str) or not path.strip():
            return self._invalid(command, "payload.path must be a non-empty string")
        path = path.strip()
        expected_kind = command.payload.get("expectedKind")
        if expected_kind not in {None, "stock", "custom"}:
            return self._invalid(
                command,
                "payload.expectedKind must be exactly stock or custom",
            )
        decision = self.safety_policy.evaluate(command, snapshot)
        if not decision.allowed:
            return self._denied(command, decision.code, decision.message)
        expected_devices = tuple(
            device.codename
            for device in snapshot.devices
            if device.serial in snapshot.selected_serials and device.codename
        )
        token = self._register_cancellation(command)
        if token is None:
            return self._denied(command, "operation_busy", "operation id is already active")
        try:
            with self._operation_guard(token) as acquired:
                if not acquired:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="firmware_cancelled",
                        cancelled_message="firmware inspection was cancelled while queued",
                        timeout_message="firmware inspection timed out while queued",
                    )
                return self._inspect_and_promote_firmware(
                    command,
                    snapshot,
                    path,
                    expected_devices,
                    token,
                    expected_kind=cast(str | None, expected_kind),
                )
        finally:
            self._unregister_cancellation(command.operation_id)

    def _inspect_and_promote_firmware(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        path: str,
        expected_devices: tuple[str, ...],
        token: CancellationToken,
        *,
        provenance: ArtifactProvenance = ArtifactProvenance.USER_SUPPLIED,
        expected_kind: str | None = None,
    ) -> OperationResult:
        imported_artifact_id = ""
        imported_artifact_created = False
        try:
            inspection = self.firmware_inspector.inspect(
                path,
                expected_devices=expected_devices,
                cancellation=token,
            )
        except Exception as error:
            if token.cancelled:
                return self._stopped_result(
                    command,
                    token,
                    cancelled_code="firmware_cancelled",
                    cancelled_message="firmware inspection was cancelled",
                    timeout_message="firmware inspection timed out",
                )
            return OperationResult.failed(
                command.operation_id,
                code="firmware_inspection_failed",
                message=str(error),
            )
        if inspection.code == "firmware_cancelled":
            return self._stopped_result(
                command,
                token,
                cancelled_code="firmware_cancelled",
                cancelled_message=inspection.message,
                timeout_message="firmware inspection timed out",
            )
        if not inspection.ok:
            return OperationResult.failed(
                command.operation_id,
                code=inspection.code,
                message=inspection.message,
            )
        if (expected_kind == "stock" and inspection.kind.value not in {"factory", "ota"}) or (
            expected_kind == "custom" and inspection.kind.value != "custom"
        ):
            return OperationResult.failed(
                command.operation_id,
                code="firmware_kind_mismatch",
                message=f"selected package is {inspection.kind.value}, expected {expected_kind}",
            )
        if self.firmware_repository is not None:
            try:
                existing_artifact_ids = {item.artifact_id for item in self.firmware_repository.list()}
                record = self.firmware_repository.import_selection(
                    inspection.path,
                    firmware_type=inspection.kind.value,
                    build=inspection.build,
                    expected_sha256=inspection.sha256,
                    device_codenames=(inspection.device,) if inspection.device else (),
                    provenance=provenance,
                    cancellation=token,
                )
                imported_artifact_id = record.artifact_id
                imported_artifact_created = record.artifact_id not in existing_artifact_ids
            except (OSError, RepositoryError, TypeError, ValueError):
                if token.cancelled:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="firmware_cancelled",
                        cancelled_message="firmware import was cancelled",
                        timeout_message="firmware import timed out",
                    )
                return OperationResult.failed(
                    command.operation_id,
                    code="firmware_repository_import_failed",
                    message="the inspected firmware could not be stored safely",
                )
            inspection = replace(inspection, path=str(record.path))
        if token.cancelled:
            stopped = self._stopped_result(
                command,
                token,
                cancelled_code="firmware_cancelled",
                cancelled_message="firmware selection was cancelled before state promotion",
                timeout_message="firmware selection timed out before state promotion",
            )
            return self._rollback_firmware_import(
                command,
                stopped,
                imported_artifact_id,
                imported_artifact_created,
            )
        current = self.store.snapshot()
        if current.revision != snapshot.revision:
            denied = self._denied(
                command,
                "stale_revision",
                f"state revision changed: expected {snapshot.revision}, current {current.revision}",
            )
            return self._rollback_firmware_import(
                command,
                denied,
                imported_artifact_id,
                imported_artifact_created,
            )
        result = self._update_state(
            command,
            firmware=inspection.to_firmware_info(processed=False),
            # A boot image belongs to one exact firmware hash. Selecting a new
            # package invalidates any previously promoted stock or patched boot.
            boot=BootInfo(),
        )
        if not result.ok:
            return self._rollback_firmware_import(
                command,
                result,
                imported_artifact_id,
                imported_artifact_created,
            )
        return replace(
            result,
            code="firmware_selected",
            message=f"{inspection.kind.value} firmware inspected successfully",
            value={
                "snapshot": self.store.snapshot().to_dict(),
                "inspection": inspection.to_public_diagnostics(
                    expected_devices=expected_devices,
                    provenance=provenance.value,
                ),
            },
        )

    def _rollback_firmware_import(
        self,
        command: AppCommand,
        intended_result: OperationResult,
        artifact_id: str,
        imported: bool,
    ) -> OperationResult:
        """Make repository import and canonical state promotion one transaction."""

        if not imported or self.firmware_repository is None:
            return intended_result
        try:
            removed = self.firmware_repository.repository.delete(artifact_id)
        except (OSError, RepositoryError, TypeError, ValueError):
            removed = False
        if not removed:
            return OperationResult.failed(
                command.operation_id,
                code="firmware_import_rollback_failed",
                message="the firmware import could not be rolled back safely",
            )
        return intended_result

    def _list_boot_inventory(self, command: AppCommand) -> OperationResult:
        if command.payload:
            return self._invalid(command, "boot.inventory does not accept payload fields")
        service = self.boot_inventory_service
        if service is None:
            return OperationResult.failed(
                command.operation_id,
                code="boot_repository_unavailable",
                message="the boot image repository is not configured",
            )
        snapshot = self.store.snapshot()
        decision = self.safety_policy.evaluate(command, snapshot)
        if not decision.allowed:
            return self._denied(command, decision.code, decision.message)
        token = self._register_cancellation(command)
        if token is None:
            return self._denied(command, "operation_busy", "operation id is already active")
        try:
            with self._operation_guard(token) as acquired:
                if not acquired:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="boot_cancelled",
                        cancelled_message="boot inventory was cancelled while queued",
                        timeout_message="boot inventory timed out while queued",
                    )
                entries = service.list_public(token)
        except BootInventoryError as error:
            if error.code == "boot_cancelled":
                return self._stopped_result(
                    command,
                    token,
                    cancelled_code=error.code,
                    cancelled_message=str(error),
                    timeout_message="boot inventory timed out",
                )
            return OperationResult.failed(
                command.operation_id,
                code=error.code,
                message=str(error),
            )
        finally:
            self._unregister_cancellation(command.operation_id)
        return OperationResult.success(
            command.operation_id,
            code="boot_inventory_listed",
            message=f"found {len(entries)} boot image(s)",
            value={
                "boots": [entry.to_public_dict() for entry in entries],
                "selectedBootId": snapshot.boot.id or None,
                "revision": snapshot.revision,
            },
        )

    def _list_backups(self, command: AppCommand) -> OperationResult:
        if set(command.payload) - {"serial"}:
            return self._invalid(command, "backups.list accepts only an optional serial")
        serial = command.payload.get("serial")
        if serial is not None and (not isinstance(serial, str) or not serial):
            return self._invalid(command, "backups.list serial must be a non-empty string")
        snapshot = self.store.snapshot()
        decision = self.safety_policy.evaluate(command, snapshot)
        if not decision.allowed:
            return self._denied(command, decision.code, decision.message)
        token = self._register_cancellation(command)
        if token is None:
            return self._denied(command, "operation_busy", "operation id is already active")
        try:
            with self._operation_guard(token) as acquired:
                if not acquired or token.cancelled:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="backup_inventory_cancelled",
                        cancelled_message="backup inventory was cancelled",
                        timeout_message="backup inventory timed out",
                    )
                try:
                    records = self.backup_repository.list(target_serial=serial)
                    total = self.backup_repository.count(target_serial=serial)
                except BackupRepositoryError as error:
                    return OperationResult.failed(
                        command.operation_id,
                        code=error.code,
                        message=str(error),
                    )
                if token.cancelled:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="backup_inventory_cancelled",
                        cancelled_message="backup inventory was cancelled",
                        timeout_message="backup inventory timed out",
                    )
                current = self.store.snapshot()
                if current.revision != snapshot.revision:
                    return self._denied(
                        command,
                        "stale_revision",
                        "application state changed while listing backups",
                    )
                public = [
                    record.to_public_dict(available=self.backup_repository.is_available(record)) for record in records
                ]
                return OperationResult.success(
                    command.operation_id,
                    code="backup_inventory_listed",
                    message=f"found {len(public)} managed backup(s)",
                    value={
                        "backups": public,
                        "count": len(public),
                        "totalCount": total,
                        "filteredSerial": serial,
                        "revision": current.revision,
                        "bounded": True,
                        "truncated": total > len(public),
                    },
                )
        finally:
            self._unregister_cancellation(command.operation_id)

    def _delete_backup(self, command: AppCommand) -> OperationResult:
        if set(command.payload) != {"backupId", "confirmationText"}:
            return self._invalid(
                command,
                "backups.delete requires backupId and confirmationText",
            )
        backup_id = command.payload.get("backupId")
        confirmation = command.payload.get("confirmationText")
        if not isinstance(backup_id, str) or not isinstance(confirmation, str):
            return self._invalid(command, "backupId and confirmationText must be strings")
        try:
            required = self.backup_repository.required_delete_confirmation(backup_id)
        except BackupRepositoryError as error:
            return OperationResult.failed(
                command.operation_id,
                code=error.code,
                message=str(error),
            )
        if confirmation != required:
            return OperationResult.failed(
                command.operation_id,
                code="backup_delete_confirmation_required",
                message=f"type {required} to delete this managed backup",
            )
        token = self._register_cancellation(command)
        if token is None:
            return self._denied(command, "operation_busy", "operation id is already active")
        try:
            with self._operation_guard(token) as acquired:
                if not acquired or token.cancelled:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="backup_delete_cancelled",
                        cancelled_message="backup deletion was cancelled",
                        timeout_message="backup deletion timed out",
                    )
                snapshot = self.store.snapshot()
                decision = self.safety_policy.evaluate(command, snapshot)
                if not decision.allowed:
                    return self._denied(command, decision.code, decision.message)
                try:
                    existing = self.backup_repository.get(backup_id)
                except BackupRepositoryError as error:
                    return OperationResult.failed(
                        command.operation_id,
                        code=error.code,
                        message=str(error),
                    )
                if existing is None:
                    return OperationResult.failed(
                        command.operation_id,
                        code="backup_not_found",
                        message="backup record was not found",
                    )
                receipt: BackupDeletionReceipt | None = None

                def remove(_current: AppSnapshot, _updated: AppSnapshot) -> None:
                    nonlocal receipt
                    receipt = self.backup_repository.delete(backup_id)

                try:
                    updated = self.store.transactional_update(
                        expected_revision=command.expected_revision,
                        prepare=lambda _current: {},
                        side_effect=remove,
                    )
                except StaleRevisionError as error:
                    return self._denied(command, "stale_revision", str(error))
                except BackupRepositoryError as error:
                    return OperationResult.failed(
                        command.operation_id,
                        code=error.code,
                        message=str(error),
                    )
                if receipt is None or not receipt.deleted:
                    return OperationResult.failed(
                        command.operation_id,
                        code="backup_delete_failed",
                        message="backup deletion produced no verified receipt",
                    )
                return OperationResult.success(
                    command.operation_id,
                    code="backup_deleted",
                    message="managed backup record deleted",
                    value={**receipt.to_public_dict(), "revision": updated.revision},
                )
        finally:
            self._unregister_cancellation(command.operation_id)

    def _select_boot(self, command: AppCommand) -> OperationResult:
        unknown = set(command.payload) - {"bootId", "path", "partition"}
        if unknown:
            return self._invalid(
                command,
                f"unsupported boot.select field: {sorted(unknown)[0]}",
            )
        boot_id = command.payload.get("bootId")
        path = command.payload.get("path")
        partition = command.payload.get("partition")
        selecting_existing = isinstance(boot_id, str) and bool(boot_id)
        importing = isinstance(path, str) and bool(path)
        if selecting_existing == importing:
            return self._invalid(
                command,
                "boot.select requires exactly one bootId or opaque file grant",
            )
        if selecting_existing and partition is not None:
            return self._invalid(
                command,
                "partition is accepted only when importing a granted boot image",
            )
        if importing and (not isinstance(partition, str) or not partition):
            return self._invalid(
                command,
                "partition is required when importing a granted boot image",
            )
        service = self.boot_inventory_service
        if service is None:
            return OperationResult.failed(
                command.operation_id,
                code="boot_repository_unavailable",
                message="the boot image repository is not configured",
            )

        token = self._register_cancellation(command)
        if token is None:
            return self._denied(command, "operation_busy", "operation id is already active")
        try:
            with self._operation_guard(token) as acquired:
                if not acquired:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="boot_selection_cancelled",
                        cancelled_message="boot selection was cancelled while queued",
                        timeout_message="boot selection timed out while queued",
                    )
                snapshot = self.store.snapshot()
                decision = self.safety_policy.evaluate(command, snapshot)
                if not decision.allowed:
                    return self._denied(command, decision.code, decision.message)
                try:
                    if selecting_existing:
                        selection = service.select(cast(str, boot_id), token)
                        code = "boot_selected"
                        message = "verified boot image selected"
                    else:
                        selection = service.import_image(
                            cast(str, path),
                            partition=cast(str, partition),
                            cancellation=token,
                        )
                        code = "boot_imported"
                        message = "boot image imported and selected"
                except BootInventoryError as error:
                    if error.code == "boot_cancelled":
                        return self._stopped_result(
                            command,
                            token,
                            cancelled_code=error.code,
                            cancelled_message=str(error),
                            timeout_message="boot selection timed out",
                        )
                    return OperationResult.failed(
                        command.operation_id,
                        code=error.code,
                        message=str(error),
                    )
                if token.cancelled:
                    stopped = self._stopped_result(
                        command,
                        token,
                        cancelled_code="boot_selection_cancelled",
                        cancelled_message="boot selection was cancelled before state promotion",
                        timeout_message="boot selection timed out before state promotion",
                    )
                    return self._rollback_boot_import(service, selection, command, stopped)
                try:
                    updated = self.store.update(
                        expected_revision=command.expected_revision,
                        boot=selection.info,
                    )
                except StaleRevisionError as error:
                    denied = self._denied(command, "stale_revision", str(error))
                    return self._rollback_boot_import(service, selection, command, denied)
                except (TypeError, ValueError) as error:
                    invalid = self._invalid(command, str(error))
                    return self._rollback_boot_import(service, selection, command, invalid)
            return OperationResult.success(
                command.operation_id,
                code=code,
                message=message,
                value={
                    "selected": selection.entry.to_public_dict(),
                    "revision": updated.revision,
                },
            )
        finally:
            self._unregister_cancellation(command.operation_id)

    def _delete_boot(self, command: AppCommand) -> OperationResult:
        if set(command.payload) != {"bootId"}:
            return self._invalid(command, "boot.delete requires exactly one bootId")
        boot_id = command.payload.get("bootId")
        if not isinstance(boot_id, str):
            return self._invalid(command, "bootId must be a string")
        service = self.boot_inventory_service
        if service is None:
            return OperationResult.failed(
                command.operation_id,
                code="boot_repository_unavailable",
                message="the boot image repository is not configured",
            )
        token = self._register_cancellation(command)
        if token is None:
            return self._denied(command, "operation_busy", "operation id is already active")
        try:
            with self._operation_guard(token) as acquired:
                if not acquired or token.cancelled:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="boot_delete_cancelled",
                        cancelled_message="boot image deletion was cancelled",
                        timeout_message="boot image deletion timed out",
                    )
                snapshot = self.store.snapshot()
                decision = self.safety_policy.evaluate(command, snapshot)
                if not decision.allowed:
                    return self._denied(command, decision.code, decision.message)
                if snapshot.active_operation is not None:
                    return self._denied(
                        command,
                        "boot_delete_operation_active",
                        "boot images cannot be deleted while an operation is active",
                    )
                if snapshot.boot.id == boot_id:
                    return self._denied(
                        command,
                        "boot_delete_selected",
                        "the selected boot image cannot be deleted",
                    )
                receipt: BootDeletionReceipt | None = None

                def prepare(current: AppSnapshot) -> Mapping[str, object]:
                    if current.active_operation is not None:
                        raise BootInventoryError(
                            "boot_delete_operation_active",
                            "boot images cannot be deleted while an operation is active",
                        )
                    if current.boot.id == boot_id:
                        raise BootInventoryError(
                            "boot_delete_selected",
                            "the selected boot image cannot be deleted",
                        )
                    return {}

                def remove(_current: AppSnapshot, _updated: AppSnapshot) -> None:
                    nonlocal receipt
                    receipt = service.delete(boot_id)

                try:
                    updated = self.store.transactional_update(
                        expected_revision=command.expected_revision,
                        prepare=prepare,
                        side_effect=remove,
                    )
                except StaleRevisionError as error:
                    return self._denied(command, "stale_revision", str(error))
                except BootInventoryError as error:
                    return OperationResult.failed(
                        command.operation_id,
                        code=error.code,
                        message=str(error),
                    )
                if receipt is None:
                    return OperationResult.failed(
                        command.operation_id,
                        code="boot_delete_failed",
                        message="the boot image deletion produced no receipt",
                    )
                return OperationResult.success(
                    command.operation_id,
                    code="boot_deleted",
                    message="boot image record deleted",
                    value={**receipt.to_public_dict(), "revision": updated.revision},
                )
        finally:
            self._unregister_cancellation(command.operation_id)

    @staticmethod
    def _rollback_boot_import(
        service: BootInventoryService,
        selection: BootSelection,
        command: AppCommand,
        intended_result: OperationResult,
    ) -> OperationResult:
        """Make a failed boot-state promotion atomic or report rollback failure."""

        if not selection.imported:
            return intended_result
        try:
            service.rollback_import(selection.info.id)
        except BootInventoryError as error:
            return OperationResult.failed(
                command.operation_id,
                code=error.code,
                message=str(error),
            )
        except Exception:
            return OperationResult.failed(
                command.operation_id,
                code="boot_import_rollback_failed",
                message="the boot import could not be rolled back safely",
            )
        return intended_result

    def _process_firmware(self, command: AppCommand) -> OperationResult:
        """Verify, extract and atomically promote canonical firmware artifacts."""

        if command.payload:
            return OperationResult.failed(
                command.operation_id,
                code="invalid_firmware_process_payload",
                message="firmware.process does not accept payload fields",
            )
        initial = self.store.snapshot()
        if not initial.firmware.path:
            return OperationResult.failed(
                command.operation_id,
                code="firmware_required",
                message="select firmware before processing it",
            )
        decision = self.safety_policy.evaluate(command, initial)
        if not decision.allowed:
            return self._denied(command, decision.code, decision.message)

        token = self._register_cancellation(command)
        if token is None:
            return self._denied(command, "operation_busy", "operation id is already active")
        try:
            with self._operation_guard(token) as acquired:
                if not acquired:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="firmware_processing_cancelled",
                        cancelled_message="firmware processing was cancelled while queued",
                        timeout_message="firmware processing timed out while queued",
                    )
                if token.cancelled:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="firmware_processing_cancelled",
                        cancelled_message="firmware processing was cancelled before it started",
                        timeout_message="firmware processing timed out before it started",
                    )
                snapshot = self.store.snapshot()
                decision = self.safety_policy.evaluate(command, snapshot)
                if not decision.allowed:
                    return self._denied(command, decision.code, decision.message)
                if snapshot.firmware != initial.firmware:
                    return self._denied(
                        command,
                        "firmware_selection_changed",
                        "selected firmware changed before processing started",
                    )

                try:
                    active_snapshot = self.store.begin_operation(
                        command.operation_id,
                        expected_revision=snapshot.revision,
                        kind="firmware.process",
                        label="Process firmware",
                    )
                except StaleRevisionError as error:
                    return self._denied(command, "stale_revision", str(error))
                except ValueError as error:
                    return self._denied(command, "operation_busy", str(error))

                expected_devices = tuple(
                    device.codename
                    for device in snapshot.devices
                    if device.serial in snapshot.selected_serials and device.codename
                )
                promoted_boot_selection: BootSelection | None = None
                processing: FirmwareProcessingResult | None = None
                try:
                    processing = self.firmware_artifact_service.process(
                        snapshot.firmware.path,
                        expected_devices=expected_devices,
                        cancellation=token,
                    )
                    if token.cancelled and processing.ok:
                        result = self._stopped_result(
                            command,
                            token,
                            cancelled_code="firmware_processing_cancelled",
                            cancelled_message="firmware processing was cancelled before state promotion",
                            timeout_message="firmware processing timed out before state promotion",
                        )
                        promoted_firmware = None
                        promoted_boot = None
                    else:
                        (
                            result,
                            promoted_firmware,
                            promoted_boot,
                            promoted_boot_selection,
                        ) = self._firmware_processing_result(command, snapshot, processing, token)
                        if result.status is OperationStatus.CANCELLED and token.reason is CancellationReason.DEADLINE:
                            result = self._stopped_result(
                                command,
                                token,
                                cancelled_code=result.code,
                                cancelled_message=result.message,
                                timeout_message="firmware processing timed out",
                            )
                            promoted_firmware = None
                            promoted_boot = None
                except Exception as error:
                    promoted_firmware = None
                    promoted_boot = None
                    promoted_boot_selection = None
                    if token.cancelled:
                        result = self._stopped_result(
                            command,
                            token,
                            cancelled_code="firmware_processing_cancelled",
                            cancelled_message="firmware processing was cancelled",
                            timeout_message="firmware processing timed out",
                        )
                    else:
                        result = OperationResult.failed(
                            command.operation_id,
                            code="firmware_processing_failed",
                            message=str(error),
                        )

                current = self.store.snapshot()
                if result.ok and token.cancelled:
                    promoted_firmware = None
                    promoted_boot = None
                    result = self._stopped_result(
                        command,
                        token,
                        cancelled_code="firmware_processing_cancelled",
                        cancelled_message="firmware processing was cancelled before state promotion",
                        timeout_message="firmware processing timed out before state promotion",
                    )
                elif result.ok and (
                    current.revision != active_snapshot.revision
                    or current.active_operation is None
                    or current.active_operation.operation_id != command.operation_id
                    or current.firmware != snapshot.firmware
                ):
                    promoted_firmware = None
                    promoted_boot = None
                    result = OperationResult.failed(
                        command.operation_id,
                        code="firmware_selection_changed",
                        message="canonical firmware state changed while processing",
                    )
                if processing is not None and processing.ok and not result.ok:
                    promoted_firmware = None
                    promoted_boot = None
                    result = self._rollback_firmware_processing(
                        command,
                        processing,
                        result,
                        promoted_boot_selection,
                    )
                try:
                    self.store.complete_operation(
                        result,
                        expected_revision=(active_snapshot.revision if result.ok else None),
                        firmware=promoted_firmware,
                        boot=promoted_boot,
                    )
                except (StaleRevisionError, TypeError, ValueError) as error:
                    fallback = OperationResult.failed(
                        command.operation_id,
                        code="firmware_state_promotion_failed",
                        message=str(error),
                    )
                    if processing is not None and processing.ok and result.ok:
                        fallback = self._rollback_firmware_processing(
                            command,
                            processing,
                            fallback,
                            promoted_boot_selection,
                        )
                    self._abort_operation_safely(fallback)
                    return fallback
                return result
        finally:
            self._unregister_cancellation(command.operation_id)

    def _rollback_firmware_processing(
        self,
        command: AppCommand,
        processing: FirmwareProcessingResult,
        intended_result: OperationResult,
        boot_selection: BootSelection | None = None,
    ) -> OperationResult:
        rollback_failed = False
        if boot_selection is not None and boot_selection.imported and self.boot_inventory_service is not None:
            try:
                self.boot_inventory_service.rollback_processed_import(
                    boot_selection.info.id,
                )
            except Exception:
                rollback_failed = True
        try:
            self.firmware_artifact_service.rollback(processing)
        except Exception:
            rollback_failed = True
        if rollback_failed:
            return OperationResult.failed(
                command.operation_id,
                code="firmware_processing_rollback_failed",
                message="processed firmware and boot artifacts could not be rolled back safely",
            )
        return intended_result

    def _create_support_package(self, command: AppCommand) -> OperationResult:
        """Create one redacted archive at a one-use native destination."""

        initial = self.store.snapshot()
        decision = self.safety_policy.evaluate(command, initial)
        if not decision.allowed:
            return self._denied(command, decision.code, decision.message)

        token = self._register_cancellation(command)
        if token is None:
            return self._denied(command, "operation_busy", "operation id is already active")
        try:
            with self._operation_guard(token) as acquired:
                if not acquired:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="support_package_cancelled",
                        cancelled_message="support package creation was cancelled while queued",
                        timeout_message="support package creation timed out while queued",
                    )
                if token.cancelled:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="support_package_cancelled",
                        cancelled_message="support package creation was cancelled before it started",
                        timeout_message="support package creation timed out before it started",
                    )
                snapshot = self.store.snapshot()
                decision = self.safety_policy.evaluate(command, snapshot)
                if not decision.allowed:
                    return self._denied(command, decision.code, decision.message)
                try:
                    self.store.begin_operation(
                        command.operation_id,
                        expected_revision=snapshot.revision,
                        kind=SUPPORT_COMMAND,
                        label="Create support package",
                    )
                except StaleRevisionError as error:
                    return self._denied(command, "stale_revision", str(error))
                except ValueError as error:
                    return self._denied(command, "operation_busy", str(error))

                try:
                    package = self.support_package_service.create(
                        command.payload,
                        snapshot=snapshot,
                        cancellation=token,
                    )
                except Exception as error:
                    if token.cancelled:
                        result = self._stopped_result(
                            command,
                            token,
                            cancelled_code="support_package_cancelled",
                            cancelled_message="support package creation was cancelled",
                            timeout_message="support package creation timed out",
                        )
                    else:
                        result = OperationResult.failed(
                            command.operation_id,
                            code="support_package_failed",
                            message=str(error),
                        )
                else:
                    if package.status is SupportPackageStatus.SUCCESS:
                        result = OperationResult.success(
                            command.operation_id,
                            code=package.code,
                            message=package.message,
                            value=package.to_dict(),
                        )
                    elif package.status is SupportPackageStatus.CANCELLED:
                        result = self._stopped_result(
                            command,
                            token,
                            cancelled_code=package.code,
                            cancelled_message=package.message,
                            timeout_message="support package creation timed out",
                        )
                    else:
                        result = OperationResult.failed(
                            command.operation_id,
                            code=package.code,
                            message=package.message,
                        )
                try:
                    self.store.complete_operation(result)
                except (TypeError, ValueError) as error:
                    fallback = OperationResult.failed(
                        command.operation_id,
                        code="support_state_completion_failed",
                        message=str(error),
                    )
                    self._abort_operation_safely(fallback)
                    return fallback
                return result
        finally:
            self._unregister_cancellation(command.operation_id)

    def _firmware_processing_result(
        self,
        command: AppCommand,
        selected_snapshot: AppSnapshot,
        processing: FirmwareProcessingResult,
        cancellation: CancellationToken,
    ) -> tuple[OperationResult, FirmwareInfo | None, BootInfo | None, BootSelection | None]:
        if processing.status is FirmwareProcessingStatus.CANCELLED:
            return (
                OperationResult.cancelled(
                    command.operation_id,
                    code=processing.code.value,
                    message=processing.message,
                ),
                None,
                None,
                None,
            )
        if processing.status is FirmwareProcessingStatus.FAILED:
            return (
                OperationResult.failed(
                    command.operation_id,
                    code=processing.code.value,
                    message=processing.message,
                ),
                None,
                None,
                None,
            )
        if not processing.ok:
            return (
                OperationResult.failed(
                    command.operation_id,
                    code="firmware_processing_result_invalid",
                    message="firmware processor returned an inconsistent result",
                ),
                None,
                None,
                None,
            )
        selected_hash = selected_snapshot.firmware.hash
        if selected_hash and selected_hash.casefold() != processing.firmware.hash.casefold():
            return (
                OperationResult.failed(
                    command.operation_id,
                    code="firmware_selection_changed",
                    message="selected firmware hash changed since inspection",
                ),
                None,
                None,
                None,
            )
        try:
            stock_boot, boot_selection = self._stock_boot_from_processing(
                processing,
                selected_snapshot,
                cancellation,
            )
        except BootInventoryError as error:
            terminal = (
                OperationResult.cancelled(
                    command.operation_id,
                    code=error.code,
                    message=str(error),
                )
                if error.code == "boot_cancelled"
                else OperationResult.failed(
                    command.operation_id,
                    code=error.code,
                    message=str(error),
                )
            )
            return terminal, None, None, None
        except ValueError as error:
            return (
                OperationResult.failed(
                    command.operation_id,
                    code="stock_boot_artifact_required",
                    message=str(error),
                ),
                None,
                None,
                None,
            )
        try:
            value = self._firmware_processing_public_value(
                selected_snapshot,
                processing,
                stock_boot,
            )
        except Exception:
            if boot_selection is not None and boot_selection.imported and self.boot_inventory_service is not None:
                self.boot_inventory_service.rollback_processed_import(
                    boot_selection.info.id,
                )
            raise
        return (
            OperationResult.success(
                command.operation_id,
                code="firmware_processed",
                message=f"{processing.inspection.kind.value} firmware processed successfully",
                value=value,
            ),
            processing.firmware,
            stock_boot,
            boot_selection,
        )

    def _firmware_processing_public_value(
        self,
        selected_snapshot: AppSnapshot,
        processing: FirmwareProcessingResult,
        stock_boot: BootInfo | None,
    ) -> dict[str, object]:
        provenance = ArtifactProvenance.USER_SUPPLIED.value
        if self.firmware_repository is not None:
            source_record = self.firmware_repository.resolve_selection(
                sha256=processing.firmware.hash,
            )
            if source_record is not None:
                provenance = source_record.provenance.value
        expected_devices = tuple(
            device.codename
            for device in selected_snapshot.devices
            if device.serial in selected_snapshot.selected_serials and device.codename
        )
        return {
            "processing": {
                "status": processing.status.value,
                "code": processing.code.value,
                "inspection": processing.inspection.to_public_diagnostics(
                    expected_devices=expected_devices,
                    provenance=provenance,
                ),
                "artifacts": [
                    {
                        "sha256": artifact.sha256,
                        "role": artifact.role,
                        "displayName": f"@artifact/{artifact.role}/{artifact.sha256[:12]}",
                    }
                    for artifact in processing.artifacts
                ],
                "detectedDevices": list(processing.detected_devices),
                "registered": processing.registered,
            },
            "firmware": processing.firmware.to_dict(),
            "boot": stock_boot.to_dict() if stock_boot is not None else None,
        }

    def _stock_boot_from_processing(
        self,
        processing: FirmwareProcessingResult,
        selected_snapshot: AppSnapshot,
        cancellation: CancellationToken,
    ) -> tuple[BootInfo | None, BootSelection | None]:
        by_role = {artifact.role: artifact for artifact in processing.artifacts}
        artifact = by_role.get("partition:init_boot") or by_role.get("partition:boot")
        if artifact is None:
            # OTA packages are safely sideloaded as one verified source archive;
            # their payload is not partially unpacked by this service.
            if processing.inspection.kind.value == "ota":
                return None, None
            raise ValueError("processed factory/custom firmware has no verified init_boot or boot image")
        partition = artifact.role.partition(":")[2]
        if self.boot_inventory_service is not None:
            device_codenames = tuple(
                sorted(
                    {
                        *processing.detected_devices,
                        *(
                            device.codename
                            for device in selected_snapshot.devices
                            if device.serial in selected_snapshot.selected_serials and device.codename
                        ),
                    }
                )
            )
            selection = self.boot_inventory_service.import_processed(
                artifact,
                firmware_hash=processing.firmware.hash,
                device_codenames=device_codenames,
                cancellation=cancellation,
            )
            return selection.info, selection
        return (
            BootInfo(
                id=f"stock:{partition}:{artifact.sha256}",
                path=artifact.path,
                hash=artifact.sha256,
                flavor=partition,
                patched=False,
            ),
            None,
        )

    def _setup_platform_tools(self, command: AppCommand) -> OperationResult:
        unknown = set(command.payload) - {"source", "path"}
        if unknown:
            return self._invalid(
                command,
                f"unsupported platformTools.setup field: {sorted(unknown)[0]}",
            )
        source = command.payload.get("source")
        path = command.payload.get("path")
        if not isinstance(source, str) or source not in {"official", "directory"}:
            return self._invalid(
                command,
                "payload.source must be exactly official or directory",
            )
        if source == "directory" and (not isinstance(path, str) or not path.strip()):
            return self._invalid(
                command,
                "payload.path must contain the resolved native directory grant",
            )
        if source == "official" and path is not None:
            return self._invalid(
                command,
                "official Platform Tools setup does not accept a local path",
            )
        decision = self.safety_policy.evaluate(command, self.store.snapshot())
        if not decision.allowed:
            return self._denied(command, decision.code, decision.message)
        token = self._register_cancellation(command)
        if token is None:
            return self._denied(command, "operation_busy", "operation id is already active")
        try:
            with self._operation_guard(token) as acquired:
                if not acquired:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="platform_tools_setup_cancelled",
                        cancelled_message="Platform Tools setup was cancelled while queued",
                        timeout_message="Platform Tools setup timed out while queued",
                    )
                if token.cancelled:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="platform_tools_setup_cancelled",
                        cancelled_message="Platform Tools setup was cancelled before it started",
                        timeout_message="Platform Tools setup timed out before it started",
                    )
                snapshot = self.store.snapshot()
                decision = self.safety_policy.evaluate(command, snapshot)
                if not decision.allowed:
                    return self._denied(command, decision.code, decision.message)
                setup = self.platform_tools_setup_service.setup(
                    source=source,
                    directory=path.strip() if isinstance(path, str) else None,
                    cancellation=token,
                    progress=lambda phase, message, percent: self._publish_progress(
                        command,
                        phase,
                        message,
                        percent,
                    ),
                )
                if setup.status is PlatformToolsStatus.CANCELLED:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code=setup.code,
                        cancelled_message=setup.message,
                        timeout_message="Platform Tools setup timed out",
                    )
                if not setup.ok or setup.toolchain is None:
                    return OperationResult.failed(
                        command.operation_id,
                        code=setup.code,
                        message=setup.message,
                    )
                if self.toolchain_state_updater is None:
                    result = self._update_state(command, toolchain=setup.toolchain)
                else:
                    result = self.toolchain_state_updater(command, setup.toolchain)
                if not result.ok:
                    return result
                self.toolchain_service.configured_path = Path(setup.toolchain.adb).parent
                return replace(
                    result,
                    code=setup.code,
                    message=setup.message,
                    value={
                        **setup.to_public_dict(),
                        "revision": self.store.snapshot().revision,
                    },
                )
        except Exception:
            if token.cancelled:
                return self._stopped_result(
                    command,
                    token,
                    cancelled_code="platform_tools_setup_cancelled",
                    cancelled_message="Platform Tools setup was cancelled",
                    timeout_message="Platform Tools setup timed out",
                )
            return OperationResult.failed(
                command.operation_id,
                code="toolchain_setup_failed",
                message="Platform Tools setup could not be completed.",
            )
        finally:
            self._unregister_cancellation(command.operation_id)

    def _setup_scrcpy(self, command: AppCommand) -> OperationResult:
        if set(command.payload) != {"source"} or command.payload.get("source") != "official":
            return self._invalid(
                command,
                "tools.scrcpy.setup accepts only source=official",
            )
        decision = self.safety_policy.evaluate(command, self.store.snapshot())
        if not decision.allowed:
            return self._denied(command, decision.code, decision.message)
        token = self._register_cancellation(command)
        if token is None:
            return self._denied(command, "operation_busy", "operation id is already active")
        try:
            with self._operation_guard(token) as acquired:
                if not acquired or token.cancelled:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="scrcpy_setup_cancelled",
                        cancelled_message="Scrcpy setup was cancelled before it started",
                        timeout_message="Scrcpy setup timed out before it started",
                    )
                decision = self.safety_policy.evaluate(command, self.store.snapshot())
                if not decision.allowed:
                    return self._denied(command, decision.code, decision.message)
                setup = self.scrcpy_setup_service.setup(
                    cancellation=token,
                    progress=lambda phase, message, percent: self._publish_progress(
                        command,
                        phase,
                        message,
                        percent,
                    ),
                )
                if setup.status is ScrcpyStatus.CANCELLED:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code=setup.code,
                        cancelled_message=setup.message,
                        timeout_message="Scrcpy setup timed out",
                    )
                if not setup.ok or setup.installation is None:
                    return OperationResult.failed(
                        command.operation_id,
                        code=setup.code,
                        message=setup.message,
                    )
                executable = setup.installation.executable
                if self.scrcpy_state_updater is None:
                    result = OperationResult.success(
                        command.operation_id,
                        code="scrcpy_activated",
                        message="Scrcpy activated.",
                        value={"revision": self.store.snapshot().revision},
                    )
                else:
                    result = self.scrcpy_state_updater(command, executable)
                if not result.ok:
                    return result
                self.device_tools_service.scrcpy_executable = executable
                return replace(
                    result,
                    code=setup.code,
                    message=setup.message,
                    value={
                        **setup.to_public_dict(),
                        "revision": self.store.snapshot().revision,
                    },
                )
        except Exception:
            if token.cancelled:
                return self._stopped_result(
                    command,
                    token,
                    cancelled_code="scrcpy_setup_cancelled",
                    cancelled_message="Scrcpy setup was cancelled",
                    timeout_message="Scrcpy setup timed out",
                )
            return OperationResult.failed(
                command.operation_id,
                code="scrcpy_setup_failed",
                message="Scrcpy setup could not be completed.",
            )
        finally:
            self._unregister_cancellation(command.operation_id)

    def _publish_progress(
        self,
        command: AppCommand,
        phase: ProgressPhase,
        message: str,
        percent: int | None,
        *,
        current: int | None = None,
        total: int | None = None,
        item: str | None = None,
    ) -> None:
        listener = self.executor.progress_listener
        if listener is None:
            return
        try:
            listener(
                ProgressEvent(
                    command.operation_id,
                    phase,
                    message,
                    percent,
                    kind=str(command.kind),
                    current=current,
                    total=total,
                    item=item,
                    target_serial=command.target_serial,
                )
            )
        except Exception:
            pass

    def _scan_devices(self, command: AppCommand) -> OperationResult:
        snapshot = self.store.snapshot()
        if not snapshot.device_management.scan_enabled:
            return OperationResult.failed(
                command.operation_id,
                code="device_scanning_paused",
                message="device scanning is paused",
            )
        include_properties = command.payload.get("includeProperties", True)
        include_battery = command.payload.get("includeBattery", True)
        if not isinstance(include_properties, bool):
            return self._invalid(command, "payload.includeProperties must be a boolean")
        if not isinstance(include_battery, bool):
            return self._invalid(command, "payload.includeBattery must be a boolean")
        decision = self.safety_policy.evaluate(command, snapshot)
        if not decision.allowed:
            return self._denied(command, decision.code, decision.message)
        token = self._register_cancellation(command)
        if token is None:
            return self._denied(command, "operation_busy", "operation id is already active")
        try:
            toolchain = snapshot.toolchain
            if not toolchain.ready:
                configured = None
                if toolchain.adb:
                    configured = str(Path(toolchain.adb).parent)
                try:
                    check = self.toolchain_service.discover(configured, cancellation=token)
                except Exception as error:
                    if token.cancelled:
                        return self._stopped_result(
                            command,
                            token,
                            cancelled_code="cancelled",
                            cancelled_message="device scan was cancelled while validating Platform Tools",
                            timeout_message="device scan timed out while validating Platform Tools",
                        )
                    return OperationResult.failed(
                        command.operation_id,
                        code="toolchain_setup_failed",
                        message=str(error),
                    )
                if check.code == "cancelled":
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="cancelled",
                        cancelled_message=check.message,
                        timeout_message="device scan timed out while validating Platform Tools",
                    )
                if not check.ok:
                    return OperationResult.failed(
                        command.operation_id,
                        code=check.code,
                        message=check.message,
                    )
                toolchain = check.info
            try:
                excluded_serials: frozenset[str] = (
                    frozenset(device.serial for device in snapshot.device_management.devices if not device.enabled)
                    if snapshot.device_management.scan_scope == "enabled"
                    else frozenset()
                )
                scan = self.device_service.scan(
                    toolchain,
                    include_properties=include_properties,
                    include_battery=include_battery,
                    previous_devices=snapshot.devices,
                    excluded_serials=excluded_serials,
                    cancellation=token,
                )
            except Exception as error:
                if token.cancelled:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="cancelled",
                        cancelled_message="device scan was cancelled",
                        timeout_message="device scan timed out",
                    )
                return OperationResult.failed(
                    command.operation_id,
                    code="device_scan_failed",
                    message=str(error),
                )
            return self._promote_device_scan(
                command,
                snapshot,
                toolchain,
                scan,
                token,
            )
        finally:
            self._unregister_cancellation(command.operation_id)

    def _promote_device_scan(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        toolchain: ToolchainInfo,
        scan: DeviceScanResult,
        token: CancellationToken,
    ) -> OperationResult:
        if scan.cancelled:
            return self._stopped_result(
                command,
                token,
                cancelled_code="cancelled",
                cancelled_message="device scan was cancelled",
                timeout_message="device scan timed out",
            )
        if not scan.ok:
            return OperationResult.failed(
                command.operation_id,
                code="device_scan_failed",
                message="; ".join(scan.warnings) or "adb and fastboot scans failed",
            )
        scanned_devices = {device.serial: device for device in scan.observed_devices}
        if "adb" not in scan.successful_sources:
            for device in snapshot.devices:
                if device.mode not in {"fastboot", "fastbootd"}:
                    scanned_devices.setdefault(device.serial, device)
        if "fastboot" not in scan.successful_sources:
            for device in snapshot.devices:
                if device.mode in {"fastboot", "fastbootd"}:
                    scanned_devices.setdefault(device.serial, device)
        for remembered in snapshot.device_management.devices:
            if not remembered.connected or remembered.serial in scanned_devices:
                continue
            is_fastboot = remembered.mode in {"fastboot", "fastbootd"}
            source = "fastboot" if is_fastboot else "adb"
            if source in scan.successful_sources:
                continue
            scanned_devices[remembered.serial] = DeviceInfo(
                serial=remembered.serial,
                model=remembered.model,
                codename=remembered.codename,
                mode=remembered.mode,
                online=True,
                name=remembered.label or remembered.model or remembered.codename,
            )
        raw_devices = tuple(scanned_devices[key] for key in sorted(scanned_devices, key=str.casefold))
        try:
            management, devices = reconcile_device_management(
                snapshot.device_management,
                raw_devices,
            )
        except DeviceManagementError as error:
            return OperationResult.failed(
                command.operation_id,
                code=error.code,
                message=str(error),
            )
        available = {device.serial for device in devices}
        selected = tuple(serial for serial in snapshot.selected_serials if serial in available)
        primary = (
            snapshot.selected_serial if snapshot.selected_serial in available else (selected[0] if selected else None)
        )
        if token.cancelled:
            return self._stopped_result(
                command,
                token,
                cancelled_code="cancelled",
                cancelled_message="device scan was cancelled before state promotion",
                timeout_message="device scan timed out before state promotion",
            )
        if self.device_scan_state_updater is not None:
            result = self.device_scan_state_updater(
                command,
                devices,
                management,
                toolchain,
            )
        else:
            result = self._update_state(
                command,
                devices=devices,
                device_management=management,
                selected_serials=selected,
                selected_serial=primary,
                toolchain=toolchain,
            )
        if not result.ok:
            return result
        return replace(
            result,
            code="device_scan_succeeded",
            message=f"found {len(devices)} device(s)",
            value={
                "snapshot": self.store.snapshot().to_dict(),
                "scan": replace(scan, devices=devices).to_dict(),
            },
        )

    def _preview_flash_plan(self, command: AppCommand) -> OperationResult:
        snapshot = self.store.snapshot()
        decision = self.safety_policy.evaluate(command, snapshot)
        if not decision.allowed:
            return self._denied(command, decision.code, decision.message)
        batch_requested = (
            command.target_serial is None and "serial" not in command.payload and len(snapshot.selected_serials) > 1
        )
        target_serial = None if batch_requested else command.target_serial or snapshot.selected_serial
        synthetic = AppCommand(
            "flash.execute",
            expected_revision=command.expected_revision,
            target_serial=target_serial,
            payload=command.payload,
            operation_id=command.operation_id,
        )
        token = self._register_cancellation(command)
        if token is None:
            return self._denied(command, "operation_busy", "operation id is already active")
        try:
            try:
                if batch_requested and snapshot.plan.dry_run:
                    compilation = self.operation_planner.compile_preview_batch(synthetic, snapshot)
                elif batch_requested:
                    compilation = self.operation_planner.compile_batch(synthetic, snapshot, preview=True)
                else:
                    compilation = self.operation_planner.compile(synthetic, snapshot, preview=True)
            except Exception as error:
                if token.cancelled:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="planning_cancelled",
                        cancelled_message="flash plan preview was cancelled",
                        timeout_message="flash plan preview timed out",
                    )
                return OperationResult.failed(
                    command.operation_id,
                    code="planner_error",
                    message=str(error),
                )
            if token.cancelled:
                return self._stopped_result(
                    command,
                    token,
                    cancelled_code="planning_cancelled",
                    cancelled_message="flash plan preview was cancelled",
                    timeout_message="flash plan preview timed out",
                )
            if not compilation.ok:
                return replace(
                    OperationResult.failed(
                        command.operation_id,
                        code=compilation.code,
                        message=compilation.message,
                    ),
                    value=compilation.to_dict(),
                )
            return OperationResult.success(
                command.operation_id,
                code="flash_plan_preview",
                value={
                    "revision": snapshot.revision,
                    "canonical_plan": snapshot.plan.to_dict(),
                    "plan": snapshot.plan.to_dict(),
                    "selected_serials": list(snapshot.selected_serials),
                    "firmware": snapshot.firmware.to_dict(),
                    "compiled": compilation.to_dict(),
                    "batch": batch_requested,
                },
            )
        finally:
            self._unregister_cancellation(command.operation_id)

    def _plan_and_execute(self, command: AppCommand) -> OperationResult:
        snapshot = self.store.snapshot()
        token = self._register_cancellation(command)
        if token is None:
            return self._denied(command, "operation_busy", "operation id is already active")
        batch_requested = (
            command.kind == "flash.execute"
            and command.target_serial is None
            and "serial" not in command.payload
            and len(snapshot.selected_serials) > 1
        )
        if batch_requested and snapshot.plan.dry_run:
            try:
                compilation = self.operation_planner.compile_preview_batch(command, snapshot)
                if token.cancelled:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="planning_cancelled",
                        cancelled_message="dry-run batch planning was cancelled",
                        timeout_message="dry-run batch planning timed out",
                    )
                if not compilation.ok or compilation.preview is None:
                    return replace(
                        OperationResult.failed(
                            command.operation_id,
                            code=compilation.code,
                            message=compilation.message,
                        ),
                        value=compilation.to_dict(),
                    )
                return OperationResult.success(
                    command.operation_id,
                    code="dry_run_batch_succeeded",
                    message=(f"planned {len(compilation.preview.plans)} devices without launching a subprocess"),
                    value={"preview": compilation.preview.to_dict()},
                )
            except Exception as error:
                return OperationResult.failed(
                    command.operation_id,
                    code="planner_error",
                    message=str(error),
                )
            finally:
                self._unregister_cancellation(command.operation_id)
        if batch_requested:
            operation_started = False
            canonical_revision = snapshot.revision

            def current_batch_snapshot(serial: str) -> AppSnapshot:
                current = self.snapshot_provider(serial)
                active = current.active_operation
                if (
                    operation_started
                    and current.revision == canonical_revision + 1
                    and active is not None
                    and active.operation_id == command.operation_id
                ):
                    return replace(
                        current,
                        revision=canonical_revision,
                        active_operation=None,
                    )
                return current

            def begin_batch(_batch: object, current: AppSnapshot) -> ExecutionBoundaryAck:
                nonlocal operation_started
                if current.revision != canonical_revision:
                    return ExecutionBoundaryAck.rejected(
                        "stale_revision",
                        "state revision changed before batch execution",
                    )
                try:
                    self.store.begin_operation(
                        command.operation_id,
                        expected_revision=canonical_revision,
                        kind=str(command.kind),
                        label=f"Flash {len(snapshot.selected_serials)} devices",
                        target_serial=None,
                    )
                except StaleRevisionError as error:
                    return ExecutionBoundaryAck.rejected("stale_revision", str(error))
                except ValueError as error:
                    return ExecutionBoundaryAck.rejected("operation_busy", str(error))
                operation_started = True
                return ExecutionBoundaryAck.accepted()

            try:
                compilation = self.operation_planner.compile_batch(command, snapshot)
                if token.cancelled:
                    return self._stopped_result(
                        command,
                        token,
                        cancelled_code="planning_cancelled",
                        cancelled_message="batch planning was cancelled",
                        timeout_message="batch planning timed out",
                    )
                if not compilation.ok or compilation.batch is None:
                    return replace(
                        OperationResult.failed(
                            command.operation_id,
                            code=compilation.code,
                            message=compilation.message,
                        ),
                        value=compilation.to_dict(),
                    )
                result = self.operation_runner.execute_batch(
                    compilation.batch,
                    cancellation=token,
                    snapshot_provider=current_batch_snapshot,
                    postcondition_observer=self.postcondition_observer,
                    before_execution=begin_batch,
                )
                result = replace(result, operation_id=command.operation_id)
                if operation_started:
                    try:
                        self.store.complete_operation(result)
                    except (StaleRevisionError, TypeError, ValueError) as error:
                        result = OperationResult.failed(
                            command.operation_id,
                            code="operation_state_completion_failed",
                            message=str(error),
                        )
                        self._abort_operation_safely(result)
                if result.ok:
                    self._promote_stock_lock_evidence(
                        compilation.batch.plans,
                        result,
                    )
                return result
            except Exception as error:
                result = OperationResult.failed(
                    command.operation_id,
                    code="operation_runner_error" if operation_started else "planner_error",
                    message=str(error),
                )
                if operation_started:
                    self._abort_operation_safely(result)
                return result
            finally:
                self._unregister_cancellation(command.operation_id)
        try:
            compilation = self.operation_planner.compile(command, snapshot)
        except Exception as error:
            self._unregister_cancellation(command.operation_id)
            if token.cancelled:
                return self._stopped_result(
                    command,
                    token,
                    cancelled_code="planning_cancelled",
                    cancelled_message="operation planning was cancelled",
                    timeout_message="operation planning timed out",
                )
            return OperationResult.failed(
                command.operation_id,
                code="planner_error",
                message=str(error),
            )
        if token.cancelled:
            self._unregister_cancellation(command.operation_id)
            return self._stopped_result(
                command,
                token,
                cancelled_code="planning_cancelled",
                cancelled_message="operation planning was cancelled",
                timeout_message="operation planning timed out",
            )
        if not compilation.ok or compilation.plan is None:
            self._unregister_cancellation(command.operation_id)
            return replace(
                OperationResult.failed(
                    command.operation_id,
                    code=compilation.code,
                    message=compilation.message,
                ),
                value=compilation.to_dict(),
            )
        planned = replace(
            command,
            target_serial=compilation.plan.target_serial,
            operation_plan=compilation.plan,
            destructive=compilation.destructive,
            requires_confirmation=compilation.requires_confirmation,
        )
        result = self._execute_process(planned, cancellation=token)
        if result.ok and compilation.plan.dry_run:
            return replace(
                result,
                code="dry_run_succeeded",
                message="dry run completed without launching a subprocess",
            )
        if result.ok:
            self._promote_stock_lock_evidence((compilation.plan,), result)
        return result

    def _prepare_root_module_updates(
        self,
        command: AppCommand,
        result: OperationResult,
        cancellation: CancellationToken,
    ) -> OperationResult:
        """Turn private device metadata into inspected opaque update artifacts."""

        if not result.ok:
            return result
        try:
            modules = parse_root_module_list(result.stdout)
        except RootingPlanningError as error:
            return OperationResult.failed(
                command.operation_id,
                code=error.code,
                message=str(error),
            )
        prepared = self.root_module_update_service.prepare(
            modules,
            cancellation,
            target_serial=cast(str, command.target_serial),
            progress=lambda phase, message, percent: self._publish_progress(
                command,
                phase,
                message,
                percent,
            ),
        )
        if prepared.status is ModuleUpdateStatus.CANCELLED:
            return self._stopped_result(
                command,
                cancellation,
                cancelled_code=prepared.code,
                cancelled_message=prepared.message,
                timeout_message="Module update check timed out.",
            )
        if not prepared.ok:
            return OperationResult.failed(
                command.operation_id,
                code=prepared.code,
                message=prepared.message,
            )
        return OperationResult.success(
            command.operation_id,
            code=prepared.code,
            message=prepared.message,
            value=prepared.to_public_dict(),
        )

    def _promote_stock_lock_evidence(
        self,
        plans: tuple[OperationPlan, ...],
        result: OperationResult,
    ) -> None:
        """Persist one-use relock eligibility only after a verified full stock flash."""

        if not result.ok or not plans:
            return
        snapshot = self.store.snapshot()
        firmware = snapshot.firmware
        flash_plan = snapshot.plan
        unsafe_options = {
            "disableVerity",
            "disableVerification",
            "disable_verity",
            "disable_verification",
            "force",
            "temporaryRoot",
            "temporary_root",
            "downgrade",
        }
        if (
            firmware.type.casefold() != "factory"
            or not firmware.verified
            or not firmware.processed
            or not firmware.hash
            or not firmware.build
            or flash_plan.mode.casefold() != "factory"
            or flash_plan.dry_run
            or flash_plan.options.get("slot") != "both"
            or "partitions" in flash_plan.options
            or any(flash_plan.options.get(option) is True for option in unsafe_options)
            or snapshot.last_result is None
            or snapshot.last_result.operation_id != result.operation_id
        ):
            return

        next_revision = snapshot.revision + 1
        evidence: list[BootloaderLockEvidence] = []
        try:
            for plan in plans:
                required = tuple(dict.fromkeys(plan.partitions))
                if (
                    plan.dry_run
                    or plan.firmware_hash.casefold() != firmware.hash.casefold()
                    or plan.fingerprint != flash_plan.fingerprint
                    or set(plan.slots) != {"a", "b"}
                    or "vbmeta" not in required
                    or not {"boot", "init_boot"}.intersection(required)
                    or not plan.target_serial
                    or not plan.expected_codename
                ):
                    return
                evidence.append(
                    BootloaderLockEvidence(
                        serial=plan.target_serial,
                        device_codename=plan.expected_codename,
                        firmware_hash=firmware.hash,
                        firmware_build=firmware.build,
                        flash_operation_id=result.operation_id,
                        flash_plan_fingerprint=flash_plan.fingerprint,
                        snapshot_revision=next_revision,
                        required_partitions=required,
                        flashed_partitions=required,
                        slots=("a", "b"),
                    )
                )
            self.store.update(
                expected_revision=snapshot.revision,
                bootloader_lock_evidence=tuple(evidence),
            )
        except (StaleRevisionError, TypeError, ValueError):
            # Relock eligibility is optional metadata. Any race or malformed
            # evidence fails closed without changing the verified flash result.
            return

    def _update_flash_plan(self, command: AppCommand) -> OperationResult:
        snapshot = self.store.snapshot()
        mode: object = command.payload.get("mode", snapshot.plan.mode)
        raw_options: object = command.payload.get("options", snapshot.plan.options)
        dry_run: object = command.payload.get("dryRun", snapshot.plan.dry_run)
        if not isinstance(mode, str) or not mode:
            return self._invalid(command, "payload.mode must be a non-empty string")
        if not isinstance(raw_options, Mapping):
            return self._invalid(command, "payload.options must be an object")
        raw_option_mapping = cast(Mapping[object, object], raw_options)
        if any(not isinstance(key, str) for key in raw_option_mapping):
            return self._invalid(command, "payload.options keys must be strings")
        options: dict[str, object] = {key: value for key, value in raw_option_mapping.items() if isinstance(key, str)}
        if "images" in options:
            return OperationResult.failed(
                command.operation_id,
                code="untrusted_artifact_metadata",
                message="image paths and hashes are accepted only from the backend artifact repository",
            )
        option_dry_values = [options.pop(key) for key in ("dryRun", "dry_run") if key in options]
        if option_dry_values:
            if any(not isinstance(value, bool) for value in option_dry_values):
                return self._invalid(command, "payload.options.dryRun must be a boolean")
            boolean_dry_values = [value for value in option_dry_values if isinstance(value, bool)]
            if len(set(boolean_dry_values)) > 1:
                return self._invalid(command, "payload.options dryRun aliases disagree")
            option_dry_run = boolean_dry_values[0]
            if "dryRun" in command.payload and dry_run != option_dry_run:
                return self._invalid(command, "payload dryRun fields disagree")
            dry_run = option_dry_run
        if not isinstance(dry_run, bool):
            return self._invalid(command, "payload.dryRun must be a boolean")
        if mode.strip().casefold() in {"dryrun", "dry-run", "dry_run"}:
            mode = "images"
            dry_run = True
        try:
            draft = FlashPlan(mode, options, dry_run=dry_run)
        except (TypeError, ValueError) as error:
            return self._invalid(command, str(error))
        encoded = json.dumps(
            {
                "mode": draft.mode,
                "options": draft.to_dict()["options"],
                "dry_run": draft.dry_run,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        try:
            plan = FlashPlan(
                mode,
                options,
                revision=snapshot.plan.revision + 1,
                fingerprint=hashlib.sha256(encoded).hexdigest(),
                dry_run=dry_run,
            )
        except (TypeError, ValueError) as error:
            return self._invalid(command, str(error))
        return self._update_state(command, plan=plan)

    def _update_state(self, command: AppCommand, **changes: object) -> OperationResult:
        decision = self.safety_policy.evaluate(command, self.store.snapshot())
        if not decision.allowed:
            return self._denied(command, decision.code, decision.message)
        try:
            snapshot = self.store.update(
                expected_revision=command.expected_revision,
                **changes,
            )
        except StaleRevisionError as error:
            return self._denied(command, "stale_revision", str(error))
        except (TypeError, ValueError) as error:
            return self._invalid(command, str(error))
        return OperationResult.success(
            command.operation_id,
            code="state_updated",
            value=snapshot.to_dict(),
        )

    def _execute_process(
        self,
        command: AppCommand,
        result_parser: ResultParser | None = None,
        *,
        result_finalizer: ResultFinalizer | None = None,
        completion_boot: CompletionBoot | None = None,
        cancellation: CancellationToken | None = None,
        operation_executor: OperationExecutor | None = None,
        cancellation_cleanup: CancellationCleanup | None = None,
        execution_preflight: ExecutionPreflight | None = None,
        request_start_index: int = 0,
    ) -> OperationResult:
        assert command.operation_plan is not None
        token = cancellation
        if token is None:
            token = self._register_cancellation(command)
            if token is None:
                return self._denied(
                    command,
                    "operation_busy",
                    "operation id is already active",
                )
        else:
            with self._cancellation_lock:
                registered = self._cancellations.get(command.operation_id)
                if registered is None:
                    self._cancellations[command.operation_id] = token
                elif registered is not token:
                    return self._denied(
                        command,
                        "operation_busy",
                        "operation id is already active",
                    )

        def finalize(result: OperationResult) -> OperationResult:
            # Domain finalization is executed inside OperationRunner after the
            # typed process result and before postcondition verification. This
            # local identity keeps early lifecycle exits free of domain side effects.
            return result

        def stopped_before_execution(message: str) -> OperationResult:
            if token.reason is CancellationReason.DEADLINE:
                return OperationResult.failed(
                    command.operation_id,
                    code="timed_out",
                    message=message,
                )
            return OperationResult.cancelled(
                command.operation_id,
                code="cancelled",
                message=message,
            )

        operation_started = False

        def begin_at_validated_boundary(
            boundary_command: AppCommand,
            boundary_plan: OperationPlan,
            snapshot: AppSnapshot,
        ) -> ExecutionBoundaryAck:
            """Open lifecycle state only after the runner's final revalidation."""

            nonlocal operation_started
            issue = self.operation_planner.revalidate(boundary_plan, snapshot)
            if issue is not None:
                return ExecutionBoundaryAck.rejected(issue[0], issue[1])
            if execution_preflight is not None:
                try:
                    preflight = execution_preflight(
                        boundary_command,
                        boundary_plan,
                        snapshot,
                        token,
                    )
                except Exception:
                    return ExecutionBoundaryAck.rejected(
                        "execution_preflight_failed",
                        "execution preflight failed before mutation",
                    )
                if not isinstance(preflight, ExecutionBoundaryAck):
                    return ExecutionBoundaryAck.rejected(
                        "execution_preflight_invalid",
                        "execution preflight returned an invalid acknowledgement",
                    )
                if not preflight.allowed:
                    return preflight
            try:
                self.store.begin_operation(
                    boundary_command.operation_id,
                    expected_revision=snapshot.revision,
                    kind=str(boundary_command.kind),
                    label=boundary_plan.label,
                    target_serial=boundary_plan.target_serial,
                )
            except StaleRevisionError as error:
                return ExecutionBoundaryAck.rejected("stale_revision", str(error))
            except ValueError as error:
                return ExecutionBoundaryAck.rejected("operation_busy", str(error))
            operation_started = True
            return ExecutionBoundaryAck.accepted()

        try:
            with self._operation_guard(token) as acquired:
                if not acquired:
                    return finalize(stopped_before_execution("operation stopped while queued"))
                if token.cancelled:
                    return finalize(stopped_before_execution("operation stopped before execution"))
                snapshot = self.store.snapshot()
                decision = self.safety_policy.evaluate(command, snapshot)
                if not decision.allowed:
                    return finalize(self._denied(command, decision.code, decision.message))

                if decision.interaction is not None:
                    try:
                        interaction = replace(
                            decision.interaction,
                            _timeout_seconds=token.remaining_seconds,
                        )
                        response = self.interaction_handler(interaction)
                    except InteractionTimeoutError:
                        if token.reason is CancellationReason.DEADLINE:
                            return finalize(
                                stopped_before_execution("operation deadline expired while awaiting confirmation")
                            )
                        return finalize(
                            OperationResult.failed(
                                command.operation_id,
                                code="interaction_timed_out",
                                message="confirmation response timed out",
                            )
                        )
                    except Exception as error:
                        if token.cancelled:
                            return finalize(stopped_before_execution("operation stopped while awaiting confirmation"))
                        return finalize(
                            OperationResult.failed(
                                command.operation_id,
                                code="interaction_error",
                                message=str(error),
                            )
                        )
                    accepted = response is True or response is InteractionDecision.ACCEPTED
                    if not accepted:
                        if token.reason is CancellationReason.DEADLINE:
                            return finalize(
                                stopped_before_execution("operation deadline expired while awaiting confirmation")
                            )
                        return finalize(
                            OperationResult.cancelled(
                                command.operation_id,
                                code="user_cancelled",
                                message="operation was not confirmed",
                            )
                        )
                    if token.cancelled:
                        return finalize(stopped_before_execution("operation stopped while awaiting confirmation"))
                    # A prompt may take an arbitrary amount of time. Validate the
                    # revision and serial again before crossing the process boundary.
                    snapshot = self.store.snapshot()
                    decision = self.safety_policy.evaluate(command, snapshot)
                    if not decision.allowed:
                        return finalize(self._denied(command, decision.code, decision.message))

                issue = self.operation_planner.revalidate(command.operation_plan, snapshot)
                if issue is not None:
                    return finalize(self._denied(command, issue[0], issue[1]))
                if token.cancelled:
                    return finalize(stopped_before_execution("operation stopped before execution"))

                result = self.operation_runner.execute(
                    command,
                    command.operation_plan,
                    snapshot,
                    cancellation=token,
                    snapshot_provider=self.snapshot_provider,
                    postcondition_observer=self.postcondition_observer,
                    operation_executor=operation_executor,
                    result_transformer=result_finalizer,
                    cancellation_cleanup=cancellation_cleanup,
                    before_execution=begin_at_validated_boundary,
                    request_start_index=request_start_index,
                )
                if result.ok and result_parser is not None:
                    try:
                        result = result_parser(result)
                    except Exception as error:
                        result = OperationResult.failed(
                            command.operation_id,
                            code="result_parse_failed",
                            message=str(error),
                            exit_code=result.exit_code,
                            stdout=result.stdout,
                            stderr=result.stderr,
                        )
                result = finalize(result)
                promoted_boot: BootInfo | None = None
                if result.ok and completion_boot is not None:
                    try:
                        promoted_boot = completion_boot(result)
                    except Exception as error:
                        result = OperationResult.failed(
                            command.operation_id,
                            code="completion_state_invalid",
                            message=str(error),
                            exit_code=result.exit_code,
                            stdout=result.stdout,
                            stderr=result.stderr,
                        )
                if command.kind == "tools.pushFiles":
                    phase = (
                        ProgressPhase.COMPLETED
                        if result.ok
                        else ProgressPhase.CANCELLED
                        if result.status is OperationStatus.CANCELLED
                        else ProgressPhase.FAILED
                    )
                    total = len(command.operation_plan.requests)
                    self._publish_progress(
                        command,
                        phase,
                        result.message or "file transfer finished",
                        100 if result.ok else None,
                        current=(total if result.ok else None),
                        total=(total if result.ok else None),
                        item=(
                            command.operation_plan.requests[-1].argv[-1].rsplit("/", 1)[-1]
                            if result.ok and total
                            else None
                        ),
                    )
                if operation_started:
                    try:
                        # LAN announcements are ephemeral, unauthenticated UI
                        # suggestions. Return them only to the correlated bridge
                        # request; never retain them in AppSnapshot or support data.
                        stored_result = (
                            replace(result, value=None, stdout="", stderr="")
                            if command.kind
                            in {
                                "tools.logcat",
                                "tools.logcat.clear",
                                "tools.wifi.discover",
                            }
                            else result
                        )
                        self.store.complete_operation(stored_result, boot=promoted_boot)
                    except (StaleRevisionError, TypeError, ValueError) as error:
                        fallback = OperationResult.failed(
                            command.operation_id,
                            code="operation_state_completion_failed",
                            message=str(error),
                        )
                        if command.kind == "tools.pushFiles":
                            self._publish_progress(
                                command,
                                ProgressPhase.FAILED,
                                fallback.message,
                                None,
                            )
                        self._abort_operation_safely(fallback)
                        return fallback
                return result
        finally:
            self._unregister_cancellation(command.operation_id)

    def _register_cancellation(self, command: AppCommand) -> CancellationToken | None:
        token = command.cancellation_token
        with self._cancellation_lock:
            if command.operation_id in self._cancellations:
                return None
            self._cancellations[command.operation_id] = token
        return token

    def _acquire_operation_lock(self, token: CancellationToken) -> bool:
        """Wait for the serialized boundary without ignoring stop requests."""

        while not token.cancelled:
            remaining = token.remaining_seconds
            if remaining is not None and remaining <= 0:
                return False
            wait_seconds = 0.05 if remaining is None else min(0.05, remaining)
            if self._operation_lock.acquire(timeout=wait_seconds):
                return True
        return False

    @contextmanager
    def _operation_guard(self, token: CancellationToken) -> Generator[bool]:
        acquired = self._acquire_operation_lock(token)
        try:
            yield acquired
        finally:
            if acquired:
                self._operation_lock.release()

    @staticmethod
    def _stopped_result(
        command: AppCommand,
        token: CancellationToken,
        *,
        cancelled_code: str,
        cancelled_message: str,
        timeout_message: str | None = None,
    ) -> OperationResult:
        if token.reason is CancellationReason.DEADLINE:
            return OperationResult.failed(
                command.operation_id,
                code="timed_out",
                message=timeout_message or "operation deadline expired",
            )
        return OperationResult.cancelled(
            command.operation_id,
            code=cancelled_code,
            message=cancelled_message,
        )

    def _abort_operation_safely(self, result: OperationResult) -> None:
        """Never let a completion failure strand the canonical operation slot."""

        try:
            self.store.abort_operation(result)
        except Exception:
            # The original typed completion failure remains the public result.
            # AppStateStore.abort_operation has no I/O and normally cannot fail;
            # this guard preserves the engine's no-exception public boundary.
            pass

    def _unregister_cancellation(self, operation_id: str) -> None:
        with self._cancellation_lock:
            self._cancellations.pop(operation_id, None)

    @staticmethod
    def _boot_info_from_patch_result(result: OperationResult) -> BootInfo:
        """Recover the typed canonical boot state from a verified patch result."""

        raw_result_value: object = result.value
        if not result.ok or not isinstance(raw_result_value, Mapping):
            raise ValueError("successful boot patch result is missing state")
        result_value = cast(Mapping[object, object], raw_result_value)
        raw_boot: object = result_value.get("boot")
        raw_patched: object = result_value.get("patchedBoot")
        if not isinstance(raw_boot, Mapping) or not isinstance(raw_patched, Mapping):
            raise ValueError("successful boot patch result is missing boot metadata")
        boot_mapping = cast(Mapping[object, object], raw_boot)
        patched_mapping = cast(Mapping[object, object], raw_patched)
        raw_artifact: object = patched_mapping.get("artifact")
        if not isinstance(raw_artifact, Mapping):
            raise ValueError("successful boot patch result is missing its artifact")
        artifact_mapping = cast(Mapping[object, object], raw_artifact)

        boot_id: object = boot_mapping.get("id")
        path: object = boot_mapping.get("path")
        digest: object = boot_mapping.get("hash")
        partition: object = boot_mapping.get("flavor")
        patched: object = boot_mapping.get("patched")
        if (
            not isinstance(boot_id, str)
            or not boot_id
            or not isinstance(path, str)
            or not path
            or not isinstance(digest, str)
            or not digest
            or not isinstance(partition, str)
            or not partition
        ):
            raise ValueError("successful boot patch result contains invalid boot fields")
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest.casefold())
            or patched is not True
        ):
            raise ValueError("successful boot patch result contains invalid boot identity")
        if partition not in {"boot", "init_boot"}:
            raise ValueError("successful boot patch result contains an invalid partition")
        if artifact_mapping.get("path") != path or artifact_mapping.get("sha256") != digest:
            raise ValueError("boot state does not match the verified patch artifact")
        return BootInfo(boot_id, path, digest.casefold(), partition, True)

    @staticmethod
    def _invalid(command: AppCommand, message: str) -> OperationResult:
        return OperationResult.failed(
            command.operation_id,
            code="invalid_command",
            message=message,
        )

    @staticmethod
    def _denied(command: AppCommand, code: str, message: str) -> OperationResult:
        return OperationResult.failed(command.operation_id, code=code, message=message)


class PixelFlasherEngine:
    """Public, synchronous application-engine facade.

    ``CommandEngine`` owns command compilation and process execution.  This
    facade is the only boundary exposed to UI hosts: it adds canonical state,
    event subscription, cancellation, interaction response, and lifecycle
    methods while guaranteeing an explicit :class:`OperationResult`.
    """

    def __init__(
        self,
        command_engine: CommandEngine,
        *,
        command_handler: CommandHandler | None = None,
        event_subscriber: EngineSubscriber | None = None,
        event_publisher: EnginePublisher | None = None,
        cancellation_handler: CancellationHandler | None = None,
        interaction_responder: InteractionResponder | None = None,
        shutdown_handler: ShutdownHandler | None = None,
    ) -> None:
        self._listener_lock = threading.RLock()
        self._lifecycle_lock = threading.RLock()
        self._listeners: dict[str, EngineListener] = {}
        self._shutdown = False
        self._owned_state_subscription: Subscription | None = None
        self._snapshot_provider = command_engine.store.snapshot

        if (event_subscriber is None) != (event_publisher is None):
            raise ValueError("event_subscriber and event_publisher must be provided together")
        if event_subscriber is None or event_publisher is None:
            event_subscriber = self._subscribe_local
            event_publisher = self._publish_local
            self._owned_state_subscription = command_engine.store.subscribe(self._publish_snapshot)

        self._command_handler = command_handler or command_engine.execute
        self._event_subscriber = event_subscriber
        self._event_publisher = event_publisher
        if cancellation_handler is None:

            def cancel_command(operation_id: str) -> CommandAck:
                return self._cancellation_ack(command_engine.cancel(operation_id))

            self._cancellation_handler = cancel_command
        else:
            self._cancellation_handler = cancellation_handler
        self._interaction_responder = interaction_responder
        self._shutdown_handler = shutdown_handler or command_engine.shutdown

    def snapshot(self) -> AppSnapshot:
        return self._snapshot_provider()

    def subscribe(
        self,
        listener: EngineListener,
        *,
        emit_current: bool = False,
    ) -> Callable[[], None]:
        return self._event_subscriber(listener, emit_current)

    def execute(self, command: AppCommand) -> OperationResult:
        """Execute synchronously and always return a typed terminal result."""

        with self._lifecycle_lock:
            if self._shutdown:
                result = OperationResult.failed(
                    command.operation_id,
                    code="engine_shutdown",
                    message="the application engine has shut down",
                )
                self._event_publisher(OperationFinished(result))
                return result
        try:
            result = self._command_handler(command)
        except Exception:
            result = OperationResult.failed(
                command.operation_id,
                code="engine_error",
                message="The command could not be completed.",
            )
        if not isinstance(result, OperationResult):
            result = OperationResult.failed(
                command.operation_id,
                code="invalid_engine_result",
                message="the command engine returned an invalid result",
            )
        self._event_publisher(OperationFinished(result))
        return result

    def cancel(self, operation_id: str) -> CommandAck:
        if not isinstance(operation_id, str) or not operation_id:
            return CommandAck(False, "invalid_operation_id", "Operation ID is required.")
        with self._lifecycle_lock:
            if self._shutdown:
                return CommandAck(False, "engine_shutdown", "The engine has shut down.")
        acknowledgement = self._cancellation_handler(operation_id)
        if not isinstance(acknowledgement, CommandAck):
            return CommandAck(
                False,
                "invalid_cancellation_ack",
                "The cancellation handler returned an invalid acknowledgement.",
            )
        return acknowledgement

    def respond_interaction(
        self,
        request_id: str,
        response: InteractionResponse,
    ) -> CommandAck:
        if not isinstance(request_id, str) or not request_id:
            return CommandAck(False, "invalid_request_id", "Request ID is required.")
        if not isinstance(response, InteractionResponse):
            return CommandAck(
                False,
                "invalid_interaction_response",
                "A typed interaction response is required.",
            )
        if self._interaction_responder is None:
            return CommandAck(
                False,
                "interaction_unsupported",
                "No interaction responder is available.",
            )
        with self._lifecycle_lock:
            if self._shutdown:
                return CommandAck(False, "engine_shutdown", "The engine has shut down.")
        acknowledgement = self._interaction_responder(request_id, response)
        if not isinstance(acknowledgement, CommandAck):
            return CommandAck(
                False,
                "invalid_interaction_ack",
                "The interaction responder returned an invalid acknowledgement.",
            )
        return acknowledgement

    def shutdown(self) -> None:
        with self._lifecycle_lock:
            if self._shutdown:
                return
            self._shutdown = True
        try:
            self._shutdown_handler()
        finally:
            if self._owned_state_subscription is not None:
                self._owned_state_subscription.cancel()

    def _subscribe_local(
        self,
        listener: EngineListener,
        emit_current: bool = False,
    ) -> Callable[[], None]:
        listener_id = uuid4().hex
        with self._listener_lock:
            self._listeners[listener_id] = listener
            current = self._snapshot_provider()
        if emit_current:
            listener(SnapshotChanged(current))

        def cancel() -> None:
            with self._listener_lock:
                self._listeners.pop(listener_id, None)

        return Subscription(cancel)

    def _publish_snapshot(self, snapshot: AppSnapshot) -> None:
        self._publish_local(SnapshotChanged(snapshot))

    def _publish_local(self, event: AppEvent) -> None:
        with self._listener_lock:
            listeners = tuple(self._listeners.values())
        for listener in listeners:
            try:
                listener(event)
            except Exception:
                continue

    @staticmethod
    def _cancellation_ack(accepted: bool) -> CommandAck:
        if accepted:
            return CommandAck(True, "cancellation_requested", "Cancellation requested.")
        return CommandAck(False, "operation_not_active", "Operation is not active.")
