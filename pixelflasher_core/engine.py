"""Synchronous command boundary for the UI-independent application core."""

from __future__ import annotations

import hashlib
import json
import tempfile
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path

from .backups import (
    BACKUP_COMMANDS,
    BackupCompilation,
    BackupPlanningError,
    BackupService,
)
from .boot_patch import (
    BOOT_PATCH_COMMAND,
    BootPatchCompilation,
    BootPatchPlanningError,
    BootPatchService,
    PatchToolBundle,
)
from .contracts import (
    AppCommand,
    AppSnapshot,
    BootInfo,
    CommandKind,
    FileArtifact,
    FirmwareInfo,
    FlashPlan,
    InteractionDecision,
    InteractionRequest,
    OperationPlan,
    OperationResult,
)
from .devices import DeviceService
from .device_tools import (
    DEVICE_TOOL_COMMANDS,
    DeviceToolCompilation,
    DeviceToolPlanningError,
    DeviceToolsService,
)
from .executor import CancellationToken, CommandExecutor
from .firmware import FirmwareInspector
from .firmware_artifacts import (
    FirmwareArtifactService,
    FirmwareProcessingResult,
    FirmwareProcessingStatus,
)
from .packages import (
    PACKAGE_COMMANDS,
    PackageCompilation,
    PackagePlanningError,
    PackageService,
    parse_package_list,
)
from .partitions import (
    PARTITION_COMMANDS,
    PartitionCompilation,
    PartitionPlanningError,
    PartitionService,
    parse_fastboot_partition_list,
)
from .planner import PLANNED_COMMANDS, OperationPlanner
from .rooting import (
    ROOTING_COMMANDS,
    RootingCompilation,
    RootingPlanningError,
    RootingService,
    parse_root_module_list,
)
from .safety import SafetyPolicy
from .store import AppStateStore, StaleRevisionError
from .support import (
    SUPPORT_COMMAND,
    SupportPackageService,
    SupportPackageStatus,
)
from .toolchain import ToolchainService


InteractionHandler = Callable[[InteractionRequest], InteractionDecision | bool]
ResultParser = Callable[[OperationResult], OperationResult]
ResultFinalizer = Callable[[OperationResult, CancellationToken], OperationResult]
CompletionBoot = Callable[[OperationResult], BootInfo | None]
OperationExecutor = Callable[
    [AppCommand, OperationPlan, CancellationToken],
    OperationResult,
]

_SERVICE_COMMANDS = (
    PACKAGE_COMMANDS
    | PARTITION_COMMANDS
    | DEVICE_TOOL_COMMANDS
    | BACKUP_COMMANDS
    | ROOTING_COMMANDS
    | frozenset({BOOT_PATCH_COMMAND})
)
_ServiceCompilation = (
    PackageCompilation
    | PartitionCompilation
    | DeviceToolCompilation
    | BackupCompilation
    | RootingCompilation
    | BootPatchCompilation
)


def deny_interaction(_request: InteractionRequest) -> InteractionDecision:
    """Safe default for a headless process with no confirmation channel."""

    return InteractionDecision.CANCELLED


class PixelFlasherEngine:
    """Execute one typed command and synchronously return one explicit result."""

    def __init__(
        self,
        store: AppStateStore | None = None,
        executor: CommandExecutor | None = None,
        safety_policy: SafetyPolicy | None = None,
        interaction_handler: InteractionHandler | None = None,
        toolchain_service: ToolchainService | None = None,
        device_service: DeviceService | None = None,
        firmware_inspector: FirmwareInspector | None = None,
        operation_planner: OperationPlanner | None = None,
        package_service: PackageService | None = None,
        partition_service: PartitionService | None = None,
        device_tools_service: DeviceToolsService | None = None,
        backup_service: BackupService | None = None,
        rooting_service: RootingService | None = None,
        boot_patch_bundles: Sequence[PatchToolBundle] = (),
        firmware_artifact_service: FirmwareArtifactService | None = None,
        firmware_artifact_cache_root: str | Path | None = None,
        support_package_service: SupportPackageService | None = None,
        support_config_path: str | Path | None = None,
    ) -> None:
        self.store = store or AppStateStore()
        self.executor = executor or CommandExecutor()
        self.safety_policy = safety_policy or SafetyPolicy()
        self.interaction_handler = interaction_handler or deny_interaction
        self.toolchain_service = toolchain_service or ToolchainService(self.executor.transport)
        self.device_service = device_service or DeviceService(self.executor.transport)
        self.firmware_inspector = firmware_inspector or FirmwareInspector()
        self.operation_planner = operation_planner or OperationPlanner()
        if firmware_artifact_service is not None and (
            firmware_artifact_service.repository
            is not self.operation_planner.artifact_repository
        ):
            raise ValueError(
                "firmware artifact service and operation planner must share one repository"
            )
        if firmware_artifact_service is None:
            cache_root = (
                Path(firmware_artifact_cache_root)
                if firmware_artifact_cache_root is not None
                else Path(tempfile.gettempdir())
                / "pixelflasher-core"
                / "firmware-artifacts"
            )
            firmware_artifact_service = FirmwareArtifactService(
                self.operation_planner.artifact_repository,
                cache_root,
            )
        self.firmware_artifact_service = firmware_artifact_service
        self.package_service = package_service or PackageService()
        self.partition_service = partition_service or PartitionService()
        self.device_tools_service = device_tools_service or DeviceToolsService()
        self.backup_service = backup_service or BackupService()
        self.rooting_service = rooting_service or RootingService()
        self.support_package_service = support_package_service or SupportPackageService(
            support_config_path
            if support_config_path is not None
            else Path(tempfile.gettempdir()) / "pixelflasher-core" / "PixelFlasher.json"
        )
        # Patch tooling is a backend-owned dependency.  Browser commands can
        # select only a verified app ID and flavor; they can never register a
        # runner path, hash, or support artifact.
        self.boot_patch_service = BootPatchService(
            self.rooting_service,
            boot_patch_bundles,
        )
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
        if command.kind == CommandKind.DEVICE_SCAN.value:
            # Compatibility for milestone-1 callers that inject an already
            # reviewed plan. Browser commands never provide operation plans.
            if command.operation_plan is not None:
                return self._execute_process(command)
            return self._scan_devices(command)
        if command.kind == CommandKind.FIRMWARE_SELECT.value:
            return self._inspect_firmware(command)
        if command.kind == "firmware.process":
            return self._process_firmware(command)
        if command.kind == SUPPORT_COMMAND:
            return self._create_support_package(command)
        if command.kind == CommandKind.FLASH_PLAN_UPDATE.value:
            return self._update_flash_plan(command)
        if command.kind == "flash.plan.preview":
            return self._preview_flash_plan(command)
        return OperationResult.failed(
            command.operation_id,
            code="not_implemented",
            message=f"unsupported command kind: {command.kind}",
        )

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
                (
                    f"state revision changed: expected {command.expected_revision}, "
                    f"current {snapshot.revision}"
                ),
            )

        planning_token: CancellationToken | None = None
        if command.kind == BOOT_PATCH_COMMAND:
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
                )
            elif command.kind in PARTITION_COMMANDS:
                partition_command = command
                if command.kind == "partitions.erase" and "confirmationText" in command.payload:
                    partition_command = replace(
                        command,
                        payload={
                            key: value
                            for key, value in command.payload.items()
                            if key != "confirmationText"
                        },
                    )
                compilation = self.partition_service.compile(partition_command, snapshot)
            elif command.kind in BACKUP_COMMANDS:
                compilation = self.backup_service.compile(command, snapshot)
            elif command.kind in ROOTING_COMMANDS:
                compilation = self.rooting_service.compile(command, snapshot)
            else:
                compilation = self.device_tools_service.compile(command, snapshot)
        except BootPatchPlanningError as error:
            if planning_token is not None:
                self._unregister_cancellation(command.operation_id)
            if error.code == "boot_patch_cancelled":
                return OperationResult.cancelled(
                    command.operation_id,
                    code=error.code,
                    message=str(error),
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
            BackupPlanningError,
            RootingPlanningError,
        ) as error:
            if planning_token is not None:
                self._unregister_cancellation(command.operation_id)
            return OperationResult.failed(
                command.operation_id,
                code=error.code,
                message=str(error),
            )
        except Exception as error:
            if planning_token is not None:
                self._unregister_cancellation(command.operation_id)
            return OperationResult.failed(
                command.operation_id,
                code="service_planning_error",
                message=str(error),
            )

        if compilation.plan is None:
            if planning_token is not None:
                self._unregister_cancellation(command.operation_id)
            if command.kind != "root.apps.list" or not isinstance(
                compilation,
                RootingCompilation,
            ):
                return OperationResult.failed(
                    command.operation_id,
                    code="service_plan_missing",
                    message=f"{command.kind} did not produce an executable plan",
                )
            current = self.store.snapshot()
            if current.revision != snapshot.revision:
                return self._denied(
                    command,
                    "stale_revision",
                    (
                        f"state revision changed: expected {snapshot.revision}, "
                        f"current {current.revision}"
                    ),
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
            self.store.complete_operation(result)
            return result

        execution_plan = compilation.plan
        if (
            isinstance(compilation, PartitionCompilation)
            and compilation.reinforced_confirmation
        ):
            reinforced = self.operation_planner.bind_reinforced_confirmation(
                command,
                snapshot,
                execution_plan,
                destructive=compilation.destructive,
                requires_confirmation=compilation.requires_confirmation,
            )
            if not reinforced.ok or reinforced.plan is None:
                return replace(
                    OperationResult.failed(
                        command.operation_id,
                        code=reinforced.code,
                        message=reinforced.message,
                    ),
                    value=reinforced.to_dict(),
                )
            execution_plan = reinforced.plan

        planned = replace(
            command,
            target_serial=execution_plan.target_serial,
            operation_plan=execution_plan,
            destructive=compilation.destructive,
            requires_confirmation=compilation.requires_confirmation,
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
                result_finalizer=lambda result, cancellation: (
                    self.boot_patch_service.finalize_result(
                        compilation,
                        result,
                        cancellation,
                    )
                ),
                completion_boot=self._boot_info_from_patch_result,
                cancellation=planning_token,
            )
        if (
            isinstance(compilation, DeviceToolCompilation)
            and compilation.execution != "process"
        ):
            return self._execute_process(
                planned,
                operation_executor=(
                    lambda _command, _plan, cancellation: (
                        self.device_tools_service.execute_special(
                            compilation,
                            command.operation_id,
                            cancellation,
                        )
                    )
                ),
            )
        if (
            isinstance(compilation, DeviceToolCompilation)
            and compilation.action.startswith("wifi.")
        ):
            return self._execute_process(
                planned,
                result_finalizer=(
                    lambda result, _cancellation: (
                        self.device_tools_service.finalize_result(
                            compilation,
                            result,
                        )
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
        )

    def _parse_service_result(
        self,
        kind: str,
        compilation: _ServiceCompilation,
        result: OperationResult,
    ) -> OperationResult:
        """Convert successful process output into bridge-safe domain values."""

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
        if kind == "tools.logcat":
            lines = result.stdout.splitlines()
            return replace(
                result,
                code="logcat_collected",
                message=f"collected {len(lines)} log line(s)",
                value={
                    "lineCount": len(lines),
                    "lines": lines,
                    "text": result.stdout,
                },
            )
        if kind == "tools.pushFiles":
            files = [
                {
                    "source": artifact.path,
                    "destination": request.argv[-1],
                    "sha256": artifact.sha256,
                }
                for artifact, request in zip(
                    compilation.plan.artifacts,
                    compilation.plan.requests,
                    strict=True,
                )
            ]
            return replace(
                result,
                code="files_pushed",
                message=f"pushed {len(files)} file(s)",
                value={
                    "count": len(files),
                    "files": files,
                    "outputLines": result.stdout.splitlines(),
                },
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
            return replace(
                result,
                code="backup_created",
                message=f"created and verified backup of {compilation.plan.partitions[0]}",
                value={
                    "action": "create",
                    "targetSerial": compilation.plan.target_serial,
                    "partition": compilation.plan.partitions[0],
                    "slot": compilation.plan.slots[0],
                    "artifact": artifact.to_dict(),
                },
            )
        if kind == "backups.restore":
            if not isinstance(compilation, BackupCompilation) or not compilation.plan.artifacts:
                return OperationResult.failed(
                    result.operation_id,
                    code="backup_compilation_invalid",
                    message="backup restore has no verified source artifact",
                    exit_code=result.exit_code,
                    stdout=result.stdout,
                    stderr=result.stderr,
                )
            artifact = compilation.plan.artifacts[0]
            return replace(
                result,
                code="backup_restored",
                message=f"restored {compilation.plan.partitions[0]}",
                value={
                    "action": "restore",
                    "targetSerial": compilation.plan.target_serial,
                    "partition": compilation.plan.partitions[0],
                    "slot": compilation.plan.slots[0],
                    "artifact": artifact.to_dict(),
                },
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
                    "targetSerial": compilation.plan.target_serial,
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
            artifact = (
                compilation.plan.artifacts[0].to_dict()
                if compilation.plan.artifacts
                else None
            )
            return replace(
                result,
                code=result_code,
                message=f"{action} Magisk module {compilation.module_id}",
                value={
                    "action": action,
                    "targetSerial": compilation.plan.target_serial,
                    "moduleId": compilation.module_id,
                    "artifact": artifact,
                },
            )
        return replace(
            result,
            code=f"{kind.replace('.', '_')}_succeeded",
            value={
                "action": compilation.action,
                "targetSerial": compilation.plan.target_serial,
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
        serial = command.payload.get("serial")
        if serial is not None and not isinstance(serial, str):
            return self._invalid(command, "payload.serial must be a string or null")
        if isinstance(serial, str) and not serial.strip():
            return self._invalid(command, "payload.serial must not be blank")
        raw_serials = command.payload.get("serials")
        if raw_serials is None:
            serials = (serial,) if serial else ()
        elif isinstance(raw_serials, (list, tuple)) and all(
            isinstance(item, str) and item.strip() for item in raw_serials
        ):
            serials = tuple(dict.fromkeys(item.strip() for item in raw_serials))
        else:
            return self._invalid(command, "payload.serials must be an array of strings")
        serials = tuple(dict.fromkeys(item.strip() for item in serials if item.strip()))
        primary = serial.strip() if isinstance(serial, str) and serial.strip() else (
            serials[0] if serials else None
        )
        inventory = {device.serial for device in self.store.snapshot().devices}
        desired = tuple(dict.fromkeys(((primary,) if primary else ()) + serials))
        missing = tuple(item for item in desired if inventory and item not in inventory)
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

    def _inspect_firmware(
        self,
        command: AppCommand,
    ) -> OperationResult:
        unknown = set(command.payload) - {"path"}
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
            try:
                inspection = self.firmware_inspector.inspect(
                    path,
                    expected_devices=expected_devices,
                    cancellation=token,
                )
            except Exception as error:
                return OperationResult.failed(
                    command.operation_id,
                    code="firmware_inspection_failed",
                    message=str(error),
                )
        finally:
            self._unregister_cancellation(command.operation_id)
        if inspection.code == "firmware_cancelled":
            return OperationResult.cancelled(
                command.operation_id,
                code="firmware_cancelled",
                message=inspection.message,
            )
        if not inspection.ok:
            return OperationResult.failed(
                command.operation_id,
                code=inspection.code,
                message=inspection.message,
            )
        result = self._update_state(
            command,
            firmware=inspection.to_firmware_info(processed=False),
            # A boot image belongs to one exact firmware hash. Selecting a new
            # package invalidates any previously promoted stock or patched boot.
            boot=BootInfo(),
        )
        if not result.ok:
            return result
        return replace(
            result,
            code="firmware_selected",
            message=f"{inspection.kind.value} firmware inspected successfully",
            value={"snapshot": self.store.snapshot().to_dict(), "inspection": inspection.to_dict()},
        )

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
            with self._operation_lock:
                if token.cancelled:
                    return OperationResult.cancelled(
                        command.operation_id,
                        code="firmware_processing_cancelled",
                        message="firmware processing was cancelled before it started",
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
                try:
                    processing = self.firmware_artifact_service.process(
                        snapshot.firmware.path,
                        expected_devices=expected_devices,
                        cancellation=token,
                    )
                    if token.cancelled and processing.ok:
                        result = OperationResult.cancelled(
                            command.operation_id,
                            code="firmware_processing_cancelled",
                            message="firmware processing was cancelled before state promotion",
                        )
                        promoted_firmware = None
                        promoted_boot = None
                    else:
                        result, promoted_firmware, promoted_boot = (
                            self._firmware_processing_result(
                                command,
                                snapshot,
                                processing,
                            )
                        )
                except Exception as error:
                    processing = None
                    promoted_firmware = None
                    promoted_boot = None
                    result = OperationResult.failed(
                        command.operation_id,
                        code="firmware_processing_failed",
                        message=str(error),
                    )

                current = self.store.snapshot()
                if result.ok and token.cancelled:
                    promoted_firmware = None
                    promoted_boot = None
                    result = OperationResult.cancelled(
                        command.operation_id,
                        code="firmware_processing_cancelled",
                        message="firmware processing was cancelled before state promotion",
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
                    try:
                        self.store.complete_operation(fallback)
                    except (TypeError, ValueError):
                        pass
                    return fallback
                return result
        finally:
            self._unregister_cancellation(command.operation_id)

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
            with self._operation_lock:
                if token.cancelled:
                    return OperationResult.cancelled(
                        command.operation_id,
                        code="support_package_cancelled",
                        message="support package creation was cancelled before it started",
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

                package = self.support_package_service.create(
                    command.payload,
                    snapshot=snapshot,
                    cancellation=token,
                )
                if package.status is SupportPackageStatus.SUCCESS:
                    result = OperationResult.success(
                        command.operation_id,
                        code=package.code,
                        message=package.message,
                        value=package.to_dict(),
                    )
                elif package.status is SupportPackageStatus.CANCELLED:
                    result = OperationResult.cancelled(
                        command.operation_id,
                        code=package.code,
                        message=package.message,
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
                    return OperationResult.failed(
                        command.operation_id,
                        code="support_state_completion_failed",
                        message=str(error),
                    )
                return result
        finally:
            self._unregister_cancellation(command.operation_id)

    def _firmware_processing_result(
        self,
        command: AppCommand,
        selected_snapshot: AppSnapshot,
        processing: FirmwareProcessingResult,
    ) -> tuple[OperationResult, FirmwareInfo | None, BootInfo | None]:
        if processing.status is FirmwareProcessingStatus.CANCELLED:
            return (
                OperationResult.cancelled(
                    command.operation_id,
                    code=processing.code.value,
                    message=processing.message,
                ),
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
            )
        try:
            stock_boot = self._stock_boot_from_processing(processing)
        except ValueError as error:
            return (
                OperationResult.failed(
                    command.operation_id,
                    code="stock_boot_artifact_required",
                    message=str(error),
                ),
                None,
                None,
            )
        value = {
            "processing": processing.to_dict(),
            "firmware": processing.firmware.to_dict(),
            "boot": stock_boot.to_dict() if stock_boot is not None else None,
        }
        return (
            OperationResult.success(
                command.operation_id,
                code="firmware_processed",
                message=f"{processing.inspection.kind.value} firmware processed successfully",
                value=value,
            ),
            processing.firmware,
            stock_boot,
        )

    @staticmethod
    def _stock_boot_from_processing(
        processing: FirmwareProcessingResult,
    ) -> BootInfo | None:
        by_role = {artifact.role: artifact for artifact in processing.artifacts}
        artifact = by_role.get("partition:init_boot") or by_role.get("partition:boot")
        if artifact is None:
            # OTA packages are safely sideloaded as one verified source archive;
            # their payload is not partially unpacked by this service.
            if processing.inspection.kind.value == "ota":
                return None
            raise ValueError(
                "processed factory/custom firmware has no verified init_boot or boot image"
            )
        partition = artifact.role.partition(":")[2]
        return BootInfo(
            id=f"stock:{partition}:{artifact.sha256}",
            path=artifact.path,
            hash=artifact.sha256,
            flavor=partition,
            patched=False,
        )

    def _setup_platform_tools(self, command: AppCommand) -> OperationResult:
        if command.payload.get("download"):
            return OperationResult.failed(
                command.operation_id,
                code="network_setup_not_supported",
                message="automatic downloads are not available in this milestone",
            )
        path = command.payload.get("path", command.payload.get("platformToolsPath"))
        if path is not None and (not isinstance(path, str) or not path.strip()):
            return self._invalid(command, "payload.path must be a non-empty string")
        if isinstance(path, str):
            try:
                if not Path(path).expanduser().resolve().is_dir():
                    return OperationResult.failed(
                        command.operation_id,
                        code="toolchain_path_invalid",
                        message="platform-tools path must be an existing directory",
                    )
            except (OSError, ValueError) as error:
                return OperationResult.failed(
                    command.operation_id,
                    code="toolchain_path_invalid",
                    message=str(error),
                )
        decision = self.safety_policy.evaluate(command, self.store.snapshot())
        if not decision.allowed:
            return self._denied(command, decision.code, decision.message)
        token = self._register_cancellation(command)
        if token is None:
            return self._denied(command, "operation_busy", "operation id is already active")
        try:
            try:
                check = self.toolchain_service.discover(
                    path.strip() if isinstance(path, str) else None,
                    cancellation=token,
                )
            except Exception as error:
                return OperationResult.failed(
                    command.operation_id,
                    code="toolchain_setup_failed",
                    message=str(error),
                )
        finally:
            self._unregister_cancellation(command.operation_id)
        if check.code == "cancelled":
            return OperationResult.cancelled(
                command.operation_id,
                code="cancelled",
                message=check.message,
            )
        if not check.ok:
            return OperationResult.failed(
                command.operation_id,
                code=check.code,
                message=check.message,
            )
        if isinstance(path, str):
            self.toolchain_service.configured_path = Path(check.info.adb).parent
        result = self._update_state(command, toolchain=check.info)
        if not result.ok:
            return result
        return replace(result, code="toolchain_ready", message="platform-tools validated")

    def _scan_devices(self, command: AppCommand) -> OperationResult:
        snapshot = self.store.snapshot()
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
                    return OperationResult.failed(
                        command.operation_id,
                        code="toolchain_setup_failed",
                        message=str(error),
                    )
                if check.code == "cancelled":
                    return OperationResult.cancelled(
                        command.operation_id,
                        code="cancelled",
                        message=check.message,
                    )
                if not check.ok:
                    return OperationResult.failed(
                        command.operation_id,
                        code=check.code,
                        message=check.message,
                    )
                toolchain = check.info
            try:
                scan = self.device_service.scan(
                    toolchain,
                    include_properties=include_properties,
                    include_battery=include_battery,
                    previous_devices=snapshot.devices,
                    cancellation=token,
                )
            except Exception as error:
                return OperationResult.failed(
                    command.operation_id,
                    code="device_scan_failed",
                    message=str(error),
                )
        finally:
            self._unregister_cancellation(command.operation_id)
        if scan.cancelled:
            return OperationResult.cancelled(
                command.operation_id,
                code="cancelled",
                message="device scan was cancelled",
            )
        if not scan.ok:
            return OperationResult.failed(
                command.operation_id,
                code="device_scan_failed",
                message="; ".join(scan.warnings) or "adb and fastboot scans failed",
            )
        scanned_devices = {device.serial: device for device in scan.devices}
        if "adb" not in scan.successful_sources:
            for device in snapshot.devices:
                if device.mode not in {"fastboot", "fastbootd"}:
                    scanned_devices.setdefault(device.serial, device)
        if "fastboot" not in scan.successful_sources:
            for device in snapshot.devices:
                if device.mode in {"fastboot", "fastbootd"}:
                    scanned_devices.setdefault(device.serial, device)
        devices = tuple(scanned_devices[key] for key in sorted(scanned_devices, key=str.casefold))
        available = {device.serial for device in devices}
        selected = tuple(serial for serial in snapshot.selected_serials if serial in available)
        primary = snapshot.selected_serial if snapshot.selected_serial in available else (
            selected[0] if selected else None
        )
        result = self._update_state(
            command,
            devices=devices,
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
            value={"snapshot": self.store.snapshot().to_dict(), "scan": scan.to_dict()},
        )

    def _preview_flash_plan(self, command: AppCommand) -> OperationResult:
        snapshot = self.store.snapshot()
        decision = self.safety_policy.evaluate(command, snapshot)
        if not decision.allowed:
            return self._denied(command, decision.code, decision.message)
        target_serial = command.target_serial or snapshot.selected_serial
        synthetic = AppCommand(
            "flash.execute",
            expected_revision=command.expected_revision,
            target_serial=target_serial,
            payload=command.payload,
            operation_id=command.operation_id,
        )
        try:
            compilation = self.operation_planner.compile(synthetic, snapshot, preview=True)
        except Exception as error:
            return OperationResult.failed(
                command.operation_id,
                code="planner_error",
                message=str(error),
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
            },
        )

    def _plan_and_execute(self, command: AppCommand) -> OperationResult:
        snapshot = self.store.snapshot()
        try:
            compilation = self.operation_planner.compile(command, snapshot)
        except Exception as error:
            return OperationResult.failed(
                command.operation_id,
                code="planner_error",
                message=str(error),
            )
        if not compilation.ok or compilation.plan is None:
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
        result = self._execute_process(planned)
        if result.ok and compilation.plan.dry_run:
            return replace(
                result,
                code="dry_run_succeeded",
                message="dry run completed without launching a subprocess",
            )
        return result

    def _update_flash_plan(self, command: AppCommand) -> OperationResult:
        snapshot = self.store.snapshot()
        mode = command.payload.get("mode", snapshot.plan.mode)
        raw_options = command.payload.get("options", snapshot.plan.options)
        dry_run = command.payload.get("dryRun", snapshot.plan.dry_run)
        if not isinstance(mode, str) or not mode:
            return self._invalid(command, "payload.mode must be a non-empty string")
        if not isinstance(raw_options, Mapping):
            return self._invalid(command, "payload.options must be an object")
        options = dict(raw_options)
        if "images" in options:
            return OperationResult.failed(
                command.operation_id,
                code="untrusted_artifact_metadata",
                message="image paths and hashes are accepted only from the backend artifact repository",
            )
        option_dry_values = [
            options.pop(key)
            for key in ("dryRun", "dry_run")
            if key in options
        ]
        if option_dry_values:
            if any(not isinstance(value, bool) for value in option_dry_values):
                return self._invalid(command, "payload.options.dryRun must be a boolean")
            if len(set(option_dry_values)) > 1:
                return self._invalid(command, "payload.options dryRun aliases disagree")
            option_dry_run = option_dry_values[0]
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
            if result_finalizer is None:
                return result
            try:
                return result_finalizer(result, token)
            except Exception as error:
                return OperationResult.failed(
                    command.operation_id,
                    code="result_finalize_failed",
                    message=str(error),
                    exit_code=result.exit_code,
                    stdout=result.stdout,
                    stderr=result.stderr,
                )

        try:
            with self._operation_lock:
                if token.cancelled:
                    return finalize(
                        OperationResult.cancelled(
                            command.operation_id,
                            code="cancelled",
                            message="operation was cancelled before execution",
                        )
                    )
                snapshot = self.store.snapshot()
                decision = self.safety_policy.evaluate(command, snapshot)
                if not decision.allowed:
                    return finalize(
                        self._denied(command, decision.code, decision.message)
                    )

                if decision.interaction is not None:
                    try:
                        response = self.interaction_handler(decision.interaction)
                    except Exception as error:
                        return finalize(
                            OperationResult.failed(
                                command.operation_id,
                                code="interaction_error",
                                message=str(error),
                            )
                        )
                    accepted = response is True or response is InteractionDecision.ACCEPTED
                    if not accepted:
                        return finalize(
                            OperationResult.cancelled(
                                command.operation_id,
                                code="user_cancelled",
                                message="operation was not confirmed",
                            )
                        )
                    if token.cancelled:
                        return finalize(
                            OperationResult.cancelled(
                                command.operation_id,
                                code="cancelled",
                                message="operation was cancelled while awaiting confirmation",
                            )
                        )
                    # A prompt may take an arbitrary amount of time. Validate the
                    # revision and serial again before crossing the process boundary.
                    snapshot = self.store.snapshot()
                    decision = self.safety_policy.evaluate(command, snapshot)
                    if not decision.allowed:
                        return finalize(
                            self._denied(command, decision.code, decision.message)
                        )

                issue = self.operation_planner.revalidate(command.operation_plan, snapshot)
                if issue is not None:
                    return finalize(self._denied(command, issue[0], issue[1]))
                if token.cancelled:
                    return finalize(
                        OperationResult.cancelled(
                            command.operation_id,
                            code="cancelled",
                            message="operation was cancelled before execution",
                        )
                    )

                try:
                    self.store.begin_operation(
                        command.operation_id,
                        expected_revision=snapshot.revision,
                        kind=str(command.kind),
                        label=command.operation_plan.label,
                    )
                except StaleRevisionError as error:
                    return finalize(self._denied(command, "stale_revision", str(error)))
                except ValueError as error:
                    return finalize(self._denied(command, "operation_busy", str(error)))

                try:
                    result = (
                        operation_executor(command, command.operation_plan, token)
                        if operation_executor is not None
                        else self.executor.execute(command, command.operation_plan, token)
                    )
                    if not isinstance(result, OperationResult):
                        raise TypeError("operation executor returned an invalid result")
                except Exception as error:
                    result = OperationResult.failed(
                        command.operation_id,
                        code="executor_error",
                        message=str(error),
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
                self.store.complete_operation(result, boot=promoted_boot)
                return result
        finally:
            self._unregister_cancellation(command.operation_id)

    def _register_cancellation(self, command: AppCommand) -> CancellationToken | None:
        token = CancellationToken()
        with self._cancellation_lock:
            if command.operation_id in self._cancellations:
                return None
            self._cancellations[command.operation_id] = token
        return token

    def _unregister_cancellation(self, operation_id: str) -> None:
        with self._cancellation_lock:
            self._cancellations.pop(operation_id, None)

    @staticmethod
    def _boot_info_from_patch_result(result: OperationResult) -> BootInfo:
        """Recover the typed canonical boot state from a verified patch result."""

        if not result.ok or not isinstance(result.value, Mapping):
            raise ValueError("successful boot patch result is missing state")
        raw_boot = result.value.get("boot")
        raw_patched = result.value.get("patchedBoot")
        if not isinstance(raw_boot, Mapping) or not isinstance(raw_patched, Mapping):
            raise ValueError("successful boot patch result is missing boot metadata")
        raw_artifact = raw_patched.get("artifact")
        if not isinstance(raw_artifact, Mapping):
            raise ValueError("successful boot patch result is missing its artifact")

        boot_id = raw_boot.get("id")
        path = raw_boot.get("path")
        digest = raw_boot.get("hash")
        partition = raw_boot.get("flavor")
        patched = raw_boot.get("patched")
        if any(
            not isinstance(value, str) or not value
            for value in (boot_id, path, digest, partition)
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
        if raw_artifact.get("path") != path or raw_artifact.get("sha256") != digest:
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
