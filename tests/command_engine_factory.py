"""Test-only composition helper for the internal command engine.

Production composition belongs exclusively to ``ApplicationRuntime``.  Tests
may override only the dependency relevant to their assertion while this module
builds the rest of the same headless graph explicitly.
"""

from __future__ import annotations

import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path

from pixelflasher_core.backups import BackupService
from pixelflasher_core.boot_inventory import BootInventoryService
from pixelflasher_core.boot_patch import BootPatchService, PatchToolBundle
from pixelflasher_core.contracts import AppCommand, OperationResult, ToolchainInfo
from pixelflasher_core.device_tools import DeviceToolsService
from pixelflasher_core.devices import DeviceService
from pixelflasher_core.engine import (
    CommandEngine,
    InteractionHandler,
    SupportPackageBackend,
    deny_interaction,
)
from pixelflasher_core.executor import CommandExecutor
from pixelflasher_core.firmware import FirmwareInspector
from pixelflasher_core.firmware_artifacts import FirmwareArtifactService
from pixelflasher_core.observer import PostconditionObserver, ProcessDeviceObservationProbe
from pixelflasher_core.operation_runner import (
    OperationRunner,
    PostconditionObserverLike,
    SnapshotProvider,
)
from pixelflasher_core.ota_diagnostics import OtaDiagnosticsService
from pixelflasher_core.packages import PackageService
from pixelflasher_core.partitions import PartitionService
from pixelflasher_core.planner import OperationPlanner
from pixelflasher_core.platform_tools_setup import PlatformToolsSetupService
from pixelflasher_core.repositories import FirmwareRepository
from pixelflasher_core.rooting import RootApkInspector, RootingService
from pixelflasher_core.safety import SafetyPolicy
from pixelflasher_core.scrcpy_setup import ScrcpySetupService
from pixelflasher_core.store import AppStateStore
from pixelflasher_core.support_v2_service import UnavailableSupportPackageV2Service
from pixelflasher_core.toolchain import ToolchainService

ToolchainStateUpdater = Callable[[AppCommand, ToolchainInfo], OperationResult]


def make_test_command_engine(
    *,
    store: AppStateStore | None = None,
    executor: CommandExecutor | None = None,
    safety_policy: SafetyPolicy | None = None,
    interaction_handler: InteractionHandler | None = None,
    toolchain_service: ToolchainService | None = None,
    platform_tools_setup_service: PlatformToolsSetupService | None = None,
    scrcpy_setup_service: ScrcpySetupService | None = None,
    toolchain_state_updater: ToolchainStateUpdater | None = None,
    device_service: DeviceService | None = None,
    firmware_inspector: FirmwareInspector | None = None,
    operation_planner: OperationPlanner | None = None,
    package_service: PackageService | None = None,
    partition_service: PartitionService | None = None,
    device_tools_service: DeviceToolsService | None = None,
    ota_diagnostics_service: OtaDiagnosticsService | None = None,
    backup_service: BackupService | None = None,
    rooting_service: RootingService | None = None,
    apk_inspector: RootApkInspector | None = None,
    boot_patch_bundles: Sequence[PatchToolBundle] = (),
    boot_inventory_service: BootInventoryService | None = None,
    firmware_repository: FirmwareRepository | None = None,
    firmware_artifact_service: FirmwareArtifactService | None = None,
    firmware_artifact_cache_root: str | Path | None = None,
    support_package_service: SupportPackageBackend | None = None,
    operation_runner: OperationRunner | None = None,
    snapshot_provider: SnapshotProvider | None = None,
    postcondition_observer: PostconditionObserverLike | None = None,
) -> CommandEngine:
    """Compose a complete engine graph for focused unit tests."""

    store = store or AppStateStore()
    executor = executor or CommandExecutor()
    safety_policy = safety_policy or SafetyPolicy()
    interaction_handler = interaction_handler or deny_interaction
    toolchain_service = toolchain_service or ToolchainService(executor.transport)
    platform_tools_setup_service = (
        platform_tools_setup_service
        or PlatformToolsSetupService(
            toolchain_service,
            cache_directory=Path(tempfile.gettempdir())
            / "pixelflasher-tests"
            / "platform-tools-downloads",
            install_directory=Path(tempfile.gettempdir())
            / "pixelflasher-tests"
            / "platform-tools",
        )
    )
    device_service = device_service or DeviceService(executor.transport)
    scrcpy_setup_service = scrcpy_setup_service or ScrcpySetupService(
        cache_directory=Path(tempfile.gettempdir())
        / "pixelflasher-tests"
        / "scrcpy-downloads",
        install_directory=Path(tempfile.gettempdir())
        / "pixelflasher-tests"
        / "scrcpy",
    )
    firmware_inspector = firmware_inspector or FirmwareInspector()
    operation_planner = operation_planner or OperationPlanner()
    if firmware_artifact_service is None:
        cache_root = (
            Path(firmware_artifact_cache_root)
            if firmware_artifact_cache_root is not None
            else Path(tempfile.gettempdir()) / "pixelflasher-tests" / "firmware-artifacts"
        )
        firmware_artifact_service = FirmwareArtifactService(
            operation_planner.artifact_repository,
            cache_root,
        )
    package_service = package_service or PackageService(apk_inspector=apk_inspector)
    partition_service = partition_service or PartitionService()
    device_tools_service = device_tools_service or DeviceToolsService()
    ota_diagnostics_service = ota_diagnostics_service or OtaDiagnosticsService()
    backup_service = backup_service or BackupService()
    rooting_service = rooting_service or RootingService(apk_inspector=apk_inspector)
    boot_patch_service = BootPatchService(rooting_service, boot_patch_bundles)
    support_package_service = support_package_service or UnavailableSupportPackageV2Service()
    snapshot_provider = snapshot_provider or (lambda _serial: store.snapshot())
    if postcondition_observer is None:
        postcondition_observer = PostconditionObserver(
            ProcessDeviceObservationProbe(
                device_service,
                lambda: store.snapshot().toolchain,
            )
        )
    operation_runner = operation_runner or OperationRunner(
        executor,
        safety_policy=safety_policy,
        snapshot_provider=snapshot_provider,
        postcondition_observer=postcondition_observer,
    )
    return CommandEngine(
        store=store,
        executor=executor,
        safety_policy=safety_policy,
        interaction_handler=interaction_handler,
        toolchain_service=toolchain_service,
        platform_tools_setup_service=platform_tools_setup_service,
        scrcpy_setup_service=scrcpy_setup_service,
        device_service=device_service,
        firmware_inspector=firmware_inspector,
        operation_planner=operation_planner,
        package_service=package_service,
        partition_service=partition_service,
        device_tools_service=device_tools_service,
        ota_diagnostics_service=ota_diagnostics_service,
        backup_service=backup_service,
        rooting_service=rooting_service,
        boot_patch_service=boot_patch_service,
        firmware_artifact_service=firmware_artifact_service,
        support_package_service=support_package_service,
        operation_runner=operation_runner,
        snapshot_provider=snapshot_provider,
        postcondition_observer=postcondition_observer,
        boot_inventory_service=boot_inventory_service,
        firmware_repository=firmware_repository,
        toolchain_state_updater=toolchain_state_updater,
        scrcpy_state_updater=None,
        device_scan_state_updater=None,
    )
