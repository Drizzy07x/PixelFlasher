"""Minimal lifecycle owner for the headless PixelFlasher core."""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from dataclasses import replace
from pathlib import Path
from typing import cast
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric import rsa

from constants import VERSION

from .apk_inspection import ApkInspector
from .artifact_downloads import ArtifactDownloader
from .backups import BackupService
from .boot_inventory import BootInventoryService
from .boot_patch import BootPatchService
from .bootloader_inspection import load_bootloader_prefix_catalog
from .config_store import ConfigDocument, ConfigError, ConfigStore
from .contracts import (
    AppCommand,
    AppEvent,
    AppSnapshot,
    BootInfo,
    CommandAck,
    FirmwareInfo,
    FlashPlan,
    InteractionDecision,
    InteractionRequest,
    InteractionResponse,
    OperationResult,
    ProgressEvent,
    SnapshotChanged,
    ToolchainInfo,
)
from .device_tools import DeviceToolsService
from .devices import DevicePoller, DeviceScanResult, DeviceService
from .engine import CommandEngine, InteractionHandler, PixelFlasherEngine
from .executor import CommandExecutor, ProcessTransport, ProgressListener
from .firmware import FirmwareInspector
from .firmware_artifacts import FirmwareArtifactService
from .interaction import InteractionBroker
from .observer import PostconditionObserver, ProcessDeviceObservationProbe
from .operation_runner import (
    OperationRunner,
    PostconditionObserverLike,
    SnapshotProvider,
)
from .ota_diagnostics import OtaDiagnosticsService
from .packages import PackageService
from .partitions import PartitionService
from .payload_extractor import BuiltinPayloadExtractor
from .persistent_artifacts import PersistentProcessedArtifactRepository
from .planner import OperationPlanner
from .platform_tools import PlatformToolsInstaller
from .platform_tools_setup import (
    PlatformToolsManifestCatalog,
    PlatformToolsSetupService,
)
from .preferences import (
    ModernPreferences,
    PreferencesError,
    document_with_preferences,
    preferences_from_document,
)
from .repositories import (
    LEGACY_V9_DATABASE_NAME,
    ArtifactRecord,
    ArtifactRepository,
    BootRepository,
    FirmwareRepository,
    LegacyMigrationReport,
    RepositoryError,
)
from .rooting import RootingService
from .safety import SafetyPolicy
from .store import AppStateStore, StaleRevisionError, Subscription
from .support_v2_service import (
    SupportPackageV2Service,
    UnavailableSupportPackageV2Service,
)
from .toolchain import ToolchainService

RuntimeListener = Callable[[AppEvent], None]


def _string_object_mapping(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        return {}
    values = cast(Mapping[object, object], value)
    return {key: item for key, item in values.items() if isinstance(key, str)}


class ApplicationRuntime:
    """Own config, state, execution, subscriptions, and orderly shutdown."""

    def __init__(
        self,
        config_store: ConfigStore,
        config_document: ConfigDocument,
        initial_snapshot: AppSnapshot,
        *,
        transport: ProcessTransport | None = None,
        interaction_handler: InteractionHandler | None = None,
        progress_listener: ProgressListener | None = None,
        interaction_timeout_seconds: float = 300.0,
        support_recipient_public_key: bytes | rsa.RSAPublicKey | None = None,
        support_key_id: str | None = None,
        snapshot_provider: SnapshotProvider | None = None,
        postcondition_observer: (PostconditionObserverLike | None) = None,
        enable_device_monitor: bool = False,
        device_monitor_interval_seconds: float = 2.0,
        legacy_database_path: str | Path | None = None,
        platform_tools_catalog: PlatformToolsManifestCatalog | None = None,
        platform_tools_downloader: ArtifactDownloader | None = None,
        platform_tools_installer: PlatformToolsInstaller | None = None,
        platform_tools_platform: str | None = None,
        platform_tools_architecture: str | None = None,
        android_device_catalog_path: str | Path | None = None,
    ) -> None:
        bootloader_prefixes = load_bootloader_prefix_catalog(
            android_device_catalog_path or self._packaged_android_device_catalog_path()
        )
        self.config_store = config_store
        self.config_document = config_document
        self.firmware_artifact_cache_root = self._firmware_artifact_cache_path(config_store.path)
        self.artifact_repository = ArtifactRepository(
            self._content_artifact_repository_path(config_store.path)
        )
        # Compatibility alias for callers introduced before the shared
        # FirmwareRepository/BootRepository composition became canonical.
        self.content_artifact_repository = self.artifact_repository
        self.firmware_repository = FirmwareRepository(self.artifact_repository)
        self.boot_repository = BootRepository(self.artifact_repository)
        self.processed_artifact_repository = PersistentProcessedArtifactRepository(
            self.firmware_repository,
            metadata_provider=self._processed_firmware_metadata,
            device_codename_provider=self._processed_device_codenames,
        )
        self.legacy_database_path = (
            Path(legacy_database_path).expanduser().resolve(strict=False)
            if legacy_database_path is not None
            else self._legacy_v9_database_path(config_store.path)
        )
        try:
            self.legacy_migration_report = self._migrate_legacy_artifacts()
            initial_snapshot = self._reconcile_artifact_selections(
                config_document,
                initial_snapshot,
            )
        except Exception:
            self.artifact_repository.close()
            raise
        self.store = AppStateStore(initial_snapshot)
        self._listeners: dict[str, RuntimeListener] = {}
        self._listener_lock = threading.RLock()
        self._shutdown_lock = threading.RLock()
        self._preferences_lock = threading.RLock()
        self._is_shutdown = False
        self._external_interaction = interaction_handler
        self._external_progress = progress_listener
        self.interaction_broker = InteractionBroker(
            interaction_timeout_seconds,
            self._publish,
        )
        self._state_subscription = self.store.subscribe(self._publish_snapshot)
        self.executor = CommandExecutor(transport, self._on_progress)
        self.device_service = DeviceService(self.executor.transport)
        configured_toolchain = self._configured_toolchain_path(config_document)
        boot_inventory_service = BootInventoryService(self.boot_repository)
        operation_planner = OperationPlanner(
            artifact_repository=self.processed_artifact_repository
        )
        firmware_artifact_service = FirmwareArtifactService(
            operation_planner.artifact_repository,
            self.firmware_artifact_cache_root,
            payload_extractor=BuiltinPayloadExtractor(),
        )
        support_package_service = (
            SupportPackageV2Service(
                config_store.path,
                support_recipient_public_key,
                key_id=support_key_id,
                app_version=VERSION,
            )
            if support_recipient_public_key is not None and support_key_id
            else UnavailableSupportPackageV2Service()
        )
        safety_policy = SafetyPolicy()
        snapshot_provider = snapshot_provider or (lambda _serial: self.store.snapshot())
        if postcondition_observer is None:
            postcondition_observer = cast(
                PostconditionObserverLike,
                PostconditionObserver(
                    ProcessDeviceObservationProbe(
                        self.device_service,
                        lambda: self.store.snapshot().toolchain,
                    )
                ),
            )
        apk_inspector = ApkInspector()
        rooting_service = RootingService(apk_inspector=apk_inspector)
        operation_runner = OperationRunner(
            self.executor,
            safety_policy=safety_policy,
            snapshot_provider=snapshot_provider,
            postcondition_observer=postcondition_observer,
        )
        toolchain_service = ToolchainService(
            self.executor.transport,
            configured_path=configured_toolchain,
        )
        self.platform_tools_setup_service = PlatformToolsSetupService(
            toolchain_service,
            cache_directory=self._platform_tools_cache_path(config_store.path),
            install_directory=self._platform_tools_install_path(config_store.path),
            catalog=platform_tools_catalog,
            downloader=platform_tools_downloader,
            installer=platform_tools_installer,
            platform=platform_tools_platform,
            architecture=platform_tools_architecture,
        )
        self.command_engine = CommandEngine(
            store=self.store,
            executor=self.executor,
            safety_policy=safety_policy,
            interaction_handler=self._on_interaction,
            toolchain_service=toolchain_service,
            platform_tools_setup_service=self.platform_tools_setup_service,
            device_service=self.device_service,
            firmware_inspector=FirmwareInspector(),
            operation_planner=operation_planner,
            package_service=PackageService(apk_inspector=apk_inspector),
            partition_service=PartitionService(),
            firmware_artifact_service=firmware_artifact_service,
            device_tools_service=DeviceToolsService(
                scrcpy_executable=self._configured_scrcpy_path(config_document),
                bootloader_prefixes=bootloader_prefixes,
                bootloader_process_transport=self.executor.transport,
            ),
            ota_diagnostics_service=OtaDiagnosticsService(),
            backup_service=BackupService(),
            rooting_service=rooting_service,
            boot_patch_service=BootPatchService(rooting_service, ()),
            support_package_service=support_package_service,
            operation_runner=operation_runner,
            snapshot_provider=snapshot_provider,
            postcondition_observer=postcondition_observer,
            boot_inventory_service=boot_inventory_service,
            firmware_repository=self.firmware_repository,
            toolchain_state_updater=self._activate_toolchain,
        )
        self.engine = PixelFlasherEngine(
            command_engine=self.command_engine,
            command_handler=self._execute_command,
            event_subscriber=lambda listener, emit_current: self._subscribe(
                listener,
                emit_current=emit_current,
            ),
            event_publisher=self._publish,
            cancellation_handler=self._cancel,
            interaction_responder=self._respond_interaction,
            shutdown_handler=self._shutdown,
        )
        self.device_poller = DevicePoller(
            self.device_service,
            lambda: self.store.snapshot().toolchain,
            self._handle_device_scan,
            interval_seconds=device_monitor_interval_seconds,
        )
        if enable_device_monitor:
            self.device_poller.start()

    @classmethod
    def open(
        cls,
        config_path: str | Path,
        *,
        transport: ProcessTransport | None = None,
        interaction_handler: InteractionHandler | None = None,
        progress_listener: ProgressListener | None = None,
        interaction_timeout_seconds: float = 300.0,
        support_recipient_public_key: bytes | rsa.RSAPublicKey | None = None,
        support_key_id: str | None = None,
        snapshot_provider: SnapshotProvider | None = None,
        postcondition_observer: (PostconditionObserverLike | None) = None,
        enable_device_monitor: bool = False,
        device_monitor_interval_seconds: float = 2.0,
        legacy_database_path: str | Path | None = None,
        platform_tools_catalog: PlatformToolsManifestCatalog | None = None,
        platform_tools_downloader: ArtifactDownloader | None = None,
        platform_tools_installer: PlatformToolsInstaller | None = None,
        platform_tools_platform: str | None = None,
        platform_tools_architecture: str | None = None,
        android_device_catalog_path: str | Path | None = None,
    ) -> ApplicationRuntime:
        config_store = ConfigStore(config_path)
        document = config_store.load()
        snapshot = cls._snapshot_from_config(document)
        return cls(
            config_store,
            document,
            snapshot,
            transport=transport,
            interaction_handler=interaction_handler,
            progress_listener=progress_listener,
            interaction_timeout_seconds=interaction_timeout_seconds,
            support_recipient_public_key=support_recipient_public_key,
            support_key_id=support_key_id,
            snapshot_provider=snapshot_provider,
            postcondition_observer=postcondition_observer,
            enable_device_monitor=enable_device_monitor,
            device_monitor_interval_seconds=device_monitor_interval_seconds,
            legacy_database_path=legacy_database_path,
            platform_tools_catalog=platform_tools_catalog,
            platform_tools_downloader=platform_tools_downloader,
            platform_tools_installer=platform_tools_installer,
            platform_tools_platform=platform_tools_platform,
            platform_tools_architecture=platform_tools_architecture,
            android_device_catalog_path=android_device_catalog_path,
        )

    def snapshot(self) -> AppSnapshot:
        return self.engine.snapshot()

    def execute(self, command: AppCommand) -> OperationResult:
        return self.engine.execute(command)

    def _execute_command(self, command: AppCommand) -> OperationResult:
        with self._shutdown_lock:
            if self._is_shutdown:
                return OperationResult.failed(
                    command.operation_id,
                    code="engine_shutdown",
                    message="the application runtime has shut down",
                )
        if command.kind == "settings.get":
            return self._get_preferences(command)
        if command.kind == "settings.update":
            return self._update_preferences(command)
        return self.command_engine.execute(command)

    def _get_preferences(self, command: AppCommand) -> OperationResult:
        if command.payload:
            return OperationResult.failed(
                command.operation_id,
                code="invalid_settings_payload",
                message="settings.get does not accept payload fields",
            )
        preferences = self.store.snapshot().preferences
        return OperationResult.success(
            command.operation_id,
            code="settings_loaded",
            message="Preferences loaded.",
            value={"preferences": preferences.to_dict()},
        )

    def _update_preferences(self, command: AppCommand) -> OperationResult:
        if command.expected_revision is None:
            return OperationResult.failed(
                command.operation_id,
                code="revision_required",
                message="expected_revision is required",
            )
        def prepare(snapshot: AppSnapshot) -> Mapping[str, object]:
            merged: dict[str, object] = dict(snapshot.preferences.to_dict())
            merged.update(command.payload)
            return {"preferences": ModernPreferences.from_mapping(merged)}

        def persist(_current: AppSnapshot, updated: AppSnapshot) -> None:
            with self._preferences_lock:
                document = document_with_preferences(
                    self.config_document,
                    updated.preferences,
                )
                self.config_store.save(document)
                self.config_document = document

        try:
            updated = self.store.transactional_update(
                expected_revision=command.expected_revision,
                prepare=prepare,
                side_effect=persist,
            )
        except StaleRevisionError as error:
            return OperationResult.failed(
                command.operation_id,
                code="stale_revision",
                message=(
                    f"state revision changed: expected {error.expected}, "
                    f"current {error.actual}"
                ),
            )
        except PreferencesError as error:
            return OperationResult.failed(
                command.operation_id,
                code=error.code,
                message=str(error),
            )
        except (ConfigError, OSError):
            return OperationResult.failed(
                command.operation_id,
                code="settings_save_failed",
                message="Preferences could not be saved.",
            )
        preferences = updated.preferences
        return OperationResult.success(
            command.operation_id,
            code="settings_updated",
            message="Preferences saved.",
            value={"preferences": preferences.to_dict()},
        )

    def _activate_toolchain(
        self,
        command: AppCommand,
        toolchain: ToolchainInfo,
    ) -> OperationResult:
        """Persist one verified toolchain before promoting canonical state."""

        if command.expected_revision is None:
            return OperationResult.failed(
                command.operation_id,
                code="revision_required",
                message="expected_revision is required",
            )
        if (
            not isinstance(toolchain, ToolchainInfo)
            or not toolchain.ready
            or not toolchain.adb
            or not toolchain.fastboot
            or Path(toolchain.adb).parent != Path(toolchain.fastboot).parent
        ):
            return OperationResult.failed(
                command.operation_id,
                code="toolchain_activation_invalid",
                message="Only one verified Platform Tools pair can be activated.",
            )

        def prepare(_snapshot: AppSnapshot) -> Mapping[str, object]:
            return {"toolchain": toolchain}

        def persist(_current: AppSnapshot, updated: AppSnapshot) -> None:
            with self._preferences_lock:
                values = dict(self.config_document.values)
                core = _string_object_mapping(
                    values.get("_pixelflasher_core_state", {})
                )
                core["toolchain"] = updated.toolchain.to_dict()
                document = self.config_document.with_values(
                    platform_tools_path=str(Path(updated.toolchain.adb).parent),
                    _pixelflasher_core_state=core,
                )
                self.config_store.save(document)
                self.config_document = document

        try:
            updated = self.store.transactional_update(
                expected_revision=command.expected_revision,
                prepare=prepare,
                side_effect=persist,
            )
        except StaleRevisionError as error:
            return OperationResult.failed(
                command.operation_id,
                code="stale_revision",
                message=(
                    f"state revision changed: expected {error.expected}, "
                    f"current {error.actual}"
                ),
            )
        except (ConfigError, OSError):
            return OperationResult.failed(
                command.operation_id,
                code="toolchain_activation_save_failed",
                message="Platform Tools activation could not be saved.",
            )
        return OperationResult.success(
            command.operation_id,
            code="toolchain_activated",
            message="Platform Tools activated.",
            value={"revision": updated.revision},
        )

    def respond_interaction(
        self,
        request_id: str,
        response: InteractionResponse,
    ) -> CommandAck:
        return self.engine.respond_interaction(request_id, response)

    def _respond_interaction(
        self,
        request_id: str,
        response: InteractionResponse,
    ) -> CommandAck:
        accepted = self.interaction_broker.respond(
            request_id,
            response.decision,
            response.expected_revision,
        )
        if accepted:
            return CommandAck(True, "interaction_recorded", "Decision recorded.")
        return CommandAck(
            False,
            "interaction_not_pending",
            "Interaction is no longer pending or its revision changed.",
        )

    def cancel(self, operation_id: str) -> CommandAck:
        return self.engine.cancel(operation_id)

    def _cancel(self, operation_id: str) -> CommandAck:
        process_cancelled = self.command_engine.cancel(operation_id)
        interaction_cancelled = self.interaction_broker.cancel(operation_id)
        if process_cancelled or interaction_cancelled:
            return CommandAck(True, "cancellation_requested", "Cancellation requested.")
        return CommandAck(False, "operation_not_active", "Operation is not active.")

    def register_support_destination(
        self,
        destination: str | Path,
        *,
        allow_overwrite: bool = False,
    ) -> str:
        """Grant a path selected by native chrome to ``support.create`` once."""

        return self.command_engine.register_support_destination(
            destination,
            allow_overwrite=allow_overwrite,
        )

    def subscribe(
        self,
        listener: RuntimeListener,
        *,
        emit_current: bool = False,
    ) -> Callable[[], None]:
        return self.engine.subscribe(listener, emit_current=emit_current)

    def _subscribe(
        self,
        listener: RuntimeListener,
        *,
        emit_current: bool = False,
    ) -> Callable[[], None]:
        listener_id = uuid4().hex
        with self._listener_lock:
            self._listeners[listener_id] = listener
            current = self.store.snapshot()
        if emit_current:
            listener(SnapshotChanged(current))

        def cancel() -> None:
            with self._listener_lock:
                self._listeners.pop(listener_id, None)

        return Subscription(cancel)

    def shutdown(self) -> None:
        self.engine.shutdown()

    def _shutdown(self) -> None:
        with self._shutdown_lock:
            if self._is_shutdown:
                return
            self._is_shutdown = True
        try:
            self.device_poller.stop()
            self.interaction_broker.shutdown()
            self.command_engine.shutdown()
            snapshot = self.store.snapshot()
            firmware_record = self._canonical_firmware_record(snapshot.firmware)
            boot_record = self._canonical_boot_record(snapshot.boot)
            with self._preferences_lock:
                values = dict(self.config_document.values)
                # Keep the three legacy Config keys usable by the current wx host.
                values.update(
                    {
                        "device": snapshot.selected_serial,
                        "firmware_path": (
                            str(firmware_record.path)
                            if firmware_record is not None
                            else None
                        ),
                        "mode": "dryRun" if snapshot.plan.dry_run else snapshot.plan.mode,
                        "_pixelflasher_core_state": {
                            "selected_serials": list(snapshot.selected_serials),
                            "firmware": self._artifact_reference(firmware_record),
                            "boot": self._artifact_reference(boot_record),
                            "plan": snapshot.plan.to_dict(),
                            "toolchain": snapshot.toolchain.to_dict(),
                        },
                    }
                )
                if snapshot.toolchain.adb and snapshot.toolchain.fastboot:
                    adb_parent = Path(snapshot.toolchain.adb).parent
                    if adb_parent == Path(snapshot.toolchain.fastboot).parent:
                        values["platform_tools_path"] = str(adb_parent)
                document = ConfigDocument(
                    values=values,
                    modern_extras=self.config_document.modern_extras,
                )
                self.config_document = document_with_preferences(
                    document,
                    snapshot.preferences,
                )
                self.config_store.save(self.config_document)
        finally:
            try:
                self._state_subscription.cancel()
            finally:
                self.artifact_repository.close()

    def __enter__(self) -> ApplicationRuntime:
        return self

    def __exit__(self, *_args: object) -> None:
        self.shutdown()

    def _on_progress(self, event: ProgressEvent) -> None:
        self._publish(event)
        if self._external_progress is not None:
            try:
                self._external_progress(event)
            except Exception:
                pass

    def _handle_device_scan(self, result: DeviceScanResult) -> None:
        """Publish one canonical hotplug inventory without selecting new devices."""

        if result.cancelled or not result.successful_sources:
            return
        with self._shutdown_lock:
            if self._is_shutdown:
                return
        self.store.reconcile_devices(result.devices)

    def _on_interaction(self, request: InteractionRequest) -> InteractionDecision | bool:
        if self._external_interaction is not None:
            self._publish(request)
            return self._external_interaction(request)
        return self.interaction_broker.request(request)

    def _publish_snapshot(self, snapshot: AppSnapshot) -> None:
        self._publish(SnapshotChanged(snapshot))

    def _publish(self, event: AppEvent) -> None:
        with self._listener_lock:
            listeners = tuple(self._listeners.values())
        for listener in listeners:
            try:
                listener(event)
            except Exception:
                continue

    @staticmethod
    def _snapshot_from_config(document: ConfigDocument) -> AppSnapshot:
        values = document.values
        core = _string_object_mapping(values.get("_pixelflasher_core_state", {}))

        legacy_serial = values.get("device")
        serial = legacy_serial if isinstance(legacy_serial, str) and legacy_serial else None
        raw_serials: object = core.get("selected_serials", ())
        if isinstance(raw_serials, (list, tuple)):
            serial_values = cast(list[object] | tuple[object, ...], raw_serials)
            serials = tuple(item for item in serial_values if isinstance(item, str) and item)
        else:
            serials = ()

        raw_plan = _string_object_mapping(core.get("plan", {}))
        legacy_mode = values.get("mode")
        mode: object = raw_plan.get(
            "mode",
            legacy_mode if isinstance(legacy_mode, str) else "dryRun",
        )
        raw_dry_run: object = raw_plan.get("dry_run")
        legacy_dry_run = isinstance(mode, str) and mode.casefold() in {
            "dryrun",
            "dry-run",
            "dry_run",
        }
        # Core state written before dry_run became an independent field must
        # migrate fail-safe. Missing data can never reactivate real flashing.
        dry_run = raw_dry_run if isinstance(raw_dry_run, bool) else True
        if legacy_dry_run:
            mode = "images"
            dry_run = True
        options = _string_object_mapping(raw_plan.get("options", {}))
        raw_toolchain = _string_object_mapping(core.get("toolchain", {}))
        configured_path = ApplicationRuntime._configured_toolchain_path(document)
        raw_adb: object = raw_toolchain.get("adb", "")
        raw_fastboot: object = raw_toolchain.get("fastboot", "")
        adb = raw_adb if isinstance(raw_adb, str) else ""
        fastboot = raw_fastboot if isinstance(raw_fastboot, str) else ""
        if configured_path is not None and not (adb and fastboot):
            directory = Path(configured_path).expanduser()
            adb = str(next((item for item in (directory / "adb.exe", directory / "adb") if item.is_file()), ""))
            fastboot = str(
                next(
                    (item for item in (directory / "fastboot.exe", directory / "fastboot") if item.is_file()),
                    "",
                )
            )
        toolchain = ToolchainInfo(
            adb=adb,
            fastboot=fastboot,
            version=str(raw_toolchain.get("version", "")),
            # Executables are revalidated before the first real scan.
            ready=False,
        )
        raw_plan_revision: object = raw_plan.get("revision", 0)
        plan_revision = (
            raw_plan_revision if isinstance(raw_plan_revision, int) and not isinstance(raw_plan_revision, bool) else 0
        )
        return AppSnapshot(
            preferences=preferences_from_document(document),
            selected_serials=serials,
            selected_serial=serial,
            plan=FlashPlan(
                mode if isinstance(mode, str) else "images",
                options,
                revision=plan_revision,
                fingerprint=str(raw_plan.get("fingerprint", "")),
                dry_run=dry_run,
            ),
            toolchain=toolchain,
        )

    def _reconcile_artifact_selections(
        self,
        document: ConfigDocument,
        snapshot: AppSnapshot,
    ) -> AppSnapshot:
        """Rehydrate selections from verified SQLite identities, never JSON paths."""

        core = _string_object_mapping(
            document.values.get("_pixelflasher_core_state", {})
        )
        firmware = self._firmware_from_repository(
            _string_object_mapping(core.get("firmware", {}))
        )
        boot = self._boot_from_repository(
            _string_object_mapping(core.get("boot", {}))
        )
        return replace(snapshot, firmware=firmware, boot=boot)

    def _firmware_from_repository(
        self,
        reference: Mapping[str, object],
    ) -> FirmwareInfo:
        artifact_id = reference.get("artifact_id", reference.get("id", ""))
        digest = reference.get("hash", reference.get("sha256", ""))
        if not isinstance(artifact_id, str) or not isinstance(digest, str) or not digest:
            return FirmwareInfo()
        try:
            record = self.firmware_repository.resolve_selection(
                artifact_id=artifact_id,
                sha256=digest,
            )
        except (OSError, RepositoryError):
            return FirmwareInfo()
        if record is None:
            return FirmwareInfo()
        firmware_type = record.metadata.get("firmwareType")
        build = record.metadata.get("firmwareBuild")
        if (
            not isinstance(firmware_type, str)
            or firmware_type not in {"factory", "ota", "custom"}
            or not isinstance(build, str)
        ):
            return FirmwareInfo()
        try:
            processed_records = self.firmware_repository.resolve_processed(
                firmware_hash=record.sha256,
            )
            processed = bool(processed_records) and all(
                self.artifact_repository.verify(item.artifact_id)
                for item in processed_records
            )
        except (OSError, RepositoryError):
            processed = False
        return FirmwareInfo(
            path=str(record.path),
            type=firmware_type,
            build=build,
            hash=record.sha256,
            verified=True,
            processed=processed,
        )

    def _boot_from_repository(
        self,
        reference: Mapping[str, object],
    ) -> BootInfo:
        artifact_id = reference.get("artifact_id", reference.get("id", ""))
        digest = reference.get("hash", reference.get("sha256", ""))
        if (
            not isinstance(artifact_id, str)
            or not artifact_id
            or not isinstance(digest, str)
            or not digest
        ):
            return BootInfo()
        try:
            record = self.boot_repository.resolve_selection(
                artifact_id=artifact_id,
                sha256=digest,
            )
        except (OSError, RepositoryError):
            return BootInfo()
        if record is None:
            return BootInfo()
        return BootInfo(
            id=record.artifact_id,
            path=str(record.path),
            hash=record.sha256,
            flavor=record.partition,
            patched=(
                record.provenance.value == "patched"
                or record.metadata.get("isPatched") is True
            ),
        )

    @staticmethod
    def _packaged_android_device_catalog_path() -> Path:
        """Resolve root-level data in source and PyInstaller bundle layouts."""

        return Path(__file__).resolve().parents[1] / "android_devices.json"

    @staticmethod
    def _firmware_artifact_cache_path(config_path: str | Path) -> Path:
        resolved = Path(config_path).expanduser().resolve(strict=False)
        return resolved.parent / f".{resolved.name}.cache" / "firmware-artifacts"

    @staticmethod
    def _platform_tools_cache_path(config_path: str | Path) -> Path:
        resolved = Path(config_path).expanduser().resolve(strict=False)
        return resolved.parent / f".{resolved.name}.cache" / "platform-tools-downloads"

    @staticmethod
    def _platform_tools_install_path(config_path: str | Path) -> Path:
        resolved = Path(config_path).expanduser().resolve(strict=False)
        return resolved.parent / f".{resolved.name}.cache" / "platform-tools"

    @staticmethod
    def _content_artifact_repository_path(config_path: str | Path) -> Path:
        resolved = Path(config_path).expanduser().resolve(strict=False)
        return resolved.parent / f".{resolved.name}.cache" / "artifact-repository"

    @staticmethod
    def _legacy_v9_database_path(config_path: str | Path) -> Path:
        """Return the audited 9.x database location beside the system config."""

        resolved = Path(config_path).expanduser().resolve(strict=False)
        return resolved.parent / LEGACY_V9_DATABASE_NAME

    def _migrate_legacy_artifacts(self) -> LegacyMigrationReport:
        source = self.legacy_database_path
        if not source.exists():
            return LegacyMigrationReport(
                source_database=str(source),
                status="not_found",
            )
        if not source.is_file():
            raise RepositoryError(
                "legacy_database_invalid",
                "legacy PixelFlasher database is not a regular file",
            )
        # ApplicationRuntime.open() calls ConfigStore.load() first.  Therefore
        # a schema-9 configuration has already received its immutable v9 backup
        # before any database row is copied into the modern repository.
        return self.artifact_repository.migrate_legacy_v9(source)

    def _processed_firmware_metadata(self) -> Mapping[str, object]:
        firmware = self.store.snapshot().firmware
        return {
            "firmwareBuild": firmware.build,
            "firmwareType": firmware.type,
        }

    def _processed_device_codenames(self) -> tuple[str, ...]:
        snapshot = self.store.snapshot()
        selected = set(snapshot.selected_serials)
        return tuple(
            sorted(
                {
                    device.codename
                    for device in snapshot.devices
                    if device.serial in selected and device.codename
                }
            )
        )

    def _canonical_firmware_record(
        self,
        firmware: FirmwareInfo,
    ) -> ArtifactRecord | None:
        if not firmware.verified or not firmware.path or not firmware.hash:
            return None
        try:
            existing = self.firmware_repository.resolve_selection(
                sha256=firmware.hash,
            )
            if (
                existing is not None
                and existing.metadata.get("firmwareType") == firmware.type
                and existing.metadata.get("firmwareBuild") == firmware.build
            ):
                return existing
            return self.firmware_repository.import_selection(
                firmware.path,
                firmware_type=firmware.type,
                build=firmware.build,
                expected_sha256=firmware.hash,
            )
        except (OSError, RepositoryError, TypeError, ValueError):
            return None

    def _canonical_boot_record(self, boot: BootInfo) -> ArtifactRecord | None:
        if not boot.path or not boot.hash or not boot.flavor:
            return None
        try:
            existing = self.boot_repository.resolve_selection(
                artifact_id=boot.id,
                sha256=boot.hash,
            )
            if existing is not None:
                return existing
            return self.boot_repository.import_selection(
                boot.path,
                partition=boot.flavor,
                patched=boot.patched,
                expected_sha256=boot.hash,
            )
        except (OSError, RepositoryError, TypeError, ValueError):
            return None

    @staticmethod
    def _artifact_reference(record: ArtifactRecord | None) -> dict[str, str]:
        if record is None:
            return {}
        return {
            "artifact_id": record.artifact_id,
            "hash": record.sha256,
        }

    @staticmethod
    def _configured_toolchain_path(document: ConfigDocument) -> str | None:
        values = document.values
        for key in ("platform_tools_path", "platformToolsPath", "platform_tools_folder"):
            value = values.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        core = _string_object_mapping(values.get("_pixelflasher_core_state", {}))
        toolchain = _string_object_mapping(core.get("toolchain", {}))
        adb: object = toolchain.get("adb")
        if isinstance(adb, str) and adb:
            return str(Path(adb).parent)
        return None

    @staticmethod
    def _configured_scrcpy_path(document: ConfigDocument) -> str | None:
        """Resolve Scrcpy only from trusted persisted configuration."""

        scrcpy = _string_object_mapping(document.values.get("scrcpy", {}))
        path: object = scrcpy.get("path")
        if not isinstance(path, str) or not path.strip():
            return None
        return path.strip()
