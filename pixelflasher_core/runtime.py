"""Minimal lifecycle owner for the headless PixelFlasher core."""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TypeAlias
from uuid import uuid4

from constants import VERSION

from .config_store import ConfigDocument, ConfigError, ConfigStore
from .contracts import (
    AppCommand,
    AppSnapshot,
    BootInfo,
    FileArtifact,
    FirmwareInfo,
    FlashPlan,
    InteractionDecision,
    InteractionRequest,
    OperationResult,
    ProgressEvent,
    ToolchainInfo,
)
from .engine import InteractionHandler, PixelFlasherEngine
from .device_tools import DeviceToolsService
from .executor import CommandExecutor, ProcessTransport, ProgressListener
from .firmware_artifacts import FLASHABLE_PARTITIONS, FirmwareArtifactService
from .interaction import InteractionBroker
from .planner import OperationPlanner
from .preferences import (
    ModernPreferences,
    PreferencesError,
    load_preferences,
    save_preferences,
)
from .safety import SafetyPolicy
from .store import AppStateStore, Subscription
from .support import SupportPackageService
from .toolchain import ToolchainService


RuntimeEvent: TypeAlias = AppSnapshot | ProgressEvent | InteractionRequest | OperationResult
RuntimeListener = Callable[[RuntimeEvent], None]


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
    ) -> None:
        self.config_store = config_store
        self.config_document = config_document
        self.store = AppStateStore(initial_snapshot)
        self._listeners: dict[str, RuntimeListener] = {}
        self._listener_lock = threading.RLock()
        self._shutdown_lock = threading.RLock()
        self._preferences_lock = threading.RLock()
        self._shutdown = False
        self._external_interaction = interaction_handler
        self._external_progress = progress_listener
        self.interaction_broker = InteractionBroker(
            interaction_timeout_seconds,
            self._publish,
        )
        self._state_subscription = self.store.subscribe(self._publish)
        self.executor = CommandExecutor(transport, self._on_progress)
        configured_toolchain = self._configured_toolchain_path(config_document)
        self.firmware_artifact_cache_root = self._firmware_artifact_cache_path(
            config_store.path
        )
        operation_planner = OperationPlanner()
        firmware_artifact_service = FirmwareArtifactService(
            operation_planner.artifact_repository,
            self.firmware_artifact_cache_root,
        )
        self.engine = PixelFlasherEngine(
            self.store,
            self.executor,
            SafetyPolicy(),
            self._on_interaction,
            toolchain_service=ToolchainService(
                self.executor.transport,
                configured_path=configured_toolchain,
            ),
            operation_planner=operation_planner,
            firmware_artifact_service=firmware_artifact_service,
            device_tools_service=DeviceToolsService(
                scrcpy_executable=self._configured_scrcpy_path(config_document),
            ),
            support_package_service=SupportPackageService(
                config_store.path,
                app_version=VERSION,
            ),
        )
        self._restore_processed_artifacts(config_document, initial_snapshot)

    @classmethod
    def open(
        cls,
        config_path: str | Path,
        *,
        transport: ProcessTransport | None = None,
        interaction_handler: InteractionHandler | None = None,
        progress_listener: ProgressListener | None = None,
        interaction_timeout_seconds: float = 300.0,
    ) -> "ApplicationRuntime":
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
        )

    def snapshot(self) -> AppSnapshot:
        return self.store.snapshot()

    def execute(self, command: AppCommand) -> OperationResult:
        with self._shutdown_lock:
            if self._shutdown:
                result = OperationResult.failed(
                    command.operation_id,
                    code="engine_shutdown",
                    message="the application runtime has shut down",
                )
                self._publish(result)
                return result
        if command.kind == "settings.get":
            result = self._get_preferences(command)
        elif command.kind == "settings.update":
            result = self._update_preferences(command)
        else:
            result = self.engine.execute(command)
        self._publish(result)
        return result

    def _get_preferences(self, command: AppCommand) -> OperationResult:
        if command.payload:
            return OperationResult.failed(
                command.operation_id,
                code="invalid_settings_payload",
                message="settings.get does not accept payload fields",
            )
        with self._preferences_lock:
            try:
                preferences = load_preferences(self.config_store)
                self.config_document = self.config_store.load()
            except PreferencesError as error:
                return OperationResult.failed(
                    command.operation_id,
                    code=error.code,
                    message=str(error),
                )
            except (ConfigError, OSError) as error:
                return OperationResult.failed(
                    command.operation_id,
                    code="settings_load_failed",
                    message=str(error),
                )
        return OperationResult.success(
            command.operation_id,
            code="settings_loaded",
            message="Preferences loaded.",
            value={"preferences": preferences.to_dict()},
        )

    def _update_preferences(self, command: AppCommand) -> OperationResult:
        snapshot = self.store.snapshot()
        if command.expected_revision is None:
            return OperationResult.failed(
                command.operation_id,
                code="revision_required",
                message="expected_revision is required",
            )
        if command.expected_revision != snapshot.revision:
            return OperationResult.failed(
                command.operation_id,
                code="stale_revision",
                message=(
                    f"state revision changed: expected {command.expected_revision}, "
                    f"current {snapshot.revision}"
                ),
            )

        with self._preferences_lock:
            try:
                current = load_preferences(self.config_store)
                merged = current.to_dict()
                merged.update(command.payload)
                preferences = ModernPreferences.from_mapping(merged)
                save_preferences(self.config_store, preferences)
                self.config_document = self.config_store.load()
            except PreferencesError as error:
                return OperationResult.failed(
                    command.operation_id,
                    code=error.code,
                    message=str(error),
                )
            except (ConfigError, OSError) as error:
                return OperationResult.failed(
                    command.operation_id,
                    code="settings_save_failed",
                    message=str(error),
                )
        return OperationResult.success(
            command.operation_id,
            code="settings_updated",
            message="Preferences saved.",
            value={"preferences": preferences.to_dict()},
        )

    def respond_interaction(
        self,
        operation_id: str,
        decision: InteractionDecision | str,
        expected_revision: int,
    ) -> bool:
        try:
            normalized = (
                decision
                if isinstance(decision, InteractionDecision)
                else InteractionDecision(str(decision))
            )
        except ValueError:
            return False
        return self.interaction_broker.respond(
            operation_id,
            normalized,
            expected_revision,
        )

    def cancel(self, operation_id: str) -> bool:
        process_cancelled = self.engine.cancel(operation_id)
        interaction_cancelled = self.interaction_broker.cancel(operation_id)
        return process_cancelled or interaction_cancelled

    def register_support_destination(
        self,
        destination: str | Path,
        *,
        allow_overwrite: bool = False,
    ) -> str:
        """Grant a path selected by native chrome to ``support.create`` once."""

        with self._shutdown_lock:
            if self._shutdown:
                raise RuntimeError("the application runtime has shut down")
        return self.engine.register_support_destination(
            destination,
            allow_overwrite=allow_overwrite,
        )

    def subscribe(
        self,
        listener: RuntimeListener,
        *,
        emit_current: bool = False,
    ) -> Subscription:
        listener_id = uuid4().hex
        with self._listener_lock:
            self._listeners[listener_id] = listener
            current = self.store.snapshot()
        if emit_current:
            listener(current)

        def cancel() -> None:
            with self._listener_lock:
                self._listeners.pop(listener_id, None)

        return Subscription(cancel)

    def shutdown(self) -> None:
        with self._shutdown_lock:
            if self._shutdown:
                return
            self._shutdown = True
        self.interaction_broker.shutdown()
        self.engine.shutdown()
        snapshot = self.store.snapshot()
        with self._preferences_lock:
            values = dict(self.config_document.values)
            # Keep the three legacy Config keys usable by the current wx host.
            values.update(
                {
                    "device": snapshot.selected_serial,
                    "firmware_path": snapshot.firmware.path or None,
                    "mode": "dryRun" if snapshot.plan.dry_run else snapshot.plan.mode,
                    "_pixelflasher_core_state": {
                        "selected_serials": list(snapshot.selected_serials),
                        "firmware": snapshot.firmware.to_dict(),
                        "boot": snapshot.boot.to_dict(),
                        "processed_artifacts": self._serialized_processed_artifacts(
                            snapshot
                        ),
                        "plan": snapshot.plan.to_dict(),
                        "toolchain": snapshot.toolchain.to_dict(),
                    },
                }
            )
            if snapshot.toolchain.adb and snapshot.toolchain.fastboot:
                adb_parent = Path(snapshot.toolchain.adb).parent
                if adb_parent == Path(snapshot.toolchain.fastboot).parent:
                    values["platform_tools_path"] = str(adb_parent)
            self.config_document = ConfigDocument(values=values)
            self.config_store.save(self.config_document)
        self._state_subscription.cancel()

    def __enter__(self) -> "ApplicationRuntime":
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

    def _on_interaction(self, request: InteractionRequest) -> InteractionDecision | bool:
        if self._external_interaction is not None:
            self._publish(request)
            return self._external_interaction(request)
        return self.interaction_broker.request(request)

    def _publish(self, event: RuntimeEvent) -> None:
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
        core = values.get("_pixelflasher_core_state", {})
        if not isinstance(core, Mapping):
            core = {}

        legacy_serial = values.get("device")
        serial = legacy_serial if isinstance(legacy_serial, str) and legacy_serial else None
        raw_serials = core.get("selected_serials", ())
        serials = (
            tuple(item for item in raw_serials if isinstance(item, str) and item)
            if isinstance(raw_serials, (list, tuple))
            else ()
        )

        raw_firmware = core.get("firmware", {})
        if not isinstance(raw_firmware, Mapping):
            raw_firmware = {}
        legacy_path = values.get("firmware_path")
        path = raw_firmware.get("path", legacy_path if isinstance(legacy_path, str) else "")
        firmware = FirmwareInfo(
            path=path if isinstance(path, str) else "",
            type=str(raw_firmware.get("type", "")),
            build=str(raw_firmware.get("build", "")),
            hash=str(raw_firmware.get("hash", "")),
            verified=bool(raw_firmware.get("verified", False)),
            processed=bool(raw_firmware.get("processed", False)),
        )

        raw_boot = core.get("boot", {})
        if not isinstance(raw_boot, Mapping):
            raw_boot = {}
        boot = ApplicationRuntime._boot_from_config(raw_boot)

        raw_plan = core.get("plan", {})
        if not isinstance(raw_plan, Mapping):
            raw_plan = {}
        legacy_mode = values.get("mode")
        mode = raw_plan.get("mode", legacy_mode if isinstance(legacy_mode, str) else "dryRun")
        raw_dry_run = raw_plan.get("dry_run")
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
        options = raw_plan.get("options", {})
        if not isinstance(options, Mapping):
            options = {}
        raw_toolchain = core.get("toolchain", {})
        if not isinstance(raw_toolchain, Mapping):
            raw_toolchain = {}
        configured_path = ApplicationRuntime._configured_toolchain_path(document)
        raw_adb = raw_toolchain.get("adb", "")
        raw_fastboot = raw_toolchain.get("fastboot", "")
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
        return AppSnapshot(
            selected_serials=serials,
            selected_serial=serial,
            firmware=firmware,
            boot=boot,
            plan=FlashPlan(
                str(mode),
                options,
                revision=(
                    int(raw_plan.get("revision", 0))
                    if isinstance(raw_plan.get("revision", 0), int)
                    else 0
                ),
                fingerprint=str(raw_plan.get("fingerprint", "")),
                dry_run=dry_run,
            ),
            toolchain=toolchain,
        )

    @staticmethod
    def _boot_from_config(raw_boot: Mapping[str, object]) -> BootInfo:
        boot_id = raw_boot.get("id")
        path = raw_boot.get("path")
        digest = raw_boot.get("hash")
        flavor = raw_boot.get("flavor")
        patched = raw_boot.get("patched")
        if not all(isinstance(value, str) and value for value in (boot_id, path, digest, flavor)):
            return BootInfo()
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest.casefold())
            or flavor not in {"boot", "init_boot"}
            or not isinstance(patched, bool)
        ):
            return BootInfo()
        try:
            resolved = Path(path).expanduser().resolve(strict=True)
        except (OSError, ValueError):
            return BootInfo()
        if not resolved.is_file():
            return BootInfo()
        return BootInfo(
            id=boot_id,
            path=str(resolved),
            hash=digest.casefold(),
            flavor=flavor,
            patched=patched,
        )

    @staticmethod
    def _firmware_artifact_cache_path(config_path: str | Path) -> Path:
        resolved = Path(config_path).expanduser().resolve(strict=False)
        return resolved.parent / f".{resolved.name}.cache" / "firmware-artifacts"

    def _restore_processed_artifacts(
        self,
        document: ConfigDocument,
        snapshot: AppSnapshot,
    ) -> None:
        if (
            not snapshot.firmware.verified
            or not snapshot.firmware.processed
            or not snapshot.firmware.hash
        ):
            return
        core = document.values.get("_pixelflasher_core_state", {})
        if not isinstance(core, Mapping):
            return
        raw_artifacts = core.get("processed_artifacts", ())
        if not isinstance(raw_artifacts, (list, tuple)) or not raw_artifacts:
            return
        if len(raw_artifacts) > len(FLASHABLE_PARTITIONS):
            return
        try:
            cache_root = self.firmware_artifact_cache_root.resolve(strict=True)
        except (OSError, ValueError):
            return
        artifacts: list[FileArtifact] = []
        roles: set[str] = set()
        try:
            for raw in raw_artifacts:
                if not isinstance(raw, Mapping) or set(raw) != {"path", "sha256", "role"}:
                    return
                role = raw.get("role")
                raw_path = raw.get("path")
                raw_hash = raw.get("sha256")
                if not isinstance(role, str) or not role.startswith("partition:"):
                    return
                partition = role.partition(":")[2]
                if partition not in FLASHABLE_PARTITIONS or role in roles:
                    return
                if not isinstance(raw_path, str) or not isinstance(raw_hash, str):
                    return
                resolved_path = Path(raw_path).expanduser().resolve(strict=True)
                resolved_path.relative_to(cache_root)
                if not resolved_path.is_file():
                    return
                artifacts.append(FileArtifact(str(resolved_path), raw_hash, role))
                roles.add(role)
        except (OSError, TypeError, ValueError):
            return
        if artifacts:
            self.engine.operation_planner.artifact_repository.register(
                tuple(artifacts),
                firmware_hash=snapshot.firmware.hash,
            )

    def _serialized_processed_artifacts(
        self,
        snapshot: AppSnapshot,
    ) -> list[dict[str, object]]:
        if (
            not snapshot.firmware.verified
            or not snapshot.firmware.processed
            or not snapshot.firmware.hash
        ):
            return []
        artifacts = self.engine.operation_planner.artifact_repository.resolve(
            AppSnapshot(firmware=snapshot.firmware)
        )
        if not artifacts:
            return []
        try:
            cache_root = self.firmware_artifact_cache_root.resolve(strict=True)
        except (OSError, ValueError):
            return []
        serialized: list[dict[str, object]] = []
        roles: set[str] = set()
        for artifact in artifacts:
            if not artifact.role.startswith("partition:") or artifact.role in roles:
                continue
            partition = artifact.role.partition(":")[2]
            if partition not in FLASHABLE_PARTITIONS:
                continue
            try:
                path = Path(artifact.path).resolve(strict=True)
                path.relative_to(cache_root)
            except (OSError, ValueError):
                continue
            if not path.is_file():
                continue
            serialized.append(
                FileArtifact(str(path), artifact.sha256, artifact.role).to_dict()
            )
            roles.add(artifact.role)
        return serialized

    @staticmethod
    def _configured_toolchain_path(document: ConfigDocument) -> str | None:
        values = document.values
        for key in ("platform_tools_path", "platformToolsPath", "platform_tools_folder"):
            value = values.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        core = values.get("_pixelflasher_core_state", {})
        if isinstance(core, Mapping):
            toolchain = core.get("toolchain", {})
            if isinstance(toolchain, Mapping):
                adb = toolchain.get("adb")
                if isinstance(adb, str) and adb:
                    return str(Path(adb).parent)
        return None

    @staticmethod
    def _configured_scrcpy_path(document: ConfigDocument) -> str | None:
        """Resolve Scrcpy only from trusted persisted configuration."""

        scrcpy = document.values.get("scrcpy", {})
        if not isinstance(scrcpy, Mapping):
            return None
        path = scrcpy.get("path")
        if not isinstance(path, str) or not path.strip():
            return None
        return path.strip()
