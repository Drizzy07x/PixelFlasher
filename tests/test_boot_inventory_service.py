import inspect
import json
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from pixelflasher_core.boot_inventory import (
    BootInventoryError,
    BootInventoryService,
)
from pixelflasher_core.cancellation import CancellationToken
from pixelflasher_core.contracts import AppCommand, AppSnapshot, OperationStatus
from pixelflasher_core.repositories import (
    ArtifactRepository,
    BootRepository,
)
from pixelflasher_core.runtime import ApplicationRuntime
from pixelflasher_core.store import AppStateStore
from tests.command_engine_factory import make_test_command_engine
from ui.bridge_contract import BRIDGE_VERSION, BridgeProtocolError, BridgeRequest
from ui.core_command_factory import CommandFactoryError, create_command_factory


def android_boot(payload: bytes = b"verified-payload") -> bytes:
    return b"ANDROID!" + payload


class BlockingIoCancellationProbe:
    """Pause a worker at a cooperative check inside real repository I/O."""

    def __init__(
        self,
        function_name: str,
        *,
        target_check: int,
        published_object_only: bool = False,
    ) -> None:
        self.function_name = function_name
        self.target_check = target_check
        self.published_object_only = published_object_only
        self.entered = threading.Event()
        self._release = threading.Event()
        self._lock = threading.Lock()
        self._cancelled = False
        self._phase_checks = 0
        self._blocked = False

    @property
    def cancelled(self) -> bool:
        stack = inspect.stack()
        functions = {frame.function for frame in stack}
        matches_phase = self.function_name in functions
        if matches_phase and self.published_object_only:
            matches_phase = any(
                frame.function == "_sha256"
                and isinstance(path := frame.frame.f_locals.get("path"), Path)
                and path.parent.parent.name == "objects"
                and not path.name.startswith(".")
                for frame in stack
            )
        should_block = False
        if matches_phase:
            with self._lock:
                self._phase_checks += 1
                if self._phase_checks == self.target_check and not self._blocked:
                    self._blocked = True
                    should_block = True
        if should_block:
            self.entered.set()
            self._release.wait(timeout=10)
        with self._lock:
            return self._cancelled

    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True
        self._release.set()


def import_boot_in_worker(
    service: BootInventoryService,
    source: Path,
    probe: BlockingIoCancellationProbe,
    errors: list[BaseException],
) -> None:
    try:
        service.import_image(
            source,
            partition="boot",
            cancellation=probe,
        )
    except BaseException as error:
        errors.append(error)


class BootInventoryServiceTests(unittest.TestCase):
    def test_cancelled_import_reports_temporary_rollback_failure(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "boot.img"
            source.write_bytes(android_boot(b"x" * (2 * 1024 * 1024)))
            repository = ArtifactRepository(root / "repository")
            service = BootInventoryService(BootRepository(repository))
            probe = BlockingIoCancellationProbe(
                "_copy_to_stream",
                target_check=2,
            )
            errors: list[BaseException] = []
            original_unlink = Path.unlink

            def fail_temporary_unlink(path, *args, **kwargs):
                if path.name.endswith(".tmp"):
                    raise PermissionError("synthetic temporary cleanup failure")
                return original_unlink(path, *args, **kwargs)

            with patch.object(Path, "unlink", fail_temporary_unlink):
                worker = threading.Thread(
                    target=import_boot_in_worker,
                    args=(service, source, probe, errors),
                    daemon=True,
                )
                worker.start()
                self.assertTrue(probe.entered.wait(timeout=5))
                probe.cancel()
                worker.join(timeout=2)

            self.assertFalse(worker.is_alive())
            self.assertEqual(1, len(errors))
            error = errors[0]
            self.assertIsInstance(error, BootInventoryError)
            if not isinstance(error, BootInventoryError):
                self.fail("cancelled import returned an unexpected error type")
            self.assertEqual("boot_import_rollback_failed", error.code)
            self.assertEqual((), repository.list())
            for temporary in repository.objects_root.rglob("*.tmp"):
                temporary.unlink()
            repository.close()

    def test_concurrent_cancellation_interrupts_real_repository_hash_and_copy(self):
        phases = (
            ("hash", "_sha256", 3, False),
            ("copy", "_copy_to_stream", 2, False),
            ("published rehash", "_sha256", 3, True),
        )
        for phase, function_name, target_check, published_object_only in phases:
            with self.subTest(phase=phase), TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "boot.img"
                source.write_bytes(android_boot(b"x" * (4 * 1024 * 1024)))
                repository = ArtifactRepository(root / "repository")
                service = BootInventoryService(BootRepository(repository))
                probe = BlockingIoCancellationProbe(
                    function_name,
                    target_check=target_check,
                    published_object_only=published_object_only,
                )
                errors: list[BaseException] = []
                worker = threading.Thread(
                    target=import_boot_in_worker,
                    args=(service, source, probe, errors),
                    daemon=True,
                )
                worker.start()
                entered = probe.entered.wait(timeout=5)
                cancelled_at = time.monotonic()
                probe.cancel()
                worker.join(timeout=2)
                cancellation_elapsed = time.monotonic() - cancelled_at
                if worker.is_alive():
                    worker.join(timeout=8)

                self.assertTrue(entered, f"worker did not enter repository {phase} I/O")
                self.assertFalse(worker.is_alive(), "cancelled import did not return promptly")
                self.assertLess(cancellation_elapsed, 2)
                self.assertEqual(1, len(errors))
                error = errors[0]
                self.assertIsInstance(error, BootInventoryError)
                if not isinstance(error, BootInventoryError):
                    self.fail("cancelled import returned an unexpected error type")
                self.assertEqual("boot_cancelled", error.code)
                self.assertEqual((), repository.list())
                object_files = tuple(
                    path
                    for path in repository.objects_root.rglob("*")
                    if path.is_file()
                )
                self.assertEqual((), object_files)
                repository.close()

    def test_inventory_hashing_rejects_a_cancelled_probe(self):
        with TemporaryDirectory() as directory:
            repository = ArtifactRepository(Path(directory) / "repository")
            service = BootInventoryService(BootRepository(repository))
            token = CancellationToken()
            token.cancel()

            with self.assertRaises(BootInventoryError) as raised:
                service.list_public(token)

            self.assertEqual("boot_cancelled", raised.exception.code)
            repository.close()

    def test_cancelled_import_rolls_back_metadata_and_content(self):
        class CancelOnCheck:
            def __init__(self, target):
                self.target = target
                self.checks = 0

            @property
            def cancelled(self):
                self.checks += 1
                return self.checks >= self.target

        for cancel_check in (2, 5):
            with self.subTest(cancel_check=cancel_check), TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "boot.img"
                source.write_bytes(android_boot(b"x" * (1024 * 1024 + 16)))
                repository = ArtifactRepository(root / "repository")
                service = BootInventoryService(BootRepository(repository))

                with self.assertRaises(BootInventoryError) as raised:
                    service.import_image(
                        source,
                        partition="boot",
                        cancellation=CancelOnCheck(cancel_check),
                    )

                self.assertEqual("boot_cancelled", raised.exception.code)
                self.assertEqual((), repository.list())
                object_files = tuple(
                    path
                    for path in (repository.root / "objects").rglob("*")
                    if path.is_file()
                )
                self.assertEqual((), object_files)
                repository.close()

    def test_import_is_content_addressed_and_public_metadata_never_contains_paths(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "boot.img"
            source.write_bytes(android_boot())
            repository = ArtifactRepository(root / "repository")
            service = BootInventoryService(BootRepository(repository))

            imported = service.import_image(source, partition="boot")
            entry = imported.entry.to_public_dict()
            listed = service.list_public()

            self.assertEqual("user_supplied", entry["provenance"])
            self.assertEqual("boot", entry["partition"])
            self.assertTrue(entry["verified"])
            self.assertEqual(imported.info.hash, entry["sha256"])
            self.assertTrue(Path(imported.info.path).is_file())
            self.assertEqual((imported.entry,), listed)
            self.assertNotIn("path", entry)
            self.assertNotIn(str(source), json.dumps(entry))
            self.assertNotIn(str(repository.root), json.dumps(entry))
            repository.close()

    def test_selection_rehashes_objects_and_rejects_unknown_ids_or_tampering(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "init_boot.img"
            source.write_bytes(android_boot(b"init"))
            repository = ArtifactRepository(root / "repository")
            service = BootInventoryService(BootRepository(repository))
            imported = service.import_image(source, partition="init_boot")

            selected = service.select(imported.info.id)
            self.assertEqual(imported.info, selected.info)

            with self.assertRaises(BootInventoryError) as malformed:
                service.select("not-an-id")
            self.assertEqual("boot_id_invalid", malformed.exception.code)
            with self.assertRaises(BootInventoryError) as missing:
                service.select("0" * 32)
            self.assertEqual("boot_not_found", missing.exception.code)

            Path(imported.info.path).write_bytes(android_boot(b"tampered"))
            with self.assertRaises(BootInventoryError) as tampered:
                service.select(imported.info.id)
            self.assertEqual("boot_integrity_failed", tampered.exception.code)
            repository.close()

    def test_import_rejects_wrong_partition_magic_and_oversized_files(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "vendor_boot.img"
            source.write_bytes(android_boot())
            repository = ArtifactRepository(root / "repository")
            service = BootInventoryService(
                BootRepository(repository),
                maximum_image_bytes=len(source.read_bytes()),
            )

            with self.assertRaises(BootInventoryError) as wrong_magic:
                service.import_image(source, partition="vendor_boot")
            self.assertEqual("boot_image_format_invalid", wrong_magic.exception.code)
            with self.assertRaises(BootInventoryError) as wrong_partition:
                service.import_image(source, partition="userdata")
            self.assertEqual("boot_partition_invalid", wrong_partition.exception.code)

            source.write_bytes(android_boot(b"x" * 128))
            with self.assertRaises(BootInventoryError) as too_large:
                service.import_image(source, partition="boot")
            self.assertEqual("boot_image_size_invalid", too_large.exception.code)
            repository.close()


class BootInventoryEngineTests(unittest.TestCase):
    def test_failed_rollback_after_cancelled_import_is_explicit_failure(self):
        class CancelAfterImportService(BootInventoryService):
            def import_image(self, path, *, partition, cancellation=None):
                selection = super().import_image(
                    path,
                    partition=partition,
                    cancellation=cancellation,
                )
                cancellation.cancel()
                return selection

            def rollback_import(self, boot_id):
                raise BootInventoryError(
                    "boot_import_rollback_failed",
                    "the cancelled boot import could not be rolled back",
                )

        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "boot.img"
            source.write_bytes(android_boot())
            repository = ArtifactRepository(root / "repository")
            service = CancelAfterImportService(BootRepository(repository))
            engine = make_test_command_engine(
                store=AppStateStore(AppSnapshot(revision=4)),
                boot_inventory_service=service,
            )

            result = engine.execute(
                AppCommand(
                    "boot.select",
                    expected_revision=4,
                    payload={"path": str(source), "partition": "boot"},
                    operation_id="cancelled-import-rollback-failure",
                )
            )

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("boot_import_rollback_failed", result.code)
            engine.shutdown()
            repository.close()

    def test_failed_rollback_after_stale_import_is_explicit_failure(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "boot.img"
            source.write_bytes(android_boot())
            repository = ArtifactRepository(root / "repository")
            store = AppStateStore(AppSnapshot(revision=4))

            class StaleAfterImportService(BootInventoryService):
                def import_image(self, path, *, partition, cancellation=None):
                    selection = super().import_image(
                        path,
                        partition=partition,
                        cancellation=cancellation,
                    )
                    store.update(
                        expected_revision=4,
                        preferences=store.snapshot().preferences,
                    )
                    return selection

                def rollback_import(self, boot_id):
                    raise BootInventoryError(
                        "boot_import_rollback_failed",
                        "the stale boot import could not be rolled back",
                    )

            service = StaleAfterImportService(BootRepository(repository))
            engine = make_test_command_engine(
                store=store,
                boot_inventory_service=service,
            )

            result = engine.execute(
                AppCommand(
                    "boot.select",
                    expected_revision=4,
                    payload={"path": str(source), "partition": "boot"},
                    operation_id="stale-import-rollback-failure",
                )
            )

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("boot_import_rollback_failed", result.code)
            self.assertEqual(5, store.snapshot().revision)
            self.assertFalse(store.snapshot().boot.id)
            engine.shutdown()
            repository.close()

    def test_expired_inventory_deadline_is_failed_not_user_cancelled(self):
        with TemporaryDirectory() as directory:
            repository = ArtifactRepository(Path(directory) / "repository")
            service = BootInventoryService(BootRepository(repository))
            engine = make_test_command_engine(
                store=AppStateStore(AppSnapshot(revision=4)),
                boot_inventory_service=service,
            )

            result = engine.execute(
                AppCommand(
                    "boot.inventory",
                    expected_revision=4,
                    operation_id="expired-boot-inventory",
                    execution_timeout_seconds=0.01,
                    _accepted_monotonic=time.monotonic() - 1,
                )
            )

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("timed_out", result.code)
            engine.shutdown()
            repository.close()

    def test_import_list_and_deterministic_selection_update_revisioned_snapshot(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "boot.img"
            source.write_bytes(android_boot())
            repository = ArtifactRepository(root / "repository")
            service = BootInventoryService(BootRepository(repository))
            store = AppStateStore(AppSnapshot(revision=4))
            engine = make_test_command_engine(
                store=store,
                boot_inventory_service=service,
            )
            factory = create_command_factory(store.snapshot)
            grant = factory.path_grants.issue_file(
                source,
                purpose="boot.select.source",
            )

            imported = engine.execute(
                factory(
                    BridgeRequest.from_json(
                        json.dumps(
                            {
                                "version": BRIDGE_VERSION,
                                "requestId": "boot-engine-import",
                                "command": "boot.select",
                                "payload": {"grant": grant.token, "partition": "boot"},
                                "expectedRevision": 4,
                            }
                        )
                    )
                )
            )
            self.assertEqual(OperationStatus.SUCCESS, imported.status)
            self.assertEqual("boot_imported", imported.code)
            boot_id = store.snapshot().boot.id
            self.assertEqual(5, store.snapshot().revision)
            self.assertNotIn("path", imported.value["selected"])

            inventory = engine.execute(
                AppCommand(
                    "boot.inventory",
                    expected_revision=5,
                    operation_id="boot-list",
                )
            )
            self.assertEqual("boot_inventory_listed", inventory.code)
            self.assertEqual(boot_id, inventory.value["selectedBootId"])
            self.assertEqual([boot_id], [entry["bootId"] for entry in inventory.value["boots"]])
            self.assertNotIn(str(source), json.dumps(inventory.value))

            stale = engine.execute(
                AppCommand(
                    "boot.select",
                    expected_revision=4,
                    payload={"bootId": boot_id},
                    operation_id="boot-stale",
                )
            )
            self.assertEqual(OperationStatus.FAILED, stale.status)
            self.assertEqual("stale_revision", stale.code)

            selected = engine.execute(
                AppCommand(
                    "boot.select",
                    expected_revision=5,
                    payload={"bootId": boot_id},
                    operation_id="boot-select",
                )
            )
            self.assertEqual("boot_selected", selected.code)
            self.assertEqual(6, store.snapshot().revision)
            engine.shutdown()
            repository.close()

    def test_closed_payload_and_bridge_grant_boundary_reject_paths_and_ambiguity(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "boot.img"
            source.write_bytes(android_boot())
            factory = create_command_factory(lambda: AppSnapshot(revision=8))
            grant = factory.path_grants.issue_file(
                source,
                purpose="boot.select.source",
            )
            request = BridgeRequest.from_json(
                json.dumps(
                    {
                        "version": BRIDGE_VERSION,
                        "requestId": "boot-grant",
                        "command": "boot.select",
                        "payload": {"grant": grant.token, "partition": "boot"},
                        "expectedRevision": 8,
                    }
                )
            )

            command = factory(request)
            self.assertEqual(
                {"path": str(source.resolve()), "partition": "boot"},
                command.payload,
            )
            self.assertNotIn("grant", command.payload)

            raw_path = {
                "version": BRIDGE_VERSION,
                "requestId": "boot-raw-path",
                "command": "boot.select",
                "payload": {"path": str(source), "partition": "boot"},
                "expectedRevision": 8,
            }
            with self.assertRaises(BridgeProtocolError) as rejected:
                BridgeRequest.from_json(json.dumps(raw_path))
            self.assertEqual("invalid_payload", rejected.exception.code)

            ambiguous = factory.path_grants.issue_file(
                source,
                purpose="boot.select.source",
            )
            with self.assertRaisesRegex(CommandFactoryError, "boot ID or a native file"):
                factory(
                    BridgeRequest.from_json(
                        json.dumps(
                            {
                                "version": BRIDGE_VERSION,
                                "requestId": "boot-ambiguous",
                                "command": "boot.select",
                                "payload": {
                                    "bootId": "0" * 32,
                                    "grant": ambiguous.token,
                                },
                                "expectedRevision": 8,
                            }
                        )
                    )
                )

    def test_runtime_persists_repository_and_selected_boot_across_restart(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            source = root / "vendor_boot.img"
            source.write_bytes(b"VNDRBOOT" + b"vendor-chain")
            runtime = ApplicationRuntime.open(config)
            factory = create_command_factory(runtime.snapshot)
            grant = factory.path_grants.issue_file(
                source,
                purpose="boot.select.source",
            )
            bridge_request = BridgeRequest.from_json(
                json.dumps(
                    {
                        "version": BRIDGE_VERSION,
                        "requestId": "runtime-boot-import",
                        "command": "boot.select",
                        "payload": {
                            "grant": grant.token,
                            "partition": "vendor_boot",
                        },
                        "expectedRevision": 0,
                    }
                )
            )

            imported = runtime.execute(factory(bridge_request))
            boot_id = runtime.snapshot().boot.id
            object_path = runtime.snapshot().boot.path
            self.assertEqual("boot_imported", imported.code)
            self.assertNotEqual(str(source.resolve()), object_path)
            runtime.shutdown()

            reopened = ApplicationRuntime.open(config)
            self.assertEqual(boot_id, reopened.snapshot().boot.id)
            self.assertEqual("vendor_boot", reopened.snapshot().boot.flavor)
            inventory = reopened.execute(
                AppCommand(
                    "boot.inventory",
                    expected_revision=0,
                    operation_id="runtime-boot-list",
                )
            )
            self.assertEqual(
                [boot_id],
                [entry["bootId"] for entry in inventory.value["boots"]],
            )
            self.assertNotIn(object_path, json.dumps(inventory.value))
            reopened.shutdown()


if __name__ == "__main__":
    unittest.main()
