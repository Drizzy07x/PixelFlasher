import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pixelflasher_core.boot_inventory import (
    BootInventoryError,
    BootInventoryService,
)
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


class BootInventoryServiceTests(unittest.TestCase):
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
