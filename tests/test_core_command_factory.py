import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from pixelflasher_core import (
    AppSnapshot,
    BoundReadFile,
    BoundWriteFile,
    GrantAccess,
    GrantError,
    SensitiveText,
)
from ui.bridge_contract import BRIDGE_VERSION, BridgeProtocolError, BridgeRequest
from ui.command_registry import COMMAND_REGISTRY
from ui.core_command_factory import CommandFactoryError, create_command_factory


def request(command, *, payload=None, revision=4, request_id="factory-test"):
    return BridgeRequest.from_json(
        json.dumps(
            {
                "version": BRIDGE_VERSION,
                "requestId": request_id,
                "command": command,
                "payload": payload or {},
                "expectedRevision": revision,
            }
        )
    )


class CoreCommandFactoryTests(unittest.TestCase):
    def test_module_update_keeps_only_opaque_artifact_identity_and_confirmation(self):
        factory = create_command_factory(lambda: AppSnapshot(revision=4))
        payload = {
            "serial": "SERIAL",
            "action": "update",
            "moduleId": "test_module",
            "artifactId": "a" * 32,
            "confirmationText": "UPDATE test_module SERIAL BBBBBBBB",
        }

        command = factory(request("root.modules.action", payload=payload))

        self.assertEqual(payload, command.payload)
        self.assertNotIn("path", command.payload)
        self.assertNotIn("url", command.payload)

    def test_every_accepted_engine_command_receives_its_registry_deadline(self):
        factory = create_command_factory(lambda: AppSnapshot(revision=4, selected_serial="SERIAL-1"))

        commands = (
            factory(request("settings.get", revision=None)),
            factory(request("device.scan")),
            factory(request("device.reboot", payload={"mode": "system"})),
            factory(request("flash.execute", payload={"serial": "SERIAL-1"})),
        )

        for command in commands:
            with self.subTest(command=command.kind):
                self.assertEqual(
                    COMMAND_REGISTRY[str(command.kind)].timeout_ms / 1000.0 * 0.95,
                    command.execution_timeout_seconds,
                )

    def test_deadline_clock_starts_before_native_resource_resolution(self):
        factory = create_command_factory(lambda: AppSnapshot(revision=4))
        entered_resolution: list[float] = []
        original = factory._resolve_native_resources

        def observe_resolution(command, payload):
            entered_resolution.append(time.monotonic())
            return original(command, payload)

        with patch.object(
            factory,
            "_resolve_native_resources",
            side_effect=observe_resolution,
        ):
            command = factory(request("settings.get", revision=None))

        self.assertEqual(1, len(entered_resolution))
        self.assertLessEqual(command.accepted_monotonic, entered_resolution[0])

    def test_risk_metadata_is_backend_owned(self):
        factory = create_command_factory(lambda: AppSnapshot(revision=4, selected_serial="SERIAL-1"))

        command = factory(request("flash.execute", payload={"serial": "SERIAL-1"}))

        self.assertTrue(command.destructive)
        self.assertTrue(command.requires_confirmation)
        self.assertEqual("SERIAL-1", command.target_serial)
        self.assertEqual(4, command.expected_revision)
        self.assertEqual("factory-test", command.operation_id)

        with self.assertRaises(BridgeProtocolError):
            request(
                "flash.execute",
                payload={"serial": "SERIAL-1", "destructive": False},
            )

    def test_device_commands_bind_only_an_explicit_or_selected_serial(self):
        factory = create_command_factory(lambda: AppSnapshot(revision=4, selected_serial="SERIAL-2"))
        self.assertEqual(
            "SERIAL-2",
            factory(request("device.reboot", payload={"mode": "system"})).target_serial,
        )

        empty = create_command_factory(lambda: AppSnapshot(revision=4))
        with self.assertRaisesRegex(CommandFactoryError, "target serial"):
            empty(request("partitions.erase", payload={"partition": "userdata"}))

    def test_multi_device_flash_preview_and_execute_preserve_batch_scope(self):
        snapshot = AppSnapshot(
            revision=4,
            selected_serials=("SERIAL-1", "SERIAL-2"),
            selected_serial="SERIAL-1",
        )
        factory = create_command_factory(lambda: snapshot)

        preview = factory(request("flash.plan.preview"))
        execute = factory(request("flash.execute"))
        explicit = factory(request("flash.execute", payload={"serial": "SERIAL-2"}))

        self.assertIsNone(preview.target_serial)
        self.assertIsNone(execute.target_serial)
        self.assertEqual("SERIAL-2", explicit.target_serial)

    def test_ota_diagnostics_bind_selected_or_explicit_serial_without_risk_flags(self):
        factory = create_command_factory(lambda: AppSnapshot(revision=4, selected_serial="SERIAL-OTA"))

        certificates = factory(request("device.ota.certificates"))
        logs = factory(
            request(
                "device.ota.logs",
                payload={
                    "serial": "SERIAL-EXPLICIT",
                    "maxLines": 250,
                    "timeoutSeconds": 12,
                },
            )
        )

        self.assertEqual("SERIAL-OTA", certificates.target_serial)
        self.assertEqual({}, certificates.payload)
        self.assertFalse(certificates.destructive)
        self.assertFalse(certificates.requires_confirmation)
        self.assertEqual("SERIAL-EXPLICIT", logs.target_serial)
        self.assertEqual(
            {
                "serial": "SERIAL-EXPLICIT",
                "maxLines": 250,
                "timeoutSeconds": 12,
            },
            logs.payload,
        )
        self.assertFalse(logs.destructive)
        self.assertFalse(logs.requires_confirmation)

    def test_device_open_url_binds_target_and_backend_confirmation_metadata(self):
        factory = create_command_factory(lambda: AppSnapshot(revision=4, selected_serial="SERIAL-URL"))

        command = factory(request("device.openUrl", payload={"url": "https://example.com/path"}))

        self.assertEqual("SERIAL-URL", command.target_serial)
        self.assertEqual({"url": "https://example.com/path"}, command.payload)
        self.assertFalse(command.destructive)
        self.assertTrue(command.requires_confirmation)
        self.assertEqual(4, command.expected_revision)

    def test_settings_and_local_inventory_are_not_device_scoped(self):
        factory = create_command_factory(lambda: AppSnapshot(revision=4, selected_serial="SERIAL-3"))

        loaded = factory(request("settings.get", revision=None))
        updated = factory(request("settings.update", payload={"theme": "light"}))
        inventory = factory(request("root.apps.list"))

        self.assertIsNone(loaded.target_serial)
        self.assertIsNone(updated.target_serial)
        self.assertIsNone(inventory.target_serial)
        self.assertEqual({"theme": "light"}, updated.payload)

    def test_backup_inventory_restore_keeps_only_the_opaque_repository_id(self):
        factory = create_command_factory(lambda: AppSnapshot(revision=4, selected_serial="SERIAL-3"))
        backup_id = "a" * 32

        restored = factory(
            request(
                "backups.restore",
                payload={
                    "partition": "boot",
                    "slot": "a",
                    "backupId": backup_id,
                },
            )
        )

        self.assertEqual("SERIAL-3", restored.target_serial)
        self.assertEqual(
            {"partition": "boot", "slot": "a", "backupId": backup_id},
            restored.payload,
        )
        self.assertNotIn("path", restored.payload)

    def test_magisk_backup_import_uses_a_reusable_purpose_bound_read_grant(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "stock_boot.img"
            source.write_bytes(b"stock boot")
            factory = create_command_factory(lambda: AppSnapshot(revision=4, selected_serial="SERIAL-MAGISK"))
            grant = factory.path_grants.issue_file(
                source,
                purpose="backups.magisk.import.source",
                access=GrantAccess.READ,
            )
            payload = {"serial": "SERIAL-MAGISK", "grant": grant.token}

            command = factory(
                request(
                    "backups.magisk.import",
                    payload=payload,
                    request_id="magisk-backup-import",
                )
            )

            self.assertEqual(source.resolve(), Path(command.payload["path"]))
            self.assertNotIn("grant", command.payload)
            self.assertEqual("SERIAL-MAGISK", command.target_serial)
            replay = factory(
                request(
                    "backups.magisk.import",
                    payload=payload,
                    request_id="magisk-backup-import-replay",
                )
            )
            self.assertEqual(source.resolve(), Path(replay.payload["path"]))
            with self.assertRaises(CommandFactoryError) as wrong_purpose:
                factory(
                    request(
                        "backups.restore",
                        payload={
                            "serial": "SERIAL-MAGISK",
                            "partition": "boot",
                            "slot": "a",
                            "grant": grant.token,
                        },
                        request_id="magisk-backup-wrong-purpose",
                    )
                )
            self.assertEqual("grant_purpose_mismatch", wrong_purpose.exception.code)

    def test_native_file_grant_becomes_a_backend_path_for_the_exact_purpose(self):
        with tempfile.TemporaryDirectory() as directory:
            firmware = Path(directory) / "firmware.zip"
            firmware.write_bytes(b"firmware")
            factory = create_command_factory(lambda: AppSnapshot(revision=4))
            grant = factory.path_grants.issue_file(
                firmware,
                purpose="firmware.select",
            )

            selected = factory(
                request(
                    "firmware.select",
                    payload={"grant": grant.token, "expectedKind": "custom"},
                )
            )

            self.assertEqual(
                {"path": str(firmware.resolve()), "expectedKind": "custom"},
                selected.payload,
            )
            self.assertIsNone(selected.target_serial)
            self.assertNotIn("grant", selected.payload)

            wrong = factory.path_grants.issue_file(
                firmware,
                purpose="root.modules.install",
            )
            with self.assertRaises(CommandFactoryError) as rejected:
                factory(request("firmware.select", payload={"grant": wrong.token}))
            self.assertEqual("grant_purpose_mismatch", rejected.exception.code)

    def test_platform_tools_source_is_explicit_and_only_directory_resolves_a_grant(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            factory = create_command_factory(lambda: AppSnapshot(revision=4))
            picker = request(
                "native.pickDirectory",
                payload={
                    "purpose": "platformTools.setup.directory",
                    "title": "Use existing folder",
                },
            )
            public = factory.issue_native_grants(picker, (root,))
            grant = public["grant"]

            official = factory(request("platformTools.setup", payload={"source": "official"}))
            self.assertEqual({"source": "official"}, official.payload)

            with self.assertRaises(CommandFactoryError) as not_applicable:
                factory(
                    request(
                        "platformTools.setup",
                        payload={"source": "official", "grant": grant},
                        request_id="official-with-grant",
                    )
                )
            self.assertEqual("grant_not_applicable", not_applicable.exception.code)

            selected = factory(
                request(
                    "platformTools.setup",
                    payload={"source": "directory", "grant": grant},
                    request_id="directory-source",
                )
            )
            self.assertEqual(
                {"source": "directory", "path": str(root.resolve())},
                selected.payload,
            )
            self.assertNotIn("grant", selected.payload)

            with self.assertRaises(CommandFactoryError) as missing:
                factory(
                    request(
                        "platformTools.setup",
                        payload={"source": "directory"},
                        request_id="directory-without-grant",
                    )
                )
            self.assertEqual("grant_required", missing.exception.code)

            with self.assertRaises(CommandFactoryError) as invalid:
                factory(
                    request(
                        "platformTools.setup",
                        payload={"source": "mirror"},
                        request_id="invalid-source",
                    )
                )
            self.assertEqual("platform_tools_source_invalid", invalid.exception.code)

    def test_platform_tools_contract_rejects_missing_source_and_path_aliases(self):
        rejected_payloads = (
            {},
            {"source": 1},
            {"source": "directory", "path": "C:/browser/platform-tools"},
            {"source": "official", "download": True},
            {"source": "directory", "platformToolsPath": "/tmp/platform-tools"},
            {"source": "directory", "directory": "/tmp/platform-tools"},
        )
        for index, payload in enumerate(rejected_payloads):
            with self.subTest(payload=payload), self.assertRaises(BridgeProtocolError):
                request(
                    "platformTools.setup",
                    payload=payload,
                    request_id=f"platform-tools-alias-{index}",
                )

    def test_write_grants_are_consumed_once_and_support_path_never_returns_to_browser(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "support.zip"
            factory = create_command_factory(lambda: AppSnapshot(revision=4))
            calls = []

            def registrar(path, *, allow_overwrite=False):
                calls.append((Path(path), allow_overwrite))
                return "D" * 64

            factory.bind_support_destination_registrar(registrar)
            grant = factory.path_grants.issue_file(
                destination,
                purpose="support.create.destination",
                access=GrantAccess.WRITE,
            )
            payload = {
                "grant": grant.token,
                "includeConfig": True,
                "includeLogs": True,
            }
            command = factory(request("support.create", payload=payload))

            self.assertEqual([(destination.resolve(), False)], calls)
            self.assertEqual("D" * 64, command.payload["destinationId"])
            self.assertNotIn("grant", command.payload)

            with self.assertRaises(CommandFactoryError) as replay:
                factory(request("support.create", payload=payload, request_id="support-replay"))
            self.assertEqual("grant_not_found", replay.exception.code)

    def test_logcat_export_consumes_exact_purpose_write_grant_without_public_path(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "device-logcat.txt"
            factory = create_command_factory(lambda: AppSnapshot(revision=4, selected_serial="SERIAL-LOG"))
            picker = request(
                "native.saveFile",
                payload={"purpose": "tools.logcat.export"},
            )
            issued = factory.issue_native_grants(picker, (destination,))
            payload = {
                "mode": "snapshot",
                "redaction": "strict",
                "grant": issued["grant"],
            }

            selected = factory(request("tools.logcat", payload=payload))

            self.assertIsInstance(selected.payload["exportDestination"], BoundWriteFile)
            self.assertNotIn("grant", selected.payload)
            self.assertNotIn(str(destination), repr(selected))
            with self.assertRaises(CommandFactoryError) as replay:
                factory(
                    request(
                        "tools.logcat",
                        payload=payload,
                        request_id="logcat-export-replay",
                    )
                )
            self.assertEqual("grant_not_found", replay.exception.code)

            with self.assertRaises(BridgeProtocolError):
                request(
                    "tools.logcat",
                    payload={"destination": str(destination)},
                    request_id="logcat-arbitrary-path",
                )

    def test_apk_export_consumes_one_use_write_grant_without_public_path(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "com.example.app.apk"
            factory = create_command_factory(lambda: AppSnapshot(revision=4, selected_serial="SERIAL-APP"))
            picker = request(
                "native.saveFile",
                payload={"purpose": "apps.export.destination"},
            )
            issued = factory.issue_native_grants(picker, (destination,))
            payload = {
                "serial": "SERIAL-APP",
                "action": "export",
                "package": "com.example.app",
                "grant": issued["grant"],
            }

            selected = factory(request("apps.action", payload=payload))

            self.assertIsInstance(
                selected.payload["exportDestination"],
                BoundWriteFile,
            )
            self.assertNotIn("grant", selected.payload)
            self.assertNotIn(str(destination), repr(selected))
            with self.assertRaises(CommandFactoryError) as replay:
                factory(
                    request(
                        "apps.action",
                        payload=payload,
                        request_id="apk-export-replay",
                    )
                )
            self.assertEqual("grant_not_found", replay.exception.code)

            with self.assertRaises(BridgeProtocolError):
                request(
                    "apps.action",
                    payload={
                        "serial": "SERIAL-APP",
                        "action": "export",
                        "package": "com.example.app",
                        "destination": str(destination),
                    },
                    request_id="apk-export-arbitrary-path",
                )

    def test_data_adb_grants_stay_bound_and_cannot_be_replayed(self):
        with tempfile.TemporaryDirectory() as directory:
            factory = create_command_factory(lambda: AppSnapshot(revision=4, selected_serial="SERIAL123456"))
            destination = Path(directory) / "root-state.pfdataadb"
            backup_picker = request(
                "native.saveFile",
                payload={"purpose": "root.dataAdb.backup.destination"},
            )
            backup_grant = factory.issue_native_grants(backup_picker, (destination,))
            backup_payload = {
                "serial": "SERIAL123456",
                "grant": backup_grant["grant"],
            }
            backup = factory(request("root.dataAdb.backup", payload=backup_payload))
            self.assertIsInstance(backup.payload["destination"], BoundWriteFile)
            self.assertNotIn("grant", backup.payload)
            self.assertNotIn(str(destination), repr(backup))
            with self.assertRaises(CommandFactoryError) as replay:
                factory(
                    request(
                        "root.dataAdb.backup",
                        payload=backup_payload,
                        request_id="data-adb-backup-replay",
                    )
                )
            self.assertEqual("grant_not_found", replay.exception.code)

            source = Path(directory) / "existing.pfdataadb"
            source.write_bytes(b"opaque container")
            restore_picker = request(
                "native.pickFile",
                payload={"purpose": "root.dataAdb.restore.source"},
                request_id="data-adb-restore-picker",
            )
            restore_grant = factory.issue_native_grants(restore_picker, (source,))
            restore = factory(
                request(
                    "root.dataAdb.restore",
                    payload={
                        "serial": "SERIAL123456",
                        "grant": restore_grant["grant"],
                        "confirmationText": "RESTORE DATAADB 123456",
                    },
                    request_id="data-adb-restore",
                )
            )
            self.assertIsInstance(restore.payload["source"], BoundReadFile)
            self.assertNotIn("grant", restore.payload)
            self.assertNotIn(str(source), repr(restore))

    def test_partition_grants_stay_bound_and_write_destination_is_one_use(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "boot.img"
            source = root / "vendor_boot.img"
            source.write_bytes(b"verified partition image")
            factory = create_command_factory(lambda: AppSnapshot(revision=4, selected_serial="SERIAL-PART"))

            read_picker = request(
                "native.saveFile",
                payload={"purpose": "partitions.read.destination"},
            )
            read_grant = factory.issue_native_grants(read_picker, (destination,))
            read_payload = {
                "serial": "SERIAL-PART",
                "partition": "boot",
                "grant": read_grant["grant"],
                "overwrite": True,
            }
            read_command = factory(request("partitions.read", payload=read_payload))

            self.assertIsInstance(read_command.payload["destination"], BoundWriteFile)
            self.assertNotIn("grant", read_command.payload)
            self.assertNotIn(str(destination), repr(read_command))
            with self.assertRaises(CommandFactoryError) as replay:
                factory(
                    request(
                        "partitions.read",
                        payload=read_payload,
                        request_id="partition-read-replay",
                    )
                )
            self.assertEqual("grant_not_found", replay.exception.code)

            write_picker = request(
                "native.pickFile",
                payload={"purpose": "partitions.write.source"},
                request_id="partition-write-picker",
            )
            write_grant = factory.issue_native_grants(write_picker, (source,))
            write_command = factory(
                request(
                    "partitions.write",
                    payload={
                        "serial": "SERIAL-PART",
                        "partition": "vendor_boot",
                        "grant": write_grant["grant"],
                    },
                    request_id="partition-write",
                )
            )
            self.assertIsInstance(write_command.payload["path"], BoundReadFile)
            self.assertNotIn("grant", write_command.payload)
            self.assertNotIn(str(source), repr(write_command))

            with self.assertRaises(BridgeProtocolError):
                request(
                    "partitions.read",
                    payload={
                        "serial": "SERIAL-PART",
                        "partition": "boot",
                        "destination": str(destination),
                    },
                    request_id="partition-read-raw-path",
                )
            with self.assertRaises(BridgeProtocolError):
                request(
                    "partitions.write",
                    payload={
                        "serial": "SERIAL-PART",
                        "partition": "boot",
                        "path": str(source),
                    },
                    request_id="partition-write-raw-path",
                )

    def test_avb_current_boot_grant_stays_bound_and_raw_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory) / "current-boot.img"
            selected.write_bytes(b"current boot")
            factory = create_command_factory(lambda: AppSnapshot(revision=4))
            picker = request(
                "native.pickFile",
                payload={"purpose": "tools.avb.currentBoot", "title": "Current boot"},
            )
            issued = factory.issue_native_grants(picker, (selected,))

            command = factory(
                request(
                    "tools.avb",
                    payload={
                        "action": "prepareDowngrade",
                        "grant": issued["grant"],
                        "patchFingerprint": True,
                    },
                )
            )

            self.assertIsInstance(command.payload["currentBoot"], BoundReadFile)
            self.assertNotIn("grant", command.payload)
            self.assertNotIn(str(selected), repr(command))
            replay = factory(
                request(
                    "tools.avb",
                    payload={
                        "action": "prepareDowngrade",
                        "grant": issued["grant"],
                    },
                    request_id="avb-replay",
                )
            )
            replacement = Path(directory) / "replacement.img"
            replacement.write_bytes(b"changed after approval")
            replacement.replace(selected)
            with self.assertRaises(GrantError) as changed:
                replay.payload["currentBoot"].open_verified()
            self.assertEqual("grant_resource_changed", changed.exception.code)

            with self.assertRaises(BridgeProtocolError):
                request(
                    "tools.avb",
                    payload={
                        "action": "prepareDowngrade",
                        "currentBootPath": str(selected),
                    },
                    request_id="avb-raw-path",
                )

    def test_binary_xml_grant_is_bound_and_never_exposes_its_host_path(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory) / "manifest.axml"
            selected.write_bytes(b"binary xml")
            factory = create_command_factory(lambda: AppSnapshot(revision=4))
            issued = factory.issue_native_grants(
                request(
                    "native.pickFile",
                    payload={"purpose": "tools.xml.source", "title": "Binary XML"},
                ),
                (selected,),
            )

            command = factory(
                request(
                    "tools.xml",
                    payload={"action": "decodeBinary", "grant": issued["grant"]},
                )
            )

            self.assertIsInstance(command.payload["source"], BoundReadFile)
            self.assertNotIn("grant", command.payload)
            self.assertNotIn(str(selected), repr(command))
            with self.assertRaises(BridgeProtocolError):
                request(
                    "tools.xml",
                    payload={"action": "decodeBinary", "path": str(selected)},
                    request_id="xml-raw-path",
                )

    def test_keybox_grants_are_bounded_and_never_expose_host_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory) / "attestation.xml"
            selected.write_bytes(b"<AndroidAttestation />")
            factory = create_command_factory(lambda: AppSnapshot(revision=4))
            issued = factory.issue_native_grants(
                request(
                    "native.pickFiles",
                    payload={"purpose": "tools.keybox.sources", "title": "Keyboxes"},
                ),
                (selected,),
            )

            command = factory(
                request(
                    "tools.keybox",
                    payload={
                        "action": "analyze",
                        "grants": [item["grant"] for item in issued["grants"]],
                    },
                )
            )

            self.assertEqual(1, len(command.payload["sources"]))
            self.assertIsInstance(command.payload["sources"][0], BoundReadFile)
            self.assertNotIn("grants", command.payload)
            self.assertNotIn(str(selected), repr(command))

    def test_wifi_secret_grant_is_one_use_and_never_serializes_plaintext(self):
        factory = create_command_factory(lambda: AppSnapshot(revision=4, selected_serial="SERIAL-WIFI"))
        issued = request(
            "secret.issue",
            payload={"purpose": "wifi.pairingCode", "secret": "123456"},
        )
        public = factory.issue_secret(issued)
        self.assertNotIn("123456", repr(issued))
        payload = {
            "action": "pair",
            "host": "192.0.2.20",
            "port": 37123,
            "secretGrant": public["grant"],
        }

        wifi = factory(request("tools.wifi", payload=payload))

        self.assertIsNone(wifi.target_serial)
        self.assertIsInstance(wifi.payload["pairingCode"], SensitiveText)
        self.assertNotIn("123456", repr(wifi))
        self.assertEqual("[REDACTED]", wifi.to_dict()["payload"]["pairingCode"])

        with self.assertRaises(CommandFactoryError) as replay:
            factory(request("tools.wifi", payload=payload, request_id="wifi-replay"))
        self.assertEqual("grant_not_found", replay.exception.code)

    def test_apatch_superkey_grant_is_consumed_only_by_apatch_patch(self):
        with tempfile.TemporaryDirectory() as directory:
            factory = create_command_factory(lambda: AppSnapshot(revision=4, selected_serial="SERIAL-APATCH"))
            issued_request = request(
                "secret.issue",
                payload={"purpose": "apatch.superkey", "secret": "correct-horse"},
            )
            secret = factory.issue_secret(issued_request)
            destination = Path(directory) / "patched-apatch.img"
            destination_grant = factory.path_grants.issue_file(
                destination,
                purpose="boot.patch.destination",
                access=GrantAccess.WRITE,
            )
            payload = {
                "serial": "SERIAL-APATCH",
                "flavor": "apatch",
                "appId": "a" * 64,
                "grant": destination_grant.token,
                "secretGrant": secret["grant"],
            }

            patch = factory(request("boot.patch", payload=payload))

            self.assertEqual(str(destination.resolve()), patch.payload["destination"])
            self.assertIsInstance(patch.payload["superKey"], SensitiveText)
            self.assertNotIn("correct-horse", repr(issued_request))
            self.assertNotIn("correct-horse", repr(patch))
            self.assertEqual("[REDACTED]", patch.to_dict()["payload"]["superKey"])
            self.assertNotIn("secretGrant", patch.payload)

            replay_destination_grant = factory.path_grants.issue_file(
                Path(directory) / "patched-apatch-replay.img",
                purpose="boot.patch.destination",
                access=GrantAccess.WRITE,
            )
            replay_payload = {**payload, "grant": replay_destination_grant.token}
            with self.assertRaises(CommandFactoryError) as replay:
                factory(
                    request(
                        "boot.patch",
                        payload=replay_payload,
                        request_id="apatch-replay",
                    )
                )
            self.assertEqual("grant_not_found", replay.exception.code)

    def test_native_issuance_checks_picker_purpose_and_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory) / "firmware.zip"
            selected.write_bytes(b"firmware")
            factory = create_command_factory(lambda: AppSnapshot(revision=9))
            picker = request(
                "native.pickFile",
                payload={"purpose": "firmware.select", "title": "Choose firmware"},
                revision=9,
            )

            public = factory.issue_native_grants(picker, (selected,))

            self.assertEqual("firmware.select", public["purpose"])
            self.assertEqual(selected.name, public["displayName"])
            self.assertNotIn("path", public)

            wrong_picker = request(
                "native.pickFile",
                payload={"purpose": "platformTools.setup.directory"},
                revision=9,
                request_id="wrong-picker",
            )
            with self.assertRaises(CommandFactoryError) as wrong:
                factory.validate_native_request(wrong_picker)
            self.assertEqual("native_purpose_not_allowed", wrong.exception.code)

            stale = request(
                "native.pickFile",
                payload={"purpose": "firmware.select"},
                revision=8,
                request_id="stale-picker",
            )
            with self.assertRaises(CommandFactoryError) as conflict:
                factory.validate_native_request(stale)
            self.assertEqual("revision_conflict", conflict.exception.code)

    def test_push_picker_and_command_share_the_thirty_two_file_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            files = []
            for index in range(33):
                path = Path(directory) / f"file-{index:02d}.bin"
                path.write_bytes(bytes([index]))
                files.append(path)
            factory = create_command_factory(lambda: AppSnapshot(revision=4, selected_serial="SERIAL"))
            picker = request(
                "native.pickFiles",
                payload={"purpose": "tools.pushFiles.sources"},
            )
            issued = factory.issue_native_grants(picker, files[:32])
            tokens = [item["grant"] for item in issued["grants"]]
            command = factory(
                request(
                    "tools.pushFiles",
                    payload={
                        "serial": "SERIAL",
                        "grants": tokens,
                        "destination": "/data/local/tmp/",
                    },
                )
            )
            self.assertEqual(32, len(command.payload["paths"]))
            self.assertTrue(all(isinstance(path, BoundReadFile) for path in command.payload["paths"]))
            self.assertNotIn("grants", command.payload)

            replacement = factory.issue_native_grants(picker, files[:32])
            replacement_tokens = [item["grant"] for item in replacement["grants"]]
            with self.assertRaises(CommandFactoryError) as superseded:
                factory(
                    request(
                        "tools.pushFiles",
                        payload={
                            "serial": "SERIAL",
                            "grants": tokens,
                            "destination": "/data/local/tmp/",
                        },
                    )
                )
            self.assertEqual("grant_not_found", superseded.exception.code)
            replacement_command = factory(
                request(
                    "tools.pushFiles",
                    payload={
                        "serial": "SERIAL",
                        "grants": replacement_tokens,
                        "destination": "/data/local/tmp/",
                    },
                )
            )
            self.assertEqual(32, len(replacement_command.payload["paths"]))

            with self.assertRaises(CommandFactoryError) as excessive:
                factory.issue_native_grants(picker, files)
            self.assertEqual("native_selection_invalid", excessive.exception.code)

    def test_direct_factory_bypass_still_rejects_raw_paths_and_v1(self):
        factory = create_command_factory(lambda: AppSnapshot(revision=0))
        unsafe = BridgeRequest(
            version=BRIDGE_VERSION,
            request_id="factory-bypass",
            command="firmware.select",
            payload={"path": "C:/browser/firmware.zip"},
            expected_revision=0,
        )
        legacy = BridgeRequest(
            version=1,
            request_id="factory-v1",
            command="firmware.process",
            payload={},
            expected_revision=0,
        )

        with self.assertRaises(BridgeProtocolError):
            factory(unsafe)
        with self.assertRaises(BridgeProtocolError):
            factory(legacy)

    def test_pif_import_grant_resolves_only_for_the_exact_purpose_and_action(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "profile.json"
            source.write_text('{"PRODUCT":"akita"}', encoding="utf-8")
            factory = create_command_factory(lambda: AppSnapshot(revision=4))
            picker = request(
                "native.pickFile",
                payload={"purpose": "root.pif.import", "title": "PIF", "filters": []},
            )
            issued = factory.issue_native_grants(picker, [source])
            profile_id = "pif.custom_json"
            command = factory(
                request(
                    "tools.pif",
                    payload={
                        "serial": "SERIAL",
                        "action": "importProfile",
                        "profileId": profile_id,
                        "confirmationText": f"IMPORT PIF {profile_id} SERIAL",
                        "grant": issued["grant"],
                    },
                )
            )
            self.assertEqual(str(source.resolve()), command.payload["path"])
            self.assertNotIn("grant", command.payload)

            with self.assertRaises(BridgeProtocolError):
                request(
                    "tools.pif",
                    payload={
                        "serial": "SERIAL",
                        "action": "deleteProfile",
                        "profileId": profile_id,
                        "confirmationText": f"DELETE PIF {profile_id} SERIAL",
                        "grant": issued["grant"],
                    },
                ).validate()

    def test_targeted_fix_profile_import_uses_its_own_purpose_bound_grant(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "target.json"
            source.write_text('{"PRODUCT":"akita"}', encoding="utf-8")
            factory = create_command_factory(lambda: AppSnapshot(revision=4))
            picker = request(
                "native.pickFile",
                payload={"purpose": "root.pif.target.import", "title": "Target", "filters": []},
            )
            issued = factory.issue_native_grants(picker, [source])
            package = "com.example.app"
            command = factory(
                request(
                    "tools.pif",
                    payload={
                        "serial": "SERIAL",
                        "action": "importTargetProfile",
                        "targetPackage": package,
                        "targetFormat": "json",
                        "confirmationText": f"IMPORT TARGET {package} JSON SERIAL",
                        "grant": issued["grant"],
                    },
                )
            )
            self.assertEqual(str(source.resolve()), command.payload["path"])
            self.assertNotIn("grant", command.payload)

    def test_pif_editor_content_is_staged_privately_and_removed_from_the_command(self):
        factory = create_command_factory(lambda: AppSnapshot(revision=4))
        content = '{"PRODUCT":"akita"}'
        command = factory(
            request(
                "tools.pif",
                payload={
                    "serial": "SERIAL",
                    "action": "updateProfile",
                    "profileId": "pif.custom_json",
                    "content": content,
                    "baseSha256": "absent",
                    "confirmationText": "SAVE PIF pif.custom_json SERIAL",
                },
            )
        )
        staged = Path(command.payload["path"])
        self.assertEqual(content, staged.read_text(encoding="utf-8"))
        self.assertNotIn("content", command.payload)
        self.assertNotIn("grant", command.payload)
        self.assertNotIn(content, repr(command))

        factory.clear_transient_resources()
        self.assertFalse(staged.exists())


if __name__ == "__main__":
    unittest.main()
