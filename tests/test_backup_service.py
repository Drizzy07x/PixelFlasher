import hashlib
import tempfile
import unittest
from pathlib import Path

from pixelflasher_core.backups import BackupPlanningError, BackupService
from pixelflasher_core.contracts import (
    AppCommand,
    AppSnapshot,
    DeviceInfo,
    OperationStatus,
    ToolchainInfo,
)
from pixelflasher_core.executor import (
    CancellationToken,
    CommandExecutor,
    FakeProcessTransport,
    TransportOutcome,
)


class BackupServiceTests(unittest.TestCase):
    def setUp(self):
        self.toolchain = ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True)
        self.fastboot_snapshot = self.snapshot("fastboot")
        self.service = BackupService(hash_chunk_size=2)

    def snapshot(self, mode, *, root=False, toolchain=None, revision=11):
        return AppSnapshot(
            revision=revision,
            devices=(
                DeviceInfo(
                    "SERIAL",
                    mode=mode,
                    slot="a",
                    root=root,
                    online=True,
                ),
            ),
            selected_serial="SERIAL",
            toolchain=self.toolchain if toolchain is None else toolchain,
        )

    def compile(self, kind, payload, snapshot=None, cancellation=None):
        current = snapshot or self.fastboot_snapshot
        command = AppCommand(
            kind,
            expected_revision=current.revision,
            target_serial="SERIAL",
            payload=payload,
        )
        return self.service.compile(command, current, cancellation)

    def test_create_in_rooted_adb_uses_exact_pull_argv(self):
        snapshot = self.snapshot("adb", root=True)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "boot_a.img"
            compilation = self.compile(
                "backups.create",
                {
                    "partition": "boot",
                    "slot": "a",
                    "destination": str(destination),
                },
                snapshot,
            )

            self.assertEqual(
                (
                    "ADB",
                    "-s",
                    "SERIAL",
                    "pull",
                    "/dev/block/by-name/boot_a",
                    str(destination.resolve()),
                ),
                compilation.plan.request.argv,
            )
            self.assertEqual("adb", compilation.plan.expected_device_state)
            self.assertEqual(("boot_a",), compilation.plan.partitions)
            self.assertEqual(("a",), compilation.plan.slots)
            self.assertEqual(str(destination.resolve()), compilation.output_path)
            self.assertFalse(compilation.device_write)
            self.assertFalse(compilation.requires_confirmation)

    def test_create_in_fastboot_uses_exact_fetch_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "vendor_boot_b.img"
            compilation = self.compile(
                "backups.create",
                {
                    "partition": "vendor_boot",
                    "slot": "B",
                    "destination": str(destination),
                },
            )

            self.assertEqual(
                (
                    "FASTBOOT",
                    "-s",
                    "SERIAL",
                    "fetch",
                    "vendor_boot_b",
                    str(destination.resolve()),
                ),
                compilation.plan.request.argv,
            )
            self.assertEqual("fastboot", compilation.plan.expected_device_state)

    def test_restore_hashes_canonical_image_and_requires_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "boot_a.img"
            contents = b"verified backup image"
            image.write_bytes(contents)

            compilation = self.compile(
                "backups.restore",
                {"partition": "boot", "slot": "a", "path": str(image)},
            )

            self.assertEqual(
                (
                    "FASTBOOT",
                    "-s",
                    "SERIAL",
                    "flash",
                    "boot_a",
                    str(image.resolve()),
                ),
                compilation.plan.request.argv,
            )
            self.assertEqual("partition_restore", compilation.plan.data_behavior)
            self.assertTrue(compilation.device_write)
            self.assertTrue(compilation.destructive)
            self.assertTrue(compilation.requires_confirmation)
            self.assertEqual("destructive", compilation.plan.risk.value)
            self.assertEqual(
                ("partition_written",),
                tuple(item.kind for item in compilation.plan.postconditions),
            )
            artifact = compilation.plan.artifacts[0]
            self.assertEqual(hashlib.sha256(contents).hexdigest(), artifact.sha256)
            self.assertEqual(str(image.resolve()), artifact.path)
            self.assertEqual("backup:boot_a", artifact.role)

    def test_finalize_created_backup_hashes_only_the_planned_output(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "dtbo_b.img"
            compilation = self.compile(
                "backups.create",
                {
                    "partition": "dtbo",
                    "slot": "b",
                    "destination": str(destination),
                },
            )

            with self.assertRaises(BackupPlanningError) as raised:
                self.service.finalize_created_backup(compilation)
            self.assertEqual("backup_output_missing", raised.exception.code)

            contents = b"created by fake fastboot"
            destination.write_bytes(contents)
            artifact = self.service.finalize_created_backup(compilation)
            self.assertEqual(str(destination.resolve()), artifact.path)
            self.assertEqual(hashlib.sha256(contents).hexdigest(), artifact.sha256)
            self.assertEqual("backup:dtbo_b", artifact.role)

    def test_partition_slot_and_payload_injection_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "boot_a.img"
            cases = (
                (
                    {
                        "partition": "../boot",
                        "slot": "a",
                        "destination": str(destination),
                    },
                    "backup_partition_not_allowed",
                ),
                (
                    {
                        "partition": "boot;erase userdata",
                        "slot": "a",
                        "destination": str(destination),
                    },
                    "backup_partition_not_allowed",
                ),
                (
                    {
                        "partition": "boot",
                        "slot": "a;reboot",
                        "destination": str(destination),
                    },
                    "backup_slot_invalid",
                ),
                (
                    {
                        "partition": "boot",
                        "slot": "a",
                        "destination": str(destination),
                        "argv": ["erase", "userdata"],
                    },
                    "invalid_backup_payload",
                ),
                (
                    {
                        "partition": "boot",
                        "slot": "a",
                        "destination": str(destination),
                        "sha256": "0" * 64,
                    },
                    "invalid_backup_payload",
                ),
            )
            for payload, code in cases:
                with self.subTest(payload=payload):
                    with self.assertRaises(BackupPlanningError) as raised:
                        self.compile("backups.create", payload)
                    self.assertEqual(code, raised.exception.code)

    def test_destination_rejects_traversal_relative_unsafe_and_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            existing = root / "existing.img"
            existing.write_bytes(b"do not overwrite")
            traversal = root / "nested" / ".." / "escape.img"
            unsafe = root / "unsafe name.img"
            cases = (
                ("relative.img", "backup_path_not_absolute"),
                (str(traversal), "backup_path_traversal"),
                (str(unsafe), "backup_destination_invalid"),
                (str(existing), "backup_destination_exists"),
            )
            for destination, code in cases:
                with self.subTest(destination=destination):
                    with self.assertRaises(BackupPlanningError) as raised:
                        self.compile(
                            "backups.create",
                            {
                                "partition": "boot",
                                "slot": "a",
                                "destination": destination,
                            },
                        )
                    self.assertEqual(code, raised.exception.code)

    def test_restore_rejects_traversal_missing_non_image_and_unknown_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text = root / "boot.txt"
            text.write_bytes(b"not raw image")
            empty = root / "empty.img"
            empty.write_bytes(b"")
            traversal = root / "nested" / ".." / "boot.img"
            cases = (
                ("relative.img", "backup_path_not_absolute"),
                (str(traversal), "backup_path_traversal"),
                (str(root / "missing.img"), "backup_image_path_invalid"),
                (str(text), "backup_image_path_invalid"),
                (str(empty), "backup_image_empty"),
            )
            for path, code in cases:
                with self.subTest(path=path):
                    with self.assertRaises(BackupPlanningError) as raised:
                        self.compile(
                            "backups.restore",
                            {"partition": "boot", "slot": "a", "path": path},
                        )
                    self.assertEqual(code, raised.exception.code)

    def test_revision_state_root_and_toolchain_are_revalidated(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = str(Path(directory) / "boot_a.img")
            payload = {
                "partition": "boot",
                "slot": "a",
                "destination": destination,
            }
            cases = (
                (
                    AppCommand(
                        "backups.create",
                        target_serial="SERIAL",
                        payload=payload,
                    ),
                    self.fastboot_snapshot,
                    "revision_required",
                ),
                (
                    AppCommand(
                        "backups.create",
                        expected_revision=10,
                        target_serial="SERIAL",
                        payload=payload,
                    ),
                    self.fastboot_snapshot,
                    "stale_revision",
                ),
                (
                    AppCommand(
                        "backups.create",
                        expected_revision=11,
                        target_serial="SERIAL",
                        payload=payload,
                    ),
                    self.snapshot("adb", root=False),
                    "backup_root_required",
                ),
                (
                    AppCommand(
                        "backups.create",
                        expected_revision=11,
                        target_serial="SERIAL",
                        payload=payload,
                    ),
                    self.snapshot("recovery", root=True),
                    "backup_state_unsupported",
                ),
                (
                    AppCommand(
                        "backups.create",
                        expected_revision=11,
                        target_serial="SERIAL",
                        payload=payload,
                    ),
                    self.snapshot("fastboot", toolchain=ToolchainInfo()),
                    "toolchain_not_ready",
                ),
            )
            for command, snapshot, code in cases:
                with self.subTest(code=code):
                    with self.assertRaises(BackupPlanningError) as raised:
                        self.service.compile(command, snapshot)
                    self.assertEqual(code, raised.exception.code)

    def test_restore_fails_explicitly_outside_fastboot(self):
        snapshot = self.snapshot("adb", root=True)
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "boot_a.img"
            image.write_bytes(b"backup")
            with self.assertRaises(BackupPlanningError) as raised:
                self.compile(
                    "backups.restore",
                    {"partition": "boot", "slot": "a", "path": str(image)},
                    snapshot,
                )
            self.assertEqual("restore_state_unsupported", raised.exception.code)

    def test_serial_identity_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(BackupPlanningError) as raised:
                self.service.compile(
                    AppCommand(
                        "backups.create",
                        expected_revision=11,
                        target_serial="SERIAL",
                        payload={
                            "serial": "OTHER",
                            "partition": "boot",
                            "slot": "a",
                            "destination": str(Path(directory) / "boot_a.img"),
                        },
                    ),
                    self.fastboot_snapshot,
                )
            self.assertEqual("ambiguous_target_serial", raised.exception.code)

    def test_cancellation_is_explicit_during_planning_and_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "boot_a.img"
            image.write_bytes(b"backup")
            token = CancellationToken()
            token.cancel()
            with self.assertRaises(BackupPlanningError) as raised:
                self.compile(
                    "backups.restore",
                    {"partition": "boot", "slot": "a", "path": str(image)},
                    cancellation=token,
                )
            self.assertEqual("backup_cancelled", raised.exception.code)

            compilation = self.compile(
                "backups.restore",
                {"partition": "boot", "slot": "a", "path": str(image)},
            )
            command = AppCommand(
                "backups.restore",
                expected_revision=11,
                target_serial="SERIAL",
                operation_plan=compilation.plan,
                destructive=True,
                requires_confirmation=True,
            )
            transport = FakeProcessTransport([TransportOutcome(0)])
            result = CommandExecutor(transport).execute(command, compilation.plan, token)
            self.assertEqual(OperationStatus.CANCELLED, result.status)
            self.assertEqual([], transport.calls)

    def test_process_failure_never_becomes_success(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "boot_a.img"
            compilation = self.compile(
                "backups.create",
                {
                    "partition": "boot",
                    "slot": "a",
                    "destination": str(destination),
                },
            )
            command = AppCommand(
                "backups.create",
                expected_revision=11,
                target_serial="SERIAL",
                operation_plan=compilation.plan,
            )
            transport = FakeProcessTransport(
                [TransportOutcome(1, stderr="fetch is not supported")]
            )
            result = CommandExecutor(transport).execute(command, compilation.plan)
            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("process_failed", result.code)
            self.assertIn("fetch is not supported", result.stderr)


if __name__ == "__main__":
    unittest.main()
