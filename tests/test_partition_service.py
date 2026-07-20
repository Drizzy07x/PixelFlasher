import hashlib
import tempfile
import unittest
from pathlib import Path

from pixelflasher_core.contracts import (
    AppCommand,
    AppSnapshot,
    DeviceInfo,
    ToolchainInfo,
)
from pixelflasher_core.executor import (
    CommandExecutor,
    FakeProcessTransport,
    TransportOutcome,
)
from pixelflasher_core.grants import GrantAccess, GrantError, PathGrantStore
from pixelflasher_core.partitions import (
    PartitionPlanningError,
    PartitionService,
    parse_fastboot_partition_list,
)


class PartitionServiceTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = AppSnapshot(
            revision=7,
            devices=(DeviceInfo("SERIAL", mode="fastboot", online=True),),
            selected_serial="SERIAL",
            toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
        )
        self.service = PartitionService(hash_chunk_size=2)
        self.grants = PathGrantStore()

    def tearDown(self):
        self.service.shutdown()

    def read_grant(self, path):
        grant = self.grants.issue_file(
            path,
            purpose="partitions.write.source",
            access=GrantAccess.READ,
        )
        return self.grants.resolve_bound_file(
            grant.token,
            purpose="partitions.write.source",
        )

    def write_grant(self, path):
        grant = self.grants.issue_file(
            path,
            purpose="partitions.read.destination",
            access=GrantAccess.WRITE,
        )
        return self.grants.resolve_bound_write_file(
            grant.token,
            purpose="partitions.read.destination",
        )

    def compile(self, kind, payload):
        return self.service.compile(
            AppCommand(
                kind,
                expected_revision=self.snapshot.revision,
                target_serial="SERIAL",
                payload=payload,
            ),
            self.snapshot,
        )

    def test_list_compiles_and_executes_exact_serial_bound_argv(self):
        command = AppCommand(
            "partitions.list",
            expected_revision=7,
            target_serial="SERIAL",
        )
        compilation = self.service.compile(command, self.snapshot)

        self.assertEqual(
            ("FASTBOOT", "-s", "SERIAL", "getvar", "all"),
            compilation.plan.request.argv,
        )
        self.assertEqual("fastboot", compilation.plan.expected_device_state)
        self.assertFalse(compilation.destructive)

        transport = FakeProcessTransport([TransportOutcome(0, stderr="partition-size:boot: 0x10")])
        result = CommandExecutor(transport).execute(command, compilation.plan)
        self.assertTrue(result.ok)
        self.assertEqual([compilation.plan.request], transport.calls)

    def test_read_uses_fetch_and_canonical_safe_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "boot.img"
            compilation = self.compile(
                "partitions.read",
                {
                    "partition": "BOOT_A",
                    "destination": self.write_grant(destination),
                },
            )

            self.assertEqual(
                (
                    "FASTBOOT",
                    "-s",
                    "SERIAL",
                    "fetch",
                    "boot_a",
                    str(compilation.local_payload),
                ),
                compilation.plan.request.argv,
            )
            self.assertEqual(("boot_a",), compilation.plan.partitions)
            self.assertFalse(compilation.requires_confirmation)
            self.assertEqual(destination.name, compilation.destination.name)
            self.assertEqual(self.service.temporary_root, compilation.local_payload.parent)
            self.assertNotEqual(destination.resolve(), compilation.local_payload)

    def test_read_never_overwrites_without_explicit_boolean_semantics(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "boot.img"
            destination.write_bytes(b"original")

            with self.assertRaises(PartitionPlanningError) as raised:
                self.compile(
                    "partitions.read",
                    {
                        "partition": "boot",
                        "destination": self.write_grant(destination),
                    },
                )
            self.assertEqual("partition_destination_exists", raised.exception.code)

            compilation = self.compile(
                "partitions.read",
                {
                    "partition": "boot",
                    "destination": self.write_grant(destination),
                    "overwrite": True,
                },
            )
            self.assertEqual(str(compilation.local_payload), compilation.plan.request.argv[-1])

            with self.assertRaises(PartitionPlanningError) as raised:
                self.compile(
                    "partitions.read",
                    {
                        "partition": "boot",
                        "destination": self.write_grant(destination),
                        "overwrite": "yes",
                    },
                )
            self.assertEqual("partition_overwrite_invalid", raised.exception.code)

    def test_write_hashing_observes_cancellation_during_planning(self):
        class CancelAfterFirstChunk:
            def __init__(self):
                self.checks = 0

            @property
            def cancelled(self):
                self.checks += 1
                return self.checks >= 3

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "boot.img"
            source.write_bytes(b"abcdef")
            probe = CancelAfterFirstChunk()

            with self.assertRaises(PartitionPlanningError) as raised:
                self.service.compile(
                    AppCommand(
                        "partitions.write",
                        expected_revision=7,
                        target_serial="SERIAL",
                        payload={"partition": "boot", "path": self.read_grant(source)},
                    ),
                    self.snapshot,
                    probe,
                )

        self.assertEqual("partition_cancelled", raised.exception.code)
        self.assertEqual(3, probe.checks)

    def test_read_staging_hash_cancellation_remains_pre_publication_cancelled(self):
        class Cancelled:
            @property
            def cancelled(self):
                return True

        with tempfile.TemporaryDirectory() as directory:
            compilation = self.compile(
                "partitions.read",
                {
                    "partition": "boot",
                    "destination": self.write_grant(Path(directory) / "boot.img"),
                },
            )
            compilation.local_payload.write_bytes(b"fetched partition")

            decision = self.service.validate_read_preflight(
                compilation,
                TransportOutcome(0),
                Cancelled(),
            )

        self.assertFalse(decision.allowed)
        self.assertEqual("partition_read_preflight_cancelled", decision.code)

    def test_native_grant_boundary_rejects_missing_parent_and_directory_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for destination in (root / "missing" / "boot.img", root):
                with self.subTest(destination=destination):
                    with self.assertRaises(GrantError):
                        self.grants.issue_file(
                            destination,
                            purpose="partitions.read.destination",
                            access=GrantAccess.WRITE,
                        )

    def test_write_hashes_canonical_image_and_keeps_path_as_one_argument(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "boot;reboot.img"
            contents = b"trusted partition image"
            image.write_bytes(contents)

            compilation = self.compile(
                "partitions.write",
                {"partition": "vendor_boot", "path": self.read_grant(image)},
            )

            self.assertEqual(
                (
                    "FASTBOOT",
                    "-s",
                    "SERIAL",
                    "flash",
                    "vendor_boot",
                    str(image.resolve()),
                ),
                compilation.plan.request.argv,
            )
            self.assertTrue(compilation.destructive)
            self.assertTrue(compilation.requires_confirmation)
            self.assertFalse(compilation.reinforced_confirmation)
            self.assertEqual("destructive", compilation.plan.risk.value)
            self.assertEqual(
                ("partition_written",),
                tuple(item.kind for item in compilation.plan.postconditions),
            )
            self.assertEqual(1, len(compilation.plan.artifacts))
            artifact = compilation.plan.artifacts[0]
            self.assertEqual(hashlib.sha256(contents).hexdigest(), artifact.sha256)
            self.assertEqual("partition:vendor_boot", artifact.role)
            self.assertEqual(str(image.resolve()), artifact.path)

    def test_erase_is_destructive_and_reinforced_confirmation_compatible(self):
        compilation = self.compile(
            "partitions.erase",
            {"partition": "userdata"},
        )

        self.assertEqual(
            ("FASTBOOT", "-s", "SERIAL", "erase", "userdata"),
            compilation.plan.request.argv,
        )
        self.assertEqual("erase", compilation.plan.data_behavior)
        self.assertEqual(("userdata",), compilation.plan.partitions)
        self.assertTrue(compilation.destructive)
        self.assertTrue(compilation.requires_confirmation)
        self.assertTrue(compilation.reinforced_confirmation)
        self.assertEqual("destructive", compilation.plan.risk.value)
        self.assertEqual(
            ("partition_erased",),
            tuple(item.kind for item in compilation.plan.postconditions),
        )

    def test_partition_and_payload_injection_are_rejected_fail_closed(self):
        for partition in (
            "boot; reboot",
            "boot && erase userdata",
            "../boot",
            "boot$(whoami)",
            "not_a_real_partition",
        ):
            with self.subTest(partition=partition):
                with self.assertRaises(PartitionPlanningError) as raised:
                    self.compile("partitions.erase", {"partition": partition})
                self.assertEqual("partition_not_allowed", raised.exception.code)

        with self.assertRaises(PartitionPlanningError) as raised:
            self.compile(
                "partitions.erase",
                {"partition": "boot", "argv": ["erase", "userdata"]},
            )
        self.assertEqual("invalid_partition_payload", raised.exception.code)

    def test_write_rejects_raw_paths_and_native_boundary_rejects_invalid_images(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(PartitionPlanningError) as raised:
                self.compile(
                    "partitions.write",
                    {"partition": "boot", "path": str(Path(directory) / "boot.img")},
                )
            self.assertEqual("partition_image_grant_required", raised.exception.code)
            for path in (Path(directory) / "missing.img", Path(directory)):
                with self.subTest(path=path):
                    with self.assertRaises(GrantError):
                        self.grants.issue_file(
                            path,
                            purpose="partitions.write.source",
                            access=GrantAccess.READ,
                        )

    def test_requires_current_revision_selected_fastboot_device_and_toolchain(self):
        cases = (
            (
                AppCommand("partitions.list", target_serial="SERIAL"),
                self.snapshot,
                "revision_required",
            ),
            (
                AppCommand(
                    "partitions.list",
                    expected_revision=6,
                    target_serial="SERIAL",
                ),
                self.snapshot,
                "stale_revision",
            ),
            (
                AppCommand(
                    "partitions.list",
                    expected_revision=7,
                    target_serial="SERIAL",
                ),
                AppSnapshot(
                    revision=7,
                    devices=(DeviceInfo("SERIAL", mode="adb"),),
                    selected_serial="SERIAL",
                    toolchain=self.snapshot.toolchain,
                ),
                "fastboot_required",
            ),
            (
                AppCommand(
                    "partitions.list",
                    expected_revision=7,
                    target_serial="SERIAL",
                ),
                AppSnapshot(
                    revision=7,
                    devices=(DeviceInfo("SERIAL", mode="fastboot"),),
                    selected_serial="SERIAL",
                    toolchain=ToolchainInfo(),
                ),
                "toolchain_not_ready",
            ),
        )
        for command, snapshot, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(PartitionPlanningError) as raised:
                    self.service.compile(command, snapshot)
                self.assertEqual(code, raised.exception.code)

    def test_conflicting_serial_sources_are_rejected(self):
        with self.assertRaises(PartitionPlanningError) as raised:
            self.service.compile(
                AppCommand(
                    "partitions.list",
                    expected_revision=7,
                    target_serial="SERIAL",
                    payload={"serial": "OTHER"},
                ),
                self.snapshot,
            )
        self.assertEqual("ambiguous_target_serial", raised.exception.code)

    def test_fastbootd_matches_the_public_command_registry(self):
        fastbootd = AppSnapshot(
            revision=7,
            devices=(DeviceInfo("SERIAL", mode="fastbootd", online=True),),
            selected_serial="SERIAL",
            toolchain=self.snapshot.toolchain,
        )

        compilation = self.service.compile(
            AppCommand(
                "partitions.list",
                expected_revision=7,
                target_serial="SERIAL",
            ),
            fastbootd,
        )

        self.assertEqual("fastbootd", compilation.plan.expected_device_state)


class FastbootPartitionParserTests(unittest.TestCase):
    def test_parser_combines_stdout_stderr_and_ignores_untrusted_names(self):
        partitions = parse_fastboot_partition_list(
            "(bootloader) partition-size:boot_a: 0x00001000\n(bootloader) partition-type:boot_a: raw\n",
            "partition-size:userdata: 8192\n"
            "partition-size:boot;erase: 0x999\n"
            "partition-size:not_a_real_partition: 0x123\n"
            "partition-size:vendor_boot: malformed\n",
        )

        self.assertEqual(
            ["boot_a", "userdata", "vendor_boot"],
            [item.name for item in partitions],
        )
        self.assertEqual(4096, partitions[0].size_bytes)
        self.assertEqual("raw", partitions[0].partition_type)
        self.assertEqual(8192, partitions[1].size_bytes)
        self.assertIsNone(partitions[2].size_bytes)


if __name__ == "__main__":
    unittest.main()
