import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from pixelflasher_core.boot_patch import (
    SUPPORTED_BOOT_PATCH_FLAVORS,
    BootPatchPlanningError,
    BootPatchService,
    PatchToolBundle,
)
from pixelflasher_core.contracts import (
    AppCommand,
    AppSnapshot,
    BootInfo,
    DeviceInfo,
    FileArtifact,
    OperationResult,
    OperationRisk,
    OperationStatus,
    SensitiveText,
    ToolchainInfo,
)
from pixelflasher_core.executor import (
    CancellationToken,
    CommandExecutor,
    FakeProcessTransport,
    TransportOutcome,
)
from pixelflasher_core.rooting import RootAppSource, RootingService
from tests.apk_test_helpers import FakeVerifiedApkInspector

PROVIDERS = {
    "magisk": "Magisk",
    "apatch": "APatch",
    "kernelsu": "KernelSU",
    "kernelsu-next": "KernelSU-Next",
    "sukisu": "SukiSU",
    "wild-ksu": "Wild_KSU",
    "legacy": "KernelSU-Legacy",
}


def sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def write_apk(path: Path, provider: str) -> bytes:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", provider.encode())
        archive.writestr("classes.dex", b"dex")
    return path.read_bytes()


class BootPatchServiceTests(unittest.TestCase):
    def make_service(self, root: Path, flavor: str):
        provider = PROVIDERS[flavor]
        apk = root / f"{flavor}.apk"
        apk_bytes = write_apk(apk, provider)
        app_hash = sha256(apk_bytes)
        rooting = RootingService(
            (
                RootAppSource(
                    str(apk),
                    provider,
                    "stable",
                    "1.0",
                    "official",
                    app_hash,
                ),
            ),
            hash_chunk_size=2,
            apk_inspector=FakeVerifiedApkInspector(),
        )
        app = rooting.root_app_inventory()[0]
        runner = root / f"{flavor}-runner"
        runner.write_bytes(f"runner:{flavor}".encode())
        runner_artifact = FileArtifact(
            str(runner.resolve()),
            sha256(runner.read_bytes()),
            f"patch-runner:{flavor}",
        )
        service = BootPatchService(
            rooting,
            (PatchToolBundle(flavor, app.id, runner_artifact),),
            hash_chunk_size=2,
        )
        return service, app, apk, runner

    def make_snapshot(
        self,
        boot: Path,
        *,
        partition: str = "boot",
        mode: str = "adb",
        revision: int = 5,
        ready: bool = True,
        patched: bool = False,
        boot_hash: str | None = None,
    ) -> AppSnapshot:
        digest = boot_hash if boot_hash is not None else sha256(boot.read_bytes())
        return AppSnapshot(
            revision=revision,
            devices=(
                DeviceInfo(
                    "SERIAL",
                    codename="akita",
                    mode=mode,
                    online=True,
                ),
            ),
            selected_serial="SERIAL",
            boot=BootInfo(
                "stock",
                str(boot),
                digest,
                partition,
                patched,
            ),
            toolchain=(ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True) if ready else ToolchainInfo()),
        )

    def command(self, flavor, app_id, destination, *, revision=5, payload=None):
        values = {
            "flavor": flavor,
            "appId": app_id,
            "destination": str(destination),
        }
        if flavor == "apatch":
            values["superKey"] = SensitiveText("correct-horse")
        values.update(payload or {})
        return AppCommand(
            "boot.patch",
            expected_revision=revision,
            target_serial="SERIAL",
            payload=values,
            operation_id="patch-operation",
        )

    def test_all_required_flavors_compile_serial_bound_hash_bound_plans(self):
        self.assertEqual(
            {
                "magisk",
                "apatch",
                "kernelsu",
                "kernelsu-next",
                "sukisu",
                "wild-ksu",
                "legacy",
            },
            set(SUPPORTED_BOOT_PATCH_FLAVORS),
        )
        for flavor in sorted(SUPPORTED_BOOT_PATCH_FLAVORS):
            with self.subTest(flavor=flavor), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                boot = root / "boot.img"
                boot.write_bytes(b"stock boot image")
                destination = root / f"patched-{flavor}.img"
                service, app, apk, runner = self.make_service(root, flavor)
                snapshot = self.make_snapshot(boot)

                compilation = service.compile(
                    self.command(flavor, app.id, destination),
                    snapshot,
                )

                self.assertEqual("SERIAL", compilation.plan.target_serial)
                self.assertEqual(5, compilation.plan.snapshot_revision)
                self.assertEqual("akita", compilation.plan.expected_codename)
                self.assertEqual("adb", compilation.plan.expected_device_state)
                self.assertIs(OperationRisk.MUTATING, compilation.plan.risk)
                self.assertEqual(
                    ("device_reachable", "host_artifact_written"),
                    tuple(item.kind for item in compilation.plan.postconditions),
                )
                self.assertEqual(
                    "adb",
                    compilation.plan.postconditions[0].expected["mode"],
                )
                artifact_condition = compilation.plan.postconditions[1]
                self.assertEqual(str(destination.resolve()), artifact_condition.expected["path"])
                self.assertEqual(
                    sha256(boot.read_bytes()),
                    artifact_condition.expected["sourceSha256"],
                )
                self.assertIs(
                    True,
                    artifact_condition.expected["requireDifferentSha256"],
                )
                self.assertEqual(1, artifact_condition.expected["minimumBytes"])
                self.assertEqual("device_temp_write", compilation.plan.data_behavior)
                self.assertEqual(sha256(boot.read_bytes()), compilation.plan.boot_hash)
                self.assertEqual(("boot",), compilation.plan.partitions)
                self.assertEqual(flavor, compilation.flavor)
                self.assertEqual(7, len(compilation.plan.requests))
                self.assertEqual(
                    ("ADB", "-s", "SERIAL", "push", str(boot.resolve())),
                    compilation.plan.requests[0].argv[:5],
                )
                self.assertEqual(str(apk.resolve()), compilation.plan.requests[1].argv[4])
                self.assertEqual(str(runner.resolve()), compilation.plan.requests[2].argv[4])
                patch_request = compilation.plan.requests[4]
                self.assertEqual(("ADB", "-s", "SERIAL", "shell"), patch_request.argv[:4])
                self.assertIn("--flavor", patch_request.argv)
                self.assertIn(flavor, patch_request.argv)
                self.assertNotIn("sh", patch_request.argv)
                self.assertNotIn("-c", patch_request.argv)
                self.assertTrue(compilation.device_write)
                self.assertFalse(compilation.destructive)
                self.assertTrue(compilation.requires_confirmation)
                self.assertEqual(
                    [sha256(boot.read_bytes()), app.sha256, sha256(runner.read_bytes())],
                    [artifact.sha256 for artifact in compilation.plan.artifacts],
                )

    def test_magisk_accepts_init_boot_but_kernel_patchers_require_boot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            boot = root / "init_boot.img"
            boot.write_bytes(b"stock init boot")
            magisk, magisk_app, _, _ = self.make_service(root, "magisk")
            snapshot = self.make_snapshot(boot, partition="init_boot")

            compilation = magisk.compile(
                self.command("magisk", magisk_app.id, root / "patched-magisk.img"),
                snapshot,
            )
            self.assertEqual(("init_boot",), compilation.plan.partitions)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            boot = root / "init_boot.img"
            boot.write_bytes(b"stock init boot")
            kernelsu, app, _, _ = self.make_service(root, "kernelsu")
            with self.assertRaises(BootPatchPlanningError) as raised:
                kernelsu.compile(
                    self.command("kernelsu", app.id, root / "patched.img"),
                    self.make_snapshot(boot, partition="init_boot"),
                )
            self.assertEqual("boot_partition_incompatible", raised.exception.code)

    def test_missing_unverified_or_wrong_provider_apps_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            boot = root / "boot.img"
            boot.write_bytes(b"boot")
            service, app, _, _ = self.make_service(root, "magisk")
            snapshot = self.make_snapshot(boot)
            cases = (
                (None, "patch_app_id_required"),
                ("0" * 64, "patch_app_not_found"),
            )
            for app_id, code in cases:
                with self.subTest(code=code):
                    with self.assertRaises(BootPatchPlanningError) as raised:
                        service.compile(
                            self.command("magisk", app_id, root / f"{code}.img"),
                            snapshot,
                        )
                    self.assertEqual(code, raised.exception.code)

            apatch_service, apatch_app, _, _ = self.make_service(root, "apatch")
            wrong_bundle = PatchToolBundle(
                "magisk",
                apatch_app.id,
                apatch_service.tool_bundles["apatch"].runner,
            )
            mismatch = BootPatchService(apatch_service.rooting_service, (wrong_bundle,))
            with self.assertRaises(BootPatchPlanningError) as raised:
                mismatch.compile(
                    self.command("magisk", apatch_app.id, root / "wrong-provider.img"),
                    snapshot,
                )
            self.assertEqual("patch_app_provider_mismatch", raised.exception.code)

            no_runner = BootPatchService(service.rooting_service)
            with self.assertRaises(BootPatchPlanningError) as raised:
                no_runner.compile(
                    self.command("magisk", app.id, root / "no-runner.img"),
                    snapshot,
                )
            self.assertEqual("patch_runner_unavailable", raised.exception.code)

    def test_patch_bundle_metadata_is_validated_before_registration(self):
        digest = "0" * 64
        runner = FileArtifact("C:/backend/runner", digest, "patch-runner")
        for field, value, error_type in (
            ("flavor", None, TypeError),
            ("flavor", "  ", ValueError),
            ("app_id", None, TypeError),
            ("app_id", "  ", ValueError),
        ):
            with self.subTest(field=field, value=value):
                values = {"flavor": "magisk", "app_id": digest, "runner": runner}
                values[field] = value
                with self.assertRaises(error_type):
                    PatchToolBundle(**values)

    def test_boot_and_runner_hashes_are_revalidated_before_planning(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            boot = root / "boot.img"
            boot.write_bytes(b"boot")
            service, app, _, runner = self.make_service(root, "magisk")

            with self.assertRaises(BootPatchPlanningError) as raised:
                service.compile(
                    self.command("magisk", app.id, root / "bad-boot.img"),
                    self.make_snapshot(boot, boot_hash="0" * 64),
                )
            self.assertEqual("boot_hash_mismatch", raised.exception.code)

            runner.write_bytes(b"changed runner")
            with self.assertRaises(BootPatchPlanningError) as raised:
                service.compile(
                    self.command("magisk", app.id, root / "bad-runner.img"),
                    self.make_snapshot(boot),
                )
            self.assertEqual("patch_tool_hash_mismatch", raised.exception.code)

    def test_payload_and_path_injection_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            boot = root / "boot.img"
            boot.write_bytes(b"boot")
            service, app, _, _ = self.make_service(root, "magisk")
            snapshot = self.make_snapshot(boot)
            cases = (
                ({"flavor": "magisk;reboot"}, "boot_patch_flavor_unsupported"),
                ({"argv": ["shell", "rm"]}, "invalid_boot_patch_payload"),
                ({"serial": "OTHER"}, "ambiguous_target_serial"),
            )
            for extra, code in cases:
                with self.subTest(extra=extra):
                    with self.assertRaises(BootPatchPlanningError) as raised:
                        service.compile(
                            self.command(
                                "magisk",
                                app.id,
                                root / f"{code}.img",
                                payload=extra,
                            ),
                            snapshot,
                        )
                    self.assertEqual(code, raised.exception.code)

            traversal = root / "nested" / ".." / "patched.img"
            with self.assertRaises(BootPatchPlanningError) as raised:
                service.compile(
                    self.command("magisk", app.id, traversal),
                    snapshot,
                )
            self.assertEqual("boot_patch_path_traversal", raised.exception.code)

            existing = root / "existing.img"
            existing.write_bytes(b"existing")
            with self.assertRaises(BootPatchPlanningError) as raised:
                service.compile(
                    self.command("magisk", app.id, existing),
                    snapshot,
                )
            self.assertEqual("patch_destination_exists", raised.exception.code)

    def test_revision_device_toolchain_and_stock_boot_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            boot = root / "boot.img"
            boot.write_bytes(b"boot")
            service, app, _, _ = self.make_service(root, "magisk")
            destination = root / "patched.img"
            cases = (
                (
                    AppCommand(
                        "boot.patch",
                        target_serial="SERIAL",
                        payload={
                            "flavor": "magisk",
                            "appId": app.id,
                            "destination": str(destination),
                        },
                    ),
                    self.make_snapshot(boot),
                    "revision_required",
                ),
                (
                    self.command("magisk", app.id, destination, revision=4),
                    self.make_snapshot(boot),
                    "stale_revision",
                ),
                (
                    self.command("magisk", app.id, destination),
                    self.make_snapshot(boot, mode="fastboot"),
                    "adb_device_required",
                ),
                (
                    self.command("magisk", app.id, destination),
                    self.make_snapshot(boot, ready=False),
                    "toolchain_not_ready",
                ),
                (
                    self.command("magisk", app.id, destination),
                    self.make_snapshot(boot, patched=True),
                    "stock_boot_required",
                ),
            )
            for command, snapshot, code in cases:
                with self.subTest(code=code):
                    with self.assertRaises(BootPatchPlanningError) as raised:
                        service.compile(command, snapshot)
                    self.assertEqual(code, raised.exception.code)

    def test_finalize_returns_hash_bound_boot_and_rejects_false_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            boot = root / "boot.img"
            stock = b"stock boot"
            boot.write_bytes(stock)
            service, app, _, _ = self.make_service(root, "magisk")
            destination = root / "patched.img"
            compilation = service.compile(
                self.command("magisk", app.id, destination),
                self.make_snapshot(boot),
            )
            process_result = OperationResult.success("patch-operation", stdout="patched\n")

            missing = service.finalize_result(compilation, process_result)
            self.assertEqual(OperationStatus.FAILED, missing.status)
            self.assertEqual("patch_output_missing", missing.code)

            destination.write_bytes(b"patched boot")
            success = service.finalize_result(compilation, process_result)
            self.assertTrue(success.ok)
            self.assertEqual("boot_patched", success.code)
            self.assertEqual(
                sha256(b"patched boot"),
                success.value["patchedBoot"]["artifact"]["sha256"],
            )
            self.assertEqual(sha256(stock), success.value["patchedBoot"]["sourceSha256"])
            self.assertTrue(success.value["boot"]["patched"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            boot = root / "boot.img"
            boot.write_bytes(b"same boot")
            service, app, _, _ = self.make_service(root, "magisk")
            destination = root / "unchanged.img"
            compilation = service.compile(
                self.command("magisk", app.id, destination),
                self.make_snapshot(boot),
            )
            destination.write_bytes(boot.read_bytes())
            unchanged = service.finalize_result(
                compilation,
                OperationResult.success("patch-operation"),
            )
            self.assertEqual(OperationStatus.FAILED, unchanged.status)
            self.assertEqual("patch_output_unchanged", unchanged.code)

    def test_cancellation_and_process_failure_remain_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            boot = root / "boot.img"
            boot.write_bytes(b"boot")
            service, app, _, _ = self.make_service(root, "magisk")
            token = CancellationToken()
            token.cancel()
            with self.assertRaises(BootPatchPlanningError) as raised:
                service.compile(
                    self.command("magisk", app.id, root / "cancelled.img"),
                    self.make_snapshot(boot),
                    token,
                )
            self.assertEqual("boot_patch_cancelled", raised.exception.code)

            compilation = service.compile(
                self.command("magisk", app.id, root / "patched.img"),
                self.make_snapshot(boot),
            )
            transport = FakeProcessTransport([TransportOutcome(1, stderr="patch failed")])
            command = self.command("magisk", app.id, root / "unused.img")
            failed = CommandExecutor(transport).execute(command, compilation.plan)
            explicit = service.finalize_result(compilation, failed)
            self.assertEqual(OperationStatus.FAILED, explicit.status)
            self.assertEqual("process_failed", explicit.code)
            self.assertEqual("patch failed", explicit.stderr)

            cancelled = OperationResult.cancelled(
                "patch-operation",
                code="cancelled",
                message="patching was cancelled",
            )
            explicit_cancelled = service.finalize_result(compilation, cancelled)
            self.assertIs(OperationStatus.CANCELLED, explicit_cancelled.status)
            self.assertEqual("cancelled", explicit_cancelled.code)


if __name__ == "__main__":
    unittest.main()
