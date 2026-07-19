import hashlib
import json
import tempfile
import threading
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    AppStateStore,
    BootInfo,
    CommandExecutor,
    DeviceInfo,
    FakeProcessTransport,
    FakeTransportStep,
    FileArtifact,
    GrantAccess,
    InteractionDecision,
    OperationStatus,
    PatchToolBundle,
    RootAppSource,
    RootingService,
    SafetyPolicy,
    ToolchainInfo,
    TransportOutcome,
)
from tests.apk_test_helpers import FakeVerifiedApkInspector
from tests.artifact_stage_assertions import assert_exact_or_staged_argv
from tests.command_engine_factory import make_test_command_engine as CommandEngine
from tests.stateful_postcondition_observer import StatefulPostconditionObserver
from ui.bridge_contract import BRIDGE_VERSION, BridgeProtocolError, BridgeRequest
from ui.core_command_factory import create_command_factory


def sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def write_apk(path: Path) -> bytes:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", b"Magisk")
        archive.writestr("classes.dex", b"dex")
    return path.read_bytes()


class PatchOutputTransport(FakeProcessTransport):
    def __init__(self, output_path: Path, output: bytes = b"patched boot") -> None:
        super().__init__([TransportOutcome(0) for _ in range(7)])
        self.output_path = output_path
        self.output = output

    def run(self, request, cancellation):
        outcome = super().run(request, cancellation)
        if (
            outcome.returncode == 0
            and not outcome.cancelled
            and not outcome.timed_out
            and len(request.argv) > 3
            and request.argv[3] == "pull"
        ):
            self.output_path.write_bytes(self.output)
        return outcome


class BootPatchEngineIntegrationTests(unittest.TestCase):
    def backend(self, root: Path):
        boot = root / "boot.img"
        boot.write_bytes(b"stock boot")
        apk = root / "magisk.apk"
        apk_contents = write_apk(apk)
        rooting = RootingService(
            (
                RootAppSource(
                    str(apk),
                    "Magisk",
                    "stable",
                    "1.0",
                    "official",
                    sha256(apk_contents),
                ),
            ),
            hash_chunk_size=2,
            apk_inspector=FakeVerifiedApkInspector("com.topjohnwu.magisk"),
        )
        app = rooting.root_app_inventory()[0]
        runner = root / "magisk-runner"
        runner.write_bytes(b"backend runner")
        bundle = PatchToolBundle(
            "magisk",
            app.id,
            FileArtifact(
                str(runner.resolve()),
                sha256(runner.read_bytes()),
                "patch-runner:magisk",
            ),
        )
        snapshot = AppSnapshot(
            revision=4,
            devices=(DeviceInfo("SERIAL", mode="adb", online=True),),
            selected_serial="SERIAL",
            boot=BootInfo(
                "stock",
                str(boot.resolve()),
                sha256(boot.read_bytes()),
                "boot",
                False,
            ),
            toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
        )
        return snapshot, rooting, app, bundle, runner

    @staticmethod
    def command(app_id: str, destination: Path, *, operation_id: str = "patch-op"):
        return AppCommand(
            "boot.patch",
            expected_revision=4,
            target_serial="SERIAL",
            operation_id=operation_id,
            payload={
                "flavor": "magisk",
                "appId": app_id,
                "destination": str(destination),
            },
        )

    def engine(self, snapshot, rooting, bundle, transport, interaction_handler=None):
        return CommandEngine(
            store=AppStateStore(snapshot),
            executor=CommandExecutor(transport),
            postcondition_observer=StatefulPostconditionObserver(transport),
            interaction_handler=(
                interaction_handler
                if interaction_handler is not None
                else lambda _request: InteractionDecision.ACCEPTED
            ),
            rooting_service=rooting,
            boot_patch_bundles=(bundle,),
        )

    def test_backend_bundle_executes_and_finalize_result_verifies_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, rooting, app, bundle, _runner = self.backend(root)
            destination = root / "patched.img"
            transport = PatchOutputTransport(destination)
            engine = self.engine(snapshot, rooting, bundle, transport)
            self.assertIs(rooting, engine.boot_patch_service.rooting_service)
            finalized_statuses = []
            original = engine.boot_patch_service.finalize_result

            def finalize(compilation, result, cancellation=None):
                finalized_statuses.append((result.status, cancellation is not None))
                return original(compilation, result, cancellation)

            engine.boot_patch_service.finalize_result = finalize
            result = engine.execute(self.command(app.id, destination))

            self.assertTrue(result.ok)
            self.assertEqual("boot_patched", result.code)
            self.assertEqual(7, len(transport.calls))
            self.assertEqual(
                sha256(b"patched boot"),
                result.value["patchedBoot"]["artifact"]["sha256"],
            )
            self.assertEqual(
                [(OperationStatus.SUCCESS, True)],
                finalized_statuses,
            )
            canonical = engine.store.snapshot()
            self.assertEqual(6, canonical.revision)
            self.assertIsNone(canonical.active_operation)
            self.assertEqual(result, canonical.last_result)
            self.assertTrue(canonical.boot.patched)
            self.assertEqual(str(destination.resolve()), canonical.boot.path)
            self.assertEqual(sha256(b"patched boot"), canonical.boot.hash)
            self.assertEqual("boot", canonical.boot.flavor)

    def test_magisk_init_boot_output_preserves_partition_in_canonical_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, rooting, app, bundle, _runner = self.backend(root)
            snapshot = AppSnapshot(
                revision=snapshot.revision,
                devices=snapshot.devices,
                selected_serial=snapshot.selected_serial,
                boot=BootInfo(
                    snapshot.boot.id,
                    snapshot.boot.path,
                    snapshot.boot.hash,
                    "init_boot",
                    False,
                ),
                toolchain=snapshot.toolchain,
            )
            destination = root / "patched-init-boot.img"
            transport = PatchOutputTransport(destination)
            engine = self.engine(
                snapshot,
                rooting,
                bundle,
                transport,
            )

            result = engine.execute(self.command(app.id, destination))

            self.assertTrue(result.ok)
            self.assertEqual("init_boot", result.value["boot"]["flavor"])
            self.assertEqual("init_boot", engine.store.snapshot().boot.flavor)

            # A later device scan can move the same selected serial into
            # fastboot without replacing the verified patched artifact.
            engine.store.update(
                expected_revision=6,
                devices=(DeviceInfo("SERIAL", mode="fastboot", online=True, bootloader="unlocked"),),
            )
            transport.enqueue(TransportOutcome(0))
            flashed = engine.execute(
                AppCommand(
                    "boot.flash",
                    expected_revision=7,
                    target_serial="SERIAL",
                    operation_id="flash-patched-init-boot",
                )
            )

            self.assertTrue(flashed.ok)
            assert_exact_or_staged_argv(
                self,
                [(
                    "FASTBOOT",
                    "-s",
                    "SERIAL",
                    "flash",
                    "init_boot",
                    str(destination.resolve()),
                )],
                [transport.calls[-1]],
            )

    def test_missing_backend_bundle_fails_closed_without_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, rooting, app, _bundle, _runner = self.backend(root)
            transport = FakeProcessTransport()
            engine = CommandEngine(
                store=AppStateStore(snapshot),
                executor=CommandExecutor(transport),
                interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
                rooting_service=rooting,
            )

            result = engine.execute(self.command(app.id, root / "patched.img"))

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("patch_runner_unavailable", result.code)
            self.assertEqual([], transport.calls)
            self.assertEqual(snapshot.boot, engine.store.snapshot().boot)

    def test_finalize_failure_closes_operation_without_promoting_stock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, rooting, app, bundle, _runner = self.backend(root)
            transport = FakeProcessTransport([TransportOutcome(0) for _ in range(7)])
            engine = self.engine(snapshot, rooting, bundle, transport)

            result = engine.execute(self.command(app.id, root / "missing.img"))

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("patch_output_missing", result.code)
            canonical = engine.store.snapshot()
            self.assertIsNone(canonical.active_operation)
            self.assertEqual(snapshot.boot, canonical.boot)
            self.assertEqual(result, canonical.last_result)

    def test_revision_and_artifact_hash_are_revalidated_after_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, rooting, app, bundle, _runner = self.backend(root)
            store = AppStateStore(snapshot)
            transport = FakeProcessTransport()

            def change_revision(_request):
                store.update(expected_revision=4, firmware=snapshot.firmware)
                return InteractionDecision.ACCEPTED

            engine = CommandEngine(
                store=store,
                executor=CommandExecutor(transport),
                interaction_handler=change_revision,
                rooting_service=rooting,
                boot_patch_bundles=(bundle,),
            )
            result = engine.execute(self.command(app.id, root / "stale.img"))
            self.assertEqual("snapshot_revision_changed", result.code)
            self.assertEqual([], transport.calls)
            self.assertEqual(snapshot.boot, engine.store.snapshot().boot)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, rooting, app, bundle, runner = self.backend(root)
            transport = FakeProcessTransport()

            def change_runner(_request):
                runner.write_bytes(b"tampered runner")
                return InteractionDecision.ACCEPTED

            engine = self.engine(
                snapshot,
                rooting,
                bundle,
                transport,
                interaction_handler=change_runner,
            )
            result = engine.execute(self.command(app.id, root / "tampered.img"))
            self.assertEqual("artifact_hash_mismatch", result.code)
            self.assertEqual([], transport.calls)
            self.assertEqual(snapshot.boot, engine.store.snapshot().boot)

    def test_process_cancellation_after_boundary_is_an_unknown_outcome(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, rooting, app, bundle, _runner = self.backend(root)
            destination = root / "cancelled.img"
            started = threading.Event()
            release = threading.Event()
            transport = FakeProcessTransport(
                [
                    FakeTransportStep(
                        TransportOutcome(0),
                        started_event=started,
                        release_event=release,
                    ),
                    *[TransportOutcome(0) for _ in range(6)],
                ]
            )
            engine = self.engine(snapshot, rooting, bundle, transport)
            seen = []
            original = engine.boot_patch_service.finalize_result

            def finalize(compilation, result, cancellation=None):
                seen.append(result.status)
                return original(compilation, result, cancellation)

            engine.boot_patch_service.finalize_result = finalize
            intent = self.command(app.id, destination, operation_id="cancel-process")
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(engine.execute, intent)
                self.assertTrue(started.wait(5))
                self.assertTrue(engine.cancel(intent.operation_id))
                release.set()
                result = future.result(timeout=5)

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("outcome_unknown", result.code)
            self.assertEqual([OperationStatus.CANCELLED], seen)
            self.assertFalse(engine.cancel(intent.operation_id))
            self.assertEqual(snapshot.boot, engine.store.snapshot().boot)

    def test_planning_hash_can_be_cancelled_through_engine(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, rooting, app, bundle, _runner = self.backend(root)
            transport = FakeProcessTransport()
            engine = self.engine(snapshot, rooting, bundle, transport)
            started = threading.Event()

            def cancellable_hash(_path, cancellation):
                started.set()
                self.assertIsNotNone(cancellation)
                while not cancellation.cancelled:
                    cancellation.wait(0.01)
                engine.boot_patch_service._check_cancelled(cancellation)
                raise AssertionError("unreachable")

            engine.boot_patch_service._sha256 = cancellable_hash
            intent = self.command(
                app.id,
                root / "cancel-planning.img",
                operation_id="cancel-planning",
            )
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(engine.execute, intent)
                self.assertTrue(started.wait(5))
                self.assertTrue(engine.cancel(intent.operation_id))
                result = future.result(timeout=5)

            self.assertEqual(OperationStatus.CANCELLED, result.status)
            self.assertEqual("boot_patch_cancelled", result.code)
            self.assertEqual([], transport.calls)
            self.assertFalse(engine.cancel(intent.operation_id))
            self.assertEqual(snapshot.boot, engine.store.snapshot().boot)

    def test_bridge_and_factory_allow_only_semantic_patch_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            factory = create_command_factory(lambda: AppSnapshot(revision=4, selected_serial="SERIAL"))
            grant = factory.path_grants.issue_file(
                Path(directory) / "patched.img",
                purpose="boot.patch.destination",
                access=GrantAccess.WRITE,
            )
            allowed = BridgeRequest.from_json(
                json.dumps(
                    {
                        "version": BRIDGE_VERSION,
                        "requestId": "boot-patch",
                        "command": "boot.patch",
                        "payload": {
                            "serial": "SERIAL",
                            "method": "magisk",
                            "appId": "0" * 64,
                            "grant": grant.token,
                        },
                        "expectedRevision": 4,
                    }
                )
            )
            command = factory(allowed)
            self.assertEqual("SERIAL", command.target_serial)
            self.assertFalse(command.destructive)
            self.assertTrue(command.requires_confirmation)
            self.assertEqual(
                str((Path(directory) / "patched.img").resolve()),
                command.payload["destination"],
            )
            self.assertIn("boot.patch", SafetyPolicy().revisioned_kinds)

            for field in ("destination", "runnerPath", "runnerSha256", "supportArtifacts", "argv"):
                with self.subTest(field=field):
                    payload = dict(allowed.payload)
                    payload[field] = "browser-controlled"
                    message = {
                        "version": BRIDGE_VERSION,
                        "requestId": f"reject-{field}",
                        "command": "boot.patch",
                        "payload": payload,
                        "expectedRevision": 4,
                    }
                    with self.assertRaises(BridgeProtocolError) as raised:
                        BridgeRequest.from_json(json.dumps(message))
                    self.assertEqual("invalid_payload", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
