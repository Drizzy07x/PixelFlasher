import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from pixelflasher_core.boot_patch import (
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
    OperationPlan,
    ProcessRequest,
    ProgressEvent,
    SensitiveText,
    ToolchainInfo,
)
from pixelflasher_core.executor import (
    CancellationToken,
    CommandExecutor,
    FakeProcessTransport,
    FakeTransportStep,
    SecretTransportError,
    SubprocessTransport,
    TransportOutcome,
)
from pixelflasher_core.rooting import RootAppSource, RootingService
from tests.apk_test_helpers import FakeVerifiedApkInspector


def sha256(contents: bytes) -> str:
    import hashlib

    return hashlib.sha256(contents).hexdigest()


class ApatchSecretPlanningTests(unittest.TestCase):
    def backend(self, root: Path) -> tuple[BootPatchService, AppSnapshot, str]:
        boot = root / "boot.img"
        boot.write_bytes(b"stock boot")
        apk = root / "apatch.apk"
        with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("AndroidManifest.xml", b"APatch")
            archive.writestr("classes.dex", b"dex")
        apk_bytes = apk.read_bytes()
        rooting = RootingService(
            (
                RootAppSource(
                    str(apk),
                    "APatch",
                    "stable",
                    "1.0",
                    "official",
                    sha256(apk_bytes),
                ),
            ),
            hash_chunk_size=2,
            apk_inspector=FakeVerifiedApkInspector("me.bmax.apatch"),
        )
        app = rooting.root_app_inventory()[0]
        runner = root / "apatch-runner"
        runner.write_bytes(b"apatch runner")
        service = BootPatchService(
            rooting,
            (
                PatchToolBundle(
                    "apatch",
                    app.id,
                    FileArtifact(
                        str(runner.resolve()),
                        sha256(runner.read_bytes()),
                        "patch-runner:apatch",
                    ),
                ),
            ),
            hash_chunk_size=2,
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
        return service, snapshot, app.id

    @staticmethod
    def command(
        app_id: str,
        destination: Path,
        super_key: object,
        *,
        flavor: str = "apatch",
    ) -> AppCommand:
        return AppCommand(
            "boot.patch",
            expected_revision=4,
            target_serial="SERIAL",
            operation_id="apatch-secret-test",
            payload={
                "flavor": flavor,
                "appId": app_id,
                "destination": str(destination),
                "superKey": super_key,
            },
        )

    def test_plan_contains_only_stdin_marker_and_fixed_runner_flag(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service, snapshot, app_id = self.backend(root)
            plaintext = "correct-horse-battery"
            command = self.command(
                app_id,
                root / "patched.img",
                SensitiveText(plaintext),
            )

            compilation = service.compile(command, snapshot)

            secret_requests = [
                request for request in compilation.plan.requests if request.stdin_secret_field is not None
            ]
            self.assertEqual(1, len(secret_requests))
            request = secret_requests[0]
            self.assertEqual("superKey", request.stdin_secret_field)
            self.assertEqual(1, request.argv.count("--superkey-stdin"))
            self.assertIsNone(request.env)
            serialized = json.dumps(compilation.plan.to_dict(), sort_keys=True)
            observed = "\n".join(
                (
                    repr(command),
                    repr(compilation),
                    repr(compilation.plan),
                    repr(request),
                    serialized,
                    compilation.plan.execution_fingerprint(),
                )
            )
            self.assertNotIn(plaintext, observed)
            public_payload = command.to_dict()["payload"]
            self.assertIsInstance(public_payload, dict)
            assert isinstance(public_payload, dict)
            self.assertEqual("[REDACTED]", public_payload["superKey"])

    def test_compiled_apatch_plan_delivers_secret_only_on_patch_step(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service, snapshot, app_id = self.backend(root)
            secret = SensitiveText("correct-horse")
            command = self.command(app_id, root / "patched.img", secret)
            compilation = service.compile(command, snapshot)
            steps = [
                FakeTransportStep(
                    TransportOutcome(0),
                    expected_secret=(
                        SensitiveText("correct-horse") if request.stdin_secret_field is not None else None
                    ),
                )
                for request in compilation.plan.requests
            ]
            transport = FakeProcessTransport(steps)

            result = CommandExecutor(transport).execute(command, compilation.plan)

            self.assertTrue(result.ok)
            self.assertEqual(7, len(transport.calls))
            self.assertEqual(1, len(transport.secret_calls))
            self.assertEqual(
                "superKey",
                transport.secret_calls[0].stdin_secret_field,
            )
            self.assertNotIn("correct-horse", repr(transport.calls))

    def test_superkey_policy_fails_closed_before_a_plan_is_created(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service, snapshot, app_id = self.backend(root)
            cases = (
                (None, "apatch_superkey_required"),
                ("not-opaque", "apatch_superkey_required"),
                (SensitiveText("1234567"), "apatch_superkey_invalid"),
                (SensitiveText("x" * 129), "apatch_superkey_invalid"),
                (SensitiveText("valid-key\x00tail"), "apatch_superkey_invalid"),
            )
            for index, (value, code) in enumerate(cases):
                with self.subTest(code=code, index=index):
                    command = self.command(
                        app_id,
                        root / f"patched-{index}.img",
                        value,
                    )
                    with self.assertRaises(BootPatchPlanningError) as raised:
                        service.compile(command, snapshot)
                    self.assertEqual(code, raised.exception.code)

    def test_superkey_is_rejected_for_every_non_apatch_flavor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service, snapshot, app_id = self.backend(root)
            command = self.command(
                app_id,
                root / "patched-magisk.img",
                SensitiveText("correct-horse"),
                flavor="magisk",
            )
            with self.assertRaises(BootPatchPlanningError) as raised:
                service.compile(command, snapshot)
            self.assertEqual("apatch_superkey_not_applicable", raised.exception.code)


class SecretExecutorTests(unittest.TestCase):
    @staticmethod
    def command(secret: object = SensitiveText("correct-horse")) -> AppCommand:
        return AppCommand(
            "boot.patch",
            operation_id="secret-execution",
            payload={"superKey": secret},
        )

    @staticmethod
    def plan() -> OperationPlan:
        return OperationPlan(
            ProcessRequest(
                ("runner", "patch", "--superkey-stdin"),
                stdin_secret_field="superKey",
            )
        )

    def test_fake_transport_validates_delivery_and_redacts_all_outputs(self) -> None:
        plaintext = "correct-horse"
        events: list[ProgressEvent] = []
        transport = FakeProcessTransport(
            [
                FakeTransportStep(
                    TransportOutcome(
                        0,
                        stdout=f"runner echoed {plaintext}",
                        stderr=f"warning {plaintext}",
                    ),
                    expected_secret=SensitiveText(plaintext),
                )
            ]
        )
        result = CommandExecutor(transport, events.append).execute(
            self.command(SensitiveText(plaintext)),
            self.plan(),
        )

        self.assertTrue(result.ok)
        self.assertEqual(1, len(transport.calls))
        self.assertEqual(transport.calls, transport.secret_calls)
        public_text = "\n".join(
            (
                repr(transport.calls),
                repr(transport.secret_calls),
                repr(result),
                result.stdout,
                result.stderr,
                repr(events),
            )
        )
        self.assertNotIn(plaintext, public_text)
        self.assertIn("[REDACTED]", result.stdout)
        self.assertIn("[REDACTED]", result.stderr)

    def test_missing_or_unsupported_secret_transport_fails_without_running(self) -> None:
        missing = FakeProcessTransport([TransportOutcome(0)])
        missing_result = CommandExecutor(missing).execute(
            self.command(None),
            self.plan(),
        )
        self.assertEqual("secret_material_missing", missing_result.code)
        self.assertEqual([], missing.calls)

        class PlainTransport:
            def __init__(self) -> None:
                self.calls = 0

            def run(
                self,
                request: ProcessRequest,
                cancellation: CancellationToken,
            ) -> TransportOutcome:
                del request, cancellation
                self.calls += 1
                return TransportOutcome(0)

        plain = PlainTransport()
        unsupported = CommandExecutor(plain).execute(self.command(), self.plan())
        self.assertEqual("secret_transport_unsupported", unsupported.code)
        self.assertEqual(0, plain.calls)

    def test_fake_transport_mismatch_is_explicit_and_never_records_plaintext(self) -> None:
        transport = FakeProcessTransport(
            [
                FakeTransportStep(
                    TransportOutcome(0),
                    expected_secret=SensitiveText("different-secret"),
                )
            ]
        )
        result = CommandExecutor(transport).execute(self.command(), self.plan())
        self.assertEqual("secret_verification_failed", result.code)
        self.assertNotIn("correct-horse", repr(transport))
        self.assertNotIn("different-secret", repr(transport))

    def test_subprocess_transport_uses_stdin_and_redacts_reflected_secret(self) -> None:
        plaintext = "correct-horse"
        request = ProcessRequest(
            (
                sys.executable,
                "-c",
                ("import sys; value=sys.stdin.read(); sys.stdout.write(value); sys.stderr.write(value)"),
                "--superkey-stdin",
            ),
            timeout_seconds=5,
            stdin_secret_field="superKey",
        )
        outcome = SubprocessTransport().run_secret(
            request,
            SensitiveText(plaintext),
            CancellationToken(),
        )
        self.assertEqual(0, outcome.returncode)
        self.assertEqual("[REDACTED]", outcome.stdout)
        self.assertEqual("[REDACTED]", outcome.stderr)
        self.assertNotIn(plaintext, repr(request))
        self.assertNotIn(plaintext, json.dumps(request.to_dict()))

    def test_secret_policy_and_normal_run_are_enforced_at_transport_boundary(self) -> None:
        request = self.plan().request
        transport = SubprocessTransport()
        with self.assertRaises(SecretTransportError) as normal:
            transport.run(request, CancellationToken())
        self.assertEqual("secret_transport_required", normal.exception.code)
        with self.assertRaises(SecretTransportError) as invalid:
            transport.run_secret(
                request,
                SensitiveText("short"),
                CancellationToken(),
            )
        self.assertEqual("secret_material_invalid", invalid.exception.code)

    def test_sensitive_text_closed_policy_and_public_forms_remain_redacted(self) -> None:
        plaintext = "correct-horse"
        secret = SensitiveText(plaintext)
        self.assertTrue(secret.meets_policy(8, 128))
        self.assertFalse(SensitiveText("short").meets_policy(8, 128))
        self.assertFalse(SensitiveText("valid-key\x00tail").meets_policy(8, 128))
        self.assertTrue(secret.same_value(SensitiveText(plaintext)))
        self.assertFalse(secret.same_value(SensitiveText("different-secret")))
        self.assertEqual("SensitiveText([REDACTED])", repr(secret))
        self.assertEqual("[REDACTED]", str(secret))
        self.assertEqual("before [REDACTED] after", secret.redact(f"before {plaintext} after"))
        self.assertNotIn(plaintext, repr(self.command(secret)))
        public_payload = self.command(secret).to_dict()["payload"]
        self.assertIsInstance(public_payload, dict)
        assert isinstance(public_payload, dict)
        self.assertEqual(
            "[REDACTED]",
            public_payload["superKey"],
        )


if __name__ == "__main__":
    unittest.main()
