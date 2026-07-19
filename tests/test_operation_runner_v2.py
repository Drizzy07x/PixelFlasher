import hashlib
import threading
import time
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from pixelflasher_core.contracts import (
    AppCommand,
    AppSnapshot,
    BootInfo,
    DeviceInfo,
    FileArtifact,
    FirmwareInfo,
    FlashPlan,
    OperationBatch,
    OperationPlan,
    OperationPostcondition,
    OperationResult,
    OperationRisk,
    OperationStatus,
    ProcessRequest,
    SensitiveText,
    ToolchainInfo,
    confirmation_serial_suffix,
)
from pixelflasher_core.executor import (
    CancellationToken,
    CommandExecutor,
    FakeProcessTransport,
    FakeTransportStep,
    TransportOutcome,
)
from pixelflasher_core.observer import DeviceObservation, PostconditionObserver
from pixelflasher_core.operation_runner import ExecutionBoundaryAck, OperationRunner
from pixelflasher_core.planner import OperationPlanner, ProcessedArtifactRepository
from pixelflasher_core.safety import SafetyPolicy

NOW = 1_800_000_000.0


def snapshot_for(
    serial="ABCDEF123456",
    *,
    revision=7,
    mode="fastboot",
    slot="a",
    bootloader="unlocked",
):
    return AppSnapshot(
        revision=revision,
        devices=(
            DeviceInfo(
                serial,
                codename="akita",
                mode=mode,
                slot=slot,
                bootloader=bootloader,
                online=True,
            ),
        ),
        selected_serial=serial,
        firmware=FirmwareInfo(hash="F1"),
        boot=BootInfo(hash="B1"),
        plan=FlashPlan(revision=3, fingerprint="P1", dry_run=False),
        toolchain=ToolchainInfo("ADB", "FASTBOOT", "36", True),
    )


def destructive_plan(serial="ABCDEF123456", *, now=NOW, postcondition=None):
    condition = postcondition or OperationPostcondition("active_slot", {"slot": "b"})
    plan = OperationPlan(
        request=ProcessRequest(("FASTBOOT", "-s", serial, "--set-active=b")),
        created=now,
        expires=now + 300,
        risk=OperationRisk.DESTRUCTIVE,
        postconditions=(condition,),
        snapshot_revision=7,
        target_serial=serial,
        expected_device_state="fastboot",
        firmware_hash="F1",
        boot_hash="B1",
        slots=("b",),
        data_behavior="switch",
        plan_revision=3,
        fingerprint="P1",
        confirmation_nonce="nonce",
    )
    return replace(plan, confirmation_token=plan.confirmation_challenge())


def read_only_plan(serial="ABCDEF123456", *, now=NOW):
    return OperationPlan(
        request=ProcessRequest(("ADB", "-s", serial, "get-state")),
        created=now,
        expires=now + 300,
        risk=OperationRisk.READ_ONLY,
        snapshot_revision=7,
        target_serial=serial,
        expected_device_state="fastboot",
        firmware_hash="F1",
        boot_hash="B1",
        data_behavior="preserve",
        plan_revision=3,
        fingerprint="P1",
    )


def confirmed_batch(*plans):
    batch = OperationBatch(plans, created=NOW, expires=NOW + 300)
    batch = replace(batch, confirmation_nonce="batch-nonce")
    return replace(batch, confirmation_token=batch.confirmation_challenge())


class OperationPlanV2Tests(unittest.TestCase):
    def test_plan_has_five_minute_lifecycle_risk_and_secret_free_postconditions(self):
        plan = destructive_plan()

        self.assertEqual(300, plan.expires - plan.created)
        self.assertEqual(plan.plan_id, plan.planId)
        self.assertEqual(OperationRisk.DESTRUCTIVE, plan.risk)
        self.assertEqual("active_slot", plan.postconditions[0].kind)
        self.assertIsNone(plan.to_dict()["confirmation_token"])
        self.assertNotIn(plan.confirmation_token, str(plan.to_dict()))
        with self.assertRaises(FrozenInstanceError):
            plan.expires = NOW + 600
        with self.assertRaises(ValueError):
            OperationPlan(
                request=ProcessRequest(("adb", "devices")),
                created=NOW,
                expires=NOW + 301,
            )
        with self.assertRaises(ValueError):
            OperationPostcondition(
                "wifi",
                {"pairingCode": SensitiveText("123456")},
            )
        with self.assertRaises(ValueError):
            confirmation_serial_suffix("")

    def test_safety_rejects_every_v2_binding_change_and_expiration(self):
        snapshot = snapshot_for()
        plan = destructive_plan()
        policy = SafetyPolicy(clock=lambda: NOW + 1)

        cases = {
            "plan_expired": replace(plan, created=NOW - 301, expires=NOW - 1),
            "snapshot_revision_changed": replace(plan, snapshot_revision=6),
            "firmware_hash_changed": replace(plan, firmware_hash="F2"),
            "boot_hash_changed": replace(plan, boot_hash="B2"),
            "plan_revision_changed": replace(plan, plan_revision=2),
            "plan_fingerprint_changed": replace(plan, fingerprint="P2"),
            "target_serial_changed": replace(plan, target_serial="OTHER"),
        }
        for expected, changed in cases.items():
            if changed.confirmation_nonce:
                changed = replace(changed, confirmation_token=changed.confirmation_challenge())
            command = AppCommand(
                "flash.execute",
                expected_revision=7,
                target_serial=changed.target_serial,
                operation_plan=changed,
                destructive=True,
            )
            with self.subTest(expected=expected):
                decision = policy.evaluate(command, snapshot)
                self.assertFalse(decision.allowed)
                self.assertEqual(expected, decision.code)

    def test_confirmation_phrases_use_real_serial_suffixes_and_batch_fingerprint(self):
        planner = OperationPlanner(
            confirmation_secret=b"x" * 32,
            clock=lambda: NOW,
        )
        snapshot = snapshot_for()
        actions = (
            ("flash.execute", "wipe", (), (), "WIPE 123456"),
            ("device.bootloader.lock", "wipe_lock", (), (), "LOCK 123456"),
            ("device.bootloader.unlock", "wipe_unlock", (), (), "UNLOCK 123456"),
            ("partitions.erase", "erase", ("userdata",), (), "ERASE userdata 123456"),
            ("device.switchSlot", "switch", (), ("b",), "SLOT b 123456"),
        )
        for kind, behavior, partitions, slots, expected in actions:
            plan = replace(
                destructive_plan(),
                data_behavior=behavior,
                partitions=partitions,
                slots=slots,
                confirmation_nonce=None,
                confirmation_token=None,
            )
            compilation = planner.bind_reinforced_confirmation(
                AppCommand(kind, expected_revision=7, target_serial=plan.target_serial),
                snapshot,
                plan,
                destructive=True,
                requires_confirmation=True,
                preview=True,
            )
            with self.subTest(kind=kind):
                self.assertEqual(expected, compilation.confirmation_text)

        second = replace(
            destructive_plan("ZYXWVU654321"),
            confirmation_nonce=None,
            confirmation_token=None,
        )
        batch = OperationBatch((destructive_plan(), second), created=NOW, expires=NOW + 300)
        self.assertEqual(
            f"FLASH 2 {batch.fingerprint[:8]}",
            batch.required_confirmation_text(),
        )
        changed = OperationBatch(
            (second, destructive_plan()),
            created=NOW,
            expires=NOW + 300,
        )
        self.assertNotEqual(batch.fingerprint, changed.fingerprint)

    def test_planner_compiles_one_stable_confirmed_flash_plan_per_serial(self):
        with TemporaryDirectory() as directory:
            image = Path(directory) / "boot.img"
            image.write_bytes(b"boot")
            digest = hashlib.sha256(image.read_bytes()).hexdigest()
            repository = ProcessedArtifactRepository()
            repository.register(
                (FileArtifact(str(image.resolve()), digest, "partition:boot"),),
                plan_fingerprint="P1",
            )
            serials = ("ABCDEF123456", "ZYXWVU654321")
            snapshot = AppSnapshot(
                revision=7,
                devices=tuple(
                    DeviceInfo(
                        serial,
                        codename="akita",
                        mode="fastboot",
                        bootloader="unlocked",
                        online=True,
                    )
                    for serial in serials
                ),
                selected_serials=serials,
                selected_serial=serials[0],
                firmware=FirmwareInfo(hash="F1"),
                boot=BootInfo(hash="B1"),
                plan=FlashPlan(
                    "images",
                    {"verify": True},
                    revision=3,
                    fingerprint="P1",
                    dry_run=False,
                ),
                toolchain=ToolchainInfo("ADB", "FASTBOOT", "36", True),
            )
            planner = OperationPlanner(
                artifact_repository=repository,
                confirmation_secret=b"z" * 32,
                clock=lambda: NOW,
            )
            preview = planner.compile_batch(
                AppCommand("flash.execute", expected_revision=7),
                snapshot,
                preview=True,
            )
            execution = planner.compile_batch(
                AppCommand(
                    "flash.execute",
                    expected_revision=7,
                    payload={"confirmationText": preview.confirmation_text},
                ),
                snapshot,
            )

            self.assertTrue(preview.ok)
            self.assertEqual(
                f"FLASH 2 {preview.batch.fingerprint[:8]}",
                preview.confirmation_text,
            )
            self.assertTrue(execution.ok)
            self.assertEqual(preview.batch.fingerprint, execution.batch.fingerprint)
            self.assertTrue(execution.batch.reinforced_confirmation_valid)
            self.assertEqual(serials, execution.batch.target_serials)
            self.assertTrue(all(plan.risk is OperationRisk.DESTRUCTIVE for plan in execution.batch.plans))


class OperationRunnerStatefulTests(unittest.TestCase):
    def test_push_staging_never_rewrites_an_equal_remote_destination(self):
        remote_path = "/data/local/tmp/payload.bin"
        request = ProcessRequest(
            ("adb", "-s", "SERIAL", "push", remote_path, remote_path)
        )

        staged = OperationRunner._rewrite_staged_request(
            request,
            {remote_path: "C:/private-stage/payload.bin"},
            {remote_path: {"push-source"}},
        )

        self.assertEqual("C:/private-stage/payload.bin", staged.argv[-2])
        self.assertEqual(remote_path, staged.argv[-1])

    def runner(self, transport, *, provider=None, observer=None):
        return OperationRunner(
            CommandExecutor(transport),
            safety_policy=SafetyPolicy(clock=lambda: NOW + 1),
            snapshot_provider=provider,
            postcondition_observer=observer,
        )

    def command_for(self, plan, operation_id="op"):
        return AppCommand(
            "flash.execute",
            expected_revision=7,
            target_serial=plan.target_serial,
            operation_plan=plan,
            operation_id=operation_id,
            destructive=True,
            requires_confirmation=True,
        )

    def test_success_requires_observed_postcondition_and_never_retries_failure(self):
        plan = destructive_plan()
        snapshot = snapshot_for(slot="b")
        success_transport = FakeProcessTransport([TransportOutcome(0)])
        observed = []
        runner = self.runner(
            success_transport,
            provider=lambda _serial: snapshot,
            observer=lambda _plan, condition, _snapshot: observed.append(condition.kind) or True,
        )

        success = runner.execute(self.command_for(plan), plan)

        self.assertEqual(OperationStatus.SUCCESS, success.status)
        self.assertEqual("postconditions_satisfied", success.code)
        self.assertEqual(["active_slot"], observed)

        failure_transport = FakeProcessTransport([TransportOutcome(9, stderr="failed"), TransportOutcome(0)])
        failed = self.runner(
            failure_transport,
            provider=lambda _serial: snapshot,
            observer=lambda *_args: True,
        ).execute(self.command_for(plan, "fail"), plan)
        self.assertEqual(OperationStatus.FAILED, failed.status)
        self.assertEqual("process_failed", failed.code)
        self.assertEqual(1, len(failure_transport.calls))

        unverified = self.runner(
            FakeProcessTransport([TransportOutcome(0)]),
            provider=lambda _serial: snapshot_for(slot="a"),
        ).execute(self.command_for(plan, "unverified"), plan)
        self.assertEqual(OperationStatus.FAILED, unverified.status)
        self.assertEqual("postcondition_unverified", unverified.code)

        no_evidence_plan = replace(
            plan,
            postconditions=(OperationPostcondition("partition_written", {"partition": "boot"}),),
            confirmation_token=None,
        )
        no_evidence_plan = replace(
            no_evidence_plan,
            confirmation_token=no_evidence_plan.confirmation_challenge(),
        )
        no_evidence = self.runner(
            FakeProcessTransport([TransportOutcome(0)]),
            provider=lambda _serial: snapshot,
        ).execute(
            self.command_for(no_evidence_plan, "no-evidence"),
            no_evidence_plan,
        )
        self.assertEqual(OperationStatus.FAILED, no_evidence.status)
        self.assertEqual("postcondition_unverified", no_evidence.code)

    def test_core_polling_observer_is_adapted_without_weakening_result_codes(self):
        class Timer:
            now = 0.0

            def clock(self):
                return self.now

            def sleep(self, seconds):
                self.now += seconds

        class Probe:
            def __init__(self, slot):
                self.slot = slot

            def observe(self, serial):
                return DeviceObservation(serial, mode="fastboot", slot=self.slot)

        class DisconnectedProbe:
            def observe(self, serial):
                return DeviceObservation(serial, connected=False)

        plan = destructive_plan()
        snapshot = snapshot_for()

        def run_with(slot, operation_id):
            timer = Timer()
            observer = PostconditionObserver(
                Probe(slot),
                poll_interval_seconds=1,
                clock=timer.clock,
                sleeper=timer.sleep,
            )
            runner = OperationRunner(
                CommandExecutor(FakeProcessTransport([TransportOutcome(0)])),
                safety_policy=SafetyPolicy(clock=lambda: NOW + 1),
                snapshot_provider=lambda _serial: snapshot,
                postcondition_observer=observer,
                postcondition_timeout_seconds=2,
            )
            return runner.execute(self.command_for(plan, operation_id), plan)

        verified = run_with("b", "verified")
        mismatched = run_with("a", "mismatched")
        unavailable = run_with(None, "unavailable")

        timer = Timer()
        disconnected = OperationRunner(
            CommandExecutor(FakeProcessTransport([TransportOutcome(0)])),
            safety_policy=SafetyPolicy(clock=lambda: NOW + 1),
            snapshot_provider=lambda _serial: snapshot,
            postcondition_observer=PostconditionObserver(
                DisconnectedProbe(),
                poll_interval_seconds=1,
                clock=timer.clock,
                sleeper=timer.sleep,
            ),
            postcondition_timeout_seconds=2,
        )
        lost = disconnected.execute(self.command_for(plan, "disconnected"), plan)

        self.assertEqual(OperationStatus.SUCCESS, verified.status)
        self.assertEqual("postconditions_satisfied", verified.code)
        self.assertEqual("postcondition_mismatch", mismatched.code)
        self.assertEqual("postcondition_unverified", unavailable.code)
        self.assertEqual("outcome_unknown", lost.code)
        self.assertEqual(False, lost.value["safetyObservation"]["connected"])

    def test_extended_mutation_postconditions_compile_to_typed_probe_evidence(self):
        runner = self.runner(
            FakeProcessTransport(),
            provider=lambda _serial: snapshot_for(),
            observer=lambda *_args: True,
        )
        plan = replace(
            destructive_plan(),
            postconditions=(
                OperationPostcondition("live_boot_active", {"sha256": "a" * 64}),
                OperationPostcondition(
                    "root_app_installed",
                    {"packageName": "com.topjohnwu.magisk"},
                ),
                OperationPostcondition(
                    "root_module_state",
                    {"moduleId": "play_integrity_fix", "state": "enabled"},
                ),
                OperationPostcondition("safe_mode_active", {"active": True}),
                OperationPostcondition(
                    "partition_erased",
                    {"partition": "metadata"},
                ),
            ),
        )

        spec = runner._postcondition_spec(plan)

        self.assertEqual("adb", spec.expected_mode)
        self.assertIs(True, spec.expected_boot_completed)
        self.assertIs(True, spec.expected_safe_mode)
        self.assertEqual(
            {"com.topjohnwu.magisk": True},
            dict(spec.expected_packages),
        )
        self.assertEqual(
            {"play_integrity_fix": "enabled"},
            dict(spec.expected_root_modules),
        )
        self.assertEqual(("metadata",), spec.erased_partitions)

    def test_host_artifact_postcondition_requires_a_new_verified_file(self):
        snapshot = snapshot_for(slot="b")
        source = b"stock boot image"
        patched = b"patched boot image"
        source_digest = hashlib.sha256(source).hexdigest()

        with TemporaryDirectory() as directory:
            output = (Path(directory) / "patched.img").resolve()

            def plan_for_output():
                candidate = replace(
                    destructive_plan(),
                    postconditions=(
                        OperationPostcondition(
                            "host_artifact_written",
                            {
                                "path": str(output),
                                "sourceSha256": source_digest,
                                "requireDifferentSha256": True,
                                "minimumBytes": 1,
                            },
                        ),
                    ),
                    confirmation_token=None,
                )
                return replace(
                    candidate,
                    confirmation_token=candidate.confirmation_challenge(),
                )

            def write_patched(command, _plan, _cancellation):
                output.write_bytes(patched)
                return OperationResult.success(
                    command.operation_id,
                    code="boot_patched",
                )

            verified_plan = plan_for_output()
            verified = self.runner(
                FakeProcessTransport(),
                provider=lambda _serial: snapshot,
                observer=lambda *_args: True,
            ).execute(
                self.command_for(verified_plan, "host-verified"),
                verified_plan,
                operation_executor=write_patched,
            )

            self.assertTrue(verified.ok)
            self.assertEqual("boot_patched", verified.code)

            output.write_bytes(source)
            unchanged_plan = plan_for_output()
            unchanged = self.runner(
                FakeProcessTransport(),
                provider=lambda _serial: snapshot,
                observer=lambda *_args: True,
            ).execute(
                self.command_for(unchanged_plan, "host-unchanged"),
                unchanged_plan,
                operation_executor=lambda command, _plan, _cancellation: OperationResult.success(
                    command.operation_id,
                    code="boot_patched",
                ),
            )

            self.assertEqual(OperationStatus.FAILED, unchanged.status)
            self.assertEqual("postcondition_mismatch", unchanged.code)

            output.unlink()
            missing_plan = plan_for_output()
            missing = self.runner(
                FakeProcessTransport(),
                provider=lambda _serial: snapshot,
                observer=lambda *_args: True,
            ).execute(
                self.command_for(missing_plan, "host-missing"),
                missing_plan,
                operation_executor=lambda command, _plan, _cancellation: OperationResult.success(
                    command.operation_id,
                    code="boot_patched",
                ),
            )

            self.assertEqual(OperationStatus.FAILED, missing.status)
            self.assertEqual("postcondition_mismatch", missing.code)

    def test_wifi_pairing_requires_typed_or_unambiguous_protocol_evidence(self):
        endpoint = "192.0.2.4:37001"
        snapshot = snapshot_for(slot="b")
        candidate = replace(
            destructive_plan(),
            postconditions=(
                OperationPostcondition(
                    "adb_wifi_pairing_recorded",
                    {"endpoint": endpoint},
                ),
            ),
            confirmation_token=None,
        )
        plan = replace(
            candidate,
            confirmation_token=candidate.confirmation_challenge(),
        )

        typed = self.runner(
            FakeProcessTransport(),
            provider=lambda _serial: snapshot,
            observer=lambda *_args: True,
        ).execute(
            self.command_for(plan, "pair-typed"),
            plan,
            operation_executor=lambda command, _plan, _cancellation: OperationResult.success(
                command.operation_id,
                code="wifi_pair_succeeded",
                value={"protocolVerified": True, "endpoint": endpoint},
            ),
        )
        ambiguous = self.runner(
            FakeProcessTransport(),
            provider=lambda _serial: snapshot,
            observer=lambda *_args: True,
        ).execute(
            self.command_for(plan, "pair-ambiguous"),
            plan,
            operation_executor=lambda command, _plan, _cancellation: OperationResult.success(
                command.operation_id,
                code="process_succeeded",
                stdout=f"Successfully paired to {endpoint}\nerror: authentication failed",
            ),
        )

        self.assertTrue(typed.ok)
        self.assertEqual("wifi_pair_succeeded", typed.code)
        self.assertEqual(OperationStatus.FAILED, ambiguous.status)
        self.assertEqual("postcondition_mismatch", ambiguous.code)

    def test_remote_file_hashes_compile_into_observer_spec(self):
        digest = "a" * 64
        plan = replace(
            destructive_plan(),
            postconditions=(
                OperationPostcondition(
                    "remote_files_written",
                    {"mode": "adb", "hashes": {"/sdcard/update.zip": digest}},
                ),
            ),
        )

        spec = self.runner(
            FakeProcessTransport(),
            provider=lambda _serial: snapshot_for(),
            observer=lambda *_args: True,
        )._postcondition_spec(plan)

        self.assertEqual("adb", spec.expected_mode)
        self.assertEqual({"/sdcard/update.zip": digest}, dict(spec.remote_hashes))

    def test_package_clear_requires_exact_success_records_before_device_observation(self):
        packages = ("com.example.alpha", "com.example.beta")
        candidate = replace(
            destructive_plan(),
            postconditions=(
                OperationPostcondition(
                    "package_data_cleared",
                    {"packages": packages, "successCount": len(packages)},
                ),
                OperationPostcondition(
                    "package_state",
                    {"packages": packages, "state": "installed"},
                ),
            ),
            confirmation_token=None,
        )
        plan = replace(candidate, confirmation_token=candidate.confirmation_challenge())
        snapshot = snapshot_for(slot="b")
        observed: list[str] = []

        verified = self.runner(
            FakeProcessTransport(),
            provider=lambda _serial: snapshot,
            observer=lambda _plan, condition, _snapshot: observed.append(condition.kind) or True,
        ).execute(
            self.command_for(plan, "clear-verified"),
            plan,
            operation_executor=lambda command, _plan, _cancellation: OperationResult.success(
                command.operation_id,
                code="process_succeeded",
                stdout="Success\nSuccess\n",
            ),
        )
        ambiguous = self.runner(
            FakeProcessTransport(),
            provider=lambda _serial: snapshot,
            observer=lambda *_args: True,
        ).execute(
            self.command_for(plan, "clear-ambiguous"),
            plan,
            operation_executor=lambda command, _plan, _cancellation: OperationResult.success(
                command.operation_id,
                code="process_succeeded",
                stdout="Success\nFailure\n",
            ),
        )

        self.assertTrue(verified.ok)
        self.assertEqual(["package_state"], observed)
        self.assertEqual(OperationStatus.FAILED, ambiguous.status)
        self.assertEqual("postcondition_mismatch", ambiguous.code)

    def test_cancellation_before_mutation_is_cancelled_after_boundary_is_unknown(self):
        plan = destructive_plan()
        snapshot = snapshot_for()
        before_transport = FakeProcessTransport([TransportOutcome(0)])
        before = CancellationToken()
        before.cancel()

        cancelled = self.runner(
            before_transport,
            provider=lambda _serial: snapshot,
            observer=lambda *_args: True,
        ).execute(self.command_for(plan, "before"), plan, cancellation=before)

        self.assertEqual(OperationStatus.CANCELLED, cancelled.status)
        self.assertEqual([], before_transport.calls)

        started = threading.Event()
        release = threading.Event()
        after_transport = FakeProcessTransport([FakeTransportStep(TransportOutcome(0), started, release)])
        after = CancellationToken()
        results = []
        worker = threading.Thread(
            target=lambda: results.append(
                self.runner(
                    after_transport,
                    provider=lambda _serial: snapshot,
                    observer=lambda *_args: True,
                ).execute(self.command_for(plan, "after"), plan, cancellation=after)
            ),
            daemon=True,
        )
        worker.start()
        self.assertTrue(started.wait(1))
        after.cancel()
        release.set()
        worker.join(2)

        self.assertFalse(worker.is_alive())
        self.assertEqual(OperationStatus.FAILED, results[0].status)
        self.assertEqual("outcome_unknown", results[0].code)
        self.assertEqual(
            "verified",
            results[0].value["safetyObservation"]["status"],
        )

    def test_deadline_before_mutation_fails_and_after_boundary_is_unknown(self):
        plan = destructive_plan()
        snapshot = snapshot_for()
        before_transport = FakeProcessTransport([TransportOutcome(0)])
        before = CancellationToken()
        before.set_deadline(0.001)
        self.assertTrue(before.wait(0.1))

        timed_out = self.runner(
            before_transport,
            provider=lambda _serial: snapshot,
            observer=lambda *_args: True,
        ).execute(self.command_for(plan, "deadline-before"), plan, cancellation=before)

        self.assertEqual(OperationStatus.FAILED, timed_out.status)
        self.assertEqual("timed_out", timed_out.code)
        self.assertEqual([], before_transport.calls)

        started = threading.Event()
        release = threading.Event()
        after_transport = FakeProcessTransport(
            [FakeTransportStep(TransportOutcome(0), started, release)]
        )
        after = CancellationToken()
        after.set_deadline(0.2)
        results: list[OperationResult] = []
        worker = threading.Thread(
            target=lambda: results.append(
                self.runner(
                    after_transport,
                    provider=lambda _serial: snapshot,
                    observer=lambda *_args: True,
                ).execute(
                    self.command_for(plan, "deadline-after"),
                    plan,
                    cancellation=after,
                )
            ),
            daemon=True,
        )
        worker.start()
        self.assertTrue(started.wait(1))
        worker.join(2)
        release.set()

        self.assertFalse(worker.is_alive())
        self.assertEqual(OperationStatus.FAILED, results[0].status)
        self.assertEqual("outcome_unknown", results[0].code)

    def test_read_only_success_after_deadline_is_timed_out(self):
        plan = read_only_plan()
        command = AppCommand(
            "tools.logcat",
            expected_revision=7,
            target_serial=plan.target_serial,
            operation_plan=plan,
            operation_id="read-only-success-deadline",
        )
        token = CancellationToken()
        token.set_deadline(1)

        def succeed_after_deadline(command, _plan, cancellation):
            self.assertFalse(cancellation.cancelled)
            cancellation.set_deadline(0.001)
            self.assertTrue(cancellation.wait(0.2))
            return OperationResult.success(
                command.operation_id,
                code="process_succeeded",
                stdout="completed output",
            )

        result = self.runner(
            FakeProcessTransport(),
            provider=lambda _serial: snapshot_for(),
        ).execute(
            command,
            plan,
            cancellation=token,
            operation_executor=succeed_after_deadline,
        )

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("timed_out", result.code)
        self.assertEqual("completed output", result.stdout)

    def test_read_only_cancelled_result_after_deadline_is_timed_out(self):
        plan = read_only_plan()
        command = AppCommand(
            "tools.logcat",
            expected_revision=7,
            target_serial=plan.target_serial,
            operation_plan=plan,
            operation_id="read-only-cancelled-deadline",
        )
        token = CancellationToken()
        token.set_deadline(1)

        def cancel_after_deadline(command, _plan, cancellation):
            self.assertFalse(cancellation.cancelled)
            cancellation.set_deadline(0.001)
            self.assertTrue(cancellation.wait(0.2))
            return OperationResult.cancelled(
                command.operation_id,
                code="cancelled",
                message="transport observed cancellation",
            )

        result = self.runner(
            FakeProcessTransport(),
            provider=lambda _serial: snapshot_for(),
        ).execute(
            command,
            plan,
            cancellation=token,
            operation_executor=cancel_after_deadline,
        )

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("timed_out", result.code)

    def test_read_only_user_cancellation_remains_cancelled(self):
        plan = read_only_plan()
        command = AppCommand(
            "tools.logcat",
            expected_revision=7,
            target_serial=plan.target_serial,
            operation_plan=plan,
            operation_id="read-only-user-cancelled",
        )
        token = CancellationToken()

        def cancel_by_user(command, _plan, cancellation):
            cancellation.cancel()
            return OperationResult.cancelled(
                command.operation_id,
                code="user_cancelled",
                message="operation cancelled by the user",
            )

        result = self.runner(
            FakeProcessTransport(),
            provider=lambda _serial: snapshot_for(),
        ).execute(
            command,
            plan,
            cancellation=token,
            operation_executor=cancel_by_user,
        )

        self.assertEqual(OperationStatus.CANCELLED, result.status)
        self.assertEqual("user_cancelled", result.code)

    def test_read_only_success_after_user_cancellation_is_cancelled(self):
        plan = read_only_plan()
        command = AppCommand(
            "tools.scrcpy",
            expected_revision=7,
            target_serial=plan.target_serial,
            operation_plan=plan,
            operation_id="read-only-success-user-cancelled",
        )
        token = CancellationToken()

        def succeed_after_user_cancel(command, _plan, cancellation):
            cancellation.cancel()
            return OperationResult.success(
                command.operation_id,
                code="process_succeeded",
                stdout="late process output",
            )

        result = self.runner(
            FakeProcessTransport(),
            provider=lambda _serial: snapshot_for(),
        ).execute(
            command,
            plan,
            cancellation=token,
            operation_executor=succeed_after_user_cancel,
        )

        self.assertEqual(OperationStatus.CANCELLED, result.status)
        self.assertEqual("cancelled", result.code)
        self.assertEqual("late process output", result.stdout)

    def test_read_only_cancellation_cleanup_failure_is_not_hidden(self):
        plan = read_only_plan()
        command = AppCommand(
            "tools.scrcpy",
            expected_revision=7,
            target_serial=plan.target_serial,
            operation_plan=plan,
            operation_id="read-only-cancel-cleanup-failed",
        )
        token = CancellationToken()

        def succeed_then_cancel(command, _plan, cancellation):
            cancellation.cancel()
            return OperationResult.success(
                command.operation_id,
                code="scrcpy_launched",
                value={"pid": 4242},
            )

        def fail_cleanup(result, cancellation):
            self.assertTrue(result.ok)
            self.assertIs(token, cancellation)
            return OperationResult.failed(
                command.operation_id,
                code="managed_process_termination_failed",
                message="managed process remains active",
            )

        result = self.runner(
            FakeProcessTransport(),
            provider=lambda _serial: snapshot_for(),
        ).execute(
            command,
            plan,
            cancellation=token,
            operation_executor=succeed_then_cancel,
            cancellation_cleanup=fail_cleanup,
        )

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("managed_process_termination_failed", result.code)

    def test_read_only_late_cancellation_runs_cleanup_before_status_mapping(self):
        plan = read_only_plan()
        command = AppCommand(
            "tools.scrcpy",
            expected_revision=7,
            target_serial=plan.target_serial,
            operation_plan=plan,
            operation_id="read-only-late-cancel-cleanup",
        )
        token = CancellationToken()
        launched = OperationResult.success(
            command.operation_id,
            code="scrcpy_launched",
            value={"pid": 4242},
        )
        cleanup_calls = []

        def finish_launch(_command, _plan, _cancellation):
            return launched

        def cancel_after_launch(result, cancellation):
            self.assertIs(launched, result)
            self.assertIs(token, cancellation)
            cancellation.cancel()
            return result

        def cleanup(result, cancellation):
            cleanup_calls.append((result, cancellation))
            return result

        result = self.runner(
            FakeProcessTransport(),
            provider=lambda _serial: snapshot_for(),
        ).execute(
            command,
            plan,
            cancellation=token,
            operation_executor=finish_launch,
            result_transformer=cancel_after_launch,
            cancellation_cleanup=cleanup,
        )

        self.assertEqual(OperationStatus.CANCELLED, result.status)
        self.assertEqual("cancelled", result.code)
        self.assertEqual([(launched, token)], cleanup_calls)

    def test_process_failure_is_unknown_only_when_target_cannot_be_observed(self):
        plan = destructive_plan()
        snapshot = snapshot_for()

        unreachable = self.runner(
            FakeProcessTransport([TransportOutcome(7, stderr="device disconnected")]),
            provider=lambda _serial: snapshot,
            observer=lambda *_args: False,
        ).execute(self.command_for(plan, "unreachable"), plan)
        reachable = self.runner(
            FakeProcessTransport([TransportOutcome(7, stderr="remote rejected write")]),
            provider=lambda _serial: snapshot,
            observer=lambda *_args: True,
        ).execute(self.command_for(plan, "reachable"), plan)

        self.assertEqual("outcome_unknown", unreachable.code)
        self.assertEqual(
            "mismatch",
            unreachable.value["safetyObservation"]["status"],
        )
        self.assertEqual("process_failed", reachable.code)

    def test_forced_process_stop_after_mutation_is_always_outcome_unknown(self):
        plan = destructive_plan()
        snapshot = snapshot_for()
        for outcome in (
            TransportOutcome(None, timed_out=True),
            TransportOutcome(None, output_limited=True),
        ):
            with self.subTest(outcome=outcome):
                result = self.runner(
                    FakeProcessTransport([outcome]),
                    provider=lambda _serial: snapshot,
                    observer=lambda *_args: True,
                ).execute(self.command_for(plan, f"forced-{id(outcome)}"), plan)

                self.assertEqual(OperationStatus.FAILED, result.status)
                self.assertEqual("outcome_unknown", result.code)
                self.assertEqual(
                    "verified",
                    result.value["safetyObservation"]["status"],
                )

    def test_cleanup_failure_never_retains_single_or_batch_destructive_lock(self):
        class FailingCleanupStage:
            def __init__(self):
                self.calls = 0

            def cleanup(self):
                self.calls += 1
                raise OSError("injected Windows cleanup failure")

        plan = destructive_plan()
        snapshot = snapshot_for(slot="b")
        for mode in ("single", "batch"):
            with self.subTest(mode=mode):
                transport = FakeProcessTransport([TransportOutcome(0)])
                runner = self.runner(
                    transport,
                    provider=lambda _serial: snapshot,
                    observer=lambda *_args: True,
                )
                stage = FailingCleanupStage()
                with patch.object(
                    runner,
                    "_stage_artifacts",
                    return_value=(plan, stage),
                ):
                    result = (
                        runner.execute(self.command_for(plan, "cleanup-single"), plan)
                        if mode == "single"
                        else runner.execute_batch(confirmed_batch(plan))
                    )

                self.assertTrue(result.ok)
                self.assertGreaterEqual(stage.calls, 1)
                self.assertTrue(runner._destructive_lock.acquire(timeout=0.1))
                runner._destructive_lock.release()

    def test_plan_is_revalidated_again_at_the_immediate_process_boundary(self):
        plan = destructive_plan()
        snapshot = snapshot_for()
        ticks = iter((NOW + 1, NOW + 301))
        transport = FakeProcessTransport([TransportOutcome(0)])
        runner = OperationRunner(
            CommandExecutor(transport),
            safety_policy=SafetyPolicy(clock=lambda: next(ticks)),
            snapshot_provider=lambda _serial: snapshot,
            postcondition_observer=lambda *_args: True,
        )

        result = runner.execute(self.command_for(plan, "expires-at-boundary"), plan)

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("plan_expired", result.code)
        self.assertEqual([], transport.calls)

    def test_typed_boundary_runs_after_revalidation_and_special_executor_crosses_runner(self):
        plan = destructive_plan()
        snapshot = snapshot_for(slot="b")
        events = []
        transport = FakeProcessTransport([])

        def provider(_serial):
            events.append("revalidate")
            return snapshot

        def boundary(_command, _plan, _snapshot):
            events.append("begin")
            return ExecutionBoundaryAck.accepted()

        def special(_command, _plan, _cancellation):
            events.append("execute")
            return OperationResult.success(
                _command.operation_id,
                code="special_succeeded",
            )

        runner = self.runner(
            transport,
            provider=provider,
            observer=lambda *_args: events.append("observe") or True,
        )
        result = runner.execute(
            self.command_for(plan, "special"),
            plan,
            operation_executor=special,
            before_execution=boundary,
        )

        self.assertTrue(result.ok)
        self.assertEqual([], transport.calls)
        self.assertLess(events.index("begin"), events.index("execute"))
        self.assertLess(events.index("execute"), events.index("observe"))
        self.assertGreaterEqual(events[: events.index("begin")].count("revalidate"), 2)

    def test_verified_artifacts_are_executed_from_private_staging_and_cleaned(self):
        with TemporaryDirectory() as directory:
            source = (Path(directory) / "root-app.apk").resolve()
            original = b"cryptographically verified APK bytes"
            source.write_bytes(original)
            digest = hashlib.sha256(original).hexdigest()
            candidate = replace(
                destructive_plan(),
                requests=(
                    ProcessRequest(
                        (
                            "ADB",
                            "-s",
                            "ABCDEF123456",
                            "install",
                            "-r",
                            str(source),
                        )
                    ),
                ),
                artifacts=(FileArtifact(str(source), digest, "root-app:test"),),
                confirmation_token=None,
            )
            plan = replace(
                candidate,
                confirmation_token=candidate.confirmation_challenge(),
            )
            staged_paths: list[Path] = []
            snapshot = snapshot_for(slot="b")

            def boundary(_command, staged_plan, _snapshot):
                staged = Path(staged_plan.artifacts[0].path)
                staged_paths.append(staged)
                self.assertNotEqual(source, staged)
                self.assertTrue(staged.is_file())
                self.assertEqual(original, staged.read_bytes())
                self.assertEqual(str(staged), staged_plan.requests[0].argv[-1])
                # A validate-then-use swap of the original pathname cannot
                # alter the private bytes handed to the executor.
                source.write_bytes(b"attacker replacement")
                return ExecutionBoundaryAck.accepted()

            def execute(command, staged_plan, _cancellation):
                staged = Path(staged_plan.requests[0].argv[-1])
                self.assertEqual(original, staged.read_bytes())
                self.assertEqual(digest, staged_plan.artifacts[0].sha256)
                return OperationResult.success(
                    command.operation_id,
                    code="apk_installed",
                )

            result = self.runner(
                FakeProcessTransport(),
                provider=lambda _serial: snapshot,
                observer=lambda *_args: True,
            ).execute(
                self.command_for(plan, "artifact-staged"),
                plan,
                operation_executor=execute,
                before_execution=boundary,
            )

            self.assertTrue(result.ok)
            self.assertEqual("apk_installed", result.code)
            self.assertEqual(1, len(staged_paths))
            self.assertFalse(staged_paths[0].exists())

    def test_state_change_during_artifact_staging_aborts_before_process_boundary(self):
        with TemporaryDirectory() as directory:
            source = (Path(directory) / "boot.img").resolve()
            source.write_bytes(b"verified boot image")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            candidate = replace(
                destructive_plan(),
                requests=(
                    ProcessRequest(
                        (
                            "FASTBOOT",
                            "-s",
                            "ABCDEF123456",
                            "flash",
                            "boot",
                            str(source),
                        )
                    ),
                ),
                artifacts=(FileArtifact(str(source), digest, "partition:boot"),),
                confirmation_token=None,
            )
            plan = replace(
                candidate,
                confirmation_token=candidate.confirmation_challenge(),
            )
            stable = snapshot_for(slot="b")
            changed = snapshot_for(revision=8, slot="b")
            provider_calls = 0
            boundary_called = False

            def provider(_serial):
                nonlocal provider_calls
                provider_calls += 1
                return changed if provider_calls >= 4 else stable

            def boundary(_command, _plan, _snapshot):
                nonlocal boundary_called
                boundary_called = True
                return ExecutionBoundaryAck.accepted()

            transport = FakeProcessTransport()
            result = self.runner(
                transport,
                provider=provider,
                observer=lambda *_args: True,
            ).execute(
                self.command_for(plan, "artifact-state-change"),
                plan,
                before_execution=boundary,
            )

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("snapshot_revision_changed", result.code)
            self.assertGreaterEqual(provider_calls, 4)
            self.assertFalse(boundary_called)
            self.assertEqual([], transport.calls)

    def test_artifact_staging_rejects_links_before_any_process_boundary(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = (root / "boot.img").resolve()
            source.write_bytes(b"boot")
            linked = root / "linked.img"
            try:
                linked.symlink_to(source)
            except (OSError, NotImplementedError):
                self.skipTest("symbolic links are unavailable on this platform")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            candidate = replace(
                destructive_plan(),
                artifacts=(FileArtifact(str(linked), digest, "partition:boot"),),
                confirmation_token=None,
            )
            plan = replace(
                candidate,
                confirmation_token=candidate.confirmation_challenge(),
            )
            boundary_called = False

            def boundary(_command, _plan, _snapshot):
                nonlocal boundary_called
                boundary_called = True
                return ExecutionBoundaryAck.accepted()

            result = self.runner(
                FakeProcessTransport(),
                provider=lambda _serial: snapshot_for(slot="b"),
                observer=lambda *_args: True,
            ).execute(
                self.command_for(plan, "artifact-link"),
                plan,
                before_execution=boundary,
            )

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("artifact_not_regular", result.code)
            self.assertFalse(boundary_called)

    def test_destructive_lock_is_global_across_runner_instances(self):
        first_started = threading.Event()
        first_release = threading.Event()
        transport = FakeProcessTransport(
            [
                FakeTransportStep(TransportOutcome(0), first_started, first_release),
                TransportOutcome(0),
            ]
        )
        snapshot = snapshot_for(slot="b")
        first_runner = self.runner(
            transport,
            provider=lambda _serial: snapshot,
            observer=lambda *_args: True,
        )
        second_runner = self.runner(
            transport,
            provider=lambda _serial: snapshot,
            observer=lambda *_args: True,
        )
        results = []
        threads = [
            threading.Thread(
                target=lambda runner=runner, name=name: results.append(
                    runner.execute(
                        self.command_for(destructive_plan(), name),
                        destructive_plan(),
                    )
                ),
                daemon=True,
            )
            for runner, name in ((first_runner, "first"), (second_runner, "second"))
        ]
        threads[0].start()
        self.assertTrue(first_started.wait(1))
        threads[1].start()
        time.sleep(0.05)
        self.assertEqual(1, len(transport.calls))
        first_release.set()
        for thread in threads:
            thread.join(2)

        self.assertTrue(all(result.ok for result in results))
        self.assertEqual(1, transport.max_active_count)

    def test_batch_revalidates_each_device_sequentially_and_fails_fast(self):
        first = destructive_plan("ABCDEF123456")
        second = destructive_plan("ZYXWVU654321")
        batch = confirmed_batch(first, second)
        snapshots = {
            first.target_serial: snapshot_for(first.target_serial, slot="b"),
            second.target_serial: snapshot_for(second.target_serial, slot="b"),
        }
        calls = {serial: 0 for serial in snapshots}

        def provider(serial):
            calls[serial] += 1
            return snapshots[serial]

        transport = FakeProcessTransport([TransportOutcome(0), TransportOutcome(7), TransportOutcome(0)])
        result = self.runner(
            transport,
            provider=provider,
            observer=lambda *_args: True,
        ).execute_batch(batch)

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("batch_failed", result.code)
        self.assertEqual(2, len(transport.calls))
        self.assertGreaterEqual(calls[first.target_serial], 3)
        self.assertGreaterEqual(calls[second.target_serial], 2)

    def test_batch_pre_mutation_stop_preserves_user_or_deadline_reason(self):
        plan = destructive_plan()
        batch = confirmed_batch(plan)
        snapshot = snapshot_for(slot="b")

        for reason, expected_status, expected_code in (
            ("user", OperationStatus.CANCELLED, "cancelled"),
            ("deadline", OperationStatus.FAILED, "timed_out"),
        ):
            with self.subTest(reason=reason):
                token = CancellationToken()
                if reason == "deadline":
                    token.set_deadline_at(0.0)
                else:
                    token.cancel()
                transport = FakeProcessTransport([])

                result = self.runner(
                    transport,
                    provider=lambda _serial: snapshot,
                    observer=lambda *_args: True,
                ).execute_batch(batch, cancellation=token)

                self.assertEqual(expected_status, result.status)
                self.assertEqual(expected_code, result.code)
                self.assertEqual([], transport.calls)

    def test_batch_deadline_while_waiting_for_lock_is_timed_out(self):
        plan = destructive_plan()
        batch = confirmed_batch(plan)
        snapshot = snapshot_for(slot="b")
        token = CancellationToken()
        transport = FakeProcessTransport([])
        runner = self.runner(
            transport,
            provider=lambda _serial: snapshot,
            observer=lambda *_args: True,
        )

        def expire(received_token):
            self.assertIs(token, received_token)
            received_token.set_deadline_at(0.0)
            return False

        with patch.object(runner, "_acquire_destructive", side_effect=expire):
            result = runner.execute_batch(batch, cancellation=token)

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("timed_out", result.code)
        self.assertEqual([], transport.calls)

    def test_batch_interrupts_artifact_revalidation_with_the_batch_token(self):
        class InterruptingReader:
            def __init__(self, stop):
                self.stop = stop
                self.reads = 0

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size=-1):
                self.reads += 1
                if self.reads == 1:
                    self.stop()
                    # A mismatching chunk ensures this test would fail with
                    # artifact_hash_mismatch if execute_batch forgot to pass
                    # the cancellation token into revalidation.
                    return b"changed after planning"
                return b""

        for reason, expected_status, expected_code in (
            ("user", OperationStatus.CANCELLED, "cancelled"),
            ("deadline", OperationStatus.FAILED, "timed_out"),
        ):
            with self.subTest(reason=reason), TemporaryDirectory() as directory:
                source = (Path(directory) / "boot.img").resolve()
                contents = b"verified boot image"
                source.write_bytes(contents)
                plan = replace(
                    destructive_plan(),
                    artifacts=(
                        FileArtifact(
                            str(source),
                            hashlib.sha256(contents).hexdigest(),
                            "partition:boot",
                        ),
                    ),
                    confirmation_token=None,
                )
                plan = replace(plan, confirmation_token=plan.confirmation_challenge())
                batch = confirmed_batch(plan)
                snapshot = snapshot_for(slot="b")
                token = CancellationToken()

                def stop(*, stop_reason=reason, stop_token=token):
                    if stop_reason == "deadline":
                        stop_token.set_deadline_at(0.0)
                    else:
                        stop_token.cancel()

                reader = InterruptingReader(stop)
                transport = FakeProcessTransport([])
                with patch.object(Path, "open", return_value=reader):
                    result = self.runner(
                        transport,
                        provider=lambda _serial, current=snapshot: current,
                        observer=lambda *_args: True,
                    ).execute_batch(batch, cancellation=token)

                self.assertEqual(expected_status, result.status)
                self.assertEqual(expected_code, result.code)
                self.assertEqual(1, reader.reads)
                self.assertEqual([], transport.calls)

    def test_batch_interrupts_artifact_staging_with_the_batch_token(self):
        for reason, expected_status, expected_code in (
            ("user", OperationStatus.CANCELLED, "cancelled"),
            ("deadline", OperationStatus.FAILED, "timed_out"),
        ):
            with self.subTest(reason=reason), TemporaryDirectory() as directory:
                source = (Path(directory) / "boot.img").resolve()
                contents = b"verified boot image"
                source.write_bytes(contents)
                plan = replace(
                    destructive_plan(),
                    artifacts=(
                        FileArtifact(
                            str(source),
                            hashlib.sha256(contents).hexdigest(),
                            "partition:boot",
                        ),
                    ),
                    confirmation_token=None,
                )
                plan = replace(plan, confirmation_token=plan.confirmation_challenge())
                batch = confirmed_batch(plan)
                snapshot = snapshot_for(slot="b")
                token = CancellationToken()
                received_tokens = []
                staged_destinations = []

                def interrupt_copy(
                    _source,
                    destination,
                    _digest,
                    received_token,
                    *,
                    observed_tokens=received_tokens,
                    observed_destinations=staged_destinations,
                    stop_reason=reason,
                    stop_token=token,
                ):
                    observed_tokens.append(received_token)
                    observed_destinations.append(destination)
                    if stop_reason == "deadline":
                        stop_token.set_deadline_at(0.0)
                    else:
                        stop_token.cancel()
                    raise InterruptedError("injected staging interruption")

                transport = FakeProcessTransport([])
                with patch.object(
                    OperationRunner,
                    "_copy_verified_artifact",
                    side_effect=interrupt_copy,
                ):
                    result = self.runner(
                        transport,
                        provider=lambda _serial, current=snapshot: current,
                        observer=lambda *_args: True,
                    ).execute_batch(batch, cancellation=token)

                self.assertEqual(expected_status, result.status)
                self.assertEqual(expected_code, result.code)
                self.assertEqual([token], received_tokens)
                self.assertEqual(1, len(staged_destinations))
                self.assertFalse(staged_destinations[0].parent.exists())
                self.assertEqual([], transport.calls)

    def test_batch_rejects_second_device_state_change_before_its_process_boundary(self):
        first = destructive_plan("ABCDEF123456")
        second = destructive_plan("ZYXWVU654321")
        batch = confirmed_batch(first, second)
        stable = {
            first.target_serial: snapshot_for(first.target_serial, slot="b"),
            second.target_serial: snapshot_for(second.target_serial, slot="b"),
        }
        calls = {serial: 0 for serial in stable}

        def provider(serial):
            calls[serial] += 1
            if serial == second.target_serial and calls[serial] > 1:
                return replace(stable[serial], firmware=FirmwareInfo(hash="CHANGED"))
            return stable[serial]

        transport = FakeProcessTransport([TransportOutcome(0), TransportOutcome(0)])
        result = self.runner(
            transport,
            provider=provider,
            observer=lambda *_args: True,
        ).execute_batch(batch)

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("firmware_hash_changed", result.code)
        self.assertEqual(1, len(transport.calls))

    def test_batch_cancellation_after_first_mutation_is_unknown(self):
        first = destructive_plan("ABCDEF123456")
        second = destructive_plan("ZYXWVU654321")
        batch = confirmed_batch(first, second)
        snapshots = {
            first.target_serial: snapshot_for(first.target_serial, slot="b"),
            second.target_serial: snapshot_for(second.target_serial, slot="b"),
        }
        token = CancellationToken()
        transport = FakeProcessTransport([TransportOutcome(0), TransportOutcome(0)])

        def observer(*_args):
            token.cancel()
            return True

        result = self.runner(
            transport,
            provider=lambda serial: snapshots[serial],
            observer=observer,
        ).execute_batch(batch, cancellation=token)

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("outcome_unknown", result.code)
        self.assertEqual(1, len(transport.calls))
        self.assertEqual(
            "verified",
            result.value["safetyObservation"]["status"],
        )


if __name__ == "__main__":
    unittest.main()
