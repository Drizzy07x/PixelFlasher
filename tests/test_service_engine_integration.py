import base64
import hashlib
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    AppStateStore,
    BackupProvenance,
    BackupRepository,
    BackupService,
    CancellationToken,
    CommandExecutor,
    DeviceInfo,
    DeviceToolsService,
    FakeProcessTransport,
    FakeTransportStep,
    GrantAccess,
    InteractionBroker,
    InteractionDecision,
    LaunchOutcome,
    LogcatStreamOutcome,
    OperationResult,
    OperationRisk,
    OperationStatus,
    PackageService,
    PathGrantStore,
    ProgressEvent,
    ProgressPhase,
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


def root_module_record(module_id: str, name: str, state: str = "enabled") -> str:
    def encode(value: str) -> str:
        return base64.b64encode(value.encode()).decode()

    return "|".join(
        (
            "PF_RM",
            module_id,
            state,
            encode(name),
            encode("1.0"),
            "1",
            encode("PixelFlasher"),
            encode("Test module"),
            "",
        )
    )


def pi_analysis_record() -> str:
    def encode(value: str) -> str:
        return base64.b64encode(value.encode()).decode()
    config_kinds = (
        "pif_custom_json",
        "pif_custom_prop",
        "pif_module_json",
        "pif_legacy_json",
        "pif_app_replace",
        "pif_scripts_only",
        "tricky_spoof",
        "tricky_target",
        "tricky_security_patch",
        "tricky_tee",
        "targeted_targets",
        "keybox",
    )
    lines = [
        "PF_PI|schema|1",
        "PF_PI|root|verified",
        "PF_PI|testKeys|false",
        "PF_PI|overlayVisible|false",
        f"PF_PI|package|gms|true|{encode('25.20.33')}|252033000",
        "PF_PI|package|play_store|false||0",
        f"PF_PI|module|{encode('playintegrityfix')}|enabled",
    ]
    lines.extend(
        f"PF_PI|config|{kind}|absent|0|-" for kind in config_kinds
    )
    lines.extend(
        (
            "PF_PI|targetCount|0",
            "PF_PI|denylistCount|3",
            "PF_PI|droidGuardVmCount|1",
            "PF_PI|complete|1",
        )
    )
    return "\n".join(lines)


def pif_inventory_record() -> str:
    specs = (
        ("pif.custom_json", "playintegrityfix", "json"),
        ("pif.custom_prop", "playintegrityfix", "prop"),
        ("pif.module_json", "playintegrityfix", "json"),
        ("pif.legacy_json", "playintegrityfix", "json"),
        ("pif.app_replace", "playintegrityfix", "list"),
        ("pif.scripts_only", "playintegrityfix", "marker"),
        ("tricky.spoof", "tricky_store", "prop"),
        ("tricky.target", "tricky_store", "list"),
        ("tricky.security_patch", "tricky_store", "text"),
        ("tricky.tee", "tricky_store", "text"),
        ("targeted.targets", "targetedfix", "list"),
    )
    lines = ["PF_PIF|schema|1", "PF_PIF|root|verified"]
    lines.extend(
        f"PF_PIF|profile|{profile_id}|{module}|{profile_format}|absent|0|-"
        for profile_id, module, profile_format in specs
    )
    target = base64.b64encode(b"com.google.android.gms").decode()
    lines.extend((f"PF_PIF|target|{target}|json|present|64|{'b' * 64}", "PF_PIF|complete|1"))
    return "\n".join(lines)


class RecordingLauncher:
    def __init__(self, *, error=None, terminate_result=True):
        self.error = error
        self.terminate_result = terminate_result
        self.calls = []
        self.terminated = []
        self.shutdown_called = False

    def launch(self, request):
        self.calls.append(request)
        if self.error is not None:
            raise self.error
        return LaunchOutcome(4242)

    def terminate(self, pid):
        self.terminated.append(pid)
        return self.terminate_result

    def shutdown(self):
        self.shutdown_called = True


class RecordingSecretRunner:
    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = []

    def run(self, request, secret, cancellation):
        self.calls.append((request, secret))
        return self.outcome


class EngineLogcatRunner:
    def __init__(self, lines, *, duration_completed=True, returncode=-15):
        self.lines = tuple(lines)
        self.duration_completed = duration_completed
        self.returncode = returncode
        self.calls = []

    def run(self, request, cancellation, *, max_lines, line_handler):
        self.calls.append((request, cancellation, max_lines))
        safe = tuple(line_handler(line) for line in self.lines[:max_lines])
        return LogcatStreamOutcome(
            self.returncode,
            safe,
            duration_completed=self.duration_completed,
            line_limit_reached=len(self.lines) >= max_lines,
        )

    def shutdown(self):
        pass


def write_scrcpy_executable(path: Path) -> None:
    path.write_bytes(b"MZ\x00\x00fake scrcpy" if sys.platform.startswith("win") else b"#!/bin/sh\nexit 0\n")
    if not sys.platform.startswith("win"):
        path.chmod(path.stat().st_mode | 0o111)


def snapshot_for(mode: str, *, revision: int = 4, root: bool = False) -> AppSnapshot:
    return AppSnapshot(
        revision=revision,
        devices=(
            DeviceInfo(
                "SERIAL",
                codename="akita",
                mode=mode,
                root=root,
                online=True,
            ),
        ),
        selected_serial="SERIAL",
        toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
    )


def command(kind: str, payload=None, *, revision: int = 4) -> AppCommand:
    return AppCommand(
        kind,
        expected_revision=revision,
        target_serial="SERIAL",
        payload=payload or {},
    )


_LOGCAT_CLEAR_TOKENS = tuple(f"{index:032x}" for index in range(1, 7))
_LOGCAT_CLEAR_MARKERS = (
    f"PF10_PRE_{_LOGCAT_CLEAR_TOKENS[0]}",
    f"PF10_POST_{_LOGCAT_CLEAR_TOKENS[1]}",
    f"PF10_PRE_START_{_LOGCAT_CLEAR_TOKENS[2]}",
    f"PF10_PRE_END_{_LOGCAT_CLEAR_TOKENS[3]}",
    f"PF10_POST_START_{_LOGCAT_CLEAR_TOKENS[4]}",
    f"PF10_POST_END_{_LOGCAT_CLEAR_TOKENS[5]}",
)


def successful_logcat_clear_outcomes() -> list[TransportOutcome]:
    pre, post, pre_start, pre_end, post_start, post_end = _LOGCAT_CLEAR_MARKERS
    return [
        TransportOutcome(0),
        TransportOutcome(0, f"{pre_start}\n"),
        TransportOutcome(0, f"{pre}\n"),
        TransportOutcome(0, f"{pre_end}\n"),
        TransportOutcome(0),
        TransportOutcome(0),
        TransportOutcome(0, f"{post_start}\n"),
        TransportOutcome(0, f"{post}\n"),
        TransportOutcome(0, f"{post_end}\n"),
    ]


class BackupCreatingTransport(FakeProcessTransport):
    """Fake process boundary which materializes a successful fetch output."""

    def __init__(self, contents: bytes):
        super().__init__([TransportOutcome(0, "fetched backup\n")])
        self.contents = contents

    def run(self, request, cancellation):
        outcome = super().run(request, cancellation)
        if outcome.returncode == 0 and not outcome.cancelled and not outcome.timed_out:
            Path(request.argv[-1]).write_bytes(self.contents)
        return outcome


def write_root_apk(path: Path, payload: bytes = b"manifest") -> bytes:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", payload)
        archive.writestr("classes.dex", b"dex")
    return path.read_bytes()


def write_root_module(path: Path, module_id: str = "test_module") -> bytes:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "module.prop",
            f"id={module_id}\nname=Test Module\n".encode(),
        )
        archive.writestr("service.sh", b"#!/system/bin/sh\n")
    return path.read_bytes()


class ServiceEngineIntegrationTests(unittest.TestCase):
    def test_factory_shares_one_apk_identity_boundary_across_app_services(self):
        inspector = FakeVerifiedApkInspector()

        engine = CommandEngine(apk_inspector=inspector)

        self.assertIs(inspector, engine.package_service.apk_inspector)
        self.assertIs(inspector, engine.rooting_service.apk_inspector)

    def test_expired_service_planning_deadlines_are_not_user_cancellations(self):
        cases = (
            ("apps.list", {}),
            ("partitions.list", {}),
            ("backups.create", {}),
            ("root.apps.list", {}),
            ("tools.logcat", {}),
            ("device.ota.certificates", {}),
            ("device.scan", {}),
        )
        for kind, payload in cases:
            with self.subTest(kind=kind):
                engine, transport = self.engine_for("adb", [])
                result = engine.execute(
                    AppCommand(
                        kind,
                        expected_revision=4,
                        target_serial="SERIAL",
                        payload=payload,
                        execution_timeout_seconds=0.01,
                        _accepted_monotonic=time.monotonic() - 1,
                    )
                )

                self.assertEqual(OperationStatus.FAILED, result.status)
                self.assertEqual("timed_out", result.code)
                self.assertEqual([], transport.calls)

    def test_process_command_deadline_interrupts_operation_lock_wait(self):
        engine, transport = self.engine_for("adb", [])
        engine._operation_lock.acquire()
        try:
            started = time.monotonic()
            result = engine.execute(
                AppCommand(
                    "tools.logcat",
                    expected_revision=4,
                    target_serial="SERIAL",
                    operation_id="logcat-lock-timeout",
                    execution_timeout_seconds=0.03,
                )
            )
            elapsed = time.monotonic() - started
        finally:
            engine._operation_lock.release()

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("timed_out", result.code)
        self.assertLess(elapsed, 0.5)
        self.assertEqual([], transport.calls)

    def test_root_app_inventory_cancellation_before_promotion_never_returns_success(self):
        class CancellingInventoryService(RootingService):
            def compile(self, command, snapshot, cancellation=None):
                compilation = super().compile(command, snapshot, cancellation)
                cancellation.cancel()
                return compilation

        engine, transport = self.engine_for(
            "adb",
            [],
            rooting_service=CancellingInventoryService(),
        )

        result = engine.execute(
            AppCommand(
                "root.apps.list",
                expected_revision=4,
                operation_id="cancel-root-inventory-before-promotion",
            )
        )

        self.assertEqual(OperationStatus.CANCELLED, result.status)
        self.assertEqual("rooting_cancelled", result.code)
        self.assertIsNone(engine.store.snapshot().last_result)
        self.assertEqual([], transport.calls)

    def engine_for(
        self,
        mode,
        outcomes,
        *,
        interaction_handler=None,
        root=False,
        rooting_service=None,
        device_tools_service=None,
        backup_repository=None,
    ):
        transport = FakeProcessTransport(outcomes)
        engine = CommandEngine(
            store=AppStateStore(snapshot_for(mode, root=root)),
            executor=CommandExecutor(transport),
            postcondition_observer=StatefulPostconditionObserver(transport),
            rooting_service=rooting_service,
            device_tools_service=device_tools_service,
            backup_repository=backup_repository,
            interaction_handler=(
                interaction_handler
                if interaction_handler is not None
                else lambda _request: InteractionDecision.CANCELLED
            ),
        )
        return engine, transport

    def test_apps_list_runs_through_executor_and_stores_parsed_result(self):
        engine, transport = self.engine_for(
            "adb",
            [
                TransportOutcome(
                    0,
                    "package:/data/app/b/base.apk=com.example.beta uid:10124\n"
                    "malformed\n"
                    "package:/data/app/a/base.apk=com.example.alpha uid:10123\n",
                )
            ],
        )

        result = engine.execute(command("apps.list", {"scope": "user"}))

        self.assertEqual(OperationStatus.SUCCESS, result.status)
        self.assertEqual("apps_list_succeeded", result.code)
        self.assertEqual(2, result.value["count"])
        self.assertEqual(
            ["com.example.alpha", "com.example.beta"],
            [item["package"] for item in result.value["packages"]],
        )
        self.assertEqual(
            [
                (
                    "ADB",
                    "-s",
                    "SERIAL",
                    "shell",
                    "pm",
                    "list",
                    "packages",
                    "-f",
                    "-U",
                    "-3",
                )
            ],
            [request.argv for request in transport.calls],
        )
        self.assertEqual(result, engine.store.snapshot().last_result)

    def test_partition_list_parses_fastboot_stderr_after_success(self):
        engine, transport = self.engine_for(
            "fastboot",
            [
                TransportOutcome(
                    0,
                    stderr=(
                        "(bootloader) partition-type:boot_a: raw\n"
                        "(bootloader) partition-size:boot_a: 0x1000\n"
                        "(bootloader) partition-size:userdata: 8192\n"
                        "(bootloader) partition-size:evil;erase: 0x1\n"
                    ),
                )
            ],
        )

        result = engine.execute(command("partitions.list"))

        self.assertTrue(result.ok)
        self.assertEqual("partitions_list_succeeded", result.code)
        self.assertEqual(
            ["boot_a", "userdata"],
            [item["name"] for item in result.value["partitions"]],
        )
        self.assertEqual(4096, result.value["partitions"][0]["size_bytes"])
        self.assertEqual(
            [("FASTBOOT", "-s", "SERIAL", "getvar", "all")],
            [request.argv for request in transport.calls],
        )

    def test_partition_erase_uses_backend_challenge_before_reinforced_confirmation(self):
        interactions = []
        engine, transport = self.engine_for(
            "fastboot",
            [TransportOutcome(0)],
            interaction_handler=lambda request: interactions.append(request) or InteractionDecision.ACCEPTED,
        )

        challenge = engine.execute(command("partitions.erase", {"partition": "userdata"}))
        required = challenge.value["confirmation"]["required_text"]
        result = engine.execute(
            command(
                "partitions.erase",
                {"partition": "userdata", "confirmationText": required},
            )
        )

        self.assertEqual("confirmation_text_required", challenge.code)
        self.assertEqual("ERASE userdata SERIAL", required)
        self.assertTrue(result.ok)
        self.assertEqual(
            [("FASTBOOT", "-s", "SERIAL", "erase", "userdata")],
            [request.argv for request in transport.calls],
        )
        self.assertEqual(1, len(interactions))
        self.assertTrue(interactions[0].reinforced)

    def test_logcat_returns_bounded_line_model_and_never_uses_shell(self):
        engine, transport = self.engine_for(
            "adb",
            [TransportOutcome(0, "07-18 I/Activity: ready\n07-18 E/System: failed\n")],
        )

        result = engine.execute(
            command(
                "tools.logcat",
                {
                    "buffers": ["main"],
                    "formatEnabled": True,
                    "formatVerb": "threadtime",
                    "formatModifiers": [],
                    "filters": [{"tag": "Activity", "priority": "I"}],
                    "maxLines": 25,
                    "timeoutSeconds": 5,
                },
            )
        )

        self.assertTrue(result.ok)
        self.assertEqual("logcat_collected", result.code)
        self.assertEqual(2, result.value["lineCount"])
        self.assertEqual(
            ["07-18 I/Activity: ready", "07-18 E/System: failed"],
            result.value["lines"],
        )
        self.assertEqual(
            (
                "ADB",
                "-s",
                "SERIAL",
                "logcat",
                "-d",
                "-b",
                "main",
                "-v",
                "threadtime",
                "-t",
                "25",
                "Activity:I",
                "*:S",
            ),
            transport.calls[0].argv,
        )
        self.assertNotIn("shell", transport.calls[0].argv)
        retained = engine.store.snapshot().last_result
        self.assertIsNotNone(retained)
        self.assertIsNone(retained.value)
        self.assertEqual("", retained.stdout)
        self.assertEqual("", retained.stderr)

    def test_logcat_clear_confirms_exact_serial_and_returns_only_the_closed_receipt(self):
        interactions = []
        engine, transport = self.engine_for(
            "adb",
            successful_logcat_clear_outcomes(),
            interaction_handler=(
                lambda request: interactions.append(request)
                or InteractionDecision.ACCEPTED
            ),
        )

        with patch(
            "pixelflasher_core.device_tools.secrets.token_hex",
            side_effect=_LOGCAT_CLEAR_TOKENS,
        ):
            result = engine.execute(
                command("tools.logcat.clear", {"serial": "SERIAL"})
            )

        self.assertEqual(OperationStatus.SUCCESS, result.status)
        self.assertEqual("logcat_buffers_cleared", result.code)
        self.assertEqual(
            {
                "targetSerial": "SERIAL",
                "buffers": ["all"],
                "clearCommandCompleted": True,
                "controlCommandVerified": True,
                "mainBufferSentinelVerified": True,
                "verificationEntryRetained": True,
            },
            result.value,
        )
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)

        self.assertEqual(1, len(interactions))
        self.assertEqual("SERIAL", interactions[0].target_serial)
        self.assertEqual(4, interactions[0].expected_revision)
        self.assertTrue(interactions[0].destructive)
        self.assertFalse(interactions[0].reinforced)

        pre, post, pre_start, pre_end, post_start, post_end = _LOGCAT_CLEAR_MARKERS
        query = (
            "ADB",
            "-s",
            "SERIAL",
            "logcat",
            "-d",
            "-b",
            "main",
            "-v",
            "raw",
            "PixelFlasherClear:I",
            "*:S",
        )
        self.assertEqual(
            [
                (
                    "ADB",
                    "-s",
                    "SERIAL",
                    "shell",
                    "log",
                    "-p",
                    "i",
                    "-t",
                    "PixelFlasherClear",
                    pre,
                ),
                ("ADB", "-s", "SERIAL", "shell", "echo", pre_start),
                query,
                ("ADB", "-s", "SERIAL", "shell", "echo", pre_end),
                ("ADB", "-s", "SERIAL", "logcat", "-b", "all", "-c"),
                (
                    "ADB",
                    "-s",
                    "SERIAL",
                    "shell",
                    "log",
                    "-p",
                    "i",
                    "-t",
                    "PixelFlasherClear",
                    post,
                ),
                ("ADB", "-s", "SERIAL", "shell", "echo", post_start),
                query,
                ("ADB", "-s", "SERIAL", "shell", "echo", post_end),
            ],
            [request.argv for request in transport.calls],
        )

        retained = engine.store.snapshot().last_result
        self.assertIsNotNone(retained)
        self.assertEqual(OperationStatus.SUCCESS, retained.status)
        self.assertEqual("logcat_buffers_cleared", retained.code)
        self.assertIsNone(retained.value)
        self.assertEqual("", retained.stdout)
        self.assertEqual("", retained.stderr)
        self.assertNotIn("PF10_", repr(engine.store.snapshot()))

    def test_logcat_clear_guards_revision_serial_and_confirmation_before_process(self):
        cases = (
            (
                command(
                    "tools.logcat.clear",
                    {"serial": "SERIAL"},
                    revision=3,
                ),
                lambda _request: InteractionDecision.ACCEPTED,
                "stale_revision",
                OperationStatus.FAILED,
                0,
            ),
            (
                AppCommand(
                    "tools.logcat.clear",
                    expected_revision=4,
                    target_serial="SERIAL",
                    payload={"serial": "OTHER"},
                ),
                lambda _request: InteractionDecision.ACCEPTED,
                "ambiguous_target_serial",
                OperationStatus.FAILED,
                0,
            ),
            (
                command("tools.logcat.clear", {"serial": "SERIAL"}),
                lambda _request: InteractionDecision.CANCELLED,
                "user_cancelled",
                OperationStatus.CANCELLED,
                1,
            ),
        )
        for intent, decision, code, status, interaction_count in cases:
            with self.subTest(code=code):
                interactions = []
                engine, transport = self.engine_for(
                    "adb",
                    [],
                    interaction_handler=(
                        lambda request, choose=decision, observed=interactions: observed.append(
                            request
                        )
                        or choose(request)
                    ),
                )
                with patch(
                    "pixelflasher_core.device_tools.secrets.token_hex",
                    side_effect=_LOGCAT_CLEAR_TOKENS,
                ):
                    result = engine.execute(intent)

                self.assertEqual(status, result.status)
                self.assertEqual(code, result.code)
                self.assertEqual(interaction_count, len(interactions))
                self.assertEqual([], transport.calls)
                self.assertIsNone(engine.store.snapshot().last_result)

    def test_logcat_stream_publishes_redacted_incremental_progress_and_safe_result(self):
        runner = EngineLogcatRunner(
            (
                "I/Auth: SERIAL token=hunter2 user@example.com",
                "I/Ready: complete",
            )
        )
        service = DeviceToolsService(logcat_stream_runner=runner)
        engine, transport = self.engine_for(
            "adb",
            [],
            device_tools_service=service,
        )
        events = []
        engine.executor.progress_listener = events.append

        result = engine.execute(
            command(
                "tools.logcat",
                {
                    "mode": "stream",
                    "maxLines": 10,
                    "timeoutSeconds": 3,
                    "redaction": "strict",
                },
            )
        )

        self.assertTrue(result.ok)
        self.assertEqual("logcat_stream_completed", result.code)
        self.assertEqual([], transport.calls)
        running = [event for event in events if event.phase is ProgressPhase.RUNNING]
        self.assertEqual(2, len(running))
        self.assertEqual((1, 10, None), (running[0].current, running[0].total, running[0].item))
        self.assertNotIn("hunter2", running[0].message)
        self.assertNotIn("SERIAL", running[0].message)
        self.assertNotIn("user@example.com", running[0].message)
        self.assertEqual(result.value["text"], "\n".join(result.value["lines"]))
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)
        retained = engine.store.snapshot().last_result
        self.assertIsNotNone(retained)
        self.assertIsNone(retained.value)
        self.assertEqual("", retained.stdout)
        self.assertEqual("", retained.stderr)

    def test_logcat_stream_natural_exit_is_not_a_false_success(self):
        runner = EngineLogcatRunner(
            ("I/Ready: one line",),
            duration_completed=False,
            returncode=0,
        )
        engine, transport = self.engine_for(
            "adb",
            [],
            device_tools_service=DeviceToolsService(logcat_stream_runner=runner),
        )

        result = engine.execute(
            command(
                "tools.logcat",
                {"mode": "stream", "maxLines": 10, "timeoutSeconds": 3},
            )
        )

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("logcat_stream_ended", result.code)
        self.assertEqual([], transport.calls)

    def test_logcat_export_is_a_verified_host_mutation_with_a_closed_result(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "logcat.txt"
            grants = PathGrantStore()
            issued = grants.issue_file(
                destination,
                purpose="tools.logcat.export",
                access=GrantAccess.WRITE,
            )
            bound = grants.resolve_bound_write_file(
                issued.token,
                purpose="tools.logcat.export",
            )
            service = DeviceToolsService()
            engine, _transport = self.engine_for(
                "adb",
                [TransportOutcome(0, "I/Ready: exported\n")],
                device_tools_service=service,
            )

            compilation = service.compile(
                command(
                    "tools.logcat",
                    {"exportDestination": bound},
                ),
                engine.store.snapshot(),
            )
            self.assertEqual(OperationRisk.MUTATING, compilation.plan.risk)
            self.assertEqual(
                ["host_artifact_written"],
                [condition.kind for condition in compilation.plan.postconditions],
            )

            result = engine.execute(
                command(
                    "tools.logcat",
                    {"exportDestination": bound},
                )
            )

            self.assertTrue(result.ok)
            self.assertEqual(b"I/Ready: exported", destination.read_bytes())
            self.assertEqual("logcat_collected", result.code)
            self.assertNotIn("planId", result.value)
            self.assertNotIn("postconditions", result.value)
            self.assertEqual(
                result.value["export"]["sha256"],
                hashlib.sha256(destination.read_bytes()).hexdigest(),
            )

    def test_logcat_export_cancelled_after_replace_never_reports_cancelled(self):
        class CancelAfterCommitService(DeviceToolsService):
            @staticmethod
            def _export_logcat(destination, text, cancellation):
                receipt = DeviceToolsService._export_logcat(
                    destination,
                    text,
                    cancellation,
                )
                cancellation.cancel()
                return receipt

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "logcat.txt"
            grants = PathGrantStore()
            issued = grants.issue_file(
                destination,
                purpose="tools.logcat.export",
                access=GrantAccess.WRITE,
            )
            bound = grants.resolve_bound_write_file(
                issued.token,
                purpose="tools.logcat.export",
            )
            engine, _transport = self.engine_for(
                "adb",
                [TransportOutcome(0, "I/Ready: committed\n")],
                device_tools_service=CancelAfterCommitService(),
            )

            result = engine.execute(
                command(
                    "tools.logcat",
                    {"exportDestination": bound},
                )
            )

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("outcome_unknown", result.code)
            self.assertEqual(b"I/Ready: committed", destination.read_bytes())

    def test_scrcpy_launch_is_serial_bound_managed_and_never_uses_executor(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / ("scrcpy.exe" if sys.platform.startswith("win") else "scrcpy")
            write_scrcpy_executable(executable)
            launcher = RecordingLauncher()
            service = DeviceToolsService(
                scrcpy_executable=executable,
                process_launcher=launcher,
            )
            engine, transport = self.engine_for(
                "adb",
                [],
                device_tools_service=service,
            )

            result = engine.execute(command("tools.scrcpy"))

            self.assertTrue(result.ok)
            self.assertEqual("scrcpy_launched", result.code)
            self.assertEqual("SERIAL", result.value["targetSerial"])
            self.assertEqual(4242, result.value["pid"])
            self.assertEqual([], transport.calls)
            self.assertEqual(
                [(str(executable.resolve()), "--serial", "SERIAL")],
                [request.argv for request in launcher.calls],
            )
            self.assertEqual(result, engine.store.snapshot().last_result)

            engine.shutdown()
            self.assertTrue(launcher.shutdown_called)

    def test_scrcpy_cancel_during_launch_terminates_managed_process(self):
        class BlockingLauncher(RecordingLauncher):
            def __init__(self):
                super().__init__()
                self.started = threading.Event()
                self.release = threading.Event()

            def launch(self, request):
                self.calls.append(request)
                self.started.set()
                if not self.release.wait(2):
                    raise TimeoutError("test launcher was not released")
                return LaunchOutcome(4242)

        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / (
                "scrcpy.exe" if sys.platform.startswith("win") else "scrcpy"
            )
            write_scrcpy_executable(executable)
            launcher = BlockingLauncher()
            engine, transport = self.engine_for(
                "adb",
                [],
                device_tools_service=DeviceToolsService(
                    scrcpy_executable=executable,
                    process_launcher=launcher,
                ),
            )
            intent = AppCommand(
                "tools.scrcpy",
                expected_revision=4,
                target_serial="SERIAL",
                operation_id="scrcpy-cancel-during-launch",
            )
            results = []
            worker = threading.Thread(target=lambda: results.append(engine.execute(intent)))
            worker.start()
            self.assertTrue(launcher.started.wait(1))

            self.assertTrue(engine.cancel(intent.operation_id))
            launcher.release.set()
            worker.join(2)

            self.assertFalse(worker.is_alive())
            self.assertEqual(1, len(results))
            self.assertEqual(OperationStatus.CANCELLED, results[0].status)
            self.assertEqual([4242], launcher.terminated)
            self.assertEqual([], transport.calls)
            engine.shutdown()

    def test_scrcpy_deadline_during_launch_terminates_before_timed_out_result(self):
        class BlockingLauncher(RecordingLauncher):
            def __init__(self):
                super().__init__()
                self.started = threading.Event()
                self.release = threading.Event()

            def launch(self, request):
                self.calls.append(request)
                self.started.set()
                if not self.release.wait(2):
                    raise TimeoutError("test launcher was not released")
                return LaunchOutcome(4242)

        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / (
                "scrcpy.exe" if sys.platform.startswith("win") else "scrcpy"
            )
            write_scrcpy_executable(executable)
            launcher = BlockingLauncher()
            engine, _transport = self.engine_for(
                "adb",
                [],
                device_tools_service=DeviceToolsService(
                    scrcpy_executable=executable,
                    process_launcher=launcher,
                ),
            )
            intent = AppCommand(
                "tools.scrcpy",
                expected_revision=4,
                target_serial="SERIAL",
                operation_id="scrcpy-deadline-during-launch",
                execution_timeout_seconds=0.03,
            )
            results = []
            worker = threading.Thread(target=lambda: results.append(engine.execute(intent)))
            worker.start()
            self.assertTrue(launcher.started.wait(1))
            time.sleep(0.05)
            launcher.release.set()
            worker.join(2)

            self.assertFalse(worker.is_alive())
            self.assertEqual(OperationStatus.FAILED, results[0].status)
            self.assertEqual("timed_out", results[0].code)
            self.assertEqual([4242], launcher.terminated)
            engine.shutdown()

    def test_scrcpy_cancel_cleanup_failure_is_explicit(self):
        class CancelDuringLaunch(RecordingLauncher):
            def launch(self, request):
                self.calls.append(request)
                token.cancel()
                return LaunchOutcome(4242)

        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / (
                "scrcpy.exe" if sys.platform.startswith("win") else "scrcpy"
            )
            write_scrcpy_executable(executable)
            token = CancellationToken()
            launcher = CancelDuringLaunch(terminate_result=False)
            service = DeviceToolsService(
                scrcpy_executable=executable,
                process_launcher=launcher,
            )
            compilation = service.compile(
                command("tools.scrcpy"),
                snapshot_for("adb"),
            )

            result = service.execute_special(compilation, "scrcpy-cleanup-failed", token)

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("managed_process_termination_failed", result.code)
            self.assertEqual([4242], launcher.terminated)

    def test_scrcpy_late_cancellation_is_cleaned_by_operation_runner(self):
        class LateCancellationService(DeviceToolsService):
            def execute_special(self, compilation, operation_id, cancellation):
                launched = self.process_launcher.launch(compilation.plan.request)
                result = OperationResult.success(
                    operation_id,
                    code="scrcpy_launched",
                    value={
                        "action": "scrcpy",
                        "targetSerial": compilation.plan.target_serial,
                        "pid": launched.pid,
                    },
                )
                cancellation.cancel()
                return result

        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / (
                "scrcpy.exe" if sys.platform.startswith("win") else "scrcpy"
            )
            write_scrcpy_executable(executable)
            launcher = RecordingLauncher()
            engine, transport = self.engine_for(
                "adb",
                [],
                device_tools_service=LateCancellationService(
                    scrcpy_executable=executable,
                    process_launcher=launcher,
                ),
            )

            result = engine.execute(
                AppCommand(
                    "tools.scrcpy",
                    expected_revision=4,
                    target_serial="SERIAL",
                    operation_id="scrcpy-late-cancel",
                )
            )

            self.assertEqual(OperationStatus.CANCELLED, result.status)
            self.assertEqual("cancelled", result.code)
            self.assertEqual([4242], launcher.terminated)
            self.assertEqual([], transport.calls)
            engine.shutdown()

    def test_scrcpy_launch_failure_is_explicit_and_does_not_fake_success(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / ("scrcpy.exe" if sys.platform.startswith("win") else "scrcpy")
            write_scrcpy_executable(executable)
            launcher = RecordingLauncher(error=OSError("launch denied"))
            engine, transport = self.engine_for(
                "adb",
                [],
                device_tools_service=DeviceToolsService(
                    scrcpy_executable=executable,
                    process_launcher=launcher,
                ),
            )

            result = engine.execute(command("tools.scrcpy"))

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("scrcpy_launch_failed", result.code)
            self.assertEqual([], transport.calls)
            self.assertEqual(result, engine.store.snapshot().last_result)

    def test_scrcpy_executable_hash_is_revalidated_immediately_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / ("scrcpy.exe" if sys.platform.startswith("win") else "scrcpy")
            write_scrcpy_executable(executable)
            launcher = RecordingLauncher()

            class MutatingService(DeviceToolsService):
                def compile(self, command, snapshot, cancellation=None, progress=None):
                    compilation = super().compile(
                        command,
                        snapshot,
                        cancellation=cancellation,
                        progress=progress,
                    )
                    executable.write_bytes(executable.read_bytes() + b"changed")
                    return compilation

            engine, transport = self.engine_for(
                "adb",
                [],
                device_tools_service=MutatingService(
                    scrcpy_executable=executable,
                    process_launcher=launcher,
                ),
            )

            result = engine.execute(command("tools.scrcpy"))

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("artifact_hash_mismatch", result.code)
            self.assertEqual([], launcher.calls)
            self.assertEqual([], transport.calls)

    def test_wifi_connect_disconnect_and_status_require_verified_adb_output(self):
        cases = (
            (
                "tools.wifi",
                {"action": "connect", "host": "192.0.2.10", "port": 5555},
                "connected to 192.0.2.10:5555\n",
                "wifi_connect_succeeded",
                None,
            ),
            (
                "tools.wifi",
                {"action": "disconnect", "host": "192.0.2.10", "port": 5555},
                "disconnected 192.0.2.10:5555\n",
                "wifi_disconnect_succeeded",
                None,
            ),
            ("tools.wifi.status", {}, "device\n", "wifi_status_succeeded", "SERIAL"),
        )
        for command_kind, payload, stdout, expected_code, expected_serial in cases:
            with self.subTest(command=command_kind, action=payload.get("action", "status")):
                engine, transport = self.engine_for(
                    "adb",
                    [TransportOutcome(0, stdout)],
                )
                result = engine.execute(command(command_kind, payload))

                self.assertTrue(result.ok)
                self.assertEqual(expected_code, result.code)
                self.assertNotIn("shell", transport.calls[0].argv)
                if expected_serial is None:
                    self.assertNotIn("targetSerial", result.value)
                else:
                    self.assertEqual(expected_serial, result.value["targetSerial"])

        engine, _transport = self.engine_for(
            "adb",
            [TransportOutcome(0, "failed to connect to 192.0.2.10:5555\n")],
        )
        failed = engine.execute(
            command(
                "tools.wifi",
                {"action": "connect", "host": "192.0.2.10", "port": 5555},
            )
        )
        self.assertEqual(OperationStatus.FAILED, failed.status)
        self.assertEqual("wifi_connect_failed", failed.code)

        engine, _transport = self.engine_for(
            "adb",
            [TransportOutcome(1, stderr="daemon rejected connection")],
        )
        process_failed = engine.execute(
            command(
                "tools.wifi",
                {"action": "connect", "host": "192.0.2.10", "port": 5555},
            )
        )
        self.assertEqual(OperationStatus.FAILED, process_failed.status)
        self.assertEqual("wifi_connect_failed", process_failed.code)

    def test_wifi_pairing_secret_uses_stdin_only_and_is_never_returned(self):
        secret = "123456"
        runner = RecordingSecretRunner(
            TransportOutcome(
                0,
                (f"Enter pairing code: Successfully paired to 192.0.2.20:37123 [guid=test]\ninput={secret}\n"),
                f"diagnostic repeated {secret}",
            )
        )
        service = DeviceToolsService(secret_runner=runner)
        engine, transport = self.engine_for(
            "adb",
            [],
            device_tools_service=service,
        )
        pairing_command = command(
            "tools.wifi",
            {
                "action": "pair",
                "host": "192.0.2.20",
                "port": 37123,
                "pairingCode": secret,
            },
        )

        result = engine.execute(pairing_command)

        self.assertTrue(result.ok)
        self.assertEqual("wifi_pair_succeeded", result.code)
        self.assertEqual([], transport.calls)
        self.assertEqual(
            ("ADB", "pair", "192.0.2.20:37123"),
            runner.calls[0][0].argv,
        )
        self.assertEqual(secret, runner.calls[0][1])
        self.assertNotIn(secret, str(pairing_command.to_dict()))
        self.assertNotIn(secret, str(result.to_dict()))
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)

    def test_wifi_pairing_false_success_and_process_failure_are_explicit_and_redacted(self):
        secret = "654321"
        for outcome in (
            TransportOutcome(0, f"failed: echoed {secret}"),
            TransportOutcome(1, f"input={secret}", f"rejected {secret}"),
        ):
            with self.subTest(returncode=outcome.returncode):
                runner = RecordingSecretRunner(outcome)
                engine, _transport = self.engine_for(
                    "adb",
                    [],
                    device_tools_service=DeviceToolsService(secret_runner=runner),
                )
                result = engine.execute(
                    command(
                        "tools.wifi",
                        {
                            "action": "pair",
                            "host": "192.0.2.20",
                            "port": 37123,
                            "pairingCode": secret,
                        },
                    )
                )
                self.assertEqual(OperationStatus.FAILED, result.status)
                # A pairing handshake can persist host/device keys before its
                # final protocol response. With no independent observation in
                # this fake, the runner must not claim a known clean failure.
                self.assertEqual("outcome_unknown", result.code)
                self.assertNotIn(secret, str(result.to_dict()))
                self.assertEqual("", result.stdout)
                self.assertEqual("", result.stderr)

    def test_push_files_confirms_revalidates_and_returns_verified_mapping(self):
        interactions = []
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "alpha.bin"
            second = Path(directory) / "beta.zip"
            first.write_bytes(b"alpha")
            second.write_bytes(b"beta")
            engine, transport = self.engine_for(
                "adb",
                [
                    TransportOutcome(0, "alpha.bin: 1 file pushed\n"),
                    TransportOutcome(0, "beta.zip: 1 file pushed\n"),
                ],
                interaction_handler=(lambda request: interactions.append(request) or InteractionDecision.ACCEPTED),
            )

            result = engine.execute(
                command(
                    "tools.pushFiles",
                    {
                        "paths": [str(first), str(second)],
                        "destination": "/data/local/tmp/",
                    },
                )
            )

        self.assertTrue(result.ok)
        self.assertEqual("files_pushed", result.code)
        self.assertEqual("SERIAL", result.value["targetSerial"])
        self.assertEqual(2, result.value["count"])
        self.assertEqual(
            ["/data/local/tmp/alpha.bin", "/data/local/tmp/beta.zip"],
            [item["destination"] for item in result.value["files"]],
        )
        self.assertEqual(
            [
                hashlib.sha256(b"alpha").hexdigest(),
                hashlib.sha256(b"beta").hexdigest(),
            ],
            [item["sha256"] for item in result.value["files"]],
        )
        self.assertEqual(1, len(interactions))
        self.assertEqual("SERIAL", interactions[0].target_serial)
        self.assertFalse(interactions[0].destructive)
        self.assertEqual(2, len(transport.calls))

    def test_push_progress_is_monotonic_and_identifies_each_remote_file(self):
        events: list[ProgressEvent] = []
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "alpha.bin"
            second = Path(directory) / "beta.zip"
            first.write_bytes(b"alpha")
            second.write_bytes(b"beta")
            engine, _transport = self.engine_for(
                "adb",
                [TransportOutcome(0), TransportOutcome(0)],
                interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
            )
            engine.executor.progress_listener = events.append

            result = engine.execute(
                command(
                    "tools.pushFiles",
                    {
                        "paths": [str(first), str(second)],
                        "destination": "/sdcard/Download/",
                    },
                )
            )

        self.assertTrue(result.ok)
        push_events = [event for event in events if event.kind == "tools.pushFiles"]
        percentages = [event.percent for event in push_events if event.percent is not None]
        self.assertEqual(sorted(percentages), percentages)
        self.assertEqual(0, percentages[0])
        self.assertEqual(100, percentages[-1])
        running = [
            event
            for event in push_events
            if event.phase is ProgressPhase.RUNNING and event.current is not None
        ]
        self.assertEqual(
            [(1, 2, "alpha.bin"), (2, 2, "beta.zip")],
            [(event.current, event.total, event.item) for event in running],
        )

    def test_push_failure_after_process_boundary_is_outcome_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "alpha.bin"
            second = Path(directory) / "beta.zip"
            first.write_bytes(b"alpha")
            second.write_bytes(b"beta")
            engine, _transport = self.engine_for(
                "adb",
                [
                    TransportOutcome(0, "alpha pushed\n"),
                    TransportOutcome(17, stderr="device disconnected\n"),
                ],
                interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
            )

            result = engine.execute(
                command(
                    "tools.pushFiles",
                    {
                        "paths": [str(first), str(second)],
                        "destination": "/data/local/tmp/",
                    },
                )
            )

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("outcome_unknown", result.code)
        self.assertNotIn("files_pushed", result.message)

    def test_first_push_process_failure_is_also_outcome_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "alpha.bin"
            source.write_bytes(b"alpha")
            engine, _transport = self.engine_for(
                "adb",
                [TransportOutcome(1, stderr="write failed\n")],
                interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
            )

            result = engine.execute(
                command(
                    "tools.pushFiles",
                    {
                        "paths": [str(source)],
                        "destination": "/data/local/tmp/",
                    },
                )
            )

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("outcome_unknown", result.code)

    def test_push_cancel_before_first_mutation_is_cancelled(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "payload.bin"
            source.write_bytes(b"payload")
            engine, transport = self.engine_for(
                "adb",
                [],
                interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
            )
            cancelled = False

            def cancel_during_hash(event: ProgressEvent) -> None:
                nonlocal cancelled
                if event.kind == "tools.pushFiles" and event.current == 1 and not cancelled:
                    cancelled = engine.cancel("push-cancel-before")

            engine.executor.progress_listener = cancel_during_hash
            result = engine.execute(
                AppCommand(
                    "tools.pushFiles",
                    expected_revision=4,
                    target_serial="SERIAL",
                    operation_id="push-cancel-before",
                    payload={
                        "paths": [str(source)],
                        "destination": "/data/local/tmp/",
                    },
                )
            )

        self.assertTrue(cancelled)
        self.assertEqual(OperationStatus.CANCELLED, result.status)
        self.assertEqual("push_cancelled", result.code)
        self.assertEqual([], transport.calls)

    def test_push_cancel_accepted_before_engine_registration_is_not_lost(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "payload.bin"
            source.write_bytes(b"payload")
            engine, transport = self.engine_for(
                "adb",
                [],
                interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
            )
            intent = AppCommand(
                "tools.pushFiles",
                expected_revision=4,
                target_serial="SERIAL",
                operation_id="push-cancel-at-handoff",
                payload={
                    "paths": [str(source)],
                    "destination": "/data/local/tmp/",
                },
            )
            intent.request_cancellation()

            result = engine.execute(intent)

        self.assertEqual(OperationStatus.CANCELLED, result.status)
        self.assertEqual("push_cancelled", result.code)
        self.assertEqual([], transport.calls)

    def test_push_deadline_includes_confirmation_wait(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "payload.bin"
            source.write_bytes(b"payload")

            def delayed_accept(_request):
                threading.Event().wait(0.03)
                return InteractionDecision.ACCEPTED

            engine, transport = self.engine_for(
                "adb",
                [],
                interaction_handler=delayed_accept,
            )
            result = engine.execute(
                AppCommand(
                    "tools.pushFiles",
                    expected_revision=4,
                    target_serial="SERIAL",
                    operation_id="push-confirmation-timeout",
                    execution_timeout_seconds=0.01,
                    payload={
                        "paths": [str(source)],
                        "destination": "/data/local/tmp/",
                    },
                )
            )

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("timed_out", result.code)
        self.assertEqual([], transport.calls)

    def test_push_deadline_interrupts_the_runtime_confirmation_broker(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "payload.bin"
            source.write_bytes(b"payload")
            broker = InteractionBroker(timeout_seconds=10)
            engine, transport = self.engine_for(
                "adb",
                [],
                interaction_handler=broker.request,
            )

            started = time.monotonic()
            result = engine.execute(
                AppCommand(
                    "tools.pushFiles",
                    expected_revision=4,
                    target_serial="SERIAL",
                    operation_id="push-broker-timeout",
                    execution_timeout_seconds=0.03,
                    payload={
                        "paths": [str(source)],
                        "destination": "/data/local/tmp/",
                    },
                )
            )
            elapsed = time.monotonic() - started

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("timed_out", result.code)
        self.assertLess(elapsed, 0.5)
        self.assertEqual([], transport.calls)

    def test_push_deadline_starts_when_the_command_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "payload.bin"
            source.write_bytes(b"payload")
            engine, transport = self.engine_for("adb", [])
            result = engine.execute(
                AppCommand(
                    "tools.pushFiles",
                    expected_revision=4,
                    target_serial="SERIAL",
                    operation_id="push-expired-in-queue",
                    execution_timeout_seconds=0.01,
                    _accepted_monotonic=time.monotonic() - 1,
                    payload={
                        "paths": [str(source)],
                        "destination": "/data/local/tmp/",
                    },
                )
            )

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("timed_out", result.code)
        self.assertEqual([], transport.calls)

    def test_push_cancel_after_first_process_boundary_is_outcome_unknown(self):
        started = threading.Event()
        release = threading.Event()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "payload.bin"
            source.write_bytes(b"payload")
            transport = FakeProcessTransport(
                [
                    FakeTransportStep(
                        TransportOutcome(0, "payload pushed\n"),
                        started_event=started,
                        release_event=release,
                    )
                ]
            )
            engine = CommandEngine(
                store=AppStateStore(snapshot_for("adb")),
                executor=CommandExecutor(transport),
                postcondition_observer=StatefulPostconditionObserver(transport),
                interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
            )
            intent = AppCommand(
                "tools.pushFiles",
                expected_revision=4,
                target_serial="SERIAL",
                operation_id="push-cancel-after",
                payload={
                    "paths": [str(source)],
                    "destination": "/data/local/tmp/",
                },
            )
            results: list[OperationResult] = []
            worker = threading.Thread(target=lambda: results.append(engine.execute(intent)))
            worker.start()
            self.assertTrue(started.wait(2))
            self.assertTrue(engine.cancel(intent.operation_id))
            release.set()
            worker.join(3)

        self.assertFalse(worker.is_alive())
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("outcome_unknown", result.code)

    def test_push_source_changed_during_confirmation_fails_before_process(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "payload.bin"
            source.write_bytes(b"before")

            def mutate_then_accept(_request):
                source.write_bytes(b"after")
                return InteractionDecision.ACCEPTED

            engine, transport = self.engine_for(
                "adb",
                [],
                interaction_handler=mutate_then_accept,
            )
            result = engine.execute(
                command(
                    "tools.pushFiles",
                    {
                        "paths": [str(source)],
                        "destination": "/sdcard/Download/",
                    },
                )
            )

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("artifact_hash_mismatch", result.code)
        self.assertEqual([], transport.calls)

    def test_backup_create_finalizes_output_and_registers_route_free_inventory(self):
        contents = b"backend-created boot partition backup"
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "boot_a.img"
            transport = BackupCreatingTransport(contents)
            engine = CommandEngine(
                store=AppStateStore(snapshot_for("fastboot")),
                executor=CommandExecutor(transport),
            )

            result = engine.execute(
                command(
                    "backups.create",
                    {
                        "partition": "boot",
                        "slot": "a",
                        "destination": str(destination),
                    },
                )
            )

            self.assertTrue(result.ok)
            self.assertEqual("backup_created", result.code)
            self.assertEqual("boot_a", result.value["partition"])
            self.assertEqual("a", result.value["slot"])
            self.assertTrue(result.value["inventoryRegistered"])
            self.assertNotIn("path", result.value["backup"])
            self.assertEqual(
                hashlib.sha256(contents).hexdigest(),
                result.value["backup"]["sha256"],
            )
            self.assertEqual("created", result.value["backup"]["provenance"])
            self.assertEqual(1, engine.backup_repository.count())
            self.assertEqual(
                (
                    "FASTBOOT",
                    "-s",
                    "SERIAL",
                    "fetch",
                    "boot_a",
                    str(destination.resolve()),
                ),
                transport.calls[0].argv,
            )
            self.assertEqual(result, engine.store.snapshot().last_result)

    def test_magisk_backup_list_import_and_delete_use_typed_results(self):
        sha1 = hashlib.sha1(b"stock image", usedforsecurity=False).hexdigest()
        engine, transport = self.engine_for(
            "adb",
            [
                TransportOutcome(0, f"PF_MB|{sha1}|1234|1700000000|{sha1}\n"),
            ],
            root=True,
        )
        listed = engine.execute(command("backups.magisk.list", {"serial": "SERIAL"}))
        self.assertTrue(listed.ok)
        self.assertEqual("magisk_backups_listed", listed.code)
        self.assertEqual(sha1, listed.value["backups"][0]["sha1"])
        self.assertEqual("verified", listed.value["backups"][0]["integrity"])
        self.assertEqual("", listed.stdout)
        self.assertEqual(1, len(transport.calls))

        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "stock.img"
            image.write_bytes(b"stock image")
            imported_engine, imported_transport = self.engine_for(
                "adb",
                [TransportOutcome(0), TransportOutcome(0)],
                root=True,
                interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
            )
            imported = imported_engine.execute(
                command(
                    "backups.magisk.import",
                    {"serial": "SERIAL", "path": str(image)},
                )
            )
        self.assertTrue(imported.ok)
        self.assertEqual("magisk_backup_imported", imported.code)
        self.assertEqual(sha1, imported.value["sha1"])
        self.assertEqual(2, len(imported_transport.calls))

        required = BackupService.required_magisk_delete_confirmation(sha1, "SERIAL")
        deleted_engine, deleted_transport = self.engine_for(
            "adb",
            [TransportOutcome(0)],
            root=True,
            interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
        )
        deleted = deleted_engine.execute(
            command(
                "backups.magisk.delete",
                {
                    "serial": "SERIAL",
                    "sha1": sha1,
                    "confirmationText": required,
                },
            )
        )
        self.assertTrue(deleted.ok)
        self.assertEqual("magisk_backup_deleted", deleted.code)
        self.assertEqual("delete", deleted.value["action"])
        self.assertEqual(1, len(deleted_transport.calls))

    def test_magisk_backup_mutations_never_succeed_without_observed_state(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "stock.img"
            image.write_bytes(b"stock image")
            engine, _transport = self.engine_for(
                "adb",
                [TransportOutcome(0), TransportOutcome(0)],
                root=True,
                interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
            )
            def rejecting_observer(*_args: object) -> bool:
                return False

            engine.postcondition_observer = rejecting_observer
            engine.operation_runner.postcondition_observer = rejecting_observer
            result = engine.execute(
                command(
                    "backups.magisk.import",
                    {"serial": "SERIAL", "path": str(image)},
                )
            )

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("postcondition_mismatch", result.code)

    def test_backup_create_success_without_output_is_an_explicit_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "boot_a.img"
            engine, transport = self.engine_for(
                "fastboot",
                [TransportOutcome(0, "device claimed success")],
            )

            result = engine.execute(
                command(
                    "backups.create",
                    {
                        "partition": "boot",
                        "slot": "a",
                        "destination": str(destination),
                    },
                )
            )

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("backup_output_missing", result.code)
            self.assertEqual(1, len(transport.calls))
            self.assertEqual(result, engine.store.snapshot().last_result)

    def test_backup_create_empty_output_is_never_reported_as_success(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "boot_a.img"
            transport = BackupCreatingTransport(b"")
            engine = CommandEngine(
                store=AppStateStore(snapshot_for("fastboot")),
                executor=CommandExecutor(transport),
            )

            result = engine.execute(
                command(
                    "backups.create",
                    {
                        "partition": "boot",
                        "slot": "a",
                        "destination": str(destination),
                    },
                )
            )

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("backup_output_empty", result.code)

    def test_backup_restore_uses_backend_risk_metadata_and_verified_artifact(self):
        interactions = []
        contents = b"verified restore image"
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "vendor_boot_b.img"
            image.write_bytes(contents)
            engine, transport = self.engine_for(
                "fastboot",
                [TransportOutcome(0, "finished\n")],
                interaction_handler=(lambda request: interactions.append(request) or InteractionDecision.ACCEPTED),
            )

            # The UI command deliberately carries no risk booleans. The engine
            # must replace them with backend-owned BackupCompilation metadata.
            result = engine.execute(
                command(
                    "backups.restore",
                    {
                        "partition": "vendor_boot",
                        "slot": "b",
                        "path": str(image),
                    },
                )
            )

            self.assertTrue(result.ok)
            self.assertEqual("backup_restored", result.code)
            self.assertEqual("vendor_boot_b", result.value["partition"])
            self.assertTrue(result.value["inventoryRegistered"])
            self.assertNotIn("path", result.value["backup"])
            self.assertEqual(
                hashlib.sha256(contents).hexdigest(),
                result.value["backup"]["sha256"],
            )
            self.assertEqual(1, len(interactions))
            self.assertTrue(interactions[0].destructive)
            self.assertEqual("SERIAL", interactions[0].target_serial)
            assert_exact_or_staged_argv(
                self,
                [(
                    "FASTBOOT",
                    "-s",
                    "SERIAL",
                    "flash",
                    "vendor_boot_b",
                    str(image.resolve()),
                )],
                transport.calls,
            )

    def test_backup_inventory_restore_rehashes_managed_object_before_transport(self):
        contents = b"managed restore image"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "boot_a.img"
            source.write_bytes(contents)
            repository = BackupRepository(root / "repository")
            record = repository.import_file(
                source,
                expected_sha256=hashlib.sha256(contents).hexdigest(),
                target_serial="SERIAL",
                device_codename="akita",
                partition="boot",
                slot="a",
                provenance=BackupProvenance.USER_SUPPLIED,
            )
            engine, transport = self.engine_for(
                "fastboot",
                [TransportOutcome(0, "finished\n")],
                interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
                backup_repository=repository,
            )

            restored = engine.execute(
                command(
                    "backups.restore",
                    {"partition": "boot", "slot": "a", "backupId": record.backup_id},
                )
            )

            self.assertTrue(restored.ok, restored)
            self.assertEqual(record.backup_id, restored.value["backup"]["id"])
            self.assertEqual("user_supplied", restored.value["backup"]["provenance"])
            assert_exact_or_staged_argv(
                self,
                [
                    (
                        "FASTBOOT",
                        "-s",
                        "SERIAL",
                        "flash",
                        "boot_a",
                        str(record.path),
                    )
                ],
                transport.calls,
            )

            record.path.write_bytes(b"tampered")
            failed = engine.execute(
                AppCommand(
                    "backups.restore",
                    expected_revision=engine.store.snapshot().revision,
                    target_serial="SERIAL",
                    payload={
                        "partition": "boot",
                        "slot": "a",
                        "backupId": record.backup_id,
                    },
                )
            )
            repository.close()
            self.assertEqual(OperationStatus.FAILED, failed.status)
            self.assertEqual("backup_integrity_mismatch", failed.code)
            self.assertEqual(1, len(transport.calls))

    def test_backup_inventory_lists_and_deletes_only_after_exact_confirmation(self):
        contents = b"inventory backup"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "vendor_boot_b.img"
            source.write_bytes(contents)
            repository = BackupRepository(root / "repository")
            record = repository.import_file(
                source,
                expected_sha256=hashlib.sha256(contents).hexdigest(),
                target_serial="SERIAL",
                device_codename="akita",
                partition="vendor_boot",
                slot="b",
                provenance=BackupProvenance.CREATED,
            )
            engine = CommandEngine(
                store=AppStateStore(snapshot_for("fastboot")),
                backup_repository=repository,
            )
            listed = engine.execute(
                AppCommand(
                    "backups.list",
                    expected_revision=4,
                    payload={"serial": "SERIAL"},
                )
            )
            self.assertTrue(listed.ok)
            self.assertEqual(1, listed.value["count"])
            self.assertEqual(record.backup_id, listed.value["backups"][0]["id"])
            self.assertNotIn("path", listed.value["backups"][0])

            rejected = engine.execute(
                AppCommand(
                    "backups.delete",
                    expected_revision=4,
                    payload={
                        "backupId": record.backup_id,
                        "confirmationText": "DELETE wrong",
                    },
                )
            )
            self.assertEqual("backup_delete_confirmation_required", rejected.code)
            self.assertEqual(1, repository.count())

            deleted = engine.execute(
                AppCommand(
                    "backups.delete",
                    expected_revision=4,
                    payload={
                        "backupId": record.backup_id,
                        "confirmationText": f"DELETE {record.backup_id[-8:].upper()}",
                    },
                )
            )
            self.assertTrue(deleted.ok)
            self.assertEqual(5, deleted.value["revision"])
            self.assertTrue(deleted.value["objectRemoved"])
            self.assertEqual(0, repository.count())
            repository.close()

    def test_backup_restore_is_revalidated_after_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "boot_a.img"
            image.write_bytes(b"before")

            def mutate_then_accept(_request):
                image.write_bytes(b"after")
                return InteractionDecision.ACCEPTED

            engine, transport = self.engine_for(
                "fastboot",
                [],
                interaction_handler=mutate_then_accept,
            )
            result = engine.execute(
                command(
                    "backups.restore",
                    {"partition": "boot", "slot": "a", "path": str(image)},
                )
            )

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("artifact_hash_mismatch", result.code)
            self.assertEqual([], transport.calls)

    def test_root_apps_list_is_local_verified_and_stored_explicitly(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "Magisk.apk"
            contents = write_root_apk(apk, b"magisk manifest")
            digest = hashlib.sha256(contents).hexdigest()
            service = RootingService(
                (
                    RootAppSource(
                        str(apk),
                        "Magisk",
                        "stable",
                        "30.7",
                        "official",
                        digest,
                        "com.topjohnwu.magisk",
                    ),
                ),
                apk_inspector=FakeVerifiedApkInspector("com.topjohnwu.magisk"),
            )
            engine, transport = self.engine_for(
                "adb",
                [],
                rooting_service=service,
            )

            result = engine.execute(command("root.apps.list"))

            self.assertTrue(result.ok)
            self.assertEqual("root_apps_list_succeeded", result.code)
            self.assertEqual(1, result.value["count"])
            self.assertEqual("Magisk", result.value["apps"][0]["provider"])
            self.assertEqual(digest, result.value["apps"][0]["sha256"])
            self.assertNotIn("path", result.value["apps"][0])
            self.assertEqual(["a" * 64], result.value["apps"][0]["signerSha256"])
            self.assertEqual(["v2"], result.value["apps"][0]["schemes"])
            self.assertEqual([], transport.calls)
            self.assertEqual(result, engine.store.snapshot().last_result)

    def test_root_app_install_confirms_and_uses_verified_inventory_artifact(self):
        interactions = []
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "Magisk.apk"
            contents = write_root_apk(apk)
            digest = hashlib.sha256(contents).hexdigest()
            service = RootingService(
                (
                    RootAppSource(
                        str(apk),
                        "Magisk",
                        "stable",
                        "30.7",
                        "official",
                        digest,
                        "com.topjohnwu.magisk",
                    ),
                ),
                apk_inspector=FakeVerifiedApkInspector("com.topjohnwu.magisk"),
            )
            app_id = service.root_app_inventory()[0].id
            engine, transport = self.engine_for(
                "adb",
                [TransportOutcome(0, "Success\n")],
                rooting_service=service,
                interaction_handler=(lambda request: interactions.append(request) or InteractionDecision.ACCEPTED),
            )

            result = engine.execute(command("root.apps.install", {"appId": app_id}))

            self.assertTrue(result.ok)
            self.assertEqual("root_app_installed", result.code)
            self.assertEqual(digest, result.value["app"]["sha256"])
            self.assertNotIn("path", result.value["app"])
            self.assertEqual(1, len(interactions))
            self.assertFalse(interactions[0].destructive)
            assert_exact_or_staged_argv(
                self,
                [("ADB", "-s", "SERIAL", "install", "-r", str(apk.resolve()))],
                transport.calls,
            )

    def test_root_modules_list_parses_only_valid_ids(self):
        engine, transport = self.engine_for(
            "adb",
            [
                TransportOutcome(
                    0,
                    root_module_record("zygisk_next", "Zygisk Next", "disabled")
                    + "\n"
                    + root_module_record("play_integrity_fix", "Play Integrity Fix")
                    + "\n",
                )
            ],
            root=True,
        )

        result = engine.execute(command("root.modules.list"))

        self.assertTrue(result.ok)
        self.assertEqual("root_modules_list_succeeded", result.code)
        self.assertEqual(
            ["play_integrity_fix", "zygisk_next"],
            [item["id"] for item in result.value["modules"]],
        )
        self.assertEqual("Play Integrity Fix", result.value["modules"][0]["name"])
        self.assertEqual("enabled", result.value["modules"][0]["state"])
        self.assertEqual("disabled", result.value["modules"][1]["state"])
        self.assertNotIn("updateUrl", result.value["modules"][0])
        self.assertEqual(
            ("ADB", "-s", "SERIAL", "shell", "su", "-c"),
            transport.calls[0].argv[:6],
        )
        self.assertIn("module.prop", transport.calls[0].argv[6])

    def test_root_module_inventory_never_succeeds_with_forged_records(self):
        engine, _transport = self.engine_for(
            "adb",
            [TransportOutcome(0, "PF_RM|../escape|enabled||||||\n")],
            root=True,
        )

        result = engine.execute(command("root.modules.list"))

        self.assertFalse(result.ok)
        self.assertNotEqual("root_modules_list_succeeded", result.code)

    def test_pi_analysis_returns_only_closed_redacted_evidence(self):
        engine, transport = self.engine_for(
            "adb",
            [TransportOutcome(0, pi_analysis_record())],
            root=True,
        )

        result = engine.execute(
            command("tools.piAnalysis", {"serial": "SERIAL", "action": "analyze"})
        )

        self.assertTrue(result.ok)
        self.assertEqual("pi_analysis_completed", result.code)
        self.assertTrue(result.value["redacted"])
        self.assertTrue(result.value["complete"])
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)
        self.assertNotIn("SERIAL", repr(result.value))
        self.assertNotIn("/data/adb", repr(result.value))
        self.assertEqual(3, result.value["signals"]["magiskDenylistCount"])
        self.assertEqual(
            ("ADB", "-s", "SERIAL", "shell", "su", "-c"),
            transport.calls[0].argv[:6],
        )

    def test_pi_analysis_never_returns_partial_device_output(self):
        engine, _transport = self.engine_for(
            "adb",
            [TransportOutcome(0, "PF_PI|schema|1\nPF_PI|root|verified\nPRIVATE_RAW_VALUE")],
            root=True,
        )

        result = engine.execute(
            command("tools.piAnalysis", {"serial": "SERIAL", "action": "analyze"})
        )

        self.assertFalse(result.ok)
        self.assertEqual("pi_analysis_incomplete", result.code)
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)
        self.assertNotIn("PRIVATE_RAW_VALUE", repr(result))

    def test_pif_inventory_returns_only_verified_metadata(self):
        engine, transport = self.engine_for(
            "adb",
            [TransportOutcome(0, pif_inventory_record())],
            root=True,
        )

        result = engine.execute(command("root.pif.inventory", {"serial": "SERIAL"}))

        self.assertTrue(result.ok)
        self.assertEqual("pif_inventory_listed", result.code)
        self.assertEqual(11, result.value["count"])
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)
        self.assertNotIn("/data/adb", repr(result.value))
        self.assertNotIn("keybox", repr(result.value).casefold())
        self.assertEqual(("ADB", "-s", "SERIAL", "shell", "su", "-c"), transport.calls[0].argv[:6])

    def test_pif_inventory_never_returns_partial_device_output(self):
        engine, _transport = self.engine_for(
            "adb",
            [TransportOutcome(0, "PF_PIF|schema|1\nPF_PIF|root|verified\nPRIVATE_RAW_VALUE")],
            root=True,
        )

        result = engine.execute(command("root.pif.inventory", {"serial": "SERIAL"}))

        self.assertFalse(result.ok)
        self.assertEqual("pif_inventory_incomplete", result.code)
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)
        self.assertNotIn("PRIVATE_RAW_VALUE", repr(result))

    def test_pif_profile_delete_requires_and_verifies_the_exact_canonical_target(self):
        engine, transport = self.engine_for(
            "adb",
            [TransportOutcome(0)],
            root=True,
            interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
        )
        profile_id = "pif.custom_json"

        result = engine.execute(
            command(
                "tools.pif",
                {
                    "serial": "SERIAL",
                    "action": "deleteProfile",
                    "profileId": profile_id,
                    "confirmationText": f"DELETE PIF {profile_id} SERIAL",
                },
            )
        )

        self.assertTrue(result.ok)
        self.assertEqual("pif_profile_deleted", result.code)
        self.assertEqual({"action": "deleteProfile", "profileId": profile_id}, result.value)
        self.assertEqual(
            "rm -f -- /data/adb/modules/playintegrityfix/custom.pif.json",
            transport.calls[0].argv[6],
        )

    def test_pif_profile_import_returns_only_the_independently_verified_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "profile.json"
            source.write_text('{"PRODUCT":"akita"}', encoding="utf-8")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            engine, transport = self.engine_for(
                "adb",
                [TransportOutcome(0), TransportOutcome(0)],
                root=True,
                interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
            )
            profile_id = "pif.custom_json"
            result = engine.execute(
                command(
                    "tools.pif",
                    {
                        "serial": "SERIAL",
                        "action": "importProfile",
                        "profileId": profile_id,
                        "confirmationText": f"IMPORT PIF {profile_id} SERIAL",
                        "path": str(source.resolve()),
                    },
                )
            )

        self.assertTrue(result.ok)
        self.assertEqual("pif_profile_imported", result.code)
        self.assertEqual(
            {"action": "importProfile", "profileId": profile_id, "sha256": digest, "size": 19},
            result.value,
        )
        self.assertEqual(2, len(transport.calls))

    def test_root_recovery_commands_require_confirmation_and_verified_postconditions(self):
        cases = (
            (
                "tools.shizuku",
                {"action": "start"},
                "shizuku_started",
                "startShizuku",
            ),
            (
                "tools.sos",
                {
                    "action": "disableModules",
                    "confirmationText": "SOS SERIAL",
                },
                "sos_modules_disabled",
                "disableModules",
            ),
        )
        for kind, payload, code, action in cases:
            with self.subTest(kind=kind):
                interactions = []
                engine, transport = self.engine_for(
                    "adb",
                    [TransportOutcome(0)],
                    root=True,
                    interaction_handler=(
                        lambda request, observed=interactions: observed.append(request)
                        or InteractionDecision.ACCEPTED
                    ),
                )

                result = engine.execute(command(kind, payload))

                self.assertTrue(result.ok)
                self.assertEqual(code, result.code)
                self.assertEqual(action, result.value["action"])
                self.assertIs(True, result.value["verified"])
                self.assertEqual("SERIAL", result.value["targetSerial"])
                self.assertEqual(1, len(interactions))
                self.assertFalse(interactions[0].destructive)
                self.assertEqual(1, len(transport.calls))

    def test_root_module_state_actions_use_backend_confirmation_metadata(self):
        expected = {
            "enable": ("root_module_enabled", False),
            "disable": ("root_module_disabled", False),
            "remove": ("root_module_removed", True),
        }
        for action, (code, destructive) in expected.items():
            with self.subTest(action=action):
                interactions = []
                engine, transport = self.engine_for(
                    "adb",
                    [TransportOutcome(0)],
                    root=True,
                    interaction_handler=(
                        lambda request, observed=interactions: observed.append(request) or InteractionDecision.ACCEPTED
                    ),
                )

                result = engine.execute(
                    command(
                        "root.modules.action",
                        {"action": action, "moduleId": "zygisk_next"},
                    )
                )

                self.assertTrue(result.ok)
                self.assertEqual(code, result.code)
                self.assertEqual("zygisk_next", result.value["moduleId"])
                self.assertEqual(1, len(interactions))
                self.assertEqual(destructive, interactions[0].destructive)
                self.assertEqual(1, len(transport.calls))

    def test_root_module_install_confirms_destructive_plan_and_returns_hash(self):
        interactions = []
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / "module.zip"
            contents = write_root_module(module, "safe_module")
            digest = hashlib.sha256(contents).hexdigest()
            engine, transport = self.engine_for(
                "adb",
                [TransportOutcome(0), TransportOutcome(0), TransportOutcome(0)],
                root=True,
                interaction_handler=(lambda request: interactions.append(request) or InteractionDecision.ACCEPTED),
            )

            result = engine.execute(
                command(
                    "root.modules.action",
                    {"action": "install", "path": str(module)},
                )
            )

            self.assertTrue(result.ok)
            self.assertEqual("root_module_installed", result.code)
            self.assertEqual("safe_module", result.value["moduleId"])
            self.assertEqual(digest, result.value["artifact"]["sha256"])
            self.assertEqual(1, len(interactions))
            self.assertTrue(interactions[0].destructive)
            self.assertEqual(3, len(transport.calls))

    def test_root_artifact_mutation_and_process_failure_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / "module.zip"
            write_root_module(module)

            def mutate_then_accept(_request):
                module.write_bytes(b"changed")
                return InteractionDecision.ACCEPTED

            engine, transport = self.engine_for(
                "adb",
                [],
                root=True,
                interaction_handler=mutate_then_accept,
            )
            changed = engine.execute(
                command(
                    "root.modules.action",
                    {"action": "install", "path": str(module)},
                )
            )
            self.assertEqual(OperationStatus.FAILED, changed.status)
            self.assertEqual("artifact_hash_mismatch", changed.code)
            self.assertEqual([], transport.calls)

            failed_engine, failed_transport = self.engine_for(
                "adb",
                [TransportOutcome(23, stderr="root denied")],
                root=True,
                interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
            )
            failed = failed_engine.execute(
                command(
                    "root.modules.action",
                    {"action": "disable", "moduleId": "safe_module"},
                )
            )
            self.assertEqual(OperationStatus.FAILED, failed.status)
            self.assertEqual("process_failed", failed.code)
            self.assertEqual("root denied", failed.stderr)
            self.assertEqual(1, len(failed_transport.calls))

    def test_typed_validation_and_process_failures_are_explicit(self):
        engine, transport = self.engine_for("adb", [])
        injected = engine.execute(
            command(
                "apps.action",
                {
                    "action": "disable",
                    "package": "com.example.good;rm",
                },
            )
        )

        self.assertEqual(OperationStatus.FAILED, injected.status)
        self.assertEqual("package_name_invalid", injected.code)
        self.assertEqual([], transport.calls)

        failed_engine, failed_transport = self.engine_for(
            "adb",
            [TransportOutcome(17, "partial", "permission denied")],
        )
        process_failure = failed_engine.execute(command("apps.list"))
        self.assertEqual(OperationStatus.FAILED, process_failure.status)
        self.assertEqual("process_failed", process_failure.code)
        self.assertIsNone(process_failure.value)
        self.assertEqual(1, len(failed_transport.calls))

    def test_arbitrary_adb_shell_is_explicitly_disabled_without_execution(self):
        engine, transport = self.engine_for("adb", [])

        result = engine.execute(command("tools.adbShell", {"command": "rm -rf /data/local/tmp"}))

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("adb_shell_unsupported", result.code)
        self.assertEqual([], transport.calls)

    def test_service_commands_require_current_revision_before_execution(self):
        engine, transport = self.engine_for("adb", [])

        missing = engine.execute(AppCommand("apps.list", target_serial="SERIAL"))
        stale = engine.execute(command("tools.logcat", revision=3))

        self.assertEqual("revision_required", missing.code)
        self.assertEqual("stale_revision", stale.code)
        self.assertEqual([], transport.calls)

    def test_safety_policy_itself_revision_guards_service_plans(self):
        snapshot = snapshot_for("adb")
        stale = command("apps.list", revision=3)
        compilation = PackageService().compile(stale, snapshot)
        planned = replace(
            stale,
            operation_plan=compilation.plan,
            destructive=compilation.destructive,
            requires_confirmation=compilation.requires_confirmation,
        )

        decision = SafetyPolicy().evaluate(planned, snapshot)

        self.assertFalse(decision.allowed)
        self.assertEqual("stale_revision", decision.code)

    def test_safety_policy_revision_guards_backup_plans(self):
        snapshot = snapshot_for("fastboot")
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "boot_a.img"
            stale = command(
                "backups.create",
                {
                    "partition": "boot",
                    "slot": "a",
                    "destination": str(destination),
                },
                revision=3,
            )
            # Compile against canonical state to isolate SafetyPolicy's own
            # revision boundary from BackupService's duplicate guard.
            canonical = replace(stale, expected_revision=4)
            compilation = BackupService().compile(canonical, snapshot)
            planned = replace(stale, operation_plan=compilation.plan)

            decision = SafetyPolicy().evaluate(planned, snapshot)

            self.assertFalse(decision.allowed)
            self.assertEqual("stale_revision", decision.code)


if __name__ == "__main__":
    unittest.main()
