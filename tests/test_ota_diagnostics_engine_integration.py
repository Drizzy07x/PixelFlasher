import tempfile
import threading
import unittest
from pathlib import Path

from pixelflasher_core import (
    OTA_CERTIFICATES_COMMAND,
    OTA_LOGS_COMMAND,
    OTA_RESET_COMMAND,
    OTA_STATUS_COMMAND,
    AppCommand,
    ApplicationRuntime,
    AppSnapshot,
    AppStateStore,
    CommandExecutor,
    DeviceInfo,
    FakeProcessTransport,
    FakeTransportStep,
    OperationResult,
    OperationStatus,
    OtaDiagnosticCompilation,
    OtaDiagnosticsService,
    ToolchainInfo,
    TransportOutcome,
)
from pixelflasher_core.ota_diagnostics import (
    OTA_RUNNER_MAIN_CLASS,
    OTA_RUNNER_REMOTE_PATH,
)
from tests.command_engine_factory import make_test_command_engine
from ui.public_bridge import project_operation_result


def unzip_listing(*entries: str) -> str:
    rows = "".join(
        f"      1675  2026-07-18 12:00   {entry}\n" for entry in entries
    )
    return (
        "Archive:  /system/etc/security/otacerts.zip\n"
        "  Length      Date    Time    Name\n"
        "---------  ---------- -----   ----\n"
        f"{rows}"
        "---------                     -------\n"
    )


def ota_snapshot() -> AppSnapshot:
    return AppSnapshot(
        revision=17,
        devices=(
            DeviceInfo(
                "SERIAL-OTA",
                codename="akita",
                mode="adb",
                root=True,
                online=True,
            ),
        ),
        selected_serial="SERIAL-OTA",
        toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
    )


def ota_command(
    kind: str,
    payload: dict[str, object] | None = None,
    *,
    revision: int = 17,
    operation_id: str | None = None,
) -> AppCommand:
    values: dict[str, object] = {
        "expected_revision": revision,
        "target_serial": "SERIAL-OTA",
        "payload": payload or {},
    }
    if operation_id is not None:
        values["operation_id"] = operation_id
    return AppCommand(kind, **values)


class RevisionChangingOtaDiagnosticsService(OtaDiagnosticsService):
    def __init__(self, store: AppStateStore) -> None:
        self.store = store

    def compile(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
    ) -> OtaDiagnosticCompilation:
        compilation = super().compile(command, snapshot)
        self.store.update(
            expected_revision=snapshot.revision,
            selected_serial=snapshot.selected_serial,
        )
        return compilation


class OtaDiagnosticsEngineIntegrationTests(unittest.TestCase):
    def engine_for(
        self,
        outcomes: list[FakeTransportStep | TransportOutcome],
        *,
        store: AppStateStore | None = None,
        service: OtaDiagnosticsService | None = None,
        interaction_handler=None,
        postcondition_observer=None,
    ):
        state = store or AppStateStore(ota_snapshot())
        transport = FakeProcessTransport(outcomes)
        diagnostics = service or OtaDiagnosticsService()
        engine = make_test_command_engine(
            store=state,
            executor=CommandExecutor(transport),
            ota_diagnostics_service=diagnostics,
            interaction_handler=interaction_handler,
            postcondition_observer=postcondition_observer,
        )
        self.assertIs(diagnostics, engine.ota_diagnostics_service)
        return engine, transport

    def test_certificates_execute_through_the_runner_and_typed_finalizer(self) -> None:
        engine, transport = self.engine_for(
            [
                TransportOutcome(
                    0,
                    unzip_listing(
                        "META-INF/com/android/otacert.x509.pem",
                        "releasekey.x509.pem",
                    ),
                )
            ]
        )

        result = engine.execute(ota_command(OTA_CERTIFICATES_COMMAND))

        self.assertIsInstance(result, OperationResult)
        self.assertIs(OperationStatus.SUCCESS, result.status)
        self.assertEqual("ota_certificates_inspected", result.code)
        self.assertEqual(2, result.value["count"])
        self.assertEqual(
            (
                "ADB",
                "-s",
                "SERIAL-OTA",
                "shell",
                "unzip",
                "-l",
                "/system/etc/security/otacerts.zip",
            ),
            transport.calls[0].argv,
        )
        self.assertEqual(result, engine.store.snapshot().last_result)

    def test_logs_execute_through_the_runner_and_return_only_the_bounded_dto(self) -> None:
        engine, transport = self.engine_for(
            [
                TransportOutcome(
                    0,
                    (
                        "I unrelated: token=visible\n"
                        "I update_engine: SERIAL-OTA user@example.com token=visible\n"
                    ),
                )
            ]
        )

        result = engine.execute(
            ota_command(
                OTA_LOGS_COMMAND,
                {"maxLines": 25, "timeoutSeconds": 12},
            )
        )

        self.assertIsInstance(result, OperationResult)
        self.assertIs(OperationStatus.SUCCESS, result.status)
        self.assertEqual("ota_update_engine_logs_collected", result.code)
        self.assertEqual(
            ["I update_engine: <serial> <email> token=<redacted>"],
            result.value["lines"],
        )
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)
        self.assertEqual(
            (
                "ADB",
                "-s",
                "SERIAL-OTA",
                "logcat",
                "-d",
                "-v",
                "threadtime",
                "-t",
                "25",
                "update_engine:V",
                "update_engine_client:V",
                "*:S",
            ),
            transport.calls[0].argv,
        )

    def test_status_executes_through_runner_and_returns_idle_evidence(self) -> None:
        engine, transport = self.engine_for(
            [
                TransportOutcome(
                    0,
                    "CURRENT_OP=UPDATE_STATUS_IDLE\nCURRENT_PROGRESS=0\n",
                )
            ]
        )

        result = engine.execute(ota_command(OTA_STATUS_COMMAND))

        self.assertIs(OperationStatus.SUCCESS, result.status)
        self.assertEqual("ota_update_engine_status_inspected", result.code)
        self.assertTrue(result.value["idle"])
        self.assertEqual(
            (
                "ADB",
                "-s",
                "SERIAL-OTA",
                "shell",
                "update_engine_client",
                "--status",
            ),
            transport.calls[0].argv,
        )

    def test_reset_preflights_then_mutates_and_requires_observed_idle_state(self) -> None:
        observations: list[str] = []

        def observe(_plan, postcondition, _snapshot):
            observations.append(postcondition.kind)
            return True

        engine, transport = self.engine_for(
            [
                TransportOutcome(0),
                TransportOutcome(0),
                TransportOutcome(
                    0,
                    "CURRENT_OP=UPDATE_STATUS_DOWNLOADING\nCURRENT_PROGRESS=0.25\n",
                ),
                TransportOutcome(0),
                TransportOutcome(0),
            ],
            interaction_handler=lambda _request: True,
            postcondition_observer=observe,
        )

        result = engine.execute(ota_command(OTA_RESET_COMMAND))

        self.assertIs(OperationStatus.SUCCESS, result.status)
        self.assertEqual("ota_update_reset", result.code)
        self.assertEqual("reset", result.value["action"])
        self.assertTrue(result.value["idle"])
        self.assertEqual(
            {"action": "reset", "idle": True, "bounded": True},
            project_operation_result(OTA_RESET_COMMAND, result)["value"],
        )
        self.assertEqual(["ota_idle_state"], observations)
        calls = tuple(request.argv for request in transport.calls)
        invoke = (
            f"CLASSPATH={OTA_RUNNER_REMOTE_PATH} app_process /system/bin "
            f"{OTA_RUNNER_MAIN_CLASS}"
        )
        self.assertEqual(("ADB", "-s", "SERIAL-OTA", "push"), calls[0][:4])
        self.assertEqual(OTA_RUNNER_REMOTE_PATH, calls[0][-1])
        self.assertIn("toybox sha256sum -c -", calls[1][-1])
        self.assertEqual(
            tuple(f"{invoke} {action}" for action in ("status", "cancel", "reset")),
            tuple(call[-1] for call in calls[2:]),
        )

    def test_reset_denial_or_incompatible_preflight_starts_no_mutation(self) -> None:
        denied_engine, denied_transport = self.engine_for(
            [],
            interaction_handler=lambda _request: False,
            postcondition_observer=lambda *_args: True,
        )
        denied = denied_engine.execute(ota_command(OTA_RESET_COMMAND))

        self.assertIs(OperationStatus.CANCELLED, denied.status)
        self.assertEqual([], denied_transport.calls)

        idle_engine, idle_transport = self.engine_for(
            [
                TransportOutcome(0),
                TransportOutcome(0),
                TransportOutcome(
                    0,
                    "CURRENT_OP=UPDATE_STATUS_IDLE\nCURRENT_PROGRESS=0\n",
                )
            ],
            interaction_handler=lambda _request: True,
            postcondition_observer=lambda *_args: True,
        )
        idle = idle_engine.execute(ota_command(OTA_RESET_COMMAND))

        self.assertIs(OperationStatus.FAILED, idle.status)
        self.assertEqual("ota_already_idle", idle.code)
        self.assertEqual(3, len(idle_transport.calls))

    def test_reset_disconnect_during_preflight_starts_no_mutation(self) -> None:
        engine, transport = self.engine_for(
            [
                TransportOutcome(0),
                TransportOutcome(0),
                TransportOutcome(1, stderr="error: device offline"),
            ],
            interaction_handler=lambda _request: True,
            postcondition_observer=lambda *_args: True,
        )

        result = engine.execute(ota_command(OTA_RESET_COMMAND))

        self.assertIs(OperationStatus.FAILED, result.status)
        self.assertEqual("ota_reset_preflight_failed", result.code)
        self.assertEqual(3, len(transport.calls))
        self.assertNotIn("cancel", transport.calls[-1].argv[-1])
        self.assertNotIn("reset", transport.calls[-1].argv[-1])

    def test_reset_cancellation_before_mutation_is_cancelled(self) -> None:
        started = threading.Event()
        release = threading.Event()
        engine, transport = self.engine_for(
            [
                TransportOutcome(0),
                TransportOutcome(0),
                FakeTransportStep(
                    TransportOutcome(
                        0,
                        "CURRENT_OP=UPDATE_STATUS_DOWNLOADING\nCURRENT_PROGRESS=0.4\n",
                    ),
                    started_event=started,
                    release_event=release,
                )
            ],
            interaction_handler=lambda _request: True,
            postcondition_observer=lambda *_args: True,
        )
        command = ota_command(OTA_RESET_COMMAND, operation_id="ota-reset-preflight")
        results: list[OperationResult] = []
        worker = threading.Thread(target=lambda: results.append(engine.execute(command)))

        worker.start()
        self.assertTrue(started.wait(2))
        self.assertTrue(engine.cancel(command.operation_id))
        worker.join(2)
        release.set()

        self.assertFalse(worker.is_alive())
        self.assertEqual(3, len(transport.calls))
        self.assertIs(OperationStatus.CANCELLED, results[0].status)
        self.assertEqual("ota_reset_preflight_cancelled", results[0].code)

    def test_reset_cancellation_after_mutation_begins_is_outcome_unknown(self) -> None:
        started = threading.Event()
        release = threading.Event()
        engine, transport = self.engine_for(
            [
                TransportOutcome(0),
                TransportOutcome(0),
                TransportOutcome(
                    0,
                    "CURRENT_OP=UPDATE_STATUS_DOWNLOADING\nCURRENT_PROGRESS=0.4\n",
                ),
                FakeTransportStep(
                    TransportOutcome(0),
                    started_event=started,
                    release_event=release,
                ),
            ],
            interaction_handler=lambda _request: True,
            postcondition_observer=lambda *_args: True,
        )
        command = ota_command(OTA_RESET_COMMAND, operation_id="ota-reset-mutating")
        results: list[OperationResult] = []
        worker = threading.Thread(target=lambda: results.append(engine.execute(command)))

        worker.start()
        self.assertTrue(started.wait(2))
        self.assertTrue(engine.cancel(command.operation_id))
        worker.join(2)
        release.set()

        self.assertFalse(worker.is_alive())
        self.assertEqual(4, len(transport.calls))
        self.assertIs(OperationStatus.FAILED, results[0].status)
        self.assertEqual("outcome_unknown", results[0].code)

    def test_reset_timeout_after_mutation_is_unknown_and_mismatch_never_succeeds(self) -> None:
        active_status = TransportOutcome(
            0,
            "CURRENT_OP=UPDATE_STATUS_DOWNLOADING\nCURRENT_PROGRESS=0.4\n",
        )
        timeout_engine, timeout_transport = self.engine_for(
            [
                TransportOutcome(0),
                TransportOutcome(0),
                active_status,
                TransportOutcome(None, timed_out=True),
            ],
            interaction_handler=lambda _request: True,
            postcondition_observer=lambda *_args: True,
        )

        timed_out = timeout_engine.execute(ota_command(OTA_RESET_COMMAND))

        self.assertIs(OperationStatus.FAILED, timed_out.status)
        self.assertEqual("outcome_unknown", timed_out.code)
        self.assertEqual(4, len(timeout_transport.calls))

        mismatch_engine, mismatch_transport = self.engine_for(
            [
                TransportOutcome(0),
                TransportOutcome(0),
                active_status,
                TransportOutcome(0),
                TransportOutcome(0),
            ],
            interaction_handler=lambda _request: True,
            postcondition_observer=lambda *_args: False,
        )

        mismatch = mismatch_engine.execute(ota_command(OTA_RESET_COMMAND))

        self.assertIs(OperationStatus.FAILED, mismatch.status)
        self.assertEqual("postcondition_mismatch", mismatch.code)
        self.assertEqual(5, len(mismatch_transport.calls))

    def test_stale_revision_and_safety_policy_revalidation_start_no_process(self) -> None:
        stale_engine, stale_transport = self.engine_for([])

        stale = stale_engine.execute(
            ota_command(OTA_LOGS_COMMAND, revision=16),
        )

        self.assertIsInstance(stale, OperationResult)
        self.assertIs(OperationStatus.FAILED, stale.status)
        self.assertEqual("stale_revision", stale.code)
        self.assertEqual([], stale_transport.calls)

        store = AppStateStore(ota_snapshot())
        safety_service = RevisionChangingOtaDiagnosticsService(store)
        safety_engine, safety_transport = self.engine_for(
            [],
            store=store,
            service=safety_service,
        )

        rejected = safety_engine.execute(ota_command(OTA_LOGS_COMMAND))

        self.assertIsInstance(rejected, OperationResult)
        self.assertIs(OperationStatus.FAILED, rejected.status)
        self.assertEqual("snapshot_revision_changed", rejected.code)
        self.assertEqual([], safety_transport.calls)

    def test_cancellation_and_process_failure_are_explicit_terminal_results(self) -> None:
        started = threading.Event()
        release = threading.Event()
        engine, _transport = self.engine_for(
            [
                FakeTransportStep(
                    TransportOutcome(0, "I update_engine: completed\n"),
                    started_event=started,
                    release_event=release,
                )
            ]
        )
        command = ota_command(
            OTA_LOGS_COMMAND,
            operation_id="ota-logs-cancel",
        )
        results: list[OperationResult] = []
        worker = threading.Thread(target=lambda: results.append(engine.execute(command)))

        worker.start()
        self.assertTrue(started.wait(2))
        self.assertTrue(engine.cancel(command.operation_id))
        worker.join(2)
        release.set()

        self.assertFalse(worker.is_alive())
        self.assertEqual(1, len(results))
        self.assertIsInstance(results[0], OperationResult)
        self.assertIs(OperationStatus.CANCELLED, results[0].status)

        failed_engine, failed_transport = self.engine_for(
            [TransportOutcome(19, "partial output", "permission denied")]
        )
        failed = failed_engine.execute(ota_command(OTA_CERTIFICATES_COMMAND))

        self.assertIsInstance(failed, OperationResult)
        self.assertIs(OperationStatus.FAILED, failed.status)
        self.assertEqual("process_failed", failed.code)
        self.assertEqual("", failed.stdout)
        self.assertEqual("", failed.stderr)
        self.assertEqual(1, len(failed_transport.calls))
        self.assertEqual(failed, failed_engine.store.snapshot().last_result)

    def test_typed_parser_failure_never_becomes_success_or_none(self) -> None:
        engine, _transport = self.engine_for([TransportOutcome(0, "")])

        result = engine.execute(ota_command(OTA_CERTIFICATES_COMMAND))

        self.assertIsInstance(result, OperationResult)
        self.assertIs(OperationStatus.FAILED, result.status)
        self.assertEqual("ota_certificates_unverified", result.code)

    def test_application_runtime_composes_the_ota_diagnostics_service(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = ApplicationRuntime.open(Path(directory) / "PixelFlasher.json")
            try:
                self.assertIsInstance(
                    runtime.command_engine.ota_diagnostics_service,
                    OtaDiagnosticsService,
                )
            finally:
                runtime.shutdown()


if __name__ == "__main__":
    unittest.main()
