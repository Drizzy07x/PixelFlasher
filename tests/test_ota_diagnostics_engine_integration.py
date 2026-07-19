import tempfile
import threading
import unittest
from pathlib import Path

from pixelflasher_core import (
    OTA_CERTIFICATES_COMMAND,
    OTA_LOGS_COMMAND,
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
from tests.command_engine_factory import make_test_command_engine


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
    ):
        state = store or AppStateStore(ota_snapshot())
        transport = FakeProcessTransport(outcomes)
        diagnostics = service or OtaDiagnosticsService()
        engine = make_test_command_engine(
            store=state,
            executor=CommandExecutor(transport),
            ota_diagnostics_service=diagnostics,
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
