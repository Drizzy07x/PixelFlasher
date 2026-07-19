import re
import threading
import unittest

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    AppStateStore,
    CommandExecutor,
    DeviceToolPlanningError,
    DeviceToolsService,
    FakeProcessTransport,
    FakeTransportStep,
    OperationResult,
    OperationRisk,
    OperationStatus,
    ToolchainInfo,
    TransportOutcome,
)
from tests.command_engine_factory import make_test_command_engine

COMMAND = "tools.wifi.discover"
CHECK = "mdns daemon version [120]\n"
HEADER = "List of discovered mdns services\n"
ROWS = (
    "adb-legacy\t_adb._tcp\t169.254.5.6:5555\n"
    "adb-akita-ABC123\t_adb-tls-connect._tcp\t10.0.0.7:39815\n"
    "adb-akita-ABC123\t_adb-tls-pairing._tcp\t192.168.1.42:37123\n"
)


def snapshot() -> AppSnapshot:
    return AppSnapshot(
        revision=23,
        toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
    )


def command(*, payload=None, revision=23, operation_id="wifi-discovery"):
    return AppCommand(
        COMMAND,
        expected_revision=revision,
        payload=payload or {},
        operation_id=operation_id,
    )


class WifiDiscoveryServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = DeviceToolsService()
        self.snapshot = snapshot()

    def compile(self, *, payload=None):
        return self.service.compile(command(payload=payload), self.snapshot)

    def test_compile_without_a_selected_device_uses_two_exact_bounded_requests(self) -> None:
        compilation = self.compile()

        self.assertEqual("wifi.discover", compilation.action)
        self.assertIsNone(compilation.plan.target_serial)
        self.assertIs(OperationRisk.READ_ONLY, compilation.plan.risk)
        self.assertEqual(23, compilation.plan.snapshot_revision)
        self.assertEqual(2, len(compilation.plan.requests))
        check, services = compilation.plan.requests
        self.assertEqual(("ADB", "mdns", "check"), check.argv)
        self.assertEqual(5.0, check.timeout_seconds)
        self.assertEqual(1_024, check.output_limit_bytes)
        self.assertNotIn("-s", check.argv)
        self.assertEqual(("ADB", "mdns", "services"), services.argv)
        self.assertEqual(10.0, services.timeout_seconds)
        self.assertEqual(261_120, services.output_limit_bytes)
        self.assertNotIn("-s", services.argv)
        for request in compilation.plan.requests:
            self.assertNotIn("sh", request.argv)
            self.assertNotIn("shell", request.argv)

    def test_compile_rejects_payload_revision_and_unready_toolchain(self) -> None:
        with self.assertRaises(DeviceToolPlanningError):
            self.compile(payload={"serial": "SERIAL"})
        with self.assertRaises(DeviceToolPlanningError) as stale:
            self.service.compile(command(revision=22), self.snapshot)
        self.assertEqual("stale_revision", stale.exception.code)
        with self.assertRaises(DeviceToolPlanningError) as unavailable:
            self.service.compile(command(), AppSnapshot(revision=23))
        self.assertEqual("toolchain_not_ready", unavailable.exception.code)

    def test_finalize_returns_the_exact_closed_discovery_dto_and_discards_raw_output(self) -> None:
        compilation = self.compile()
        result = self.service.finalize_result(
            compilation,
            OperationResult.success(
                "wifi-discovery",
                stdout=CHECK + HEADER + ROWS,
            ),
        )

        self.assertIs(OperationStatus.SUCCESS, result.status)
        self.assertEqual("wifi_mdns_discovery_succeeded", result.code)
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)
        self.assertEqual(
            {"action", "count", "services", "discardedCount", "bounded"},
            set(result.value),
        )
        self.assertEqual("discover", result.value["action"])
        self.assertEqual(3, result.value["count"])
        self.assertEqual(0, result.value["discardedCount"])
        self.assertIs(True, result.value["bounded"])

        expected = {
            ("legacy", "169.254.5.6", 5555, "169.254.5.6:5555", "ipv4"),
            ("connect", "10.0.0.7", 39815, "10.0.0.7:39815", "ipv4"),
            ("pairing", "192.168.1.42", 37123, "192.168.1.42:37123", "ipv4"),
        }
        actual = {
            (
                item["serviceType"],
                item["host"],
                item["port"],
                item["endpoint"],
                item["addressFamily"],
            )
            for item in result.value["services"]
        }
        self.assertEqual(expected, actual)
        for item in result.value["services"]:
            self.assertEqual(
                {
                    "id",
                    "instance",
                    "serviceType",
                    "host",
                    "port",
                    "endpoint",
                    "addressFamily",
                },
                set(item),
            )
            self.assertRegex(item["id"], re.compile(r"^[0-9a-f]{64}$"))
        self.assertEqual(3, len({item["id"] for item in result.value["services"]}))

    def test_invalid_but_well_formed_candidates_are_counted_not_exposed(self) -> None:
        compilation = self.compile()
        output = (
            CHECK
            + HEADER
            + "adb-valid\t_adb-tls-pairing._tcp\t192.168.1.8:37123\n"
            + "bad instance\t_adb-tls-pairing._tcp\t192.168.1.9:37124\n"
            + "adb-unknown\t_http._tcp\t192.168.1.10:80\n"
            + "adb-global\t_adb-tls-connect._tcp\t8.8.8.8:5555\n"
            + "only-two\tfields\n"
            + "four\tfields\there\tnow\n"
        )

        result = self.service.finalize_result(
            compilation,
            OperationResult.success("wifi-discovery", stdout=output),
        )

        self.assertIs(OperationStatus.SUCCESS, result.status)
        self.assertEqual(1, result.value["count"])
        self.assertEqual(5, result.value["discardedCount"])
        self.assertEqual("adb-valid", result.value["services"][0]["instance"])

    def test_malformed_protocol_header_and_stderr_never_succeed(self) -> None:
        compilation = self.compile()
        malformed = (
            "",
            CHECK,
            HEADER + CHECK,
            "ERROR: mdns daemon unavailable\n" + HEADER,
            "mdns daemon version [0]\n" + HEADER,
            CHECK + "Wrong header\n",
        )
        for stdout in malformed:
            with self.subTest(stdout=stdout):
                result = self.service.finalize_result(
                    compilation,
                    OperationResult.success("wifi-discovery", stdout=stdout),
                )
                self.assertIs(OperationStatus.FAILED, result.status)
                self.assertEqual("", result.stdout)
                self.assertEqual("", result.stderr)

        stderr = self.service.finalize_result(
            compilation,
            OperationResult.success(
                "wifi-discovery",
                stdout=CHECK + HEADER,
                stderr="private mdns diagnostic",
            ),
        )
        self.assertIs(OperationStatus.FAILED, stderr.status)
        self.assertEqual("", stderr.stdout)
        self.assertEqual("", stderr.stderr)

    def test_header_only_is_a_verified_empty_success(self) -> None:
        result = self.service.finalize_result(
            self.compile(),
            OperationResult.success("wifi-discovery", stdout=CHECK + HEADER),
        )

        self.assertIs(OperationStatus.SUCCESS, result.status)
        self.assertEqual(0, result.value["count"])
        self.assertEqual([], result.value["services"])
        self.assertEqual(0, result.value["discardedCount"])

    def test_timeout_cancellation_and_failures_are_explicit_and_scrub_raw_output(self) -> None:
        compilation = self.compile()
        outcomes = (
            OperationResult.failed(
                "wifi-timeout",
                code="timed_out",
                stdout="PRIVATE-STDOUT",
                stderr="PRIVATE-STDERR",
            ),
            OperationResult.cancelled(
                "wifi-cancelled",
                stdout="PRIVATE-STDOUT",
                stderr="PRIVATE-STDERR",
            ),
            OperationResult.failed(
                "wifi-output-limit",
                code="output_limit_exceeded",
                stdout="PRIVATE-STDOUT",
                stderr="PRIVATE-STDERR",
            ),
        )
        for outcome in outcomes:
            with self.subTest(status=outcome.status, code=outcome.code):
                result = self.service.finalize_result(compilation, outcome)
                self.assertIsNot(OperationStatus.SUCCESS, result.status)
                self.assertEqual("", result.stdout)
                self.assertEqual("", result.stderr)


class WifiDiscoveryEngineIntegrationTests(unittest.TestCase):
    def test_engine_executes_both_requests_without_selected_device_or_raw_result(self) -> None:
        transport = FakeProcessTransport(
            [
                TransportOutcome(0, CHECK),
                TransportOutcome(0, HEADER + ROWS),
            ]
        )
        store = AppStateStore(snapshot())
        engine = make_test_command_engine(
            store=store,
            executor=CommandExecutor(transport),
        )

        result = engine.execute(command())

        self.assertIs(OperationStatus.SUCCESS, result.status)
        self.assertEqual(3, result.value["count"])
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)
        self.assertEqual(
            [("ADB", "mdns", "check"), ("ADB", "mdns", "services")],
            [call.argv for call in transport.calls],
        )
        stored_result = store.snapshot().last_result
        self.assertIsNotNone(stored_result)
        self.assertEqual(result.status, stored_result.status)
        self.assertEqual(result.code, stored_result.code)
        self.assertIsNone(stored_result.value)
        self.assertEqual("", stored_result.stdout)
        self.assertEqual("", stored_result.stderr)
        self.assertNotIn("192.168.1.42", repr(store.snapshot().to_dict()))

    def test_engine_cancellation_is_terminal_and_never_keeps_partial_mdns_output(self) -> None:
        started = threading.Event()
        release = threading.Event()
        transport = FakeProcessTransport(
            [
                FakeTransportStep(
                    TransportOutcome(0, CHECK),
                    started_event=started,
                    release_event=release,
                )
            ]
        )
        engine = make_test_command_engine(
            store=AppStateStore(snapshot()),
            executor=CommandExecutor(transport),
        )
        results = []
        worker = threading.Thread(
            target=lambda: results.append(
                engine.execute(command(operation_id="wifi-discovery-cancel"))
            )
        )

        worker.start()
        self.assertTrue(started.wait(2))
        self.assertTrue(engine.cancel("wifi-discovery-cancel"))
        worker.join(2)
        release.set()

        self.assertFalse(worker.is_alive())
        self.assertEqual(1, len(results))
        self.assertIs(OperationStatus.CANCELLED, results[0].status)
        self.assertEqual("", results[0].stdout)
        self.assertEqual("", results[0].stderr)


if __name__ == "__main__":
    unittest.main()
