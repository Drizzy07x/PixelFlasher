import json
import threading
import unittest

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    AppStateStore,
    CommandExecutor,
    DeviceInfo,
    DeviceService,
    DeviceToolPlanningError,
    DeviceToolsService,
    FakeProcessTransport,
    FakeTransportStep,
    OperationRisk,
    OperationRunner,
    OperationStatus,
    PostconditionObserver,
    ProcessDeviceObservationProbe,
    SafetyPolicy,
    SensitiveText,
    ToolchainInfo,
    TransportOutcome,
)
from tests.command_engine_factory import make_test_command_engine
from ui.bridge_contract import BRIDGE_VERSION, BridgeProtocolError, BridgeRequest
from ui.command_registry import (
    COMMAND_REGISTRY,
    CommandMutability,
    CommandRisk,
    ExpectedRevision,
    TargetScope,
)
from ui.core_command_factory import CommandFactoryError, create_command_factory

COMMAND = "tools.wifi"
STATUS_COMMAND = "tools.wifi.status"
ENDPOINT = "192.168.1.42:37123"
HOST = "192.168.1.42"
PORT = 37123
TOOLCHAIN = ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True)


def bridge_request(
    command: str,
    *,
    payload=None,
    revision=11,
    request_id="wifi-host-operation",
) -> BridgeRequest:
    return BridgeRequest.from_json(
        json.dumps(
            {
                "version": BRIDGE_VERSION,
                "requestId": request_id,
                "command": command,
                "payload": {} if payload is None else payload,
                "expectedRevision": revision,
            }
        )
    )


def host_snapshot() -> AppSnapshot:
    return AppSnapshot(revision=11, toolchain=TOOLCHAIN)


def selected_snapshot() -> AppSnapshot:
    device = DeviceInfo(
        serial="SERIAL",
        mode="adb",
        online=True,
        name="Pixel",
    )
    return AppSnapshot(
        revision=11,
        devices=(device,),
        selected_serials=(device.serial,),
        selected_serial=device.serial,
        toolchain=TOOLCHAIN,
    )


def wifi_command(
    action: str,
    *,
    operation_id="wifi-host-operation",
    pairing_code: str | None = None,
) -> AppCommand:
    payload: dict[str, object] = {
        "action": action,
        "host": HOST,
        "port": PORT,
    }
    if pairing_code is not None:
        payload["pairingCode"] = pairing_code
    return AppCommand(
        COMMAND,
        expected_revision=11,
        payload=payload,
        operation_id=operation_id,
    )


class FakeTime:
    def __init__(self) -> None:
        self.value = 0.0

    def clock(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class HostWifiTransport:
    """Exact host ADB fake; any serial-bound observation is a test failure."""

    def __init__(self, *, listed_state: str | None) -> None:
        self.listed_state = listed_state
        self.calls = []

    def run(self, request, cancellation):
        del cancellation
        self.calls.append(request)
        argv = request.argv
        if "-s" in argv:
            raise AssertionError("host-global Wi-Fi observation must not use -s")
        if argv == ("ADB", "connect", ENDPOINT):
            return TransportOutcome(0, f"connected to {ENDPOINT}\n")
        if argv == ("ADB", "disconnect", ENDPOINT):
            return TransportOutcome(0, f"disconnected {ENDPOINT}\n")
        if argv == ("ADB", "devices", "-l"):
            row = (
                f"{ENDPOINT}\t{self.listed_state} product:akita transport_id:1\n"
                if self.listed_state is not None
                else ""
            )
            return TransportOutcome(0, "List of devices attached\n" + row)
        raise AssertionError(f"unexpected host Wi-Fi argv: {argv!r}")


class StatusTransport:
    def __init__(self) -> None:
        self.calls = []

    def run(self, request, cancellation):
        del cancellation
        self.calls.append(request)
        if request.argv != ("ADB", "-s", "SERIAL", "get-state"):
            raise AssertionError(f"unexpected status argv: {request.argv!r}")
        return TransportOutcome(0, "device\n")


class RecordingSecretRunner:
    def __init__(self, outcome: TransportOutcome) -> None:
        self.outcome = outcome
        self.calls = []

    def run(self, request, secret, cancellation):
        del cancellation
        self.calls.append((request, secret))
        return self.outcome


def engine_with_production_observer(
    transport,
    snapshot: AppSnapshot,
    *,
    device_tools_service: DeviceToolsService | None = None,
):
    store = AppStateStore(snapshot)
    executor = CommandExecutor(transport)
    safety = SafetyPolicy()
    device_service = DeviceService(transport)
    timer = FakeTime()
    observer = PostconditionObserver(
        ProcessDeviceObservationProbe(
            device_service,
            lambda: store.snapshot().toolchain,
            command_timeout_seconds=0.05,
        ),
        poll_interval_seconds=0.05,
        clock=timer.clock,
        sleeper=timer.sleep,
    )
    def snapshot_provider(_serial):
        return store.snapshot()

    runner = OperationRunner(
        executor,
        safety_policy=safety,
        snapshot_provider=snapshot_provider,
        postcondition_observer=observer,
        postcondition_timeout_seconds=0.2,
    )
    engine = make_test_command_engine(
        store=store,
        executor=executor,
        safety_policy=safety,
        device_service=device_service,
        device_tools_service=device_tools_service,
        operation_runner=runner,
        snapshot_provider=snapshot_provider,
        postcondition_observer=observer,
    )
    return engine, store


class WifiHostContractTests(unittest.TestCase):
    def test_registry_separates_host_mutations_from_selected_device_status(self) -> None:
        mutations = COMMAND_REGISTRY[COMMAND]
        self.assertEqual(CommandMutability.MUTATING, mutations.mutability)
        self.assertEqual(CommandRisk.HOST_WRITE, mutations.risk)
        self.assertEqual(ExpectedRevision.REQUIRED, mutations.expected_revision)
        self.assertEqual(TargetScope.APPLICATION, mutations.target_scope)
        self.assertEqual(frozenset({"*"}), mutations.valid_device_states)
        self.assertEqual(COMMAND, mutations.planner)
        self.assertEqual(
            {"action", "host", "port", "secretGrant"},
            set(mutations.payload.fields),
        )
        for field in ("action", "host", "port"):
            self.assertTrue(mutations.payload.fields[field].required)
        self.assertFalse(mutations.payload.fields["secretGrant"].required)

        status = COMMAND_REGISTRY[STATUS_COMMAND]
        self.assertEqual(CommandMutability.READ_ONLY, status.mutability)
        self.assertEqual(CommandRisk.DEVICE_READ, status.risk)
        self.assertEqual(ExpectedRevision.REQUIRED, status.expected_revision)
        self.assertEqual(TargetScope.SELECTED_DEVICE, status.target_scope)
        self.assertEqual(frozenset({"adb"}), status.valid_device_states)
        self.assertEqual(STATUS_COMMAND, status.planner)
        self.assertEqual({"serial"}, set(status.payload.fields))

    def test_bridge_accepts_only_the_three_closed_host_actions(self) -> None:
        for action in ("pair", "connect", "disconnect"):
            payload = {"action": action, "host": HOST, "port": PORT}
            if action == "pair":
                payload["secretGrant"] = "g" * 32
            with self.subTest(action=action):
                request = bridge_request(COMMAND, payload=payload)
                self.assertEqual(action, request.payload["action"])

        invalid_payloads = (
            {"action": "status", "host": HOST, "port": PORT},
            {"action": "connect", "port": PORT},
            {"action": "connect", "host": HOST},
            {"action": "connect", "host": HOST, "port": PORT, "serial": "SERIAL"},
            {"action": "pair", "host": HOST, "port": PORT},
            {
                "action": "disconnect",
                "host": HOST,
                "port": PORT,
                "secretGrant": "not-applicable",
            },
        )
        for payload in invalid_payloads:
            with self.subTest(payload=payload), self.assertRaises(BridgeProtocolError) as rejected:
                bridge_request(COMMAND, payload=payload)
            self.assertEqual("invalid_payload", rejected.exception.code)

        with self.assertRaises(BridgeProtocolError) as missing_revision:
            bridge_request(
                COMMAND,
                payload={"action": "connect", "host": HOST, "port": PORT},
                revision=None,
            )
        self.assertEqual("revision_required", missing_revision.exception.code)

        status = bridge_request(STATUS_COMMAND, payload={})
        self.assertEqual({}, status.payload)

    def test_factory_consumes_pairing_grant_without_selected_device(self) -> None:
        factory = create_command_factory(host_snapshot)
        issued_request = bridge_request(
            "secret.issue",
            payload={"purpose": "wifi.pairingCode", "secret": "123456"},
            request_id="issue-wifi-secret",
        )
        issued = factory.issue_secret(issued_request)
        payload = {
            "action": "pair",
            "host": HOST,
            "port": PORT,
            "secretGrant": issued["grant"],
        }

        command = factory(bridge_request(COMMAND, payload=payload))

        self.assertIsNone(command.target_serial)
        self.assertIsInstance(command.payload["pairingCode"], SensitiveText)
        self.assertNotIn("secretGrant", command.payload)
        self.assertNotIn("123456", repr(command))
        self.assertEqual("[REDACTED]", command.to_dict()["payload"]["pairingCode"])
        with self.assertRaises(CommandFactoryError) as replay:
            factory(
                bridge_request(
                    COMMAND,
                    payload=payload,
                    request_id="replay-wifi-secret",
                )
            )
        self.assertEqual("grant_not_found", replay.exception.code)

    def test_factory_binds_status_but_not_host_mutations_to_selection(self) -> None:
        empty = create_command_factory(host_snapshot)
        connect = empty(
            bridge_request(
                COMMAND,
                payload={"action": "connect", "host": HOST, "port": PORT},
            )
        )
        self.assertIsNone(connect.target_serial)

        with self.assertRaises(CommandFactoryError) as missing:
            empty(bridge_request(STATUS_COMMAND))
        self.assertEqual("target_serial_required", missing.exception.code)

        selected = create_command_factory(selected_snapshot)
        status = selected(bridge_request(STATUS_COMMAND))
        self.assertEqual("SERIAL", status.target_serial)


class WifiHostPlanningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = DeviceToolsService()

    def test_host_actions_compile_without_device_and_never_emit_a_serial(self) -> None:
        for action in ("pair", "connect", "disconnect"):
            with self.subTest(action=action):
                command = wifi_command(
                    action,
                    pairing_code="123456" if action == "pair" else None,
                )
                compilation = self.service.compile(command, host_snapshot())
                request = compilation.plan.request

                self.assertIsNone(compilation.plan.target_serial)
                self.assertIs(OperationRisk.MUTATING, compilation.plan.risk)
                self.assertEqual(("ADB", action, ENDPOINT), request.argv)
                self.assertNotIn("-s", request.argv)
                self.assertNotIn("shell", request.argv)
                self.assertIsNone(request.cwd)
                self.assertIsNone(request.env)
                expected_postcondition = (
                    "adb_wifi_pairing_recorded"
                    if action == "pair"
                    else "adb_wifi_endpoint_state"
                )
                self.assertEqual(
                    expected_postcondition,
                    compilation.plan.postconditions[0].kind,
                )

    def test_status_remains_read_only_and_selected_device_bound(self) -> None:
        compilation = self.service.compile(
            AppCommand(
                STATUS_COMMAND,
                expected_revision=11,
                target_serial="SERIAL",
            ),
            selected_snapshot(),
        )

        self.assertEqual(("ADB", "-s", "SERIAL", "get-state"), compilation.plan.request.argv)
        self.assertEqual("SERIAL", compilation.plan.target_serial)
        self.assertIs(OperationRisk.READ_ONLY, compilation.plan.risk)
        self.assertEqual((), compilation.plan.postconditions)

    def test_host_planning_still_rejects_missing_or_stale_revision(self) -> None:
        for revision, code in ((None, "revision_required"), (10, "stale_revision")):
            with self.subTest(revision=revision), self.assertRaises(DeviceToolPlanningError) as raised:
                self.service.compile(
                    AppCommand(
                        COMMAND,
                        expected_revision=revision,
                        payload={"action": "connect", "host": HOST, "port": PORT},
                    ),
                    host_snapshot(),
                )
            self.assertEqual(code, getattr(raised.exception, "code", None))


class WifiHostExecutionTests(unittest.TestCase):
    def test_connect_and_disconnect_require_real_host_inventory_evidence(self) -> None:
        cases = (
            ("connect", "device", "wifi_connect_succeeded"),
            ("disconnect", None, "wifi_disconnect_succeeded"),
        )
        for action, listed_state, code in cases:
            with self.subTest(action=action):
                transport = HostWifiTransport(listed_state=listed_state)
                engine, store = engine_with_production_observer(
                    transport,
                    host_snapshot(),
                )

                result = engine.execute(wifi_command(action))

                self.assertIs(OperationStatus.SUCCESS, result.status)
                self.assertEqual(code, result.code)
                self.assertEqual(ENDPOINT, result.value["endpoint"])
                self.assertEqual(
                    [("ADB", action, ENDPOINT), ("ADB", "devices", "-l")],
                    [call.argv for call in transport.calls],
                )
                self.assertEqual(result, store.snapshot().last_result)

    def test_cli_success_without_matching_inventory_state_is_not_success(self) -> None:
        for action, listed_state in (("connect", None), ("disconnect", "device")):
            with self.subTest(action=action):
                transport = HostWifiTransport(listed_state=listed_state)
                engine, _store = engine_with_production_observer(
                    transport,
                    host_snapshot(),
                )

                result = engine.execute(wifi_command(action))

                self.assertIs(OperationStatus.FAILED, result.status)
                self.assertEqual("postcondition_mismatch", result.code)
                self.assertGreaterEqual(
                    [call.argv for call in transport.calls].count(
                        ("ADB", "devices", "-l")
                    ),
                    1,
                )

    def test_pair_succeeds_only_with_exact_protocol_proof_and_no_device_probe(self) -> None:
        exact = RecordingSecretRunner(
            TransportOutcome(0, f"Successfully paired to {ENDPOINT} [guid=test]\n")
        )
        transport = HostWifiTransport(listed_state=None)
        engine, _store = engine_with_production_observer(
            transport,
            host_snapshot(),
            device_tools_service=DeviceToolsService(secret_runner=exact),
        )

        result = engine.execute(wifi_command("pair", pairing_code="123456"))

        self.assertIs(OperationStatus.SUCCESS, result.status)
        self.assertEqual("wifi_pair_succeeded", result.code)
        self.assertEqual(("ADB", "pair", ENDPOINT), exact.calls[0][0].argv)
        self.assertEqual("123456", exact.calls[0][1])
        self.assertEqual([], transport.calls)
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)
        self.assertNotIn("123456", str(result.to_dict()))

        forged = RecordingSecretRunner(
            TransportOutcome(0, "Successfully paired to 192.168.1.99:37123\n")
        )
        forged_engine, _store = engine_with_production_observer(
            HostWifiTransport(listed_state=None),
            host_snapshot(),
            device_tools_service=DeviceToolsService(secret_runner=forged),
        )
        rejected = forged_engine.execute(
            wifi_command("pair", pairing_code="654321", operation_id="forged-pair")
        )
        self.assertIs(OperationStatus.FAILED, rejected.status)
        self.assertEqual("outcome_unknown", rejected.code)
        self.assertNotIn("654321", str(rejected.to_dict()))

    def test_selected_status_uses_get_state_and_exact_result(self) -> None:
        transport = StatusTransport()
        engine, _store = engine_with_production_observer(
            transport,
            selected_snapshot(),
        )

        result = engine.execute(
            AppCommand(
                STATUS_COMMAND,
                expected_revision=11,
                target_serial="SERIAL",
                operation_id="wifi-status",
            )
        )

        self.assertIs(OperationStatus.SUCCESS, result.status)
        self.assertEqual("wifi_status_succeeded", result.code)
        self.assertEqual([("ADB", "-s", "SERIAL", "get-state")], [call.argv for call in transport.calls])

    def test_cancellation_after_host_mutation_begins_is_outcome_unknown(self) -> None:
        started = threading.Event()
        release = threading.Event()
        transport = FakeProcessTransport(
            [
                FakeTransportStep(
                    TransportOutcome(0, f"connected to {ENDPOINT}\n"),
                    started_event=started,
                    release_event=release,
                )
            ]
        )
        engine, _store = engine_with_production_observer(
            transport,
            host_snapshot(),
        )
        results = []
        worker = threading.Thread(
            target=lambda: results.append(
                engine.execute(
                    wifi_command(
                        "connect",
                        operation_id="wifi-host-cancel",
                    )
                )
            )
        )

        worker.start()
        self.assertTrue(started.wait(2))
        self.assertTrue(engine.cancel("wifi-host-cancel"))
        worker.join(2)
        release.set()

        self.assertFalse(worker.is_alive())
        self.assertEqual(1, len(results))
        self.assertIs(OperationStatus.FAILED, results[0].status)
        self.assertEqual("outcome_unknown", results[0].code)
        self.assertEqual("", results[0].stdout)
        self.assertEqual("", results[0].stderr)


if __name__ == "__main__":
    unittest.main()
