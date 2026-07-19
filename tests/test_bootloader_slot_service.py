import hashlib
import json
import unittest
from collections import deque
from collections.abc import Sequence
from dataclasses import replace
from typing import cast

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    AppStateStore,
    CommandExecutor,
    DeviceInfo,
    FakeProcessTransport,
    OperationRisk,
    OperationStatus,
    ToolchainInfo,
    TransportOutcome,
)
from pixelflasher_core.bootloader_inspection import (
    BOOTLOADER_PARTITION_LIMIT,
    BOOTLOADER_STDERR_LIMIT,
    BootloaderInspectionError,
    BootloaderSlotEvidence,
    BootloaderStreamOutcome,
)
from pixelflasher_core.cancellation import CancellationToken
from pixelflasher_core.contracts import ProcessRequest
from pixelflasher_core.device_tools import DeviceToolPlanningError, DeviceToolsService
from tests.command_engine_factory import make_test_command_engine

GETPROP_A = """\
[ro.boot.slot_suffix]: [_a]
[ro.bootloader]: [akita-15.2-12345678]
[ro.product.device]: [akita]
"""


def snapshot(*, codename: str = "akita", mode: str = "adb") -> AppSnapshot:
    return AppSnapshot(
        revision=7,
        devices=(DeviceInfo("SERIAL", codename=codename, mode=mode, online=True),),
        selected_serial="SERIAL",
        toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
    )


def command(**payload_overrides: object) -> AppCommand:
    payload: dict[str, object] = {"action": "bootloaderVersions"}
    payload.update(payload_overrides)
    return AppCommand(
        "device.inspect",
        expected_revision=7,
        target_serial="SERIAL",
        payload=payload,
        operation_id="inspect-slots",
    )


def evidence(slot: str, version: str = "15.2-12345678") -> BootloaderSlotEvidence:
    payload = f"{slot}:{version}".encode("ascii")
    return BootloaderSlotEvidence(
        slot,
        f"abl_{slot}",
        "akita",
        version,
        hashlib.sha256(payload).hexdigest(),
        len(payload),
    )


class FakeBootloaderPartitionRunner:
    def __init__(self, outcomes: Sequence[object]) -> None:
        self.outcomes = deque(outcomes)
        self.calls: list[tuple[ProcessRequest, str, str]] = []

    def run(
        self,
        request: ProcessRequest,
        cancellation: CancellationToken,
        *,
        slot: str,
        bootloader_codename: str,
    ) -> BootloaderStreamOutcome:
        del cancellation
        self.calls.append((request, slot, bootloader_codename))
        if not self.outcomes:
            raise AssertionError("unexpected bootloader partition runner call")
        outcome = self.outcomes.popleft()
        if isinstance(outcome, BaseException):
            raise outcome
        return cast(BootloaderStreamOutcome, outcome)


class CancelAfterFirstProcessTransport:
    def __init__(self, outcome: TransportOutcome) -> None:
        self.outcome = outcome
        self.calls: list[ProcessRequest] = []

    def run(
        self,
        request: ProcessRequest,
        cancellation: CancellationToken,
    ) -> TransportOutcome:
        self.calls.append(request)
        cancellation.cancel()
        return self.outcome


class CancelAfterFirstPartitionRunner(FakeBootloaderPartitionRunner):
    def run(
        self,
        request: ProcessRequest,
        cancellation: CancellationToken,
        *,
        slot: str,
        bootloader_codename: str,
    ) -> BootloaderStreamOutcome:
        outcome = super().run(
            request,
            cancellation,
            slot=slot,
            bootloader_codename=bootloader_codename,
        )
        cancellation.cancel()
        return outcome


class BootloaderSlotPlanningTests(unittest.TestCase):
    def service(self) -> DeviceToolsService:
        return DeviceToolsService(bootloader_prefixes={"akita": "akita"})

    def test_compiles_four_exact_serial_bound_requests_and_slot_metadata(self):
        compilation = self.service().compile(command(), snapshot())

        self.assertEqual("inspect.bootloaderVersions", compilation.action)
        self.assertEqual("bootloader-slot-stream", compilation.execution)
        self.assertEqual("akita", compilation.bootloader_codename)
        self.assertEqual("SERIAL", compilation.plan.target_serial)
        self.assertEqual(7, compilation.plan.snapshot_revision)
        self.assertEqual("akita", compilation.plan.expected_codename)
        self.assertEqual("adb", compilation.plan.expected_device_state)
        self.assertEqual(("abl_a", "abl_b"), compilation.plan.partitions)
        self.assertEqual(("a", "b"), compilation.plan.slots)
        self.assertEqual("preserve", compilation.plan.data_behavior)
        self.assertIs(OperationRisk.READ_ONLY, compilation.plan.risk)
        self.assertEqual((), compilation.plan.postconditions)
        self.assertFalse(compilation.device_write)
        self.assertFalse(compilation.destructive)
        self.assertFalse(compilation.requires_confirmation)

        requests = compilation.plan.requests
        self.assertEqual(4, len(requests))
        self.assertEqual(("ADB", "-s", "SERIAL", "shell", "getprop"), requests[0].argv)
        self.assertEqual(15.0, requests[0].timeout_seconds)
        self.assertEqual(1024 * 1024, requests[0].output_limit_bytes)
        self.assertEqual(
            ("ADB", "-s", "SERIAL", "shell", "su", "0", "id", "-u"),
            requests[1].argv,
        )
        self.assertEqual(10.0, requests[1].timeout_seconds)
        self.assertEqual(1_024, requests[1].output_limit_bytes)
        for index, slot in enumerate(("a", "b"), start=2):
            with self.subTest(slot=slot):
                self.assertEqual(
                    (
                        "ADB",
                        "-s",
                        "SERIAL",
                        "exec-out",
                        "su",
                        "0",
                        "toybox",
                        "cat",
                        f"/dev/block/by-name/abl_{slot}",
                    ),
                    requests[index].argv,
                )
                self.assertEqual(90.0, requests[index].timeout_seconds)
                self.assertEqual(BOOTLOADER_PARTITION_LIMIT, requests[index].output_limit_bytes)
                self.assertIsNone(requests[index].cwd)
                self.assertIsNone(requests[index].env)
                self.assertIsNone(requests[index].stdin_secret_field)

    def test_rejects_unknown_payload_fields_before_any_execution(self):
        with self.assertRaises(DeviceToolPlanningError) as raised:
            self.service().compile(command(command="id"), snapshot())
        self.assertEqual("invalid_device_tool_payload", raised.exception.code)

    def test_requires_a_snapshot_codename_and_an_injected_catalog_prefix(self):
        with self.assertRaises(DeviceToolPlanningError) as missing_codename:
            self.service().compile(command(), snapshot(codename=""))
        self.assertEqual("bootloader_codename_required", missing_codename.exception.code)

        with self.assertRaises(DeviceToolPlanningError) as missing_prefix:
            DeviceToolsService(bootloader_prefixes={}).compile(command(), snapshot())
        self.assertEqual("bootloader_prefix_unavailable", missing_prefix.exception.code)

    def test_constructor_copies_and_strictly_validates_the_prefix_catalog(self):
        mutable = {"akita": "akita"}
        service = DeviceToolsService(bootloader_prefixes=mutable)
        mutable["akita"] = "forged"
        self.assertEqual("akita", service.bootloader_prefixes["akita"])
        with self.assertRaises(TypeError):
            service.bootloader_prefixes["akita"] = "forged"  # type: ignore[index]

        invalid_catalogs = (
            {"Akita": "akita"},
            {"akita/path": "akita"},
            {"akita": "Akita"},
            {"akita": "-akita"},
            {"akita": "akita/path"},
        )
        for catalog in invalid_catalogs:
            with self.subTest(catalog=catalog), self.assertRaises(ValueError):
                DeviceToolsService(bootloader_prefixes=catalog)


class BootloaderSlotExecutionTests(unittest.TestCase):
    def execute(
        self,
        process_outcomes: Sequence[TransportOutcome],
        stream_outcomes: Sequence[object],
        *,
        cancellation: CancellationToken | None = None,
    ):
        transport = FakeProcessTransport(process_outcomes)
        runner = FakeBootloaderPartitionRunner(stream_outcomes)
        service = DeviceToolsService(
            bootloader_prefixes={"akita": "akita"},
            bootloader_process_transport=transport,
            bootloader_partition_runner=runner,
        )
        compilation = service.compile(command(), snapshot())
        result = service.execute_special(
            compilation,
            "inspect-slots",
            cancellation or CancellationToken(),
        )
        return result, transport, runner, compilation

    def test_active_slot_b_is_verified_against_b_not_a(self):
        getprop_b = GETPROP_A.replace("[_a]", "[_b]").replace(
            "akita-15.2-12345678",
            "akita-15.1-99999999",
        )
        result, _, _, _ = self.execute(
            [TransportOutcome(0, getprop_b), TransportOutcome(0, "0\r\n")],
            [
                BootloaderStreamOutcome(0, evidence("a")),
                BootloaderStreamOutcome(0, evidence("b", "15.1-99999999")),
            ],
        )
        self.assertTrue(result.ok)
        self.assertEqual("b", result.value["activeSlot"])
        self.assertEqual("akita-15.1-99999999", result.value["current"])

    def test_success_requires_both_slots_and_returns_the_exact_closed_dto(self):
        result, transport, runner, compilation = self.execute(
            [TransportOutcome(0, GETPROP_A), TransportOutcome(0, "0\n")],
            [
                BootloaderStreamOutcome(0, evidence("a")),
                BootloaderStreamOutcome(0, evidence("b", "15.1-99999999")),
            ],
        )

        self.assertTrue(result.ok)
        self.assertEqual("device_inspection_bootloaderVersions_succeeded", result.code)
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)
        self.assertEqual(
            {
                "action": "bootloaderVersions",
                "targetSerial": "SERIAL",
                "source": "abl_slots",
                "current": "akita-15.2-12345678",
                "activeSlot": "a",
                "bootloaderCodename": "akita",
                "slots": {
                    "a": evidence("a").to_dict(),
                    "b": evidence("b", "15.1-99999999").to_dict(),
                },
                "activeMatchesReported": True,
            },
            result.value,
        )
        self.assertEqual(list(compilation.plan.requests[:2]), transport.calls)
        self.assertEqual(
            [
                (compilation.plan.requests[2], "a", "akita"),
                (compilation.plan.requests[3], "b", "akita"),
            ],
            runner.calls,
        )
        self.assertNotIn(GETPROP_A, json.dumps(result.to_dict()))

    def test_getprop_failures_stop_before_root_or_partition_reads(self):
        failures = (
            (TransportOutcome(1, stderr="adb failed"), "bootloader_getprop_failed"),
            (TransportOutcome(0, GETPROP_A, stderr="unexpected"), "bootloader_getprop_failed"),
            (TransportOutcome(0, "not getprop"), "getprop_format_invalid"),
            (
                TransportOutcome(0, GETPROP_A.replace("[ro.bootloader]", "[ro.other]")),
                "bootloader_version_unavailable",
            ),
            (
                TransportOutcome(0, GETPROP_A.replace("[_a]", "[_c]")),
                "bootloader_active_slot_unavailable",
            ),
            (TransportOutcome(None, timed_out=True), "timed_out"),
            (TransportOutcome(None, cancelled=True), "cancelled"),
        )
        for outcome, code in failures:
            with self.subTest(code=code):
                result, transport, runner, _ = self.execute([outcome], [])
                self.assertEqual(code, result.code)
                self.assertEqual(1, len(transport.calls))
                self.assertEqual([], runner.calls)

    def test_fresh_getprop_rejects_device_version_and_slot_ambiguity(self):
        failures = (
            (
                GETPROP_A + "[ro.build.product]: [bluejay]\n",
                "bootloader_device_mismatch",
            ),
            (
                GETPROP_A + "[ro.boot.bootloader]: [akita-other]\n",
                "bootloader_version_unavailable",
            ),
            (
                GETPROP_A + "[ro.boot.slot]: [b]\n",
                "bootloader_active_slot_unavailable",
            ),
            (
                GETPROP_A.replace("akita-15.2-12345678", "bluejay-15.2"),
                "bootloader_version_prefix_mismatch",
            ),
            (
                GETPROP_A.replace("akita-15.2-12345678", "akita-bad value"),
                "bootloader_version_invalid",
            ),
        )
        for output, code in failures:
            with self.subTest(code=code):
                result, transport, runner, _ = self.execute(
                    [TransportOutcome(0, output)],
                    [],
                )
                self.assertIs(OperationStatus.FAILED, result.status)
                self.assertEqual(code, result.code)
                self.assertEqual(1, len(transport.calls))
                self.assertEqual([], runner.calls)

    def test_root_proof_must_be_an_exact_clean_zero(self):
        failures = (
            TransportOutcome(1, stderr="no su"),
            TransportOutcome(0, "2000\n"),
            TransportOutcome(0, "0\nextra\n"),
            TransportOutcome(0, "0\n", stderr="warning"),
            TransportOutcome(None, timed_out=True),
        )
        for outcome in failures:
            with self.subTest(outcome=outcome):
                result, transport, runner, _ = self.execute(
                    [TransportOutcome(0, GETPROP_A), outcome],
                    [],
                )
                self.assertIs(OperationStatus.FAILED, result.status)
                self.assertEqual(2, len(transport.calls))
                self.assertEqual([], runner.calls)

    def test_control_cancellation_and_limits_have_explicit_results(self):
        root_outcomes = (
            (TransportOutcome(None, cancelled=True), OperationStatus.CANCELLED, "cancelled"),
            (TransportOutcome(None, timed_out=True), OperationStatus.FAILED, "timed_out"),
            (
                TransportOutcome(0, output_limited=True),
                OperationStatus.FAILED,
                "output_limit_exceeded",
            ),
        )
        for outcome, status, code in root_outcomes:
            with self.subTest(code=code):
                result, transport, runner, _ = self.execute(
                    [TransportOutcome(0, GETPROP_A), outcome],
                    [],
                )
                self.assertIs(status, result.status)
                self.assertEqual(code, result.code)
                self.assertEqual(2, len(transport.calls))
                self.assertEqual([], runner.calls)

    def test_cancellation_after_getprop_never_crosses_the_root_boundary(self):
        token = CancellationToken()
        transport = CancelAfterFirstProcessTransport(TransportOutcome(0, GETPROP_A))
        runner = FakeBootloaderPartitionRunner([])
        service = DeviceToolsService(
            bootloader_prefixes={"akita": "akita"},
            bootloader_process_transport=transport,
            bootloader_partition_runner=runner,
        )
        result = service.execute_special(
            service.compile(command(), snapshot()),
            "inspect-slots",
            token,
        )
        self.assertIs(OperationStatus.CANCELLED, result.status)
        self.assertEqual("cancelled", result.code)
        self.assertEqual(1, len(transport.calls))
        self.assertEqual([], runner.calls)

    def test_slot_a_failure_is_fail_fast_and_never_reads_slot_b(self):
        failure_outcomes = (
            BootloaderStreamOutcome(7, error_code="bootloader_partition_read_failed"),
            BootloaderStreamOutcome(None, timed_out=True),
            BootloaderStreamOutcome(0, output_limited=True, error_code="bootloader_partition_limit_exceeded"),
            BootloaderStreamOutcome(0, termination_failed=True, error_code="managed_process_termination_failed"),
            BootloaderStreamOutcome(0, stderr_bytes=1, error_code="bootloader_partition_stderr_unexpected"),
            BootloaderStreamOutcome(0),
        )
        for outcome in failure_outcomes:
            with self.subTest(outcome=outcome):
                result, _, runner, compilation = self.execute(
                    [TransportOutcome(0, GETPROP_A), TransportOutcome(0, "0\n")],
                    [outcome],
                )
                self.assertIs(OperationStatus.FAILED, result.status)
                self.assertEqual([(compilation.plan.requests[2], "a", "akita")], runner.calls)

    def test_slot_b_failure_returns_no_partial_value(self):
        result, _, runner, compilation = self.execute(
            [TransportOutcome(0, GETPROP_A), TransportOutcome(0, "0\n")],
            [
                BootloaderStreamOutcome(0, evidence("a")),
                BootloaderStreamOutcome(9, error_code="bootloader_partition_read_failed"),
            ],
        )
        self.assertIs(OperationStatus.FAILED, result.status)
        self.assertIsNone(result.value)
        self.assertEqual(
            [
                (compilation.plan.requests[2], "a", "akita"),
                (compilation.plan.requests[3], "b", "akita"),
            ],
            runner.calls,
        )

    def test_cancellation_during_slot_a_is_cancelled_and_fail_fast(self):
        token = CancellationToken()
        transport = FakeProcessTransport(
            [TransportOutcome(0, GETPROP_A), TransportOutcome(0, "0\n")]
        )
        runner = CancelAfterFirstPartitionRunner(
            [BootloaderStreamOutcome(0, evidence("a"))]
        )
        service = DeviceToolsService(
            bootloader_prefixes={"akita": "akita"},
            bootloader_process_transport=transport,
            bootloader_partition_runner=runner,
        )
        compilation = service.compile(command(), snapshot())
        result = service.execute_special(compilation, "inspect-slots", token)
        self.assertIs(OperationStatus.CANCELLED, result.status)
        self.assertEqual("cancelled", result.code)
        self.assertEqual([(compilation.plan.requests[2], "a", "akita")], runner.calls)

    def test_active_slot_must_exactly_match_the_fresh_reported_version(self):
        result, _, _, _ = self.execute(
            [TransportOutcome(0, GETPROP_A), TransportOutcome(0, "0\n")],
            [
                BootloaderStreamOutcome(0, evidence("a", "different")),
                BootloaderStreamOutcome(0, evidence("b")),
            ],
        )
        self.assertIs(OperationStatus.FAILED, result.status)
        self.assertEqual("bootloader_active_version_mismatch", result.code)
        self.assertIsNone(result.value)

    def test_pre_cancel_is_cancelled_without_crossing_either_boundary(self):
        token = CancellationToken()
        token.cancel()
        result, transport, runner, _ = self.execute([], [], cancellation=token)
        self.assertIs(OperationStatus.CANCELLED, result.status)
        self.assertEqual([], transport.calls)
        self.assertEqual([], runner.calls)

        deadline = CancellationToken()
        deadline.set_deadline_at(0.0)
        timed_out, transport, runner, _ = self.execute([], [], cancellation=deadline)
        self.assertIs(OperationStatus.FAILED, timed_out.status)
        self.assertEqual("timed_out", timed_out.code)
        self.assertEqual([], transport.calls)
        self.assertEqual([], runner.calls)

    def test_execution_revalidates_the_exact_compiled_plan_before_any_boundary(self):
        transport = FakeProcessTransport([])
        runner = FakeBootloaderPartitionRunner([])
        service = DeviceToolsService(
            bootloader_prefixes={"akita": "akita"},
            bootloader_process_transport=transport,
            bootloader_partition_runner=runner,
        )
        compilation = service.compile(command(), snapshot())
        first = compilation.plan.requests[0]
        second = compilation.plan.requests[1]
        third = compilation.plan.requests[2]
        tampered_plans = (
            replace(compilation.plan, partitions=("abl_a",)),
            replace(
                compilation.plan,
                requests=(replace(first, timeout_seconds=14.0),)
                + compilation.plan.requests[1:],
            ),
            replace(
                compilation.plan,
                requests=(first, replace(second, cwd="C:\\unsafe"))
                + compilation.plan.requests[2:],
            ),
            replace(
                compilation.plan,
                requests=compilation.plan.requests[:2]
                + (
                    replace(
                        third,
                        argv=third.argv[:-1] + ("/dev/block/by-name/abl_b",),
                    ),
                )
                + compilation.plan.requests[3:],
            ),
        )
        for plan in tampered_plans:
            with self.subTest(plan=plan):
                result = service.execute_special(
                    replace(compilation, plan=plan),
                    "inspect-slots",
                    CancellationToken(),
                )
                self.assertIs(OperationStatus.FAILED, result.status)
                self.assertEqual("bootloader_inspection_compilation_invalid", result.code)
        self.assertEqual([], transport.calls)
        self.assertEqual([], runner.calls)

    def test_rejects_malformed_control_outcomes_before_parsing_stdout(self):
        malformed = (
            TransportOutcome(True),
            TransportOutcome(0, cancelled=True, timed_out=True),
            TransportOutcome(0, cancelled=cast(bool, 1)),
            cast(TransportOutcome, object()),
        )
        for outcome in malformed:
            with self.subTest(outcome=outcome):
                result, transport, runner, _ = self.execute([outcome], [])
                self.assertIs(OperationStatus.FAILED, result.status)
                self.assertEqual("bootloader_control_result_invalid", result.code)
                self.assertEqual(1, len(transport.calls))
                self.assertEqual([], runner.calls)

    def test_rejects_forged_typed_stream_evidence(self):
        wrong_slot = evidence("b")
        wrong_prefix = replace(evidence("a"), bootloader_codename="bluejay")
        for forged in (wrong_slot, wrong_prefix):
            with self.subTest(forged=forged):
                result, _, _, _ = self.execute(
                    [TransportOutcome(0, GETPROP_A), TransportOutcome(0, "0\n")],
                    [BootloaderStreamOutcome(0, forged)],
                )
                self.assertIs(OperationStatus.FAILED, result.status)
                self.assertIsNone(result.value)

    def test_rejects_malformed_stream_outcomes_before_using_evidence(self):
        malformed = (
            object(),
            BootloaderStreamOutcome(True),
            BootloaderStreamOutcome(0, stderr_bytes=-1),
            BootloaderStreamOutcome(0, stderr_bytes=BOOTLOADER_STDERR_LIMIT + 1),
            BootloaderStreamOutcome(0, stderr_bytes=True),
            BootloaderStreamOutcome(0, cancelled=True, timed_out=True),
            BootloaderStreamOutcome(0, error_code="unregistered_error"),
            BootloaderStreamOutcome(0, evidence=cast(BootloaderSlotEvidence, object())),
        )
        for outcome in malformed:
            with self.subTest(outcome=outcome):
                result, _, runner, _ = self.execute(
                    [TransportOutcome(0, GETPROP_A), TransportOutcome(0, "0\n")],
                    [outcome],
                )
                self.assertIs(OperationStatus.FAILED, result.status)
                self.assertEqual("bootloader_stream_result_invalid", result.code)
                self.assertEqual(1, len(runner.calls))

    def test_runner_exceptions_are_fixed_code_failures(self):
        failures = (
            (
                BootloaderInspectionError("bootloader_version_invalid", "bounded"),
                "bootloader_stream_request_invalid",
            ),
            (RuntimeError("private diagnostic"), "bootloader_stream_failed"),
        )
        for error, code in failures:
            with self.subTest(code=code):
                result, _, runner, _ = self.execute(
                    [TransportOutcome(0, GETPROP_A), TransportOutcome(0, "0\n")],
                    [error],
                )
                self.assertIs(OperationStatus.FAILED, result.status)
                self.assertEqual(code, result.code)
                self.assertNotIn("private diagnostic", result.message)
                self.assertEqual(1, len(runner.calls))


class BootloaderSlotCommandEngineTests(unittest.TestCase):
    def test_engine_routes_special_execution_and_persists_only_the_closed_result(self):
        control = FakeProcessTransport(
            [TransportOutcome(0, GETPROP_A), TransportOutcome(0, "0\n")]
        )
        runner = FakeBootloaderPartitionRunner(
            [
                BootloaderStreamOutcome(0, evidence("a")),
                BootloaderStreamOutcome(0, evidence("b", "15.1-99999999")),
            ]
        )
        service = DeviceToolsService(
            bootloader_prefixes={"akita": "akita"},
            bootloader_process_transport=control,
            bootloader_partition_runner=runner,
        )
        store = AppStateStore(snapshot())
        generic_transport = FakeProcessTransport([])
        engine = make_test_command_engine(
            store=store,
            executor=CommandExecutor(generic_transport),
            device_tools_service=service,
        )
        try:
            result = engine.execute(command())
        finally:
            engine.shutdown()

        self.assertTrue(result.ok)
        self.assertEqual("device_inspection_bootloaderVersions_succeeded", result.code)
        persisted = store.snapshot().last_result
        self.assertEqual(result, persisted)
        assert persisted is not None
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)
        serialized = json.dumps(persisted.to_dict())
        self.assertNotIn("[ro.boot", serialized)
        self.assertNotIn("[ro.product", serialized)
        self.assertEqual([], generic_transport.calls)
        self.assertEqual(2, len(control.calls))
        self.assertEqual(["a", "b"], [slot for _, slot, _ in runner.calls])

    def test_engine_rejects_stale_revision_before_any_boundary(self):
        control = FakeProcessTransport([])
        runner = FakeBootloaderPartitionRunner([])
        service = DeviceToolsService(
            bootloader_prefixes={"akita": "akita"},
            bootloader_process_transport=control,
            bootloader_partition_runner=runner,
        )
        engine = make_test_command_engine(
            store=AppStateStore(snapshot()),
            executor=CommandExecutor(FakeProcessTransport([])),
            device_tools_service=service,
        )
        try:
            stale = replace(command(), expected_revision=6)
            result = engine.execute(stale)
        finally:
            engine.shutdown()

        self.assertIs(OperationStatus.FAILED, result.status)
        self.assertEqual("stale_revision", result.code)
        self.assertEqual([], control.calls)
        self.assertEqual([], runner.calls)

    def test_runner_revalidates_device_state_before_special_boundary(self):
        control = FakeProcessTransport([])
        runner = FakeBootloaderPartitionRunner([])
        service = DeviceToolsService(
            bootloader_prefixes={"akita": "akita"},
            bootloader_process_transport=control,
            bootloader_partition_runner=runner,
        )
        engine = make_test_command_engine(
            store=AppStateStore(snapshot()),
            executor=CommandExecutor(FakeProcessTransport([])),
            device_tools_service=service,
            snapshot_provider=lambda _serial: snapshot(mode="fastboot"),
        )
        try:
            result = engine.execute(command())
        finally:
            engine.shutdown()

        self.assertIs(OperationStatus.FAILED, result.status)
        self.assertEqual("device_state_changed", result.code)
        self.assertEqual([], control.calls)
        self.assertEqual([], runner.calls)


if __name__ == "__main__":
    unittest.main()
