import inspect
import tempfile
import time
import unittest
from pathlib import Path

from pixelflasher_core.contracts import (
    AppCommand,
    AppSnapshot,
    DeviceInfo,
    OperationPlan,
    OperationPostcondition,
    OperationRisk,
    OperationStatus,
    ProcessRequest,
)
from pixelflasher_core.engine import CommandEngine as CommandEngineType
from pixelflasher_core.executor import (
    CommandExecutor,
    FakeProcessTransport,
    TransportOutcome,
)
from pixelflasher_core.observer import (
    PostconditionObserver,
    ProcessDeviceObservationProbe,
)
from pixelflasher_core.runtime import ApplicationRuntime
from pixelflasher_core.store import AppStateStore
from tests.command_engine_factory import make_test_command_engine as CommandEngine

SERIAL = "ABCDEF123456"


def state() -> AppSnapshot:
    return AppSnapshot(
        devices=(DeviceInfo(SERIAL, mode="adb", online=True),),
        selected_serials=(SERIAL,),
        selected_serial=SERIAL,
    )


def mutation() -> AppCommand:
    created = time.time()
    plan = OperationPlan(
        requests=(ProcessRequest(("adb", "-s", SERIAL, "reboot", "recovery")),),
        label="Reboot to recovery",
        created=created,
        expires=created + 300,
        risk=OperationRisk.MUTATING,
        postconditions=(
            OperationPostcondition("device_mode", {"mode": "recovery"}),
        ),
        snapshot_revision=0,
        target_serial=SERIAL,
        expected_device_state="adb",
    )
    return AppCommand(
        "device.reboot",
        expected_revision=0,
        target_serial=SERIAL,
        operation_plan=plan,
        operation_id="runner-integration",
    )


class EngineOperationRunnerIntegrationTests(unittest.TestCase):
    def test_begin_operation_occurs_at_runner_boundary_and_completion_closes_state(self):
        store = AppStateStore(state())
        transport = FakeProcessTransport([TransportOutcome(0)])
        observed: list[AppSnapshot] = []
        subscription = store.subscribe(observed.append)
        engine = CommandEngine(
            store=store,
            executor=CommandExecutor(transport),
            postcondition_observer=lambda *_args: True,
        )

        result = engine.execute(mutation())

        self.assertTrue(result.ok)
        self.assertEqual("postconditions_satisfied", result.code)
        self.assertEqual(1, len(transport.calls))
        self.assertEqual([1, 2], [snapshot.revision for snapshot in observed])
        active_operation = observed[0].active_operation
        self.assertIsNotNone(active_operation)
        if active_operation is None:
            self.fail("runner boundary did not open active operation state")
        self.assertEqual(
            "runner-integration",
            active_operation.operation_id,
        )
        self.assertIsNone(observed[1].active_operation)
        self.assertEqual(result, observed[1].last_result)
        subscription.cancel()
        engine.shutdown()

    def test_default_production_observer_fails_closed_when_toolchain_is_unavailable(self):
        store = AppStateStore(state())
        transport = FakeProcessTransport([TransportOutcome(0)])
        engine = CommandEngine(
            store=store,
            executor=CommandExecutor(transport),
        )
        command = mutation()
        plan = command.operation_plan
        self.assertIsNotNone(plan)
        if plan is None:
            self.fail("mutation command omitted its plan")

        result = engine.execute(command)

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("postcondition_unverified", result.code)
        self.assertEqual([plan.request], transport.calls)
        self.assertEqual(2, store.snapshot().revision)
        self.assertIsNone(store.snapshot().active_operation)
        self.assertEqual(result, store.snapshot().last_result)
        engine.shutdown()

    def test_unknown_command_uses_closed_registry_error(self):
        engine = CommandEngine()

        result = engine.execute(AppCommand("unknown.command"))

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("command_unknown", result.code)
        self.assertNotIn("not_implemented", result.to_dict().values())
        engine.shutdown()

    def test_runtime_installs_one_shared_production_observer(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime_transport = FakeProcessTransport()
            runtime = ApplicationRuntime.open(
                Path(directory) / "PixelFlasher.json",
                transport=runtime_transport,
            )
            runtime_observer = runtime.command_engine.postcondition_observer
            self.assertIsInstance(runtime_observer, PostconditionObserver)
            if not isinstance(runtime_observer, PostconditionObserver):
                self.fail("ApplicationRuntime omitted its production observer")
            runtime_probe = runtime_observer.probe
            self.assertIsInstance(runtime_probe, ProcessDeviceObservationProbe)
            if not isinstance(runtime_probe, ProcessDeviceObservationProbe):
                self.fail("ApplicationRuntime installed the wrong observer probe")
            self.assertIs(runtime.command_engine.device_service, runtime_probe.device_service)
            self.assertIs(runtime.executor.transport, runtime_probe.transport)
            runtime.shutdown()

    def test_command_engine_requires_an_explicitly_composed_dependency_graph(self):
        signature = inspect.signature(CommandEngineType)
        dependencies = tuple(signature.parameters.values())

        self.assertGreater(len(dependencies), 1)
        self.assertTrue(
            all(parameter.default is inspect.Parameter.empty for parameter in dependencies)
        )
        with self.assertRaises(TypeError):
            CommandEngineType()  # type: ignore[call-arg]

    def test_explicit_test_observer_takes_precedence(self):
        def explicit(
            _plan: OperationPlan,
            _postcondition: OperationPostcondition,
            _snapshot: AppSnapshot,
        ) -> bool:
            return True

        engine = CommandEngine(postcondition_observer=explicit)

        self.assertIs(explicit, engine.postcondition_observer)
        engine.shutdown()

    def test_command_engine_has_no_direct_process_executor_bypass(self):
        source = inspect.getsource(CommandEngineType)

        self.assertNotIn("self.executor.execute(", source)
        self.assertIn("self.operation_runner.execute(", source)
        self.assertNotIn("not_implemented", source)


if __name__ == "__main__":
    unittest.main()
