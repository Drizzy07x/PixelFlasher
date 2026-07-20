import ast
import inspect
import json
import sys
import threading
import time
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from pixelflasher_core import (
    AppCommand,
    ApplicationRuntime,
    AppSnapshot,
    AppStateStore,
    BootInfo,
    CancellationToken,
    CommandExecutor,
    CommandKind,
    ConfigStore,
    DeviceInfo,
    FakeProcessTransport,
    FakeTransportStep,
    FirmwareInfo,
    FlashPlan,
    InteractionBroker,
    InteractionDecision,
    InteractionKind,
    InteractionRequest,
    InteractionResponse,
    InteractionTimeoutError,
    OperationFinished,
    OperationPlan,
    OperationResult,
    OperationStatus,
    PixelFlasherEngine,
    ProcessRequest,
    SafetyPolicy,
    SnapshotChanged,
    StaleRevisionError,
    SubprocessTransport,
    ToolchainInfo,
    TransportOutcome,
)
from pixelflasher_core.contracts import OperationPostcondition, OperationRisk
from tests.command_engine_factory import make_test_command_engine as CommandEngine
from tests.stateful_postcondition_observer import StatefulPostconditionObserver


def process(*argv):
    return ProcessRequest(tuple(argv))


def plan_for(serial="SERIAL-A", *requests, **overrides):
    values = {
        "requests": requests or (process("fastboot", "-s", serial, "getvar", "product"),),
        "target_serial": serial,
        "risk": OperationRisk.DESTRUCTIVE,
        "postconditions": (
            OperationPostcondition(
                "device_reachable",
                {"mode": "fastboot"},
                "the simulated fastboot target remains reachable",
            ),
        ),
    }
    values.update(overrides)
    return OperationPlan(**values)


def flash_command(operation_plan, *, revision=0, operation_id="flash-op", serial="SERIAL-A"):
    return AppCommand(
        CommandKind.FLASH_EXECUTE,
        expected_revision=revision,
        target_serial=serial,
        operation_plan=operation_plan,
        operation_id=operation_id,
    )


class ContractTests(unittest.TestCase):
    def test_public_engine_facade_has_one_synchronous_typed_boundary(self):
        store = AppStateStore(AppSnapshot())
        command_engine = CommandEngine(store=store)
        facade = PixelFlasherEngine(
            command_engine=command_engine,
            command_handler=lambda _command: None,  # type: ignore[arg-type,return-value]
        )
        observed = []
        subscription = facade.subscribe(observed.append, emit_current=True)

        result = facade.execute(AppCommand("unsupported", operation_id="typed-result"))

        self.assertIs(facade.snapshot(), store.snapshot())
        self.assertFalse(hasattr(facade, "command_engine"))
        self.assertFalse(hasattr(facade, "store"))
        self.assertEqual(
            {
                "cancel",
                "execute",
                "respond_interaction",
                "shutdown",
                "snapshot",
                "subscribe",
            },
            {
                name
                for name, value in vars(PixelFlasherEngine).items()
                if not name.startswith("_") and callable(value)
            },
        )
        self.assertEqual(
            [
                "command_engine",
                "command_handler",
                "event_subscriber",
                "event_publisher",
                "cancellation_handler",
                "interaction_responder",
                "shutdown_handler",
            ],
            list(inspect.signature(PixelFlasherEngine).parameters),
        )
        with self.assertRaises(TypeError):
            PixelFlasherEngine(store=store)  # type: ignore[call-arg]
        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("invalid_engine_result", result.code)
        self.assertIsInstance(observed[0], SnapshotChanged)
        self.assertIs(result, observed[-1].result)
        self.assertIsInstance(observed[-1], OperationFinished)
        self.assertEqual("operation_not_active", facade.cancel("missing").code)
        self.assertEqual(
            "interaction_unsupported",
            facade.respond_interaction(
                "missing",
                InteractionResponse(InteractionDecision.ACCEPTED, 0),
            ).code,
        )

        subscription()
        facade.shutdown()
        stopped = facade.execute(AppCommand("unsupported", operation_id="stopped"))
        self.assertEqual("engine_shutdown", stopped.code)

    def test_stable_command_kinds_and_json_serialization(self):
        self.assertEqual(
            [
                "snapshot.get",
                "device.scan",
                "device.select",
                "firmware.select",
                "flash.plan.update",
                "flash.execute",
            ],
            [kind.value for kind in CommandKind],
        )
        snapshot = AppSnapshot(
            revision=8,
            devices=(DeviceInfo("A", "Pixel", "akita", "fastboot", "a", True, True),),
            selected_serials=("A", "B"),
            selected_serial="A",
            firmware=FirmwareInfo("factory.zip", "factory", "AP4A", "firmware-hash", True, True),
            boot=BootInfo("boot-1", "boot.img", "boot-hash", "init_boot", True),
            plan=FlashPlan("wipeData", {"disable_verity": True}, 3, "plan-fingerprint"),
            toolchain=ToolchainInfo("adb", "fastboot", "36.0.0", True),
        )
        result = OperationResult.success("op", value=snapshot.to_dict())

        encoded = json.dumps({"snapshot": snapshot.to_dict(), "result": result.to_dict()})
        decoded = json.loads(encoded)

        self.assertEqual("snapshot", decoded["snapshot"]["event_type"])
        self.assertEqual(["A", "B"], decoded["snapshot"]["selected_serials"])
        self.assertEqual("firmware-hash", decoded["snapshot"]["firmware"]["hash"])
        self.assertEqual("runtime", decoded["result"]["event_type"])

    def test_public_engine_never_serializes_unexpected_exception_text(self):
        secret = "APATCH-SUPERKEY-MUST-NOT-LEAK"
        command_engine = CommandEngine(store=AppStateStore())

        def failing_handler(_command):
            raise RuntimeError(secret)

        facade = PixelFlasherEngine(
            command_engine=command_engine,
            command_handler=failing_handler,
        )

        result = facade.execute(
            AppCommand("test.failure", operation_id="redacted-failure")
        )

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("engine_error", result.code)
        self.assertEqual("The command could not be completed.", result.message)
        self.assertNotIn(secret, repr(result))

    def test_operation_plan_has_an_immutable_exact_command_sequence(self):
        operation_plan = OperationPlan(
            requests=(process("fastboot", "devices"), process("fastboot", "getvar", "product")),
            target_serial="A",
            expected_device_state="fastboot",
            firmware_hash="F",
            boot_hash="B",
            partitions=("boot", "vendor_boot"),
            slots=("a", "b"),
            data_behavior="preserve",
            plan_revision=2,
            fingerprint="P",
            confirmation_nonce="N",
        )

        self.assertIsInstance(operation_plan.requests, tuple)
        self.assertEqual(("boot", "vendor_boot"), operation_plan.partitions)
        with self.assertRaises(AttributeError):
            _ = operation_plan.request
        with self.assertRaises(FrozenInstanceError):
            operation_plan.slots += ("c",)

    def test_process_output_limits_are_bounded_and_serialized(self):
        request = ProcessRequest(("adb", "devices"), output_limit_bytes=8_192)

        self.assertEqual(8_192, request.to_dict()["output_limit_bytes"])
        self.assertEqual(8_192, request.to_public_dict()["output_limit_bytes"])
        for invalid in (True, 0, 1_023, 64 * 1_024 * 1_024 + 1):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                ProcessRequest(("adb", "devices"), output_limit_bytes=invalid)

    def test_core_never_imports_wx_or_legacy_runtime_modules(self):
        package = Path(__file__).resolve().parents[1] / "pixelflasher_core"
        forbidden = {"wx", "Main", "runtime", "pf_modules"}
        violations = []
        for source_path in package.glob("*.py"):
            tree = ast.parse(source_path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    roots = {alias.name.split(".", 1)[0] for alias in node.names}
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    roots = {node.module.split(".", 1)[0]}
                else:
                    continue
                if roots & forbidden:
                    violations.append((source_path.name, roots & forbidden))
        self.assertEqual([], violations)


class StoreAndEngineTests(unittest.TestCase):
    def test_store_revisions_and_subscription_are_canonical(self):
        store = AppStateStore()
        observed = []
        subscription = store.subscribe(observed.append, emit_current=True)

        updated = store.update(
            expected_revision=0,
            selected_serials=("A",),
            selected_serial="A",
        )
        with self.assertRaises(StaleRevisionError):
            store.update(expected_revision=0, selected_serial=None, selected_serials=())
        subscription.cancel()
        store.update(expected_revision=1, selected_serial=None, selected_serials=())

        self.assertEqual(1, updated.revision)
        self.assertEqual([0, 1], [snapshot.revision for snapshot in observed])

    def test_stale_revision_is_an_explicit_failure(self):
        store = AppStateStore()
        store.update(expected_revision=0, selected_serial="A", selected_serials=("A",))
        engine = CommandEngine(store=store)

        result = engine.execute(
            AppCommand(
                CommandKind.FIRMWARE_SELECT,
                expected_revision=0,
                payload={"path": "factory.zip"},
            )
        )

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("stale_revision", result.code)

    def test_serial_changed_while_confirming_is_blocked_before_execution(self):
        store = AppStateStore(AppSnapshot(selected_serial="SERIAL-A"))
        transport = FakeProcessTransport([TransportOutcome(0)])

        def change_selection(_request):
            store.update(
                expected_revision=0,
                selected_serials=("SERIAL-B",),
                selected_serial="SERIAL-B",
            )
            return InteractionDecision.ACCEPTED

        engine = CommandEngine(
            store=store,
            executor=CommandExecutor(transport),
            interaction_handler=change_selection,
        )
        result = engine.execute(flash_command(plan_for()))

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("target_serial_changed", result.code)
        self.assertEqual([], transport.calls)

    def test_destructive_operations_are_serialized_and_revalidated(self):
        started = threading.Event()
        release = threading.Event()
        transport = FakeProcessTransport(
            [
                FakeTransportStep(TransportOutcome(0), started, release),
                TransportOutcome(0),
            ]
        )
        engine = CommandEngine(
            store=AppStateStore(AppSnapshot(selected_serial="SERIAL-A")),
            executor=CommandExecutor(transport),
            postcondition_observer=StatefulPostconditionObserver(transport),
            interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
        )
        results = {}
        first = flash_command(plan_for(), operation_id="first")
        second = flash_command(plan_for(), operation_id="second")
        first_thread = threading.Thread(
            target=lambda: results.setdefault("first", engine.execute(first)),
            daemon=True,
        )
        second_thread = threading.Thread(
            target=lambda: results.setdefault("second", engine.execute(second)),
            daemon=True,
        )

        first_thread.start()
        self.assertTrue(started.wait(1))
        second_thread.start()
        release.set()
        first_thread.join(2)
        second_thread.join(2)

        self.assertFalse(first_thread.is_alive())
        self.assertFalse(second_thread.is_alive())
        self.assertEqual(OperationStatus.SUCCESS, results["first"].status)
        self.assertEqual("stale_revision", results["second"].code)
        self.assertEqual(1, transport.max_active_count)
        self.assertEqual(1, len(transport.calls))

    def test_running_operation_can_be_cancelled_explicitly(self):
        started = threading.Event()
        release = threading.Event()
        transport = FakeProcessTransport(
            [FakeTransportStep(TransportOutcome(0), started, release)]
        )
        engine = CommandEngine(
            store=AppStateStore(AppSnapshot(selected_serial="SERIAL-A")),
            executor=CommandExecutor(transport),
            postcondition_observer=StatefulPostconditionObserver(transport),
            interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
        )
        command = flash_command(plan_for(), operation_id="cancel-me")
        results = []
        worker = threading.Thread(target=lambda: results.append(engine.execute(command)), daemon=True)

        worker.start()
        self.assertTrue(started.wait(1))
        self.assertTrue(engine.cancel("cancel-me"))
        worker.join(2)

        self.assertFalse(worker.is_alive())
        self.assertEqual(OperationStatus.FAILED, results[0].status)
        self.assertEqual("outcome_unknown", results[0].code)
        self.assertEqual((), engine.store.snapshot().active_operations)

    def test_success_failure_fail_fast_and_exact_commands(self):
        first = process("adb", "devices", "-l")
        second = process("fastboot", "devices")
        success_transport = FakeProcessTransport(
            [TransportOutcome(0, "adb-out\n"), TransportOutcome(0, "fastboot-out\n")]
        )
        success_engine = CommandEngine(
            executor=CommandExecutor(success_transport),
        )
        success = success_engine.execute(
            AppCommand(
                CommandKind.DEVICE_SCAN,
                expected_revision=0,
                operation_plan=OperationPlan(requests=(first, second)),
            )
        )

        self.assertEqual(OperationStatus.SUCCESS, success.status)
        self.assertEqual("adb-out\nfastboot-out\n", success.stdout)
        self.assertEqual([first, second], success_transport.calls)

        failure_transport = FakeProcessTransport(
            [TransportOutcome(17, "partial", "bad"), TransportOutcome(0)]
        )
        failure_engine = CommandEngine(executor=CommandExecutor(failure_transport))
        failure = failure_engine.execute(
            AppCommand(
                CommandKind.DEVICE_SCAN,
                expected_revision=0,
                operation_plan=OperationPlan(requests=(first, second)),
            )
        )

        self.assertEqual(OperationStatus.FAILED, failure.status)
        self.assertEqual("process_failed", failure.code)
        self.assertEqual(17, failure.exit_code)
        self.assertEqual([first], failure_transport.calls)

    def test_default_headless_policy_cancels_unconfirmed_destructive_work(self):
        transport = FakeProcessTransport([TransportOutcome(0)])
        engine = CommandEngine(
            store=AppStateStore(AppSnapshot(selected_serial="SERIAL-A")),
            executor=CommandExecutor(transport),
        )

        result = engine.execute(flash_command(plan_for()))

        self.assertEqual(OperationStatus.CANCELLED, result.status)
        self.assertEqual("user_cancelled", result.code)
        self.assertEqual([], transport.calls)


class SafetyPolicyTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = AppSnapshot(
            revision=7,
            devices=(
                DeviceInfo(
                    "SERIAL-A",
                    mode="fastboot",
                    architecture="arm64",
                    kmi="android14-5.15",
                ),
            ),
            selected_serial="SERIAL-A",
            firmware=FirmwareInfo(hash="F1"),
            boot=BootInfo(hash="B1"),
            plan=FlashPlan(revision=3, fingerprint="P1"),
        )
        self.base_plan = plan_for(
            "SERIAL-A",
            expected_device_state="fastboot",
            firmware_hash="F1",
            boot_hash="B1",
            plan_revision=3,
            fingerprint="P1",
        )
        self.policy = SafetyPolicy()

    def decision_for(self, operation_plan=None, **command_changes):
        values = {
            "kind": CommandKind.FLASH_EXECUTE,
            "expected_revision": 7,
            "target_serial": "SERIAL-A",
            "operation_plan": operation_plan or self.base_plan,
        }
        values.update(command_changes)
        return self.policy.evaluate(AppCommand(**values), self.snapshot)

    def test_golden_safety_mismatch_codes(self):
        branches = {
            "device_state_changed": replace(self.base_plan, expected_device_state="adb"),
            "device_architecture_changed": replace(
                self.base_plan,
                expected_architecture="x86_64",
            ),
            "device_kmi_changed": replace(
                self.base_plan,
                expected_kmi="android15-6.1",
            ),
            "firmware_hash_changed": replace(self.base_plan, firmware_hash="F2"),
            "boot_hash_changed": replace(self.base_plan, boot_hash="B2"),
            "plan_revision_changed": replace(self.base_plan, plan_revision=2),
            "plan_fingerprint_changed": replace(self.base_plan, fingerprint="P2"),
        }
        for expected_code, operation_plan in branches.items():
            with self.subTest(expected_code=expected_code):
                decision = self.decision_for(operation_plan)
                self.assertFalse(decision.allowed)
                self.assertEqual(expected_code, decision.code)

        stale = self.decision_for(expected_revision=6)
        self.assertEqual("stale_revision", stale.code)
        ambiguous = self.decision_for(target_serial="SERIAL-B")
        self.assertEqual("ambiguous_target_serial", ambiguous.code)

    def test_each_high_risk_branch_requires_a_nonce_bound_token(self):
        for behavior in ("wipe", "erase", "switch", "unlock"):
            with self.subTest(behavior=behavior):
                risky = replace(
                    self.base_plan,
                    data_behavior=behavior,
                    confirmation_nonce="nonce",
                    confirmation_token=None,
                )
                decision = self.decision_for(risky)
                self.assertFalse(decision.allowed)
                self.assertEqual("reinforced_confirmation_required", decision.code)

        risky = replace(
            self.base_plan,
            data_behavior="wipe",
            confirmation_nonce="nonce",
            confirmation_token=None,
        )
        confirmed = replace(risky, confirmation_token=risky.confirmation_challenge())
        decision = self.decision_for(confirmed)
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.interaction.reinforced)
        self.assertEqual("nonce", decision.interaction.confirmation_nonce)

    def test_reinforced_confirmation_uses_semantic_tokens_not_path_substrings(self):
        harmless = replace(
            self.base_plan,
            requests=(
                process(
                    "adb",
                    "-s",
                    "SERIAL-A",
                    "exec-out",
                    "cat",
                    "/dev/block/by-name/abl_a",
                    r"C:\verified\unlock-images\boot.img",
                ),
            ),
            risk=OperationRisk.READ_ONLY,
            postconditions=(),
            data_behavior="preserve",
        )
        read_command = AppCommand(
            "device.inspect",
            expected_revision=7,
            target_serial="SERIAL-A",
            operation_plan=harmless,
        )

        self.assertFalse(self.policy.requires_reinforced_confirmation(read_command))

        for argv in (
            ("fastboot", "erase", "userdata"),
            ("fastboot", "flashing", "unlock"),
            ("fastboot", "--set-active=b"),
        ):
            with self.subTest(argv=argv):
                risky = replace(self.base_plan, requests=(process(*argv),))
                self.assertTrue(
                    self.policy.requires_reinforced_confirmation(
                        replace(read_command, operation_plan=risky)
                    )
                )


class ExecutorAndInteractionTests(unittest.TestCase):
    def test_subprocess_transport_sets_shell_false_and_preserves_argv(self):
        child = Mock()
        child.returncode = 0
        child.communicate.return_value = ("out", "err")
        with patch("pixelflasher_core.executor.subprocess.Popen", return_value=child) as popen:
            outcome = SubprocessTransport().run(
                process("literal tool", "argument with spaces", "&not-a-shell-token"),
                __import__("pixelflasher_core").CancellationToken(),
            )

        self.assertEqual(0, outcome.returncode)
        args, kwargs = popen.call_args
        self.assertEqual(
            ["literal tool", "argument with spaces", "&not-a-shell-token"],
            args[0],
        )
        self.assertIs(False, kwargs["shell"])

    def test_subprocess_transport_terminates_at_the_aggregate_output_limit(self):
        request = ProcessRequest(
            (
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'x' * 1048576)",
            ),
            timeout_seconds=5,
            output_limit_bytes=4_096,
        )

        outcome = SubprocessTransport().run(request, CancellationToken())

        self.assertTrue(outcome.output_limited)
        self.assertFalse(outcome.timed_out)
        self.assertLessEqual(
            len(outcome.stdout.encode("utf-8"))
            + len(outcome.stderr.encode("utf-8")),
            4_096,
        )

    def test_executor_fails_closed_on_an_oversized_injected_transport(self):
        request = ProcessRequest(("adb", "devices"), output_limit_bytes=1_024)
        executor = CommandExecutor(
            FakeProcessTransport([TransportOutcome(0, "x" * 1_025)])
        )

        result = executor.execute(
            AppCommand("test.bounded", operation_id="bounded-output"),
            OperationPlan(requests=(request,)),
        )

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("output_limit_exceeded", result.code)
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)

    def test_interaction_broker_checks_revision_and_releases_waiters(self):
        broker = InteractionBroker(timeout_seconds=1)
        request = InteractionRequest(
            "op",
            InteractionKind.CONFIRM,
            "Confirm",
            "Continue?",
            expected_revision=5,
        )
        decisions = []
        worker = threading.Thread(target=lambda: decisions.append(broker.request(request)), daemon=True)
        worker.start()
        deadline = time.monotonic() + 1
        while not broker.pending_requests() and time.monotonic() < deadline:
            time.sleep(0.005)

        self.assertFalse(broker.respond("op", InteractionDecision.ACCEPTED, 4))
        self.assertTrue(broker.respond("op", InteractionDecision.ACCEPTED, 5))
        worker.join(1)
        self.assertEqual([InteractionDecision.ACCEPTED], decisions)

        blocked = threading.Thread(target=lambda: decisions.append(broker.request(replace(request, operation_id="op2"))), daemon=True)
        blocked.start()
        deadline = time.monotonic() + 1
        while not broker.pending_requests() and time.monotonic() < deadline:
            time.sleep(0.005)
        broker.shutdown()
        blocked.join(1)
        self.assertEqual(InteractionDecision.CANCELLED, decisions[-1])

    def test_interaction_broker_honors_the_command_wait_budget(self):
        broker = InteractionBroker(timeout_seconds=10)
        request = InteractionRequest(
            "deadline-op",
            InteractionKind.CONFIRM,
            "Confirm",
            "Continue?",
            expected_revision=5,
            _timeout_seconds=0.01,
        )

        started = time.monotonic()
        with self.assertRaises(InteractionTimeoutError):
            broker.request(request)
        elapsed = time.monotonic() - started

        self.assertLess(elapsed, 0.5)
        self.assertEqual((), broker.pending_requests())

    def test_interaction_callback_time_is_charged_to_the_wait_budget(self):
        broker = InteractionBroker(
            timeout_seconds=10,
            on_request=lambda _request: time.sleep(0.03),
        )
        request = InteractionRequest(
            "slow-publish-op",
            InteractionKind.CONFIRM,
            "Confirm",
            "Continue?",
            expected_revision=5,
            _timeout_seconds=0.01,
        )

        started = time.monotonic()
        with self.assertRaises(InteractionTimeoutError):
            broker.request(request)
        elapsed = time.monotonic() - started

        self.assertLess(elapsed, 0.1)


class ConfigAndRuntimeTests(unittest.TestCase):
    def test_legacy_config_is_preserved_versioned_backed_up_and_atomically_saved(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            legacy = {"device": "A", "firmware_path": "factory.zip", "mode": "dryRun", "theme": "dark"}
            path.write_text(json.dumps(legacy), encoding="utf-8")
            store = ConfigStore(path)

            document = store.load()
            self.assertEqual("dark", document.values["theme"])
            store.save(document.with_values(theme="light"))

            saved = json.loads(path.read_text(encoding="utf-8"))
            backup = json.loads(store.backup_path.read_text(encoding="utf-8"))
            self.assertEqual(2, saved["_pixelflasher_core_schema"])
            self.assertEqual("light", saved["theme"])
            self.assertEqual(2, backup["_pixelflasher_core_schema"])
            self.assertEqual("dark", backup["theme"])
            self.assertEqual(
                legacy,
                json.loads(
                    store.migration_backup_path.read_text(encoding="utf-8")
                ),
            )
            self.assertEqual([], list(path.parent.glob(".config.json.*.tmp")))

    def test_latin1_legacy_config_is_backed_up_on_first_load(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            legacy_bytes = json.dumps(
                {"device": "A", "label": "teléfono"},
                ensure_ascii=False,
            ).encode("latin-1")
            path.write_bytes(legacy_bytes)
            store = ConfigStore(path)

            document = store.load()

            self.assertEqual("teléfono", document.values["label"])
            self.assertEqual(legacy_bytes, store.backup_path.read_bytes())

    def test_runtime_broker_delivers_typed_events_and_persists_on_shutdown(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps({"device": "SERIAL-A", "firmware_path": "factory.zip", "mode": "dryRun"}),
                encoding="utf-8",
            )
            transport = FakeProcessTransport([TransportOutcome(0, "ok")])
            runtime = ApplicationRuntime.open(
                path,
                transport=transport,
                postcondition_observer=StatefulPostconditionObserver(transport),
                interaction_timeout_seconds=1,
            )
            event_types = []

            def observe(event):
                event_types.append(event.event_type)
                if isinstance(event, InteractionRequest):
                    self.assertTrue(
                        runtime.respond_interaction(
                            event.operation_id,
                            InteractionResponse(
                                InteractionDecision.ACCEPTED,
                                event.expected_revision,
                            ),
                        )
                    )

            runtime.subscribe(observe, emit_current=True)
            command = flash_command(plan_for())
            result = runtime.execute(command)
            runtime.shutdown()

            self.assertEqual(OperationStatus.SUCCESS, result.status)
            self.assertTrue({"snapshot", "progress", "interaction", "runtime"} <= set(event_types))
            saved = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual("SERIAL-A", saved["device"])
            self.assertEqual(2, saved["_pixelflasher_core_schema"])

    def test_runtime_cancel_wakes_a_pending_interaction_immediately(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "device": "SERIAL-A",
                        "firmware_path": "factory.zip",
                        "mode": "dryRun",
                    }
                ),
                encoding="utf-8",
            )
            runtime = ApplicationRuntime.open(
                path,
                transport=FakeProcessTransport([]),
                interaction_timeout_seconds=10,
            )
            command = flash_command(
                plan_for(),
                operation_id="cancel-pending-interaction",
            )
            results: list[OperationResult] = []
            worker = threading.Thread(
                target=lambda: results.append(runtime.execute(command)),
                daemon=True,
            )
            worker.start()
            deadline = time.monotonic() + 1
            while not runtime.interaction_broker.pending_requests() and time.monotonic() < deadline:
                time.sleep(0.005)

            started = time.monotonic()
            acknowledgement = runtime.cancel(command.operation_id)
            worker.join(0.5)
            elapsed = time.monotonic() - started
            runtime.shutdown()

        self.assertTrue(acknowledgement)
        self.assertFalse(worker.is_alive())
        self.assertLess(elapsed, 0.5)
        self.assertEqual(1, len(results))
        self.assertEqual(OperationStatus.CANCELLED, results[0].status)

    def test_runtime_round_trips_dry_run_and_missing_field_migrates_safe(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            explicit = root / "explicit.json"
            explicit.write_text(
                json.dumps(
                    {
                        "_pixelflasher_core_state": {
                            "plan": {
                                "mode": "factory",
                                "options": {"verify": True},
                                "revision": 4,
                                "fingerprint": "P4",
                                "dry_run": False,
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            runtime = ApplicationRuntime.open(explicit)
            self.assertFalse(runtime.snapshot().plan.dry_run)
            runtime.shutdown()
            reopened = ApplicationRuntime.open(explicit)
            self.assertFalse(reopened.snapshot().plan.dry_run)
            reopened.shutdown()

            migrated = root / "migrated.json"
            migrated.write_text(
                json.dumps(
                    {
                        "mode": "keepData",
                        "_pixelflasher_core_state": {
                            "plan": {"mode": "factory", "options": {"verify": True}}
                        },
                    }
                ),
                encoding="utf-8",
            )
            safe = ApplicationRuntime.open(migrated)
            self.assertTrue(safe.snapshot().plan.dry_run)
            safe.shutdown()


if __name__ == "__main__":
    unittest.main()
