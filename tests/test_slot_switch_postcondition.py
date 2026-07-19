from __future__ import annotations

import unittest

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    AppStateStore,
    CommandExecutor,
    DeviceInfo,
    InteractionDecision,
    OperationResult,
    OperationRunner,
    OperationStatus,
    SafetyPolicy,
    ToolchainInfo,
)
from pixelflasher_core.engine import CommandEngine
from tests.command_engine_factory import make_test_command_engine
from tests.stateful_slot_transport import StatefulSlotTransport, make_slot_observer

SERIAL = "ABCDEF123456"
MUTATION = ("FASTBOOT", "-s", SERIAL, "--set-active=b")
SLOT_QUERY = ("FASTBOOT", "-s", SERIAL, "getvar", "current-slot")


def snapshot() -> AppSnapshot:
    return AppSnapshot(
        devices=(
            DeviceInfo(
                SERIAL,
                codename="akita",
                mode="fastboot",
                slot="a",
                bootloader="unlocked",
                online=True,
            ),
        ),
        selected_serial=SERIAL,
        toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
    )


def command(payload: dict[str, object]) -> AppCommand:
    return AppCommand(
        "device.switchSlot",
        expected_revision=0,
        target_serial=SERIAL,
        payload=payload,
    )


class SlotSwitchPostconditionGateTests(unittest.TestCase):
    def _engine(self, transport: StatefulSlotTransport) -> CommandEngine:
        canonical = snapshot()
        store = AppStateStore(canonical)
        executor = CommandExecutor(transport)
        postcondition_observer = make_slot_observer(transport)
        safety_policy = SafetyPolicy()

        def snapshot_provider(_serial: str) -> AppSnapshot:
            return store.snapshot()

        return make_test_command_engine(
            store=store,
            executor=executor,
            safety_policy=safety_policy,
            operation_runner=OperationRunner(
                executor,
                safety_policy=safety_policy,
                snapshot_provider=snapshot_provider,
                postcondition_observer=postcondition_observer,
                postcondition_timeout_seconds=0.15,
            ),
            snapshot_provider=snapshot_provider,
            postcondition_observer=postcondition_observer,
            interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
        )

    @staticmethod
    def _confirmed_switch(engine: CommandEngine) -> OperationResult:
        preview = engine.execute(command({"slot": "b"}))
        confirmation = preview.value["confirmation"]["required_text"]
        return engine.execute(
            command(
                {
                    "slot": "b",
                    "confirmationText": confirmation,
                }
            )
        )

    def test_zero_exit_without_slot_change_is_typed_mismatch(self) -> None:
        transport = StatefulSlotTransport(
            SERIAL,
            active_slot="a",
            switch_applies=False,
        )

        result = self._confirmed_switch(self._engine(transport))

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("postcondition_mismatch", result.code)
        self.assertEqual("a", transport.active_slot)
        argv = [request.argv for request in transport.calls]
        self.assertEqual(1, argv.count(MUTATION))
        self.assertIn(SLOT_QUERY, argv)
        self.assertTrue(all(value[1:3] == ("-s", SERIAL) for value in argv))

    def test_missing_current_slot_evidence_is_typed_unverified(self) -> None:
        transport = StatefulSlotTransport(
            SERIAL,
            active_slot="a",
            switch_applies=True,
            slot_evidence_available=False,
        )

        result = self._confirmed_switch(self._engine(transport))

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("postcondition_unverified", result.code)
        self.assertEqual("b", transport.active_slot)
        argv = [request.argv for request in transport.calls]
        self.assertEqual(1, argv.count(MUTATION))
        self.assertIn(SLOT_QUERY, argv)
        self.assertTrue(all(value[1:3] == ("-s", SERIAL) for value in argv))


if __name__ == "__main__":
    unittest.main()
