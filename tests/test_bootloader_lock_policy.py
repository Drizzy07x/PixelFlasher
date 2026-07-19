import unittest
from dataclasses import replace

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    AppStateStore,
    BootloaderLockEvidence,
    CommandExecutor,
    DeviceInfo,
    FakeProcessTransport,
    FirmwareInfo,
    FlashPlan,
    InteractionDecision,
    OperationResult,
    OperationStatus,
    ToolchainInfo,
    TransportOutcome,
)
from tests.command_engine_factory import make_test_command_engine as CommandEngine
from tests.stateful_postcondition_observer import StatefulPostconditionObserver

SERIAL = "SERIAL-STOCK"
FIRMWARE_HASH = "f" * 64
FLASH_OPERATION_ID = "verified-factory-flash"
PLAN_FINGERPRINT = "verified-stock-plan"


def lock_evidence(*, revision=0, firmware_hash=FIRMWARE_HASH, codename="akita"):
    return BootloaderLockEvidence(
        serial=SERIAL,
        device_codename=codename,
        firmware_hash=firmware_hash,
        firmware_build="AP4A.250205.002",
        flash_operation_id=FLASH_OPERATION_ID,
        flash_plan_fingerprint=PLAN_FINGERPRINT,
        snapshot_revision=revision,
        required_partitions=("boot", "vbmeta"),
        flashed_partitions=("boot", "vbmeta", "dtbo"),
        slots=("a", "b"),
    )


def stock_snapshot(*, evidence=(), revision=0, firmware_hash=FIRMWARE_HASH):
    return AppSnapshot(
        revision=revision,
        devices=(
            DeviceInfo(
                SERIAL,
                codename="akita",
                mode="fastboot",
                online=True,
                bootloader="unlocked",
            ),
        ),
        selected_serial=SERIAL,
        firmware=FirmwareInfo(
            "factory.zip",
            "factory",
            "AP4A.250205.002",
            firmware_hash,
            True,
            True,
        ),
        plan=FlashPlan(
            "factory",
            {"verify": True, "slot": "both"},
            revision=3,
            fingerprint=PLAN_FINGERPRINT,
            dry_run=False,
        ),
        toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
        last_result=OperationResult.success(
            FLASH_OPERATION_ID,
            code="process_succeeded",
        ),
        bootloader_lock_evidence=tuple(evidence),
    )


def lock_command(*, confirmation_text=None, revision=0):
    payload = {}
    if confirmation_text is not None:
        payload["confirmationText"] = confirmation_text
    return AppCommand(
        "device.bootloader.lock",
        expected_revision=revision,
        target_serial=SERIAL,
        payload=payload,
    )


class BootloaderLockPolicyTests(unittest.TestCase):
    def test_lock_fails_closed_without_backend_stock_evidence(self):
        transport = FakeProcessTransport([])
        engine = CommandEngine(
            store=AppStateStore(stock_snapshot()),
            executor=CommandExecutor(transport),
        )

        result = engine.execute(lock_command())

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("bootloader_lock_stock_evidence_required", result.code)
        self.assertIn("complete compatible stock factory flash", result.message)
        self.assertEqual([], transport.calls)

    def test_valid_revision_bound_stock_evidence_allows_only_exact_reinforced_lock(self):
        evidence = lock_evidence()
        transport = FakeProcessTransport([TransportOutcome(0)])
        interactions = []
        engine = CommandEngine(
            store=AppStateStore(stock_snapshot(evidence=(evidence,))),
            executor=CommandExecutor(transport),
            postcondition_observer=StatefulPostconditionObserver(transport),
            interaction_handler=lambda request: interactions.append(request)
            or InteractionDecision.ACCEPTED,
        )

        preview = engine.execute(lock_command())
        required = preview.value["confirmation"]["required_text"]
        result = engine.execute(lock_command(confirmation_text=required))

        self.assertEqual("LOCK -STOCK", required)
        self.assertEqual(OperationStatus.SUCCESS, result.status)
        self.assertEqual(
            [("FASTBOOT", "-s", SERIAL, "flashing", "lock")],
            [request.argv for request in transport.calls],
        )
        self.assertTrue(interactions[0].reinforced)
        self.assertEqual((), engine.store.snapshot().bootloader_lock_evidence)

    def test_stale_or_incompatible_evidence_never_reaches_fastboot(self):
        cases = (
            (
                stock_snapshot(evidence=(lock_evidence(revision=1),)),
                "bootloader_lock_state_changed",
            ),
            (
                stock_snapshot(
                    evidence=(lock_evidence(),),
                    firmware_hash="e" * 64,
                ),
                "bootloader_lock_firmware_mismatch",
            ),
            (
                stock_snapshot(evidence=(lock_evidence(codename="husky"),)),
                "bootloader_lock_device_mismatch",
            ),
        )
        for snapshot, expected_code in cases:
            with self.subTest(expected_code=expected_code):
                transport = FakeProcessTransport([])
                result = CommandEngine(
                    store=AppStateStore(snapshot),
                    executor=CommandExecutor(transport),
                ).execute(lock_command())
                self.assertEqual(expected_code, result.code)
                self.assertEqual([], transport.calls)

    def test_store_invalidates_evidence_on_state_change_and_other_operations(self):
        evidence = lock_evidence()
        store = AppStateStore(stock_snapshot(evidence=(evidence,)))

        updated = store.update(expected_revision=0, selected_serial=SERIAL)
        self.assertEqual((), updated.bootloader_lock_evidence)

        revision_one_evidence = replace(evidence, snapshot_revision=1)
        store = AppStateStore(
            replace(
                stock_snapshot(revision=1),
                bootloader_lock_evidence=(revision_one_evidence,),
            )
        )
        started = store.begin_operation(
            "other-operation",
            expected_revision=1,
            kind="boot.flash",
        )
        self.assertEqual((), started.bootloader_lock_evidence)


if __name__ == "__main__":
    unittest.main()
