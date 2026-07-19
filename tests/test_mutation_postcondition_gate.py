import unittest

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    CommandExecutor,
    DeviceInfo,
    FakeProcessTransport,
    ProcessRequest,
    TransportOutcome,
)
from pixelflasher_core.contracts import (
    OperationPlan,
    OperationPostcondition,
    OperationRisk,
)
from pixelflasher_core.observer import DeviceObservation, PostconditionObserver
from pixelflasher_core.operation_runner import OperationRunner


class ConnectedProbe:
    def observe(self, serial: str) -> DeviceObservation:
        return DeviceObservation(serial, mode="adb")


class MutationPostconditionGateTests(unittest.TestCase):
    def test_all_nine_mutation_families_stop_before_process_without_observer(self):
        cases = (
            ("reboot", OperationPostcondition("device_mode", {"mode": "recovery"})),
            ("slot", OperationPostcondition("active_slot", {"slot": "b"})),
            (
                "bootloader",
                OperationPostcondition("bootloader_state", {"state": "unlocked"}),
            ),
            (
                "boot",
                OperationPostcondition("live_boot_active", {"sha256": "a" * 64}),
            ),
            (
                "flash",
                OperationPostcondition("flash_applied", {"partitions": ("boot",)}),
            ),
            (
                "backup",
                OperationPostcondition(
                    "partition_written",
                    {"partition": "boot_a", "slot": "", "sha256": "b" * 64},
                ),
            ),
            (
                "partition",
                OperationPostcondition("partition_erased", {"partition": "userdata"}),
            ),
            (
                "root_module",
                OperationPostcondition(
                    "root_module_state",
                    {"moduleId": "zygisk_next", "state": "disabled"},
                ),
            ),
            (
                "ota_reset",
                OperationPostcondition("ota_idle_state", {"idle": True}),
            ),
        )
        snapshot = AppSnapshot(
            devices=(DeviceInfo("SERIAL", mode="fastboot", online=True),),
            selected_serial="SERIAL",
        )

        for family, postcondition in cases:
            with self.subTest(family=family):
                transport = FakeProcessTransport([TransportOutcome(0)])
                request = ProcessRequest(("fastboot", "-s", "SERIAL", "getvar", "product"))
                plan = OperationPlan(
                    request=request,
                    target_serial="SERIAL",
                    risk=OperationRisk.MUTATING,
                    postconditions=(postcondition,),
                )
                command = AppCommand(
                    f"test.{family}",
                    expected_revision=0,
                    target_serial="SERIAL",
                    operation_plan=plan,
                )

                result = OperationRunner(CommandExecutor(transport)).execute(
                    command,
                    plan,
                    snapshot,
                )

                self.assertEqual("postcondition_unverified", result.code)
                self.assertEqual([], transport.calls)

    def test_unsupported_production_postcondition_stops_before_first_process(self):
        transport = FakeProcessTransport([TransportOutcome(0)])
        plan = OperationPlan(
            request=ProcessRequest(("adb", "-s", "SERIAL", "install", "selected.apk")),
            target_serial="SERIAL",
            expected_device_state="adb",
            risk=OperationRisk.MUTATING,
            postconditions=(
                OperationPostcondition(
                    "package_installation",
                    {"apkSha256": "a" * 64},
                ),
            ),
        )
        snapshot = AppSnapshot(
            devices=(DeviceInfo("SERIAL", mode="adb", online=True),),
            selected_serial="SERIAL",
        )
        command = AppCommand(
            "apps.action",
            expected_revision=snapshot.revision,
            target_serial="SERIAL",
            operation_plan=plan,
        )
        observer = PostconditionObserver(ConnectedProbe())

        result = OperationRunner(CommandExecutor(transport)).execute(
            command,
            plan,
            snapshot,
            postcondition_observer=observer,
        )

        self.assertEqual("postcondition_unverified", result.code)
        self.assertIn("package_installation", result.message)
        self.assertEqual([], transport.calls)


if __name__ == "__main__":
    unittest.main()
