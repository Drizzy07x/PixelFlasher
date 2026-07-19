import unittest

from pixelflasher_core import (
    AppSnapshot,
    DeviceInfo,
    OperationPlan,
    OperationPlanner,
    ProcessRequest,
)

NOW = 1_700_000_000.0


def plan_for(codename: str) -> OperationPlan:
    return OperationPlan(
        (ProcessRequest(("fastboot", "-s", "SERIAL", "getvar", "product")),),
        plan_id="plan",
        created=NOW,
        expires=NOW + 300,
        snapshot_revision=0,
        target_serial="SERIAL",
        expected_codename=codename,
        expected_device_state="fastboot",
    )


class OperationPlanCodenameTests(unittest.TestCase):
    def test_codename_is_immutable_serialized_and_fingerprinted(self):
        akita = plan_for("akita")
        husky = plan_for("husky")

        self.assertEqual("akita", akita.expected_codename)
        self.assertEqual("akita", akita.to_dict()["expected_codename"])
        self.assertNotEqual(akita.execution_fingerprint(), husky.execution_fingerprint())

    def test_planner_rejects_device_substitution_with_same_serial_and_mode(self):
        planner = OperationPlanner(clock=lambda: NOW + 1)
        snapshot = AppSnapshot(
            devices=(DeviceInfo("SERIAL", codename="husky", mode="fastboot"),),
            selected_serials=("SERIAL",),
        )

        issue = planner.revalidate(plan_for("akita"), snapshot)

        self.assertEqual(
            ("device_codename_changed", "device codename changed after planning"),
            issue,
        )


if __name__ == "__main__":
    unittest.main()
