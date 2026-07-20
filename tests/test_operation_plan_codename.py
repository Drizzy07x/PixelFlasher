import unittest

from pixelflasher_core import (
    AppSnapshot,
    DeviceInfo,
    OperationPlan,
    OperationPlanner,
    ProcessRequest,
)

NOW = 1_700_000_000.0


def plan_for(
    codename: str,
    *,
    architecture: str = "arm64",
    kmi: str = "android14-5.15",
) -> OperationPlan:
    return OperationPlan(
        (ProcessRequest(("fastboot", "-s", "SERIAL", "getvar", "product")),),
        plan_id="plan",
        created=NOW,
        expires=NOW + 300,
        snapshot_revision=0,
        target_serial="SERIAL",
        expected_codename=codename,
        expected_device_state="fastboot",
        expected_architecture=architecture,
        expected_kmi=kmi,
    )


class OperationPlanCodenameTests(unittest.TestCase):
    def test_codename_is_immutable_serialized_and_fingerprinted(self):
        akita = plan_for("akita")
        husky = plan_for("husky")

        self.assertEqual("akita", akita.expected_codename)
        self.assertEqual("akita", akita.to_dict()["expected_codename"])
        self.assertEqual("arm64", akita.to_dict()["expected_architecture"])
        self.assertEqual("android14-5.15", akita.to_dict()["expected_kmi"])
        self.assertNotEqual(akita.execution_fingerprint(), husky.execution_fingerprint())
        self.assertNotEqual(
            akita.execution_fingerprint(),
            plan_for("akita", architecture="x86_64").execution_fingerprint(),
        )
        self.assertNotEqual(
            akita.execution_fingerprint(),
            plan_for("akita", kmi="android15-6.1").execution_fingerprint(),
        )

    def test_planner_rejects_device_substitution_with_same_serial_and_mode(self):
        planner = OperationPlanner(clock=lambda: NOW + 1)
        snapshot = AppSnapshot(
            devices=(
                DeviceInfo(
                    "SERIAL",
                    codename="husky",
                    mode="fastboot",
                    architecture="arm64",
                    kmi="android14-5.15",
                ),
            ),
            selected_serials=("SERIAL",),
        )

        issue = planner.revalidate(plan_for("akita"), snapshot)

        self.assertEqual(
            ("device_codename_changed", "device codename changed after planning"),
            issue,
        )

    def test_planner_rejects_architecture_or_kmi_changes(self):
        planner = OperationPlanner(clock=lambda: NOW + 1)
        for device, expected in (
            (
                DeviceInfo(
                    "SERIAL",
                    codename="akita",
                    mode="fastboot",
                    architecture="x86_64",
                    kmi="android14-5.15",
                ),
                "device_architecture_changed",
            ),
            (
                DeviceInfo(
                    "SERIAL",
                    codename="akita",
                    mode="fastboot",
                    architecture="arm64",
                    kmi="android15-6.1",
                ),
                "device_kmi_changed",
            ),
        ):
            with self.subTest(expected=expected):
                issue = planner.revalidate(
                    plan_for("akita"),
                    AppSnapshot(
                        devices=(device,),
                        selected_serials=("SERIAL",),
                    ),
                )
                self.assertIsNotNone(issue)
                assert issue is not None
                self.assertEqual(expected, issue[0])


if __name__ == "__main__":
    unittest.main()
