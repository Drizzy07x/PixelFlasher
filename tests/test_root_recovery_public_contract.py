import unittest

from pixelflasher_core import OperationResult
from ui.public_bridge import PublicProjectionError, project_operation_result


class RootRecoveryPublicContractTests(unittest.TestCase):
    def test_projects_only_verified_closed_recovery_receipt(self):
        projected = project_operation_result(
            "tools.shizuku",
            OperationResult.success(
                "shizuku-public",
                value={
                    "action": "startShizuku",
                    "targetSerial": "SERIAL",
                    "verified": True,
                },
            ),
        )["value"]

        self.assertEqual(
            {
                "action": "startShizuku",
                "targetSerial": "SERIAL",
                "verified": True,
            },
            projected,
        )

    def test_rejects_unknown_fields_unverified_results_and_action_confusion(self):
        invalid = (
            {
                "action": "startShizuku",
                "targetSerial": "SERIAL",
                "verified": True,
                "path": "/data/private",
            },
            {
                "action": "startShizuku",
                "targetSerial": "SERIAL",
                "verified": False,
            },
            {
                "action": "eraseModules",
                "targetSerial": "SERIAL",
                "verified": True,
            },
        )
        for command in ("tools.shizuku", "tools.sos"):
            for value in invalid:
                with self.subTest(command=command, value=value):
                    with self.assertRaises(PublicProjectionError):
                        project_operation_result(
                            command,
                            OperationResult.success("root-recovery-public", value=value),
                        )

        confused = (
            ("tools.shizuku", "disableModules"),
            ("tools.sos", "startShizuku"),
        )
        for command, action in confused:
            with self.subTest(command=command, action=action):
                with self.assertRaises(PublicProjectionError):
                    project_operation_result(
                        command,
                        OperationResult.success(
                            "root-recovery-confused",
                            value={
                                "action": action,
                                "targetSerial": "SERIAL",
                                "verified": True,
                            },
                        ),
                    )


if __name__ == "__main__":
    unittest.main()
