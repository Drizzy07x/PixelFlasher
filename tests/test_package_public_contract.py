import unittest

from pixelflasher_core import OperationResult
from ui.public_bridge import PublicProjectionError, project_operation_result


class PackagePublicContractTests(unittest.TestCase):
    def test_projects_closed_permission_report(self):
        value = {
            "action": "permissions",
            "report": {
                "package": "com.example.app",
                "requested": ["android.permission.CAMERA"],
                "runtimeGranted": ["android.permission.CAMERA"],
                "runtimeDenied": [],
                "requestedCount": 1,
                "runtimeCount": 1,
                "bounded": True,
            },
        }

        public = project_operation_result(
            "apps.action",
            OperationResult.success("permissions", value=value),
        )

        self.assertEqual(value, public["value"])

    def test_rejects_open_or_inconsistent_package_results(self):
        invalid = (
            {"action": "launch", "path": "C:/private/app.apk"},
            {
                "action": "permissions",
                "report": {
                    "package": "com.example.app",
                    "requested": [],
                    "runtimeGranted": ["android.permission.CAMERA"],
                    "runtimeDenied": ["android.permission.CAMERA"],
                    "requestedCount": 0,
                    "runtimeCount": 2,
                    "bounded": True,
                },
            },
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(PublicProjectionError):
                project_operation_result(
                    "apps.action",
                    OperationResult.success("package", value=value),
                )


if __name__ == "__main__":
    unittest.main()
