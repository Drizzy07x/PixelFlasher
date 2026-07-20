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

    def test_root_package_actions_have_closed_route_free_receipts(self):
        for action in ("denylistAdd", "denylistRemove", "suPolicy"):
            with self.subTest(action=action):
                public = project_operation_result(
                    "apps.action",
                    OperationResult.success(
                        "package-root",
                        value={"action": action},
                    ),
                )
                self.assertEqual({"action": action}, public["value"])
                with self.assertRaises(PublicProjectionError):
                    project_operation_result(
                        "apps.action",
                        OperationResult.success(
                            "package-root-open",
                            value={"action": action, "path": "C:/private/device.apk"},
                        ),
                    )

    def test_projects_only_a_verified_route_free_apk_export_receipt(self):
        value = {
            "action": "export",
            "export": {
                "package": "com.example.app",
                "fileName": "com.example.app.apk",
                "sha256": "a" * 64,
                "size": 1024,
                "verified": True,
                "remoteCleaned": True,
            },
        }
        public = project_operation_result(
            "apps.action",
            OperationResult.success("package-export", value=value),
        )

        self.assertEqual(value, public["value"])
        self.assertNotIn("path", repr(public).casefold())
        for field, replacement in (
            ("remoteCleaned", False),
            ("sha256", "A" * 64),
            ("fileName", "../private.apk"),
        ):
            hostile = {
                **value,
                "export": {**value["export"], field: replacement},
            }
            with self.subTest(field=field), self.assertRaises(PublicProjectionError):
                project_operation_result(
                    "apps.action",
                    OperationResult.success("package-export-hostile", value=hostile),
                )


if __name__ == "__main__":
    unittest.main()
