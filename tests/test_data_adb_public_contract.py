import unittest

from pixelflasher_core import OperationResult
from ui.public_bridge import PublicProjectionError, project_operation_result


class DataAdbPublicContractTests(unittest.TestCase):
    def test_projects_only_closed_route_free_receipts(self) -> None:
        values = {
            "root.dataAdb.backup": {
                "action": "backup",
                "targetSerial": "SERIAL123456",
                "fileName": "root-state.pfdataadb",
                "sha256": "a" * 64,
                "sizeBytes": 2048,
                "payloadSha256": "b" * 64,
                "entryCount": 3,
                "contentFingerprint": "c" * 64,
                "deviceCodename": "komodo",
                "verified": True,
                "remoteCleaned": True,
            },
            "root.dataAdb.restore": {
                "action": "restore",
                "targetSerial": "SERIAL123456",
                "payloadSha256": "b" * 64,
                "entryCount": 3,
                "contentFingerprint": "c" * 64,
                "deviceCodename": "komodo",
                "verified": True,
                "remoteCleaned": True,
            },
            "root.dataAdb.clear": {
                "action": "clear",
                "targetSerial": "SERIAL123456",
                "empty": True,
                "verified": True,
            },
        }
        for command, value in values.items():
            with self.subTest(command=command):
                public = project_operation_result(
                    command,
                    OperationResult.success(command, value=value),
                )
                self.assertEqual(value, public["value"])
                self.assertNotIn("path", repr(public).casefold())

    def test_rejects_open_or_unverified_receipts(self) -> None:
        base = {
            "action": "backup",
            "targetSerial": "SERIAL123456",
            "fileName": "root-state.pfdataadb",
            "sha256": "a" * 64,
            "sizeBytes": 2048,
            "payloadSha256": "b" * 64,
            "entryCount": 3,
            "contentFingerprint": "c" * 64,
            "deviceCodename": "komodo",
            "verified": True,
            "remoteCleaned": True,
        }
        for hostile in (
            {**base, "path": "C:/private/root-state.pfdataadb"},
            {**base, "verified": False},
            {**base, "fileName": "../root-state.pfdataadb"},
            {**base, "sha256": "A" * 64},
        ):
            with self.subTest(hostile=hostile), self.assertRaises(PublicProjectionError):
                project_operation_result(
                    "root.dataAdb.backup",
                    OperationResult.success("data-adb", value=hostile),
                )


if __name__ == "__main__":
    unittest.main()
