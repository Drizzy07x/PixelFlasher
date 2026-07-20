import unittest

from pixelflasher_core import OperationResult
from ui.public_bridge import PublicProjectionError, project_operation_result

BACKUP_ID = "a" * 32
BACKUP_RECORD = {
    "id": BACKUP_ID,
    "sha256": "b" * 64,
    "sizeBytes": 4096,
    "createdAt": 1_700_000_000,
    "targetSerial": "SERIAL",
    "deviceCodename": "akita",
    "partition": "boot",
    "slot": "a",
    "targetPartition": "boot_a",
    "provenance": "created",
    "available": True,
    "integrity": "stored",
}


class BackupPublicContractTests(unittest.TestCase):
    def project(self, command: str, value: object):
        return project_operation_result(
            command,
            OperationResult.success("backup-public-contract", value=value),
        )["value"]

    def test_projects_route_free_inventory_and_operation_receipts(self):
        inventory = self.project(
            "backups.list",
            {
                "backups": [BACKUP_RECORD],
                "count": 1,
                "totalCount": 1,
                "filteredSerial": "SERIAL",
                "revision": 7,
                "bounded": True,
                "truncated": False,
            },
        )
        created = self.project(
            "backups.create",
            {
                "action": "create",
                "targetSerial": "SERIAL",
                "partition": "boot_a",
                "slot": "a",
                "backup": BACKUP_RECORD,
                "inventoryRegistered": True,
            },
        )
        deleted = self.project(
            "backups.delete",
            {
                "backupId": BACKUP_ID,
                "deleted": True,
                "objectRemoved": True,
                "sharedObjectRetained": False,
                "objectMissing": False,
                "cleanupDeferred": False,
                "revision": 8,
            },
        )

        self.assertNotIn("path", inventory["backups"][0])
        self.assertEqual(BACKUP_ID, created["backup"]["id"])
        self.assertTrue(deleted["objectRemoved"])

    def test_rejects_paths_unbounded_inventory_and_inconsistent_receipts(self):
        invalid_values = (
            (
                "backups.list",
                {
                    "backups": [{**BACKUP_RECORD, "path": "C:/private/boot.img"}],
                    "count": 1,
                    "totalCount": 1,
                    "filteredSerial": None,
                    "revision": 7,
                    "bounded": True,
                    "truncated": False,
                },
            ),
            (
                "backups.list",
                {
                    "backups": [],
                    "count": 0,
                    "totalCount": 1,
                    "filteredSerial": None,
                    "revision": 7,
                    "bounded": False,
                    "truncated": True,
                },
            ),
            (
                "backups.delete",
                {
                    "backupId": BACKUP_ID,
                    "deleted": True,
                    "objectRemoved": True,
                    "sharedObjectRetained": True,
                    "objectMissing": False,
                    "cleanupDeferred": False,
                    "revision": 8,
                },
            ),
        )
        for command, value in invalid_values:
            with self.subTest(command=command), self.assertRaises(
                PublicProjectionError
            ):
                self.project(command, value)


if __name__ == "__main__":
    unittest.main()
