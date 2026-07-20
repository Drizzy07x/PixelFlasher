from __future__ import annotations

import unittest
from dataclasses import replace

from pixelflasher_core import OperationResult
from ui.public_bridge import PublicProjectionError, project_operation_result


class PartitionPublicContractTests(unittest.TestCase):
    def test_read_projects_only_the_closed_verified_receipt(self) -> None:
        value = {
            "action": "read",
            "targetSerial": "SERIAL123456",
            "partition": "vendor_boot_a",
            "fileName": "vendor_boot_a.img",
            "sha256": "a" * 64,
            "sizeBytes": 4096,
            "verified": True,
        }

        public = project_operation_result(
            "partitions.read",
            OperationResult.success("read-partition", value=value),
        )

        self.assertEqual(value, public["value"])
        for field in tuple(value):
            with self.subTest(field=field), self.assertRaises(PublicProjectionError):
                project_operation_result(
                    "partitions.read",
                    OperationResult.success(
                        "read-partition",
                        value={key: item for key, item in value.items() if key != field},
                    ),
                )
        with self.assertRaises(PublicProjectionError):
            project_operation_result(
                "partitions.read",
                OperationResult.success(
                    "read-partition",
                    value={**value, "path": "C:\\private\\vendor_boot.img"},
                ),
            )

    def test_write_and_erase_require_exact_device_side_proof(self) -> None:
        receipts = {
            "partitions.write": {
                "action": "write",
                "targetSerial": "SERIAL123456",
                "partition": "boot_a",
                "sha256": "b" * 64,
                "verified": True,
            },
            "partitions.erase": {
                "action": "erase",
                "targetSerial": "SERIAL123456",
                "partition": "metadata",
                "erased": True,
                "verified": True,
            },
        }

        for command, value in receipts.items():
            with self.subTest(command=command):
                public = project_operation_result(
                    command,
                    OperationResult.success("partition-mutation", value=value),
                )
                self.assertEqual(value, public["value"])
                with self.assertRaises(PublicProjectionError):
                    project_operation_result(
                        command,
                        OperationResult.success(
                            "partition-mutation",
                            value={**value, "verified": False},
                        ),
                    )
                with self.assertRaises(PublicProjectionError):
                    project_operation_result(
                        command,
                        OperationResult.success(
                            "partition-mutation",
                            value={**value, "diagnostic": "raw output"},
                        ),
                    )

    def test_erase_confirmation_remains_available_before_execution(self) -> None:
        value = {"confirmation": {"required_text": "ERASE metadata 123456"}}

        public = project_operation_result(
            "partitions.erase",
            replace(
                OperationResult.failed(
                    "erase-partition",
                    code="reinforced_confirmation_required",
                ),
                value=value,
            ),
        )

        self.assertEqual(value, public["value"])

    def test_success_without_receipt_is_rejected(self) -> None:
        for command in ("partitions.read", "partitions.write", "partitions.erase"):
            with self.subTest(command=command), self.assertRaises(PublicProjectionError):
                project_operation_result(
                    command,
                    OperationResult.success("partition-missing-receipt"),
                )


if __name__ == "__main__":
    unittest.main()
