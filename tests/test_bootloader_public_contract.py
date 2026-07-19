from __future__ import annotations

import unittest
from typing import cast

from pixelflasher_core import OperationResult
from ui.public_bridge import JSONValue, PublicProjectionError, project_operation_result

COMMAND = "device.inspect"
MAX_ABL_PARTITION_BYTES = 64 * 1024 * 1024


def bootloader_value() -> dict[str, object]:
    return {
        "action": "bootloaderVersions",
        "targetSerial": "ABC123",
        "source": "abl_slots",
        "current": "akita-15.2-12345678",
        "activeSlot": "a",
        "bootloaderCodename": "akita",
        "slots": {
            "a": {
                "partition": "abl_a",
                "version": "15.2-12345678",
                "fullVersion": "akita-15.2-12345678",
                "sha256": "a" * 64,
                "sizeBytes": MAX_ABL_PARTITION_BYTES,
            },
            "b": {
                "partition": "abl_b",
                "version": "15.1-12000000",
                "fullVersion": "akita-15.1-12000000",
                "sha256": "b" * 64,
                "sizeBytes": 1,
            },
        },
        "activeMatchesReported": True,
    }


class BootloaderPublicContractTests(unittest.TestCase):
    def project(self, value: object) -> dict[str, JSONValue]:
        return project_operation_result(
            COMMAND,
            OperationResult.success("bootloader-contract", value=value),
        )

    def test_projects_only_the_closed_verified_slot_report(self) -> None:
        value = bootloader_value()

        public = self.project(value)

        self.assertEqual(value, public["value"])
        self.assertNotIn("stdout", public)
        self.assertNotIn("stderr", public)

    def test_success_requires_a_typed_value_with_exact_outer_fields(self) -> None:
        with self.assertRaises(PublicProjectionError):
            project_operation_result(
                COMMAND,
                OperationResult.success("bootloader-contract"),
            )

        value = bootloader_value()
        for field in tuple(value):
            with self.subTest(field=field):
                malformed = {key: item for key, item in value.items() if key != field}
                with self.assertRaises(PublicProjectionError):
                    self.project(malformed)

        with self.assertRaises(PublicProjectionError):
            self.project({**value, "rawPartition": "private bytes"})

    def test_rejects_invalid_identity_version_and_active_slot_evidence(self) -> None:
        value = bootloader_value()
        invalid_values = (
            {**value, "action": "bootloaderVersionsUnknown"},
            {**value, "targetSerial": "bad serial"},
            {**value, "source": "adb_getprop"},
            {**value, "current": "akita-15.1-12000000"},
            {**value, "current": "akita-15.2\nprivate"},
            {**value, "activeSlot": "c"},
            {**value, "bootloaderCodename": "Akita"},
            {**value, "bootloaderCodename": "akita_private"},
            {**value, "activeMatchesReported": False},
        )
        for malformed in invalid_values:
            with self.subTest(malformed=malformed), self.assertRaises(PublicProjectionError):
                self.project(malformed)

    def test_rejects_expanded_or_invalid_nested_slot_receipts(self) -> None:
        value = bootloader_value()
        slots = cast(dict[str, object], value["slots"])
        slot_values = dict(slots)
        slot_a = dict(cast(dict[str, object], slot_values["a"]))
        invalid_slot_a = (
            {**slot_a, "partition": "abl_b"},
            {**slot_a, "version": "15.2 private"},
            {**slot_a, "version": "x" * 128},
            {**slot_a, "fullVersion": "akita-15.1-12000000"},
            {**slot_a, "sha256": "A" * 64},
            {**slot_a, "sha256": "a" * 63},
            {**slot_a, "sizeBytes": 0},
            {**slot_a, "sizeBytes": MAX_ABL_PARTITION_BYTES + 1},
            {**slot_a, "sizeBytes": True},
            {**slot_a, "path": "/dev/block/by-name/abl_a"},
        )
        for malformed_slot in invalid_slot_a:
            with self.subTest(malformed_slot=malformed_slot):
                malformed_slots = {**slot_values, "a": malformed_slot}
                with self.assertRaises(PublicProjectionError):
                    self.project({**value, "slots": malformed_slots})

        for malformed_slots in (
            {"a": slot_values["a"]},
            {**slot_values, "c": slot_values["a"]},
            {**slot_values, "a": slot_values["b"], "b": slot_values["a"]},
        ):
            with self.subTest(slots=malformed_slots), self.assertRaises(PublicProjectionError):
                self.project({**value, "slots": malformed_slots})


if __name__ == "__main__":
    unittest.main()
