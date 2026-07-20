import unittest
from typing import Any, cast

from pixelflasher_core import OperationResult
from ui.bridge_contract import BridgeProtocolError, BridgeRequest
from ui.command_registry import COMMAND_REGISTRY
from ui.public_bridge import PublicProjectionError, project_operation_result


def inventory_value() -> dict[str, Any]:
    specs = (
        ("pif.custom_json", "playintegrityfix", "json"),
        ("pif.custom_prop", "playintegrityfix", "prop"),
        ("pif.module_json", "playintegrityfix", "json"),
        ("pif.legacy_json", "playintegrityfix", "json"),
        ("pif.app_replace", "playintegrityfix", "list"),
        ("pif.scripts_only", "playintegrityfix", "marker"),
        ("tricky.spoof", "tricky_store", "prop"),
        ("tricky.target", "tricky_store", "list"),
        ("tricky.security_patch", "tricky_store", "text"),
        ("tricky.tee", "tricky_store", "text"),
        ("targeted.targets", "targetedfix", "list"),
    )
    profiles = [
        {
            "id": profile_id,
            "module": module,
            "format": profile_format,
            "present": index == 0,
            "size": 128 if index == 0 else 0,
            "sha256": "a" * 64 if index == 0 else None,
        }
        for index, (profile_id, module, profile_format) in enumerate(specs)
    ]
    return {
        "schemaVersion": 1,
        "rootAccess": "verified",
        "bounded": True,
        "count": len(profiles),
        "profiles": profiles,
        "targetCount": 1,
        "targets": [
            {
                "packageName": "com.google.android.gms",
                "format": "json",
                "present": True,
                "size": 64,
                "sha256": "b" * 64,
            }
        ],
    }


class PifInventoryPublicContractTests(unittest.TestCase):
    def project(self, value: object) -> dict[str, Any]:
        result = project_operation_result(
            "root.pif.inventory",
            OperationResult.success("pif-inventory", value=value),
        )
        return cast(dict[str, Any], result["value"])

    def test_registry_bridge_and_projection_are_read_only_and_closed(self):
        spec = COMMAND_REGISTRY["root.pif.inventory"]
        self.assertTrue(spec.implemented)
        self.assertTrue(spec.exposed)
        self.assertEqual("read_only", spec.mutability.value)
        self.assertEqual("device_read", spec.risk.value)
        self.assertEqual(("bounded_pif_inventory_returned",), spec.postconditions)
        valid = BridgeRequest(2, "pif", "root.pif.inventory", {"serial": "SERIAL"}, 7)
        self.assertIs(valid, valid.validate())

        projected = self.project(inventory_value())
        self.assertEqual(11, projected["count"])
        serialized = repr(projected).casefold()
        self.assertNotIn("/data/adb", serialized)
        self.assertNotIn("keybox", serialized)

    def test_bridge_and_projection_reject_ambiguous_or_hostile_values(self):
        for payload in ({}, {"serial": ""}, {"serial": "SERIAL", "path": "/data/adb"}):
            with self.subTest(payload=payload):
                with self.assertRaises(BridgeProtocolError):
                    BridgeRequest(2, "bad-pif", "root.pif.inventory", payload, 7).validate()

        cases = []
        extra = inventory_value()
        extra["path"] = "C:\\private\\pif.json"
        cases.append(extra)
        reordered = inventory_value()
        reordered["profiles"] = list(reversed(reordered["profiles"]))
        cases.append(reordered)
        invalid_target = inventory_value()
        invalid_target["targets"][0]["packageName"] = "../private"
        cases.append(invalid_target)
        unhashed = inventory_value()
        unhashed["profiles"][0]["sha256"] = None
        cases.append(unhashed)
        for value in cases:
            with self.subTest(keys=tuple(value)):
                with self.assertRaises(PublicProjectionError):
                    self.project(value)


if __name__ == "__main__":
    unittest.main()
