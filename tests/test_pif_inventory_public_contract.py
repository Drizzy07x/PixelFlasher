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

    def test_delete_contract_requires_canonical_profile_serial_and_phrase(self):
        profile_id = "pif.custom_json"
        payload = {
            "serial": "SERIAL",
            "action": "deleteProfile",
            "profileId": profile_id,
            "confirmationText": f"DELETE PIF {profile_id} SERIAL",
        }
        spec = COMMAND_REGISTRY["tools.pif"]
        self.assertTrue(spec.implemented)
        self.assertTrue(spec.exposed)
        self.assertEqual("destructive", spec.mutability.value)
        self.assertEqual("destructive", spec.risk.value)
        request = BridgeRequest(2, "pif-delete", "tools.pif", payload, 7)
        self.assertIs(request, request.validate())

        projected = project_operation_result(
            "tools.pif",
            OperationResult.success(
                "pif-delete",
                value={"action": "deleteProfile", "profileId": profile_id},
            ),
        )["value"]
        self.assertEqual({"action": "deleteProfile", "profileId": profile_id}, projected)

        hostile_payloads = (
            {**payload, "action": "delete"},
            {**payload, "profileId": "../private"},
            {**payload, "confirmationText": "DELETE"},
            {**payload, "path": "/data/adb/private"},
        )
        for hostile in hostile_payloads:
            with self.subTest(payload=hostile):
                with self.assertRaises(BridgeProtocolError):
                    BridgeRequest(2, "bad-pif-delete", "tools.pif", hostile, 7).validate()

        with self.assertRaises(PublicProjectionError):
            project_operation_result(
                "tools.pif",
                OperationResult.success(
                    "bad-pif-delete",
                    value={"action": "deleteProfile", "profileId": "../private"},
                ),
            )

    def test_import_contract_requires_opaque_grant_and_projects_only_hash_metadata(self):
        profile_id = "pif.custom_json"
        digest = "a" * 64
        payload = {
            "serial": "SERIAL",
            "action": "importProfile",
            "profileId": profile_id,
            "confirmationText": f"IMPORT PIF {profile_id} SERIAL",
            "grant": "G" * 32,
        }
        request = BridgeRequest(2, "pif-import", "tools.pif", payload, 7)
        self.assertIs(request, request.validate())
        projected = project_operation_result(
            "tools.pif",
            OperationResult.success(
                "pif-import",
                value={"action": "importProfile", "profileId": profile_id, "sha256": digest, "size": 19},
            ),
        )["value"]
        self.assertEqual(
            {"action": "importProfile", "profileId": profile_id, "sha256": digest, "size": 19},
            projected,
        )
        with self.assertRaises(BridgeProtocolError):
            BridgeRequest(2, "bad-import", "tools.pif", {**payload, "grant": ""}, 7).validate()
        with self.assertRaises(PublicProjectionError):
            project_operation_result(
                "tools.pif",
                OperationResult.success(
                    "bad-import",
                    value={"action": "importProfile", "profileId": profile_id, "sha256": "bad", "size": 19},
                ),
            )

    def test_target_contract_is_package_scoped_confirmed_and_route_free(self):
        package = "com.example.app"
        for action, verb in (("addTarget", "ADD"), ("deleteTarget", "DELETE")):
            with self.subTest(action=action):
                payload = {
                    "serial": "SERIAL",
                    "action": action,
                    "targetPackage": package,
                    "confirmationText": f"{verb} TARGET {package} SERIAL",
                }
                request = BridgeRequest(2, f"target-{action}", "tools.pif", payload, 7)
                self.assertIs(request, request.validate())
                projected = project_operation_result(
                    "tools.pif",
                    OperationResult.success(
                        f"target-{action}",
                        value={"action": action, "targetPackage": package},
                    ),
                )["value"]
                self.assertEqual({"action": action, "targetPackage": package}, projected)

        hostile_payloads = (
            {"serial": "SERIAL", "action": "addTarget", "targetPackage": "../private", "confirmationText": "x"},
            {
                "serial": "SERIAL",
                "action": "addTarget",
                "targetPackage": package,
                "profileId": "targeted.targets",
                "confirmationText": f"ADD TARGET {package} SERIAL",
            },
            {
                "serial": "SERIAL",
                "action": "deleteTarget",
                "targetPackage": package,
                "grant": "opaque",
                "confirmationText": f"DELETE TARGET {package} SERIAL",
            },
        )
        for payload in hostile_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(BridgeProtocolError):
                    BridgeRequest(2, "bad-target", "tools.pif", payload, 7).validate()


if __name__ == "__main__":
    unittest.main()
