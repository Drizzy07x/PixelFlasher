import unittest
from typing import Any, cast

from pixelflasher_core import OperationResult
from ui.bridge_contract import BridgeProtocolError, BridgeRequest
from ui.command_registry import COMMAND_REGISTRY
from ui.public_bridge import PublicProjectionError, project_operation_result


def report_value() -> dict[str, Any]:
    kinds = (
        "pif_custom_json",
        "pif_custom_prop",
        "pif_module_json",
        "pif_legacy_json",
        "pif_app_replace",
        "pif_scripts_only",
        "tricky_spoof",
        "tricky_target",
        "tricky_security_patch",
        "tricky_tee",
        "targeted_targets",
        "keybox",
    )
    return {
        "schemaVersion": 1,
        "redacted": True,
        "complete": True,
        "device": {
            "codename": "akita",
            "build": "AP4A.260101.001",
            "rootAccess": "verified",
            "testKeys": False,
            "overlayVisible": False,
        },
        "packages": [
            {"id": "gms", "installed": True, "version": "25.20.33", "versionCode": 252033000},
            {"id": "play_store", "installed": False, "version": "", "versionCode": 0},
        ],
        "modules": [
            {"id": "playintegrityfix", "state": "enabled"},
            {"id": "tricky_store", "state": "disabled"},
        ],
        "configs": [
            {
                "kind": kind,
                "present": kind in {"pif_custom_json", "keybox"},
                "size": 512 if kind == "pif_custom_json" else 2048 if kind == "keybox" else 0,
                "sha256": "a" * 64 if kind == "pif_custom_json" else None,
            }
            for kind in kinds
        ],
        "signals": {
            "targetedFixTargetCount": 2,
            "magiskDenylistCount": 5,
            "droidGuardVmCount": 1,
        },
        "withheld": [
            "android_ids",
            "device_serial",
            "keybox_material",
            "raw_config_contents",
            "raw_logs",
            "target_package_names",
        ],
    }


class PiAnalysisPublicContractTests(unittest.TestCase):
    def project(self, value: object):
        projected = project_operation_result(
            "tools.piAnalysis",
            OperationResult.success("pi-analysis", value=value),
        )["value"]
        return cast(dict[str, Any], projected)

    def test_projection_is_closed_route_free_and_explicitly_redacted(self):
        projected = self.project(report_value())

        self.assertTrue(projected["redacted"])
        self.assertTrue(projected["complete"])
        serialized = repr(projected).casefold()
        self.assertNotIn("serial123", serialized)
        self.assertNotIn("/data/adb", serialized)
        self.assertNotIn("certificate", serialized)
        keybox = next(item for item in projected["configs"] if item["kind"] == "keybox")
        self.assertIsNone(keybox["sha256"])

    def test_registry_and_bridge_allow_only_the_exact_read_only_analysis_action(self):
        spec = COMMAND_REGISTRY["tools.piAnalysis"]
        self.assertTrue(spec.implemented)
        self.assertTrue(spec.exposed)
        self.assertEqual("read_only", spec.mutability.value)
        self.assertEqual("device_read", spec.risk.value)
        self.assertEqual(frozenset({"adb"}), spec.valid_device_states)
        self.assertEqual(("bounded_redacted_analysis_returned",), spec.postconditions)

        valid = BridgeRequest(
            2,
            "pi-analysis",
            "tools.piAnalysis",
            {"serial": "SERIAL", "action": "analyze"},
            7,
        )
        self.assertIs(valid, valid.validate())
        for payload in (
            {"serial": "SERIAL", "action": "report"},
            {"serial": "SERIAL", "action": "analyze", "includeSecrets": True},
            {"serial": "", "action": "analyze"},
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(BridgeProtocolError):
                    BridgeRequest(
                        2,
                        "pi-analysis-invalid",
                        "tools.piAnalysis",
                        payload,
                        7,
                    ).validate()

    def test_projection_rejects_extra_fields_secret_digests_and_incomplete_receipts(self):
        cases: list[dict[str, Any]] = []
        extra = report_value()
        extra["path"] = "C:\\private\\analysis.log"
        cases.append(extra)
        unredacted = report_value()
        unredacted["redacted"] = False
        cases.append(unredacted)
        keybox_digest = report_value()
        keybox_digest["configs"][-1]["sha256"] = "b" * 64
        cases.append(keybox_digest)
        identity = report_value()
        identity["device"]["serial"] = "SERIAL123"
        cases.append(identity)
        unsorted = report_value()
        unsorted["modules"] = list(reversed(unsorted["modules"]))
        cases.append(unsorted)

        for value in cases:
            with self.subTest(keys=tuple(value)):
                with self.assertRaises(PublicProjectionError):
                    self.project(value)


if __name__ == "__main__":
    unittest.main()
