import ast
import json
import unittest
from pathlib import Path

from ui.command_registry import ALLOWED_COMMANDS, REGISTERED_COMMANDS

INVENTORY_PATH = Path("docs/modern-ui-parity.json")
GOLDEN_PATH = Path("tests/golden/modern_action_contracts.json")

CAPABILITY_FIELDS = {
    "area",
    "blockReason",
    "capability",
    "currentEvidence",
    "dependsOn",
    "exitCriteria",
    "gap",
    "id",
    "legacyEvidence",
    "modernActionIds",
    "modernCommandIds",
    "modernStatus",
    "owner",
    "platforms",
    "releaseGate",
    "risk",
    "tests",
}
ARRAY_FIELDS = {
    "currentEvidence",
    "dependsOn",
    "exitCriteria",
    "legacyEvidence",
    "modernActionIds",
    "modernCommandIds",
    "platforms",
    "tests",
}
IMPLEMENTED_STATUSES = {
    "native",
    "read_only",
    "delegated",
    "partial",
    "blocked",
    "policy_absent",
}
PARITY_GAP_STATUSES = {"read_only", "delegated", "partial", "blocked", "missing"}

USER_INPUT_EVENTS = {
    "wx.EVT_BUTTON",
    "wx.EVT_CHECKBOX",
    "wx.EVT_CHOICE",
    "wx.EVT_COMBOBOX",
    "wx.EVT_DIRPICKER_CHANGED",
    "wx.EVT_FILEPICKER_CHANGED",
    "wx.EVT_LEFT_DCLICK",
    "wx.EVT_LEFT_DOWN",
    "wx.EVT_LIST_COL_CLICK",
    "wx.EVT_RADIOBUTTON",
}


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _main_primary_control_handlers():
    tree = ast.parse(Path("Main.py").read_text(encoding="utf-8"))
    init_ui = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_init_ui"
    )
    handlers = set()
    for node in ast.walk(init_ui):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "Bind":
            continue
        if len(node.args) < 2 or ast.unparse(node.args[0]) not in USER_INPUT_EVENTS:
            continue
        handler = node.args[1]
        if isinstance(handler, ast.Attribute):
            handlers.add(handler.attr)
        elif isinstance(handler, ast.Name):
            handlers.add(handler.id)
    return handlers


def _menu_handlers(path):
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    handlers = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "Bind":
            continue
        if len(node.args) < 2 or "EVT_MENU" not in ast.unparse(node.args[0]):
            continue

        handler = node.args[1]
        if isinstance(handler, ast.Attribute):
            handlers.add(handler.attr)
        elif isinstance(handler, ast.Name):
            handlers.add(handler.id)
        elif isinstance(handler, ast.Lambda):
            for child in ast.walk(handler.body):
                if not isinstance(child, ast.Call):
                    continue
                if isinstance(child.func, ast.Attribute):
                    handlers.add(child.func.attr)
                elif isinstance(child.func, ast.Name):
                    handlers.add(child.func.id)
    return handlers


class ModernParityInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory = _load(INVENTORY_PATH)
        cls.capabilities = cls.inventory["capabilities"]

    def test_inventory_schema_references_and_enums_are_valid(self):
        self.assertEqual(
            {
                "baseline",
                "capabilities",
                "legacyBindings",
                "ownerDefinitions",
                "platformDefinitions",
                "primaryControlBindings",
                "riskDefinitions",
                "schemaVersion",
                "statusDefinitions",
            },
            set(self.inventory),
        )
        self.assertEqual(2, self.inventory["schemaVersion"])
        capability_ids = [row["id"] for row in self.capabilities]
        self.assertEqual(len(capability_ids), len(set(capability_ids)))

        valid_statuses = set(self.inventory["statusDefinitions"])
        valid_risks = set(self.inventory["riskDefinitions"])
        valid_owners = set(self.inventory["ownerDefinitions"])
        valid_platforms = set(self.inventory["platformDefinitions"])
        self.assertEqual(
            {
                "native",
                "read_only",
                "delegated",
                "partial",
                "blocked",
                "missing",
                "policy_absent",
            },
            valid_statuses,
        )
        self.assertEqual({"windows", "macos", "linux"}, valid_platforms)
        for definitions in (
            self.inventory["statusDefinitions"],
            self.inventory["riskDefinitions"],
            self.inventory["ownerDefinitions"],
            self.inventory["platformDefinitions"],
        ):
            self.assertTrue(
                all(
                    isinstance(description, str) and description.strip()
                    for description in definitions.values()
                )
            )

        for row in self.capabilities:
            with self.subTest(capability=row["id"]):
                self.assertEqual(CAPABILITY_FIELDS, set(row))
                self.assertIn(row["modernStatus"], valid_statuses)
                self.assertIn(row["risk"], valid_risks)
                self.assertIn(row["owner"], valid_owners)
                self.assertTrue(row["legacyEvidence"])
                self.assertIs(type(row["releaseGate"]), bool)
                self.assertIsInstance(row["gap"], str)
                self.assertTrue(row["exitCriteria"])
                self.assertTrue(row["platforms"])
                self.assertLessEqual(set(row["platforms"]), valid_platforms)
                self.assertTrue(
                    row["blockReason"] is None
                    or isinstance(row["blockReason"], str)
                    and row["blockReason"].strip()
                )

                for field in ARRAY_FIELDS:
                    values = row[field]
                    self.assertIsInstance(values, list, field)
                    self.assertEqual(len(values), len(set(values)), field)
                    self.assertTrue(
                        all(isinstance(value, str) and value.strip() for value in values),
                        field,
                    )

                for reference in row["currentEvidence"] + row["tests"]:
                    source = Path(reference.split(":", 1)[0])
                    self.assertTrue(source.is_file(), f"missing evidence source: {source}")

                if row["modernStatus"] in IMPLEMENTED_STATUSES:
                    self.assertTrue(row["currentEvidence"])
                    self.assertTrue(row["tests"])
                if row["modernStatus"] in PARITY_GAP_STATUSES:
                    self.assertTrue(row["gap"].strip())
                    self.assertTrue(row["releaseGate"])
                else:
                    self.assertFalse(row["gap"].strip())
                if row["modernStatus"] == "native":
                    self.assertIsNone(row["blockReason"])
                if row["modernStatus"] == "blocked":
                    self.assertTrue(row["blockReason"])
                if row["modernStatus"] == "policy_absent":
                    self.assertTrue(row["blockReason"])
                    self.assertFalse(row["releaseGate"])
                else:
                    self.assertTrue(row["releaseGate"])

        known = set(capability_ids)
        graph = {row["id"]: row["dependsOn"] for row in self.capabilities}
        for capability_id, dependencies in graph.items():
            with self.subTest(capability=capability_id, field="dependsOn"):
                self.assertNotIn(capability_id, dependencies)
                self.assertLessEqual(set(dependencies), known)

        visited = set()
        active = set()

        def visit(capability_id):
            self.assertNotIn(capability_id, active, f"dependency cycle at {capability_id}")
            if capability_id in visited:
                return
            active.add(capability_id)
            for dependency in graph[capability_id]:
                visit(dependency)
            active.remove(capability_id)
            visited.add(capability_id)

        for capability_id in graph:
            visit(capability_id)

        for binding in (
            self.inventory["legacyBindings"]
            + self.inventory["primaryControlBindings"]
        ):
            with self.subTest(handler=binding["handler"]):
                self.assertIn(binding["capabilityId"], known)

    def test_downloads_has_one_firmware_owner(self):
        rows = {row["id"]: row for row in self.capabilities}

        self.assertNotIn("navigation.downloads", rows)
        downloads = rows["firmware.downloads"]
        self.assertEqual("firmware", downloads["owner"])
        self.assertEqual(
            {"open_downloads", "firmware_downloads"},
            set(downloads["modernActionIds"]),
        )
        self.assertEqual("partial", downloads["modernStatus"])
        self.assertEqual(
            {"firmware.catalog.refresh", "firmware.download"},
            set(downloads["modernCommandIds"]),
        )
        self.assertIn("Production Ed25519 catalog manifests", downloads["gap"])

    def test_flash_navigation_does_not_claim_execution_parity(self):
        rows = {row["id"]: row for row in self.capabilities}
        navigation = rows["navigation.flash"]
        execution = rows["flash.execute"]

        self.assertEqual("Flash workspace navigation shell", navigation["capability"])
        self.assertEqual("navigation", navigation["owner"])
        self.assertEqual("native", navigation["modernStatus"])
        self.assertEqual([], navigation["modernCommandIds"])
        self.assertEqual("flash", execution["owner"])
        self.assertEqual("partial", execution["modernStatus"])
        self.assertEqual(
            {"flash.plan.preview", "flash.execute"},
            set(execution["modernCommandIds"]),
        )

    def test_standalone_wipe_is_policy_absent(self):
        rows = {row["id"]: row for row in self.capabilities}
        wipe = rows["flash.wipe_shortcut"]

        self.assertEqual("policy_absent", wipe["modernStatus"])
        self.assertEqual("destructive", wipe["risk"])
        self.assertEqual([], wipe["modernCommandIds"])
        self.assertEqual(["disabled_wipe"], wipe["modernActionIds"])
        self.assertFalse(wipe["releaseGate"])
        self.assertIn("immutable flash plan", wipe["blockReason"])

    def test_device_transition_evidence_matches_the_fail_closed_contract(self):
        rows = {row["id"]: row for row in self.capabilities}
        reboot = rows["device.reboot"]
        push = rows["device.push_files"]

        self.assertEqual("native", reboot["modernStatus"])
        self.assertEqual("", reboot["gap"])
        self.assertIn("policy-absent", reboot["capability"])
        self.assertIn(
            "tests/test_operation_planner.py:test_download_reboot_is_explicitly_unverifiable_and_never_executes",
            reboot["tests"],
        )
        self.assertEqual("native", push["modernStatus"])
        self.assertEqual("", push["gap"])
        self.assertIn(
            "tests/test_operation_runner_v2.py:test_remote_file_hashes_compile_into_observer_spec",
            push["tests"],
        )
        self.assertIn("ui/web/src/test/push-files.test.tsx", push["tests"])
        self.assertTrue(
            any(
                "complete selected batch" in criterion
                for criterion in push["exitCriteria"]
            )
        )

    def test_ota_diagnostics_inventory_tracks_reset_and_fallback_runner_gap(self):
        rows = {row["id"]: row for row in self.capabilities}
        diagnostics = rows["device.ota_diagnostics"]
        logs = rows["device.logs"]

        self.assertEqual("partial", diagnostics["modernStatus"])
        self.assertEqual(
            {
                "device.ota.status",
                "device.ota.certificates",
                "device.ota.logs",
                "device.ota.reset",
            },
            set(diagnostics["modernCommandIds"]),
        )
        self.assertIn("Root-only cancel/reset", diagnostics["gap"])
        self.assertIn("fallback runner", diagnostics["gap"])
        self.assertNotIn("No typed modern flow", diagnostics["gap"])
        self.assertIn(
            "pixelflasher_core/ota_diagnostics.py:OtaDiagnosticsService",
            diagnostics["currentEvidence"],
        )
        self.assertIn(
            "ui/web/src/test/ota-diagnostics.test.tsx",
            diagnostics["tests"],
        )
        self.assertEqual(
            {"tools.logcat", "tools.logcat.clear"},
            set(logs["modernCommandIds"]),
        )
        self.assertEqual("native", logs["modernStatus"])
        self.assertEqual("", logs["gap"])
        self.assertEqual("destructive", logs["risk"])
        self.assertIn(
            "pixelflasher_core/operation_runner.py:OperationRunner._verify_logcat_buffers_cleared",
            logs["currentEvidence"],
        )
        self.assertIn(
            "ui/web/src/test/logcat.test.tsx",
            logs["tests"],
        )

    def test_device_inspection_inventory_closes_the_per_slot_gate(self):
        rows = {row["id"]: row for row in self.capabilities}
        inspection = rows["device.inspect"]

        self.assertEqual("native", inspection["modernStatus"])
        self.assertEqual("", inspection["gap"])
        self.assertIn(
            "pixelflasher_core/bootloader_inspection.py",
            inspection["currentEvidence"],
        )
        self.assertIn(
            "tests/test_bootloader_slot_service.py",
            inspection["tests"],
        )
        self.assertIn(
            "ui/web/src/test/device-inspection.test.tsx",
            inspection["tests"],
        )

    def test_every_registered_bridge_command_has_one_parity_owner(self):
        inventoried = [
            command_id
            for row in self.capabilities
            for command_id in row.get("modernCommandIds", [])
        ]

        self.assertEqual(len(inventoried), len(set(inventoried)))
        self.assertEqual(set(REGISTERED_COMMANDS), set(inventoried))
        self.assertLessEqual(set(ALLOWED_COMMANDS), set(inventoried))

    def test_legacy_preview_actions_remain_a_versioned_migration_baseline(self):
        golden = _load(GOLDEN_PATH)
        actions = golden["actions"]
        action_ids = [action["id"] for action in actions]
        inventoried = [
            action_id
            for row in self.capabilities
            for action_id in row["modernActionIds"]
        ]

        self.assertEqual(1, golden["schemaVersion"])
        self.assertEqual(32, len(actions))
        self.assertEqual(len(action_ids), len(set(action_ids)))
        self.assertEqual(set(action_ids), set(inventoried))

    def test_primary_wx_control_handlers_are_characterized(self):
        actual = _main_primary_control_handlers()
        inventoried = {
            binding["handler"] for binding in self.inventory["primaryControlBindings"]
        }

        self.assertEqual(actual, inventoried)

    def test_inventory_covers_every_referenced_legacy_handler_definition(self):
        definitions_by_source = {}
        for source in sorted({row["source"] for row in self.inventory["legacyBindings"]}):
            tree = ast.parse(Path(source).read_text(encoding="utf-8"))
            definitions_by_source[source] = {
                node.name
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            }

        externally_imported = {("Main.py", "run_tool")}
        for binding in self.inventory["legacyBindings"]:
            key = (binding["source"], binding["handler"])
            if key in externally_imported:
                continue
            with self.subTest(source=key[0], handler=key[1]):
                self.assertIn(binding["handler"], definitions_by_source[key[0]])

    def test_every_current_legacy_menu_handler_is_in_the_inventory(self):
        sources = sorted({row["source"] for row in self.inventory["legacyBindings"]})
        for source in sources:
            actual = _menu_handlers(source)
            inventoried = {
                row["handler"]
                for row in self.inventory["legacyBindings"]
                if row["source"] == source
            }
            with self.subTest(source=source):
                self.assertEqual(actual, inventoried)

    def test_legacy_action_golden_preserves_safety_metadata(self):
        for action in _load(GOLDEN_PATH)["actions"]:
            with self.subTest(action=action["id"]):
                if action["dangerous"]:
                    self.assertTrue(action["requiresConfirmation"])
                    self.assertTrue(action["enabled"])
                    self.assertTrue(action["delegate"])
                if not action["enabled"]:
                    self.assertFalse(action["delegate"])


if __name__ == "__main__":
    unittest.main()
