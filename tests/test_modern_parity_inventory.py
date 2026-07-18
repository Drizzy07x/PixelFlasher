import ast
import json
import unittest
from pathlib import Path

from ui.bridge_contract import ALLOWED_COMMANDS


INVENTORY_PATH = Path("docs/modern-ui-parity.json")
GOLDEN_PATH = Path("tests/golden/modern_action_contracts.json")

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
        self.assertEqual(1, self.inventory["schemaVersion"])
        capability_ids = [row["id"] for row in self.capabilities]
        self.assertEqual(len(capability_ids), len(set(capability_ids)))

        valid_statuses = set(self.inventory["statusDefinitions"])
        valid_risks = set(self.inventory["riskDefinitions"])
        for row in self.capabilities:
            with self.subTest(capability=row["id"]):
                self.assertIn(row["modernStatus"], valid_statuses)
                self.assertIn(row["risk"], valid_risks)
                self.assertTrue(row["legacyEvidence"])
                self.assertTrue(row["exitContract"])

        known = set(capability_ids)
        for binding in (
            self.inventory["legacyBindings"]
            + self.inventory["primaryControlBindings"]
        ):
            with self.subTest(handler=binding["handler"]):
                self.assertIn(binding["capabilityId"], known)

    def test_every_live_bridge_command_has_one_parity_owner(self):
        inventoried = [
            command_id
            for row in self.capabilities
            for command_id in row.get("modernCommandIds", [])
        ]

        self.assertEqual(len(inventoried), len(set(inventoried)))
        self.assertEqual(set(ALLOWED_COMMANDS), set(inventoried))

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
