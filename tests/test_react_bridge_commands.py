import tempfile
import unittest
from pathlib import Path

from scripts.verify_react_bridge_commands import (
    load_react_commands,
    raw_command_emissions,
    verify_react_commands,
)
from ui.command_registry import ALLOWED_COMMANDS


class ReactBridgeCommandTests(unittest.TestCase):
    def test_every_runtime_react_command_comes_from_allow_listed_constants(self):
        commands = verify_react_commands()
        self.assertGreater(len(commands), 10)
        self.assertTrue(set(commands).issubset(ALLOWED_COMMANDS))
        self.assertEqual((), raw_command_emissions())

    def test_parser_rejects_unknown_duplicate_and_bypassing_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands_path = root / "commands.ts"
            commands_path.write_text(
                "export const commands = { good: 'device.scan' } as const;\n",
                encoding="utf-8",
            )
            (root / "App.tsx").write_text(
                "bridge.command('legacy_scan');\n",
                encoding="utf-8",
            )
            self.assertEqual({"good": "device.scan"}, load_react_commands(commands_path))
            with self.assertRaisesRegex(ValueError, "commands.ts"):
                verify_react_commands(commands_path, root, {"device.scan"})

            (root / "App.tsx").write_text(
                "bridge.command(commands.good);\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "absent"):
                verify_react_commands(commands_path, root, {"snapshot.get"})


if __name__ == "__main__":
    unittest.main()
