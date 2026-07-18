import json
import unittest

from pixelflasher_core import AppSnapshot
from ui.bridge_contract import BridgeRequest
from ui.core_command_factory import create_command_factory


def request(command, *, payload=None, revision=4):
    return BridgeRequest.from_json(
        json.dumps(
            {
                "version": 1,
                "requestId": "factory-test",
                "command": command,
                "payload": payload or {},
                "expectedRevision": revision,
            }
        )
    )


class CoreCommandFactoryTests(unittest.TestCase):
    def test_risk_metadata_cannot_be_lowered_by_the_browser(self):
        factory = create_command_factory(lambda: AppSnapshot(selected_serial="SERIAL-1"))

        command = factory(
            request(
                "flash.execute",
                payload={"serial": "SERIAL-1", "destructive": False, "requiresConfirmation": False},
            )
        )

        self.assertTrue(command.destructive)
        self.assertTrue(command.requires_confirmation)
        self.assertEqual("SERIAL-1", command.target_serial)
        self.assertEqual(4, command.expected_revision)

    def test_device_commands_bind_the_selected_serial(self):
        factory = create_command_factory(lambda: AppSnapshot(selected_serial="SERIAL-2"))

        command = factory(request("device.reboot", payload={"mode": "system"}))

        self.assertEqual("SERIAL-2", command.target_serial)

    def test_device_commands_reject_an_ambiguous_target(self):
        factory = create_command_factory(AppSnapshot)

        with self.assertRaisesRegex(ValueError, "target serial"):
            factory(request("partitions.erase", payload={"partition": "userdata"}))

    def test_settings_commands_are_explicitly_not_device_scoped(self):
        factory = create_command_factory(lambda: AppSnapshot(selected_serial="SERIAL-3"))

        loaded = factory(request("settings.get", revision=4))
        updated = factory(
            request("settings.update", payload={"theme": "light"}, revision=4)
        )

        self.assertIsNone(loaded.target_serial)
        self.assertIsNone(updated.target_serial)
        self.assertEqual({"theme": "light"}, updated.payload)

    def test_root_app_inventory_is_local_but_root_actions_are_guarded(self):
        factory = create_command_factory(AppSnapshot)

        inventory = factory(request("root.apps.list"))
        module_action = factory(
            request(
                "root.modules.action",
                payload={"serial": "SERIAL-ROOT", "action": "enable", "moduleId": "safe"},
            )
        )

        self.assertIsNone(inventory.target_serial)
        # The bridge boundary is intentionally conservative. The engine later
        # replaces these flags with action-specific RootingCompilation metadata.
        self.assertTrue(module_action.destructive)
        self.assertTrue(module_action.requires_confirmation)
        self.assertEqual("SERIAL-ROOT", module_action.target_serial)

    def test_firmware_processing_is_local_even_with_a_selected_device(self):
        factory = create_command_factory(
            lambda: AppSnapshot(selected_serial="SERIAL-SELECTED")
        )

        selected = factory(
            request("firmware.select", payload={"path": "C:/firmware.zip"})
        )
        processed = factory(request("firmware.process", payload={}))

        self.assertIsNone(selected.target_serial)
        self.assertIsNone(processed.target_serial)
        self.assertEqual({"path": "C:/firmware.zip"}, selected.payload)
        self.assertEqual({}, processed.payload)

    def test_factory_rejects_untrusted_firmware_fields_defence_in_depth(self):
        factory = create_command_factory(AppSnapshot)
        unsafe = BridgeRequest(
            version=1,
            request_id="factory-bypass",
            command="firmware.process",
            payload={"outputRoot": "C:/browser-cache"},
            expected_revision=0,
        )

        with self.assertRaisesRegex(ValueError, "unsupported field"):
            factory(unsafe)

    def test_device_connectivity_is_serial_bound_and_pairing_secret_is_redacted(self):
        factory = create_command_factory(
            lambda: AppSnapshot(selected_serial="SERIAL-WIFI")
        )

        scrcpy = factory(request("tools.scrcpy"))
        wifi = factory(
            request(
                "tools.wifi",
                payload={
                    "action": "pair",
                    "host": "192.0.2.20",
                    "port": 37123,
                    "pairingCode": "123456",
                },
            )
        )

        self.assertEqual("SERIAL-WIFI", scrcpy.target_serial)
        self.assertEqual("SERIAL-WIFI", wifi.target_serial)
        self.assertNotIn("123456", repr(wifi))
        self.assertNotIn("123456", str(wifi.to_dict()))
        self.assertEqual("[REDACTED]", wifi.to_dict()["payload"]["pairingCode"])

    def test_factory_rejects_device_tool_process_fields_defence_in_depth(self):
        factory = create_command_factory(
            lambda: AppSnapshot(selected_serial="SERIAL")
        )
        unsafe = BridgeRequest(
            version=1,
            request_id="factory-device-tool-bypass",
            command="tools.scrcpy",
            payload={"path": "C:/browser/scrcpy.exe"},
            expected_revision=0,
        )

        with self.assertRaisesRegex(ValueError, "unsupported field"):
            factory(unsafe)


if __name__ == "__main__":
    unittest.main()
