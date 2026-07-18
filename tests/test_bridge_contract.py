import json
import unittest

from ui.bridge_contract import (
    ALLOWED_COMMANDS,
    BRIDGE_CHANNEL,
    BRIDGE_VERSION,
    BridgeProtocolError,
    BridgeRequest,
    event_envelope,
    protocol_error_envelope,
)


def message(**overrides):
    value = {
        "version": BRIDGE_VERSION,
        "requestId": "request-1",
        "command": "snapshot.get",
        "payload": {},
        "expectedRevision": 0,
    }
    value.update(overrides)
    return json.dumps(value)


class BridgeContractTests(unittest.TestCase):
    def test_uses_the_single_edge_compatible_channel(self):
        self.assertEqual("pixelflasher", BRIDGE_CHANNEL)

    def test_parses_a_versioned_allow_listed_request(self):
        request = BridgeRequest.from_json(message(payload={"include": ["devices"]}))

        self.assertEqual("request-1", request.request_id)
        self.assertEqual("snapshot.get", request.command)
        self.assertEqual({"include": ["devices"]}, request.payload)
        self.assertEqual(0, request.expected_revision)

    def test_rejects_unknown_commands_and_extra_fields(self):
        with self.assertRaisesRegex(BridgeProtocolError, "not allow-listed") as unknown:
            BridgeRequest.from_json(message(command="python.eval"))
        self.assertEqual("command_not_allowed", unknown.exception.code)

        value = json.loads(message())
        value["delegate"] = "_on_flash"
        with self.assertRaisesRegex(BridgeProtocolError, "unexpected: delegate") as extra:
            BridgeRequest.from_json(json.dumps(value))
        self.assertEqual("invalid_envelope", extra.exception.code)

    def test_rejects_wrong_versions_and_invalid_revisions(self):
        with self.assertRaises(BridgeProtocolError) as version:
            BridgeRequest.from_json(message(version=BRIDGE_VERSION + 1))
        self.assertEqual("unsupported_version", version.exception.code)

        for revision in (-1, True, "1"):
            with self.subTest(revision=revision):
                with self.assertRaises(BridgeProtocolError) as invalid:
                    BridgeRequest.from_json(message(expectedRevision=revision))
                self.assertEqual("invalid_revision", invalid.exception.code)

    def test_protocol_errors_are_safe_json_responses(self):
        error = BridgeProtocolError("invalid_json", "Malformed request", request_id="safe-id")
        envelope = protocol_error_envelope(error)

        self.assertFalse(envelope["ok"])
        self.assertEqual("safe-id", envelope["requestId"])
        self.assertEqual("invalid_json", envelope["error"]["code"])
        json.dumps(envelope)

    def test_event_types_are_constrained(self):
        self.assertEqual("snapshot", event_envelope("snapshot", {"revision": 1})["type"])
        with self.assertRaises(ValueError):
            event_envelope("javascript", {})

    def test_allow_list_covers_all_primary_product_areas(self):
        prefixes = {
            command.split(".", 1)[0]
            for command in ALLOWED_COMMANDS
        }
        self.assertTrue(
            {"device", "flash", "firmware", "boot", "root", "apps", "backups", "tools", "settings"}
            <= prefixes
        )
        self.assertIn("settings.get", ALLOWED_COMMANDS)
        self.assertIn("settings.update", ALLOWED_COMMANDS)
        self.assertTrue(
            {
                "root.apps.list",
                "root.apps.install",
                "root.modules.list",
                "root.modules.action",
            }
            <= ALLOWED_COMMANDS
        )

    def test_settings_get_is_read_only_and_accepts_a_null_revision(self):
        request = BridgeRequest.from_json(
            message(command="settings.get", expectedRevision=None)
        )

        self.assertEqual("settings.get", request.command)
        self.assertIsNone(request.expected_revision)

    def test_firmware_process_has_an_empty_public_payload(self):
        request = BridgeRequest.from_json(
            message(command="firmware.process", payload={}, expectedRevision=7)
        )

        self.assertEqual({}, request.payload)
        for payload in (
            {"path": "C:/firmware.zip"},
            {"sha256": "0" * 64},
            {"argv": ["fastboot", "flash"]},
            {"outputRoot": "C:/browser-cache"},
            {"stagingPath": "C:/browser-stage"},
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(BridgeProtocolError) as rejected:
                    BridgeRequest.from_json(
                        message(command="firmware.process", payload=payload)
                    )
                self.assertEqual("invalid_payload", rejected.exception.code)

    def test_firmware_select_accepts_only_the_native_picker_path(self):
        selected = BridgeRequest.from_json(
            message(command="firmware.select", payload={"path": "C:/firmware.zip"})
        )
        self.assertEqual({"path": "C:/firmware.zip"}, selected.payload)

        with self.assertRaises(BridgeProtocolError) as rejected:
            BridgeRequest.from_json(
                message(
                    command="firmware.select",
                    payload={"path": "C:/firmware.zip", "hash": "browser"},
                )
            )
        self.assertEqual("invalid_payload", rejected.exception.code)

    def test_device_connectivity_payloads_reject_browser_process_fields(self):
        scrcpy = BridgeRequest.from_json(
            message(command="tools.scrcpy", payload={"serial": "SERIAL"})
        )
        wifi = BridgeRequest.from_json(
            message(
                command="tools.wifi",
                payload={
                    "serial": "SERIAL",
                    "action": "pair",
                    "host": "192.0.2.20",
                    "port": 37123,
                    "pairingCode": "123456",
                },
            )
        )
        self.assertEqual({"serial": "SERIAL"}, scrcpy.payload)
        self.assertEqual("pair", wifi.payload["action"])
        self.assertNotIn("123456", repr(wifi))

        for command, payload in (
            ("tools.scrcpy", {"path": "C:/browser/scrcpy.exe"}),
            ("tools.scrcpy", {"argv": ["scrcpy", "--record", "x"]}),
            ("tools.wifi", {"stdin": "123456"}),
            ("tools.wifi", {"command": "pair 192.0.2.1:1 123456"}),
        ):
            with self.subTest(command=command, payload=payload):
                with self.assertRaises(BridgeProtocolError) as rejected:
                    BridgeRequest.from_json(message(command=command, payload=payload))
                self.assertEqual("invalid_payload", rejected.exception.code)


if __name__ == "__main__":
    unittest.main()
