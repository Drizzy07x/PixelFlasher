import json
import tempfile
import unittest
from pathlib import Path

from scripts.generate_bridge_contracts import (
    DEFAULT_OUTPUT,
    render_typescript,
    write_or_check,
)
from scripts.verify_react_bridge_commands import load_react_commands
from ui.bridge_contract import BRIDGE_VERSION, BridgeProtocolError, BridgeRequest
from ui.command_registry import (
    ALLOWED_COMMANDS,
    COMMAND_REGISTRY,
    FUTURE_COMMANDS,
    PAYLOAD_FIELDS,
    REGISTERED_COMMANDS,
    REGISTERED_PAYLOAD_FIELDS,
    CommandMutability,
    CommandOwner,
    CommandRisk,
    ConfirmationPolicy,
    ExpectedRevision,
    PayloadKind,
    TargetScope,
)


def _request(command, payload=None, revision=1):
    return json.dumps(
        {
            "version": BRIDGE_VERSION,
            "requestId": "registry-test",
            "command": command,
            "payload": payload or {},
            "expectedRevision": revision,
        }
    )


class CommandRegistryTests(unittest.TestCase):
    def test_production_allow_list_contains_only_owned_implemented_commands(self):
        self.assertEqual(set(COMMAND_REGISTRY), set(REGISTERED_COMMANDS))
        self.assertEqual(set(REGISTERED_PAYLOAD_FIELDS), set(REGISTERED_COMMANDS))
        self.assertEqual(set(PAYLOAD_FIELDS), set(ALLOWED_COMMANDS))
        self.assertTrue(FUTURE_COMMANDS)
        self.assertEqual(set(REGISTERED_COMMANDS) - set(FUTURE_COMMANDS), set(ALLOWED_COMMANDS))

        for command in ALLOWED_COMMANDS:
            with self.subTest(command=command):
                spec = COMMAND_REGISTRY[command]
                self.assertTrue(spec.implemented)
                self.assertTrue(spec.exposed)
                self.assertTrue(spec.owner.value)
                self.assertTrue(spec.planner)
                self.assertGreater(spec.timeout_ms, 0)
                self.assertTrue(spec.valid_device_states)

        for command in FUTURE_COMMANDS:
            with self.subTest(command=command):
                spec = COMMAND_REGISTRY[command]
                self.assertFalse(spec.implemented)
                self.assertFalse(spec.exposed)
                self.assertIsNone(spec.planner)

    def test_long_running_command_deadlines_cover_their_bounded_workflows(self):
        minimum_timeout_ms = {
            "apps.action": 15 * 60_000,
            "backups.create": 20 * 60_000,
            "backups.restore": 20 * 60_000,
            "boot.flash": 10 * 60_000,
            "boot.inventory": 60 * 60_000,
            "boot.live": 5 * 60_000,
            "boot.patch": 2 * 60 * 60_000,
            "boot.select": 60 * 60_000,
            "device.bootloader.lock": 5 * 60_000,
            "device.bootloader.unlock": 5 * 60_000,
            "device.reboot": 5 * 60_000,
            "device.scan": 5 * 60_000,
            "device.switchSlot": 5 * 60_000,
            "firmware.process": 60 * 60_000,
            "firmware.select": 30 * 60_000,
            "flash.execute": 2 * 60 * 60_000,
            "platformTools.setup": 20 * 60_000,
            "root.apps.install": 15 * 60_000,
            "root.apps.list": 30 * 60_000,
            "root.modules.action": 25 * 60_000,
            "support.create": 20 * 60_000,
            # A single request may contain 32 sequential pushes, each with a
            # ten-minute process boundary, followed by postcondition checks.
            "tools.pushFiles": 330 * 60_000,
        }

        for command, minimum in minimum_timeout_ms.items():
            with self.subTest(command=command):
                self.assertGreaterEqual(COMMAND_REGISTRY[command].timeout_ms, minimum)

    def test_future_commands_are_documented_but_rejected_by_production_bridge(self):
        for command in FUTURE_COMMANDS:
            with self.subTest(command=command), self.assertRaises(BridgeProtocolError) as rejected:
                BridgeRequest.from_json(_request(command))
            self.assertEqual("command_not_allowed", rejected.exception.code)

    def test_registry_payload_schema_rejects_missing_wrong_and_unknown_fields(self):
        cases = (
            ("device.select", {}, "required"),
            ("device.select", {"serials": "SERIAL"}, "string_array"),
            ("platformTools.setup", {}, "source"),
            ("platformTools.setup", {"source": 1}, "string"),
            (
                "platformTools.setup",
                {"source": "directory", "path": "C:/browser/platform-tools"},
                "unsupported",
            ),
            ("settings.update", {"zoom": True}, "integer"),
            (
                "tools.wifi",
                {"action": "connect", "host": "192.0.2.20", "port": "37123"},
                "integer",
            ),
            ("device.ota.certificates", {"path": "/system/etc/security"}, "unsupported"),
            ("device.ota.logs", {"maxLines": True}, "integer"),
            ("device.ota.logs", {"timeoutSeconds": "30"}, "integer"),
            ("snapshot.get", {"alias": True}, "unsupported"),
        )
        for command, payload, detail in cases:
            revision = None if command == "snapshot.get" else 1
            with self.subTest(command=command), self.assertRaises(BridgeProtocolError) as rejected:
                BridgeRequest.from_json(_request(command, payload, revision))
            self.assertEqual("invalid_payload", rejected.exception.code)
            self.assertIn(detail, str(rejected.exception))

    def test_platform_tools_payload_shape_is_closed_and_source_driven(self):
        fields = COMMAND_REGISTRY["platformTools.setup"].payload.fields
        self.assertEqual({"grant", "source"}, set(fields))
        self.assertFalse(fields["grant"].required)
        self.assertTrue(fields["source"].required)

    def test_device_tools_accept_only_the_adb_state_supported_by_the_service(self):
        for command in (
            "tools.scrcpy",
            "tools.wifi.status",
            "tools.logcat",
            "tools.logcat.clear",
            "device.ota.certificates",
            "device.ota.logs",
            "tools.pushFiles",
        ):
            with self.subTest(command=command):
                self.assertEqual(
                    frozenset({"adb"}),
                    COMMAND_REGISTRY[command].valid_device_states,
                )

        grants = COMMAND_REGISTRY["tools.pushFiles"].payload.fields["grants"]
        self.assertEqual(1, grants.min_items)
        self.assertEqual(32, grants.max_items)
        self.assertEqual(
            ("remote_files_written",),
            COMMAND_REGISTRY["tools.pushFiles"].postconditions,
        )
        logcat = COMMAND_REGISTRY["tools.logcat"]
        self.assertEqual(CommandMutability.MUTATING, logcat.mutability)
        self.assertEqual(CommandRisk.HOST_WRITE, logcat.risk)
        self.assertEqual(
            {
                "serial",
                "mode",
                "buffers",
                "formatEnabled",
                "formatVerb",
                "formatModifiers",
                "filters",
                "regex",
                "uids",
                "maxLines",
                "timeoutSeconds",
                "redaction",
                "grant",
            },
            set(logcat.payload.fields),
        )
        self.assertIs(PayloadKind.LOGCAT_FILTER_ARRAY, logcat.payload.fields["filters"].kind)
        self.assertIs(PayloadKind.INTEGER_ARRAY, logcat.payload.fields["uids"].kind)
        clear = COMMAND_REGISTRY["tools.logcat.clear"]
        self.assertIs(CommandMutability.DESTRUCTIVE, clear.mutability)
        self.assertIs(CommandRisk.DESTRUCTIVE, clear.risk)
        self.assertEqual(ConfirmationPolicy.STANDARD, clear.confirmation)
        self.assertEqual(("logcat_buffers_cleared",), clear.postconditions)
        self.assertEqual((1, 6), (
            logcat.payload.fields["buffers"].min_items,
            logcat.payload.fields["buffers"].max_items,
        ))
        self.assertEqual((0, 32), (
            logcat.payload.fields["filters"].min_items,
            logcat.payload.fields["filters"].max_items,
        ))

    def test_ota_diagnostic_contracts_are_closed_read_only_device_reads(self):
        expected_payloads = {
            "device.ota.certificates": {"serial": PayloadKind.STRING},
            "device.ota.logs": {
                "serial": PayloadKind.STRING,
                "maxLines": PayloadKind.INTEGER,
                "timeoutSeconds": PayloadKind.INTEGER,
            },
        }
        for command, expected_payload in expected_payloads.items():
            with self.subTest(command=command):
                spec = COMMAND_REGISTRY[command]
                self.assertEqual(CommandOwner.DEVICE_TOOLS, spec.owner)
                self.assertEqual(CommandMutability.READ_ONLY, spec.mutability)
                self.assertEqual(CommandRisk.DEVICE_READ, spec.risk)
                self.assertEqual(ExpectedRevision.REQUIRED, spec.expected_revision)
                self.assertEqual(TargetScope.SELECTED_DEVICE, spec.target_scope)
                self.assertEqual(frozenset({"adb"}), spec.valid_device_states)
                self.assertEqual(command, spec.planner)
                self.assertEqual(
                    expected_payload,
                    {name: field.kind for name, field in spec.payload.fields.items()},
                )
                self.assertFalse(
                    any(field.required for field in spec.payload.fields.values())
                )

    def test_expected_revision_policy_is_registry_owned(self):
        optional = {
            command
            for command in ALLOWED_COMMANDS
            if COMMAND_REGISTRY[command].expected_revision is ExpectedRevision.OPTIONAL
        }
        self.assertEqual({"app.ready", "settings.get", "snapshot.get"}, optional)

        for command in ALLOWED_COMMANDS - optional:
            spec = COMMAND_REGISTRY[command]
            payload = {
                name: _valid_value(field.kind.value)
                for name, field in spec.payload.fields.items()
                if field.required
            }
            # Conditional semantic rules are irrelevant here; revision is
            # checked after shape validation, so use a direct request object.
            request = BridgeRequest(
                version=BRIDGE_VERSION,
                request_id="revision-test",
                command=command,
                payload=payload,
                expected_revision=None,
            )
            with self.subTest(command=command), self.assertRaises(BridgeProtocolError) as rejected:
                request.validate()
            self.assertIn(
                rejected.exception.code,
                {"invalid_payload", "revision_required"},
            )

    def test_generated_typescript_is_current_and_exactly_matches_allow_list(self):
        self.assertEqual(render_typescript(), DEFAULT_OUTPUT.read_text(encoding="utf-8"))
        self.assertTrue(write_or_check(DEFAULT_OUTPUT, check=True))
        self.assertEqual(
            set(ALLOWED_COMMANDS),
            set(load_react_commands(DEFAULT_OUTPUT).values()),
        )

    def test_generator_check_detects_a_stale_artifact_without_overwriting_it(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "commands.ts"
            target.write_text("stale\n", encoding="utf-8")
            self.assertFalse(write_or_check(target, check=True))
            self.assertEqual("stale\n", target.read_text(encoding="utf-8"))


def _valid_value(kind):
    return {
        "string": "value",
        "boolean": False,
        "integer": 1,
        "number": 1,
        "object": {},
        "array": [],
        "string_array": [],
        "filter_array": [],
    }[kind]


if __name__ == "__main__":
    unittest.main()
