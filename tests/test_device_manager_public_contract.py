from __future__ import annotations

import json
import unittest

from pixelflasher_core import (
    AppSnapshot,
    DeviceManagementState,
    ManagedDeviceInfo,
    OperationResult,
)
from scripts.generate_bridge_contracts import DEFAULT_OUTPUT, render_typescript, write_or_check
from scripts.verify_react_bridge_commands import load_react_commands
from ui.bridge_contract import BRIDGE_VERSION, BridgeProtocolError, BridgeRequest
from ui.command_registry import (
    ALLOWED_COMMANDS,
    COMMAND_REGISTRY,
    CommandMutability,
    CommandOwner,
    CommandRisk,
    ConfirmationPolicy,
    ExpectedRevision,
    PayloadKind,
    TargetScope,
)
from ui.core_command_factory import create_command_factory
from ui.public_bridge import project_operation_result, public_snapshot

MANAGER_COMMANDS = frozenset(
    {
        "device.manager.policy",
        "device.manager.update",
        "device.manager.remove",
    }
)
HOST_ROUTE = r"C:\Users\Alice\private\devices.json"


def request(
    command: str,
    payload: dict[str, object],
    *,
    revision: int | None = 7,
) -> BridgeRequest:
    return BridgeRequest.from_json(
        json.dumps(
            {
                "version": BRIDGE_VERSION,
                "requestId": "device-manager-contract",
                "command": command,
                "payload": payload,
                "expectedRevision": revision,
            }
        )
    )


def managed_device(
    serial: str = "SERIAL-A",
    *,
    label: str = "Daily Pixel",
    enabled: bool = True,
    connected: bool = True,
    first_seen: int = 1_721_234_567,
    last_seen: int = 1_721_345_678,
) -> ManagedDeviceInfo:
    return ManagedDeviceInfo(
        serial=serial,
        label=label,
        enabled=enabled,
        model="Pixel 9",
        codename="tokay",
        connected=connected,
        mode="adb" if connected else "offline",
        first_seen=first_seen,
        last_seen=last_seen,
    )


class DeviceManagerPublicContractTests(unittest.TestCase):
    def test_registry_exposes_only_owned_revision_bound_application_mutations(self) -> None:
        self.assertTrue(MANAGER_COMMANDS <= ALLOWED_COMMANDS)
        expected_payloads = {
            "device.manager.policy": {
                "scanEnabled": (PayloadKind.BOOLEAN, False),
                "scanScope": (PayloadKind.STRING, False),
            },
            "device.manager.update": {
                "serial": (PayloadKind.STRING, True),
                "label": (PayloadKind.STRING, False),
                "enabled": (PayloadKind.BOOLEAN, False),
            },
            "device.manager.remove": {
                "serial": (PayloadKind.STRING, True),
            },
        }
        expected_postconditions = {
            "device.manager.policy": (
                "scan_policy_persisted",
                "monitor_lifecycle_matches",
            ),
            "device.manager.update": ("managed_device_persisted",),
            "device.manager.remove": ("managed_device_removed",),
        }

        for command in sorted(MANAGER_COMMANDS):
            with self.subTest(command=command):
                spec = COMMAND_REGISTRY[command]
                self.assertTrue(spec.implemented)
                self.assertTrue(spec.exposed)
                self.assertEqual(CommandOwner.DEVICE, spec.owner)
                self.assertEqual(CommandMutability.MUTATING, spec.mutability)
                self.assertEqual(CommandRisk.HOST_WRITE, spec.risk)
                self.assertEqual(ExpectedRevision.REQUIRED, spec.expected_revision)
                self.assertEqual(TargetScope.APPLICATION, spec.target_scope)
                self.assertEqual(frozenset({"*"}), spec.valid_device_states)
                self.assertEqual(command, spec.planner)
                self.assertEqual(ConfirmationPolicy.NONE, spec.confirmation)
                self.assertEqual(expected_postconditions[command], spec.postconditions)
                self.assertEqual(
                    expected_payloads[command],
                    {
                        name: (field.kind, field.required)
                        for name, field in spec.payload.fields.items()
                    },
                )

    def test_bridge_accepts_only_closed_semantically_complete_manager_payloads(self) -> None:
        accepted = (
            ("device.manager.policy", {"scanEnabled": False}),
            ("device.manager.policy", {"scanScope": "all"}),
            (
                "device.manager.policy",
                {"scanEnabled": True, "scanScope": "enabled"},
            ),
            ("device.manager.update", {"serial": "SERIAL-A", "label": "Lab"}),
            ("device.manager.update", {"serial": "SERIAL-A", "enabled": False}),
            (
                "device.manager.update",
                {"serial": "SERIAL-A", "label": "", "enabled": True},
            ),
            ("device.manager.remove", {"serial": "SERIAL-A"}),
        )
        for command, payload in accepted:
            with self.subTest(command=command, payload=payload):
                parsed = request(command, payload)
                self.assertEqual(payload, parsed.payload)
                self.assertEqual(7, parsed.expected_revision)

        rejected = (
            ("device.manager.policy", {}),
            ("device.manager.policy", {"scanScope": "selected"}),
            ("device.manager.policy", {"scanEnabled": 1}),
            ("device.manager.policy", {"scanEnabled": True, "path": HOST_ROUTE}),
            ("device.manager.update", {"serial": "SERIAL-A"}),
            ("device.manager.update", {"serial": ""}),
            ("device.manager.update", {"serial": " SERIAL-A", "enabled": True}),
            ("device.manager.update", {"serial": "SERIAL-A ", "enabled": True}),
            ("device.manager.update", {"serial": "SERIAL-A", "label": "x" * 121}),
            ("device.manager.update", {"serial": "SERIAL-A", "label": "bad\nlabel"}),
            ("device.manager.update", {"serial": "SERIAL-A", "enabled": 1}),
            ("device.manager.update", {"label": "Missing serial"}),
            ("device.manager.update", {"serial": "SERIAL-A", "path": HOST_ROUTE}),
            ("device.manager.remove", {"serial": ""}),
            ("device.manager.remove", {"serial": "SERIAL-A", "enabled": False}),
        )
        for command, payload in rejected:
            with self.subTest(command=command, payload=payload):
                with self.assertRaises(BridgeProtocolError) as error:
                    request(command, payload)
                self.assertEqual("invalid_payload", error.exception.code)

        for command, payload in accepted:
            with self.subTest(command=command):
                with self.assertRaises(BridgeProtocolError) as error:
                    request(command, payload, revision=None)
                self.assertEqual("revision_required", error.exception.code)

    def test_factory_preserves_payload_and_never_binds_manager_commands_to_device(self) -> None:
        factory = create_command_factory(
            lambda: AppSnapshot(revision=7, selected_serial="SELECTED-SERIAL")
        )
        cases = (
            ("device.manager.policy", {"scanEnabled": False}),
            (
                "device.manager.update",
                {"serial": "REMEMBERED-SERIAL", "label": "Travel"},
            ),
            ("device.manager.remove", {"serial": "REMEMBERED-SERIAL"}),
        )

        for command, payload in cases:
            with self.subTest(command=command):
                created = factory(request(command, payload))
                self.assertEqual(command, created.kind)
                self.assertEqual(payload, created.payload)
                self.assertIsNone(created.target_serial)
                self.assertEqual(7, created.expected_revision)
                self.assertEqual("device-manager-contract", created.operation_id)
                self.assertFalse(created.destructive)
                self.assertFalse(created.requires_confirmation)
                self.assertEqual(
                    COMMAND_REGISTRY[command].timeout_ms / 1000.0 * 0.95,
                    created.execution_timeout_seconds,
                )

    def test_snapshot_serializers_include_the_exact_versioned_management_state(self) -> None:
        state = DeviceManagementState(
            scan_enabled=False,
            scan_scope="all",
            devices=(
                managed_device("SERIAL-B", label="Spare", connected=False),
                managed_device("SERIAL-A"),
            ),
        )
        snapshot = AppSnapshot(revision=7, device_management=state)
        expected = {
            "schemaVersion": 1,
            "scanEnabled": False,
            "scanScope": "all",
            "devices": [
                managed_device("SERIAL-A").to_dict(),
                managed_device("SERIAL-B", label="Spare", connected=False).to_dict(),
            ],
        }

        internal = snapshot.to_dict()
        public = snapshot.to_public_dict()

        self.assertEqual(expected, internal["device_management"])
        self.assertEqual(expected, public["device_management"])
        self.assertEqual(
            expected,
            json.loads(json.dumps(internal))["device_management"],
        )
        self.assertEqual(
            {
                "schemaVersion",
                "scanEnabled",
                "scanScope",
                "devices",
            },
            set(public["device_management"]),
        )
        for device in public["device_management"]["devices"]:
            self.assertEqual(
                {
                    "serial",
                    "label",
                    "enabled",
                    "model",
                    "codename",
                    "connected",
                    "mode",
                    "firstSeen",
                    "lastSeen",
                },
                set(device),
            )

    def test_snapshot_projector_bounds_management_records_timestamps_and_fields(self) -> None:
        raw_devices = [
            {
                "serial": f"SERIAL-{index:03d}",
                "label": "x" * 121,
                "enabled": True,
                "model": "m" * 257,
                "codename": "c" * 129,
                "connected": False,
                "mode": "offline",
                "firstSeen": 9_000_000_000_000_000,
                "lastSeen": 1_721_345_678,
                "path": HOST_ROUTE,
                "lastCommand": ["adb", "devices"],
            }
            for index in range(258)
        ]
        source = AppSnapshot(revision=7).to_dict()
        source["device_management"] = {
            "schemaVersion": 99,
            "scanEnabled": False,
            "scanScope": "all",
            "devices": raw_devices,
            "storagePath": HOST_ROUTE,
        }
        source["deviceManagerDatabase"] = HOST_ROUTE

        public = public_snapshot(source)
        management = public["device_management"]

        self.assertEqual(
            {
                "schemaVersion",
                "scanEnabled",
                "scanScope",
                "devices",
            },
            set(management),
        )
        self.assertEqual(1, management["schemaVersion"])
        self.assertFalse(management["scanEnabled"])
        self.assertEqual("all", management["scanScope"])
        devices = management["devices"]
        self.assertEqual(256, len(devices))
        first = devices[0]
        self.assertEqual(120, len(first["label"]))
        self.assertEqual(256, len(first["model"]))
        self.assertEqual(128, len(first["codename"]))
        self.assertEqual(0, first["firstSeen"])
        self.assertEqual(1_721_345_678, first["lastSeen"])
        self.assertEqual(
            {
                "serial",
                "label",
                "enabled",
                "model",
                "codename",
                "connected",
                "mode",
                "firstSeen",
                "lastSeen",
            },
            set(first),
        )
        self.assertNotIn(HOST_ROUTE, json.dumps(public))

        for command in sorted(MANAGER_COMMANDS):
            with self.subTest(command=command):
                projected = project_operation_result(
                    command,
                    OperationResult.success(
                        "device-manager-contract",
                        value=source,
                        stdout=HOST_ROUTE,
                        stderr=HOST_ROUTE,
                    ),
                )
                self.assertEqual(management, projected["value"]["device_management"])
                self.assertNotIn(HOST_ROUTE, json.dumps(projected))
                self.assertNotIn("stdout", projected)
                self.assertNotIn("stderr", projected)

    def test_generated_typescript_contains_the_exact_current_manager_contract(self) -> None:
        expected = render_typescript()
        actual = DEFAULT_OUTPUT.read_text(encoding="utf-8")

        self.assertEqual(expected, actual)
        self.assertTrue(write_or_check(DEFAULT_OUTPUT, check=True))
        generated_commands = load_react_commands(DEFAULT_OUTPUT)
        self.assertEqual(
            {
                "deviceManagerPolicy": "device.manager.policy",
                "deviceManagerUpdate": "device.manager.update",
                "deviceManagerRemove": "device.manager.remove",
            },
            {
                name: command
                for name, command in generated_commands.items()
                if command in MANAGER_COMMANDS
            },
        )
        for fragment in (
            '"device.manager.policy": {',
            '"scanEnabled"?: boolean;',
            '"scanScope"?: string;',
            '"device.manager.update": {',
            '"serial": string;',
            '"label"?: string;',
            '"enabled"?: boolean;',
            '"device.manager.remove": {',
            '"expectedRevision":"required"',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, actual)


if __name__ == "__main__":
    unittest.main()
