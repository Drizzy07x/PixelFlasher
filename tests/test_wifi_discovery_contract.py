import hashlib
import json
import unittest

from pixelflasher_core import AppSnapshot, OperationResult
from ui.bridge_contract import BRIDGE_VERSION, BridgeProtocolError, BridgeRequest
from ui.command_registry import (
    COMMAND_REGISTRY,
    CommandMutability,
    CommandOwner,
    CommandRisk,
    ExpectedRevision,
    TargetScope,
)
from ui.core_command_factory import create_command_factory
from ui.public_bridge import PublicProjectionError, project_operation_result

COMMAND = "tools.wifi.discover"


def request(*, payload=None, revision=4):
    return BridgeRequest.from_json(
        json.dumps(
            {
                "version": BRIDGE_VERSION,
                "requestId": "wifi-discovery-contract",
                "command": COMMAND,
                "payload": payload or {},
                "expectedRevision": revision,
            }
        )
    )


def discovery_value():
    endpoint = "192.168.1.42:37123"
    return {
        "action": "discover",
        "count": 1,
        "services": [
            {
                "id": hashlib.sha256(
                    f"pairing\0{endpoint}".encode("ascii")
                ).hexdigest(),
                "instance": "adb-akita-ABC123",
                "serviceType": "pairing",
                "host": "192.168.1.42",
                "port": 37123,
                "endpoint": endpoint,
                "addressFamily": "ipv4",
            }
        ],
        "discardedCount": 0,
        "bounded": True,
    }


class WifiDiscoveryContractTests(unittest.TestCase):
    def test_registry_declares_a_closed_application_scoped_host_read(self) -> None:
        spec = COMMAND_REGISTRY[COMMAND]

        self.assertEqual(CommandOwner.DEVICE_TOOLS, spec.owner)
        self.assertEqual(CommandMutability.READ_ONLY, spec.mutability)
        self.assertEqual(CommandRisk.HOST_READ, spec.risk)
        self.assertEqual(ExpectedRevision.REQUIRED, spec.expected_revision)
        self.assertEqual(TargetScope.APPLICATION, spec.target_scope)
        self.assertEqual(frozenset({"*"}), spec.valid_device_states)
        self.assertEqual(COMMAND, spec.planner)
        self.assertEqual((), spec.postconditions)
        self.assertEqual({}, dict(spec.payload.fields))
        self.assertTrue(spec.implemented)
        self.assertTrue(spec.exposed)

    def test_bridge_requires_revision_and_rejects_every_payload_field(self) -> None:
        accepted = request()
        self.assertEqual({}, accepted.payload)
        self.assertEqual(4, accepted.expected_revision)

        with self.assertRaises(BridgeProtocolError) as unknown:
            request(payload={"serial": "SERIAL"})
        self.assertEqual("invalid_payload", unknown.exception.code)

        with self.assertRaises(BridgeProtocolError) as missing_revision:
            request(revision=None)
        self.assertEqual("revision_required", missing_revision.exception.code)

    def test_factory_does_not_bind_discovery_to_a_selected_device(self) -> None:
        factory = create_command_factory(lambda: AppSnapshot(revision=4))

        command = factory(request())

        self.assertEqual(COMMAND, command.kind)
        self.assertEqual({}, command.payload)
        self.assertIsNone(command.target_serial)
        self.assertFalse(command.destructive)
        self.assertFalse(command.requires_confirmation)

    def test_public_projector_exposes_only_the_closed_typed_dto(self) -> None:
        value = discovery_value()
        public = project_operation_result(
            COMMAND,
            OperationResult.success("wifi-discovery", value=value),
        )

        self.assertEqual(value, public["value"])
        self.assertNotIn("stdout", public)
        self.assertNotIn("stderr", public)

        for extra in (
            {"raw": "private mdns output"},
            {"trusted": True},
            {"serial": "DEVICE-SERIAL"},
            {"txt": {"v": "1"}},
        ):
            with self.subTest(extra=extra):
                invalid = {**value, **extra}
                with self.assertRaises(PublicProjectionError):
                    project_operation_result(
                        COMMAND,
                        OperationResult.success("wifi-discovery", value=invalid),
                    )

        with self.assertRaises(PublicProjectionError):
            project_operation_result(
                COMMAND,
                OperationResult.success("wifi-discovery"),
            )


if __name__ == "__main__":
    unittest.main()
