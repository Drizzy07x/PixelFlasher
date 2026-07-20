import json
import unittest

from ui.bridge_contract import (
    ALLOWED_COMMANDS,
    BRIDGE_CHANNEL,
    BRIDGE_VERSION,
    MAX_PAYLOAD_BYTES,
    BridgeProtocolError,
    BridgeRequest,
    event_envelope,
    protocol_error_envelope,
    response_envelope,
)


def message(**overrides):
    value = {
        "version": BRIDGE_VERSION,
        "requestId": "request-1",
        "command": "snapshot.get",
        "payload": {},
        "expectedRevision": None,
    }
    value.update(overrides)
    return json.dumps(value)


class BridgeContractTests(unittest.TestCase):
    def test_uses_v2_on_the_single_edge_compatible_channel(self):
        self.assertEqual(2, BRIDGE_VERSION)
        self.assertEqual("pixelflasher", BRIDGE_CHANNEL)

    def test_parses_only_the_exact_request_envelope(self):
        request = BridgeRequest.from_json(message())

        self.assertEqual("request-1", request.request_id)
        self.assertEqual("snapshot.get", request.command)
        self.assertEqual({}, request.payload)
        self.assertIsNone(request.expected_revision)

        for alias, value in (
            ("request_id", "alias"),
            ("expected_revision", 0),
            ("delegate", "_on_flash"),
        ):
            raw = json.loads(message())
            raw[alias] = value
            with self.subTest(alias=alias), self.assertRaises(BridgeProtocolError) as rejected:
                BridgeRequest.from_json(json.dumps(raw))
            self.assertEqual("invalid_envelope", rejected.exception.code)

    def test_rejects_unknown_commands_versions_duplicates_and_nonfinite_json(self):
        with self.assertRaises(BridgeProtocolError) as unknown:
            BridgeRequest.from_json(message(command="python.eval"))
        self.assertEqual("command_not_allowed", unknown.exception.code)

        with self.assertRaises(BridgeProtocolError) as version:
            BridgeRequest.from_json(message(version=1))
        self.assertEqual("unsupported_version", version.exception.code)

        duplicate = (
            '{"version":2,"version":2,"requestId":"r","command":"snapshot.get",'
            '"payload":{},"expectedRevision":null}'
        )
        with self.assertRaises(BridgeProtocolError) as duplicated:
            BridgeRequest.from_json(duplicate)
        self.assertEqual("invalid_json", duplicated.exception.code)

        with self.assertRaises(BridgeProtocolError) as nonfinite:
            BridgeRequest.from_json(message(payload={"value": float("nan")}))
        self.assertEqual("invalid_json", nonfinite.exception.code)

    def test_mutations_require_a_non_negative_expected_revision(self):
        for revision in (None, -1, True, "1"):
            with self.subTest(revision=revision), self.assertRaises(BridgeProtocolError) as invalid:
                BridgeRequest.from_json(
                    message(command="device.scan", expectedRevision=revision)
                )
            self.assertIn(invalid.exception.code, {"revision_required", "invalid_revision"})

        loaded = BridgeRequest.from_json(
            message(command="settings.get", expectedRevision=None)
        )
        self.assertIsNone(loaded.expected_revision)

    def test_boot_delete_accepts_only_one_opaque_repository_id(self):
        loaded = BridgeRequest.from_json(
            message(
                command="boot.delete",
                payload={"bootId": "a" * 32},
                expectedRevision=7,
            )
        )
        self.assertEqual({"bootId": "a" * 32}, loaded.payload)

        for payload in (
            {},
            {"bootId": "A" * 32},
            {"bootId": "a" * 31},
            {"bootId": "a" * 32, "path": "C:/private/boot.img"},
        ):
            with self.subTest(payload=payload), self.assertRaises(
                BridgeProtocolError
            ) as rejected:
                BridgeRequest.from_json(
                    message(
                        command="boot.delete",
                        payload=payload,
                        expectedRevision=7,
                    )
                )
            self.assertEqual("invalid_payload", rejected.exception.code)

    def test_backup_inventory_uses_opaque_ids_and_exact_delete_confirmation(self):
        backup_id = "a" * 24 + "1234abcd"
        listed = BridgeRequest.from_json(
            message(
                command="backups.list",
                payload={"serial": "SERIAL"},
                expectedRevision=7,
            )
        )
        restored = BridgeRequest.from_json(
            message(
                command="backups.restore",
                payload={
                    "serial": "SERIAL",
                    "partition": "boot",
                    "slot": "a",
                    "backupId": backup_id,
                },
                expectedRevision=7,
            )
        )
        deleted = BridgeRequest.from_json(
            message(
                command="backups.delete",
                payload={
                    "backupId": backup_id,
                    "confirmationText": "DELETE 1234ABCD",
                },
                expectedRevision=7,
            )
        )

        self.assertEqual({"serial": "SERIAL"}, listed.payload)
        self.assertEqual(backup_id, restored.payload["backupId"])
        self.assertEqual("DELETE 1234ABCD", deleted.payload["confirmationText"])

        invalid = (
            ("backups.list", {"serial": ""}),
            (
                "backups.restore",
                {"partition": "boot", "slot": "a", "backupId": "A" * 32},
            ),
            (
                "backups.restore",
                {
                    "partition": "boot",
                    "slot": "a",
                    "backupId": backup_id,
                    "grant": "g" * 64,
                },
            ),
            (
                "backups.delete",
                {"backupId": backup_id, "confirmationText": "DELETE wrong"},
            ),
        )
        for command_name, payload in invalid:
            with self.subTest(command=command_name, payload=payload), self.assertRaises(
                BridgeProtocolError
            ) as rejected:
                BridgeRequest.from_json(
                    message(
                        command=command_name,
                        payload=payload,
                        expectedRevision=7,
                    )
                )
            self.assertEqual("invalid_payload", rejected.exception.code)

    def test_root_app_catalog_accepts_only_channels_and_opaque_artifact_ids(self):
        refresh = BridgeRequest.from_json(
            message(
                command="root.apps.catalog.refresh",
                payload={"channel": "canary"},
                expectedRevision=7,
            )
        )
        download = BridgeRequest.from_json(
            message(
                command="root.apps.download",
                payload={"artifactId": "a" * 32},
                expectedRevision=7,
            )
        )
        self.assertEqual({"channel": "canary"}, refresh.payload)
        self.assertEqual({"artifactId": "a" * 32}, download.payload)

        invalid = (
            ("root.apps.catalog.refresh", {"channel": "nightly"}),
            ("root.apps.download", {"artifactId": "A" * 32}),
            ("root.apps.download", {"artifactId": "a" * 32, "url": "https://evil.test/app.apk"}),
            ("root.apps.download", {"path": "C:/private/app.apk"}),
        )
        for command, payload in invalid:
            with self.subTest(command=command, payload=payload), self.assertRaises(
                BridgeProtocolError
            ) as rejected:
                BridgeRequest.from_json(
                    message(
                        command=command,
                        payload=payload,
                        expectedRevision=7,
                    )
                )
            self.assertEqual("invalid_payload", rejected.exception.code)

    def test_logcat_clear_contract_binds_one_serial_to_an_exact_revision(self):
        loaded = BridgeRequest.from_json(
            message(
                command="tools.logcat.clear",
                payload={"serial": "SERIAL"},
                expectedRevision=7,
            )
        )

        self.assertEqual("tools.logcat.clear", loaded.command)
        self.assertEqual({"serial": "SERIAL"}, loaded.payload)
        self.assertEqual(7, loaded.expected_revision)

        invalid_cases = (
            ({"serial": "SERIAL"}, None, "revision_required"),
            ({"serial": ""}, 7, "invalid_payload"),
            ({"serial": "SERIAL", "buffers": ["all"]}, 7, "invalid_payload"),
            (
                {"serial": "SERIAL", "confirmationText": "CLEAR SERIAL"},
                7,
                "invalid_payload",
            ),
        )
        for payload, revision, code in invalid_cases:
            with self.subTest(payload=payload, revision=revision), self.assertRaises(
                BridgeProtocolError
            ) as rejected:
                BridgeRequest.from_json(
                    message(
                        command="tools.logcat.clear",
                        payload=payload,
                        expectedRevision=revision,
                    )
                )
            self.assertEqual(code, rejected.exception.code)

    def test_all_commands_reject_unknown_fields_and_browser_paths(self):
        cases = (
            ("firmware.process", {"path": "C:/firmware.zip"}),
            ("firmware.select", {"path": "C:/firmware.zip"}),
            ("boot.patch", {"destination": "C:/patched.img"}),
            ("tools.pushFiles", {"paths": ["C:/private/file"]}),
            ("support.create", {"destinationId": "x" * 64}),
            ("tools.wifi", {"pairingCode": "123456"}),
            ("native.pickFile", {"purpose": "firmware.select", "initialDirectory": "C:/"}),
        )
        for command, payload in cases:
            with self.subTest(command=command), self.assertRaises(BridgeProtocolError) as rejected:
                BridgeRequest.from_json(
                    message(command=command, payload=payload, expectedRevision=1)
                )
            self.assertEqual("invalid_payload", rejected.exception.code)

    def test_grants_and_native_picker_purposes_are_bounded(self):
        token = "g" * 64
        selected = BridgeRequest.from_json(
            message(
                command="firmware.select",
                payload={"grant": token, "expectedKind": "custom"},
                expectedRevision=7,
            )
        )
        with self.assertRaises(BridgeProtocolError) as invalid_kind:
            BridgeRequest.from_json(
                message(
                    command="firmware.select",
                    payload={"grant": token, "expectedKind": "unknown"},
                    expectedRevision=7,
                )
            )
        self.assertEqual("invalid_payload", invalid_kind.exception.code)
        prompt = BridgeRequest.from_json(
            message(
                command="secret.issue",
                payload={
                    "purpose": "wifi.pairingCode",
                    "secret": "123456",
                },
                expectedRevision=7,
            )
        )
        wifi = BridgeRequest.from_json(
            message(
                command="tools.wifi",
                payload={
                    "action": "pair",
                    "host": "192.0.2.20",
                    "port": 37123,
                    "secretGrant": token,
                },
                expectedRevision=7,
            )
        )

        self.assertEqual(token, selected.payload["grant"])
        self.assertEqual("wifi.pairingCode", prompt.payload["purpose"])
        self.assertNotIn("123456", repr(prompt))
        self.assertNotIn("123456", repr(wifi))

        push = BridgeRequest.from_json(
            message(
                command="tools.pushFiles",
                payload={
                    "serial": "SERIAL",
                    "grants": [f"{index:064x}" for index in range(32)],
                    "destination": "/sdcard/Download/",
                },
                expectedRevision=7,
            )
        )
        self.assertEqual(32, len(push.payload["grants"]))
        with self.assertRaises(BridgeProtocolError) as excessive:
            BridgeRequest.from_json(
                message(
                    command="tools.pushFiles",
                    payload={
                        "serial": "SERIAL",
                        "grants": [f"{index:064x}" for index in range(33)],
                        "destination": "/sdcard/Download/",
                    },
                    expectedRevision=7,
                )
            )
        self.assertEqual("invalid_payload", excessive.exception.code)

        apatch = BridgeRequest.from_json(
            message(
                command="boot.patch",
                payload={
                    "serial": "SERIAL",
                    "flavor": "apatch",
                    "appId": "a" * 64,
                    "grant": "w" * 64,
                    "secretGrant": token,
                },
                expectedRevision=7,
            )
        )
        self.assertEqual(token, apatch.payload["secretGrant"])

        with self.assertRaises(BridgeProtocolError) as missing_apatch_secret:
            BridgeRequest.from_json(
                message(
                    command="boot.patch",
                    payload={
                        "serial": "SERIAL",
                        "flavor": "apatch",
                        "appId": "a" * 64,
                        "grant": "w" * 64,
                    },
                    expectedRevision=7,
                )
            )
        self.assertEqual("invalid_payload", missing_apatch_secret.exception.code)

        with self.assertRaises(BridgeProtocolError) as raw_secret:
            BridgeRequest.from_json(
                message(
                    command="tools.wifi",
                    payload={
                        "action": "pair",
                        "host": "192.0.2.20",
                        "port": 37123,
                        "pairingCode": "123456",
                    },
                    expectedRevision=7,
                )
            )
        self.assertEqual("invalid_payload", raw_secret.exception.code)

    def test_payload_has_an_independent_size_limit(self):
        with self.assertRaises(BridgeProtocolError) as large:
            BridgeRequest.from_json(
                message(
                    command="settings.update",
                    payload={"theme": "x" * (MAX_PAYLOAD_BYTES + 1)},
                    expectedRevision=1,
                )
            )
        self.assertEqual("payload_too_large", large.exception.code)

    def test_response_and_event_envelopes_are_exact(self):
        success = response_envelope("r1", ok=True, result={"status": "SUCCESS"})
        failure = response_envelope(
            "r2", ok=False, error={"code": "failed", "message": "Failed."}
        )
        event = event_envelope("snapshot", {"revision": 3}, revision=3)

        self.assertEqual({"version", "requestId", "ok", "result"}, set(success))
        self.assertEqual({"version", "requestId", "ok", "error"}, set(failure))
        self.assertEqual({"version", "event", "revision", "payload"}, set(event))
        self.assertNotIn("type", success)
        self.assertNotIn("type", event)

    def test_protocol_errors_are_safe_exact_failure_responses(self):
        error = BridgeProtocolError("invalid_json", "Malformed request", request_id="safe-id")
        envelope = protocol_error_envelope(error)

        self.assertEqual(
            {"version", "requestId", "ok", "error"},
            set(envelope),
        )
        self.assertFalse(envelope["ok"])
        self.assertEqual("invalid_json", envelope["error"]["code"])
        json.dumps(envelope)

    def test_event_types_are_constrained(self):
        self.assertEqual(
            "snapshot",
            event_envelope("snapshot", {"revision": 1}, revision=1)["event"],
        )
        with self.assertRaises(ValueError):
            event_envelope("javascript", {}, revision=1)

    def test_allow_list_covers_primary_product_areas(self):
        prefixes = {command.split(".", 1)[0] for command in ALLOWED_COMMANDS}
        self.assertTrue(
            {"device", "flash", "firmware", "boot", "root", "apps", "backups", "tools", "settings"}
            <= prefixes
        )


if __name__ == "__main__":
    unittest.main()
