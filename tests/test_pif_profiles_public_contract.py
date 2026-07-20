from __future__ import annotations

import hashlib
import unittest
from typing import Any, cast

from pixelflasher_core import OperationResult
from ui.bridge_contract import BridgeProtocolError, BridgeRequest
from ui.command_registry import COMMAND_REGISTRY
from ui.public_bridge import PublicProjectionError, project_operation_result


def metadata(content: str, *, label: str = "Pixel 9") -> dict[str, object]:
    digest = hashlib.sha256(content.encode()).hexdigest()
    return {
        "favoriteId": digest, "label": label,
        "createdAt": "2026-07-20T12:00:00+00:00", "sha256": digest,
        "size": len(content.encode()),
    }


class PifProfilesPublicContractTests(unittest.TestCase):
    def project(self, command: str, value: object) -> dict[str, Any]:
        result = project_operation_result(
            command, OperationResult.success("operation", value=value)
        )
        return cast(dict[str, Any], result["value"])

    def test_transform_contract_and_projection_verify_every_content_byte(self):
        payload = {
            "content": "BRAND=google\n", "inputFormat": "prop", "outputFormat": "json",
            "normalize": True, "keepUnknown": False, "sortKeys": True, "firstApi": 35,
        }
        request = BridgeRequest(2, "transform", "root.pif.transform", payload, 7)
        self.assertIs(request, request.validate())
        content = '{\n  "BRAND": "google"\n}\n'
        value = {
            "schemaVersion": 1, "format": "json", "content": content,
            "sha256": hashlib.sha256(content.encode()).hexdigest(),
            "size": len(content.encode()), "fieldCount": 1, "bounded": True,
        }
        self.assertEqual(self.project("root.pif.transform", value), value)
        for hostile in (
            {**payload, "inputFormat": "env"}, {**payload, "firstApi": 0},
            {**payload, "content": ""}, {**payload, "path": "C:\\private.json"},
        ):
            with self.subTest(hostile=hostile), self.assertRaises(BridgeProtocolError):
                BridgeRequest(2, "bad-transform", "root.pif.transform", hostile, 7).validate()
        with self.assertRaises(PublicProjectionError):
            self.project("root.pif.transform", {**value, "sha256": "a" * 64})

    def test_favorites_list_get_save_delete_are_closed_and_revision_bound(self):
        content = '{\n  "BRAND": "google"\n}\n'
        item = metadata(content)
        listed = self.project("root.pif.favorites.list", {
            "schemaVersion": 1, "revision": 3, "count": 1,
            "favorites": [item], "bounded": True,
        })
        self.assertEqual(listed["favorites"], [item])
        loaded = self.project("root.pif.favorites.get", {
            "schemaVersion": 1, "revision": 3,
            "favorite": {**item, "content": content}, "bounded": True,
        })
        self.assertEqual(loaded["favorite"]["content"], content)
        for command, action in (
            ("root.pif.favorites.save", "saved"),
            ("root.pif.favorites.delete", "deleted"),
        ):
            projected = self.project(command, {
                "schemaVersion": 1, "action": action, "revision": 4,
                "snapshotRevision": 8, "favorite": item, "bounded": True,
            })
            self.assertEqual(projected["favorite"], item)

        favorite_id = cast(str, item["favoriteId"])
        valid_requests = (
            BridgeRequest(2, "list", "root.pif.favorites.list", {}, 7),
            BridgeRequest(2, "get", "root.pif.favorites.get", {"favoriteId": favorite_id}, 7),
            BridgeRequest(2, "save", "root.pif.favorites.save", {
                "label": "Pixel 9", "content": content,
            }, 7),
            BridgeRequest(2, "delete", "root.pif.favorites.delete", {
                "favoriteId": favorite_id,
            }, 7),
        )
        for request in valid_requests:
            self.assertIs(request, request.validate())
            self.assertEqual(
                COMMAND_REGISTRY[request.command].expected_revision.value, "required"
            )

    def test_favorite_contract_rejects_routes_tampering_and_aliases(self):
        content = '{\n  "BRAND": "google"\n}\n'
        item = metadata(content)
        hostile_requests = (
            ("root.pif.favorites.list", {"includeContent": True}),
            ("root.pif.favorites.get", {"favoriteId": "../favorite"}),
            ("root.pif.favorites.save", {"label": "bad\nlabel", "content": content}),
            ("root.pif.favorites.delete", {"favoriteId": "a" * 64, "path": "/tmp"}),
        )
        for command, payload in hostile_requests:
            with self.subTest(command=command), self.assertRaises(BridgeProtocolError):
                BridgeRequest(2, "hostile", command, payload, 7).validate()
        hostile_values = (
            ("root.pif.favorites.list", {
                "schemaVersion": 1, "revision": 1, "count": 2,
                "favorites": [item], "bounded": True,
            }),
            ("root.pif.favorites.get", {
                "schemaVersion": 1, "revision": 1,
                "favorite": {**item, "content": content + " "}, "bounded": True,
            }),
            ("root.pif.favorites.save", {
                "schemaVersion": 1, "action": "saved", "revision": 1,
                "snapshotRevision": 1, "favorite": {**item, "path": "C:\\private"},
                "bounded": True,
            }),
        )
        for command, value in hostile_values:
            with self.subTest(command=command), self.assertRaises(PublicProjectionError):
                self.project(command, value)


if __name__ == "__main__":
    unittest.main()
