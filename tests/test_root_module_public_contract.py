import unittest

from pixelflasher_core import OperationResult
from ui.public_bridge import PublicProjectionError, project_operation_result

MODULE = {
    "id": "play_integrity_fix",
    "name": "Play Integrity Fix",
    "version": "19.1",
    "versionCode": 19100,
    "author": "Test author",
    "description": "Verified module metadata",
    "state": "enabled",
    "updateMetadata": "available",
}


class RootModulePublicContractTests(unittest.TestCase):
    @staticmethod
    def project(value: object):
        return project_operation_result(
            "root.modules.list",
            OperationResult.success("root-module-public", value=value),
        )["value"]

    def test_projects_closed_route_and_url_free_module_metadata(self):
        projected = self.project({"count": 1, "modules": [MODULE]})

        self.assertEqual(MODULE, projected["modules"][0])
        self.assertNotIn("updateUrl", projected["modules"][0])
        self.assertNotIn("path", projected["modules"][0])

    def test_rejects_unknown_fields_duplicates_counts_and_invalid_states(self):
        invalid = (
            {"count": 1, "modules": [{**MODULE, "updateUrl": "https://private.test"}]},
            {"count": 2, "modules": [MODULE]},
            {"count": 2, "modules": [MODULE, {**MODULE, "id": "PLAY_INTEGRITY_FIX"}]},
            {"count": 1, "modules": [{**MODULE, "state": "running"}]},
            {"count": 1, "modules": [{**MODULE, "description": "bad\nrecord"}]},
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(PublicProjectionError):
                    self.project(value)

    def test_projects_verified_update_artifacts_without_backend_routes(self):
        value = {
            "count": 1,
            "updates": [
                {
                    "artifactId": "a" * 32,
                    "moduleId": "play_integrity_fix",
                    "installedVersion": "",
                    "installedVersionCode": 19100,
                    "version": "19.2",
                    "versionCode": 19200,
                    "sha256": "b" * 64,
                    "size": 4096,
                    "provenance": "module-update-json",
                    "trust": "unverified-author",
                }
            ],
            "issueCount": 1,
            "issues": [
                {
                    "moduleId": "other_module",
                    "code": "root_module_update_url_untrusted",
                }
            ],
        }

        projected = project_operation_result(
            "root.modules.updates",
            OperationResult.success("updates", value=value),
        )["value"]

        self.assertEqual(value, projected)
        self.assertNotIn("path", repr(projected))
        self.assertNotIn("https://", repr(projected).casefold())

    def test_rejects_expanded_update_and_mutation_receipts(self):
        with self.assertRaises(PublicProjectionError):
            project_operation_result(
                "root.modules.updates",
                OperationResult.success(
                    "updates",
                    value={
                        "count": 1,
                        "updates": [
                            {
                                "artifactId": "a" * 32,
                                "moduleId": "play_integrity_fix",
                                "installedVersion": "",
                                "installedVersionCode": 19100,
                                "version": "19.2",
                                "versionCode": 19200,
                                "sha256": "b" * 64,
                                "size": 4096,
                                "provenance": "module-update-json",
                                "trust": "unverified-author",
                                "path": "C:/private/update.zip",
                            }
                        ],
                        "issueCount": 0,
                        "issues": [],
                    },
                ),
            )
        projected = project_operation_result(
            "root.modules.action",
            OperationResult.success(
                "updated",
                value={
                    "action": "update",
                    "targetSerial": "SERIAL",
                    "moduleId": "play_integrity_fix",
                    "artifact": {
                        "path": "C:/private/update.zip",
                        "sha256": "b" * 64,
                        "role": "root-module-update:play_integrity_fix",
                    },
                    "verified": True,
                },
            ),
        )["value"]
        self.assertEqual("update", projected["action"])
        self.assertNotIn("path", projected)


if __name__ == "__main__":
    unittest.main()
