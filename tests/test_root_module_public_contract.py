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


if __name__ == "__main__":
    unittest.main()
