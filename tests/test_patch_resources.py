import hashlib
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from pixelflasher_core.boot_patch import BootPatchService
from pixelflasher_core.patch_resources import (
    PATCH_RUNNER_PROTOCOL,
    PatchResourceError,
    load_patch_resource_registry,
)
from pixelflasher_core.runtime import ApplicationRuntime


def sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def write_manifest(root: Path, document: dict) -> tuple[Path, str]:
    path = root / "patch-resources.json"
    contents = json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
    path.write_bytes(contents)
    return path, sha256(contents)


class PatchResourceRegistryTests(unittest.TestCase):
    def resources(self, root: Path):
        runner = root / "patch-runner"
        runner.write_bytes(b"PIXELFLASHER_BOOT_PATCH_RUNNER_V1")
        support = root / "busybox"
        support.write_bytes(b"backend-pinned-support")
        document = {
            "schemaVersion": 3,
            "protocol": PATCH_RUNNER_PROTOCOL,
            "bundles": [
                {
                    "flavor": "magisk",
                    "runner": {
                        "path": "patch-runner",
                        "sha256": sha256(runner.read_bytes()),
                    },
                    "support": [
                        {
                            "path": "busybox",
                            "sha256": sha256(support.read_bytes()),
                        }
                    ],
                    "compatibility": {
                        "architectures": ["arm64"],
                        "kmi": ["android14-5.15"],
                    },
                }
            ],
        }
        return document, runner, support

    def load(self, root: Path, document: dict):
        manifest, digest = write_manifest(root, document)
        return load_patch_resource_registry(
            manifest,
            expected_manifest_sha256=digest,
            resource_root=root,
            hash_chunk_size=2,
        )

    def test_pinned_manifest_builds_backend_runner_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document, runner, support = self.resources(root)

            registry = self.load(root, document)

            self.assertEqual(frozenset({"magisk"}), registry.ready_flavors)
            self.assertFalse(registry.complete)
            bundle = registry.tool_bundles[0]
            self.assertEqual("", bundle.app_id)
            self.assertEqual(str(runner.resolve()), bundle.runner.path)
            self.assertEqual("patch-runner:magisk", bundle.runner.role)
            self.assertEqual(("arm64",), bundle.architectures)
            self.assertEqual(("android14-5.15",), bundle.kmi_versions)
            self.assertEqual(str(support.resolve()), bundle.support_artifacts[0].path)
            self.assertEqual("patch-support:magisk:0", bundle.support_artifacts[0].role)
            service = BootPatchService(tool_bundles=registry.tool_bundles)
            self.assertEqual((), service.rooting_service.root_app_inventory())

    def test_runtime_composes_the_verified_registry_for_catalog_and_patching(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document, runner, _support = self.resources(root)
            registry = self.load(root, document)

            runtime = ApplicationRuntime.open(
                root / "config.json",
                patch_resource_registry=registry,
            )
            try:
                self.assertIs(runtime.patch_resource_registry, registry)
                self.assertIs(
                    runtime.root_app_catalog_service.rooting_service,
                    runtime.command_engine.rooting_service,
                )
                self.assertEqual(
                    (),
                    runtime.command_engine.rooting_service.root_app_inventory(),
                )
                bundles = runtime.command_engine.boot_patch_service.tool_bundles["magisk"]
                self.assertEqual(1, len(bundles))
                bundle = bundles[0]
                self.assertEqual(str(runner.resolve()), bundle.runner.path)
                self.assertEqual("", bundle.app_id)
            finally:
                runtime.shutdown()

    def test_one_pinned_generic_runner_can_cover_all_seven_flavors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / "generic-runner"
            runner.write_bytes(b"PIXELFLASHER_BOOT_PATCH_RUNNER_V1")
            support = root / "busybox"
            support.write_bytes(b"multi-architecture-dispatch-support")
            bundles = [
                {
                    "flavor": flavor,
                    "runner": {
                        "path": runner.name,
                        "sha256": sha256(runner.read_bytes()),
                    },
                    "support": [
                        {
                            "path": support.name,
                            "sha256": sha256(support.read_bytes()),
                        }
                    ],
                    "compatibility": {
                        "architectures": ["*"],
                        "kmi": ["*"],
                    },
                }
                for flavor in (
                    "magisk",
                    "apatch",
                    "kernelsu",
                    "kernelsu-next",
                    "sukisu",
                    "wild-ksu",
                    "legacy",
                )
            ]
            registry = self.load(
                root,
                {
                    "schemaVersion": 3,
                    "protocol": PATCH_RUNNER_PROTOCOL,
                    "bundles": bundles,
                },
            )

            self.assertTrue(registry.complete)
            self.assertEqual(frozenset(), registry.missing_flavors)
            self.assertEqual(7, len(registry.tool_bundles))

    def test_same_flavor_variants_require_disjoint_compatibility(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document, _runner, _support = self.resources(root)
            runner = root / "patch-runner-6.1"
            runner.write_bytes(b"PIXELFLASHER_BOOT_PATCH_RUNNER_V1:6.1")
            variant = deepcopy(document["bundles"][0])
            variant["runner"] = {
                "path": runner.name,
                "sha256": sha256(runner.read_bytes()),
            }
            variant["compatibility"] = {
                "architectures": ["arm64"],
                "kmi": ["android15-6.1"],
            }
            document["bundles"].append(variant)

            registry = self.load(root, document)

            self.assertEqual(2, len(registry.tool_bundles))
            self.assertEqual(
                {("android14-5.15",), ("android15-6.1",)},
                {bundle.kmi_versions for bundle in registry.tool_bundles},
            )

            overlapping = deepcopy(document)
            overlapping["bundles"][1]["compatibility"]["kmi"] = ["*"]
            with self.assertRaises(PatchResourceError) as raised:
                self.load(root, overlapping)
            self.assertEqual("patch_compatibility_overlap", raised.exception.code)

            missing = deepcopy(document)
            del missing["bundles"][0]["compatibility"]
            with self.assertRaises(PatchResourceError) as raised:
                self.load(root, missing)
            self.assertEqual("manifest_schema_invalid", raised.exception.code)

    def test_manifest_and_every_resource_are_hash_pinned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document, runner, _support = self.resources(root)
            manifest, digest = write_manifest(root, document)

            with self.assertRaises(PatchResourceError) as raised:
                load_patch_resource_registry(
                    manifest,
                    expected_manifest_sha256="0" * 64,
                    resource_root=root,
                )
            self.assertEqual("manifest_hash_mismatch", raised.exception.code)

            runner.write_bytes(b"tampered")
            with self.assertRaises(PatchResourceError) as raised:
                load_patch_resource_registry(
                    manifest,
                    expected_manifest_sha256=digest,
                    resource_root=root,
                )
            self.assertEqual("resource_hash_mismatch", raised.exception.code)

    def test_arbitrary_pinned_binary_is_not_mislabeled_as_protocol_runner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document, runner, _support = self.resources(root)
            runner.write_bytes(b"ordinary busybox-like executable")
            document["bundles"][0]["runner"]["sha256"] = sha256(runner.read_bytes())

            with self.assertRaises(PatchResourceError) as raised:
                self.load(root, document)

            self.assertEqual(
                "runner_protocol_marker_missing",
                raised.exception.code,
            )

    def test_relative_paths_and_exact_schema_reject_frontend_execution_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document, _runner, _support = self.resources(root)
            traversal = deepcopy(document)
            traversal["bundles"][0]["runner"]["path"] = "../runner"
            with self.assertRaises(PatchResourceError) as raised:
                self.load(root, traversal)
            self.assertEqual("resource_path_invalid", raised.exception.code)

            for field in ("argv", "runnerPath", "url", "command"):
                with self.subTest(field=field):
                    untrusted = deepcopy(document)
                    untrusted["bundles"][0][field] = "browser-controlled"
                    with self.assertRaises(PatchResourceError) as raised:
                        self.load(root, untrusted)
                    self.assertEqual("manifest_schema_invalid", raised.exception.code)

    def test_duplicate_json_keys_and_unsupported_flavor_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document, _runner, _support = self.resources(root)
            manifest = root / "patch-resources.json"
            contents = (
                f'{{"schemaVersion":3,"schemaVersion":3,"protocol":"{PATCH_RUNNER_PROTOCOL}","bundles":[]}}'
            ).encode()
            manifest.write_bytes(contents)
            with self.assertRaises(PatchResourceError) as raised:
                load_patch_resource_registry(
                    manifest,
                    expected_manifest_sha256=sha256(contents),
                    resource_root=root,
                )
            self.assertEqual("manifest_duplicate_key", raised.exception.code)

            mismatch = deepcopy(document)
            mismatch["bundles"][0]["flavor"] = "unknown"
            with self.assertRaises(PatchResourceError) as raised:
                self.load(root, mismatch)
            self.assertEqual("patch_flavor_unsupported", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
