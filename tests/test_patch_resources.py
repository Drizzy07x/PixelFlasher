import hashlib
import json
import tempfile
import unittest
import zipfile
from copy import deepcopy
from pathlib import Path

from pixelflasher_core.boot_patch import BootPatchService
from pixelflasher_core.patch_resources import (
    PATCH_RUNNER_PROTOCOL,
    PatchResourceError,
    load_patch_resource_registry,
)


def sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def write_apk(path: Path, provider: str) -> str:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", provider.encode("utf-8"))
        archive.writestr("classes.dex", b"dex")
    return sha256(path.read_bytes())


def write_manifest(root: Path, document: dict) -> tuple[Path, str]:
    path = root / "patch-resources.json"
    contents = json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
    path.write_bytes(contents)
    return path, sha256(contents)


class PatchResourceRegistryTests(unittest.TestCase):
    def resources(self, root: Path):
        apk = root / "magisk.apk"
        apk_hash = write_apk(apk, "Magisk")
        runner = root / "patch-runner"
        runner.write_bytes(b"PIXELFLASHER_BOOT_PATCH_RUNNER_V1")
        support = root / "busybox"
        support.write_bytes(b"backend-pinned-support")
        document = {
            "schemaVersion": 1,
            "protocol": PATCH_RUNNER_PROTOCOL,
            "apps": [
                {
                    "key": "magisk-stable",
                    "path": "magisk.apk",
                    "sha256": apk_hash,
                    "provider": "Magisk",
                    "flavor": "stable",
                    "version": "1.0",
                    "provenance": "bundled",
                }
            ],
            "bundles": [
                {
                    "flavor": "magisk",
                    "app": "magisk-stable",
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
                }
            ],
        }
        return document, apk, runner, support

    def load(self, root: Path, document: dict):
        manifest, digest = write_manifest(root, document)
        return load_patch_resource_registry(
            manifest,
            expected_manifest_sha256=digest,
            resource_root=root,
            hash_chunk_size=2,
        )

    def test_pinned_manifest_builds_backend_rooting_service_and_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document, apk, runner, support = self.resources(root)

            registry = self.load(root, document)

            inventory = registry.rooting_service.root_app_inventory()
            self.assertEqual(1, len(inventory))
            self.assertEqual(str(apk.resolve()), inventory[0].path)
            self.assertEqual("bundled", inventory[0].provenance)
            self.assertEqual(frozenset({"magisk"}), registry.ready_flavors)
            self.assertFalse(registry.complete)
            bundle = registry.tool_bundles[0]
            self.assertEqual(inventory[0].id, bundle.app_id)
            self.assertEqual(str(runner.resolve()), bundle.runner.path)
            self.assertEqual("patch-runner:magisk", bundle.runner.role)
            self.assertEqual(str(support.resolve()), bundle.support_artifacts[0].path)
            self.assertEqual("patch-support:magisk:0", bundle.support_artifacts[0].role)
            service = BootPatchService(
                registry.rooting_service,
                registry.tool_bundles,
            )
            self.assertIs(registry.rooting_service, service.rooting_service)

    def test_one_pinned_generic_runner_can_cover_all_seven_flavors(self):
        providers = {
            "magisk": "Magisk",
            "apatch": "APatch",
            "kernelsu": "KernelSU",
            "kernelsu-next": "KernelSU-Next",
            "sukisu": "SukiSU",
            "wild-ksu": "Wild_KSU",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / "generic-runner"
            runner.write_bytes(b"PIXELFLASHER_BOOT_PATCH_RUNNER_V1")
            support = root / "busybox"
            support.write_bytes(b"multi-architecture-dispatch-support")
            apps = []
            app_keys = {}
            for flavor, provider in providers.items():
                key = f"{flavor}-app"
                apk = root / f"{flavor}.apk"
                apps.append(
                    {
                        "key": key,
                        "path": apk.name,
                        "sha256": write_apk(apk, provider),
                        "provider": provider,
                        "flavor": "stable",
                        "version": "1.0",
                        "provenance": "bundled",
                    }
                )
                app_keys[flavor] = key
            app_keys["legacy"] = app_keys["kernelsu"]
            bundles = [
                {
                    "flavor": flavor,
                    "app": app_keys[flavor],
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
                    "schemaVersion": 1,
                    "protocol": PATCH_RUNNER_PROTOCOL,
                    "apps": apps,
                    "bundles": bundles,
                },
            )

            self.assertTrue(registry.complete)
            self.assertEqual(frozenset(), registry.missing_flavors)
            self.assertEqual(7, len(registry.tool_bundles))
            self.assertEqual(6, len(registry.root_app_sources))

    def test_manifest_and_every_resource_are_hash_pinned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document, _apk, runner, _support = self.resources(root)
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
            document, _apk, runner, _support = self.resources(root)
            runner.write_bytes(b"ordinary busybox-like executable")
            document["bundles"][0]["runner"]["sha256"] = sha256(
                runner.read_bytes()
            )

            with self.assertRaises(PatchResourceError) as raised:
                self.load(root, document)

            self.assertEqual(
                "runner_protocol_marker_missing",
                raised.exception.code,
            )

    def test_relative_paths_and_exact_schema_reject_frontend_execution_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document, _apk, _runner, _support = self.resources(root)
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

    def test_duplicate_json_keys_and_incompatible_provider_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document, _apk, _runner, _support = self.resources(root)
            manifest = root / "patch-resources.json"
            contents = (
                '{"schemaVersion":1,"schemaVersion":1,'
                f'"protocol":"{PATCH_RUNNER_PROTOCOL}","apps":[],"bundles":[]}}'
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
            mismatch["bundles"][0]["flavor"] = "apatch"
            with self.assertRaises(PatchResourceError) as raised:
                self.load(root, mismatch)
            self.assertEqual("patch_app_provider_mismatch", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
