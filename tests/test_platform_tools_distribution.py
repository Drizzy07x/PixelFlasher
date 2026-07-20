from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pixelflasher_core.artifact_downloads import canonical_manifest_bytes
from pixelflasher_core.platform_tools_distribution import (
    PlatformToolsDistributionError,
    load_optional_platform_tools_distribution,
    load_platform_tools_distribution,
)


def _write_distribution(
    root: Path,
) -> tuple[Ed25519PrivateKey, bytes, dict[str, object]]:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    payload: dict[str, object] = {
        "keyId": "platform-tools-2026",
        "version": "37.0.0",
        "platform": "windows",
        "arch": "x86_64",
        "license": "Android-SDK-License",
        "provenance": "Google Android SDK Platform Tools stable repository",
        "url": "https://dl.google.com/android/repository/platform-tools_r37.0.0-win.zip",
        "sha256": hashlib.sha256(b"archive").hexdigest(),
        "size": len(b"archive"),
        "expiresAt": (datetime.now(UTC) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    signature = private_key.sign(canonical_manifest_bytes(payload))
    manifest = {
        **payload,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    (root / "windows-x86_64.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    catalog = {
        "schemaVersion": 1,
        "allowedHosts": ["dl.google.com"],
        "manifests": [
            {
                "platform": "windows",
                "architecture": "x86_64",
                "manifest": "windows-x86_64.json",
            }
        ],
    }
    (root / "catalog.json").write_text(
        json.dumps(catalog, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    return private_key, public_key, catalog


class PlatformToolsDistributionTests(unittest.TestCase):
    def test_authenticated_catalog_builds_route_free_runtime_components(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-platform-distribution-") as directory:
            root = Path(directory)
            _private_key, public_key, _catalog = _write_distribution(root)

            distribution = load_platform_tools_distribution(
                root,
                trusted_public_keys={"platform-tools-2026": public_key},
            )

            self.assertEqual(
                frozenset({("windows", "x86_64")}),
                distribution.targets,
            )
            self.assertEqual(
                frozenset({"platform-tools-2026"}),
                distribution.key_ids,
            )
            document = distribution.catalog.manifest_for(
                platform="win32",
                architecture="AMD64",
            )
            verified = distribution.downloader.verifier.verify(
                document,
                expected_platform="windows",
                expected_arch="x86_64",
            )
            self.assertEqual("37.0.0", verified.version)
            self.assertNotIn(str(root), repr(distribution.targets))

    def test_absence_is_optional_but_partial_or_tampered_catalogs_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-platform-distribution-bad-") as directory:
            parent = Path(directory)
            missing = parent / "missing"
            self.assertIsNone(load_optional_platform_tools_distribution(missing))

            root = parent / "resources"
            root.mkdir()
            with self.assertRaisesRegex(PlatformToolsDistributionError, "missing"):
                load_optional_platform_tools_distribution(root)

            _private_key, public_key, catalog = _write_distribution(root)
            manifest_path = root / "windows-x86_64.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["size"] = 8
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(PlatformToolsDistributionError, "authenticated"):
                load_platform_tools_distribution(
                    root,
                    trusted_public_keys={"platform-tools-2026": public_key},
                )

            catalog["manifests"][0]["manifest"] = "../outside.json"  # type: ignore[index]
            (root / "catalog.json").write_text(json.dumps(catalog), encoding="utf-8")
            with self.assertRaisesRegex(PlatformToolsDistributionError, "path"):
                load_platform_tools_distribution(
                    root,
                    trusted_public_keys={"platform-tools-2026": public_key},
                )

    def test_catalog_cannot_supply_or_replace_its_own_trust_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-platform-distribution-trust-") as directory:
            root = Path(directory)
            _private_key, public_key, catalog = _write_distribution(root)

            with self.assertRaisesRegex(PlatformToolsDistributionError, "trust policy"):
                load_platform_tools_distribution(root)

            catalog["publicKeys"] = {
                "platform-tools-2026": base64.b64encode(public_key).decode("ascii")
            }
            (root / "catalog.json").write_text(json.dumps(catalog), encoding="utf-8")
            with self.assertRaisesRegex(PlatformToolsDistributionError, "fields"):
                load_platform_tools_distribution(
                    root,
                    trusted_public_keys={"platform-tools-2026": public_key},
                )


if __name__ == "__main__":
    unittest.main()
