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
from pixelflasher_core.root_app_distribution import (
    RootAppDistributionError,
    load_optional_root_app_distribution,
    load_root_app_distribution,
)


def _write_distribution(
    root: Path,
) -> tuple[bytes, dict[str, object]]:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    payload: dict[str, object] = {
        "keyId": "root-apps-2026",
        "version": "30.7",
        "platform": "android",
        "arch": "universal",
        "license": "GPL-3.0",
        "provenance": "Official GitHub release topjohnwu/Magisk v30.7",
        "url": "https://github.com/topjohnwu/Magisk/releases/download/v30.7/Magisk-v30.7.apk",
        "sha256": hashlib.sha256(b"apk").hexdigest(),
        "size": len(b"apk"),
        "expiresAt": (datetime.now(UTC) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    manifest = {
        **payload,
        "signature": base64.b64encode(private_key.sign(canonical_manifest_bytes(payload))).decode("ascii"),
    }
    (root / "magisk-stable-universal.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    catalog: dict[str, object] = {
        "schemaVersion": 1,
        "allowedHosts": [
            "github.com",
            "release-assets.githubusercontent.com",
        ],
        "entries": [
            {
                "provider": "magisk",
                "channel": "stable",
                "flavor": "magisk",
                "packageName": "com.topjohnwu.magisk",
                "signerSha256": ["a" * 64],
                "architecture": "universal",
                "manifest": "magisk-stable-universal.json",
            }
        ],
    }
    (root / "catalog.json").write_text(
        json.dumps(catalog, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    return public_key, catalog


class RootAppDistributionTests(unittest.TestCase):
    def test_authenticated_catalog_builds_root_app_runtime_components(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-root-app-distribution-") as directory:
            root = Path(directory)
            public_key, _catalog = _write_distribution(root)

            distribution = load_root_app_distribution(
                root,
                trusted_public_keys={"root-apps-2026": public_key},
            )

            self.assertEqual(
                frozenset({("magisk", "stable", "universal")}),
                distribution.targets,
            )
            self.assertEqual(frozenset({"root-apps-2026"}), distribution.key_ids)
            sources = distribution.catalog.manifests_for(channel="stable")
            self.assertEqual(1, len(sources))
            self.assertEqual("com.topjohnwu.magisk", sources[0].package_name)
            verified = distribution.downloader.verifier.verify(
                sources[0].manifest_document,
                expected_platform="android",
                expected_arch="universal",
            )
            self.assertEqual("30.7", verified.version)

    def test_absence_is_optional_but_partial_and_tampered_catalogs_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-root-app-distribution-bad-") as directory:
            parent = Path(directory)
            self.assertIsNone(load_optional_root_app_distribution(parent / "missing"))

            root = parent / "runtime"
            root.mkdir()
            with self.assertRaisesRegex(RootAppDistributionError, "missing"):
                load_optional_root_app_distribution(root)

            public_key, catalog = _write_distribution(root)
            manifest_path = root / "magisk-stable-universal.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["size"] = 4
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(RootAppDistributionError, "authenticated"):
                load_root_app_distribution(
                    root,
                    trusted_public_keys={"root-apps-2026": public_key},
                )

            catalog["entries"][0]["manifest"] = "../outside.json"  # type: ignore[index]
            (root / "catalog.json").write_text(json.dumps(catalog), encoding="utf-8")
            with self.assertRaisesRegex(RootAppDistributionError, "path"):
                load_root_app_distribution(
                    root,
                    trusted_public_keys={"root-apps-2026": public_key},
                )

    def test_catalog_cannot_supply_its_own_key_or_unapproved_hosts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-root-app-distribution-trust-") as directory:
            root = Path(directory)
            public_key, catalog = _write_distribution(root)

            # Refused whether or not a production key is compiled in: without
            # one the trust policy is empty, with one the signature is unknown.
            with self.assertRaises(RootAppDistributionError) as refused:
                load_root_app_distribution(root)
            self.assertIn(
                refused.exception.code,
                {"root_app_catalog_policy_invalid", "root_app_manifest_verification_failed"},
            )

            catalog["publicKeys"] = {"root-apps-2026": base64.b64encode(public_key).decode("ascii")}
            (root / "catalog.json").write_text(json.dumps(catalog), encoding="utf-8")
            with self.assertRaisesRegex(RootAppDistributionError, "fields"):
                load_root_app_distribution(
                    root,
                    trusted_public_keys={"root-apps-2026": public_key},
                )

            del catalog["publicKeys"]
            catalog["allowedHosts"] = ["github.com", "example.com"]
            (root / "catalog.json").write_text(json.dumps(catalog), encoding="utf-8")
            with self.assertRaisesRegex(RootAppDistributionError, "hosts"):
                load_root_app_distribution(
                    root,
                    trusted_public_keys={"root-apps-2026": public_key},
                )


if __name__ == "__main__":
    unittest.main()
