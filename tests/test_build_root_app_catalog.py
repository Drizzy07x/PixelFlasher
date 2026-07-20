from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pixelflasher_core.apk_inspection import ApkIdentity
from pixelflasher_core.root_app_distribution import load_root_app_distribution
from scripts.build_root_app_catalog import (
    RootAppCatalogBuildError,
    build_catalog,
)
from scripts.verify_root_app_catalog import verify

PROVIDERS = (
    "magisk",
    "apatch",
    "kernelsu",
    "kernelsu-next",
    "sukisu",
    "wild-ksu",
    "legacy",
)
ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
ARCHITECTURES = {
    "magisk": ("universal",),
    "apatch": ("universal",),
    "kernelsu": ("arm64", "x86_64"),
    "kernelsu-next": ("arm64", "x86_64"),
    "sukisu": ("arm64", "arm", "x86_64"),
    "wild-ksu": ("arm64", "x86_64"),
    "legacy": ("arm64", "arm"),
}
ABI_FOR_ARCHITECTURE = {
    "arm64": "arm64-v8a",
    "arm": "armeabi-v7a",
    "x86_64": "x86_64",
    "x86": "x86",
}


def _inputs(
    root: Path,
) -> tuple[Path, Path, Path, dict[str, bytes], dict[Path, ApkIdentity]]:
    apks = root / "apks"
    output = root / "output"
    apks.mkdir()
    output.mkdir()
    identities: dict[Path, ApkIdentity] = {}
    apps: list[dict[str, object]] = []
    for index, provider in enumerate(PROVIDERS):
        asset = f"{provider}.apk"
        path = apks / asset
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"manifest")
            architectures = ARCHITECTURES[provider]
            native_abis = (
                ABIS
                if architectures == ("universal",)
                else tuple(ABI_FOR_ARCHITECTURE[value] for value in architectures)
            )
            for abi in native_abis:
                archive.writestr(f"lib/{abi}/libpatch.so", abi.encode("ascii"))
        content = path.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        package_name = f"org.example.rootapp{index}"
        signer = f"{index + 1:064x}"
        identities[path.resolve()] = ApkIdentity(
            package_name=package_name,
            sha256=digest,
            signer_sha256=(signer,),
            schemes=("v2",),
            verified=True,
        )
        apps.append(
            {
                "provider": provider,
                "repository": f"official{index}/rootapp{index}",
                "tag": "v1.0.0",
                "publishedAt": "2026-01-01T00:00:00Z",
                "asset": asset,
                "version": "1.0.0",
                "url": (f"https://github.com/official{index}/rootapp{index}/releases/download/v1.0.0/{asset}"),
                "size": len(content),
                "sha256": digest,
                "packageName": package_name,
                "signerSha256": [signer],
                "schemes": ["v2"],
                "architectures": list(architectures),
            }
        )
    source = {
        "schemaVersion": 1,
        "channel": "stable",
        "license": "GPL-3.0",
        "provenance": "Official GitHub release",
        "apps": apps,
    }
    source_path = root / "source-lock.json"
    source_path.write_text(json.dumps(source), encoding="utf-8")
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    private_path = root / "private.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return (
        source_path,
        private_path,
        output,
        {"root-app-release": public_key},
        identities,
    )


class BuildRootAppCatalogTests(unittest.TestCase):
    def test_inspected_apks_generate_complete_authenticated_catalog(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-build-root-app-catalog-") as directory:
            root = Path(directory)
            source, private, output, trusted_keys, identities = _inputs(root)

            catalog = build_catalog(
                source_lock_path=source,
                private_key_path=private,
                key_id="root-app-release",
                apks_directory=root / "apks",
                output_directory=output,
                expires_at=(datetime.now(UTC) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                trusted_public_keys=trusted_keys,
                apk_inspector=lambda path: identities[path.resolve()],
            )
            distribution = load_root_app_distribution(
                output,
                trusted_public_keys=trusted_keys,
            )

            self.assertEqual(13, len(catalog["entries"]))
            self.assertEqual(
                {
                    (provider, "stable", architecture)
                    for provider, architectures in ARCHITECTURES.items()
                    for architecture in architectures
                },
                set(distribution.targets),
            )
            self.assertEqual(13, len(distribution.catalog.manifests_for(channel="stable")))
            self.assertEqual(
                "Verified 13 signed root-app targets with 1 pinned key(s).",
                verify(output, trusted_public_keys=trusted_keys),
            )
            self.assertFalse(any(output.glob(".*.tmp")))

    def test_unpinned_key_and_changed_apk_fail_before_catalog_publication(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-build-root-app-catalog-bad-") as directory:
            root = Path(directory)
            source, private, output, trusted_keys, identities = _inputs(root)
            expires = (datetime.now(UTC) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")

            with self.assertRaisesRegex(RootAppCatalogBuildError, "does not match"):
                build_catalog(
                    source_lock_path=source,
                    private_key_path=private,
                    key_id="root-app-release",
                    apks_directory=root / "apks",
                    output_directory=output,
                    expires_at=expires,
                    trusted_public_keys={"root-app-release": b"x" * 32},
                    apk_inspector=lambda path: identities[path.resolve()],
                )
            self.assertFalse((output / "catalog.json").exists())

            changed = root / "apks" / "magisk.apk"
            changed.write_bytes(changed.read_bytes() + b"tampered")
            with self.assertRaisesRegex(RootAppCatalogBuildError, "size"):
                build_catalog(
                    source_lock_path=source,
                    private_key_path=private,
                    key_id="root-app-release",
                    apks_directory=root / "apks",
                    output_directory=output,
                    expires_at=expires,
                    trusted_public_keys=trusted_keys,
                    apk_inspector=lambda path: identities[path.resolve()],
                )
            self.assertFalse((output / "catalog.json").exists())


if __name__ == "__main__":
    unittest.main()
