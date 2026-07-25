from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pixelflasher_core.artifact_downloads import canonical_manifest_bytes
from pixelflasher_core.firmware_distribution import (
    FirmwareDistributionError,
    load_firmware_distribution,
    load_optional_firmware_distribution,
)
from pixelflasher_core.keybox_distribution import (
    KeyboxDistributionError,
    load_keybox_revocations,
    load_optional_keybox_revocations,
)
from pixelflasher_core.scrcpy_distribution import (
    ScrcpyDistributionError,
    load_optional_scrcpy_distribution,
    load_scrcpy_distribution,
)
from pixelflasher_core.support_distribution import (
    load_optional_support_recipient,
    load_support_recipient,
)
from pixelflasher_core.update_distribution import (
    UpdateDistributionError,
    load_optional_update_distribution,
    load_update_distribution,
)
from scripts.verify_firmware_catalog import verify as verify_firmware_catalog
from scripts.verify_keybox_revocations import verify as verify_keybox_revocations
from scripts.verify_scrcpy_catalog import verify as verify_scrcpy_catalog
from scripts.verify_update_manifest import verify as verify_update_manifest

PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
PUBLIC_KEY = PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)


def _artifact_manifest(
    *,
    key_id: str,
    platform: str,
    architecture: str,
    url: str,
    version: str,
) -> bytes:
    payload: dict[str, object] = {
        "keyId": key_id,
        "version": version,
        "platform": platform,
        "arch": architecture,
        "license": "Apache-2.0",
        "provenance": "Audited upstream release",
        "url": url,
        "sha256": hashlib.sha256(url.encode("utf-8")).hexdigest(),
        "size": 1024,
        "expiresAt": (datetime.now(UTC) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    signature = PRIVATE_KEY.sign(canonical_manifest_bytes(payload))
    return json.dumps(
        {**payload, "signature": base64.b64encode(signature).decode("ascii")},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _write_firmware_distribution(root: Path) -> None:
    entries: list[dict[str, str]] = []
    for channel in ("stable", "beta", "canary"):
        for kind in ("factory", "ota"):
            name = f"akita-{channel}-{kind}.json"
            (root / name).write_bytes(
                _artifact_manifest(
                    key_id="firmware-2026",
                    platform="android",
                    architecture="akita",
                    url=f"https://dl.google.com/android/{name}.zip",
                    version=f"16.0.0-{channel}-{kind}",
                )
            )
            entries.append(
                {
                    "device": "akita",
                    "channel": channel,
                    "kind": kind,
                    "manifest": name,
                }
            )
    (root / "catalog.json").write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "allowedHosts": ["dl.google.com"],
                "entries": entries,
            }
        ),
        encoding="utf-8",
    )


def _write_scrcpy_distribution(root: Path) -> None:
    targets = (
        ("windows", "x86_64"),
        ("windows", "arm64"),
        ("darwin", "x86_64"),
        ("darwin", "arm64"),
        ("linux", "x86_64"),
    )
    entries: list[dict[str, str]] = []
    for platform, architecture in targets:
        name = f"scrcpy-{platform}-{architecture}.json"
        (root / name).write_bytes(
            _artifact_manifest(
                key_id="scrcpy-2026",
                platform=platform,
                architecture=architecture,
                url=(f"https://github.com/Genymobile/scrcpy/releases/download/v3.3/{name}.zip"),
                version="3.3",
            )
        )
        entries.append(
            {
                "platform": platform,
                "architecture": architecture,
                "manifest": name,
            }
        )
    (root / "catalog.json").write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "allowedHosts": ["github.com"],
                "manifests": entries,
            }
        ),
        encoding="utf-8",
    )


def _update_manifest() -> bytes:
    now = datetime.now(UTC).replace(microsecond=0)
    payload: dict[str, object] = {
        "schemaVersion": 1,
        "keyId": "updates-2026",
        "sequence": 1,
        "version": "10.0.0-rc.1",
        "channel": "rc",
        "releaseUrl": ("https://github.com/badabing2005/PixelFlasher/releases/tag/v10.0.0-rc.1"),
        "publishedAt": (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expiresAt": (now + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return json.dumps(
        {
            **payload,
            "signature": base64.b64encode(PRIVATE_KEY.sign(canonical)).decode("ascii"),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _keybox_revocations() -> bytes:
    now = datetime.now(UTC).replace(microsecond=0)
    document: dict[str, object] = {
        "schemaVersion": 1,
        "sourceId": "android-key-attestation-status",
        "keyId": "keybox-2026",
        "issuedAt": (now - timedelta(hours=1)).isoformat(),
        "expiresAt": (now + timedelta(days=7)).isoformat(),
        "entries": ["a001", "b002"],
    }
    canonical = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return json.dumps(
        {
            **document,
            "signature": base64.b64encode(PRIVATE_KEY.sign(canonical)).decode("ascii"),
        }
    ).encode("utf-8")


class ProductionDistributionTests(unittest.TestCase):
    def test_firmware_catalog_authenticates_every_channel_and_kind(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-firmware-catalog-") as directory:
            root = Path(directory)
            _write_firmware_distribution(root)

            distribution = load_firmware_distribution(
                root,
                trusted_public_keys={"firmware-2026": PUBLIC_KEY},
            )

            self.assertEqual(6, len(distribution.targets))
            self.assertEqual(
                2,
                len(
                    distribution.catalog.manifests_for(
                        device="akita",
                        channel="stable",
                    )
                ),
            )
            self.assertIn(
                "Verified 6 signed firmware targets",
                verify_firmware_catalog(
                    root,
                    trusted_public_keys={"firmware-2026": PUBLIC_KEY},
                ),
            )

    def test_firmware_catalog_absence_is_optional_but_tampering_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-firmware-catalog-bad-") as directory:
            parent = Path(directory)
            self.assertIsNone(load_optional_firmware_distribution(parent / "missing"))
            root = parent / "runtime"
            root.mkdir()
            _write_firmware_distribution(root)
            manifest = root / "akita-stable-factory.json"
            document = json.loads(manifest.read_text(encoding="utf-8"))
            document["version"] = "tampered"
            manifest.write_text(json.dumps(document), encoding="utf-8")

            with self.assertRaisesRegex(FirmwareDistributionError, "authenticated"):
                load_firmware_distribution(
                    root,
                    trusted_public_keys={"firmware-2026": PUBLIC_KEY},
                )

    def test_scrcpy_catalog_authenticates_the_release_matrix(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-scrcpy-catalog-") as directory:
            root = Path(directory)
            _write_scrcpy_distribution(root)

            distribution = load_scrcpy_distribution(
                root,
                trusted_public_keys={"scrcpy-2026": PUBLIC_KEY},
            )

            self.assertEqual(5, len(distribution.targets))
            self.assertIn(
                "Verified 5 signed Scrcpy targets",
                verify_scrcpy_catalog(
                    root,
                    trusted_public_keys={"scrcpy-2026": PUBLIC_KEY},
                ),
            )

    def test_scrcpy_catalog_absence_is_optional_but_paths_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-scrcpy-catalog-bad-") as directory:
            parent = Path(directory)
            self.assertIsNone(load_optional_scrcpy_distribution(parent / "missing"))
            root = parent / "runtime"
            root.mkdir()
            _write_scrcpy_distribution(root)
            catalog = json.loads((root / "catalog.json").read_text(encoding="utf-8"))
            catalog["manifests"][0]["manifest"] = "../outside.json"
            (root / "catalog.json").write_text(json.dumps(catalog), encoding="utf-8")

            with self.assertRaisesRegex(ScrcpyDistributionError, "path"):
                load_scrcpy_distribution(
                    root,
                    trusted_public_keys={"scrcpy-2026": PUBLIC_KEY},
                )

    def test_update_manifest_is_loaded_and_authenticated_separately(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-update-manifest-") as directory:
            path = Path(directory) / "manifest.json"
            path.write_bytes(_update_manifest())

            distribution = load_update_distribution(
                path,
                trusted_public_keys={"updates-2026": PUBLIC_KEY},
            )

            self.assertEqual(
                distribution.document,
                distribution.source.load(type("Cancellation", (), {"cancelled": False})()),
            )
            self.assertIn(
                "Verified signed rc update 10.0.0-rc.1",
                verify_update_manifest(
                    path,
                    trusted_public_keys={"updates-2026": PUBLIC_KEY},
                ),
            )

    def test_update_manifest_absence_is_optional_but_tampering_fails_verification(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-update-manifest-bad-") as directory:
            root = Path(directory)
            path = root / "manifest.json"
            self.assertIsNone(load_optional_update_distribution(path))
            document = json.loads(_update_manifest())
            document["sequence"] = 2
            path.write_text(json.dumps(document), encoding="utf-8")

            with self.assertRaises(UpdateDistributionError):
                verify_update_manifest(
                    path,
                    trusted_public_keys={"updates-2026": PUBLIC_KEY},
                )

    def test_support_recipient_is_rsa_and_has_a_stable_derived_key_id(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-support-recipient-") as directory:
            root = Path(directory)
            path = root / "recipient-public-key.pem"
            self.assertIsNone(load_optional_support_recipient(root / "missing.pem"))
            public_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            ).public_key()
            path.write_bytes(
                public_key.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

            first = load_support_recipient(path)
            second = load_support_recipient(path)

            self.assertEqual(first.key_id, second.key_id)
            self.assertRegex(first.key_id, r"^support-rsa-[0-9a-f]{16}$")

    def test_keybox_revocations_are_authenticated_before_rc_acceptance(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-keybox-revocations-") as directory:
            root = Path(directory)
            path = root / "revocations.json"
            self.assertIsNone(load_optional_keybox_revocations(root / "missing.json"))
            path.write_bytes(_keybox_revocations())

            distribution = load_keybox_revocations(
                path,
                trusted_public_keys={"keybox-2026": PUBLIC_KEY},
            )

            self.assertEqual(
                frozenset({"a001", "b002"}),
                distribution.provider.load(now=datetime.now(UTC)).revoked_serials,
            )
            self.assertIn(
                "Verified 2 keybox revocation serial(s)",
                verify_keybox_revocations(
                    path,
                    trusted_public_keys={"keybox-2026": PUBLIC_KEY},
                ),
            )
            path.write_bytes(path.read_bytes().replace(b"a001", b"a003"))
            with self.assertRaises(KeyboxDistributionError):
                verify_keybox_revocations(
                    path,
                    trusted_public_keys={"keybox-2026": PUBLIC_KEY},
                )


if __name__ == "__main__":
    unittest.main()
