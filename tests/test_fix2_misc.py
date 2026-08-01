from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import scripts.build_scrcpy_catalog as builder
from pixelflasher_core.scrcpy_distribution import _APPROVED_HOSTS, load_scrcpy_distribution

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
PACKAGED_CATALOG = REPOSITORY_ROOT / "resources" / "scrcpy" / "runtime" / "catalog.json"
KEY_ID = "scrcpy-release-test"
TARGETS = (
    ("windows", ("x86_64", "arm64")),
    ("darwin", ("x86_64",)),
    ("darwin", ("arm64",)),
    ("linux", ("x86_64",)),
)


def _inputs(root: Path) -> tuple[Path, Path, Path, Path, dict[str, bytes]]:
    archives = root / "archives"
    output = root / "output"
    archives.mkdir()
    entries: list[dict[str, object]] = []
    for index, (platform_name, hosts) in enumerate(TARGETS):
        asset = f"scrcpy-{platform_name}-{index}.zip"
        content = f"scrcpy {platform_name} {index}".encode("ascii")
        (archives / asset).write_bytes(content)
        entries.append(
            {
                "platform": platform_name,
                "hostArchitectures": list(hosts),
                "asset": asset,
                "url": f"https://github.com/Genymobile/scrcpy/releases/download/v4.1/{asset}",
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    source_lock = root / "source-lock.json"
    source_lock.write_text(
        json.dumps(
            {
                "version": "4.1",
                "license": "Apache-2.0",
                "provenance": "Official Genymobile/scrcpy GitHub release",
                "archives": entries,
            }
        ),
        encoding="utf-8",
    )
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    private_path = root / "private.pem"
    private_path.write_bytes(
        private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return source_lock, private_path, archives, output, {KEY_ID: public}


class ScrcpyCatalogBuilderHostTests(unittest.TestCase):
    def test_generated_catalog_keeps_every_approved_redirect_host(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-build-scrcpy-catalog-") as directory:
            root = Path(directory)
            source_lock, private_path, archives, output, trusted = _inputs(root)

            with mock.patch.object(builder, "SCRCPY_ED25519_PUBLIC_KEYS", trusted):
                count = builder.build_catalog(
                    source_lock=source_lock,
                    private_key=private_path,
                    key_id=KEY_ID,
                    archives=archives,
                    output=output,
                    expires_at=(datetime.now(UTC) + timedelta(days=30)).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                )

            self.assertEqual(5, count)
            generated = json.loads((output / "catalog.json").read_text(encoding="utf-8"))
            packaged = json.loads(PACKAGED_CATALOG.read_text(encoding="utf-8"))
            self.assertEqual(set(_APPROVED_HOSTS), set(generated["allowedHosts"]))
            self.assertEqual(packaged["allowedHosts"], generated["allowedHosts"])
            # The loader re-validates the host list, so a drifting builder would
            # either be rejected here or silently narrow the download policy.
            distribution = load_scrcpy_distribution(output, trusted_public_keys=trusted)
            self.assertEqual(
                {(platform, host) for platform, hosts in TARGETS for host in hosts},
                set(distribution.targets),
            )


if __name__ == "__main__":
    unittest.main()
