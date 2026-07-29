#!/usr/bin/env python3
"""Sign the packaged Scrcpy catalog from locally staged official archives.

Like the Platform Tools and root-app builders this never reaches the network:
it verifies the staged archives against the source lock and signs a manifest per
release target. scrcpy publishes no Windows ARM64 build, so that target pins the
official win64 archive, which is the same call the Platform Tools lock makes for
Windows ARM64 hosts.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from pixelflasher_core.artifact_downloads import canonical_manifest_bytes  # noqa: E402
from pixelflasher_core.artifact_trust import SCRCPY_ED25519_PUBLIC_KEYS  # noqa: E402

REQUIRED_TARGETS = (
    ("windows", "x86_64"),
    ("windows", "arm64"),
    ("darwin", "x86_64"),
    ("darwin", "arm64"),
    ("linux", "x86_64"),
)
ALLOWED_HOSTS = ("github.com",)
KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
EXPIRES_AT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class CatalogBuildError(RuntimeError):
    """The catalog cannot be produced from the supplied inputs."""


def _private_key(path: Path) -> Ed25519PrivateKey:
    loaded = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise CatalogBuildError("the signing key must be an Ed25519 private key")
    return loaded


def _require_pinned_public_key(key_id: str, private: Ed25519PrivateKey) -> None:
    """A catalog may only be signed by a key the binary already trusts."""

    pinned = SCRCPY_ED25519_PUBLIC_KEYS.get(key_id)
    if pinned is None:
        raise CatalogBuildError(f"signing key ID is not pinned in artifact_trust: {key_id}")
    raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if raw != pinned:
        raise CatalogBuildError(f"the private key does not match the pinned public key for {key_id}")


def _verified_archive(archives: Path, entry: Mapping[str, object]) -> Path:
    asset = str(entry["asset"])
    path = (archives / asset).resolve()
    if not path.is_file() or path.parent != archives.resolve():
        raise CatalogBuildError(f"staged archive is missing or escapes the directory: {asset}")
    size = path.stat().st_size
    if size != entry["size"]:
        raise CatalogBuildError(f"{asset} is {size} bytes, the lock pins {entry['size']}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != entry["sha256"]:
        raise CatalogBuildError(f"{asset} does not match the pinned SHA-256")
    return path


def build_catalog(
    *,
    source_lock: Path,
    private_key: Path,
    key_id: str,
    archives: Path,
    output: Path,
    expires_at: str,
) -> int:
    if KEY_ID.fullmatch(key_id) is None:
        raise CatalogBuildError(f"invalid key id: {key_id!r}")
    if EXPIRES_AT.fullmatch(expires_at) is None:
        raise CatalogBuildError("expires-at must use the YYYY-MM-DDTHH:MM:SSZ form")
    if datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC) <= datetime.now(UTC):
        raise CatalogBuildError("expires-at must be in the future")

    private = _private_key(private_key)
    _require_pinned_public_key(key_id, private)

    lock = json.loads(source_lock.read_text(encoding="utf-8"))
    version = str(lock["version"])
    license_name = str(lock["license"])
    provenance = str(lock["provenance"])

    by_target: dict[tuple[str, str], Mapping[str, object]] = {}
    for entry in lock["archives"]:
        _verified_archive(archives, entry)
        for host in entry["hostArchitectures"]:
            by_target[(str(entry["platform"]), str(host))] = entry
    missing = [target for target in REQUIRED_TARGETS if target not in by_target]
    if missing:
        raise CatalogBuildError(f"the source lock does not cover every release target: {missing}")

    output.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, str]] = []
    for platform_name, architecture in REQUIRED_TARGETS:
        archive = by_target[(platform_name, architecture)]
        payload: dict[str, object] = {
            "keyId": key_id,
            "version": version,
            "platform": platform_name,
            "arch": architecture,
            "license": license_name,
            "provenance": provenance,
            "url": str(archive["url"]),
            "sha256": str(archive["sha256"]),
            "size": int(archive["size"]),
            "expiresAt": expires_at,
        }
        signature = private.sign(canonical_manifest_bytes(payload))
        name = f"scrcpy-{platform_name}-{architecture}.json"
        document = json.dumps(
            {**payload, "signature": base64.b64encode(signature).decode("ascii")},
            sort_keys=True,
            separators=(",", ":"),
        )
        (output / name).write_text(document + "\n", encoding="utf-8", newline="\n")
        entries.append(
            {"platform": platform_name, "architecture": architecture, "manifest": name}
        )

    catalog = {
        "schemaVersion": 1,
        "allowedHosts": list(ALLOWED_HOSTS),
        "manifests": entries,
    }
    (output / "catalog.json").write_text(
        json.dumps(catalog, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return len(entries)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-lock", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expires-at", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        count = build_catalog(
            source_lock=args.source_lock,
            private_key=args.private_key,
            key_id=args.key_id,
            archives=args.archives,
            output=args.output,
            expires_at=args.expires_at,
        )
    except (CatalogBuildError, OSError, ValueError, KeyError) as error:
        print(f"error: {error}")
        return 1
    print(f"Generated {count} signed Scrcpy manifests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
