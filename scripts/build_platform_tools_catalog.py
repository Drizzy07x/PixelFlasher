#!/usr/bin/env python3
"""Verify official Platform Tools archives and sign the packaged catalog."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import zipfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import cast
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pixelflasher_core.artifact_downloads import canonical_manifest_bytes  # noqa: E402
from pixelflasher_core.artifact_trust import (  # noqa: E402
    PLATFORM_TOOLS_ED25519_PUBLIC_KEYS,
)
from pixelflasher_core.platform_tools import (  # noqa: E402
    architecture_key,
    binary_architectures,
    platform_key,
    platform_tools_binary_names,
)

_HEX_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class CatalogBuildError(RuntimeError):
    pass


def build_catalog(
    *,
    source_lock_path: Path,
    private_key_path: Path,
    key_id: str,
    archives_directory: Path,
    output_directory: Path,
    expires_at: str,
    trusted_public_keys: Mapping[str, bytes] | None = None,
) -> dict[str, object]:
    if not _KEY_ID.fullmatch(key_id):
        raise CatalogBuildError("key ID is invalid")
    expiration = _parse_expiration(expires_at)
    source = _source_lock(source_lock_path)
    public_keys = (
        PLATFORM_TOOLS_ED25519_PUBLIC_KEYS
        if trusted_public_keys is None
        else trusted_public_keys
    )
    private_key = _private_key(private_key_path)
    _require_pinned_public_key(private_key, key_id=key_id, public_keys=public_keys)

    version = _required_string(source, "version")
    license_value = _required_string(source, "license")
    provenance = _required_string(source, "provenance")
    raw_archives = source["archives"]
    assert isinstance(raw_archives, list)
    targets: list[tuple[str, str, dict[str, object]]] = []
    for raw_archive in cast(list[object], raw_archives):
        if not isinstance(raw_archive, dict):
            raise CatalogBuildError("source archive entry must be an object")
        archive = cast(dict[str, object], raw_archive)
        if set(archive) != {
            "platform",
            "hostArchitectures",
            "binaryArchitectures",
            "url",
            "size",
            "sha1",
            "sha256",
        }:
            raise CatalogBuildError("source archive fields are invalid")
        platform = platform_key(_required_string(archive, "platform"))
        host_architectures = _string_list(archive.get("hostArchitectures"), "hostArchitectures")
        expected_binary_architectures = frozenset(
            architecture_key(value)
            for value in _string_list(archive.get("binaryArchitectures"), "binaryArchitectures")
        )
        url = _required_string(archive, "url")
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "dl.google.com"
            or parsed.query
            or parsed.fragment
        ):
            raise CatalogBuildError("source archive URL is not an approved Google URL")
        filename = PurePosixPath(parsed.path).name
        if not filename or filename != Path(filename).name:
            raise CatalogBuildError("source archive URL has an invalid filename")
        archive_path = archives_directory / filename
        _verify_archive_file(archive_path, archive)
        _verify_archive_content(
            archive_path,
            platform=platform,
            version=version,
            expected_binary_architectures=expected_binary_architectures,
        )
        for raw_architecture in host_architectures:
            architecture = architecture_key(raw_architecture)
            targets.append((platform, architecture, archive))

    expected_targets = {
        ("windows", "x86_64"),
        ("windows", "arm64"),
        ("darwin", "x86_64"),
        ("darwin", "arm64"),
        ("linux", "x86_64"),
    }
    observed_targets = {(platform, architecture) for platform, architecture, _ in targets}
    if observed_targets != expected_targets or len(targets) != len(expected_targets):
        raise CatalogBuildError("source lock does not cover the complete release matrix")

    manifest_entries: list[dict[str, str]] = []
    output_directory.mkdir(parents=True, exist_ok=True)
    for platform, architecture, archive in sorted(targets):
        payload: dict[str, object] = {
            "keyId": key_id,
            "version": version,
            "platform": platform,
            "arch": architecture,
            "license": license_value,
            "provenance": provenance,
            "url": _required_string(archive, "url"),
            "sha256": _required_string(archive, "sha256"),
            "size": _required_integer(archive, "size"),
            "expiresAt": expiration.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        signature = private_key.sign(canonical_manifest_bytes(payload))
        manifest = {
            **payload,
            "signature": base64.b64encode(signature).decode("ascii"),
        }
        name = f"{platform}-{architecture}.json"
        _write_json_atomic(output_directory / name, manifest)
        manifest_entries.append(
            {
                "platform": platform,
                "architecture": architecture,
                "manifest": name,
            }
        )

    catalog: dict[str, object] = {
        "schemaVersion": 1,
        "allowedHosts": ["dl.google.com"],
        "manifests": manifest_entries,
    }
    _write_json_atomic(output_directory / "catalog.json", catalog)
    return catalog


def _source_lock(path: Path) -> dict[str, object]:
    values = _json_object(path)
    if set(values) != {
        "schemaVersion",
        "sourceMetadataUrl",
        "releaseChannel",
        "version",
        "license",
        "provenance",
        "archives",
    }:
        raise CatalogBuildError("source lock fields are invalid")
    if values.get("schemaVersion") != 1 or values.get("releaseChannel") != "stable":
        raise CatalogBuildError("source lock schema or channel is invalid")
    if values.get("sourceMetadataUrl") != "https://dl.google.com/android/repository/repository2-1.xml":
        raise CatalogBuildError("source metadata URL is invalid")
    version = _required_string(values, "version")
    if not _VERSION.fullmatch(version):
        raise CatalogBuildError("source version is invalid")
    raw_archives = values.get("archives")
    archives = cast(list[object], raw_archives) if isinstance(raw_archives, list) else []
    if not archives or len(archives) > 8:
        raise CatalogBuildError("source archives are invalid")
    return values


def _private_key(path: Path) -> Ed25519PrivateKey:
    try:
        loaded = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, TypeError, ValueError) as exc:
        raise CatalogBuildError("private signing key is unavailable or invalid") from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise CatalogBuildError("private signing key must use Ed25519")
    return loaded


def _require_pinned_public_key(
    private_key: Ed25519PrivateKey,
    *,
    key_id: str,
    public_keys: Mapping[str, bytes],
) -> None:
    pinned = public_keys.get(key_id)
    if pinned is None:
        raise CatalogBuildError("signing key ID is not pinned")
    derived = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if pinned != derived:
        raise CatalogBuildError("private signing key does not match the pinned public key")


def _verify_archive_file(path: Path, values: Mapping[str, object]) -> None:
    try:
        target = path.resolve(strict=True)
    except OSError as exc:
        raise CatalogBuildError(f"official archive is missing: {path.name}") from exc
    if path.is_symlink() or path.is_junction() or not target.is_file():
        raise CatalogBuildError("official archive path is invalid")
    expected_size = _required_integer(values, "size")
    expected_sha1 = _required_string(values, "sha1")
    expected_sha256 = _required_string(values, "sha256")
    if not _HEX_SHA1.fullmatch(expected_sha1) or not _HEX_SHA256.fullmatch(expected_sha256):
        raise CatalogBuildError("official archive hashes are invalid")
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    observed_size = 0
    with target.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            observed_size += len(block)
            sha1.update(block)
            sha256.update(block)
    if (
        observed_size != expected_size
        or sha1.hexdigest() != expected_sha1
        or sha256.hexdigest() != expected_sha256
    ):
        raise CatalogBuildError("official archive does not match its locked hashes")


def _verify_archive_content(
    path: Path,
    *,
    platform: str,
    version: str,
    expected_binary_architectures: frozenset[str],
) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)) or len(names) > 512:
                raise CatalogBuildError("official archive entries are invalid")
            source_name = "platform-tools/source.properties"
            if source_name not in names:
                raise CatalogBuildError("official archive has no source.properties")
            properties = archive.read(source_name).decode("utf-8", "strict")
            if f"Pkg.Revision={version}" not in properties.splitlines():
                raise CatalogBuildError("official archive version does not match the source lock")
            with tempfile.TemporaryDirectory(prefix="pf-platform-tools-sign-") as directory:
                temporary = Path(directory)
                for binary_name in platform_tools_binary_names(platform):
                    member = f"platform-tools/{binary_name}"
                    if member not in names:
                        raise CatalogBuildError("official archive is missing adb or fastboot")
                    target = temporary / binary_name
                    target.write_bytes(archive.read(member))
                    observed = binary_architectures(target, platform=platform)
                    if observed != expected_binary_architectures:
                        raise CatalogBuildError("official binary architecture does not match the source lock")
    except (OSError, UnicodeError, zipfile.BadZipFile) as exc:
        raise CatalogBuildError("official archive content is invalid") from exc


def _json_object(path: Path) -> dict[str, object]:
    try:
        decoded = cast(
            object,
            json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CatalogBuildError(f"JSON input is invalid: {path.name}") from exc
    if not isinstance(decoded, dict):
        raise CatalogBuildError(f"JSON input must be an object: {path.name}")
    return cast(dict[str, object], decoded)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    values: dict[str, object] = {}
    for key, value in pairs:
        if key in values:
            raise CatalogBuildError("JSON input contains a duplicate field")
        values[key] = value
    return values


def _parse_expiration(value: str) -> datetime:
    if not _TIMESTAMP.fullmatch(value):
        raise CatalogBuildError("expiration must be an exact UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise CatalogBuildError("expiration is invalid") from exc
    if parsed <= datetime.now(UTC):
        raise CatalogBuildError("expiration must be in the future")
    return parsed


def _required_string(values: Mapping[str, object], key: str) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value:
        raise CatalogBuildError(f"{key} must be a non-empty string")
    return value


def _required_integer(values: Mapping[str, object], key: str) -> int:
    value = values.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise CatalogBuildError(f"{key} must be a positive integer")
    return value


def _string_list(raw: object, name: str) -> tuple[str, ...]:
    if not isinstance(raw, list):
        raise CatalogBuildError(f"{name} must be a list")
    values = cast(list[object], raw)
    if not values or len(values) > 4:
        raise CatalogBuildError(f"{name} is invalid")
    parsed: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value or value in parsed:
            raise CatalogBuildError(f"{name} is invalid")
        parsed.append(value)
    return tuple(parsed)


def _write_json_atomic(path: Path, values: Mapping[str, object]) -> None:
    payload = (json.dumps(dict(values), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            parent_descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


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
        catalog = build_catalog(
            source_lock_path=args.source_lock,
            private_key_path=args.private_key,
            key_id=args.key_id,
            archives_directory=args.archives,
            output_directory=args.output,
            expires_at=args.expires_at,
        )
    except CatalogBuildError as exc:
        print(f"Platform Tools catalog build failed: {exc}", file=sys.stderr)
        return 1
    print(f"Generated {len(cast(list[object], catalog['manifests']))} signed Platform Tools manifests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
