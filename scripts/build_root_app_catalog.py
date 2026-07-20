#!/usr/bin/env python3
"""Inspect pinned official APKs and sign the packaged root-app catalog."""

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
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import cast
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pixelflasher_core.apk_inspection import ApkIdentity, inspect_apk  # noqa: E402
from pixelflasher_core.artifact_downloads import canonical_manifest_bytes  # noqa: E402
from pixelflasher_core.artifact_trust import ROOT_APP_ED25519_PUBLIC_KEYS  # noqa: E402

_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_PROVIDERS = frozenset({"magisk", "apatch", "kernelsu", "kernelsu-next", "sukisu", "wild-ksu", "legacy"})
_ARCHITECTURES = frozenset({"universal", "arm64", "arm", "x86_64", "x86"})
_ABI_FOR_ARCHITECTURE = {
    "arm64": "arm64-v8a",
    "arm": "armeabi-v7a",
    "x86_64": "x86_64",
    "x86": "x86",
}
_ALL_ABIS = frozenset(_ABI_FOR_ARCHITECTURE.values())
_FLAVOR_FOR_PROVIDER = {
    "magisk": "magisk",
    "apatch": "apatch",
    "kernelsu": "kernelsu",
    "kernelsu-next": "kernelsu-next",
    "sukisu": "sukisu",
    "wild-ksu": "wild-ksu",
    "legacy": "legacy",
}


class RootAppCatalogBuildError(RuntimeError):
    pass


def build_catalog(
    *,
    source_lock_path: Path,
    private_key_path: Path,
    key_id: str,
    apks_directory: Path,
    output_directory: Path,
    expires_at: str,
    trusted_public_keys: Mapping[str, bytes] | None = None,
    apk_inspector: Callable[[Path], ApkIdentity] = inspect_apk,
) -> dict[str, object]:
    if _KEY_ID.fullmatch(key_id) is None:
        raise RootAppCatalogBuildError("key ID is invalid")
    expiration = _parse_expiration(expires_at)
    source = _source_lock(source_lock_path)
    private_key = _private_key(private_key_path)
    public_keys = ROOT_APP_ED25519_PUBLIC_KEYS if trusted_public_keys is None else trusted_public_keys
    _require_pinned_public_key(private_key, key_id=key_id, public_keys=public_keys)

    license_value = _required_string(source, "license")
    provenance_root = _required_string(source, "provenance")
    raw_apps = cast(list[object], source["apps"])
    verified: list[tuple[dict[str, object], str]] = []
    seen_providers: set[str] = set()
    for raw_app in raw_apps:
        app = _source_app(raw_app)
        provider = _required_string(app, "provider")
        if provider not in _PROVIDERS or provider in seen_providers:
            raise RootAppCatalogBuildError("source app providers are invalid")
        seen_providers.add(provider)
        asset = _required_string(app, "asset")
        if PurePosixPath(asset).name != asset or not asset.casefold().endswith(".apk"):
            raise RootAppCatalogBuildError("source APK filename is invalid")
        apk_path = _real_apk(apks_directory, asset)
        _verify_file(apk_path, app)
        identity = apk_inspector(apk_path)
        _verify_identity(identity, app)
        _verify_architectures(apk_path, app)
        verified.append((app, provider))
    if seen_providers != _PROVIDERS:
        raise RootAppCatalogBuildError("source lock does not cover all root-app providers")

    entries: list[dict[str, object]] = []
    output_directory.mkdir(parents=True, exist_ok=True)
    for app, provider in sorted(verified, key=lambda item: item[1]):
        for architecture in _string_list(app.get("architectures"), "architectures"):
            payload: dict[str, object] = {
                "keyId": key_id,
                "version": _required_string(app, "version"),
                "platform": "android",
                "arch": architecture,
                "license": license_value,
                "provenance": (
                    f"{provenance_root} {_required_string(app, 'repository')} {_required_string(app, 'tag')}"
                ),
                "url": _required_string(app, "url"),
                "sha256": _required_string(app, "sha256"),
                "size": _required_integer(app, "size"),
                "expiresAt": expiration.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            signature = private_key.sign(canonical_manifest_bytes(payload))
            manifest = {**payload, "signature": base64.b64encode(signature).decode("ascii")}
            name = f"{provider}-stable-{architecture}.json"
            _write_json_atomic(output_directory / name, manifest)
            entries.append(
                {
                    "provider": provider,
                    "channel": "stable",
                    "flavor": _FLAVOR_FOR_PROVIDER[provider],
                    "packageName": _required_string(app, "packageName"),
                    "signerSha256": _string_list(app.get("signerSha256"), "signerSha256"),
                    "architecture": architecture,
                    "manifest": name,
                }
            )

    catalog: dict[str, object] = {
        "schemaVersion": 1,
        "allowedHosts": ["github.com", "release-assets.githubusercontent.com"],
        "entries": entries,
    }
    _write_json_atomic(output_directory / "catalog.json", catalog)
    return catalog


def _source_lock(path: Path) -> dict[str, object]:
    values = _json_object(path)
    if set(values) != {"schemaVersion", "channel", "license", "provenance", "apps"}:
        raise RootAppCatalogBuildError("source lock fields are invalid")
    if values.get("schemaVersion") != 1 or values.get("channel") != "stable":
        raise RootAppCatalogBuildError("source lock schema or channel is invalid")
    raw_apps = values.get("apps")
    apps = cast(list[object], raw_apps) if isinstance(raw_apps, list) else []
    if len(apps) != len(_PROVIDERS):
        raise RootAppCatalogBuildError("source apps are invalid")
    return values


def _source_app(raw: object) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise RootAppCatalogBuildError("source app entry must be an object")
    app = cast(dict[str, object], raw)
    if set(app) != {
        "provider",
        "repository",
        "tag",
        "publishedAt",
        "asset",
        "version",
        "url",
        "size",
        "sha256",
        "packageName",
        "signerSha256",
        "schemes",
        "architectures",
    }:
        raise RootAppCatalogBuildError("source app fields are invalid")
    repository = _required_string(app, "repository")
    if _REPOSITORY.fullmatch(repository) is None:
        raise RootAppCatalogBuildError("source repository is invalid")
    published_at = _required_string(app, "publishedAt")
    if _TIMESTAMP.fullmatch(published_at) is None:
        raise RootAppCatalogBuildError("source publication timestamp is invalid")
    try:
        datetime.strptime(published_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise RootAppCatalogBuildError("source publication timestamp is invalid") from exc
    url = _required_string(app, "url")
    parsed = urlsplit(url)
    expected_path = f"/{repository}/releases/download/{_required_string(app, 'tag')}/{_required_string(app, 'asset')}"
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.path != expected_path
        or parsed.query
        or parsed.fragment
    ):
        raise RootAppCatalogBuildError("source APK URL is not an approved GitHub release URL")
    digest = _required_string(app, "sha256")
    if _SHA256.fullmatch(digest) is None:
        raise RootAppCatalogBuildError("source APK hash is invalid")
    architectures = _string_list(app.get("architectures"), "architectures")
    if not architectures or any(value not in _ARCHITECTURES for value in architectures):
        raise RootAppCatalogBuildError("source APK architectures are invalid")
    if "universal" in architectures and architectures != ["universal"]:
        raise RootAppCatalogBuildError("universal architecture cannot be mixed")
    signers = _string_list(app.get("signerSha256"), "signerSha256")
    if not signers or any(_SHA256.fullmatch(value) is None for value in signers):
        raise RootAppCatalogBuildError("source APK signers are invalid")
    schemes = _string_list(app.get("schemes"), "schemes")
    if not schemes or any(value not in {"v1", "v2", "v3"} for value in schemes):
        raise RootAppCatalogBuildError("source APK signature schemes are invalid")
    return app


def _real_apk(directory: Path, filename: str) -> Path:
    try:
        root = directory.resolve(strict=True)
        target = (root / filename).resolve(strict=True)
    except OSError as exc:
        raise RootAppCatalogBuildError(f"official APK is missing: {filename}") from exc
    candidate = root / filename
    if (
        directory.is_symlink()
        or directory.is_junction()
        or candidate.is_symlink()
        or candidate.is_junction()
        or not root.is_dir()
        or target.parent != root
        or not target.is_file()
    ):
        raise RootAppCatalogBuildError("official APK path is invalid")
    return target


def _verify_file(path: Path, app: Mapping[str, object]) -> None:
    expected_size = _required_integer(app, "size")
    digest = hashlib.sha256()
    observed_size = 0
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                observed_size += len(chunk)
                if observed_size > expected_size:
                    raise RootAppCatalogBuildError("official APK size changed")
                digest.update(chunk)
    except OSError as exc:
        raise RootAppCatalogBuildError("official APK is unreadable") from exc
    if observed_size != expected_size or digest.hexdigest() != _required_string(app, "sha256"):
        raise RootAppCatalogBuildError("official APK size or SHA-256 changed")


def _verify_identity(identity: ApkIdentity, app: Mapping[str, object]) -> None:
    if not identity.verified:
        raise RootAppCatalogBuildError("APK identity is not verified")
    if identity.package_name != _required_string(app, "packageName"):
        raise RootAppCatalogBuildError("APK package identity changed")
    if identity.sha256 != _required_string(app, "sha256"):
        raise RootAppCatalogBuildError("APK inspector hash changed")
    if list(identity.signer_sha256) != _string_list(app.get("signerSha256"), "signerSha256"):
        raise RootAppCatalogBuildError("APK signer identity changed")
    if list(identity.schemes) != _string_list(app.get("schemes"), "schemes"):
        raise RootAppCatalogBuildError("APK signature schemes changed")


def _verify_architectures(path: Path, app: Mapping[str, object]) -> None:
    found: set[str] = set()
    try:
        with zipfile.ZipFile(path, "r", allowZip64=False) as archive:
            for info in archive.infolist():
                parts = info.filename.split("/")
                if len(parts) >= 3 and parts[0] == "lib" and parts[1] in _ALL_ABIS:
                    found.add(parts[1])
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise RootAppCatalogBuildError("APK native libraries are unreadable") from exc
    expected_architectures = _string_list(app.get("architectures"), "architectures")
    expected = (
        _ALL_ABIS
        if expected_architectures == ["universal"]
        else frozenset(_ABI_FOR_ARCHITECTURE[value] for value in expected_architectures)
    )
    if found != expected:
        raise RootAppCatalogBuildError("APK native architectures changed")


def _private_key(path: Path) -> Ed25519PrivateKey:
    try:
        loaded = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, TypeError, ValueError) as exc:
        raise RootAppCatalogBuildError("private signing key is unavailable or invalid") from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise RootAppCatalogBuildError("private signing key must use Ed25519")
    return loaded


def _require_pinned_public_key(
    private_key: Ed25519PrivateKey,
    *,
    key_id: str,
    public_keys: Mapping[str, bytes],
) -> None:
    pinned = public_keys.get(key_id)
    derived = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if pinned is None:
        raise RootAppCatalogBuildError("signing key ID is not pinned")
    if pinned != derived:
        raise RootAppCatalogBuildError("private signing key does not match the pinned public key")


def _parse_expiration(value: str) -> datetime:
    if _TIMESTAMP.fullmatch(value) is None:
        raise RootAppCatalogBuildError("expiration must be a UTC timestamp")
    try:
        expiration = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise RootAppCatalogBuildError("expiration is invalid") from exc
    if expiration <= datetime.now(UTC):
        raise RootAppCatalogBuildError("expiration must be in the future")
    return expiration


def _json_object(path: Path) -> dict[str, object]:
    try:
        decoded = cast(object, json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RootAppCatalogBuildError("source lock is invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise RootAppCatalogBuildError("source lock must be an object")
    return cast(dict[str, object], decoded)


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    values: dict[str, object] = {}
    for key, value in pairs:
        if key in values:
            raise RootAppCatalogBuildError("source lock contains a duplicate field")
        values[key] = value
    return values


def _required_string(values: Mapping[str, object], key: str) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value:
        raise RootAppCatalogBuildError(f"{key} must be a non-empty string")
    return value


def _required_integer(values: Mapping[str, object], key: str) -> int:
    value = values.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RootAppCatalogBuildError(f"{key} must be a positive integer")
    return value


def _string_list(raw: object, field: str) -> list[str]:
    items = cast(list[object], raw) if isinstance(raw, list) else []
    if not items or any(not isinstance(value, str) or not value for value in items):
        raise RootAppCatalogBuildError(f"{field} must be a non-empty string list")
    values = cast(list[str], items)
    if len(values) != len(set(values)):
        raise RootAppCatalogBuildError(f"{field} contains duplicates")
    return values


def _write_json_atomic(path: Path, value: Mapping[str, object]) -> None:
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-lock", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--apks", type=Path, required=True)
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
            apks_directory=args.apks,
            output_directory=args.output,
            expires_at=args.expires_at,
        )
    except RootAppCatalogBuildError as exc:
        print(f"Root-app catalog build failed: {exc}", file=sys.stderr)
        return 1
    entries = cast(list[object], catalog["entries"])
    print(f"Built {len(entries)} signed root-app target(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
