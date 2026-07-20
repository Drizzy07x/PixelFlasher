"""Pinned backend resource registry for boot-patch runners.

The runner trust chain is deliberately independent from root-application
delivery. Runners are packaged with the application and fixed by this
manifest; provider APKs are downloaded on demand through the separately
signed root-app catalog and registered with the shared ``RootingService``.

The expected manifest SHA-256 is an API argument, not a manifest field.  It
must come from trusted backend configuration or release metadata and must
never be copied from a WebView request.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from .boot_patch import (
    SUPPORTED_BOOT_PATCH_FLAVORS,
    BootPatchService,
    PatchToolBundle,
)
from .contracts import FileArtifact

PATCH_RESOURCE_SCHEMA_VERSION = 3
PATCH_RUNNER_PROTOCOL = "pixelflasher.boot-patch.v1"
PATCH_RUNNER_MARKER = b"PIXELFLASHER_BOOT_PATCH_RUNNER_V1"
PATCH_RESOURCE_MANIFEST_NAME = "patch-resources.json"
PATCH_RESOURCE_DIGEST_NAME = "patch-resources.sha256"
PACKAGED_PATCH_RESOURCE_DIRECTORY = Path("resources/boot-patch/runtime")

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MAX_MANIFEST_BYTES = 1024 * 1024
_MAX_BUNDLES = 64
_MAX_SUPPORT_ARTIFACTS = 32
_MAX_ARCHITECTURES = 5
_MAX_KMI_VERSIONS = 64

class PatchResourceError(ValueError):
    """Stable fail-closed error raised while loading backend resources."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class _DuplicateManifestKey(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PatchResourceRegistry:
    """Verified services and bundles produced from one pinned manifest."""

    manifest_path: str
    manifest_sha256: str
    resource_root: str
    tool_bundles: tuple[PatchToolBundle, ...]

    @property
    def ready_flavors(self) -> frozenset[str]:
        return frozenset(bundle.flavor for bundle in self.tool_bundles)

    @property
    def missing_flavors(self) -> frozenset[str]:
        return SUPPORTED_BOOT_PATCH_FLAVORS - self.ready_flavors

    @property
    def complete(self) -> bool:
        return not self.missing_flavors


def load_optional_packaged_patch_resource_registry(
    application_root: str | Path,
    *,
    hash_chunk_size: int = 1024 * 1024,
) -> PatchResourceRegistry | None:
    """Load the packaged runner manifest or fail on a partial distribution."""

    raw_root = Path(application_root).expanduser()
    try:
        root = raw_root.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        raise PatchResourceError("packaged_resource_root_invalid", str(error)) from error
    if not root.is_dir() or raw_root.is_symlink():
        raise PatchResourceError(
            "packaged_resource_root_invalid",
            "application resource root must be a real directory",
        )
    distribution = root / PACKAGED_PATCH_RESOURCE_DIRECTORY
    if not distribution.exists():
        return None
    try:
        resolved_distribution = distribution.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        raise PatchResourceError("packaged_distribution_invalid", str(error)) from error
    if distribution.is_symlink() or not resolved_distribution.is_dir():
        raise PatchResourceError(
            "packaged_distribution_invalid",
            "packaged patch resource distribution is invalid",
        )
    manifest = resolved_distribution / PATCH_RESOURCE_MANIFEST_NAME
    digest_path = resolved_distribution / PATCH_RESOURCE_DIGEST_NAME
    try:
        encoded_digest = digest_path.read_bytes()
        if not encoded_digest or len(encoded_digest) > 128:
            raise ValueError("digest size")
        expected_digest = encoded_digest.decode("ascii", "strict").strip().casefold()
    except (OSError, UnicodeError, ValueError) as error:
        raise PatchResourceError(
            "packaged_manifest_digest_invalid",
            "packaged patch resource digest is unavailable",
        ) from error
    if _SHA256_PATTERN.fullmatch(expected_digest) is None:
        raise PatchResourceError(
            "packaged_manifest_digest_invalid",
            "packaged patch resource digest is invalid",
        )
    return load_patch_resource_registry(
        manifest,
        expected_manifest_sha256=expected_digest,
        resource_root=root,
        hash_chunk_size=hash_chunk_size,
    )


def load_patch_resource_registry(
    manifest_path: str | Path,
    *,
    expected_manifest_sha256: str,
    resource_root: str | Path | None = None,
    hash_chunk_size: int = 1024 * 1024,
) -> PatchResourceRegistry:
    """Load only hash-pinned, relative backend resources.

    ``manifest_path`` and ``expected_manifest_sha256`` are backend injection
    points.  No command payload, path, argv, URL, or hash is accepted here.
    """

    if not isinstance(hash_chunk_size, int) or isinstance(hash_chunk_size, bool):
        raise TypeError("hash_chunk_size must be an integer")
    if hash_chunk_size <= 0:
        raise ValueError("hash_chunk_size must be positive")
    expected_manifest_hash = _sha256_value(
        expected_manifest_sha256,
        "manifest_hash_invalid",
    )
    manifest = _absolute_file(
        manifest_path,
        suffix=".json",
        code="manifest_path_invalid",
    )
    try:
        manifest_size = manifest.stat().st_size
    except OSError as error:
        raise PatchResourceError("manifest_read_failed", str(error)) from error
    if manifest_size <= 0 or manifest_size > _MAX_MANIFEST_BYTES:
        raise PatchResourceError(
            "manifest_size_invalid",
            f"patch resource manifest must be 1-{_MAX_MANIFEST_BYTES} bytes",
        )
    manifest_bytes, manifest_hash = _read_manifest_stable(
        manifest,
        hash_chunk_size,
    )
    if not hmac.compare_digest(manifest_hash, expected_manifest_hash):
        raise PatchResourceError(
            "manifest_hash_mismatch",
            "patch resource manifest does not match backend release metadata",
        )

    root = _resource_root(resource_root, manifest)
    try:
        raw_manifest = manifest_bytes.decode("utf-8", errors="strict")
        document_value: object = json.loads(
            raw_manifest,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except _DuplicateManifestKey as error:
        raise PatchResourceError("manifest_duplicate_key", str(error)) from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PatchResourceError("manifest_json_invalid", str(error)) from error
    if not isinstance(document_value, Mapping):
        raise PatchResourceError(
            "manifest_schema_invalid",
            "patch resource manifest must be a JSON object",
        )
    document = cast(Mapping[str, object], document_value)
    _exact_fields(
        document,
        {"schemaVersion", "protocol", "bundles"},
        "manifest",
    )
    version = document["schemaVersion"]
    if isinstance(version, bool) or not isinstance(version, int):
        raise PatchResourceError(
            "manifest_schema_invalid",
            "schemaVersion must be an integer",
        )
    if version != PATCH_RESOURCE_SCHEMA_VERSION:
        raise PatchResourceError(
            "manifest_version_unsupported",
            f"unsupported patch resource schema: {version}",
        )
    if document["protocol"] != PATCH_RUNNER_PROTOCOL:
        raise PatchResourceError(
            "runner_protocol_unsupported",
            "manifest does not target the required boot-patch runner protocol",
        )

    raw_bundles = _bounded_list(document["bundles"], "bundles", _MAX_BUNDLES)
    bundles: list[PatchToolBundle] = []
    for index, raw_bundle in enumerate(raw_bundles):
        if not isinstance(raw_bundle, Mapping):
            raise PatchResourceError(
                "manifest_schema_invalid",
                f"bundles[{index}] must be an object",
            )
        bundle_values = cast(Mapping[str, object], raw_bundle)
        _exact_fields(
            bundle_values,
            {"flavor", "runner", "support", "compatibility"},
            f"bundles[{index}]",
        )
        flavor = _text(bundle_values["flavor"], f"bundles[{index}].flavor").casefold()
        if flavor not in SUPPORTED_BOOT_PATCH_FLAVORS:
            raise PatchResourceError(
                "patch_flavor_unsupported",
                f"manifest uses unsupported patch flavor: {flavor}",
            )
        # One generic protocol runner or support binary may intentionally be
        # shared across flavors.  Ambiguity is rejected within each compiled
        # bundle and against every APK, where roles would overlap in one plan.
        bundle_paths: set[str] = set()
        runner = _manifest_artifact(
            root,
            bundle_values["runner"],
            role=f"patch-runner:{flavor}",
            seen_paths=bundle_paths,
            hash_chunk_size=hash_chunk_size,
            field=f"bundles[{index}].runner",
        )
        _require_runner_marker(Path(runner.path), hash_chunk_size)
        raw_support = _bounded_list(
            bundle_values["support"],
            f"bundles[{index}].support",
            _MAX_SUPPORT_ARTIFACTS,
        )
        support = tuple(
            _manifest_artifact(
                root,
                raw_artifact,
                role=f"patch-support:{flavor}:{support_index}",
                seen_paths=bundle_paths,
                hash_chunk_size=hash_chunk_size,
                field=f"bundles[{index}].support[{support_index}]",
            )
            for support_index, raw_artifact in enumerate(raw_support)
        )
        architectures, kmi_versions = _compatibility(
            bundle_values["compatibility"],
            field=f"bundles[{index}].compatibility",
        )
        try:
            bundles.append(
                PatchToolBundle(
                    flavor,
                    "",
                    runner,
                    support,
                    architectures,
                    kmi_versions,
                )
            )
        except (TypeError, ValueError) as error:
            raise PatchResourceError(
                "patch_compatibility_invalid",
                str(error),
            ) from error

    try:
        BootPatchService(tool_bundles=tuple(bundles))
    except ValueError as error:
        raise PatchResourceError(
            "patch_compatibility_overlap",
            str(error),
        ) from error

    return PatchResourceRegistry(
        str(manifest),
        manifest_hash,
        str(root),
        tuple(bundles),
    )


def _compatibility(
    value: object,
    *,
    field: str,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if not isinstance(value, Mapping):
        raise PatchResourceError(
            "manifest_schema_invalid",
            f"{field} must be an object",
        )
    values = cast(Mapping[str, object], value)
    _exact_fields(values, {"architectures", "kmi"}, field)
    raw_architectures = _bounded_list(
        values["architectures"],
        f"{field}.architectures",
        _MAX_ARCHITECTURES,
    )
    raw_kmi = _bounded_list(
        values["kmi"],
        f"{field}.kmi",
        _MAX_KMI_VERSIONS,
    )
    architectures = tuple(
        _text(item, f"{field}.architectures[{index}]").casefold()
        for index, item in enumerate(raw_architectures)
    )
    kmi_versions = tuple(
        _text(item, f"{field}.kmi[{index}]").casefold()
        for index, item in enumerate(raw_kmi)
    )
    return architectures, kmi_versions


def _manifest_artifact(
    root: Path,
    value: object,
    *,
    role: str,
    seen_paths: set[str],
    hash_chunk_size: int,
    field: str,
) -> FileArtifact:
    if not isinstance(value, Mapping):
        raise PatchResourceError(
            "manifest_schema_invalid",
            f"{field} must be an object",
        )
    values = cast(Mapping[str, object], value)
    _exact_fields(values, {"path", "sha256"}, field)
    path = _resource_file(root, values["path"], suffix=None)
    _claim_path(path, seen_paths)
    expected = _sha256_value(values["sha256"], "resource_hash_invalid")
    digest = _sha256_stable(path, hash_chunk_size, "resource_read_failed")
    if not hmac.compare_digest(digest, expected):
        raise PatchResourceError(
            "resource_hash_mismatch",
            f"patch resource does not match pinned SHA-256: {path}",
        )
    return FileArtifact(str(path), digest, role)


def _absolute_file(raw_path: str | Path, *, suffix: str, code: str) -> Path:
    if not isinstance(raw_path, (str, Path)):
        raise PatchResourceError(code, "an absolute file path is required")
    try:
        raw = Path(raw_path).expanduser()
    except (OSError, RuntimeError, ValueError) as error:
        raise PatchResourceError(code, str(error)) from error
    if not raw.is_absolute() or raw.is_symlink():
        raise PatchResourceError(code, "manifest path must be absolute and not a symlink")
    try:
        path = raw.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        raise PatchResourceError(code, str(error)) from error
    if not path.is_file() or path.suffix.casefold() != suffix:
        raise PatchResourceError(code, "manifest path has an invalid file type")
    return path


def _resource_root(raw_root: str | Path | None, manifest: Path) -> Path:
    candidate = manifest.parent if raw_root is None else Path(raw_root).expanduser()
    if not candidate.is_absolute() or candidate.is_symlink():
        raise PatchResourceError(
            "resource_root_invalid",
            "resource root must be an absolute non-symlink directory",
        )
    try:
        root = candidate.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        raise PatchResourceError("resource_root_invalid", str(error)) from error
    if not root.is_dir():
        raise PatchResourceError("resource_root_invalid", "resource root is not a directory")
    return root


def _resource_file(root: Path, raw_path: object, *, suffix: str | None) -> Path:
    if not isinstance(raw_path, str) or not raw_path or len(raw_path) > 512:
        raise PatchResourceError(
            "resource_path_invalid",
            "resource path must be a bounded relative POSIX path",
        )
    if "\\" in raw_path or "\x00" in raw_path or ":" in raw_path:
        raise PatchResourceError(
            "resource_path_invalid",
            "resource path contains unsupported characters",
        )
    relative = PurePosixPath(raw_path)
    if relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise PatchResourceError(
            "resource_path_invalid",
            "resource paths must stay below the configured resource root",
        )
    candidate = root.joinpath(*relative.parts)
    if candidate.is_symlink():
        raise PatchResourceError(
            "resource_path_invalid",
            "symlink resources are not accepted",
        )
    current = candidate.parent
    while current != root:
        if current.is_symlink():
            raise PatchResourceError(
                "resource_path_invalid",
                "resources below symlink directories are not accepted",
            )
        if root not in current.parents:
            raise PatchResourceError(
                "resource_path_invalid",
                "resource path escaped its configured root",
            )
        current = current.parent
    try:
        path = candidate.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        raise PatchResourceError("resource_path_invalid", str(error)) from error
    if root not in path.parents or not path.is_file():
        raise PatchResourceError(
            "resource_path_invalid",
            "resource path escaped its configured root or is not a file",
        )
    if suffix is not None and path.suffix.casefold() != suffix:
        raise PatchResourceError(
            "resource_path_invalid",
            f"resource must use the {suffix} suffix",
        )
    try:
        if path.stat().st_size <= 0:
            raise PatchResourceError("resource_path_invalid", "resource file is empty")
    except OSError as error:
        raise PatchResourceError("resource_path_invalid", str(error)) from error
    return path


def _sha256_stable(path: Path, chunk_size: int, code: str) -> str:
    try:
        before = path.stat()
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(chunk_size):
                digest.update(chunk)
        after = path.stat()
    except OSError as error:
        raise PatchResourceError(code, str(error)) from error
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_identity != after_identity:
        raise PatchResourceError(
            "resource_changed",
            f"resource changed while being hashed: {path}",
        )
    return digest.hexdigest()


def _read_manifest_stable(path: Path, chunk_size: int) -> tuple[bytes, str]:
    try:
        before = path.stat()
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        with path.open("rb") as stream:
            while chunk := stream.read(chunk_size):
                digest.update(chunk)
                chunks.append(chunk)
        after = path.stat()
    except OSError as error:
        raise PatchResourceError("manifest_read_failed", str(error)) from error
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_identity != after_identity:
        raise PatchResourceError(
            "resource_changed",
            f"manifest changed while being hashed: {path}",
        )
    return b"".join(chunks), digest.hexdigest()


def _require_runner_marker(path: Path, chunk_size: int) -> None:
    overlap = b""
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(chunk_size):
                window = overlap + chunk
                if PATCH_RUNNER_MARKER in window:
                    return
                overlap = window[-(len(PATCH_RUNNER_MARKER) - 1) :]
    except OSError as error:
        raise PatchResourceError("resource_read_failed", str(error)) from error
    raise PatchResourceError(
        "runner_protocol_marker_missing",
        f"patch runner does not identify {PATCH_RUNNER_PROTOCOL}: {path}",
    )


def _reject_duplicate_keys(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateManifestKey(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _exact_fields(value: Mapping[str, object], expected: set[str], field: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        details: list[str] = []
        if missing:
            details.append(f"missing {missing[0]}")
        if unknown:
            details.append(f"unsupported {unknown[0]}")
        raise PatchResourceError(
            "manifest_schema_invalid",
            f"{field} fields are invalid: {', '.join(details)}",
        )


def _bounded_list(value: object, field: str, limit: int) -> list[object]:
    if not isinstance(value, list):
        raise PatchResourceError(
            "manifest_schema_invalid",
            f"{field} must be an array",
        )
    values = cast(list[object], value)
    if len(values) > limit:
        raise PatchResourceError(
            "manifest_limit_exceeded",
            f"{field} exceeds its limit of {limit}",
        )
    return values


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 128:
        raise PatchResourceError(
            "manifest_schema_invalid",
            f"{field} must be a bounded non-empty string",
        )
    return value.strip()


def _sha256_value(value: object, code: str) -> str:
    if not isinstance(value, str) or not _SHA256_PATTERN.fullmatch(value.casefold()):
        raise PatchResourceError(code, "expected SHA-256 must contain 64 hexadecimal characters")
    return value.casefold()


def _claim_path(path: Path, seen_paths: set[str]) -> None:
    key = os.path.normcase(str(path))
    if key in seen_paths:
        raise PatchResourceError(
            "resource_path_duplicate",
            f"one file cannot serve multiple resource roles: {path}",
        )
    seen_paths.add(key)


__all__ = [
    "PACKAGED_PATCH_RESOURCE_DIRECTORY",
    "PATCH_RESOURCE_DIGEST_NAME",
    "PATCH_RESOURCE_MANIFEST_NAME",
    "PATCH_RESOURCE_SCHEMA_VERSION",
    "PATCH_RUNNER_MARKER",
    "PATCH_RUNNER_PROTOCOL",
    "PatchResourceError",
    "PatchResourceRegistry",
    "load_optional_packaged_patch_resource_registry",
    "load_patch_resource_registry",
]
