"""Fail-closed Magisk module update inspection and private artifact cache.

The WebView never receives an update URL or a filesystem path.  Installed
``updateJson`` values are consumed only by this backend service, restricted to
HTTPS code-hosting origins, downloaded with strict limits, and promoted only
after the resulting ZIP has passed the same module inspection used for manual
installs.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import tempfile
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, cast
from urllib.parse import urljoin, urlsplit

import requests

from .apk_inspection import CancellationProbe
from .contracts import JSONValue, ProgressPhase
from .rooting import RootingPlanningError, RootModuleInfo

_MODULE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
_ARTIFACT_ID = re.compile(r"^[0-9a-f]{32}$")
_MAX_METADATA_BYTES = 64 * 1024
_MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
_MAX_REDIRECTS = 5
_MAX_UPDATES = 64
_CHUNK_SIZE = 64 * 1024
_ALLOWED_METADATA_FIELDS = frozenset({"version", "versionCode", "zipUrl", "changelog"})
_DEFAULT_ALLOWED_HOSTS = frozenset(
    {
        "github.com",
        "githubusercontent.com",
        "gitlab.com",
        "codeberg.org",
        "codeberg.page",
    }
)

ProgressReporter = Callable[[ProgressPhase, str, int | None], None]
ModuleInspector = Callable[[Path, CancellationProbe | None], str]
HostValidator = Callable[[str], bool]


class ModuleUpdateStatus(StrEnum):
    SUCCESS = "SUCCESS"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class ModuleUpdateError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class _Response(Protocol):
    status_code: int
    headers: Mapping[str, str]

    def iter_content(self, chunk_size: int) -> Iterable[bytes]: ...

    def close(self) -> None: ...


class _Session(Protocol):
    def get(self, url: str, **kwargs: object) -> _Response: ...


@dataclass(frozen=True, slots=True)
class RootModuleUpdateEntry:
    artifact_id: str
    module_id: str
    installed_version: str
    installed_version_code: int
    version: str
    version_code: int
    sha256: str
    size: int
    provenance: str = "module-update-json"
    trust: str = "unverified-author"

    def to_public_dict(self) -> dict[str, JSONValue]:
        return {
            "artifactId": self.artifact_id,
            "moduleId": self.module_id,
            "installedVersion": self.installed_version,
            "installedVersionCode": self.installed_version_code,
            "version": self.version,
            "versionCode": self.version_code,
            "sha256": self.sha256,
            "size": self.size,
            "provenance": self.provenance,
            "trust": self.trust,
        }


@dataclass(frozen=True, slots=True)
class RootModuleUpdateIssue:
    module_id: str
    code: str

    def to_public_dict(self) -> dict[str, JSONValue]:
        return {"moduleId": self.module_id, "code": self.code}


@dataclass(frozen=True, slots=True)
class RootModuleUpdateResult:
    status: ModuleUpdateStatus
    code: str
    message: str
    entries: tuple[RootModuleUpdateEntry, ...] = ()
    issues: tuple[RootModuleUpdateIssue, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "entries", tuple(self.entries))
        object.__setattr__(self, "issues", tuple(self.issues))

    @property
    def ok(self) -> bool:
        return self.status is ModuleUpdateStatus.SUCCESS

    def to_public_dict(self) -> dict[str, JSONValue]:
        return {
            "count": len(self.entries),
            "updates": [entry.to_public_dict() for entry in self.entries],
            "issueCount": len(self.issues),
            "issues": [issue.to_public_dict() for issue in self.issues],
        }


@dataclass(frozen=True, slots=True)
class ResolvedRootModuleUpdate:
    entry: RootModuleUpdateEntry
    path: Path
    target_serial: str


@dataclass(frozen=True, slots=True)
class _UpdateMetadata:
    version: str
    version_code: int
    zip_url: str


class RootModuleUpdateService:
    """Prepare identity-checked update ZIPs behind opaque artifact IDs."""

    def __init__(
        self,
        cache_directory: str | os.PathLike[str],
        inspector: ModuleInspector,
        *,
        session: _Session | None = None,
        allowed_hosts: Sequence[str] = tuple(sorted(_DEFAULT_ALLOWED_HOSTS)),
        host_validator: HostValidator | None = None,
    ) -> None:
        if not callable(inspector):
            raise TypeError("inspector must be callable")
        normalized_hosts = frozenset(
            host.strip().casefold().rstrip(".")
            for host in allowed_hosts
            if isinstance(host, str) and host.strip()
        )
        if not normalized_hosts:
            raise ValueError("at least one update host must be allowed")
        self.cache_directory = Path(cache_directory)
        self.inspector = inspector
        self.session = cast(_Session, session or requests.Session())
        self.allowed_hosts = normalized_hosts
        self.host_validator = host_validator or _public_host
        self._artifacts: Mapping[str, ResolvedRootModuleUpdate] = MappingProxyType({})

    def prepare(
        self,
        modules: Sequence[RootModuleInfo],
        cancellation: CancellationProbe | None,
        *,
        target_serial: str,
        progress: ProgressReporter | None = None,
    ) -> RootModuleUpdateResult:
        self._artifacts = MappingProxyType({})
        if (
            not isinstance(target_serial, str)
            or not target_serial.strip()
            or len(target_serial) > 256
            or any(ord(character) < 32 or ord(character) == 127 for character in target_serial)
        ):
            return RootModuleUpdateResult(
                ModuleUpdateStatus.FAILED,
                "root_module_update_binding_invalid",
                "The module update device binding is invalid.",
            )
        target_serial = target_serial.strip()
        if len(modules) > 256 or any(not isinstance(module, RootModuleInfo) for module in modules):
            return RootModuleUpdateResult(
                ModuleUpdateStatus.FAILED,
                "root_module_update_inventory_invalid",
                "The module inventory is invalid.",
            )
        candidates = tuple(
            module
            for module in modules
            if module.update_url and module.version_code is not None
        )
        if len(candidates) > _MAX_UPDATES:
            return RootModuleUpdateResult(
                ModuleUpdateStatus.FAILED,
                "root_module_update_limit_exceeded",
                "Too many module update sources were reported.",
            )
        prepared: dict[str, ResolvedRootModuleUpdate] = {}
        issues: list[RootModuleUpdateIssue] = []
        try:
            self._raise_if_cancelled(cancellation)
            self._progress(progress, ProgressPhase.STARTED, "Checking module update metadata.", 0)
            cache = self.cache_directory.resolve(strict=False)
            cache.mkdir(parents=True, exist_ok=True)
            for index, module in enumerate(candidates):
                self._raise_if_cancelled(cancellation)
                try:
                    metadata = self._metadata(module.update_url, cancellation)
                    assert module.version_code is not None
                    if metadata.version_code <= module.version_code:
                        continue
                    resolved = self._download_and_inspect(
                        module,
                        metadata,
                        cache,
                        cancellation,
                        target_serial=target_serial,
                    )
                    if resolved.entry.artifact_id in prepared:
                        raise ModuleUpdateError(
                            "root_module_update_duplicate",
                            "A duplicate module update artifact was produced.",
                        )
                    prepared[resolved.entry.artifact_id] = resolved
                except (ModuleUpdateError, RootingPlanningError) as error:
                    issues.append(RootModuleUpdateIssue(module.id, error.code))
                percent = int(((index + 1) / max(1, len(candidates))) * 95)
                self._progress(progress, ProgressPhase.RUNNING, "Verifying module updates.", percent)
            self._raise_if_cancelled(cancellation)
            self._artifacts = MappingProxyType(prepared)
            entries = tuple(
                sorted(
                    (resolved.entry for resolved in prepared.values()),
                    key=lambda item: item.module_id.casefold(),
                )
            )
            self._progress(progress, ProgressPhase.COMPLETED, "Module update check completed.", 100)
            return RootModuleUpdateResult(
                ModuleUpdateStatus.SUCCESS,
                "root_module_updates_prepared",
                f"Prepared {len(entries)} module update(s).",
                entries,
                tuple(sorted(issues, key=lambda item: item.module_id.casefold())),
            )
        except ModuleUpdateError as error:
            if error.code == "root_module_update_cancelled":
                self._progress(progress, ProgressPhase.CANCELLED, "Module update check cancelled.", None)
                return RootModuleUpdateResult(ModuleUpdateStatus.CANCELLED, error.code, str(error))
            self._progress(progress, ProgressPhase.FAILED, "Module update check failed.", None)
            return RootModuleUpdateResult(ModuleUpdateStatus.FAILED, error.code, str(error))
        except OSError:
            self._progress(progress, ProgressPhase.FAILED, "Module update check failed.", None)
            return RootModuleUpdateResult(
                ModuleUpdateStatus.FAILED,
                "root_module_update_cache_failed",
                "The private module update cache is unavailable.",
            )

    def resolve(
        self,
        artifact_id: object,
        module_id: object,
        *,
        target_serial: object,
    ) -> ResolvedRootModuleUpdate:
        if not isinstance(artifact_id, str) or _ARTIFACT_ID.fullmatch(artifact_id) is None:
            raise RootingPlanningError(
                "root_module_update_artifact_invalid",
                "The module update artifact ID is invalid.",
            )
        if not isinstance(module_id, str) or _MODULE_ID.fullmatch(module_id) is None:
            raise RootingPlanningError(
                "root_module_id_invalid",
                "The module update identity is invalid.",
            )
        resolved = self._artifacts.get(artifact_id)
        if (
            resolved is None
            or resolved.entry.module_id != module_id
            or resolved.target_serial != target_serial
        ):
            raise RootingPlanningError(
                "root_module_update_artifact_unknown",
                "Check for module updates again before installing this artifact.",
            )
        try:
            path = resolved.path.resolve(strict=True)
            cache = self.cache_directory.resolve(strict=True)
            path.relative_to(cache)
            stat_result = path.stat()
        except (OSError, RuntimeError, ValueError) as error:
            raise RootingPlanningError(
                "root_module_update_artifact_missing",
                "The prepared module update is no longer available.",
            ) from error
        if not path.is_file() or stat_result.st_size != resolved.entry.size:
            raise RootingPlanningError(
                "root_module_update_artifact_changed",
                "The prepared module update changed after verification.",
            )
        digest = _hash_file(path)
        if digest != resolved.entry.sha256:
            raise RootingPlanningError(
                "root_module_update_artifact_changed",
                "The prepared module update changed after verification.",
            )
        return resolved

    def _metadata(
        self,
        update_url: str,
        cancellation: CancellationProbe | None,
    ) -> _UpdateMetadata:
        payload = self._read_response(
            update_url,
            maximum=_MAX_METADATA_BYTES,
            cancellation=cancellation,
            accept="application/json, text/plain;q=0.5",
        )
        try:
            raw_document: object = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ModuleUpdateError(
                "root_module_update_metadata_invalid",
                "Module update metadata is not valid UTF-8 JSON.",
            ) from error
        if not isinstance(raw_document, dict):
            raise ModuleUpdateError(
                "root_module_update_metadata_invalid",
                "Module update metadata has unsupported fields.",
            )
        document_values = cast(Mapping[object, object], raw_document)
        if any(not isinstance(key, str) for key in document_values) or set(document_values) - _ALLOWED_METADATA_FIELDS:
            raise ModuleUpdateError(
                "root_module_update_metadata_invalid",
                "Module update metadata has unsupported fields.",
            )
        document = cast(Mapping[str, object], document_values)
        version = document.get("version")
        version_code = document.get("versionCode")
        zip_url = document.get("zipUrl")
        if (
            not isinstance(version, str)
            or not version.strip()
            or len(version.strip()) > 128
            or any(ord(character) < 32 or ord(character) == 127 for character in version)
            or not isinstance(version_code, int)
            or isinstance(version_code, bool)
            or not 0 <= version_code <= 2_147_483_647
            or not isinstance(zip_url, str)
        ):
            raise ModuleUpdateError(
                "root_module_update_metadata_invalid",
                "Module update version metadata is invalid.",
            )
        self._validated_url(zip_url)
        return _UpdateMetadata(version.strip(), version_code, zip_url)

    def _download_and_inspect(
        self,
        module: RootModuleInfo,
        metadata: _UpdateMetadata,
        cache: Path,
        cancellation: CancellationProbe | None,
        *,
        target_serial: str,
    ) -> ResolvedRootModuleUpdate:
        descriptor, temporary_name = tempfile.mkstemp(prefix=".module-update-", suffix=".zip", dir=cache)
        temporary = Path(temporary_name)
        digest = hashlib.sha256()
        downloaded = 0
        try:
            with os.fdopen(descriptor, "wb") as stream:
                response = self._open(metadata.zip_url, cancellation)
                try:
                    length = self._content_length(response)
                    if length is not None and not 1 <= length <= _MAX_ARCHIVE_BYTES:
                        raise ModuleUpdateError(
                            "root_module_update_archive_too_large",
                            "The module update archive is outside its size limit.",
                        )
                    for chunk in response.iter_content(_CHUNK_SIZE):
                        self._raise_if_cancelled(cancellation)
                        if not chunk:
                            continue
                        if not isinstance(chunk, bytes):
                            raise ModuleUpdateError(
                                "root_module_update_stream_invalid",
                                "The module update response is invalid.",
                            )
                        downloaded += len(chunk)
                        if downloaded > _MAX_ARCHIVE_BYTES:
                            raise ModuleUpdateError(
                                "root_module_update_archive_too_large",
                                "The module update archive exceeds its size limit.",
                            )
                        digest.update(chunk)
                        stream.write(chunk)
                    if downloaded < 1 or (length is not None and downloaded != length):
                        raise ModuleUpdateError(
                            "root_module_update_archive_incomplete",
                            "The module update archive is incomplete.",
                        )
                    stream.flush()
                    os.fsync(stream.fileno())
                finally:
                    response.close()
            self._raise_if_cancelled(cancellation)
            inspected_id = self.inspector(temporary, cancellation)
            if inspected_id != module.id:
                raise ModuleUpdateError(
                    "root_module_update_identity_mismatch",
                    "The downloaded archive declares a different module identity.",
                )
            sha256 = digest.hexdigest()
            destination = cache / f"{sha256}.zip"
            if destination.exists():
                if not destination.is_file() or destination.stat().st_size != downloaded or _hash_file(destination) != sha256:
                    raise ModuleUpdateError(
                        "root_module_update_cache_collision",
                        "The private update cache contains conflicting data.",
                    )
                temporary.unlink()
            else:
                os.replace(temporary, destination)
                _fsync_directory(cache)
            artifact_id = hashlib.sha256(
                b"pixelflasher-root-module-update-v1\0"
                + module.id.encode("utf-8")
                + b"\0"
                + target_serial.encode("utf-8")
                + b"\0"
                + str(metadata.version_code).encode("ascii")
                + b"\0"
                + sha256.encode("ascii")
            ).hexdigest()[:32]
            entry = RootModuleUpdateEntry(
                artifact_id,
                module.id,
                module.version,
                cast(int, module.version_code),
                metadata.version,
                metadata.version_code,
                sha256,
                downloaded,
            )
            return ResolvedRootModuleUpdate(
                entry,
                destination,
                target_serial,
            )
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def _read_response(
        self,
        url: str,
        *,
        maximum: int,
        cancellation: CancellationProbe | None,
        accept: str,
    ) -> bytes:
        response = self._open(url, cancellation, accept=accept)
        payload = bytearray()
        try:
            length = self._content_length(response)
            if length is not None and not 1 <= length <= maximum:
                raise ModuleUpdateError(
                    "root_module_update_metadata_too_large",
                    "Module update metadata exceeds its size limit.",
                )
            for chunk in response.iter_content(_CHUNK_SIZE):
                self._raise_if_cancelled(cancellation)
                if not chunk:
                    continue
                if not isinstance(chunk, bytes):
                    raise ModuleUpdateError(
                        "root_module_update_stream_invalid",
                        "The module update response is invalid.",
                    )
                payload.extend(chunk)
                if len(payload) > maximum:
                    raise ModuleUpdateError(
                        "root_module_update_metadata_too_large",
                        "Module update metadata exceeds its size limit.",
                    )
            if not payload or (length is not None and len(payload) != length):
                raise ModuleUpdateError(
                    "root_module_update_metadata_incomplete",
                    "Module update metadata is incomplete.",
                )
            return bytes(payload)
        finally:
            response.close()

    def _open(
        self,
        url: str,
        cancellation: CancellationProbe | None,
        *,
        accept: str = "application/zip, application/octet-stream;q=0.8",
    ) -> _Response:
        current = self._validated_url(url)
        headers = {
            "Accept": accept,
            "Accept-Encoding": "identity",
            "User-Agent": "PixelFlasher-module-updates/1",
        }
        for redirect_count in range(_MAX_REDIRECTS + 1):
            self._raise_if_cancelled(cancellation)
            try:
                response = self.session.get(
                    current,
                    allow_redirects=False,
                    stream=True,
                    timeout=(10.0, 30.0),
                    headers=headers,
                )
            except requests.RequestException as error:
                raise ModuleUpdateError(
                    "root_module_update_transport_failed",
                    "The module update server could not be reached.",
                ) from error
            if response.status_code in {301, 302, 303, 307, 308}:
                location = self._header(response, "Location")
                response.close()
                if not location or redirect_count >= _MAX_REDIRECTS:
                    raise ModuleUpdateError(
                        "root_module_update_redirect_invalid",
                        "The module update redirect chain is invalid.",
                    )
                current = self._validated_url(urljoin(current, location))
                continue
            if response.status_code != 200:
                response.close()
                raise ModuleUpdateError(
                    "root_module_update_http_status_invalid",
                    "The module update server returned an unexpected status.",
                )
            return response
        raise ModuleUpdateError(
            "root_module_update_redirect_invalid",
            "The module update redirect chain is invalid.",
        )

    def _validated_url(self, value: str) -> str:
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as error:
            raise ModuleUpdateError(
                "root_module_update_url_invalid",
                "The module update URL is invalid.",
            ) from error
        host = (parsed.hostname or "").casefold().rstrip(".")
        if (
            parsed.scheme != "https"
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or port not in {None, 443}
            or not any(host == allowed or host.endswith(f".{allowed}") for allowed in self.allowed_hosts)
            or not self.host_validator(host)
        ):
            raise ModuleUpdateError(
                "root_module_update_url_untrusted",
                "The module update URL is outside the trusted HTTPS boundary.",
            )
        return value

    @staticmethod
    def _content_length(response: _Response) -> int | None:
        value = RootModuleUpdateService._header(response, "Content-Length")
        if value is None:
            return None
        try:
            parsed = int(value, 10)
        except ValueError as error:
            raise ModuleUpdateError(
                "root_module_update_length_invalid",
                "The module update response length is invalid.",
            ) from error
        if parsed < 0:
            raise ModuleUpdateError(
                "root_module_update_length_invalid",
                "The module update response length is invalid.",
            )
        return parsed

    @staticmethod
    def _header(response: _Response, name: str) -> str | None:
        for key, value in response.headers.items():
            if key.casefold() == name.casefold():
                return value.strip()
        return None

    @staticmethod
    def _raise_if_cancelled(cancellation: CancellationProbe | None) -> None:
        if cancellation is not None and cancellation.cancelled:
            raise ModuleUpdateError(
                "root_module_update_cancelled",
                "The module update operation was cancelled.",
            )

    @staticmethod
    def _progress(
        reporter: ProgressReporter | None,
        phase: ProgressPhase,
        message: str,
        percent: int | None,
    ) -> None:
        if reporter is None:
            return
        try:
            reporter(phase, message, percent)
        except Exception:
            pass


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(_CHUNK_SIZE):
                digest.update(chunk)
    except OSError as error:
        raise RootingPlanningError(
            "root_module_update_artifact_missing",
            "The prepared module update could not be read.",
        ) from error
    return digest.hexdigest()


def _public_host(host: str) -> bool:
    try:
        records = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        addresses = {ipaddress.ip_address(record[4][0]) for record in records}
    except (OSError, ValueError):
        return False
    return bool(addresses) and all(address.is_global for address in addresses)


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "ModuleUpdateError",
    "ModuleUpdateStatus",
    "ResolvedRootModuleUpdate",
    "RootModuleUpdateEntry",
    "RootModuleUpdateIssue",
    "RootModuleUpdateResult",
    "RootModuleUpdateService",
]
