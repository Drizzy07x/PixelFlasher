"""Verified, bounded backup and restore workflows for ``/data/adb``.

The browser can provide only opaque native grants.  Backup payloads are
created under a nonce-scoped device staging path, pulled into a private host
staging directory, inspected as tar data, and published atomically as a
``.pfdataadb`` container.  Restore performs the inverse operation only after
the closed manifest, payload hash, member types, paths and per-file hashes
have all been validated by the backend.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tarfile
import time
import zipfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import IO, Protocol, cast

from .contracts import (
    AppCommand,
    AppSnapshot,
    DeviceInfo,
    FileArtifact,
    OperationPlan,
    OperationPostcondition,
    OperationResult,
    OperationRisk,
    ProcessRequest,
)
from .executor import CancellationToken, CommandExecutor
from .grants import (
    AtomicWriteOutcomeUnknownError,
    BoundReadFile,
    BoundWriteFile,
    GrantError,
)

DATA_ADB_COMMANDS = frozenset(
    {
        "root.dataAdb.backup",
        "root.dataAdb.restore",
        "root.dataAdb.clear",
    }
)

_KIND = "pixelflasher.data_adb"
_SCHEMA_VERSION = 1
_CONTAINER_MEMBERS = frozenset({"manifest.json", "payload.tar"})
_SAFE_MEMBER = re.compile(r"^[A-Za-z0-9._+@=-]+(?:/[A-Za-z0-9._+@=-]+)*$")
_SAFE_DEVICE_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+ -]{0,127}$")
_CONTAINER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,191}\.pfdataadb$", re.I)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REMOTE_MARKER = re.compile(r"^PF_DAB\|([0-9a-f]{64})\|([0-9]{1,12})$")
_RESTORE_MARKER = re.compile(r"^PF_DAB_RESTORED\|([0-9a-f]{64})\|([0-9]{1,6})$")
_CLEAR_MARKER = "PF_DAB_CLEARED|0"

_MAX_PAYLOAD_BYTES = 2 * 1024 * 1024 * 1024
_MAX_CONTAINER_BYTES = _MAX_PAYLOAD_BYTES + 32 * 1024 * 1024
_MAX_MANIFEST_BYTES = 16 * 1024 * 1024
_MAX_ENTRIES = 20_000
_MAX_MEMBER_BYTES = 512 * 1024 * 1024
_MAX_PATH_BYTES = 512
_COPY_CHUNK = 1024 * 1024


class CancellationProbe(Protocol):
    @property
    def cancelled(self) -> bool: ...


class DataAdbError(ValueError):
    """Stable planning/finalization failure for a data-adb workflow."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class DataAdbEntry:
    path: str
    kind: str
    mode: int
    uid: int
    gid: int
    size: int
    sha256: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "kind": self.kind,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
            "size": self.size,
            "sha256": self.sha256,
        }

    def verification_line(self) -> str:
        digest = self.sha256 or "-"
        return (
            f"{self.kind}|{self.mode:o}|{self.uid}|{self.gid}|"
            f"{self.size}|{digest}|{self.path}\n"
        )


@dataclass(frozen=True, slots=True)
class DataAdbManifest:
    created_at: int
    device_codename: str
    source_build: str
    payload_sha256: str
    payload_size: int
    content_fingerprint: str
    entries: tuple[DataAdbEntry, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": _SCHEMA_VERSION,
            "kind": _KIND,
            "createdAt": self.created_at,
            "deviceCodename": self.device_codename,
            "sourceBuild": self.source_build,
            "payloadSha256": self.payload_sha256,
            "payloadSize": self.payload_size,
            "contentFingerprint": self.content_fingerprint,
            "entryCount": len(self.entries),
            "entries": [entry.to_dict() for entry in self.entries],
        }


@dataclass(frozen=True, slots=True)
class DataAdbCompilation:
    plan: OperationPlan
    action: str
    local_payload: Path = field(repr=False)
    remote_payload: str
    device_codename: str = ""
    source_build: str = ""
    destination: BoundWriteFile | None = field(default=None, repr=False)
    local_verification: Path | None = field(default=None, repr=False)
    remote_verification: str | None = None
    manifest: DataAdbManifest | None = None
    device_write: bool = False
    destructive: bool = False
    requires_confirmation: bool = False
    mutation_request_index: int | None = None


class DataAdbService:
    """Compile and execute the three closed ``/data/adb`` operations."""

    def __init__(self, temporary_root: str | Path | None = None) -> None:
        self._owned_temporary_root: TemporaryDirectory[str] | None = None
        if temporary_root is None:
            self._owned_temporary_root = TemporaryDirectory(
                prefix="pixelflasher-data-adb-"
            )
            root = Path(self._owned_temporary_root.name)
        else:
            root = Path(temporary_root).expanduser().resolve(strict=True)
        if not root.is_dir():
            raise ValueError("data-adb temporary root must be a directory")
        self.temporary_root = root

    def compile(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        cancellation: CancellationProbe | None = None,
    ) -> DataAdbCompilation:
        self._check_cancelled(cancellation)
        if command.kind not in DATA_ADB_COMMANDS:
            raise DataAdbError(
                "data_adb_command_unsupported",
                f"unsupported /data/adb command: {command.kind}",
            )
        self._revision(command, snapshot)
        device = self._device(command, snapshot)
        adb = self._adb(snapshot)
        nonce = hashlib.sha256(command.operation_id.encode("utf-8")).hexdigest()[:24]
        local_payload = self.temporary_root / f"{nonce}.payload.tar"
        remote_payload = f"/data/local/tmp/pixelflasher-data-adb-{nonce}.tar"
        self._remove_local(local_payload)

        if command.kind == "root.dataAdb.backup":
            return self._compile_backup(
                command,
                snapshot,
                device,
                adb,
                local_payload,
                remote_payload,
            )
        if command.kind == "root.dataAdb.restore":
            return self._compile_restore(
                command,
                snapshot,
                device,
                adb,
                nonce,
                local_payload,
                remote_payload,
                cancellation,
            )
        return self._compile_clear(command, snapshot, device, adb, local_payload)

    def _compile_backup(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
        local_payload: Path,
        remote_payload: str,
    ) -> DataAdbCompilation:
        self._validate_payload(command, {"serial", "destination"})
        destination = command.payload.get("destination")
        if not isinstance(destination, BoundWriteFile):
            raise DataAdbError(
                "data_adb_destination_grant_required",
                "backup requires an opaque native write destination",
            )
        if _CONTAINER_NAME.fullmatch(destination.name) is None:
            raise DataAdbError(
                "data_adb_destination_invalid",
                "backup destination must use a safe .pfdataadb file name",
            )
        codename, build = self._device_identity(device)
        script = (
            f"target={remote_payload}; rm -f -- \"$target\"; umask 077; "
            'tar -C /data/adb -cf "$target" . || exit 81; '
            'size=$(stat -c %s "$target") || exit 82; '
            f'[ "$size" -gt 0 ] && [ "$size" -le {_MAX_PAYLOAD_BYTES} ] || exit 83; '
            'digest=$(sha256sum "$target" | cut -d " " -f 1) || exit 84; '
            'chown shell:shell "$target" && chmod 0600 "$target" || exit 85; '
            'printf "PF_DAB|%s|%s\\n" "$digest" "$size"'
        )
        requests = (
            ProcessRequest(
                (adb, "-s", device.serial, "shell", "su", "-c", script),
                timeout_seconds=20 * 60.0,
                output_limit_bytes=64 * 1024,
            ),
            ProcessRequest(
                (adb, "-s", device.serial, "pull", remote_payload, str(local_payload)),
                timeout_seconds=30 * 60.0,
                output_limit_bytes=64 * 1024,
            ),
            self._cleanup_request(adb, device.serial, remote_payload),
        )
        plan = self._base_plan(
            snapshot,
            device,
            requests,
            label=f"Back up /data/adb from {device.serial}",
            risk=OperationRisk.MUTATING,
            postconditions=(
                OperationPostcondition(
                    "data_adb_backup_verified",
                    {"fileName": destination.name},
                    "the archive manifest, members, hashes, cleanup and atomic publication are verified",
                ),
            ),
        )
        return DataAdbCompilation(
            plan,
            "backup",
            local_payload,
            remote_payload,
            device_codename=codename,
            source_build=build,
            destination=destination,
            requires_confirmation=True,
        )

    def _compile_restore(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
        nonce: str,
        local_payload: Path,
        remote_payload: str,
        cancellation: CancellationProbe | None,
    ) -> DataAdbCompilation:
        self._validate_payload(
            command,
            {"serial", "source", "confirmationText"},
        )
        required = self.required_restore_confirmation(device.serial)
        if command.payload.get("confirmationText") != required:
            raise DataAdbError(
                "data_adb_restore_confirmation_required",
                f"type {required} to replace /data/adb contents",
            )
        source = command.payload.get("source")
        if not isinstance(source, BoundReadFile):
            raise DataAdbError(
                "data_adb_source_grant_required",
                "restore requires an opaque native read grant",
            )
        manifest = self._read_container(source, local_payload, cancellation)
        codename, build = self._device_identity(device)
        if manifest.device_codename.casefold() != codename.casefold():
            raise DataAdbError(
                "data_adb_device_incompatible",
                "backup codename does not match the selected device",
            )
        local_verification = self.temporary_root / f"{nonce}.entries"
        self._remove_local(local_verification)
        self._write_verification_file(local_verification, manifest.entries)
        verification_digest = self._sha256_file(local_verification, cancellation)
        remote_verification = (
            f"/data/local/tmp/pixelflasher-data-adb-{nonce}.entries"
        )
        stage = f"/data/local/tmp/pixelflasher-data-adb-{nonce}.stage"
        script = self._restore_script(
            remote_payload,
            remote_verification,
            stage,
            manifest,
            verification_digest,
        )
        requests = (
            ProcessRequest(
                (adb, "-s", device.serial, "push", str(local_payload), remote_payload),
                timeout_seconds=30 * 60.0,
                output_limit_bytes=64 * 1024,
            ),
            ProcessRequest(
                (
                    adb,
                    "-s",
                    device.serial,
                    "push",
                    str(local_verification),
                    remote_verification,
                ),
                timeout_seconds=5 * 60.0,
                output_limit_bytes=64 * 1024,
            ),
            ProcessRequest(
                (adb, "-s", device.serial, "shell", "su", "-c", script),
                timeout_seconds=30 * 60.0,
                output_limit_bytes=64 * 1024,
            ),
            self._cleanup_request(
                adb,
                device.serial,
                remote_payload,
                remote_verification,
                stage,
                root=True,
            ),
        )
        artifacts = (
            FileArtifact(
                str(local_payload),
                manifest.payload_sha256,
                "data-adb-payload",
            ),
            FileArtifact(
                str(local_verification),
                verification_digest,
                "data-adb-verification-manifest",
            ),
        )
        plan = self._base_plan(
            snapshot,
            device,
            requests,
            label=f"Restore /data/adb on {device.serial}",
            data_behavior="data_adb_replace",
            artifacts=artifacts,
            risk=OperationRisk.DESTRUCTIVE,
            postconditions=(
                OperationPostcondition(
                    "data_adb_restore_verified",
                    {
                        "contentFingerprint": manifest.content_fingerprint,
                        "entryCount": len(manifest.entries),
                    },
                    "the restored tree matches every validated manifest entry",
                ),
            ),
        )
        return DataAdbCompilation(
            plan,
            "restore",
            local_payload,
            remote_payload,
            device_codename=codename,
            source_build=build,
            local_verification=local_verification,
            remote_verification=remote_verification,
            manifest=manifest,
            device_write=True,
            destructive=True,
            requires_confirmation=True,
            mutation_request_index=2,
        )

    def _compile_clear(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
        local_payload: Path,
    ) -> DataAdbCompilation:
        self._validate_payload(command, {"serial", "confirmationText"})
        required = self.required_clear_confirmation(device.serial)
        if command.payload.get("confirmationText") != required:
            raise DataAdbError(
                "data_adb_clear_confirmation_required",
                f"type {required} to clear /data/adb contents",
            )
        script = (
            "find /data/adb -mindepth 1 -maxdepth 1 "
            "-exec rm -rf -- {} \\; || exit 91; "
            'remaining=$(find /data/adb -mindepth 1 -print -quit); '
            '[ -z "$remaining" ] || exit 92; '
            f'printf "{_CLEAR_MARKER}\\n"'
        )
        request = ProcessRequest(
            (adb, "-s", device.serial, "shell", "su", "-c", script),
            timeout_seconds=10 * 60.0,
            output_limit_bytes=64 * 1024,
        )
        plan = self._base_plan(
            snapshot,
            device,
            (request,),
            label=f"Clear /data/adb on {device.serial}",
            data_behavior="data_adb_clear",
            risk=OperationRisk.DESTRUCTIVE,
            postconditions=(
                OperationPostcondition(
                    "data_adb_empty",
                    {"empty": True},
                    "/data/adb contains no entries",
                ),
            ),
        )
        return DataAdbCompilation(
            plan,
            "clear",
            local_payload,
            remote_payload="",
            device_write=True,
            destructive=True,
            requires_confirmation=True,
            mutation_request_index=0,
        )

    def execute(
        self,
        compilation: DataAdbCompilation,
        command: AppCommand,
        executor: CommandExecutor,
        cancellation: CancellationToken,
    ) -> OperationResult:
        cleanup = compilation.plan.requests[-1] if compilation.action != "clear" else None
        main_requests = (
            compilation.plan.requests[:-1]
            if cleanup is not None
            else compilation.plan.requests
        )
        results: list[OperationResult] = []
        cleanup_verified = cleanup is None
        try:
            for request_index, request in enumerate(main_requests):
                result = executor.execute(
                    command,
                    replace(compilation.plan, requests=(request,)),
                    cancellation,
                )
                results.append(result)
                if not result.ok:
                    if self._failure_may_follow_mutation(
                        compilation,
                        request_index,
                        result,
                    ):
                        return OperationResult.failed(
                            command.operation_id,
                            code="outcome_unknown",
                            message=(
                                f"{compilation.action} stopped after /data/adb "
                                "may have begun changing"
                            ),
                            exit_code=result.exit_code,
                            stdout=result.stdout,
                            stderr=result.stderr,
                        )
                    return result
            if cleanup is not None:
                cleaned = executor.execute(
                    command,
                    replace(compilation.plan, requests=(cleanup,)),
                    CancellationToken(),
                )
                if not cleaned.ok:
                    return OperationResult.failed(
                        command.operation_id,
                        code="data_adb_cleanup_failed",
                        message="device staging could not be removed",
                    )
                cleanup_verified = True
            if compilation.action == "backup":
                return self._finalize_backup(
                    compilation,
                    command.operation_id,
                    results,
                    cancellation,
                    cleanup_verified,
                )
            if compilation.action == "restore":
                return self._finalize_restore(
                    compilation,
                    command.operation_id,
                    results,
                    cleanup_verified,
                )
            return self._finalize_clear(
                command.operation_id,
                cast(str, compilation.plan.target_serial),
                results,
            )
        finally:
            if cleanup is not None and not cleanup_verified:
                executor.execute(
                    command,
                    replace(compilation.plan, requests=(cleanup,)),
                    CancellationToken(),
                )
            self._remove_local(compilation.local_payload)
            if compilation.local_verification is not None:
                self._remove_local(compilation.local_verification)

    @staticmethod
    def _failure_may_follow_mutation(
        compilation: DataAdbCompilation,
        request_index: int,
        result: OperationResult,
    ) -> bool:
        boundary = compilation.mutation_request_index
        if boundary is None or request_index < boundary:
            return False
        # Restore exit codes 101-114 are emitted while validating the private
        # staging tree, before the script touches /data/adb. Any other result
        # from that request is ambiguous (including transport loss). Clear
        # starts deleting immediately, so every failed clear is ambiguous.
        return not (
            compilation.action == "restore"
            and result.exit_code is not None
            and 101 <= result.exit_code <= 114
        )

    def _finalize_backup(
        self,
        compilation: DataAdbCompilation,
        operation_id: str,
        results: list[OperationResult],
        cancellation: CancellationToken,
        cleanup_verified: bool,
    ) -> OperationResult:
        destination = compilation.destination
        if destination is None or len(results) != 2 or not cleanup_verified:
            return OperationResult.failed(
                operation_id,
                code="data_adb_backup_plan_invalid",
                message="backup execution did not complete its typed staging plan",
            )
        marker = self._single_marker(results[0].stdout, _REMOTE_MARKER)
        if marker is None:
            return OperationResult.failed(
                operation_id,
                code="data_adb_backup_evidence_invalid",
                message="device backup did not return bounded hash evidence",
            )
        remote_hash, raw_size = marker.groups()
        remote_size = int(raw_size, 10)
        try:
            payload_size = compilation.local_payload.stat().st_size
            if payload_size != remote_size or not 0 < payload_size <= _MAX_PAYLOAD_BYTES:
                raise DataAdbError(
                    "data_adb_payload_size_mismatch",
                    "pulled payload size differs from device evidence",
                )
            payload_hash = self._sha256_file(compilation.local_payload, cancellation)
            if payload_hash != remote_hash:
                raise DataAdbError(
                    "data_adb_payload_hash_mismatch",
                    "pulled payload hash differs from device evidence",
                )
            entries = self._inspect_tar(compilation.local_payload, cancellation)
            manifest = self._manifest(
                compilation.device_codename,
                compilation.source_build,
                payload_hash,
                payload_size,
                entries,
            )
            package_hash, package_size = self._publish_container(
                destination,
                compilation.local_payload,
                manifest,
                cancellation,
            )
        except InterruptedError:
            return OperationResult.cancelled(
                operation_id,
                code="data_adb_backup_cancelled",
                message="backup was cancelled before atomic publication",
            )
        except AtomicWriteOutcomeUnknownError as error:
            return OperationResult.failed(
                operation_id,
                code="outcome_unknown",
                message=str(error),
            )
        except (DataAdbError, GrantError, OSError, tarfile.TarError, zipfile.BadZipFile) as error:
            return OperationResult.failed(
                operation_id,
                code=getattr(error, "code", "data_adb_backup_failed"),
                message=str(error),
            )
        return OperationResult.success(
            operation_id,
            code="data_adb_backup_created",
            message="/data/adb backup manifest, hashes, cleanup and publication were verified",
            value={
                "action": "backup",
                "targetSerial": compilation.plan.target_serial,
                "fileName": destination.name,
                "sha256": package_hash,
                "sizeBytes": package_size,
                "payloadSha256": payload_hash,
                "entryCount": len(entries),
                "contentFingerprint": manifest.content_fingerprint,
                "deviceCodename": manifest.device_codename,
                "verified": True,
                "remoteCleaned": True,
            },
        )

    def _finalize_restore(
        self,
        compilation: DataAdbCompilation,
        operation_id: str,
        results: list[OperationResult],
        cleanup_verified: bool,
    ) -> OperationResult:
        manifest = compilation.manifest
        if manifest is None or len(results) != 3 or not cleanup_verified:
            return OperationResult.failed(
                operation_id,
                code="data_adb_restore_plan_invalid",
                message="restore execution did not complete its typed staging plan",
            )
        marker = self._single_marker(results[-1].stdout, _RESTORE_MARKER)
        if (
            marker is None
            or marker.group(1) != manifest.content_fingerprint
            or int(marker.group(2), 10) != len(manifest.entries)
        ):
            return OperationResult.failed(
                operation_id,
                code="data_adb_restore_postcondition_mismatch",
                message="restored tree does not match the validated manifest",
            )
        return OperationResult.success(
            operation_id,
            code="data_adb_restore_completed",
            message="/data/adb restore and every manifest entry were verified",
            value={
                "action": "restore",
                "targetSerial": compilation.plan.target_serial,
                "payloadSha256": manifest.payload_sha256,
                "entryCount": len(manifest.entries),
                "contentFingerprint": manifest.content_fingerprint,
                "deviceCodename": manifest.device_codename,
                "verified": True,
                "remoteCleaned": True,
            },
        )

    @staticmethod
    def _finalize_clear(
        operation_id: str,
        target_serial: str,
        results: list[OperationResult],
    ) -> OperationResult:
        if (
            len(results) != 1
            or DataAdbService._single_line(results[0].stdout) != _CLEAR_MARKER
        ):
            return OperationResult.failed(
                operation_id,
                code="data_adb_clear_postcondition_mismatch",
                message="clear operation did not prove /data/adb is empty",
            )
        return OperationResult.success(
            operation_id,
            code="data_adb_clear_completed",
            message="/data/adb is empty",
            value={
                "action": "clear",
                "targetSerial": target_serial,
                "empty": True,
                "verified": True,
            },
        )

    def _read_container(
        self,
        source: BoundReadFile,
        local_payload: Path,
        cancellation: CancellationProbe | None,
    ) -> DataAdbManifest:
        if not source.path.name.casefold().endswith(".pfdataadb"):
            raise DataAdbError(
                "data_adb_container_extension_invalid",
                "restore source must use the .pfdataadb extension",
            )
        try:
            with source.open_verified() as stream:
                size = self._stream_size(stream)
                if not 1 <= size <= _MAX_CONTAINER_BYTES:
                    raise DataAdbError(
                        "data_adb_container_size_invalid",
                        "backup container is outside its size limit",
                    )
                with zipfile.ZipFile(stream) as archive:
                    infos = archive.infolist()
                    names = [info.filename for info in infos]
                    if (
                        len(names) != 2
                        or frozenset(names) != _CONTAINER_MEMBERS
                        or len(names) != len(set(names))
                        or any(info.flag_bits & 0x1 for info in infos)
                    ):
                        raise DataAdbError(
                            "data_adb_container_members_invalid",
                            "backup container members are invalid",
                        )
                    manifest_info = archive.getinfo("manifest.json")
                    payload_info = archive.getinfo("payload.tar")
                    if (
                        not 1 <= manifest_info.file_size <= _MAX_MANIFEST_BYTES
                        or not 1 <= payload_info.file_size <= _MAX_PAYLOAD_BYTES
                    ):
                        raise DataAdbError(
                            "data_adb_container_members_invalid",
                            "backup container member size is invalid",
                        )
                    manifest_raw = archive.read(manifest_info)
                    self._copy_zip_member(
                        archive,
                        payload_info,
                        local_payload,
                        cancellation,
                    )
        except DataAdbError:
            self._remove_local(local_payload)
            raise
        except (GrantError, OSError, zipfile.BadZipFile, KeyError) as error:
            self._remove_local(local_payload)
            raise DataAdbError("data_adb_container_invalid", str(error)) from error
        manifest = self._parse_manifest(manifest_raw)
        payload_hash = self._sha256_file(local_payload, cancellation)
        if (
            local_payload.stat().st_size != manifest.payload_size
            or payload_hash != manifest.payload_sha256
        ):
            self._remove_local(local_payload)
            raise DataAdbError(
                "data_adb_payload_hash_mismatch",
                "container payload does not match its manifest",
            )
        inspected = self._inspect_tar(local_payload, cancellation)
        if inspected != manifest.entries:
            self._remove_local(local_payload)
            raise DataAdbError(
                "data_adb_manifest_mismatch",
                "tar entries do not match the closed manifest",
            )
        return manifest

    def _inspect_tar(
        self,
        path: Path,
        cancellation: CancellationProbe | None,
    ) -> tuple[DataAdbEntry, ...]:
        entries: list[DataAdbEntry] = []
        seen: set[str] = set()
        total_file_bytes = 0
        with tarfile.open(path, mode="r:") as archive:
            for member in archive:
                self._check_cancelled(cancellation)
                normalized = self._member_path(member.name)
                if normalized is None:
                    continue
                identity = normalized.casefold()
                if identity in seen or len(entries) >= _MAX_ENTRIES:
                    raise DataAdbError(
                        "data_adb_tar_ambiguous",
                        "backup tar contains duplicate or too many entries",
                    )
                if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                    raise DataAdbError(
                        "data_adb_tar_type_unsafe",
                        "backup tar contains links or special files",
                    )
                if getattr(member, "sparse", None):
                    raise DataAdbError(
                        "data_adb_tar_sparse_unsupported",
                        "sparse tar entries are not supported",
                    )
                mode = stat.S_IMODE(member.mode)
                if not 0 <= member.uid <= 2_147_483_647 or not 0 <= member.gid <= 2_147_483_647:
                    raise DataAdbError(
                        "data_adb_tar_identity_invalid",
                        "tar owner metadata is outside its bounds",
                    )
                if member.isdir():
                    entry = DataAdbEntry(
                        normalized,
                        "D",
                        mode,
                        member.uid,
                        member.gid,
                        0,
                        None,
                    )
                else:
                    if not 0 <= member.size <= _MAX_MEMBER_BYTES:
                        raise DataAdbError(
                            "data_adb_tar_member_oversized",
                            "tar member exceeds its size limit",
                        )
                    total_file_bytes += member.size
                    if total_file_bytes > _MAX_PAYLOAD_BYTES:
                        raise DataAdbError(
                            "data_adb_tar_oversized",
                            "tar contents exceed their aggregate size limit",
                        )
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        raise DataAdbError(
                            "data_adb_tar_member_invalid",
                            "regular tar member cannot be read",
                        )
                    digest = self._hash_stream(extracted, cancellation)
                    entry = DataAdbEntry(
                        normalized,
                        "F",
                        mode,
                        member.uid,
                        member.gid,
                        member.size,
                        digest,
                    )
                entries.append(entry)
                seen.add(identity)
        return tuple(sorted(entries, key=lambda item: (item.path.casefold(), item.path)))

    @staticmethod
    def _member_path(name: str) -> str | None:
        if not isinstance(name, str) or "\x00" in name or "\\" in name:
            raise DataAdbError("data_adb_tar_path_unsafe", "tar member path is unsafe")
        value = name
        while value.startswith("./"):
            value = value[2:]
        value = value.rstrip("/")
        if value in {"", "."}:
            return None
        try:
            encoded = value.encode("ascii")
        except UnicodeEncodeError as error:
            raise DataAdbError(
                "data_adb_tar_path_unsafe",
                "tar member paths must use bounded ASCII names",
            ) from error
        if (
            len(encoded) > _MAX_PATH_BYTES
            or value.startswith("/")
            or ".." in value.split("/")
            or _SAFE_MEMBER.fullmatch(value) is None
        ):
            raise DataAdbError("data_adb_tar_path_unsafe", "tar member path is unsafe")
        return value

    def _manifest(
        self,
        codename: str,
        build: str,
        payload_hash: str,
        payload_size: int,
        entries: tuple[DataAdbEntry, ...],
    ) -> DataAdbManifest:
        fingerprint = self._entries_fingerprint(entries)
        return DataAdbManifest(
            int(time.time()),
            codename,
            build,
            payload_hash,
            payload_size,
            fingerprint,
            entries,
        )

    def _parse_manifest(self, raw: bytes) -> DataAdbManifest:
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise DataAdbError(
                "data_adb_manifest_invalid",
                "manifest must be valid UTF-8 JSON",
            ) from error
        if not isinstance(parsed, dict):
            raise DataAdbError(
                "data_adb_manifest_invalid",
                "manifest schema is not closed",
            )
        document = cast(dict[str, object], parsed)
        if set(document) != {
            "schemaVersion",
            "kind",
            "createdAt",
            "deviceCodename",
            "sourceBuild",
            "payloadSha256",
            "payloadSize",
            "contentFingerprint",
            "entryCount",
            "entries",
        }:
            raise DataAdbError(
                "data_adb_manifest_invalid",
                "manifest schema is not closed",
            )
        if document["schemaVersion"] != _SCHEMA_VERSION or document["kind"] != _KIND:
            raise DataAdbError(
                "data_adb_manifest_unsupported",
                "manifest schema or kind is unsupported",
            )
        created_at = document["createdAt"]
        codename = document["deviceCodename"]
        build = document["sourceBuild"]
        payload_hash = document["payloadSha256"]
        payload_size = document["payloadSize"]
        fingerprint = document["contentFingerprint"]
        raw_entries = document["entries"]
        typed_entries = (
            cast(list[object], raw_entries) if isinstance(raw_entries, list) else None
        )
        if (
            not isinstance(created_at, int)
            or isinstance(created_at, bool)
            or not 0 <= created_at <= 9_999_999_999
            or not isinstance(codename, str)
            or _SAFE_DEVICE_VALUE.fullmatch(codename) is None
            or not isinstance(build, str)
            or _SAFE_DEVICE_VALUE.fullmatch(build) is None
            or not isinstance(payload_hash, str)
            or _SHA256.fullmatch(payload_hash) is None
            or not isinstance(payload_size, int)
            or isinstance(payload_size, bool)
            or not 1 <= payload_size <= _MAX_PAYLOAD_BYTES
            or not isinstance(fingerprint, str)
            or _SHA256.fullmatch(fingerprint) is None
            or typed_entries is None
            or len(typed_entries) > _MAX_ENTRIES
            or document["entryCount"] != len(typed_entries)
        ):
            raise DataAdbError(
                "data_adb_manifest_invalid",
                "manifest metadata is invalid",
            )
        entries: list[DataAdbEntry] = []
        for raw_entry in typed_entries:
            if not isinstance(raw_entry, dict):
                raise DataAdbError(
                    "data_adb_manifest_invalid",
                    "manifest entry schema is invalid",
                )
            entry_record = cast(dict[str, object], raw_entry)
            if set(entry_record) != {
                "path",
                "kind",
                "mode",
                "uid",
                "gid",
                "size",
                "sha256",
            }:
                raise DataAdbError(
                    "data_adb_manifest_invalid",
                    "manifest entry schema is invalid",
                )
            path = entry_record["path"]
            kind = entry_record["kind"]
            mode = entry_record["mode"]
            uid = entry_record["uid"]
            gid = entry_record["gid"]
            size = entry_record["size"]
            digest = entry_record["sha256"]
            if (
                not isinstance(path, str)
                or self._member_path(path) != path
                or kind not in {"D", "F"}
                or not isinstance(mode, int)
                or isinstance(mode, bool)
                or not 0 <= mode <= 0o7777
                or not isinstance(uid, int)
                or isinstance(uid, bool)
                or not 0 <= uid <= 2_147_483_647
                or not isinstance(gid, int)
                or isinstance(gid, bool)
                or not 0 <= gid <= 2_147_483_647
                or not isinstance(size, int)
                or isinstance(size, bool)
                or not 0 <= size <= _MAX_MEMBER_BYTES
                or (kind == "D" and (size != 0 or digest is not None))
                or (
                    kind == "F"
                    and (not isinstance(digest, str) or _SHA256.fullmatch(digest) is None)
                )
            ):
                raise DataAdbError(
                    "data_adb_manifest_invalid",
                    "manifest entry value is invalid",
                )
            entries.append(
                DataAdbEntry(
                    path,
                    cast(str, kind),
                    mode,
                    uid,
                    gid,
                    size,
                    cast(str | None, digest),
                )
            )
        canonical = tuple(sorted(entries, key=lambda item: (item.path.casefold(), item.path)))
        if len({entry.path.casefold() for entry in canonical}) != len(canonical):
            raise DataAdbError(
                "data_adb_manifest_ambiguous",
                "manifest paths are duplicated",
            )
        if self._entries_fingerprint(canonical) != fingerprint:
            raise DataAdbError(
                "data_adb_manifest_fingerprint_mismatch",
                "manifest content fingerprint is invalid",
            )
        return DataAdbManifest(
            created_at,
            codename,
            build,
            payload_hash,
            payload_size,
            fingerprint,
            canonical,
        )

    def _publish_container(
        self,
        destination: BoundWriteFile,
        payload: Path,
        manifest: DataAdbManifest,
        cancellation: CancellationProbe | None,
    ) -> tuple[str, int]:
        manifest_bytes = json.dumps(
            manifest.to_dict(),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if len(manifest_bytes) > _MAX_MANIFEST_BYTES:
            raise DataAdbError(
                "data_adb_manifest_oversized",
                "generated manifest exceeds its size limit",
            )
        expected_hash = ""
        expected_size = 0
        with destination.begin_atomic_replace() as transaction:
            with zipfile.ZipFile(
                transaction.stream,
                mode="w",
                compression=zipfile.ZIP_STORED,
                allowZip64=True,
            ) as archive:
                archive.writestr("manifest.json", manifest_bytes)
                with archive.open("payload.tar", mode="w", force_zip64=True) as target:
                    with payload.open("rb") as source:
                        self._copy_stream(source, target, cancellation)
            transaction.stream.flush()
            os.fsync(transaction.stream.fileno())
            transaction.stream.seek(0)
            expected_hash = self._hash_stream(transaction.stream, cancellation)
            expected_size = transaction.stream.tell()
            if not 1 <= expected_size <= _MAX_CONTAINER_BYTES:
                raise DataAdbError(
                    "data_adb_container_size_invalid",
                    "generated container is outside its size limit",
                )
            self._check_cancelled(cancellation)
            transaction.commit()
            with transaction.open_committed() as committed:
                actual_hash = self._hash_stream(committed, cancellation, published=True)
                actual_size = committed.tell()
        if actual_hash != expected_hash or actual_size != expected_size:
            raise AtomicWriteOutcomeUnknownError(
                "published /data/adb backup differs from the verified staging container"
            )
        return actual_hash, actual_size

    def _restore_script(
        self,
        archive: str,
        verification: str,
        stage: str,
        manifest: DataAdbManifest,
        verification_digest: str,
    ) -> str:
        verify = (
            "verify_tree() { root=$1; seen=0; "
            "while IFS='|' read -r kind mode uid gid size digest rel; do "
            '[ -n "$rel" ] || exit 101; path="$root/$rel"; '
            'case "$kind" in D) [ -d "$path" ] && [ ! -L "$path" ] || exit 102;; '
            'F) [ -f "$path" ] && [ ! -L "$path" ] || exit 103; '
            'actual=$(sha256sum "$path" | cut -d " " -f 1) || exit 104; '
            '[ "$actual" = "$digest" ] || exit 105;; *) exit 106;; esac; '
            'meta=$(stat -c "%a|%u|%g|%s" "$path") || exit 107; '
            'expected="$mode|$uid|$gid|$size"; [ "$meta" = "$expected" ] || exit 108; '
            "seen=$((seen + 1)); done < \"$manifest_file\"; "
            'actual_count=$(find "$root" -mindepth 1 \\( -type f -o -type d \\) | wc -l); '
            '[ "$seen" -eq "$actual_count" ] || exit 109; '
            'special=$(find "$root" -mindepth 1 ! -type f ! -type d -print -quit); '
            '[ -z "$special" ] || exit 110; }; '
        )
        return (
            f"archive={archive}; manifest_file={verification}; stage={stage}; "
            'cleanup() { rm -rf -- "$archive" "$manifest_file" "$stage"; }; '
            "trap cleanup EXIT; "
            f'archive_hash=$(sha256sum "$archive" | cut -d " " -f 1); '
            f'[ "$archive_hash" = "{manifest.payload_sha256}" ] || exit 111; '
            'manifest_hash=$(sha256sum "$manifest_file" | cut -d " " -f 1); '
            f'[ "$manifest_hash" = "{verification_digest}" ] || exit 112; '
            'rm -rf -- "$stage"; mkdir -p "$stage" || exit 113; '
            'tar -C "$stage" -xpf "$archive" || exit 114; '
            + verify
            + 'verify_tree "$stage" || exit $?; '
            + "find /data/adb -mindepth 1 -maxdepth 1 -exec rm -rf -- {} \\; || exit 115; "
            + 'cp -a "$stage/." /data/adb/ || exit 116; '
            + "command -v restorecon >/dev/null 2>&1 || exit 117; "
            + "restorecon -RF /data/adb >/dev/null 2>&1 || exit 118; "
            + 'verify_tree /data/adb || exit 119; '
            + f'printf "PF_DAB_RESTORED|{manifest.content_fingerprint}|{len(manifest.entries)}\\n"'
        )

    @staticmethod
    def _cleanup_request(
        adb: str,
        serial: str,
        *paths: str,
        root: bool = False,
    ) -> ProcessRequest:
        if not paths or any(re.fullmatch(r"/data/local/tmp/pixelflasher-data-adb-[A-Za-z0-9.-]+", path) is None for path in paths):
            raise DataAdbError(
                "data_adb_cleanup_path_invalid",
                "cleanup path is outside the backend staging namespace",
            )
        argv = (adb, "-s", serial, "shell")
        if root:
            argv += ("su", "-c", f"rm -rf -- {' '.join(paths)}")
        else:
            argv += ("rm", "-f", "--", *paths)
        return ProcessRequest(
            argv,
            timeout_seconds=60.0,
            output_limit_bytes=64 * 1024,
        )

    @staticmethod
    def _base_plan(
        snapshot: AppSnapshot,
        device: DeviceInfo,
        requests: tuple[ProcessRequest, ...],
        *,
        label: str,
        data_behavior: str = "preserve",
        artifacts: tuple[FileArtifact, ...] = (),
        risk: OperationRisk,
        postconditions: tuple[OperationPostcondition, ...],
    ) -> OperationPlan:
        return OperationPlan(
            requests=requests,
            label=label,
            snapshot_revision=snapshot.revision,
            target_serial=device.serial,
            expected_codename=device.codename,
            expected_device_state=device.mode,
            firmware_hash=snapshot.firmware.hash,
            boot_hash=snapshot.boot.hash,
            data_behavior=data_behavior,
            plan_revision=snapshot.plan.revision,
            fingerprint=snapshot.plan.fingerprint,
            artifacts=artifacts,
            risk=risk,
            postconditions=postconditions,
        )

    @staticmethod
    def required_restore_confirmation(serial: str) -> str:
        return f"RESTORE DATAADB {DataAdbService._serial_suffix(serial)}"

    @staticmethod
    def required_clear_confirmation(serial: str) -> str:
        return f"CLEAR DATAADB {DataAdbService._serial_suffix(serial)}"

    @staticmethod
    def _serial_suffix(serial: str) -> str:
        if not isinstance(serial, str) or not serial.strip():
            raise DataAdbError("target_serial_invalid", "target serial is required")
        return serial.strip()[-6:].upper()

    @staticmethod
    def _device_identity(device: DeviceInfo) -> tuple[str, str]:
        codename = device.codename.strip()
        build = device.build.strip()
        if (
            _SAFE_DEVICE_VALUE.fullmatch(codename) is None
            or _SAFE_DEVICE_VALUE.fullmatch(build) is None
        ):
            raise DataAdbError(
                "data_adb_device_identity_unverified",
                "device codename and build are required for a portable backup",
            )
        return codename, build

    @staticmethod
    def _device(command: AppCommand, snapshot: AppSnapshot) -> DeviceInfo:
        raw = command.payload.get("serial")
        if not isinstance(raw, str) or not raw.strip():
            raise DataAdbError("target_serial_required", "one target serial is required")
        serial = raw.strip()
        if command.target_serial and command.target_serial != serial:
            raise DataAdbError(
                "ambiguous_target_serial",
                "command and payload target different devices",
            )
        if serial not in snapshot.selected_serials:
            raise DataAdbError(
                "target_serial_changed",
                "target serial is no longer selected",
            )
        device = next((item for item in snapshot.devices if item.serial == serial), None)
        if device is None or not device.online:
            raise DataAdbError("device_disconnected", "target device is not online")
        if device.mode != "adb" or not device.root:
            raise DataAdbError(
                "data_adb_root_required",
                "/data/adb operations require one rooted device in ADB mode",
            )
        return device

    @staticmethod
    def _adb(snapshot: AppSnapshot) -> str:
        if not snapshot.toolchain.ready or not snapshot.toolchain.adb:
            raise DataAdbError("toolchain_not_ready", "validated adb is required")
        return snapshot.toolchain.adb

    @staticmethod
    def _revision(command: AppCommand, snapshot: AppSnapshot) -> None:
        if command.expected_revision is None:
            raise DataAdbError("revision_required", "expected_revision is required")
        if command.expected_revision != snapshot.revision:
            raise DataAdbError(
                "stale_revision",
                f"state revision changed: expected {command.expected_revision}, current {snapshot.revision}",
            )

    @staticmethod
    def _validate_payload(command: AppCommand, allowed: set[str]) -> None:
        unknown = set(command.payload) - allowed
        if unknown:
            raise DataAdbError(
                "invalid_data_adb_payload",
                f"unsupported semantic field: {sorted(unknown)[0]}",
            )

    @staticmethod
    def _entries_fingerprint(entries: tuple[DataAdbEntry, ...]) -> str:
        canonical = json.dumps(
            [entry.to_dict() for entry in entries],
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    @staticmethod
    def _write_verification_file(
        path: Path,
        entries: tuple[DataAdbEntry, ...],
    ) -> None:
        try:
            with path.open("x", encoding="ascii", newline="\n") as stream:
                for entry in entries:
                    stream.write(entry.verification_line())
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as error:
            raise DataAdbError(
                "data_adb_staging_failed",
                "verification manifest could not be staged",
            ) from error

    @staticmethod
    def _copy_zip_member(
        archive: zipfile.ZipFile,
        info: zipfile.ZipInfo,
        destination: Path,
        cancellation: CancellationProbe | None,
    ) -> None:
        try:
            with archive.open(info) as source, destination.open("xb") as target:
                DataAdbService._copy_stream(source, target, cancellation)
                target.flush()
                os.fsync(target.fileno())
        except OSError as error:
            raise DataAdbError(
                "data_adb_staging_failed",
                "container payload could not be staged",
            ) from error

    @staticmethod
    def _copy_stream(
        source: IO[bytes],
        target: IO[bytes],
        cancellation: CancellationProbe | None,
    ) -> int:
        copied = 0
        while chunk := source.read(_COPY_CHUNK):
            DataAdbService._check_cancelled(cancellation)
            copied += len(chunk)
            if copied > _MAX_PAYLOAD_BYTES:
                raise DataAdbError(
                    "data_adb_payload_oversized",
                    "payload exceeds its streaming size limit",
                )
            target.write(chunk)
        return copied

    @staticmethod
    def _sha256_file(
        path: Path,
        cancellation: CancellationProbe | None,
    ) -> str:
        try:
            before = path.stat()
            with path.open("rb") as stream:
                digest = DataAdbService._hash_stream(stream, cancellation)
            after = path.stat()
        except OSError as error:
            raise DataAdbError(
                "data_adb_hash_failed",
                "staged file could not be hashed",
            ) from error
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise DataAdbError(
                "data_adb_staging_changed",
                "staged file changed while it was being verified",
            )
        return digest

    @staticmethod
    def _hash_stream(
        stream: IO[bytes],
        cancellation: CancellationProbe | None,
        *,
        published: bool = False,
    ) -> str:
        digest = hashlib.sha256()
        while chunk := stream.read(_COPY_CHUNK):
            if cancellation is not None and cancellation.cancelled:
                if published:
                    raise AtomicWriteOutcomeUnknownError(
                        "backup cancellation occurred after atomic publication"
                    )
                raise InterruptedError("data-adb operation was cancelled")
            digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _stream_size(stream: IO[bytes]) -> int:
        current = stream.tell()
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        stream.seek(current)
        return size

    @staticmethod
    def _single_line(value: str) -> str | None:
        lines = [line.strip() for line in value.splitlines() if line.strip()]
        return lines[0] if len(lines) == 1 else None

    @staticmethod
    def _single_marker(value: str, pattern: re.Pattern[str]) -> re.Match[str] | None:
        line = DataAdbService._single_line(value)
        return pattern.fullmatch(line) if line is not None else None

    @staticmethod
    def _check_cancelled(cancellation: CancellationProbe | None) -> None:
        if cancellation is not None and cancellation.cancelled:
            raise InterruptedError("data-adb operation was cancelled")

    @staticmethod
    def _remove_local(path: Path) -> None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass

    def shutdown(self) -> None:
        owned = self._owned_temporary_root
        self._owned_temporary_root = None
        if owned is not None:
            owned.cleanup()


__all__ = [
    "DATA_ADB_COMMANDS",
    "DataAdbCompilation",
    "DataAdbEntry",
    "DataAdbError",
    "DataAdbManifest",
    "DataAdbService",
]
