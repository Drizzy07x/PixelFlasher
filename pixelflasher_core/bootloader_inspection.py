"""Bounded binary inspection of A/B bootloader partitions.

The legacy implementation copied complete ABL images through
``/data/local/tmp`` and loaded them into memory.  This module keeps the binary
boundary backend-owned: bytes are streamed directly from ADB, reduced to a
digest plus one validated version marker, and never enter an app snapshot or
public result.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import BinaryIO, Protocol, cast

from .cancellation import CancellationReason, CancellationToken
from .contracts import ProcessRequest
from .executor import SubprocessTransport

BOOTLOADER_PARTITION_LIMIT = 64 * 1024 * 1024
BOOTLOADER_STDERR_LIMIT = 64 * 1024
BOOTLOADER_READ_CHUNK = 1024 * 1024
BOOTLOADER_VERSION_LIMIT = 127
_CATALOG_LIMIT = 1024 * 1024
_CATALOG_ENTRY_LIMIT = 512
_DEVICE_CODENAME = re.compile(r"^[a-z0-9_]{1,64}$")
_BOOTLOADER_CODENAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_BOOTLOADER_VERSION = re.compile(rb"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$")


class BootloaderInspectionError(ValueError):
    """A fixed-code failure safe to expose through a typed result."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class _DuplicateCatalogKey(ValueError):
    pass


def _catalog_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateCatalogKey(key)
        result[key] = value
    return result


def load_bootloader_prefix_catalog(path: str | Path) -> Mapping[str, str]:
    """Load a strict codename-to-bootloader-prefix map from packaged metadata."""

    catalog_path = Path(path).expanduser().resolve(strict=False)
    try:
        if not catalog_path.is_file():
            raise BootloaderInspectionError(
                "bootloader_catalog_unavailable",
                "the packaged Android device catalog is unavailable",
            )
        size = catalog_path.stat().st_size
        if size <= 0 or size > _CATALOG_LIMIT:
            raise BootloaderInspectionError(
                "bootloader_catalog_invalid",
                "the packaged Android device catalog has an invalid size",
            )
        raw = catalog_path.read_bytes()
    except BootloaderInspectionError:
        raise
    except OSError as error:
        raise BootloaderInspectionError(
            "bootloader_catalog_unavailable",
            "the packaged Android device catalog could not be read",
        ) from error

    try:
        decoded = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_catalog_object)
    except (UnicodeError, json.JSONDecodeError, _DuplicateCatalogKey) as error:
        raise BootloaderInspectionError(
            "bootloader_catalog_invalid",
            "the packaged Android device catalog is malformed",
        ) from error
    if not isinstance(decoded, dict):
        raise BootloaderInspectionError(
            "bootloader_catalog_invalid",
            "the packaged Android device catalog has an invalid root",
        )
    values = cast(dict[object, object], decoded)
    if not 1 <= len(values) <= _CATALOG_ENTRY_LIMIT:
        raise BootloaderInspectionError(
            "bootloader_catalog_invalid",
            "the packaged Android device catalog has an invalid root",
        )

    catalog: dict[str, str] = {}
    for raw_codename, raw_record in values.items():
        if not isinstance(raw_codename, str) or _DEVICE_CODENAME.fullmatch(raw_codename) is None:
            raise BootloaderInspectionError(
                "bootloader_catalog_invalid",
                "the packaged Android device catalog contains an invalid codename",
            )
        if not isinstance(raw_record, dict):
            raise BootloaderInspectionError(
                "bootloader_catalog_invalid",
                "the packaged Android device catalog contains an invalid device record",
            )
        prefix = cast(dict[object, object], raw_record).get("bootloader_codename")
        if not isinstance(prefix, str) or _BOOTLOADER_CODENAME.fullmatch(prefix) is None:
            raise BootloaderInspectionError(
                "bootloader_catalog_invalid",
                "the packaged Android device catalog contains an invalid bootloader prefix",
            )
        catalog[raw_codename] = prefix
    return MappingProxyType(catalog)


class BootloaderVersionScanner:
    """Incrementally reduce a binary partition to one unambiguous version."""

    def __init__(self, bootloader_codename: str) -> None:
        if (
            not isinstance(bootloader_codename, str)
            or _BOOTLOADER_CODENAME.fullmatch(bootloader_codename) is None
        ):
            raise BootloaderInspectionError(
                "bootloader_prefix_invalid",
                "the backend bootloader prefix is invalid",
            )
        self.bootloader_codename = bootloader_codename
        self._marker = f"{bootloader_codename}-".encode("ascii")
        self._tail = b""
        self._candidates: set[str] = set()
        self._invalid_candidate = False

    def feed(self, chunk: bytes) -> None:
        if not isinstance(chunk, bytes):
            raise TypeError("bootloader partition chunks must be bytes")
        if not chunk:
            return
        window = self._tail + chunk
        search_from = 0
        while True:
            marker_at = window.find(self._marker, search_from)
            if marker_at < 0:
                break
            value_at = marker_at + len(self._marker)
            nul_at = window.find(b"\x00", value_at, value_at + BOOTLOADER_VERSION_LIMIT + 1)
            if nul_at >= 0:
                candidate = window[value_at:nul_at]
                if _BOOTLOADER_VERSION.fullmatch(candidate) is None:
                    self._invalid_candidate = True
                else:
                    self._candidates.add(candidate.decode("ascii"))
            elif len(window) - value_at > BOOTLOADER_VERSION_LIMIT:
                self._invalid_candidate = True
            search_from = marker_at + 1
        retained = len(self._marker) + BOOTLOADER_VERSION_LIMIT + 1
        self._tail = window[-retained:]

    def finish(self) -> str:
        # A marker close to EOF without a terminator is never accepted.
        marker_at = self._tail.rfind(self._marker)
        if marker_at >= 0 and b"\x00" not in self._tail[marker_at + len(self._marker) :]:
            self._invalid_candidate = True
        if len(self._candidates) > 1:
            raise BootloaderInspectionError(
                "bootloader_version_ambiguous",
                "the partition contains conflicting bootloader versions",
            )
        if not self._candidates:
            raise BootloaderInspectionError(
                "bootloader_version_invalid" if self._invalid_candidate else "bootloader_version_unavailable",
                "the partition does not contain one bounded bootloader version",
            )
        return next(iter(self._candidates))


@dataclass(frozen=True, slots=True)
class BootloaderSlotEvidence:
    slot: str
    partition: str
    bootloader_codename: str
    version: str
    sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        if self.slot not in {"a", "b"} or self.partition != f"abl_{self.slot}":
            raise ValueError("bootloader slot evidence target is invalid")
        if _BOOTLOADER_CODENAME.fullmatch(self.bootloader_codename) is None:
            raise ValueError("bootloader slot evidence prefix is invalid")
        try:
            encoded_version = self.version.encode("ascii")
        except UnicodeEncodeError as error:
            raise ValueError("bootloader slot evidence version is invalid") from error
        if _BOOTLOADER_VERSION.fullmatch(encoded_version) is None:
            raise ValueError("bootloader slot evidence version is invalid")
        if re.fullmatch(r"[0-9a-f]{64}", self.sha256) is None:
            raise ValueError("bootloader slot evidence digest is invalid")
        if (
            not isinstance(self.size_bytes, int)
            or isinstance(self.size_bytes, bool)
            or not 1 <= self.size_bytes <= BOOTLOADER_PARTITION_LIMIT
        ):
            raise ValueError("bootloader slot evidence size is invalid")

    @property
    def full_version(self) -> str:
        return f"{self.bootloader_codename}-{self.version}"

    def to_dict(self) -> dict[str, object]:
        return {
            "partition": self.partition,
            "version": self.version,
            "fullVersion": self.full_version,
            "sha256": self.sha256,
            "sizeBytes": self.size_bytes,
        }


@dataclass(frozen=True, slots=True)
class BootloaderStreamOutcome:
    returncode: int | None
    evidence: BootloaderSlotEvidence | None = None
    stderr_bytes: int = 0
    cancelled: bool = False
    timed_out: bool = False
    output_limited: bool = False
    termination_failed: bool = False
    error_code: str = ""


class BootloaderPartitionRunner(Protocol):
    def run(
        self,
        request: ProcessRequest,
        cancellation: CancellationToken,
        *,
        slot: str,
        bootloader_codename: str,
    ) -> BootloaderStreamOutcome: ...


class SubprocessBootloaderPartitionRunner:
    """Stream one fixed ABL partition and retain only validated evidence."""

    poll_interval_seconds = 0.05

    def run(
        self,
        request: ProcessRequest,
        cancellation: CancellationToken,
        *,
        slot: str,
        bootloader_codename: str,
    ) -> BootloaderStreamOutcome:
        self._validate_request(request, slot)
        if cancellation.cancelled:
            return self._stopped(cancellation, None)

        process: subprocess.Popen[bytes] = subprocess.Popen(  # noqa: S603
            list(request.argv),
            cwd=None,
            env=None,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            start_new_session=os.name != "nt",
            creationflags=SubprocessTransport._creation_flags(),
        )
        SubprocessTransport._attach_windows_job(process)
        assert process.stdout is not None
        assert process.stderr is not None
        scanner = BootloaderVersionScanner(bootloader_codename)
        digest = hashlib.sha256()
        stdout_bytes = 0
        stderr_bytes = 0
        output_limited = threading.Event()
        stderr_limited = threading.Event()
        reader_failed = threading.Event()

        def read_stdout(stream: BinaryIO) -> None:
            nonlocal stdout_bytes
            try:
                while True:
                    remaining = BOOTLOADER_PARTITION_LIMIT - stdout_bytes
                    chunk = os.read(stream.fileno(), min(BOOTLOADER_READ_CHUNK, max(1, remaining + 1)))
                    if not chunk:
                        return
                    accepted = min(len(chunk), max(0, remaining))
                    if accepted:
                        payload = chunk[:accepted]
                        digest.update(payload)
                        scanner.feed(payload)
                        stdout_bytes += accepted
                    if accepted != len(chunk):
                        output_limited.set()
                        return
            except (OSError, ValueError):
                reader_failed.set()

        def read_stderr(stream: BinaryIO) -> None:
            nonlocal stderr_bytes
            try:
                while True:
                    remaining = BOOTLOADER_STDERR_LIMIT - stderr_bytes
                    chunk = os.read(stream.fileno(), min(64 * 1024, max(1, remaining + 1)))
                    if not chunk:
                        return
                    stderr_bytes += min(len(chunk), max(0, remaining))
                    if len(chunk) > remaining:
                        stderr_limited.set()
                        return
            except (OSError, ValueError):
                reader_failed.set()

        readers = (
            threading.Thread(
                target=read_stdout,
                args=(process.stdout,),
                name="pixelflasher-bootloader-stdout",
                daemon=True,
            ),
            threading.Thread(
                target=read_stderr,
                args=(process.stderr,),
                name="pixelflasher-bootloader-stderr",
                daemon=True,
            ),
        )
        for reader in readers:
            reader.start()

        deadline = time.monotonic() + cast(float, request.timeout_seconds)
        cancelled = False
        timed_out = False
        stopped = False
        while process.poll() is None or any(reader.is_alive() for reader in readers):
            if output_limited.is_set() or stderr_limited.is_set() or reader_failed.is_set():
                SubprocessTransport._stop_process(process)
                stopped = True
                break
            if cancellation.cancelled:
                cancelled = cancellation.reason is CancellationReason.USER
                timed_out = cancellation.reason is CancellationReason.DEADLINE
                SubprocessTransport._stop_process(process)
                stopped = True
                break
            if time.monotonic() >= deadline:
                timed_out = True
                SubprocessTransport._stop_process(process)
                stopped = True
                break
            cancellation.wait(self.poll_interval_seconds)

        for reader in readers:
            reader.join(timeout=1)
        for stream, reader in zip((process.stdout, process.stderr), readers, strict=True):
            if reader.is_alive():
                try:
                    stream.close()
                except OSError:
                    pass
                reader.join(timeout=1)
        termination_failed = stopped and process.poll() is None
        SubprocessTransport._release_windows_job(process)

        if cancelled or timed_out:
            return BootloaderStreamOutcome(
                process.returncode,
                stderr_bytes=stderr_bytes,
                cancelled=cancelled,
                timed_out=timed_out,
                termination_failed=termination_failed,
            )
        if termination_failed:
            return BootloaderStreamOutcome(
                process.returncode,
                stderr_bytes=stderr_bytes,
                termination_failed=True,
                error_code="managed_process_termination_failed",
            )
        if output_limited.is_set():
            return BootloaderStreamOutcome(
                process.returncode,
                stderr_bytes=stderr_bytes,
                output_limited=True,
                error_code="bootloader_partition_limit_exceeded",
            )
        if stderr_limited.is_set():
            return BootloaderStreamOutcome(
                process.returncode,
                stderr_bytes=stderr_bytes,
                output_limited=True,
                error_code="bootloader_stderr_limit_exceeded",
            )
        if reader_failed.is_set():
            return BootloaderStreamOutcome(
                process.returncode,
                stderr_bytes=stderr_bytes,
                error_code="bootloader_stream_failed",
            )
        if process.returncode != 0:
            return BootloaderStreamOutcome(
                process.returncode,
                stderr_bytes=stderr_bytes,
                error_code="bootloader_partition_read_failed",
            )
        if stderr_bytes:
            return BootloaderStreamOutcome(
                process.returncode,
                stderr_bytes=stderr_bytes,
                error_code="bootloader_partition_stderr_unexpected",
            )
        if stdout_bytes <= 0:
            return BootloaderStreamOutcome(
                process.returncode,
                error_code="bootloader_partition_empty",
            )
        try:
            version = scanner.finish()
            evidence = BootloaderSlotEvidence(
                slot,
                f"abl_{slot}",
                bootloader_codename,
                version,
                digest.hexdigest(),
                stdout_bytes,
            )
        except BootloaderInspectionError as error:
            return BootloaderStreamOutcome(
                process.returncode,
                error_code=error.code,
            )
        return BootloaderStreamOutcome(process.returncode, evidence=evidence)

    @staticmethod
    def _validate_request(request: ProcessRequest, slot: str) -> None:
        expected_tail = (
            "exec-out",
            "su",
            "0",
            "toybox",
            "cat",
            f"/dev/block/by-name/abl_{slot}",
        )
        if (
            slot not in {"a", "b"}
            or len(request.argv) != 9
            or not request.argv[0]
            or request.argv[1] != "-s"
            or not request.argv[2]
            or request.argv[3:] != expected_tail
            or request.cwd is not None
            or request.env is not None
            or request.stdin_secret_field is not None
            or request.timeout_seconds is None
            or request.timeout_seconds > 90
            or request.output_limit_bytes != BOOTLOADER_PARTITION_LIMIT
        ):
            raise BootloaderInspectionError(
                "bootloader_stream_request_invalid",
                "bootloader streaming requires one fixed serial-bound ABL request",
            )

    @staticmethod
    def _stopped(
        cancellation: CancellationToken,
        returncode: int | None,
    ) -> BootloaderStreamOutcome:
        return BootloaderStreamOutcome(
            returncode,
            cancelled=cancellation.reason is CancellationReason.USER,
            timed_out=cancellation.reason is CancellationReason.DEADLINE,
        )


__all__ = [
    "BOOTLOADER_PARTITION_LIMIT",
    "BOOTLOADER_STDERR_LIMIT",
    "BootloaderInspectionError",
    "BootloaderPartitionRunner",
    "BootloaderSlotEvidence",
    "BootloaderStreamOutcome",
    "BootloaderVersionScanner",
    "SubprocessBootloaderPartitionRunner",
    "load_bootloader_prefix_catalog",
]
