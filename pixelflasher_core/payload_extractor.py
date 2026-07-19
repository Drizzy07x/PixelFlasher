"""Built-in, bounded reconstruction for Android full-update payloads.

Only the source-independent full operation types accepted by :mod:`payload`
are implemented here.  The runner is intentionally an in-process typed
boundary: it never invokes a shell, imports updater scripts, or delegates to
third-party payload dumper programs.
"""

from __future__ import annotations

import bz2
import hashlib
import hmac
import json
import lzma
import os
import stat
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Final, Protocol, cast

from .executor import CancellationToken
from .payload import (
    FULL_PAYLOAD_OPERATION_TYPES,
    PAYLOAD_MAJOR_VERSION,
    PayloadExtent,
    PayloadExtractionError,
    PayloadExtractionRequest,
    PayloadExtractionResult,
    PayloadExtractorIdentity,
    PayloadOperation,
    PayloadPartition,
)

BUILTIN_PAYLOAD_EXTRACTOR_NAME: Final = "pixelflasher-builtin-full-payload"
BUILTIN_PAYLOAD_EXTRACTOR_VERSION: Final = "1"
_INTEGRITY_RESOURCE: Final = "payload_extractor.integrity.json"
_SOURCE_RESOURCE: Final = "payload_extractor.py"
_HASH_BYTES: Final = hashlib.sha256().digest_size
_UNVERIFIED_DIGEST: Final = "0" * (_HASH_BYTES * 2)
_REPLACE: Final = 0
_REPLACE_BZ: Final = 1
_REPLACE_XZ: Final = 8


@dataclass(frozen=True, slots=True)
class BuiltinPayloadExtractorLimits:
    """Independent defense-in-depth limits for reconstruction."""

    maximum_partition_bytes: int = 16 * 1024 * 1024 * 1024
    maximum_output_bytes: int = 64 * 1024 * 1024 * 1024
    maximum_operation_data_bytes: int = 64 * 1024 * 1024 * 1024
    maximum_operations: int = 1_000_000
    lzma_memory_limit: int = 256 * 1024 * 1024
    chunk_size: int = 1024 * 1024

    def __post_init__(self) -> None:
        if any(
            value <= 0
            for value in (
                self.maximum_partition_bytes,
                self.maximum_output_bytes,
                self.maximum_operation_data_bytes,
                self.maximum_operations,
                self.lzma_memory_limit,
                self.chunk_size,
            )
        ):
            raise ValueError("payload extractor limits must be positive")


class _BoundedDecompressor(Protocol):
    @property
    def eof(self) -> bool: ...

    @property
    def needs_input(self) -> bool: ...

    @property
    def unused_data(self) -> bytes: ...

    def decompress(self, data: bytes, max_length: int = -1) -> bytes: ...


class _Digest(Protocol):
    def update(self, data: bytes, /) -> None: ...

    def digest(self) -> bytes: ...


@dataclass(frozen=True, slots=True)
class _IntegrityManifest:
    name: str
    version: str
    source: str
    canonical_source_sha256: str


def _read_packaged_resource(name: str) -> bytes:
    return resources.files("pixelflasher_core").joinpath(name).read_bytes()


def _canonical_source(source: bytes) -> bytes:
    """Make the checked digest independent of checkout newline policy."""

    text = source.decode("utf-8", errors="strict")
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def _load_integrity_manifest() -> tuple[_IntegrityManifest, bytes]:
    raw_manifest = _read_packaged_resource(_INTEGRITY_RESOURCE)
    if len(raw_manifest) > 4096:
        raise ValueError("payload runner integrity manifest is too large")
    decoded = json.loads(raw_manifest.decode("utf-8", errors="strict"))
    if not isinstance(decoded, Mapping):
        raise ValueError("payload runner integrity manifest is not an object")
    values = cast(Mapping[object, object], decoded)
    expected_fields = {
        "schema",
        "name",
        "version",
        "source",
        "canonicalSourceSha256",
    }
    if set(values) != expected_fields or values.get("schema") != 1:
        raise ValueError("payload runner integrity manifest has an unsupported schema")
    strings = {
        key: value
        for key in ("name", "version", "source", "canonicalSourceSha256")
        if isinstance((value := values.get(key)), str)
    }
    if len(strings) != 4:
        raise ValueError("payload runner integrity manifest contains invalid fields")
    digest = strings["canonicalSourceSha256"]
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError("payload runner integrity digest is not canonical SHA-256")
    manifest = _IntegrityManifest(
        strings["name"],
        strings["version"],
        strings["source"],
        digest,
    )
    source = _read_packaged_resource(manifest.source)
    return manifest, _canonical_source(source)


def verify_builtin_payload_extractor_identity() -> PayloadExtractorIdentity:
    """Verify the packaged source resource against its pinned build manifest.

    The source resource is compiled into the same artifact as this module and
    is retained as package data for this check.  A future signed release
    manifest can pin the same digest without changing this public contract.
    """

    observed = _UNVERIFIED_DIGEST
    packaged = False
    verified = False
    try:
        manifest, source = _load_integrity_manifest()
        packaged = True
        observed = hashlib.sha256(source).hexdigest()
        verified = (
            manifest.name == BUILTIN_PAYLOAD_EXTRACTOR_NAME
            and manifest.version == BUILTIN_PAYLOAD_EXTRACTOR_VERSION
            and manifest.source == _SOURCE_RESOURCE
            and hmac.compare_digest(observed, manifest.canonical_source_sha256)
        )
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        pass
    return PayloadExtractorIdentity(
        BUILTIN_PAYLOAD_EXTRACTOR_NAME,
        BUILTIN_PAYLOAD_EXTRACTOR_VERSION,
        observed,
        packaged=packaged,
        verified=verified,
    )


class _ExtentWriter:
    def __init__(
        self,
        descriptor: int,
        operation: PayloadOperation,
        block_size: int,
        cancellation: CancellationToken,
    ) -> None:
        self._descriptor = descriptor
        self._extents: tuple[PayloadExtent, ...] = operation.destination_extents
        self._block_size = block_size
        self._cancellation = cancellation
        self._extent_index: int = 0
        self._extent_offset: int = 0
        self.written: int = 0
        self.expected: int = sum(extent.block_count * block_size for extent in self._extents)

    def write(self, data: bytes) -> None:
        view = memoryview(data)
        position = 0
        while position < len(view):
            _check_cancelled(self._cancellation)
            if self._extent_index >= len(self._extents):
                raise PayloadExtractionError(
                    "payload_decompression_limit_exceeded",
                    "payload operation produced more bytes than its destination extents",
                )
            extent = self._extents[self._extent_index]
            extent_size = extent.block_count * self._block_size
            available = extent_size - self._extent_offset
            length = min(available, len(view) - position)
            absolute_offset = extent.start_block * self._block_size + self._extent_offset
            _write_all_at(
                self._descriptor,
                view[position : position + length],
                absolute_offset,
                self._cancellation,
            )
            position += length
            self.written += length
            self._extent_offset += length
            if self._extent_offset == extent_size:
                self._extent_index += 1
                self._extent_offset = 0

    def finish(self) -> None:
        if self.written != self.expected or self._extent_index != len(self._extents):
            raise PayloadExtractionError(
                "payload_decompressed_size_mismatch",
                "payload operation did not fill its destination extents exactly",
            )


class BuiltinPayloadExtractor:
    """Reconstruct allow-listed images from one validated Android full payload."""

    def __init__(self, limits: BuiltinPayloadExtractorLimits | None = None) -> None:
        self.limits = limits or BuiltinPayloadExtractorLimits()

    @property
    def identity(self) -> PayloadExtractorIdentity:
        # Recompute on every trust boundary, so post-start resource replacement
        # cannot reuse a cached successful verification.
        return verify_builtin_payload_extractor_identity()

    def extract(
        self,
        request: PayloadExtractionRequest,
        cancellation: CancellationToken,
    ) -> PayloadExtractionResult:
        identity = self.identity
        if not identity.trusted:
            raise PayloadExtractionError(
                "payload_runner_identity_mismatch",
                "the built-in payload runner does not match its packaged integrity manifest",
            )
        _check_cancelled(cancellation)
        self._validate_request(request)
        payload_descriptor = _open_regular_input(request.payload_path)
        created: list[Path] = []
        try:
            payload_stat = os.fstat(payload_descriptor)
            if payload_stat.st_size != request.manifest.payload_size:
                raise PayloadExtractionError(
                    "payload_input_size_mismatch",
                    "payload.bin changed after its manifest was validated",
                )
            self._validate_output_directory(request.output_directory)
            for partition in request.partitions:
                _check_cancelled(cancellation)
                output = request.output_directory / f"{partition.name}.img"
                descriptor = _open_exclusive_output(output)
                created.append(output)
                try:
                    os.ftruncate(descriptor, partition.size)
                    for operation in partition.operations:
                        self._extract_operation(
                            payload_descriptor,
                            descriptor,
                            request.manifest.data_offset,
                            request.manifest.block_size,
                            operation,
                            cancellation,
                        )
                    observed = _hash_descriptor(
                        descriptor,
                        partition.size,
                        self.limits.chunk_size,
                        cancellation,
                    )
                    if not hmac.compare_digest(observed, partition.sha256):
                        raise PayloadExtractionError(
                            "payload_partition_hash_mismatch",
                            f"reconstructed payload partition {partition.name} failed SHA-256 verification",
                        )
                    os.fsync(descriptor)
                    _verify_open_output_identity(output, descriptor, partition.size)
                finally:
                    os.close(descriptor)
            _fsync_directory(request.output_directory)
            return PayloadExtractionResult(tuple(partition.name for partition in request.partitions))
        except InterruptedError:
            self._remove_created(created)
            raise
        except PayloadExtractionError:
            self._remove_created(created)
            raise
        except (OSError, EOFError, ValueError, lzma.LZMAError) as error:
            self._remove_created(created)
            raise PayloadExtractionError(
                "payload_extraction_io_failed",
                f"built-in payload extraction failed: {type(error).__name__}",
            ) from error
        finally:
            os.close(payload_descriptor)

    def _validate_request(self, request: PayloadExtractionRequest) -> None:
        manifest = request.manifest
        if manifest.major_version != PAYLOAD_MAJOR_VERSION or manifest.minor_version != 0:
            raise PayloadExtractionError(
                "payload_version_unsupported",
                "built-in extraction accepts only Android full payload v2",
            )
        if manifest.block_size <= 0:
            raise PayloadExtractionError(
                "payload_manifest_invalid",
                "payload block size must be positive",
            )
        manifest_partitions = {partition.name: partition for partition in manifest.partitions}
        output_bytes = 0
        operation_data_bytes = 0
        operation_count = 0
        for partition in request.partitions:
            if manifest_partitions.get(partition.name) != partition:
                raise PayloadExtractionError(
                    "payload_request_manifest_mismatch",
                    "requested payload partitions do not match the validated manifest",
                )
            if partition.size > self.limits.maximum_partition_bytes:
                raise PayloadExtractionError(
                    "payload_partition_limit_exceeded",
                    f"payload partition {partition.name} exceeds the runner limit",
                )
            output_bytes += partition.size
            if output_bytes > self.limits.maximum_output_bytes:
                raise PayloadExtractionError(
                    "payload_output_limit_exceeded",
                    "payload extraction exceeds the runner output limit",
                )
            operation_count += len(partition.operations)
            if operation_count > self.limits.maximum_operations:
                raise PayloadExtractionError(
                    "payload_operation_limit_exceeded",
                    "payload extraction contains too many operations",
                )
            self._validate_partition_layout(partition, manifest.block_size)
            for operation in partition.operations:
                operation_data_bytes += operation.data_length
                if operation_data_bytes > self.limits.maximum_operation_data_bytes:
                    raise PayloadExtractionError(
                        "payload_operation_data_limit_exceeded",
                        "payload operations reference too much compressed data",
                    )
                end = manifest.data_offset + operation.data_offset + operation.data_length
                operation_data_end = (
                    manifest.data_offset + manifest.signatures_offset
                    if manifest.signatures_offset is not None
                    else manifest.payload_size
                )
                if end < manifest.data_offset or end > operation_data_end:
                    raise PayloadExtractionError(
                        "payload_operation_out_of_range",
                        "payload operation data extends outside payload.bin",
                    )

    @staticmethod
    def _validate_partition_layout(partition: PayloadPartition, block_size: int) -> None:
        intervals: list[tuple[int, int]] = []
        for operation in partition.operations:
            if operation.operation_type not in FULL_PAYLOAD_OPERATION_TYPES:
                raise PayloadExtractionError(
                    "payload_delta_operation_unsupported",
                    "built-in extraction rejects source-dependent payload operations",
                )
            expected = 0
            for extent in operation.destination_extents:
                start = extent.start_block * block_size
                end = (extent.start_block + extent.block_count) * block_size
                if end <= start or end > partition.size:
                    raise PayloadExtractionError(
                        "payload_destination_out_of_range",
                        f"payload destination extent exceeds {partition.name}",
                    )
                intervals.append((start, end))
                expected += end - start
            if operation.destination_length is not None and operation.destination_length != expected:
                raise PayloadExtractionError(
                    "payload_destination_size_mismatch",
                    "payload destination length does not match its extents",
                )
            if operation.operation_type == _REPLACE and operation.data_length != expected:
                raise PayloadExtractionError(
                    "payload_replace_size_mismatch",
                    "payload REPLACE bytes do not match destination extents",
                )
            if not operation.data_length or len(operation.data_sha256) != _HASH_BYTES:
                raise PayloadExtractionError(
                    "payload_operation_invalid",
                    "payload full operation requires hashed input data",
                )
        cursor = 0
        for start, end in sorted(intervals):
            if start != cursor:
                raise PayloadExtractionError(
                    "payload_destination_coverage_invalid",
                    f"payload destination extents do not exactly cover {partition.name}",
                )
            cursor = end
        if cursor != partition.size:
            raise PayloadExtractionError(
                "payload_destination_coverage_invalid",
                f"payload destination extents do not exactly cover {partition.name}",
            )

    def _extract_operation(
        self,
        payload_descriptor: int,
        output_descriptor: int,
        data_offset: int,
        block_size: int,
        operation: PayloadOperation,
        cancellation: CancellationToken,
    ) -> None:
        writer = _ExtentWriter(output_descriptor, operation, block_size, cancellation)
        digest = hashlib.sha256()
        chunks = _read_operation_chunks(
            payload_descriptor,
            data_offset + operation.data_offset,
            operation.data_length,
            self.limits.chunk_size,
            digest,
            cancellation,
        )
        if operation.operation_type == _REPLACE:
            for chunk in chunks:
                writer.write(chunk)
        elif operation.operation_type == _REPLACE_BZ:
            self._decompress_operation(bz2.BZ2Decompressor(), chunks, writer, cancellation)
        elif operation.operation_type == _REPLACE_XZ:
            self._decompress_operation(
                lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=self.limits.lzma_memory_limit),
                chunks,
                writer,
                cancellation,
            )
        else:  # The request validation above keeps this branch unreachable.
            raise PayloadExtractionError(
                "payload_operation_unsupported",
                "payload operation is not supported by the built-in runner",
            )
        writer.finish()
        if not hmac.compare_digest(digest.digest(), operation.data_sha256):
            raise PayloadExtractionError(
                "payload_operation_hash_mismatch",
                "payload operation bytes changed after parser verification",
            )

    def _decompress_operation(
        self,
        decompressor: _BoundedDecompressor,
        chunks: Iterator[bytes],
        writer: _ExtentWriter,
        cancellation: CancellationToken,
    ) -> None:
        saw_eof = False
        for chunk in chunks:
            _check_cancelled(cancellation)
            if saw_eof:
                raise PayloadExtractionError(
                    "payload_compressed_trailing_data",
                    "payload compressed operation contains trailing data",
                )
            pending = chunk
            while True:
                _check_cancelled(cancellation)
                remaining = writer.expected - writer.written
                maximum = min(self.limits.chunk_size, max(1, remaining + 1))
                output = decompressor.decompress(pending, max_length=maximum)
                pending = b""
                if output:
                    writer.write(output)
                if decompressor.eof:
                    if decompressor.unused_data:
                        raise PayloadExtractionError(
                            "payload_compressed_trailing_data",
                            "payload compressed operation contains a concatenated or trailing stream",
                        )
                    saw_eof = True
                    break
                if decompressor.needs_input:
                    break
        while not saw_eof and not decompressor.needs_input:
            _check_cancelled(cancellation)
            remaining = writer.expected - writer.written
            maximum = min(self.limits.chunk_size, max(1, remaining + 1))
            output = decompressor.decompress(b"", max_length=maximum)
            if output:
                writer.write(output)
            if decompressor.eof:
                if decompressor.unused_data:
                    raise PayloadExtractionError(
                        "payload_compressed_trailing_data",
                        "payload compressed operation contains trailing data",
                    )
                saw_eof = True
        if not saw_eof:
            raise PayloadExtractionError(
                "payload_compressed_stream_truncated",
                "payload compressed operation ended before its stream was complete",
            )

    @staticmethod
    def _validate_output_directory(path: Path) -> None:
        try:
            info = path.lstat()
        except OSError as error:
            raise PayloadExtractionError(
                "payload_output_directory_invalid",
                "payload output directory is unavailable",
            ) from error
        if not stat.S_ISDIR(info.st_mode) or path.is_symlink():
            raise PayloadExtractionError(
                "payload_output_directory_invalid",
                "payload output directory must be a real directory",
            )
        try:
            if next(path.iterdir(), None) is not None:
                raise PayloadExtractionError(
                    "payload_output_directory_not_empty",
                    "payload output directory must be empty",
                )
        except OSError as error:
            raise PayloadExtractionError(
                "payload_output_directory_invalid",
                "payload output directory could not be inspected",
            ) from error

    @staticmethod
    def _remove_created(paths: list[Path]) -> None:
        for path in reversed(paths):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass


def _check_cancelled(cancellation: CancellationToken) -> None:
    if cancellation.cancelled:
        raise InterruptedError("payload extraction was cancelled")


def _binary_flag() -> int:
    return cast(int, getattr(os, "O_BINARY", 0))


def _no_follow_flag() -> int:
    return cast(int, getattr(os, "O_NOFOLLOW", 0))


def _open_regular_input(path: Path) -> int:
    flags = os.O_RDONLY | _binary_flag() | _no_follow_flag()
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or path.is_symlink():
            raise OSError("payload input is not a regular file")
        descriptor = os.open(path, flags)
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode) or not _same_file(before, after):
            os.close(descriptor)
            raise OSError("payload input identity changed while opening")
        return descriptor
    except OSError as error:
        raise PayloadExtractionError(
            "payload_input_invalid",
            "payload input must be an unchanged regular file",
        ) from error


def _open_exclusive_output(path: Path) -> int:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | _binary_flag() | _no_follow_flag()
    try:
        return os.open(path, flags, 0o600)
    except OSError as error:
        raise PayloadExtractionError(
            "payload_output_create_failed",
            "payload output could not be created exclusively",
        ) from error


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    # Windows can report a zero inode for some filesystems.  The exclusive
    # open/no-follow flags still protect those systems; compare identities when
    # the platform provides useful values.
    if left.st_ino and right.st_ino:
        return left.st_ino == right.st_ino and left.st_dev == right.st_dev
    return left.st_size == right.st_size and left.st_mode == right.st_mode


def _verify_open_output_identity(path: Path, descriptor: int, expected_size: int) -> None:
    before = os.fstat(descriptor)
    after = path.lstat()
    if (
        not stat.S_ISREG(after.st_mode)
        or path.is_symlink()
        or before.st_size != expected_size
        or after.st_size != expected_size
        or not _same_file(before, after)
    ):
        raise PayloadExtractionError(
            "payload_output_identity_changed",
            "payload output identity changed during reconstruction",
        )


def _read_operation_chunks(
    descriptor: int,
    offset: int,
    length: int,
    chunk_size: int,
    digest: _Digest,
    cancellation: CancellationToken,
) -> Iterator[bytes]:
    os.lseek(descriptor, offset, os.SEEK_SET)
    remaining = length
    while remaining:
        _check_cancelled(cancellation)
        chunk = os.read(descriptor, min(remaining, chunk_size))
        if not chunk:
            raise PayloadExtractionError(
                "payload_operation_truncated",
                "payload operation data ended unexpectedly",
            )
        digest.update(chunk)
        remaining -= len(chunk)
        yield chunk


def _write_all_at(
    descriptor: int,
    data: memoryview,
    offset: int,
    cancellation: CancellationToken,
) -> None:
    os.lseek(descriptor, offset, os.SEEK_SET)
    position = 0
    while position < len(data):
        _check_cancelled(cancellation)
        written = os.write(descriptor, data[position:])
        if written <= 0:
            raise OSError("payload output write made no progress")
        position += written


def _hash_descriptor(
    descriptor: int,
    expected_size: int,
    chunk_size: int,
    cancellation: CancellationToken,
) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = expected_size
    while remaining:
        _check_cancelled(cancellation)
        chunk = os.read(descriptor, min(remaining, chunk_size))
        if not chunk:
            raise PayloadExtractionError(
                "payload_output_truncated",
                "payload output ended before its expected size",
            )
        digest.update(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise PayloadExtractionError(
            "payload_output_size_mismatch",
            "payload output exceeds its expected size",
        )
    return digest.digest()


def _fsync_directory(path: Path) -> None:
    directory_flag = cast(int, getattr(os, "O_DIRECTORY", 0))
    try:
        descriptor = os.open(path, os.O_RDONLY | directory_flag | _binary_flag())
    except OSError:
        # Windows does not allow opening directories with os.open.  Each file
        # has already been fsynced, and the caller performs an atomic promotion.
        if os.name == "nt":
            return
        raise
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
