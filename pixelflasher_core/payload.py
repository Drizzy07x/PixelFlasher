"""Bounded Android ``payload.bin`` inspection and extraction contracts.

The parser deliberately implements only the small protobuf wire subset needed
to validate Android full-update payloads.  It does not execute archive content
or attempt to apply update operations.  Image reconstruction is delegated to a
separately packaged extractor and its output must still be verified by the
caller against the manifest hashes.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import struct
from collections.abc import Collection
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO, Never, Protocol, runtime_checkable

from .executor import CancellationToken

PAYLOAD_MAGIC = b"CrAU"
PAYLOAD_MAJOR_VERSION = 2
PAYLOAD_OPERATION_TYPES = frozenset({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13})
FULL_PAYLOAD_OPERATION_TYPES = frozenset({0, 1, 8})

_SHA256_BYTES = hashlib.sha256().digest_size
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_PARTITION_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_]{0,63}$")
_UINT64_MAX = (1 << 64) - 1


class PayloadErrorCode(StrEnum):
    INVALID_HEADER = "payload_invalid_header"
    UNSUPPORTED_VERSION = "payload_version_unsupported"
    DELTA_UNSUPPORTED = "payload_delta_unsupported"
    MANIFEST_LIMIT_EXCEEDED = "payload_manifest_limit_exceeded"
    MALFORMED_MANIFEST = "payload_manifest_malformed"
    PARTITION_LIMIT_EXCEEDED = "payload_partition_limit_exceeded"
    OPERATION_LIMIT_EXCEEDED = "payload_operation_limit_exceeded"
    UNSAFE_PARTITION = "payload_partition_not_allowed"
    NO_FLASHABLE_PARTITIONS = "payload_has_no_flashable_partitions"
    SIZE_LIMIT_EXCEEDED = "payload_size_limit_exceeded"
    OFFSET_OUT_OF_RANGE = "payload_offset_out_of_range"
    DATA_HASH_MISMATCH = "payload_data_hash_mismatch"


class PayloadValidationError(ValueError):
    """A stable, non-secret validation failure for an untrusted payload."""

    def __init__(self, code: PayloadErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


class PayloadExtractionError(RuntimeError):
    """An explicit failure reported by a packaged payload extractor."""

    def __init__(self, code: str, message: str) -> None:
        if not code or not message:
            raise ValueError("payload extraction errors require code and message")
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class PayloadLimits:
    maximum_payload_bytes: int = 16 * 1024 * 1024 * 1024
    maximum_manifest_bytes: int = 32 * 1024 * 1024
    maximum_metadata_signature_bytes: int = 16 * 1024 * 1024
    maximum_partitions: int = 256
    maximum_operations: int = 1_000_000
    maximum_protobuf_fields: int = 4_000_000
    maximum_partition_bytes: int = 16 * 1024 * 1024 * 1024
    maximum_output_bytes: int = 64 * 1024 * 1024 * 1024
    maximum_referenced_data_bytes: int = 64 * 1024 * 1024 * 1024
    hash_chunk_size: int = 1024 * 1024

    def __post_init__(self) -> None:
        if any(
            value <= 0
            for value in (
                self.maximum_payload_bytes,
                self.maximum_manifest_bytes,
                self.maximum_metadata_signature_bytes,
                self.maximum_partitions,
                self.maximum_operations,
                self.maximum_protobuf_fields,
                self.maximum_partition_bytes,
                self.maximum_output_bytes,
                self.maximum_referenced_data_bytes,
                self.hash_chunk_size,
            )
        ):
            raise ValueError("payload limits must be positive")


@dataclass(frozen=True, slots=True)
class PayloadExtent:
    start_block: int
    block_count: int

    def __post_init__(self) -> None:
        if (
            self.start_block < 0
            or self.block_count <= 0
            or self.start_block > _UINT64_MAX
            or self.block_count > _UINT64_MAX
        ):
            raise ValueError("payload destination extent is invalid")


@dataclass(frozen=True, slots=True)
class PayloadOperation:
    operation_type: int
    data_offset: int
    data_length: int
    data_sha256: bytes
    destination_extents: tuple[PayloadExtent, ...]
    destination_length: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "destination_extents", tuple(self.destination_extents))
        if self.operation_type not in PAYLOAD_OPERATION_TYPES:
            raise ValueError("unsupported payload operation type")
        if self.data_offset < 0 or self.data_length < 0:
            raise ValueError("payload operation offsets must not be negative")
        if self.data_length and len(self.data_sha256) != _SHA256_BYTES:
            raise ValueError("payload operation data requires a SHA-256 hash")
        if not self.data_length and self.data_sha256:
            raise ValueError("empty payload operation data cannot have a hash")
        if not self.destination_extents:
            raise ValueError("payload operation requires destination extents")
        if self.destination_length is not None and self.destination_length <= 0:
            raise ValueError("payload destination length must be positive")


@dataclass(frozen=True, slots=True)
class PayloadPartition:
    name: str
    size: int
    sha256: bytes
    operations: tuple[PayloadOperation, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "operations", tuple(self.operations))
        if not _PARTITION_PATTERN.fullmatch(self.name):
            raise ValueError("payload partition name is invalid")
        if self.size <= 0:
            raise ValueError("payload partition size must be positive")
        if len(self.sha256) != _SHA256_BYTES:
            raise ValueError("payload partition requires a SHA-256 hash")
        if not self.operations:
            raise ValueError("payload partition requires operations")

    @property
    def sha256_hex(self) -> str:
        return self.sha256.hex()


@dataclass(frozen=True, slots=True)
class PayloadManifest:
    major_version: int
    minor_version: int
    block_size: int
    payload_size: int
    data_offset: int
    metadata_size: int
    metadata_sha256: str
    manifest_sha256: str
    signatures_offset: int | None
    signatures_size: int | None
    partitions: tuple[PayloadPartition, ...]
    ignored_partitions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "partitions", tuple(self.partitions))
        object.__setattr__(self, "ignored_partitions", tuple(self.ignored_partitions))
        if self.major_version != PAYLOAD_MAJOR_VERSION or self.minor_version != 0:
            raise ValueError("only Android full payload v2 manifests are supported")
        if self.payload_size <= 0 or self.data_offset <= 0 or self.metadata_size <= 0:
            raise ValueError("payload sizes must be positive")
        if self.metadata_size > self.data_offset:
            raise ValueError("payload metadata size must not extend into operation data")
        if not _SHA256_PATTERN.fullmatch(self.metadata_sha256):
            raise ValueError("payload metadata hash must be canonical SHA-256")
        if not _SHA256_PATTERN.fullmatch(self.manifest_sha256):
            raise ValueError("payload manifest hash must be canonical SHA-256")
        if not self.partitions:
            raise ValueError("payload manifest requires flashable partitions")


@dataclass(frozen=True, slots=True)
class PayloadExtractorIdentity:
    name: str
    version: str
    binary_sha256: str
    packaged: bool
    verified: bool

    def __post_init__(self) -> None:
        if not self.name.strip() or not self.version.strip():
            raise ValueError("payload extractor identity requires name and version")
        if not _SHA256_PATTERN.fullmatch(self.binary_sha256):
            raise ValueError("payload extractor binary hash must be canonical SHA-256")

    @property
    def trusted(self) -> bool:
        """Whether packaging verified this exact runner against its manifest."""

        return self.packaged and self.verified


@dataclass(frozen=True, slots=True)
class PayloadExtractionRequest:
    payload_path: Path
    output_directory: Path
    manifest: PayloadManifest
    partitions: tuple[PayloadPartition, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "partitions", tuple(self.partitions))
        if not self.partitions:
            raise ValueError("payload extraction requires at least one partition")
        manifest_names = {partition.name for partition in self.manifest.partitions}
        requested_names = {partition.name for partition in self.partitions}
        if len(requested_names) != len(self.partitions) or not requested_names.issubset(manifest_names):
            raise ValueError("payload extraction partitions must be unique manifest entries")


@dataclass(frozen=True, slots=True)
class PayloadExtractionResult:
    partitions: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "partitions", tuple(self.partitions))
        if not self.partitions or len(set(self.partitions)) != len(self.partitions):
            raise ValueError("payload extractor must report unique output partitions")
        if any(not _PARTITION_PATTERN.fullmatch(item) for item in self.partitions):
            raise ValueError("payload extractor reported an invalid partition")


@runtime_checkable
class PayloadExtractor(Protocol):
    """Packagable image reconstruction boundary.

    Production composition must expose an identity whose binary digest has
    already been checked against the signed artifact manifest.  The extractor
    may only write the fixed partition filenames in ``output_directory``.
    """

    @property
    def identity(self) -> PayloadExtractorIdentity: ...

    def extract(
        self,
        request: PayloadExtractionRequest,
        cancellation: CancellationToken,
    ) -> PayloadExtractionResult: ...


class _Digest(Protocol):
    def update(self, data: bytes, /) -> None: ...


@dataclass(slots=True)
class _ParseBudget:
    remaining_fields: int

    def consume(self) -> None:
        self.remaining_fields -= 1
        if self.remaining_fields < 0:
            raise PayloadValidationError(
                PayloadErrorCode.MANIFEST_LIMIT_EXCEEDED,
                "payload manifest contains too many protobuf fields",
            )


@dataclass(frozen=True, slots=True)
class _PayloadDataReference:
    partition: str
    offset: int
    length: int
    sha256: bytes


class _WireReader:
    def __init__(self, data: memoryview, budget: _ParseBudget) -> None:
        self._data = data
        self._budget = budget
        self._position = 0

    @property
    def done(self) -> bool:
        return self._position == len(self._data)

    def key(self) -> tuple[int, int]:
        self._budget.consume()
        raw = self._varint()
        field = raw >> 3
        wire = raw & 0x07
        if field == 0 or field >= (1 << 29) or wire not in {0, 1, 2, 5}:
            self._malformed("payload manifest contains an invalid protobuf key")
        return field, wire

    def uint(self, wire: int, label: str) -> int:
        if wire != 0:
            self._malformed(f"{label} has the wrong protobuf wire type")
        return self._varint()

    def bytes(self, wire: int, label: str) -> memoryview:
        if wire != 2:
            self._malformed(f"{label} has the wrong protobuf wire type")
        length = self._varint()
        end = self._position + length
        if end < self._position or end > len(self._data):
            self._malformed(f"{label} exceeds the payload manifest")
        value = self._data[self._position : end]
        self._position = end
        return value

    def skip(self, wire: int) -> None:
        if wire == 0:
            self._varint()
            return
        if wire == 1:
            self._advance(8)
            return
        if wire == 2:
            length = self._varint()
            self._advance(length)
            return
        if wire == 5:
            self._advance(4)
            return
        self._malformed("payload manifest contains an unsupported protobuf wire type")

    def _advance(self, length: int) -> None:
        end = self._position + length
        if end < self._position or end > len(self._data):
            self._malformed("protobuf field exceeds the payload manifest")
        self._position = end

    def _varint(self) -> int:
        value = 0
        for shift in range(0, 70, 7):
            if self._position >= len(self._data):
                self._malformed("payload manifest contains a truncated varint")
            byte = self._data[self._position]
            self._position += 1
            if shift == 63 and byte > 1:
                self._malformed("payload manifest varint exceeds uint64")
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value
        self._malformed("payload manifest contains an overlong varint")

    @staticmethod
    def _malformed(message: str) -> Never:
        raise PayloadValidationError(PayloadErrorCode.MALFORMED_MANIFEST, message)


class PayloadParser:
    """Parse and hash-check one Android full payload using bounded resources."""

    def __init__(self, limits: PayloadLimits | None = None) -> None:
        self.limits = limits or PayloadLimits()

    def parse(
        self,
        payload_path: Path,
        *,
        allowed_partitions: Collection[str],
        cancellation: CancellationToken,
    ) -> PayloadManifest:
        allowed = frozenset(allowed_partitions)
        if not allowed or any(not _PARTITION_PATTERN.fullmatch(item) for item in allowed):
            raise ValueError("allowed payload partitions must be canonical names")
        if cancellation.cancelled:
            raise InterruptedError("payload parsing was cancelled")
        try:
            payload_size = payload_path.stat().st_size
            if payload_size > self.limits.maximum_payload_bytes:
                self._fail(
                    PayloadErrorCode.SIZE_LIMIT_EXCEEDED,
                    "payload.bin exceeds the configured size limit",
                )
            with payload_path.open("rb") as stream:
                fixed_header = self._read_exact(stream, 20, cancellation)
                magic, major_version, manifest_size = struct.unpack(">4sQQ", fixed_header)
                if magic != PAYLOAD_MAGIC:
                    self._fail(
                        PayloadErrorCode.INVALID_HEADER,
                        "payload.bin has an invalid magic header",
                    )
                if major_version != PAYLOAD_MAJOR_VERSION:
                    self._fail(
                        PayloadErrorCode.UNSUPPORTED_VERSION,
                        f"payload major version {major_version} is not supported",
                    )
                if not manifest_size or manifest_size > self.limits.maximum_manifest_bytes:
                    self._fail(
                        PayloadErrorCode.MANIFEST_LIMIT_EXCEEDED,
                        "payload manifest exceeds the configured size limit",
                    )
                signature_header = self._read_exact(stream, 4, cancellation)
                (metadata_signature_size,) = struct.unpack(">I", signature_header)
                if metadata_signature_size > self.limits.maximum_metadata_signature_bytes:
                    self._fail(
                        PayloadErrorCode.MANIFEST_LIMIT_EXCEEDED,
                        "payload metadata signature exceeds the configured size limit",
                    )
                metadata_size = 24 + manifest_size
                data_offset = metadata_size + metadata_signature_size
                if data_offset > payload_size:
                    self._fail(
                        PayloadErrorCode.INVALID_HEADER,
                        "payload metadata extends beyond the payload file",
                    )
                manifest_bytes = self._read_exact(stream, manifest_size, cancellation)
                metadata_digest = hashlib.sha256(fixed_header + signature_header)
                metadata_digest.update(manifest_bytes)
                self._skip_exact(stream, metadata_signature_size, cancellation)
                parsed, data_references = self._parse_manifest(
                    memoryview(manifest_bytes),
                    major_version=major_version,
                    payload_size=payload_size,
                    data_offset=data_offset,
                    metadata_size=metadata_size,
                    metadata_sha256=metadata_digest.hexdigest(),
                    allowed_partitions=allowed,
                )
                self._verify_operation_data(
                    stream,
                    parsed.data_offset,
                    data_references,
                    cancellation,
                )
                return parsed
        except PayloadValidationError:
            raise
        except InterruptedError:
            raise
        except (OSError, struct.error) as error:
            raise PayloadValidationError(
                PayloadErrorCode.INVALID_HEADER,
                f"could not read payload.bin: {error}",
            ) from error

    def _parse_manifest(
        self,
        raw: memoryview,
        *,
        major_version: int,
        payload_size: int,
        data_offset: int,
        metadata_size: int,
        metadata_sha256: str,
        allowed_partitions: frozenset[str],
    ) -> tuple[PayloadManifest, tuple[_PayloadDataReference, ...]]:
        budget = _ParseBudget(self.limits.maximum_protobuf_fields)
        reader = _WireReader(raw, budget)
        block_size: int | None = None
        signatures_offset: int | None = None
        signatures_size: int | None = None
        minor_version: int | None = None
        parsed_partitions: list[PayloadPartition] = []
        while not reader.done:
            field, wire = reader.key()
            if field == 3:
                block_size = self._once(
                    block_size,
                    reader.uint(wire, "payload block size"),
                    "payload block size",
                )
            elif field == 4:
                signatures_offset = self._once(
                    signatures_offset,
                    reader.uint(wire, "payload signatures offset"),
                    "payload signatures offset",
                )
            elif field == 5:
                signatures_size = self._once(
                    signatures_size,
                    reader.uint(wire, "payload signatures size"),
                    "payload signatures size",
                )
            elif field == 12:
                minor_version = self._once(
                    minor_version,
                    reader.uint(wire, "payload minor version"),
                    "payload minor version",
                )
            elif field == 13:
                if len(parsed_partitions) >= self.limits.maximum_partitions:
                    self._fail(
                        PayloadErrorCode.PARTITION_LIMIT_EXCEEDED,
                        "payload contains too many partitions",
                    )
                parsed_partitions.append(self._parse_partition(reader.bytes(wire, "payload partition"), budget))
            else:
                reader.skip(wire)

        effective_block_size = 4096 if block_size is None else block_size
        if (
            effective_block_size < 512
            or effective_block_size > 1024 * 1024
            or effective_block_size & (effective_block_size - 1)
        ):
            self._fail(
                PayloadErrorCode.MALFORMED_MANIFEST,
                "payload block size is outside the supported power-of-two range",
            )
        effective_minor_version = 0 if minor_version is None else minor_version
        if effective_minor_version != 0:
            self._fail(
                PayloadErrorCode.DELTA_UNSUPPORTED,
                "delta payloads require a source image and are not accepted for extraction",
            )
        if (signatures_offset is None) != (signatures_size is None):
            self._fail(
                PayloadErrorCode.MALFORMED_MANIFEST,
                "payload signature offset and size must be present together",
            )
        blob_size = payload_size - data_offset
        if signatures_offset is not None and signatures_size is not None:
            self._validate_span(
                signatures_offset,
                signatures_size,
                blob_size,
                "payload signature",
            )

        seen: set[str] = set()
        selected: list[PayloadPartition] = []
        ignored: list[str] = []
        output_size = 0
        operation_count = 0
        spans: list[_PayloadDataReference] = []
        operation_data_end = signatures_offset if signatures_offset is not None else blob_size
        for partition in parsed_partitions:
            if partition.name in seen:
                self._fail(
                    PayloadErrorCode.MALFORMED_MANIFEST,
                    f"payload contains duplicate partition {partition.name}",
                )
            seen.add(partition.name)
            if partition.size > self.limits.maximum_partition_bytes:
                self._fail(
                    PayloadErrorCode.SIZE_LIMIT_EXCEEDED,
                    f"payload partition {partition.name} exceeds the configured size limit",
                )
            operation_count += len(partition.operations)
            if operation_count > self.limits.maximum_operations:
                self._fail(
                    PayloadErrorCode.OPERATION_LIMIT_EXCEEDED,
                    "payload contains too many operations",
                )
            for operation in partition.operations:
                if operation.operation_type not in FULL_PAYLOAD_OPERATION_TYPES:
                    self._fail(
                        PayloadErrorCode.DELTA_UNSUPPORTED,
                        "full payload contains an operation that requires a source image",
                    )
                self._validate_operation_layout(
                    partition,
                    operation,
                    effective_block_size,
                )
                if operation.data_length:
                    self._validate_span(
                        operation.data_offset,
                        operation.data_length,
                        operation_data_end,
                        f"payload operation for {partition.name}",
                    )
                    spans.append(
                        _PayloadDataReference(
                            partition.name,
                            operation.data_offset,
                            operation.data_length,
                            operation.data_sha256,
                        )
                    )
            self._validate_partition_coverage(partition, effective_block_size)
            if partition.name in allowed_partitions:
                output_size += partition.size
                if output_size > self.limits.maximum_output_bytes:
                    self._fail(
                        PayloadErrorCode.SIZE_LIMIT_EXCEEDED,
                        "payload extraction output exceeds the configured size limit",
                    )
                selected.append(partition)
            else:
                ignored.append(partition.name)
        if not selected:
            self._fail(
                PayloadErrorCode.NO_FLASHABLE_PARTITIONS,
                "payload contains no allow-listed flashable partitions",
            )

        referenced = 0
        previous_end = 0
        for reference in sorted(spans, key=lambda item: item.offset):
            if reference.offset < previous_end:
                self._fail(
                    PayloadErrorCode.OFFSET_OUT_OF_RANGE,
                    f"payload data for {reference.partition} overlaps another operation",
                )
            previous_end = reference.offset + reference.length
            referenced += reference.length
            if referenced > self.limits.maximum_referenced_data_bytes:
                self._fail(
                    PayloadErrorCode.SIZE_LIMIT_EXCEEDED,
                    "payload references too much operation data",
                )

        return (
            PayloadManifest(
                major_version=major_version,
                minor_version=effective_minor_version,
                block_size=effective_block_size,
                payload_size=payload_size,
                data_offset=data_offset,
                metadata_size=metadata_size,
                metadata_sha256=metadata_sha256,
                manifest_sha256=hashlib.sha256(raw).hexdigest(),
                signatures_offset=signatures_offset,
                signatures_size=signatures_size,
                partitions=tuple(selected),
                ignored_partitions=tuple(sorted(ignored)),
            ),
            tuple(spans),
        )

    def _parse_partition(
        self,
        raw: memoryview,
        budget: _ParseBudget,
    ) -> PayloadPartition:
        reader = _WireReader(raw, budget)
        name: str | None = None
        size: int | None = None
        partition_hash: bytes | None = None
        operations: list[PayloadOperation] = []
        while not reader.done:
            field, wire = reader.key()
            if field == 1:
                if name is not None:
                    self._duplicate("payload partition name")
                try:
                    name = bytes(reader.bytes(wire, "payload partition name")).decode(
                        "utf-8",
                        errors="strict",
                    )
                except UnicodeDecodeError as error:
                    raise PayloadValidationError(
                        PayloadErrorCode.UNSAFE_PARTITION,
                        "payload partition name is not valid UTF-8",
                    ) from error
                if not _PARTITION_PATTERN.fullmatch(name):
                    self._fail(
                        PayloadErrorCode.UNSAFE_PARTITION,
                        f"payload partition name is not safe: {name!r}",
                    )
            elif field == 7:
                if size is not None or partition_hash is not None:
                    self._duplicate("payload new partition info")
                size, partition_hash = self._parse_partition_info(
                    reader.bytes(wire, "payload new partition info"),
                    budget,
                )
            elif field == 8:
                if len(operations) >= self.limits.maximum_operations:
                    self._fail(
                        PayloadErrorCode.OPERATION_LIMIT_EXCEEDED,
                        "payload partition contains too many operations",
                    )
                operations.append(self._parse_operation(reader.bytes(wire, "payload operation"), budget))
            else:
                reader.skip(wire)
        if name is None or size is None or partition_hash is None or not operations:
            self._fail(
                PayloadErrorCode.MALFORMED_MANIFEST,
                "payload partition is missing its name, final hash, size, or operations",
            )
        try:
            return PayloadPartition(name, size, partition_hash, tuple(operations))
        except ValueError as error:
            raise PayloadValidationError(
                PayloadErrorCode.MALFORMED_MANIFEST,
                str(error),
            ) from error

    def _parse_partition_info(
        self,
        raw: memoryview,
        budget: _ParseBudget,
    ) -> tuple[int, bytes]:
        reader = _WireReader(raw, budget)
        size: int | None = None
        digest: bytes | None = None
        while not reader.done:
            field, wire = reader.key()
            if field == 1:
                size = self._once(
                    size,
                    reader.uint(wire, "payload partition size"),
                    "payload partition size",
                )
            elif field == 2:
                if digest is not None:
                    self._duplicate("payload partition hash")
                digest = bytes(reader.bytes(wire, "payload partition hash"))
            else:
                reader.skip(wire)
        if size is None or size <= 0 or digest is None or len(digest) != _SHA256_BYTES:
            self._fail(
                PayloadErrorCode.MALFORMED_MANIFEST,
                "payload new partition info requires a positive size and SHA-256 hash",
            )
        return size, digest

    def _parse_operation(
        self,
        raw: memoryview,
        budget: _ParseBudget,
    ) -> PayloadOperation:
        reader = _WireReader(raw, budget)
        operation_type: int | None = None
        data_offset: int | None = None
        data_length: int | None = None
        data_hash: bytes | None = None
        destination_extents: list[PayloadExtent] = []
        destination_length: int | None = None
        while not reader.done:
            field, wire = reader.key()
            if field == 1:
                operation_type = self._once(
                    operation_type,
                    reader.uint(wire, "payload operation type"),
                    "payload operation type",
                )
            elif field == 2:
                data_offset = self._once(
                    data_offset,
                    reader.uint(wire, "payload operation offset"),
                    "payload operation offset",
                )
            elif field == 3:
                data_length = self._once(
                    data_length,
                    reader.uint(wire, "payload operation length"),
                    "payload operation length",
                )
            elif field == 8:
                if data_hash is not None:
                    self._duplicate("payload operation data hash")
                data_hash = bytes(reader.bytes(wire, "payload operation data hash"))
            elif field == 6:
                destination_extents.append(
                    self._parse_extent(
                        reader.bytes(wire, "payload destination extent"),
                        budget,
                    )
                )
            elif field == 7:
                destination_length = self._once(
                    destination_length,
                    reader.uint(wire, "payload destination length"),
                    "payload destination length",
                )
            else:
                reader.skip(wire)
        if operation_type is None or operation_type not in PAYLOAD_OPERATION_TYPES:
            self._fail(
                PayloadErrorCode.MALFORMED_MANIFEST,
                "payload operation has an unknown or missing type",
            )
        effective_length = 0 if data_length is None else data_length
        effective_offset = 0 if data_offset is None else data_offset
        effective_hash = b"" if data_hash is None else data_hash
        if effective_length and len(effective_hash) != _SHA256_BYTES:
            self._fail(
                PayloadErrorCode.MALFORMED_MANIFEST,
                "payload operation data requires a SHA-256 hash",
            )
        if not effective_length and effective_hash:
            self._fail(
                PayloadErrorCode.MALFORMED_MANIFEST,
                "payload operation without data cannot contain a data hash",
            )
        try:
            return PayloadOperation(
                operation_type,
                effective_offset,
                effective_length,
                effective_hash,
                tuple(destination_extents),
                destination_length,
            )
        except ValueError as error:
            raise PayloadValidationError(
                PayloadErrorCode.MALFORMED_MANIFEST,
                str(error),
            ) from error

    def _parse_extent(
        self,
        raw: memoryview,
        budget: _ParseBudget,
    ) -> PayloadExtent:
        reader = _WireReader(raw, budget)
        start_block: int | None = None
        block_count: int | None = None
        while not reader.done:
            field, wire = reader.key()
            if field == 1:
                start_block = self._once(
                    start_block,
                    reader.uint(wire, "payload extent start block"),
                    "payload extent start block",
                )
            elif field == 2:
                block_count = self._once(
                    block_count,
                    reader.uint(wire, "payload extent block count"),
                    "payload extent block count",
                )
            else:
                reader.skip(wire)
        if start_block is None or block_count is None or block_count <= 0:
            self._fail(
                PayloadErrorCode.MALFORMED_MANIFEST,
                "payload destination extent is missing its start or block count",
            )
        try:
            return PayloadExtent(start_block, block_count)
        except ValueError as error:
            raise PayloadValidationError(
                PayloadErrorCode.MALFORMED_MANIFEST,
                str(error),
            ) from error

    def _validate_operation_layout(
        self,
        partition: PayloadPartition,
        operation: PayloadOperation,
        block_size: int,
    ) -> None:
        destination_bytes = 0
        for extent in operation.destination_extents:
            block_end = extent.start_block + extent.block_count
            if block_end > _UINT64_MAX:
                self._fail(
                    PayloadErrorCode.OFFSET_OUT_OF_RANGE,
                    f"payload destination extent overflows for {partition.name}",
                )
            byte_end = block_end * block_size
            extent_bytes = extent.block_count * block_size
            if byte_end > partition.size or byte_end > _UINT64_MAX:
                self._fail(
                    PayloadErrorCode.OFFSET_OUT_OF_RANGE,
                    f"payload destination extent exceeds {partition.name}",
                )
            destination_bytes += extent_bytes
            if destination_bytes > partition.size:
                self._fail(
                    PayloadErrorCode.SIZE_LIMIT_EXCEEDED,
                    f"payload destination extents exceed {partition.name}",
                )
        if operation.destination_length is not None and operation.destination_length != destination_bytes:
            self._fail(
                PayloadErrorCode.MALFORMED_MANIFEST,
                f"payload destination length does not match extents for {partition.name}",
            )
        if operation.operation_type == 0 and operation.data_length != destination_bytes:
            self._fail(
                PayloadErrorCode.MALFORMED_MANIFEST,
                f"payload REPLACE data does not fill its destination for {partition.name}",
            )
        if operation.operation_type in FULL_PAYLOAD_OPERATION_TYPES and not operation.data_length:
            self._fail(
                PayloadErrorCode.MALFORMED_MANIFEST,
                f"payload full operation has no data for {partition.name}",
            )

    def _validate_partition_coverage(
        self,
        partition: PayloadPartition,
        block_size: int,
    ) -> None:
        intervals = sorted(
            (
                extent.start_block * block_size,
                (extent.start_block + extent.block_count) * block_size,
            )
            for operation in partition.operations
            for extent in operation.destination_extents
        )
        cursor = 0
        for start, end in intervals:
            if start != cursor:
                reason = "overlap" if start < cursor else "gap"
                self._fail(
                    PayloadErrorCode.MALFORMED_MANIFEST,
                    f"payload destination extents contain a {reason} for {partition.name}",
                )
            cursor = end
        if cursor != partition.size:
            self._fail(
                PayloadErrorCode.MALFORMED_MANIFEST,
                f"payload destination extents do not cover {partition.name}",
            )

    def _verify_operation_data(
        self,
        stream: BinaryIO,
        data_offset: int,
        references: tuple[_PayloadDataReference, ...],
        cancellation: CancellationToken,
    ) -> None:
        for reference in references:
            if cancellation.cancelled:
                raise InterruptedError("payload parsing was cancelled")
            stream.seek(data_offset + reference.offset)
            digest = hashlib.sha256()
            self._hash_exact(stream, reference.length, digest, cancellation)
            if not hmac.compare_digest(digest.digest(), reference.sha256):
                self._fail(
                    PayloadErrorCode.DATA_HASH_MISMATCH,
                    f"payload operation data hash does not match for {reference.partition}",
                )

    def _read_exact(
        self,
        stream: BinaryIO,
        length: int,
        cancellation: CancellationToken,
    ) -> bytes:
        output = bytearray()
        remaining = length
        while remaining:
            if cancellation.cancelled:
                raise InterruptedError("payload parsing was cancelled")
            chunk = stream.read(min(remaining, self.limits.hash_chunk_size))
            if not chunk:
                self._fail(
                    PayloadErrorCode.INVALID_HEADER,
                    "payload.bin is truncated",
                )
            output.extend(chunk)
            remaining -= len(chunk)
        return bytes(output)

    def _hash_exact(
        self,
        stream: BinaryIO,
        length: int,
        digest: _Digest,
        cancellation: CancellationToken,
    ) -> None:
        remaining = length
        while remaining:
            if cancellation.cancelled:
                raise InterruptedError("payload parsing was cancelled")
            chunk = stream.read(min(remaining, self.limits.hash_chunk_size))
            if not chunk:
                self._fail(
                    PayloadErrorCode.OFFSET_OUT_OF_RANGE,
                    "payload operation data is truncated",
                )
            digest.update(chunk)
            remaining -= len(chunk)

    def _skip_exact(
        self,
        stream: BinaryIO,
        length: int,
        cancellation: CancellationToken,
    ) -> None:
        remaining = length
        while remaining:
            if cancellation.cancelled:
                raise InterruptedError("payload parsing was cancelled")
            chunk = stream.read(min(remaining, self.limits.hash_chunk_size))
            if not chunk:
                self._fail(
                    PayloadErrorCode.INVALID_HEADER,
                    "payload metadata signature is truncated",
                )
            remaining -= len(chunk)

    @staticmethod
    def _validate_span(offset: int, length: int, boundary: int, label: str) -> None:
        if offset > _UINT64_MAX or length > _UINT64_MAX or offset > boundary:
            PayloadParser._fail(
                PayloadErrorCode.OFFSET_OUT_OF_RANGE,
                f"{label} starts outside payload data",
            )
        end = offset + length
        if end > _UINT64_MAX or end > boundary:
            PayloadParser._fail(
                PayloadErrorCode.OFFSET_OUT_OF_RANGE,
                f"{label} extends outside payload data",
            )

    @staticmethod
    def _once(current: int | None, value: int, label: str) -> int:
        if current is not None:
            PayloadParser._duplicate(label)
        return value

    @staticmethod
    def _duplicate(label: str) -> Never:
        raise PayloadValidationError(
            PayloadErrorCode.MALFORMED_MANIFEST,
            f"{label} appears more than once",
        )

    @staticmethod
    def _fail(code: PayloadErrorCode, message: str) -> Never:
        raise PayloadValidationError(code, message)
