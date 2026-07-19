from __future__ import annotations

import base64
import hashlib
import struct
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from pixelflasher_core.contracts import AppSnapshot
from pixelflasher_core.executor import CancellationToken
from pixelflasher_core.firmware import FirmwareKind
from pixelflasher_core.firmware_artifacts import (
    FirmwareArtifactService,
    FirmwareProcessingCode,
    FirmwareProcessingStatus,
)
from pixelflasher_core.payload import (
    PayloadExtractionError,
    PayloadExtractionRequest,
    PayloadExtractionResult,
    PayloadExtractorIdentity,
)
from pixelflasher_core.planner import ProcessedArtifactRepository

PAYLOAD_BLOCK_SIZE = 512


def padded_partition(image: bytes) -> bytes:
    remainder = len(image) % PAYLOAD_BLOCK_SIZE
    return image if remainder == 0 else image + (b"\0" * (PAYLOAD_BLOCK_SIZE - remainder))


def _varint(value: int) -> bytes:
    encoded = bytearray()
    while value > 0x7F:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _uint_field(number: int, value: int) -> bytes:
    return _varint(number << 3) + _varint(value)


def _bytes_field(number: int, value: bytes) -> bytes:
    return _varint((number << 3) | 2) + _varint(len(value)) + value


def minimal_payload(
    partitions: dict[str, bytes],
    *,
    operation_hashes: dict[str, bytes] | None = None,
    operation_offsets: dict[str, int] | None = None,
    operation_types: dict[str, int] | None = None,
    extent_start_blocks: dict[str, int] | None = None,
    include_destination_extents: bool = True,
    metadata_signature: bytes = b"",
) -> bytes:
    manifest_parts: list[bytes] = []
    payload_data = bytearray()
    operation_hashes = operation_hashes or {}
    operation_offsets = operation_offsets or {}
    operation_types = operation_types or {}
    extent_start_blocks = extent_start_blocks or {}
    for name, raw_image in partitions.items():
        image = padded_partition(raw_image)
        offset = operation_offsets.get(name, len(payload_data))
        payload_data.extend(image)
        operation_hash = operation_hashes.get(name, hashlib.sha256(image).digest())
        destination_extent = _uint_field(1, extent_start_blocks.get(name, 0)) + _uint_field(
            2,
            len(image) // PAYLOAD_BLOCK_SIZE,
        )
        operation_fields = [
            _uint_field(1, operation_types.get(name, 0)),
            _uint_field(2, offset),
            _uint_field(3, len(image)),
        ]
        if include_destination_extents:
            operation_fields.extend(
                (
                    _bytes_field(6, destination_extent),
                    _uint_field(7, len(image)),
                )
            )
        operation_fields.append(_bytes_field(8, operation_hash))
        operation = b"".join(operation_fields)
        partition_info = _uint_field(1, len(image)) + _bytes_field(
            2,
            hashlib.sha256(image).digest(),
        )
        partition = b"".join(
            (
                _bytes_field(1, name.encode("ascii")),
                _bytes_field(7, partition_info),
                _bytes_field(8, operation),
            )
        )
        manifest_parts.append(_bytes_field(13, partition))
    manifest = _uint_field(3, PAYLOAD_BLOCK_SIZE) + _uint_field(12, 0) + b"".join(manifest_parts)
    return (
        b"CrAU"
        + struct.pack(">QQI", 2, len(manifest), len(metadata_signature))
        + manifest
        + metadata_signature
        + payload_data
    )


def payload_properties(payload: bytes, *, file_hash: bytes | None = None) -> bytes:
    _major, manifest_size, signature_size = struct.unpack(">QQI", payload[4:24])
    metadata_size = 24 + manifest_size
    properties = (
        f"FILE_HASH={base64.b64encode(file_hash or hashlib.sha256(payload).digest()).decode('ascii')}\n"
        f"FILE_SIZE={len(payload)}\n"
        f"METADATA_HASH={base64.b64encode(hashlib.sha256(payload[:metadata_size]).digest()).decode('ascii')}\n"
        f"METADATA_SIZE={metadata_size}\n"
    )
    return properties.encode("ascii")


def write_zip(path: Path, entries: list[tuple[str, bytes]]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in entries:
            archive.writestr(name, content)


class StrictPayloadExtractor:
    def __init__(
        self,
        *,
        verified: bool = True,
        cancel: bool = False,
        corrupt_output: bool = False,
        extra_output: bool = False,
    ) -> None:
        self._identity = PayloadExtractorIdentity(
            "strict-test-extractor",
            "1",
            hashlib.sha256(b"strict-test-extractor-v1").hexdigest(),
            packaged=True,
            verified=verified,
        )
        self.cancel = cancel
        self.corrupt_output = corrupt_output
        self.extra_output = extra_output
        self.calls: list[PayloadExtractionRequest] = []

    @property
    def identity(self) -> PayloadExtractorIdentity:
        return self._identity

    def extract(
        self,
        request: PayloadExtractionRequest,
        cancellation: CancellationToken,
    ) -> PayloadExtractionResult:
        self.calls.append(request)
        partitions = tuple(partition.name for partition in request.partitions)
        if self.cancel:
            cancellation.cancel()
            return PayloadExtractionResult(partitions)
        with request.payload_path.open("rb") as payload:
            for partition in request.partitions:
                if len(partition.operations) != 1:
                    raise PayloadExtractionError(
                        "strict_fake_operation_count",
                        "strict fake accepts one operation per partition",
                    )
                operation = partition.operations[0]
                if operation.operation_type != 0 or operation.data_length != partition.size:
                    raise PayloadExtractionError(
                        "strict_fake_operation_invalid",
                        "strict fake accepts one full REPLACE operation",
                    )
                payload.seek(request.manifest.data_offset + operation.data_offset)
                image = payload.read(operation.data_length)
                if len(image) != operation.data_length:
                    raise PayloadExtractionError(
                        "strict_fake_payload_truncated",
                        "strict fake could not read operation data",
                    )
                if self.corrupt_output and image:
                    image = bytes([image[0] ^ 0xFF]) + image[1:]
                (request.output_directory / f"{partition.name}.img").write_bytes(image)
        if self.extra_output:
            (request.output_directory / "unexpected.txt").write_bytes(b"unexpected")
        return PayloadExtractionResult(partitions)


class SwappingPayloadExtractor(StrictPayloadExtractor):
    def __init__(self, replacement: bytes) -> None:
        super().__init__()
        self.replacement = replacement
        self.swap_now = threading.Event()
        self.swapped = threading.Event()

    def extract(
        self,
        request: PayloadExtractionRequest,
        cancellation: CancellationToken,
    ) -> PayloadExtractionResult:
        result = super().extract(request, cancellation)

        def swap() -> None:
            if not self.swap_now.wait(5):
                return
            temporary = request.output_directory / "replacement.tmp"
            temporary.write_bytes(self.replacement)
            temporary.replace(request.output_directory / "boot.img")
            self.swapped.set()

        threading.Thread(target=swap, daemon=True).start()
        return result


class PayloadFirmwareProcessingTests(unittest.TestCase):
    def make_service(
        self,
        output: Path,
        extractor: StrictPayloadExtractor | None,
    ) -> tuple[FirmwareArtifactService, ProcessedArtifactRepository]:
        repository = ProcessedArtifactRepository()
        return (
            FirmwareArtifactService(
                repository,
                output,
                payload_extractor=extractor,
            ),
            repository,
        )

    def test_valid_minimal_payload_is_extracted_for_custom_and_ota(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = minimal_payload({"boot": b"verified stock boot"})
            cases = (
                ("custom", [], FirmwareKind.CUSTOM),
                (
                    "ota",
                    [
                        (
                            "META-INF/com/android/metadata",
                            b"ota-type=AB\npre-device=husky\npost-build-incremental=123\n",
                        )
                    ],
                    FirmwareKind.OTA,
                ),
            )
            for label, metadata, expected_kind in cases:
                with self.subTest(kind=label):
                    archive = root / f"{label}.zip"
                    write_zip(
                        archive,
                        metadata
                        + [
                            ("payload.bin", payload),
                            ("payload_properties.txt", payload_properties(payload)),
                        ],
                    )
                    extractor = StrictPayloadExtractor()
                    service, repository = self.make_service(
                        root / f"processed-{label}",
                        extractor,
                    )

                    result = service.process(archive, expected_devices=("husky",))

                    self.assertTrue(result.ok)
                    self.assertEqual(expected_kind, result.inspection.kind)
                    self.assertEqual(
                        ["firmware", "partition:boot"],
                        [artifact.role for artifact in result.artifacts],
                    )
                    self.assertEqual({"boot.img"}, {item.name for item in Path(result.output_directory).iterdir()})
                    self.assertEqual(
                        padded_partition(b"verified stock boot"),
                        Path(result.artifacts[1].path).read_bytes(),
                    )
                    self.assertEqual(1, len(extractor.calls))
                    self.assertEqual(
                        result.artifacts,
                        repository.resolve(AppSnapshot(firmware=result.firmware)),
                    )

    def test_signed_payload_properties_hash_only_the_aosp_metadata_region(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            signature = b"signed-metadata" * 4
            payload = minimal_payload(
                {"boot": b"signed payload boot"},
                metadata_signature=signature,
            )
            archive = root / "signed.zip"
            write_zip(
                archive,
                [
                    ("payload.bin", payload),
                    ("payload_properties.txt", payload_properties(payload)),
                ],
            )
            service, _repository = self.make_service(
                root / "processed-signed",
                StrictPayloadExtractor(),
            )

            result = service.process(archive)

            self.assertTrue(result.ok)
            self.assertEqual(
                padded_partition(b"signed payload boot"),
                Path(result.artifacts[1].path).read_bytes(),
            )

    def test_output_name_swap_cannot_promote_bytes_that_were_not_hashed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            verified = padded_partition(b"GOOD")
            replacement = padded_partition(b"EVL!")
            expected_hash = hashlib.sha256(verified).hexdigest()
            payload = minimal_payload({"boot": verified})
            archive = root / "swap.zip"
            write_zip(archive, [("payload.bin", payload)])
            extractor = SwappingPayloadExtractor(replacement)
            service, _repository = self.make_service(root / "processed-swap", extractor)

            original_compare = __import__("hmac").compare_digest

            def compare(left: object, right: object) -> bool:
                if left == expected_hash and right == expected_hash and not extractor.swap_now.is_set():
                    extractor.swap_now.set()
                    self.assertTrue(extractor.swapped.wait(5))
                return original_compare(left, right)  # type: ignore[arg-type]

            with patch(
                "pixelflasher_core.firmware_artifacts.hmac.compare_digest",
                side_effect=compare,
            ):
                result = service.process(archive)

            self.assertTrue(extractor.swapped.is_set())
            if result.ok:
                artifact = result.artifacts[1]
                self.assertEqual(expected_hash, artifact.sha256)
                self.assertEqual(verified, Path(artifact.path).read_bytes())
            else:
                self.assertIn(
                    result.code,
                    {
                        FirmwareProcessingCode.PAYLOAD_HASH_MISMATCH,
                        FirmwareProcessingCode.PAYLOAD_OUTPUT_INVALID,
                    },
                )

    def test_production_fails_closed_without_a_packaged_verified_extractor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = minimal_payload({"boot": b"boot"})
            archive = root / "custom.zip"
            write_zip(archive, [("payload.bin", payload)])
            cases = (
                ("missing", None),
                ("unverified", StrictPayloadExtractor(verified=False)),
            )
            for label, extractor in cases:
                with self.subTest(extractor=label):
                    output = root / f"processed-{label}"
                    service, repository = self.make_service(output, extractor)

                    result = service.process(archive)

                    self.assertEqual(
                        FirmwareProcessingCode.PAYLOAD_EXTRACTOR_UNAVAILABLE,
                        result.code,
                    )
                    self.assertFalse(result.registered)
                    self.assertEqual((), repository.resolve(AppSnapshot(firmware=result.firmware)))
                    if extractor is not None:
                        self.assertEqual([], extractor.calls)
                    self.assertTrue(output.exists())
                    self.assertEqual([], list(output.iterdir()))

    def test_payload_zip_traversal_is_rejected_before_staging(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "traversal.zip"
            write_zip(archive, [("../payload.bin", minimal_payload({"boot": b"boot"}))])
            output = root / "processed"
            service, _repository = self.make_service(output, StrictPayloadExtractor())

            result = service.process(archive)

            self.assertEqual(FirmwareProcessingCode.UNSAFE_PATH, result.code)
            self.assertFalse(output.exists())
            self.assertFalse((root / "payload.bin").exists())

    def test_truncated_and_malformed_payloads_fail_without_running_extractor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            truncated = b"CrAU" + struct.pack(">QQI", 2, 100, 0) + b"short"
            malformed_manifest = b"\x80" * 11
            malformed = b"CrAU" + struct.pack(">QQI", 2, len(malformed_manifest), 0) + malformed_manifest
            out_of_range = minimal_payload(
                {"boot": b"boot"},
                operation_offsets={"boot": 10_000},
            )
            for label, payload in (
                ("truncated", truncated),
                ("malformed", malformed),
                ("out-of-range", out_of_range),
            ):
                with self.subTest(payload=label):
                    archive = root / f"{label}.zip"
                    write_zip(archive, [("payload.bin", payload)])
                    extractor = StrictPayloadExtractor()
                    service, _repository = self.make_service(
                        root / f"processed-{label}",
                        extractor,
                    )

                    result = service.process(archive)

                    self.assertEqual(FirmwareProcessingCode.PAYLOAD_INVALID, result.code)
                    self.assertEqual([], extractor.calls)
                    self.assertFalse(result.registered)

    def test_full_payload_requires_safe_destination_extents_and_full_operation_types(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = (
                (
                    "missing-extents",
                    minimal_payload(
                        {"boot": b"boot"},
                        include_destination_extents=False,
                    ),
                ),
                (
                    "out-of-range-extent",
                    minimal_payload(
                        {"boot": b"boot"},
                        extent_start_blocks={"boot": 1},
                    ),
                ),
                (
                    "delta-zero-operation",
                    minimal_payload(
                        {"boot": b"boot"},
                        operation_types={"boot": 6},
                    ),
                ),
            )
            for label, payload in cases:
                with self.subTest(payload=label):
                    archive = root / f"{label}.zip"
                    write_zip(archive, [("payload.bin", payload)])
                    extractor = StrictPayloadExtractor()
                    service, _repository = self.make_service(
                        root / f"processed-{label}",
                        extractor,
                    )

                    result = service.process(archive)

                    self.assertEqual(FirmwareProcessingCode.PAYLOAD_INVALID, result.code)
                    self.assertEqual([], extractor.calls)
                    self.assertFalse(result.registered)

    def test_wrong_device_is_rejected_before_payload_parsing_or_staging(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "wrong-device.zip"
            write_zip(
                archive,
                [
                    ("android-info.txt", b"require product=husky\n"),
                    ("payload.bin", minimal_payload({"boot": b"boot"})),
                ],
            )
            extractor = StrictPayloadExtractor()
            output = root / "processed"
            service, _repository = self.make_service(output, extractor)

            result = service.process(archive, expected_devices=("shiba",))

            self.assertEqual(FirmwareProcessingCode.DEVICE_MISMATCH, result.code)
            self.assertEqual([], extractor.calls)
            self.assertFalse(output.exists())

    def test_operation_property_and_output_hash_mismatches_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = b"verified image"
            valid_payload = minimal_payload({"boot": image})
            bad_operation_payload = minimal_payload(
                {"boot": image},
                operation_hashes={"boot": hashlib.sha256(b"different").digest()},
            )
            cases = (
                (
                    "operation",
                    bad_operation_payload,
                    None,
                    StrictPayloadExtractor(),
                ),
                (
                    "properties",
                    valid_payload,
                    payload_properties(valid_payload, file_hash=b"\0" * 32),
                    StrictPayloadExtractor(),
                ),
                (
                    "output",
                    valid_payload,
                    None,
                    StrictPayloadExtractor(corrupt_output=True),
                ),
            )
            for label, payload, properties, extractor in cases:
                with self.subTest(source=label):
                    archive = root / f"{label}.zip"
                    entries = [("payload.bin", payload)]
                    if properties is not None:
                        entries.append(("payload_properties.txt", properties))
                    write_zip(archive, entries)
                    output = root / f"processed-{label}"
                    service, repository = self.make_service(output, extractor)

                    result = service.process(archive)

                    self.assertEqual(FirmwareProcessingCode.PAYLOAD_HASH_MISMATCH, result.code)
                    self.assertFalse(result.registered)
                    self.assertEqual((), repository.resolve(AppSnapshot(firmware=result.firmware)))
                    self.assertTrue(output.exists())
                    self.assertEqual([], list(output.iterdir()))

    def test_cancellation_and_extra_extractor_output_never_promote_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "custom.zip"
            write_zip(archive, [("payload.bin", minimal_payload({"boot": b"boot"}))])
            cases = (
                (
                    "cancelled",
                    StrictPayloadExtractor(cancel=True),
                    FirmwareProcessingStatus.CANCELLED,
                    FirmwareProcessingCode.CANCELLED,
                ),
                (
                    "extra",
                    StrictPayloadExtractor(extra_output=True),
                    FirmwareProcessingStatus.FAILED,
                    FirmwareProcessingCode.PAYLOAD_OUTPUT_INVALID,
                ),
            )
            for label, extractor, status, code in cases:
                with self.subTest(case=label):
                    output = root / f"processed-{label}"
                    service, repository = self.make_service(output, extractor)

                    result = service.process(archive)

                    self.assertEqual(status, result.status)
                    self.assertEqual(code, result.code)
                    self.assertFalse(result.registered)
                    self.assertEqual((), repository.resolve(AppSnapshot(firmware=result.firmware)))
                    self.assertTrue(output.exists())
                    self.assertEqual([], list(output.iterdir()))


if __name__ == "__main__":
    unittest.main()
