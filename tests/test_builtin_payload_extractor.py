from __future__ import annotations

import bz2
import hashlib
import lzma
import struct
import tempfile
import unittest
import zipfile
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

import pixelflasher_core.payload_extractor as payload_extractor_module
from pixelflasher_core.executor import CancellationToken
from pixelflasher_core.firmware_artifacts import FirmwareArtifactService
from pixelflasher_core.payload import (
    PayloadExtent,
    PayloadExtractionError,
    PayloadExtractionRequest,
    PayloadLimits,
    PayloadManifest,
    PayloadOperation,
    PayloadParser,
    PayloadPartition,
)
from pixelflasher_core.payload_extractor import (
    BuiltinPayloadExtractor,
    BuiltinPayloadExtractorLimits,
    verify_builtin_payload_extractor_identity,
)
from pixelflasher_core.planner import ProcessedArtifactRepository
from pixelflasher_core.runtime import ApplicationRuntime

_BLOCK_SIZE = 512


def _varint(value: int) -> bytes:
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def _uint_field(number: int, value: int) -> bytes:
    return _varint(number << 3) + _varint(value)


def _bytes_field(number: int, value: bytes) -> bytes:
    return _varint((number << 3) | 2) + _varint(len(value)) + value


@dataclass(frozen=True, slots=True)
class _PayloadFixture:
    payload: bytes
    image: bytes


def _multi_operation_payload() -> _PayloadFixture:
    blocks = tuple(bytes([value]) * _BLOCK_SIZE for value in (0x11, 0x22, 0x33, 0x44))
    image = b"".join(blocks)
    specifications = (
        (0, blocks[0] + blocks[2], ((0, 1), (2, 1))),
        (1, bz2.compress(blocks[1]), ((1, 1),)),
        (8, lzma.compress(blocks[3], format=lzma.FORMAT_XZ), ((3, 1),)),
    )
    data = bytearray()
    operations: list[bytes] = []
    for operation_type, encoded, extents in specifications:
        offset = len(data)
        data.extend(encoded)
        destination_bytes = sum(block_count * _BLOCK_SIZE for _, block_count in extents)
        fields = [
            _uint_field(1, operation_type),
            _uint_field(2, offset),
            _uint_field(3, len(encoded)),
        ]
        for start_block, block_count in extents:
            fields.append(
                _bytes_field(
                    6,
                    _uint_field(1, start_block) + _uint_field(2, block_count),
                )
            )
        fields.extend(
            (
                _uint_field(7, destination_bytes),
                _bytes_field(8, hashlib.sha256(encoded).digest()),
            )
        )
        operations.append(_bytes_field(8, b"".join(fields)))
    partition_info = _uint_field(1, len(image)) + _bytes_field(2, hashlib.sha256(image).digest())
    partition = _bytes_field(1, b"boot") + _bytes_field(7, partition_info) + b"".join(operations)
    manifest = _uint_field(3, _BLOCK_SIZE) + _uint_field(12, 0) + _bytes_field(13, partition)
    payload = b"CrAU" + struct.pack(">QQI", 2, len(manifest), 0) + manifest + data
    return _PayloadFixture(payload, image)


def _parse_request(
    root: Path,
    fixture: _PayloadFixture,
) -> tuple[PayloadExtractionRequest, CancellationToken]:
    payload_path = root / "payload.bin"
    payload_path.write_bytes(fixture.payload)
    output = root / "images"
    output.mkdir(mode=0o700)
    cancellation = CancellationToken()
    manifest = PayloadParser(
        PayloadLimits(
            maximum_payload_bytes=16 * 1024 * 1024,
            maximum_partition_bytes=16 * 1024 * 1024,
            maximum_output_bytes=16 * 1024 * 1024,
            maximum_referenced_data_bytes=16 * 1024 * 1024,
        )
    ).parse(
        payload_path,
        allowed_partitions={"boot"},
        cancellation=cancellation,
    )
    return (
        PayloadExtractionRequest(payload_path, output, manifest, manifest.partitions),
        cancellation,
    )


def _synthetic_compressed_request(
    root: Path,
    *,
    encoded: bytes,
    expected: bytes,
    operation_type: int = 1,
) -> PayloadExtractionRequest:
    payload_path = root / "payload.bin"
    prefix = b"X"
    payload_path.write_bytes(prefix + encoded)
    output = root / "images"
    output.mkdir(mode=0o700)
    operation = PayloadOperation(
        operation_type,
        0,
        len(encoded),
        hashlib.sha256(encoded).digest(),
        (PayloadExtent(0, len(expected) // _BLOCK_SIZE),),
        len(expected),
    )
    partition = PayloadPartition(
        "boot",
        len(expected),
        hashlib.sha256(expected).digest(),
        (operation,),
    )
    manifest = PayloadManifest(
        2,
        0,
        _BLOCK_SIZE,
        len(prefix) + len(encoded),
        len(prefix),
        len(prefix),
        "0" * 64,
        "0" * 64,
        None,
        None,
        (partition,),
    )
    return PayloadExtractionRequest(payload_path, output, manifest, (partition,))


class _AutoCancellingToken(CancellationToken):
    def __init__(self, cancel_after_checks: int) -> None:
        super().__init__()
        self._checks = 0
        self._cancel_after_checks = cancel_after_checks

    @property
    def cancelled(self) -> bool:
        self._checks += 1
        return self._checks >= self._cancel_after_checks


class BuiltinPayloadExtractorTests(unittest.TestCase):
    def test_multi_operation_and_extent_replace_bz_and_xz_are_reconstructed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _multi_operation_payload()
            request, cancellation = _parse_request(Path(directory), fixture)

            result = BuiltinPayloadExtractor().extract(request, cancellation)

            self.assertEqual(("boot",), result.partitions)
            self.assertEqual(fixture.image, (request.output_directory / "boot.img").read_bytes())

    def test_firmware_service_uses_real_runner_and_promotes_verified_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = _multi_operation_payload()
            archive_path = root / "ota.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("payload.bin", fixture.payload)
            repository = ProcessedArtifactRepository()
            service = FirmwareArtifactService(
                repository,
                root / "processed",
                payload_extractor=BuiltinPayloadExtractor(),
            )

            result = service.process(archive_path)

            self.assertTrue(result.ok, result.message)
            boot = next(artifact for artifact in result.artifacts if artifact.role == "partition:boot")
            self.assertEqual(fixture.image, Path(boot.path).read_bytes())

    def test_truncated_compressed_stream_fails_typed_and_removes_partial_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = b"A" * _BLOCK_SIZE
            request = _synthetic_compressed_request(
                root,
                encoded=bz2.compress(expected)[:-4],
                expected=expected,
            )

            with self.assertRaises(PayloadExtractionError) as raised:
                BuiltinPayloadExtractor().extract(request, CancellationToken())

            self.assertEqual("payload_compressed_stream_truncated", raised.exception.code)
            self.assertEqual([], list(request.output_directory.iterdir()))

    def test_decompression_bomb_cannot_write_past_manifest_extents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = b"A" * _BLOCK_SIZE
            request = _synthetic_compressed_request(
                root,
                encoded=bz2.compress(expected * 4),
                expected=expected,
            )

            with self.assertRaises(PayloadExtractionError) as raised:
                BuiltinPayloadExtractor(BuiltinPayloadExtractorLimits(chunk_size=128)).extract(
                    request, CancellationToken()
                )

            self.assertEqual("payload_decompression_limit_exceeded", raised.exception.code)
            self.assertEqual([], list(request.output_directory.iterdir()))

    def test_cancellation_during_decompression_removes_exclusive_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = b"B" * (4 * 1024 * 1024)
            request = _synthetic_compressed_request(
                root,
                encoded=bz2.compress(expected),
                expected=expected,
            )

            with self.assertRaises(InterruptedError):
                BuiltinPayloadExtractor(BuiltinPayloadExtractorLimits(chunk_size=64 * 1024)).extract(
                    request, _AutoCancellingToken(5)
                )

            self.assertEqual([], list(request.output_directory.iterdir()))

    def test_payload_tamper_is_detected_even_after_parser_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _multi_operation_payload()
            request, cancellation = _parse_request(Path(directory), fixture)
            payload = bytearray(request.payload_path.read_bytes())
            payload[request.manifest.data_offset] ^= 0xFF
            request.payload_path.write_bytes(payload)

            with self.assertRaises(PayloadExtractionError) as raised:
                BuiltinPayloadExtractor().extract(request, cancellation)

            self.assertEqual("payload_operation_hash_mismatch", raised.exception.code)
            self.assertEqual([], list(request.output_directory.iterdir()))

    def test_integrity_resource_tamper_fails_closed_before_output_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _multi_operation_payload()
            request, cancellation = _parse_request(Path(directory), fixture)
            original_reader = payload_extractor_module._read_packaged_resource

            def tampered_reader(name: str) -> bytes:
                value = original_reader(name)
                return value + b"# tampered" if name == "payload_extractor.py" else value

            with patch(
                "pixelflasher_core.payload_extractor._read_packaged_resource",
                side_effect=tampered_reader,
            ):
                self.assertFalse(verify_builtin_payload_extractor_identity().trusted)
                with self.assertRaises(PayloadExtractionError) as raised:
                    BuiltinPayloadExtractor().extract(request, cancellation)

            self.assertEqual("payload_runner_identity_mismatch", raised.exception.code)
            self.assertEqual([], list(request.output_directory.iterdir()))

    def test_existing_output_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _multi_operation_payload()
            request, cancellation = _parse_request(Path(directory), fixture)
            existing = request.output_directory / "boot.img"
            existing.write_bytes(b"preserve")

            with self.assertRaises(PayloadExtractionError) as raised:
                BuiltinPayloadExtractor().extract(request, cancellation)

            self.assertEqual("payload_output_directory_not_empty", raised.exception.code)
            self.assertEqual(b"preserve", existing.read_bytes())

    def test_application_runtime_composes_builtin_payload_runner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = ApplicationRuntime.open(Path(directory) / "PixelFlasher.json")
            try:
                extractor = runtime.command_engine.firmware_artifact_service.payload_extractor
                self.assertIsInstance(extractor, BuiltinPayloadExtractor)
                self.assertTrue(extractor.identity.trusted)
            finally:
                runtime.engine.shutdown()

    def test_all_packaging_specs_retain_integrity_resources(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        specs = (
            "build-on-linux.spec",
            "build-on-mac-intel-only.spec",
            "build-on-mac.spec",
            "build-on-win-arm64.spec",
            "build-on-win.spec",
        )
        for name in specs:
            with self.subTest(spec=name):
                content = (repository / name).read_text(encoding="utf-8")
                self.assertIn("pixelflasher_core/payload_extractor.py", content)
                self.assertIn(
                    "pixelflasher_core/payload_extractor.integrity.json",
                    content,
                )


if __name__ == "__main__":
    unittest.main()
