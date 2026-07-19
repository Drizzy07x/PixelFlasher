"""Bounded, fail-closed APK identity and signature verification.

The inspector deliberately does not call Android tooling and never extracts an
archive member to disk.  APK Signature Scheme v2/v3 signatures are verified
against the exact signed file regions.  JAR (v1) signatures are verified as a
detached CMS signature and every non-signature archive member is checked
against ``META-INF/MANIFEST.MF``.

Only a successfully verified APK produces :class:`ApkIdentity`.  All malformed,
unsupported, or unverifiable input crosses the public boundary as
:class:`ApkInspectionError` with a stable code.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import stat
import struct
import unicodedata
import xml.etree.ElementTree as ET
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import TYPE_CHECKING, BinaryIO, Final

if TYPE_CHECKING:
    from cryptography import x509
    from cryptography.hazmat.primitives.hashes import HashAlgorithm

__all__ = (
    "ApkIdentity",
    "ApkInspectionCode",
    "ApkInspectionError",
    "ApkInspectionLimits",
    "ApkInspector",
    "inspect_apk",
)

_APK_SIG_BLOCK_MAGIC: Final = b"APK Sig Block 42"
_APK_SIG_V2_ID: Final = 0x7109871A
_APK_SIG_V3_ID: Final = 0xF05368C0
_APK_SIG_V31_ID: Final = 0x1B93AD61
_V2_STRIPPING_PROTECTION_ATTR_ID: Final = 0xBEEFF00D
_EOCD_SIGNATURE: Final = b"PK\x05\x06"
_LOCAL_FILE_SIGNATURE: Final = 0x04034B50
_MANIFEST_PATH: Final = "AndroidManifest.xml"
_JAR_MANIFEST_PATH: Final = "META-INF/MANIFEST.MF"
_PACKAGE_NAME = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+\Z"
)
_V1_SIGNATURE_FILE = re.compile(
    r"META-INF/([A-Za-z0-9_-]{1,64})\.SF\Z",
    re.IGNORECASE,
)
_V1_BLOCK_FILE = re.compile(
    r"META-INF/([A-Za-z0-9_-]{1,64})\.(RSA|DSA|EC)\Z",
    re.IGNORECASE,
)
_V1_IGNORED_FILE = re.compile(
    r"META-INF/(?:MANIFEST\.MF|[A-Za-z0-9_-]{1,64}\.(?:SF|RSA|DSA|EC))\Z",
    re.IGNORECASE,
)


class ApkInspectionCode(StrEnum):
    INVALID_PATH = "apk_invalid_path"
    FILE_NOT_FOUND = "apk_file_not_found"
    FILE_TOO_LARGE = "apk_file_too_large"
    NOT_REGULAR_FILE = "apk_not_regular_file"
    READ_FAILED = "apk_read_failed"
    SOURCE_CHANGED = "apk_source_changed"
    INVALID_ZIP = "apk_invalid_zip"
    UNSAFE_ARCHIVE = "apk_unsafe_archive"
    DUPLICATE_ENTRY = "apk_duplicate_entry"
    TOO_MANY_ENTRIES = "apk_entry_limit_exceeded"
    MEMBER_TOO_LARGE = "apk_member_limit_exceeded"
    EXPANDED_SIZE_EXCEEDED = "apk_expanded_size_exceeded"
    SUSPICIOUS_COMPRESSION = "apk_suspicious_compression"
    MANIFEST_MISSING = "apk_manifest_missing"
    MANIFEST_TOO_LARGE = "apk_manifest_too_large"
    MANIFEST_INVALID = "apk_manifest_invalid"
    PACKAGE_NAME_INVALID = "apk_package_name_invalid"
    SIGNATURE_MISSING = "apk_signature_missing"
    SIGNATURE_BLOCK_INVALID = "apk_signature_block_invalid"
    SIGNATURE_UNSUPPORTED = "apk_signature_unsupported"
    SIGNATURE_INVALID = "apk_signature_invalid"
    CONTENT_DIGEST_MISMATCH = "apk_content_digest_mismatch"
    CRYPTOGRAPHY_UNAVAILABLE = "apk_cryptography_unavailable"
    INSPECTION_FAILED = "apk_inspection_failed"


class ApkInspectionError(RuntimeError):
    """Stable public failure raised instead of parser/library exceptions."""

    def __init__(self, code: ApkInspectionCode, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class ApkIdentity:
    package_name: str
    sha256: str
    signer_sha256: tuple[str, ...]
    schemes: tuple[str, ...]
    verified: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "signer_sha256", tuple(self.signer_sha256))
        object.__setattr__(self, "schemes", tuple(self.schemes))
        if not _valid_package_name(self.package_name):
            raise ValueError("package_name must be a valid Android package name")
        if not re.fullmatch(r"[0-9a-f]{64}", self.sha256):
            raise ValueError("sha256 must be a lowercase SHA-256 digest")
        if not self.signer_sha256 or any(
            not re.fullmatch(r"[0-9a-f]{64}", value)
            for value in self.signer_sha256
        ):
            raise ValueError("signer_sha256 must contain SHA-256 certificate digests")
        if not self.schemes or any(value not in {"v1", "v2", "v3"} for value in self.schemes):
            raise ValueError("schemes must contain supported APK signature schemes")
        if tuple(dict.fromkeys(self.signer_sha256)) != self.signer_sha256:
            raise ValueError("signer_sha256 must not contain duplicates")
        if tuple(dict.fromkeys(self.schemes)) != self.schemes:
            raise ValueError("schemes must not contain duplicates")
        if not self.verified:
            raise ValueError("ApkIdentity can only represent a verified APK")


@dataclass(frozen=True, slots=True)
class ApkInspectionLimits:
    maximum_apk_bytes: int = 4 * 1024 * 1024 * 1024
    maximum_entries: int = 20_000
    maximum_member_bytes: int = 2 * 1024 * 1024 * 1024
    maximum_expanded_bytes: int = 8 * 1024 * 1024 * 1024
    maximum_compression_ratio: float = 1_000.0
    maximum_manifest_bytes: int = 2 * 1024 * 1024
    maximum_signature_block_bytes: int = 32 * 1024 * 1024
    maximum_v1_metadata_bytes: int = 8 * 1024 * 1024
    maximum_signers: int = 32
    maximum_certificates_per_signer: int = 16
    maximum_axml_strings: int = 100_000
    maximum_axml_string_bytes: int = 1024 * 1024
    io_chunk_size: int = 1024 * 1024

    def __post_init__(self) -> None:
        integers = (
            self.maximum_apk_bytes,
            self.maximum_entries,
            self.maximum_member_bytes,
            self.maximum_expanded_bytes,
            self.maximum_manifest_bytes,
            self.maximum_signature_block_bytes,
            self.maximum_v1_metadata_bytes,
            self.maximum_signers,
            self.maximum_certificates_per_signer,
            self.maximum_axml_strings,
            self.maximum_axml_string_bytes,
            self.io_chunk_size,
        )
        if any(value <= 0 for value in integers):
            raise ValueError("APK inspection limits must be positive")
        if self.maximum_compression_ratio < 1:
            raise ValueError("maximum_compression_ratio must be at least one")


@dataclass(frozen=True, slots=True)
class _Eocd:
    offset: int
    central_directory_offset: int
    central_directory_size: int
    bytes: bytes


@dataclass(frozen=True, slots=True)
class _SigningBlock:
    offset: int
    pairs: Mapping[int, bytes]

    def __post_init__(self) -> None:
        object.__setattr__(self, "pairs", MappingProxyType(dict(self.pairs)))


@dataclass(frozen=True, slots=True)
class _Archive:
    infos: tuple[zipfile.ZipInfo, ...]
    by_name: Mapping[str, zipfile.ZipInfo]
    eocd: _Eocd
    signing_block: _SigningBlock | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "infos", tuple(self.infos))
        object.__setattr__(self, "by_name", MappingProxyType(dict(self.by_name)))


@dataclass(frozen=True, slots=True)
class _SchemeResult:
    scheme: str
    signer_digests: tuple[str, ...]


class _ParseFailure(Exception):
    def __init__(self, code: ApkInspectionCode, message: str) -> None:
        super().__init__(message)
        self.code = code


class _ByteReader:
    __slots__ = ("_data", "_offset")

    def __init__(self, data: bytes | memoryview) -> None:
        self._data = memoryview(data)
        self._offset = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self._offset

    def take(self, size: int) -> bytes:
        if size < 0 or size > self.remaining:
            raise _ParseFailure(
                ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                "APK signature structure is truncated",
            )
        start = self._offset
        self._offset += size
        return bytes(self._data[start : start + size])

    def uint32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def length_prefixed(self) -> bytes:
        return self.take(self.uint32())

    def finish(self) -> None:
        if self.remaining:
            raise _ParseFailure(
                ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                "APK signature structure contains trailing data",
            )


@dataclass(frozen=True, slots=True)
class _DerValue:
    tag: int
    encoded: bytes
    content: bytes


class ApkInspector:
    """Inspect one APK without extraction or external executables."""

    def __init__(self, *, limits: ApkInspectionLimits | None = None) -> None:
        self.limits = limits or ApkInspectionLimits()

    def inspect(self, path: str | os.PathLike[str]) -> ApkIdentity:
        try:
            source = _validated_source_path(path)
            with source.open("rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise _ParseFailure(
                        ApkInspectionCode.NOT_REGULAR_FILE,
                        "APK source must be a regular file",
                    )
                if before.st_size > self.limits.maximum_apk_bytes:
                    raise _ParseFailure(
                        ApkInspectionCode.FILE_TOO_LARGE,
                        "APK exceeds the configured file-size limit",
                    )
                apk_digest = _sha256_stream(stream, self.limits.io_chunk_size)
                stream.seek(0)
                archive = self._open_archive(stream, before.st_size)
                manifest = self._read_member_from_stream(
                    stream,
                    archive.by_name[_MANIFEST_PATH],
                    self.limits.maximum_manifest_bytes,
                )
                package_name = _parse_package_name(manifest, self.limits)
                scheme_results = self._verify_signatures(stream, archive)
                after_digest = _sha256_stream(stream, self.limits.io_chunk_size)
                after = os.fstat(stream.fileno())
                if (
                    after_digest != apk_digest
                    or before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns
                ):
                    raise _ParseFailure(
                        ApkInspectionCode.SOURCE_CHANGED,
                        "APK changed during inspection",
                    )
            schemes = tuple(result.scheme for result in scheme_results)
            signer_digests = tuple(
                dict.fromkeys(
                    signer
                    for result in scheme_results
                    for signer in result.signer_digests
                )
            )
            return ApkIdentity(
                package_name=package_name,
                sha256=apk_digest.hex(),
                signer_sha256=signer_digests,
                schemes=schemes,
                verified=True,
            )
        except ApkInspectionError:
            raise
        except _ParseFailure as error:
            raise ApkInspectionError(error.code, str(error)) from error
        except FileNotFoundError as error:
            raise ApkInspectionError(
                ApkInspectionCode.FILE_NOT_FOUND,
                "APK file does not exist",
            ) from error
        except (PermissionError, OSError) as error:
            raise ApkInspectionError(
                ApkInspectionCode.READ_FAILED,
                "APK could not be read",
            ) from error
        except (zipfile.BadZipFile, zipfile.LargeZipFile) as error:
            raise ApkInspectionError(
                ApkInspectionCode.INVALID_ZIP,
                "APK is not a valid bounded ZIP archive",
            ) from error
        except Exception as error:
            # The public parser boundary must remain fuzz-friendly.  Programmer
            # and third-party parser exceptions are never exposed to callers.
            raise ApkInspectionError(
                ApkInspectionCode.INSPECTION_FAILED,
                "APK inspection failed safely",
            ) from error

    def _open_archive(self, stream: BinaryIO, file_size: int) -> _Archive:
        eocd = _read_eocd(stream, file_size)
        signing_block = self._read_signing_block(stream, eocd)
        data_boundary = (
            signing_block.offset
            if signing_block is not None
            else eocd.central_directory_offset
        )
        stream.seek(0)
        with zipfile.ZipFile(stream, mode="r", allowZip64=False) as apk:
            infos = tuple(apk.infolist())
            if len(infos) > self.limits.maximum_entries:
                raise _ParseFailure(
                    ApkInspectionCode.TOO_MANY_ENTRIES,
                    "APK contains too many archive entries",
                )
            by_name = self._validate_entries(stream, infos, data_boundary)
        if _MANIFEST_PATH not in by_name:
            raise _ParseFailure(
                ApkInspectionCode.MANIFEST_MISSING,
                "APK does not contain AndroidManifest.xml",
            )
        return _Archive(infos, by_name, eocd, signing_block)

    def _validate_entries(
        self,
        stream: BinaryIO,
        infos: Sequence[zipfile.ZipInfo],
        data_boundary: int,
    ) -> dict[str, zipfile.ZipInfo]:
        expanded = 0
        normalized: dict[str, zipfile.ZipInfo] = {}
        ranges: list[tuple[int, int]] = []
        for info in infos:
            name = _safe_archive_name(info.filename)
            identity = name.casefold()
            if identity in normalized:
                raise _ParseFailure(
                    ApkInspectionCode.DUPLICATE_ENTRY,
                    "APK contains duplicate or ambiguous archive entries",
                )
            normalized[identity] = info
            expanded += info.file_size
            if info.file_size > self.limits.maximum_member_bytes:
                raise _ParseFailure(
                    ApkInspectionCode.MEMBER_TOO_LARGE,
                    "APK member exceeds the configured size limit",
                )
            if expanded > self.limits.maximum_expanded_bytes:
                raise _ParseFailure(
                    ApkInspectionCode.EXPANDED_SIZE_EXCEEDED,
                    "APK expanded size exceeds the configured limit",
                )
            if info.flag_bits & 0x1:
                raise _ParseFailure(
                    ApkInspectionCode.UNSAFE_ARCHIVE,
                    "encrypted APK members are not accepted",
                )
            if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                raise _ParseFailure(
                    ApkInspectionCode.UNSAFE_ARCHIVE,
                    "APK uses an unsupported compression method",
                )
            mode = (info.external_attr >> 16) & 0xFFFF
            kind = stat.S_IFMT(mode)
            if kind not in {0, stat.S_IFREG, stat.S_IFDIR}:
                raise _ParseFailure(
                    ApkInspectionCode.UNSAFE_ARCHIVE,
                    "APK contains a non-regular archive member",
                )
            if kind == stat.S_IFDIR and not info.is_dir():
                raise _ParseFailure(
                    ApkInspectionCode.UNSAFE_ARCHIVE,
                    "APK directory metadata disagrees with its path",
                )
            if info.compress_size == 0:
                if info.file_size:
                    raise _ParseFailure(
                        ApkInspectionCode.SUSPICIOUS_COMPRESSION,
                        "APK member declares an impossible compressed size",
                    )
            elif info.file_size / info.compress_size > self.limits.maximum_compression_ratio:
                raise _ParseFailure(
                    ApkInspectionCode.SUSPICIOUS_COMPRESSION,
                    "APK member exceeds the configured compression ratio",
                )
            ranges.append(self._validate_local_header(stream, info, data_boundary))
        ranges.sort()
        for previous, current in zip(ranges, ranges[1:], strict=False):
            if current[0] < previous[1]:
                raise _ParseFailure(
                    ApkInspectionCode.UNSAFE_ARCHIVE,
                    "APK archive members overlap",
                )
        return {info.filename: info for info in infos}

    def _validate_local_header(
        self,
        stream: BinaryIO,
        info: zipfile.ZipInfo,
        data_boundary: int,
    ) -> tuple[int, int]:
        if info.header_offset < 0 or info.header_offset + 30 > data_boundary:
            raise _ParseFailure(
                ApkInspectionCode.UNSAFE_ARCHIVE,
                "APK local header is outside the signed data region",
            )
        header = _read_exact_at(stream, info.header_offset, 30)
        (
            signature,
            _version,
            flags,
            method,
            _time,
            _date,
            local_crc,
            local_compressed,
            local_expanded,
            name_length,
            extra_length,
        ) = struct.unpack("<IHHHHHIIIHH", header)
        if signature != _LOCAL_FILE_SIGNATURE or method != info.compress_type:
            raise _ParseFailure(
                ApkInspectionCode.UNSAFE_ARCHIVE,
                "APK local and central directory headers disagree",
            )
        if not flags & 0x8 and (
            local_crc != info.CRC
            or local_compressed != info.compress_size
            or local_expanded != info.file_size
        ):
            raise _ParseFailure(
                ApkInspectionCode.UNSAFE_ARCHIVE,
                "APK local and central directory sizes or CRC disagree",
            )
        if flags != info.flag_bits or flags & 0x1:
            raise _ParseFailure(
                ApkInspectionCode.UNSAFE_ARCHIVE,
                "APK local header flags are inconsistent",
            )
        raw_name = _read_exact_at(stream, info.header_offset + 30, name_length)
        try:
            local_name = raw_name.decode("utf-8" if flags & 0x800 else "cp437")
        except UnicodeError as error:
            raise _ParseFailure(
                ApkInspectionCode.UNSAFE_ARCHIVE,
                "APK local header name is invalid",
            ) from error
        if local_name != info.filename:
            raise _ParseFailure(
                ApkInspectionCode.UNSAFE_ARCHIVE,
                "APK local and central directory names disagree",
            )
        data_start = info.header_offset + 30 + name_length + extra_length
        data_end = data_start + info.compress_size
        if data_end > data_boundary:
            raise _ParseFailure(
                ApkInspectionCode.UNSAFE_ARCHIVE,
                "APK member data exceeds the signed data region",
            )
        return (info.header_offset, data_end)

    def _read_signing_block(self, stream: BinaryIO, eocd: _Eocd) -> _SigningBlock | None:
        central = eocd.central_directory_offset
        if central < 24:
            return None
        footer = _read_exact_at(stream, central - 24, 24)
        if footer[8:] != _APK_SIG_BLOCK_MAGIC:
            return None
        size = struct.unpack_from("<Q", footer, 0)[0]
        if size < 24 or size + 8 > self.limits.maximum_signature_block_bytes:
            raise _ParseFailure(
                ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                "APK signing block size is invalid",
            )
        block_offset = central - size - 8
        if block_offset < 0:
            raise _ParseFailure(
                ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                "APK signing block starts outside the file",
            )
        block = _read_exact_at(stream, block_offset, size + 8)
        if struct.unpack_from("<Q", block, 0)[0] != size:
            raise _ParseFailure(
                ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                "APK signing block size fields disagree",
            )
        pairs_end = len(block) - 24
        offset = 8
        pairs: dict[int, bytes] = {}
        while offset < pairs_end:
            if pairs_end - offset < 8:
                raise _ParseFailure(
                    ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                    "APK signing block pair is truncated",
                )
            pair_size = struct.unpack_from("<Q", block, offset)[0]
            offset += 8
            if pair_size < 4 or pair_size > pairs_end - offset:
                raise _ParseFailure(
                    ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                    "APK signing block pair has an invalid size",
                )
            pair_id = struct.unpack_from("<I", block, offset)[0]
            value = block[offset + 4 : offset + pair_size]
            if pair_id in pairs:
                raise _ParseFailure(
                    ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                    "APK signing block contains duplicate pair IDs",
                )
            pairs[pair_id] = value
            offset += pair_size
        if offset != pairs_end:
            raise _ParseFailure(
                ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                "APK signing block is not aligned",
            )
        return _SigningBlock(block_offset, pairs)

    def _read_member_from_stream(
        self,
        stream: BinaryIO,
        info: zipfile.ZipInfo,
        limit: int,
    ) -> bytes:
        code = (
            ApkInspectionCode.MANIFEST_TOO_LARGE
            if info.filename == _MANIFEST_PATH
            else ApkInspectionCode.SIGNATURE_BLOCK_INVALID
        )
        if info.file_size > limit:
            raise _ParseFailure(code, "APK metadata member exceeds its size limit")
        stream.seek(0)
        with zipfile.ZipFile(stream, mode="r", allowZip64=False) as apk:
            with apk.open(info, mode="r") as member:
                data = member.read(limit + 1)
                if len(data) > limit or member.read(1):
                    raise _ParseFailure(code, "APK metadata member exceeds its size limit")
                return data

    def _verify_signatures(self, stream: BinaryIO, archive: _Archive) -> tuple[_SchemeResult, ...]:
        results: list[_SchemeResult] = []
        signing_block = archive.signing_block
        content_digests: dict[str, bytes] = {}
        if signing_block is not None:
            v3_results = tuple(
                self._verify_v2_v3(
                    stream,
                    archive,
                    signing_block.pairs[pair_id],
                    scheme="v3",
                    content_digests=content_digests,
                )
                for pair_id in (_APK_SIG_V3_ID, _APK_SIG_V31_ID)
                if pair_id in signing_block.pairs
            )
            if v3_results:
                results.append(
                    _SchemeResult(
                        "v3",
                        tuple(
                            dict.fromkeys(
                                signer
                                for result in v3_results
                                for signer in result.signer_digests
                            )
                        ),
                    )
                )
            v2 = signing_block.pairs.get(_APK_SIG_V2_ID)
            if v2 is not None:
                results.append(
                    self._verify_v2_v3(
                        stream,
                        archive,
                        v2,
                        scheme="v2",
                        content_digests=content_digests,
                    )
                )
        v1 = self._v1_signers(archive)
        if v1:
            results.append(self._verify_v1(stream, archive, v1))
        if not results:
            raise _ParseFailure(
                ApkInspectionCode.SIGNATURE_MISSING,
                "APK does not contain a supported signature",
            )
        order = {"v1": 0, "v2": 1, "v3": 2}
        return tuple(sorted(results, key=lambda result: order[result.scheme]))

    def _verify_v2_v3(
        self,
        stream: BinaryIO,
        archive: _Archive,
        value: bytes,
        *,
        scheme: str,
        content_digests: dict[str, bytes],
    ) -> _SchemeResult:
        outer = _ByteReader(value)
        signers_data = outer.length_prefixed()
        outer.finish()
        signers = _length_prefixed_sequence(signers_data, self.limits.maximum_signers)
        if not signers:
            raise _ParseFailure(
                ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                f"APK {scheme} block contains no signers",
            )
        signer_digests: list[str] = []
        for signer in signers:
            signer_digests.append(
                self._verify_scheme_signer(
                    stream,
                    archive,
                    signer,
                    scheme=scheme,
                    content_digests=content_digests,
                )
            )
        if len(set(signer_digests)) != len(signer_digests):
            raise _ParseFailure(
                ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                f"APK {scheme} block repeats a signer",
            )
        return _SchemeResult(scheme, tuple(signer_digests))

    def _verify_scheme_signer(
        self,
        stream: BinaryIO,
        archive: _Archive,
        signer: bytes,
        *,
        scheme: str,
        content_digests: dict[str, bytes],
    ) -> str:
        reader = _ByteReader(signer)
        signed_data = reader.length_prefixed()
        outside_min_sdk: int | None = None
        outside_max_sdk: int | None = None
        if scheme == "v3":
            outside_min_sdk = reader.uint32()
            outside_max_sdk = reader.uint32()
            if outside_min_sdk > outside_max_sdk:
                raise _ParseFailure(
                    ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                    "APK v3 signer has an invalid SDK range",
                )
        signatures_data = reader.length_prefixed()
        public_key = reader.length_prefixed()
        reader.finish()

        signed = _ByteReader(signed_data)
        digests_data = signed.length_prefixed()
        certificates_data = signed.length_prefixed()
        if scheme == "v3":
            if signed.uint32() != outside_min_sdk or signed.uint32() != outside_max_sdk:
                raise _ParseFailure(
                    ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                    "APK v3 signer SDK ranges disagree",
                )
        attributes = signed.length_prefixed()
        if scheme == "v2" and signed.remaining:
            reserved = signed.length_prefixed()
            if reserved:
                raise _ParseFailure(
                    ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                    "APK v2 reserved signer field is not empty",
                )
        signed.finish()
        _verify_scheme_attributes(attributes, scheme, archive.signing_block)

        digest_records = _algorithm_records(digests_data)
        signature_records = _algorithm_records(signatures_data)
        if tuple(digest_records) != tuple(signature_records):
            raise _ParseFailure(
                ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                f"APK {scheme} digest and signature algorithm lists disagree",
            )
        supported = tuple(
            algorithm
            for algorithm in signature_records
            if algorithm in _SIGNATURE_ALGORITHMS
        )
        if not supported:
            raise _ParseFailure(
                ApkInspectionCode.SIGNATURE_UNSUPPORTED,
                f"APK {scheme} signer has no supported signature algorithm",
            )
        certificates = _length_prefixed_sequence(
            certificates_data,
            self.limits.maximum_certificates_per_signer,
        )
        if not certificates:
            raise _ParseFailure(
                ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                f"APK {scheme} signer contains no certificate",
            )
        leaf = _load_x509_certificate(certificates[0])
        _verify_public_key_encoding(leaf, public_key)
        for algorithm in supported:
            _verify_signature(leaf, algorithm, signature_records[algorithm], signed_data)
            digest_name = _SIGNATURE_ALGORITHMS[algorithm][0]
            expected = digest_records[algorithm]
            actual = content_digests.get(digest_name)
            if actual is None:
                actual = _apk_content_digest(
                    stream,
                    archive,
                    digest_name,
                    self.limits.io_chunk_size,
                )
                content_digests[digest_name] = actual
            if not _constant_time_equal(actual, expected):
                raise _ParseFailure(
                    ApkInspectionCode.CONTENT_DIGEST_MISMATCH,
                    f"APK {scheme} signed content digest does not match",
                )
        return hashlib.sha256(certificates[0]).hexdigest()

    def _v1_signers(self, archive: _Archive) -> tuple[tuple[str, zipfile.ZipInfo, zipfile.ZipInfo], ...]:
        sf: dict[str, zipfile.ZipInfo] = {}
        blocks: dict[str, zipfile.ZipInfo] = {}
        for info in archive.infos:
            sf_match = _V1_SIGNATURE_FILE.fullmatch(info.filename)
            if sf_match:
                sf[sf_match.group(1).casefold()] = info
            block_match = _V1_BLOCK_FILE.fullmatch(info.filename)
            if block_match:
                key = block_match.group(1).casefold()
                if key in blocks:
                    raise _ParseFailure(
                        ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                        "APK contains ambiguous v1 signature blocks",
                    )
                blocks[key] = info
        if not sf and not blocks:
            return ()
        if set(sf) != set(blocks):
            raise _ParseFailure(
                ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                "APK v1 signature files are incomplete",
            )
        if len(sf) > self.limits.maximum_signers:
            raise _ParseFailure(
                ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                "APK contains too many v1 signers",
            )
        return tuple((key, sf[key], blocks[key]) for key in sorted(sf))

    def _verify_v1(
        self,
        stream: BinaryIO,
        archive: _Archive,
        signers: Sequence[tuple[str, zipfile.ZipInfo, zipfile.ZipInfo]],
    ) -> _SchemeResult:
        manifest_info = archive.by_name.get(_JAR_MANIFEST_PATH)
        if manifest_info is None:
            raise _ParseFailure(
                ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                "APK v1 signature is missing META-INF/MANIFEST.MF",
            )
        manifest = self._read_member_from_stream(
            stream,
            manifest_info,
            self.limits.maximum_v1_metadata_bytes,
        )
        manifest_sections = _parse_jar_manifest(manifest)
        self._verify_v1_entry_digests(stream, archive, manifest_sections)
        signer_digests: list[str] = []
        for _name, sf_info, block_info in signers:
            sf_data = self._read_member_from_stream(
                stream,
                sf_info,
                self.limits.maximum_v1_metadata_bytes,
            )
            signature_block = self._read_member_from_stream(
                stream,
                block_info,
                self.limits.maximum_v1_metadata_bytes,
            )
            sf_sections = _parse_jar_manifest(sf_data)
            _verify_sf_manifest(sf_sections, manifest_sections, manifest)
            _enforce_scheme_stripping_protection(
                sf_sections[0][0],
                archive.signing_block,
            )
            signer_digests.extend(_verify_cms_signature(signature_block, sf_data))
        unique = tuple(dict.fromkeys(signer_digests))
        if not unique:
            raise _ParseFailure(
                ApkInspectionCode.SIGNATURE_INVALID,
                "APK v1 signature did not identify a signer",
            )
        return _SchemeResult("v1", unique)

    def _verify_v1_entry_digests(
        self,
        stream: BinaryIO,
        archive: _Archive,
        sections: Sequence[tuple[Mapping[str, bytes], bytes]],
    ) -> None:
        manifest_entries: dict[str, Mapping[str, bytes]] = {}
        for headers, _raw in sections[1:]:
            raw_name = headers.get("name")
            if raw_name is None:
                raise _ParseFailure(
                    ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                    "APK v1 manifest section has no Name header",
                )
            name = _decode_manifest_value(raw_name)
            _safe_archive_name(name)
            identity = name.casefold()
            if identity in manifest_entries:
                raise _ParseFailure(
                    ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                    "APK v1 manifest contains duplicate entry sections",
                )
            manifest_entries[identity] = headers

        expected_infos = tuple(
            info
            for info in archive.infos
            if not info.is_dir() and not _V1_IGNORED_FILE.fullmatch(info.filename)
        )
        expected_identities = {info.filename.casefold() for info in expected_infos}
        if set(manifest_entries) != expected_identities:
            raise _ParseFailure(
                ApkInspectionCode.SIGNATURE_INVALID,
                "APK v1 manifest does not cover every archive member exactly",
            )
        stream.seek(0)
        with zipfile.ZipFile(stream, mode="r", allowZip64=False) as apk:
            for info in expected_infos:
                headers = manifest_entries[info.filename.casefold()]
                algorithm, expected = _select_manifest_digest(headers, "digest")
                digest = hashlib.new(algorithm)
                with apk.open(info, mode="r") as member:
                    while chunk := member.read(self.limits.io_chunk_size):
                        digest.update(chunk)
                if not _constant_time_equal(digest.digest(), expected):
                    raise _ParseFailure(
                        ApkInspectionCode.CONTENT_DIGEST_MISMATCH,
                        "APK v1 member digest does not match",
                    )


def inspect_apk(
    path: str | os.PathLike[str],
    *,
    limits: ApkInspectionLimits | None = None,
) -> ApkIdentity:
    """Convenience wrapper around :class:`ApkInspector`."""

    return ApkInspector(limits=limits).inspect(path)


def _validated_source_path(path: str | os.PathLike[str]) -> Path:
    try:
        source = Path(path).expanduser()
    except (TypeError, ValueError, OSError) as error:
        raise _ParseFailure(
            ApkInspectionCode.INVALID_PATH,
            "APK path is invalid",
        ) from error
    if source.is_symlink():
        raise _ParseFailure(
            ApkInspectionCode.NOT_REGULAR_FILE,
            "APK source cannot be a symbolic link",
        )
    return source


def _sha256_stream(stream: BinaryIO, chunk_size: int) -> bytes:
    stream.seek(0)
    digest = hashlib.sha256()
    while chunk := stream.read(chunk_size):
        digest.update(chunk)
    return digest.digest()


def _read_exact_at(stream: BinaryIO, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0:
        raise _ParseFailure(ApkInspectionCode.INVALID_ZIP, "APK offset is invalid")
    stream.seek(offset)
    data = stream.read(size)
    if len(data) != size:
        raise _ParseFailure(ApkInspectionCode.INVALID_ZIP, "APK is truncated")
    return data


def _read_eocd(stream: BinaryIO, file_size: int) -> _Eocd:
    if file_size < 22:
        raise _ParseFailure(ApkInspectionCode.INVALID_ZIP, "APK ZIP footer is missing")
    tail_size = min(file_size, 22 + 0xFFFF)
    tail_offset = file_size - tail_size
    tail = _read_exact_at(stream, tail_offset, tail_size)
    position = tail.rfind(_EOCD_SIGNATURE)
    if position < 0 or position + 22 > len(tail):
        raise _ParseFailure(ApkInspectionCode.INVALID_ZIP, "APK ZIP footer is missing")
    fields = struct.unpack_from("<4s4H2IH", tail, position)
    (
        _signature,
        disk,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        comment_size,
    ) = fields
    if position + 22 + comment_size != len(tail):
        raise _ParseFailure(
            ApkInspectionCode.INVALID_ZIP,
            "APK contains an ambiguous ZIP footer or trailing data",
        )
    if disk or central_disk or disk_entries != total_entries:
        raise _ParseFailure(ApkInspectionCode.INVALID_ZIP, "multi-disk APKs are not accepted")
    if total_entries == 0xFFFF or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
        raise _ParseFailure(ApkInspectionCode.INVALID_ZIP, "ZIP64 APKs are not accepted")
    eocd_offset = tail_offset + position
    if central_offset + central_size != eocd_offset:
        raise _ParseFailure(
            ApkInspectionCode.INVALID_ZIP,
            "APK central directory boundaries are inconsistent",
        )
    return _Eocd(
        eocd_offset,
        central_offset,
        central_size,
        tail[position:],
    )


def _safe_archive_name(value: str) -> str:
    if (
        not value
        or len(value) > 4096
        or "\\" in value
        or "\x00" in value
        or unicodedata.normalize("NFC", value) != value
    ):
        raise _ParseFailure(
            ApkInspectionCode.UNSAFE_ARCHIVE,
            "APK contains an unsafe archive path",
        )
    path = PurePosixPath(value)
    raw_parts = value.split("/")
    invalid_raw_part = any(
        part in {"", ".", ".."}
        for part in (raw_parts[:-1] if value.endswith("/") else raw_parts)
    )
    if path.is_absolute() or invalid_raw_part:
        raise _ParseFailure(
            ApkInspectionCode.UNSAFE_ARCHIVE,
            "APK contains an unsafe archive path",
        )
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise _ParseFailure(
            ApkInspectionCode.UNSAFE_ARCHIVE,
            "APK contains control characters in an archive path",
        )
    return value


def _valid_package_name(value: str) -> bool:
    return 3 <= len(value) <= 255 and _PACKAGE_NAME.fullmatch(value) is not None


def _parse_package_name(data: bytes, limits: ApkInspectionLimits) -> str:
    if not data:
        raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "AndroidManifest.xml is empty")
    stripped = data.lstrip()
    if stripped.startswith((b"<", b"\xef\xbb\xbf<")):
        package_name = _parse_text_manifest(data)
    else:
        package_name = _parse_binary_manifest(data, limits)
    if not _valid_package_name(package_name):
        raise _ParseFailure(
            ApkInspectionCode.PACKAGE_NAME_INVALID,
            "AndroidManifest.xml contains an invalid package name",
        )
    return package_name


def _parse_text_manifest(data: bytes) -> str:
    lowered = data.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise _ParseFailure(
            ApkInspectionCode.MANIFEST_INVALID,
            "AndroidManifest.xml declarations are not accepted",
        )
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, UnicodeError, ValueError) as error:
        raise _ParseFailure(
            ApkInspectionCode.MANIFEST_INVALID,
            "AndroidManifest.xml text XML is invalid",
        ) from error
    if root.tag != "manifest":
        raise _ParseFailure(
            ApkInspectionCode.MANIFEST_INVALID,
            "AndroidManifest.xml root element is not manifest",
        )
    value = root.attrib.get("package")
    if value is None:
        raise _ParseFailure(
            ApkInspectionCode.PACKAGE_NAME_INVALID,
            "AndroidManifest.xml has no package attribute",
        )
    return value


def _parse_binary_manifest(data: bytes, limits: ApkInspectionLimits) -> str:
    if len(data) < 8:
        raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary manifest is truncated")
    chunk_type, header_size, total_size = struct.unpack_from("<HHI", data, 0)
    if chunk_type != 0x0003 or header_size != 8 or total_size != len(data):
        raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary manifest header is invalid")
    strings: tuple[str, ...] | None = None
    root_seen = False
    offset = header_size
    while offset < total_size:
        chunk_type, chunk_header, chunk_size = _chunk_header(data, offset, total_size)
        if chunk_type == 0x0001:
            if strings is not None:
                raise _ParseFailure(
                    ApkInspectionCode.MANIFEST_INVALID,
                    "binary manifest contains multiple string pools",
                )
            strings = _parse_string_pool(data[offset : offset + chunk_size], limits)
        elif chunk_type == 0x0102:
            if strings is None:
                raise _ParseFailure(
                    ApkInspectionCode.MANIFEST_INVALID,
                    "binary manifest element precedes its string pool",
                )
            element_name, package_name = _start_element(
                data[offset : offset + chunk_size],
                chunk_header,
                strings,
            )
            if root_seen or element_name != "manifest":
                raise _ParseFailure(
                    ApkInspectionCode.MANIFEST_INVALID,
                    "binary AndroidManifest.xml root element is not manifest",
                )
            root_seen = True
            if package_name is None:
                raise _ParseFailure(
                    ApkInspectionCode.PACKAGE_NAME_INVALID,
                    "binary AndroidManifest.xml has no package attribute",
                )
            return package_name
        offset += chunk_size
    raise _ParseFailure(
        ApkInspectionCode.PACKAGE_NAME_INVALID,
        "binary AndroidManifest.xml has no manifest package attribute",
    )


def _chunk_header(data: bytes, offset: int, boundary: int) -> tuple[int, int, int]:
    if offset < 0 or offset + 8 > boundary:
        raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary XML chunk is truncated")
    chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
    if header_size < 8 or chunk_size < header_size or offset + chunk_size > boundary:
        raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary XML chunk size is invalid")
    return chunk_type, header_size, chunk_size


def _parse_string_pool(data: bytes, limits: ApkInspectionLimits) -> tuple[str, ...]:
    if len(data) < 28:
        raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary XML string pool is truncated")
    (
        _chunk_type,
        header_size,
        chunk_size,
        string_count,
        style_count,
        flags,
        strings_start,
        styles_start,
    ) = struct.unpack_from("<HHIIIIII", data, 0)
    if (
        header_size < 28
        or chunk_size != len(data)
        or string_count > limits.maximum_axml_strings
        or header_size + 4 * (string_count + style_count) > len(data)
        or strings_start < header_size + 4 * (string_count + style_count)
        or strings_start > len(data)
        or (styles_start and (styles_start < strings_start or styles_start > len(data)))
    ):
        raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary XML string pool is invalid")
    string_boundary = styles_start or len(data)
    utf8 = bool(flags & 0x100)
    strings: list[str] = []
    for index in range(string_count):
        relative = struct.unpack_from("<I", data, header_size + index * 4)[0]
        start = strings_start + relative
        if start < strings_start or start >= string_boundary:
            raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary XML string offset is invalid")
        value = (
            _decode_utf8_pool_string(data, start, string_boundary, limits.maximum_axml_string_bytes)
            if utf8
            else _decode_utf16_pool_string(data, start, string_boundary, limits.maximum_axml_string_bytes)
        )
        strings.append(value)
    return tuple(strings)


def _pool_length8(data: bytes, offset: int, boundary: int) -> tuple[int, int]:
    if offset >= boundary:
        raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary XML string length is truncated")
    first = data[offset]
    if first & 0x80:
        if offset + 2 > boundary:
            raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary XML string length is truncated")
        return ((first & 0x7F) << 8) | data[offset + 1], offset + 2
    return first, offset + 1


def _pool_length16(data: bytes, offset: int, boundary: int) -> tuple[int, int]:
    if offset + 2 > boundary:
        raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary XML string length is truncated")
    first = struct.unpack_from("<H", data, offset)[0]
    if first & 0x8000:
        if offset + 4 > boundary:
            raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary XML string length is truncated")
        second = struct.unpack_from("<H", data, offset + 2)[0]
        return ((first & 0x7FFF) << 16) | second, offset + 4
    return first, offset + 2


def _decode_utf8_pool_string(data: bytes, start: int, boundary: int, limit: int) -> str:
    utf16_length, offset = _pool_length8(data, start, boundary)
    byte_length, offset = _pool_length8(data, offset, boundary)
    if byte_length > limit or offset + byte_length + 1 > boundary or data[offset + byte_length] != 0:
        raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary XML UTF-8 string is invalid")
    try:
        value = data[offset : offset + byte_length].decode("utf-8")
    except UnicodeError as error:
        raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary XML UTF-8 string is invalid") from error
    if len(value.encode("utf-16le")) // 2 != utf16_length:
        raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary XML UTF-8 string length is invalid")
    return value


def _decode_utf16_pool_string(data: bytes, start: int, boundary: int, limit: int) -> str:
    code_units, offset = _pool_length16(data, start, boundary)
    byte_length = code_units * 2
    if byte_length > limit or offset + byte_length + 2 > boundary or data[offset + byte_length : offset + byte_length + 2] != b"\0\0":
        raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary XML UTF-16 string is invalid")
    try:
        value = data[offset : offset + byte_length].decode("utf-16le")
    except UnicodeError as error:
        raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary XML UTF-16 string is invalid") from error
    if len(value.encode("utf-16le")) != byte_length:
        raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary XML UTF-16 string is invalid")
    return value


def _string_at(strings: Sequence[str], index: int) -> str | None:
    if index == 0xFFFFFFFF:
        return None
    if index >= len(strings):
        raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary XML string index is invalid")
    return strings[index]


def _start_element(
    chunk: bytes,
    header_size: int,
    strings: Sequence[str],
) -> tuple[str, str | None]:
    if header_size < 16 or len(chunk) < header_size + 20:
        raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary XML start element is truncated")
    extension = header_size
    _namespace, name_index, attribute_start, attribute_size, attribute_count = struct.unpack_from(
        "<IIHHH", chunk, extension
    )
    element_name = _string_at(strings, name_index)
    if element_name is None:
        raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary XML element name is missing")
    if element_name != "manifest":
        return element_name, None
    if attribute_size < 20 or attribute_count > 10_000:
        raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary XML attributes are invalid")
    attributes = extension + attribute_start
    if attributes < extension + 20 or attributes + attribute_count * attribute_size > len(chunk):
        raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary XML attributes are truncated")
    package_value: str | None = None
    for index in range(attribute_count):
        offset = attributes + index * attribute_size
        namespace, name, raw_value = struct.unpack_from("<III", chunk, offset)
        value_size, value_zero, value_type, typed_data = struct.unpack_from("<HBBI", chunk, offset + 12)
        if value_size != 8 or value_zero != 0:
            raise _ParseFailure(ApkInspectionCode.MANIFEST_INVALID, "binary XML typed value is invalid")
        if _string_at(strings, name) != "package" or namespace != 0xFFFFFFFF:
            continue
        candidate = _string_at(strings, raw_value)
        if candidate is None:
            if value_type != 0x03:
                raise _ParseFailure(ApkInspectionCode.PACKAGE_NAME_INVALID, "binary manifest package is not a string")
            candidate = _string_at(strings, typed_data)
        if candidate is None or package_value is not None:
            raise _ParseFailure(ApkInspectionCode.PACKAGE_NAME_INVALID, "binary manifest package is ambiguous")
        package_value = candidate
    return element_name, package_value


_SIGNATURE_ALGORITHMS: Final[Mapping[int, tuple[str, str]]] = MappingProxyType(
    {
        0x0101: ("sha256", "rsa_pss"),
        0x0102: ("sha512", "rsa_pss"),
        0x0103: ("sha256", "rsa_pkcs1"),
        0x0104: ("sha512", "rsa_pkcs1"),
        0x0201: ("sha256", "ecdsa"),
        0x0202: ("sha512", "ecdsa"),
        0x0301: ("sha256", "dsa"),
    }
)


def _length_prefixed_sequence(data: bytes, limit: int) -> tuple[bytes, ...]:
    reader = _ByteReader(data)
    values: list[bytes] = []
    while reader.remaining:
        if len(values) >= limit:
            raise _ParseFailure(
                ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                "APK signature sequence exceeds its item limit",
            )
        values.append(reader.length_prefixed())
    return tuple(values)


def _algorithm_records(data: bytes) -> dict[int, bytes]:
    records: dict[int, bytes] = {}
    for record_data in _length_prefixed_sequence(data, 64):
        record = _ByteReader(record_data)
        algorithm = record.uint32()
        value = record.length_prefixed()
        record.finish()
        if algorithm in records:
            raise _ParseFailure(
                ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                "APK signer repeats a signature algorithm",
            )
        records[algorithm] = value
    if not records:
        raise _ParseFailure(
            ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
            "APK signer contains no algorithm records",
        )
    return records


def _verify_scheme_attributes(
    data: bytes,
    scheme: str,
    signing_block: _SigningBlock | None,
) -> None:
    attributes: dict[int, bytes] = {}
    for encoded in _length_prefixed_sequence(data, 64):
        reader = _ByteReader(encoded)
        attribute_id = reader.uint32()
        value = reader.take(reader.remaining)
        if attribute_id in attributes:
            raise _ParseFailure(
                ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
                f"APK {scheme} signer repeats an additional attribute",
            )
        attributes[attribute_id] = value
    stripping = attributes.get(_V2_STRIPPING_PROTECTION_ATTR_ID)
    if scheme != "v2" or stripping is None:
        return
    if len(stripping) != 4:
        raise _ParseFailure(
            ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
            "APK v2 stripping-protection attribute is malformed",
        )
    referenced_scheme = struct.unpack("<I", stripping)[0]
    pairs: Mapping[int, bytes] = (
        signing_block.pairs if signing_block is not None else MappingProxyType({})
    )
    if referenced_scheme == 3 and not ({_APK_SIG_V3_ID, _APK_SIG_V31_ID} & pairs.keys()):
        raise _ParseFailure(
            ApkInspectionCode.SIGNATURE_INVALID,
            "APK v3 signature referenced by v2 stripping protection is missing",
        )


def _load_x509_certificate(data: bytes) -> x509.Certificate:
    try:
        from cryptography import x509
    except ImportError as error:
        raise _ParseFailure(
            ApkInspectionCode.CRYPTOGRAPHY_UNAVAILABLE,
            "cryptography is required to verify APK signatures",
        ) from error
    try:
        return x509.load_der_x509_certificate(data)
    except (TypeError, ValueError) as error:
        raise _ParseFailure(
            ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
            "APK signer certificate is invalid",
        ) from error


def _verify_public_key_encoding(certificate: x509.Certificate, encoded: bytes) -> None:
    try:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except ImportError as error:
        raise _ParseFailure(
            ApkInspectionCode.CRYPTOGRAPHY_UNAVAILABLE,
            "cryptography is required to verify APK signatures",
        ) from error
    try:
        public_key = certificate.public_key()
        actual = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    except (AttributeError, TypeError, ValueError) as error:
        raise _ParseFailure(
            ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
            "APK signer public key is invalid",
        ) from error
    if not _constant_time_equal(actual, encoded):
        raise _ParseFailure(
            ApkInspectionCode.SIGNATURE_INVALID,
            "APK signer public key does not match its certificate",
        )


def _hash_algorithm(name: str) -> HashAlgorithm:
    try:
        from cryptography.hazmat.primitives import hashes
    except ImportError as error:
        raise _ParseFailure(
            ApkInspectionCode.CRYPTOGRAPHY_UNAVAILABLE,
            "cryptography is required to verify APK signatures",
        ) from error
    if name == "sha256":
        return hashes.SHA256()
    if name == "sha384":
        return hashes.SHA384()
    if name == "sha512":
        return hashes.SHA512()
    raise _ParseFailure(ApkInspectionCode.SIGNATURE_UNSUPPORTED, "APK uses an unsupported digest")


def _verify_signature(
    certificate: x509.Certificate,
    algorithm: int,
    signature: bytes,
    payload: bytes,
) -> None:
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa
    except ImportError as error:
        raise _ParseFailure(
            ApkInspectionCode.CRYPTOGRAPHY_UNAVAILABLE,
            "cryptography is required to verify APK signatures",
        ) from error
    digest_name, signature_kind = _SIGNATURE_ALGORITHMS[algorithm]
    digest = _hash_algorithm(digest_name)
    try:
        public_key = certificate.public_key()
        if signature_kind == "rsa_pss":
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise TypeError("RSA signature requires an RSA key")
            public_key.verify(
                signature,
                payload,
                padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size),
                digest,
            )
        elif signature_kind == "rsa_pkcs1":
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise TypeError("RSA signature requires an RSA key")
            public_key.verify(signature, payload, padding.PKCS1v15(), digest)
        elif signature_kind == "ecdsa":
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise TypeError("ECDSA signature requires an EC key")
            public_key.verify(signature, payload, ec.ECDSA(digest))
        elif signature_kind == "dsa":
            if not isinstance(public_key, dsa.DSAPublicKey):
                raise TypeError("DSA signature requires a DSA key")
            public_key.verify(signature, payload, digest)
        else:
            raise TypeError("unknown signature kind")
    except InvalidSignature as error:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_INVALID, "APK signature is invalid") from error
    except UnsupportedAlgorithm as error:
        raise _ParseFailure(
            ApkInspectionCode.SIGNATURE_UNSUPPORTED,
            "APK signature algorithm is unavailable",
        ) from error
    except (AttributeError, TypeError, ValueError) as error:
        raise _ParseFailure(
            ApkInspectionCode.SIGNATURE_BLOCK_INVALID,
            "APK signature key or parameters are invalid",
        ) from error


def _apk_content_digest(
    stream: BinaryIO,
    archive: _Archive,
    digest_name: str,
    io_chunk_size: int,
) -> bytes:
    signing_block = archive.signing_block
    if signing_block is None:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK signing block is missing")
    chunk_size = 1024 * 1024
    sections: tuple[tuple[int, int] | bytes, ...] = (
        (0, signing_block.offset),
        (archive.eocd.central_directory_offset, archive.eocd.offset),
        _patched_eocd(archive.eocd, signing_block.offset),
    )
    chunk_hashes: list[bytes] = []
    for section in sections:
        if isinstance(section, bytes):
            for offset in range(0, len(section), chunk_size):
                chunk_hashes.append(_digest_content_chunk(section[offset : offset + chunk_size], digest_name))
            continue
        start, end = section
        stream.seek(start)
        remaining = end - start
        while remaining:
            requested = min(chunk_size, remaining)
            chunk = stream.read(requested)
            if len(chunk) != requested:
                raise _ParseFailure(ApkInspectionCode.READ_FAILED, "APK signed region is truncated")
            chunk_hashes.append(_digest_content_chunk(chunk, digest_name))
            remaining -= requested
    if not chunk_hashes or len(chunk_hashes) > 0xFFFFFFFF:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK signed region count is invalid")
    digest = hashlib.new(digest_name)
    digest.update(b"\x5a")
    digest.update(struct.pack("<I", len(chunk_hashes)))
    for chunk_hash in chunk_hashes:
        digest.update(chunk_hash)
    _ = io_chunk_size  # API-level I/O bound retained for future streaming variants.
    return digest.digest()


def _digest_content_chunk(data: bytes, digest_name: str) -> bytes:
    digest = hashlib.new(digest_name)
    digest.update(b"\xa5")
    digest.update(struct.pack("<I", len(data)))
    digest.update(data)
    return digest.digest()


def _patched_eocd(eocd: _Eocd, signing_block_offset: int) -> bytes:
    if signing_block_offset > 0xFFFFFFFF:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_UNSUPPORTED, "APK offset exceeds v2/v3 limits")
    patched = bytearray(eocd.bytes)
    struct.pack_into("<I", patched, 16, signing_block_offset)
    return bytes(patched)


def _constant_time_equal(left: bytes, right: bytes) -> bool:
    import hmac

    return hmac.compare_digest(left, right)


type JarSection = tuple[Mapping[str, bytes], bytes]


def _parse_jar_manifest(data: bytes) -> tuple[JarSection, ...]:
    if not data or b"\x00" in data or len(data) > 8 * 1024 * 1024:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 metadata is invalid")
    lines = data.splitlines(keepends=True)
    if not lines or any(not line.endswith(b"\n") for line in lines[:-1]):
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 metadata lines are invalid")
    sections: list[JarSection] = []
    current: list[bytes] = []
    for line in lines:
        current.append(line)
        if line in {b"\n", b"\r\n"}:
            sections.append(_jar_section(current))
            current = []
    if current:
        sections.append(_jar_section(current))
    if not sections:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 metadata has no sections")
    return tuple(sections)


def _jar_section(lines: Sequence[bytes]) -> JarSection:
    headers: dict[str, bytes] = {}
    current_key: str | None = None
    for line in lines:
        content = line.removesuffix(b"\n").removesuffix(b"\r")
        if not content:
            continue
        if len(content) > 16 * 1024:
            raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 metadata line is too long")
        if content.startswith(b" "):
            if current_key is None:
                raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 continuation is invalid")
            headers[current_key] += content[1:]
            continue
        if b": " not in content:
            raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 header is invalid")
        raw_key, value = content.split(b": ", 1)
        try:
            key = raw_key.decode("ascii").casefold()
        except UnicodeError as error:
            raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 header name is invalid") from error
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,69}", key) or key in headers:
            raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 header is duplicate or invalid")
        headers[key] = value
        current_key = key
    if not headers:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 metadata section is empty")
    return MappingProxyType(headers), b"".join(lines)


def _decode_manifest_value(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeError as error:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 header value is invalid") from error


def _select_manifest_digest(headers: Mapping[str, bytes], suffix: str) -> tuple[str, bytes]:
    supported = (
        ("sha512", f"sha-512-{suffix}"),
        ("sha384", f"sha-384-{suffix}"),
        ("sha256", f"sha-256-{suffix}"),
    )
    matches = tuple((algorithm, headers[key]) for algorithm, key in supported if key in headers)
    if not matches:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_UNSUPPORTED, "APK v1 metadata has no strong digest")
    algorithm, encoded = matches[0]
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 digest is invalid") from error
    if len(decoded) != hashlib.new(algorithm).digest_size:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 digest length is invalid")
    return algorithm, decoded


def _verify_sf_manifest(
    sf_sections: Sequence[JarSection],
    manifest_sections: Sequence[JarSection],
    manifest: bytes,
) -> None:
    main = sf_sections[0][0]
    try:
        algorithm, expected = _select_manifest_digest(main, "digest-manifest")
    except _ParseFailure as whole_error:
        if whole_error.code is not ApkInspectionCode.SIGNATURE_UNSUPPORTED:
            raise
        _verify_sf_sections(sf_sections, manifest_sections)
        return
    if not _constant_time_equal(hashlib.new(algorithm, manifest).digest(), expected):
        raise _ParseFailure(ApkInspectionCode.CONTENT_DIGEST_MISMATCH, "APK v1 manifest digest does not match")


def _verify_sf_sections(sf_sections: Sequence[JarSection], manifest_sections: Sequence[JarSection]) -> None:
    main_headers = sf_sections[0][0]
    algorithm, expected = _select_manifest_digest(main_headers, "digest-manifest-main-attributes")
    if not _constant_time_equal(hashlib.new(algorithm, manifest_sections[0][1]).digest(), expected):
        raise _ParseFailure(ApkInspectionCode.CONTENT_DIGEST_MISMATCH, "APK v1 main attributes digest does not match")
    manifest_by_name = {
        _decode_manifest_value(headers["name"]).casefold(): raw
        for headers, raw in manifest_sections[1:]
        if "name" in headers
    }
    if len(sf_sections) - 1 != len(manifest_by_name):
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_INVALID, "APK v1 SF does not cover every manifest section")
    seen: set[str] = set()
    for headers, _raw in sf_sections[1:]:
        name_value = headers.get("name")
        if name_value is None:
            raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 SF section has no Name")
        name = _decode_manifest_value(name_value).casefold()
        target = manifest_by_name.get(name)
        if target is None or name in seen:
            raise _ParseFailure(ApkInspectionCode.SIGNATURE_INVALID, "APK v1 SF references an invalid section")
        seen.add(name)
        algorithm, expected = _select_manifest_digest(headers, "digest")
        if not _constant_time_equal(hashlib.new(algorithm, target).digest(), expected):
            raise _ParseFailure(ApkInspectionCode.CONTENT_DIGEST_MISMATCH, "APK v1 section digest does not match")


def _enforce_scheme_stripping_protection(
    sf_main: Mapping[str, bytes],
    signing_block: _SigningBlock | None,
) -> None:
    declared = sf_main.get("x-android-apk-signed")
    if declared is None:
        return
    try:
        values = {int(value.strip()) for value in declared.decode("ascii").split(",")}
    except (UnicodeError, ValueError) as error:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK signing-scheme declaration is invalid") from error
    pairs: Mapping[int, bytes] = (
        signing_block.pairs if signing_block is not None else MappingProxyType({})
    )
    if 2 in values and _APK_SIG_V2_ID not in pairs:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_INVALID, "APK v2 signature was stripped")
    if 3 in values and not ({_APK_SIG_V3_ID, _APK_SIG_V31_ID} & pairs.keys()):
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_INVALID, "APK v3 signature was stripped")


def _der_value(data: bytes, offset: int = 0) -> tuple[_DerValue, int]:
    if offset < 0 or offset + 2 > len(data):
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "CMS value is truncated")
    start = offset
    tag = data[offset]
    offset += 1
    if tag & 0x1F == 0x1F:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_UNSUPPORTED, "CMS high-tag values are unsupported")
    first_length = data[offset]
    offset += 1
    if first_length == 0x80:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_UNSUPPORTED, "indefinite CMS values are unsupported")
    if first_length & 0x80:
        count = first_length & 0x7F
        if count == 0 or count > 4 or offset + count > len(data) or data[offset] == 0:
            raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "CMS length is invalid")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
        if length < 128:
            raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "CMS length is not DER-minimal")
    else:
        length = first_length
    end = offset + length
    if end > len(data):
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "CMS value is truncated")
    return _DerValue(tag, data[start:end], data[offset:end]), end


def _der_children(value: _DerValue) -> tuple[_DerValue, ...]:
    values: list[_DerValue] = []
    offset = 0
    while offset < len(value.content):
        child, offset = _der_value(value.content, offset)
        values.append(child)
    return tuple(values)


def _der_single(data: bytes, expected_tag: int) -> _DerValue:
    value, end = _der_value(data)
    if end != len(data) or value.tag != expected_tag:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "CMS structure is invalid")
    return value


def _der_integer(value: _DerValue) -> int:
    if value.tag != 0x02 or not value.content or value.content[0] & 0x80:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "CMS integer is invalid")
    if len(value.content) > 1 and value.content[0] == 0 and not value.content[1] & 0x80:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "CMS integer is not minimal")
    return int.from_bytes(value.content, "big")


def _der_oid(value: _DerValue) -> str:
    if value.tag != 0x06 or not value.content:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "CMS object identifier is invalid")
    first = value.content[0]
    parts = [min(first // 40, 2), first - min(first // 40, 2) * 40]
    current = 0
    continuation = False
    for byte in value.content[1:]:
        if current == 0 and byte == 0x80:
            raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "CMS object identifier is not minimal")
        current = (current << 7) | (byte & 0x7F)
        continuation = bool(byte & 0x80)
        if not continuation:
            parts.append(current)
            current = 0
    if continuation:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "CMS object identifier is truncated")
    return ".".join(str(part) for part in parts)


def _algorithm_oid(value: _DerValue) -> str:
    if value.tag != 0x30:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "CMS algorithm is invalid")
    children = _der_children(value)
    if not children or len(children) > 2:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "CMS algorithm parameters are invalid")
    first = next(iter(children))
    return _der_oid(first)


_CMS_DIGEST_OIDS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "2.16.840.1.101.3.4.2.1": "sha256",
        "2.16.840.1.101.3.4.2.2": "sha384",
        "2.16.840.1.101.3.4.2.3": "sha512",
    }
)
_CMS_RSA_OIDS: Final[Mapping[str, str | None]] = MappingProxyType(
    {
        "1.2.840.113549.1.1.1": None,
        "1.2.840.113549.1.1.11": "sha256",
        "1.2.840.113549.1.1.12": "sha384",
        "1.2.840.113549.1.1.13": "sha512",
    }
)
_CMS_ECDSA_OIDS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "1.2.840.10045.4.3.2": "sha256",
        "1.2.840.10045.4.3.3": "sha384",
        "1.2.840.10045.4.3.4": "sha512",
    }
)


def _verify_cms_signature(cms: bytes, content: bytes) -> tuple[str, ...]:
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7
    except ImportError as error:
        raise _ParseFailure(
            ApkInspectionCode.CRYPTOGRAPHY_UNAVAILABLE,
            "cryptography is required to verify APK signatures",
        ) from error
    outer = _der_children(_der_single(cms, 0x30))
    if len(outer) != 2:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 CMS container is invalid")
    content_type, explicit_signed_data = outer
    if _der_oid(content_type) != "1.2.840.113549.1.7.2" or explicit_signed_data.tag != 0xA0:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 CMS container is invalid")
    signed_data = _der_single(explicit_signed_data.content, 0x30)
    fields = _der_children(signed_data)
    if len(fields) < 4 or fields[0].tag != 0x02 or fields[1].tag != 0x31 or fields[2].tag != 0x30:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 SignedData is invalid")
    encap = _der_children(fields[2])
    if not encap or _der_oid(encap[0]) != "1.2.840.113549.1.7.1":
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 CMS content type is invalid")
    if len(encap) > 1:
        if len(encap) != 2 or encap[1].tag != 0xA0:
            raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 CMS content is invalid")
        embedded = _der_single(encap[1].content, 0x04).content
        if not _constant_time_equal(embedded, content):
            raise _ParseFailure(ApkInspectionCode.SIGNATURE_INVALID, "APK v1 CMS content disagrees with SF")

    certificates_field = next((field for field in fields[3:] if field.tag == 0xA0), None)
    signer_infos = next((field for field in reversed(fields[3:]) if field.tag == 0x31), None)
    if certificates_field is None or signer_infos is None:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 CMS has no signer data")
    try:
        certificates = tuple(pkcs7.load_der_pkcs7_certificates(cms))
    except (TypeError, ValueError) as error:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 certificates are invalid") from error
    if not certificates or len(certificates) > 64:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 certificate count is invalid")
    verified: list[str] = []
    signer_values = _der_children(signer_infos)
    if not signer_values or len(signer_values) > 32:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 signer count is invalid")
    for signer in signer_values:
        certificate = _verify_cms_signer(signer, certificates, content)
        try:
            from cryptography.hazmat.primitives.serialization import Encoding

            encoded = certificate.public_bytes(Encoding.DER)
        except ImportError as error:
            raise _ParseFailure(
                ApkInspectionCode.CRYPTOGRAPHY_UNAVAILABLE,
                "cryptography is required to verify APK signatures",
            ) from error
        verified.append(hashlib.sha256(encoded).hexdigest())
    return tuple(dict.fromkeys(verified))


def _verify_cms_signer(
    signer: _DerValue,
    certificates: Sequence[x509.Certificate],
    content: bytes,
) -> x509.Certificate:
    if signer.tag != 0x30:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 signer is invalid")
    fields = _der_children(signer)
    if len(fields) < 5:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 signer is truncated")
    _version = _der_integer(fields[0])
    sid = fields[1]
    digest_name = _CMS_DIGEST_OIDS.get(_algorithm_oid(fields[2]))
    if digest_name is None:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_UNSUPPORTED, "APK v1 uses a weak or unsupported digest")
    index = 3
    signed_attributes: _DerValue | None = None
    if fields[index].tag == 0xA0:
        signed_attributes = fields[index]
        index += 1
    if index + 2 > len(fields):
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 signer fields are missing")
    signature_oid = _algorithm_oid(fields[index])
    signature_value = fields[index + 1]
    if signature_value.tag != 0x04:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 signature value is invalid")
    certificate = _cms_certificate_for_sid(sid, certificates)
    payload = content
    if signed_attributes is not None:
        _verify_cms_attributes(signed_attributes, content, digest_name)
        payload = bytes([0x31]) + signed_attributes.encoded[1:]
    _verify_cms_crypto(certificate, signature_oid, digest_name, signature_value.content, payload)
    return certificate


def _cms_certificate_for_sid(
    sid: _DerValue,
    certificates: Sequence[x509.Certificate],
) -> x509.Certificate:
    if sid.tag == 0x30:
        parts = _der_children(sid)
        if len(parts) != 2:
            raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 signer identifier is invalid")
        serial = _der_integer(parts[1])
        matches = tuple(
            certificate
            for certificate in certificates
            if certificate.serial_number == serial
            and certificate.issuer.public_bytes() == parts[0].encoded
        )
    elif sid.tag == 0x80:
        try:
            from cryptography import x509
            from cryptography.x509.oid import ExtensionOID
        except ImportError as error:
            raise _ParseFailure(
                ApkInspectionCode.CRYPTOGRAPHY_UNAVAILABLE,
                "cryptography is required to verify APK signatures",
            ) from error
        matches_list: list[x509.Certificate] = []
        for certificate in certificates:
            try:
                extension = certificate.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_KEY_IDENTIFIER
                ).value
            except x509.ExtensionNotFound:
                continue
            if not isinstance(extension, x509.SubjectKeyIdentifier):
                continue
            key_id = extension.digest
            if _constant_time_equal(key_id, sid.content):
                matches_list.append(certificate)
        matches = tuple(matches_list)
    else:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_UNSUPPORTED, "APK v1 signer identifier is unsupported")
    if len(matches) != 1:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_INVALID, "APK v1 signer certificate is missing or ambiguous")
    return matches[0]


def _verify_cms_attributes(attributes: _DerValue, content: bytes, digest_name: str) -> None:
    found: dict[str, _DerValue] = {}
    for attribute in _der_children(attributes):
        parts = _der_children(attribute)
        if attribute.tag != 0x30 or len(parts) != 2 or parts[1].tag != 0x31:
            raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 signed attribute is invalid")
        oid = _der_oid(parts[0])
        values = _der_children(parts[1])
        if len(values) != 1 or oid in found:
            raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 signed attribute is ambiguous")
        found[oid] = values[0]
    content_type = found.get("1.2.840.113549.1.9.3")
    message_digest = found.get("1.2.840.113549.1.9.4")
    if (
        content_type is None
        or _der_oid(content_type) != "1.2.840.113549.1.7.1"
        or message_digest is None
        or message_digest.tag != 0x04
    ):
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_INVALID, "APK v1 required signed attributes are missing")
    actual = hashlib.new(digest_name, content).digest()
    if not _constant_time_equal(message_digest.content, actual):
        raise _ParseFailure(ApkInspectionCode.CONTENT_DIGEST_MISMATCH, "APK v1 signed content digest does not match")


def _verify_cms_crypto(
    certificate: x509.Certificate,
    signature_oid: str,
    digest_name: str,
    signature: bytes,
    payload: bytes,
) -> None:
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa
    except ImportError as error:
        raise _ParseFailure(
            ApkInspectionCode.CRYPTOGRAPHY_UNAVAILABLE,
            "cryptography is required to verify APK signatures",
        ) from error
    expected_rsa_digest = _CMS_RSA_OIDS.get(signature_oid, "missing")
    expected_ec_digest = _CMS_ECDSA_OIDS.get(signature_oid)
    digest = _hash_algorithm(digest_name)
    try:
        public_key = certificate.public_key()
        if expected_rsa_digest != "missing":
            if expected_rsa_digest is not None and expected_rsa_digest != digest_name:
                raise _ParseFailure(ApkInspectionCode.SIGNATURE_INVALID, "APK v1 signature digest algorithms disagree")
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise TypeError("RSA CMS signature requires an RSA key")
            public_key.verify(signature, payload, padding.PKCS1v15(), digest)
        elif expected_ec_digest is not None:
            if expected_ec_digest != digest_name or not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise TypeError("ECDSA CMS signature parameters disagree")
            public_key.verify(signature, payload, ec.ECDSA(digest))
        elif signature_oid == "2.16.840.1.101.3.4.3.2":
            if digest_name != "sha256" or not isinstance(public_key, dsa.DSAPublicKey):
                raise TypeError("DSA CMS signature parameters disagree")
            public_key.verify(signature, payload, digest)
        else:
            raise _ParseFailure(ApkInspectionCode.SIGNATURE_UNSUPPORTED, "APK v1 signature algorithm is unsupported")
    except InvalidSignature as error:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_INVALID, "APK v1 signature is invalid") from error
    except UnsupportedAlgorithm as error:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_UNSUPPORTED, "APK v1 signature algorithm is unavailable") from error
    except (AttributeError, TypeError, ValueError) as error:
        raise _ParseFailure(ApkInspectionCode.SIGNATURE_BLOCK_INVALID, "APK v1 signature key is invalid") from error
