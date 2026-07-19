from __future__ import annotations

import base64
import builtins
import hashlib
import io
import os
import struct
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import Any, BinaryIO, cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import pixelflasher_core.apk_inspection as apk_module
from pixelflasher_core.apk_inspection import (
    ApkIdentity,
    ApkInspectionCode,
    ApkInspectionError,
    ApkInspectionLimits,
    inspect_apk,
)
from pixelflasher_core.cancellation import CancellationReason, CancellationToken


class _BlockingReader:
    def __init__(
        self,
        raw: BinaryIO,
        started: threading.Event,
        release: threading.Event,
        *,
        fail_after_release: bool,
    ) -> None:
        self._raw = raw
        self._started = started
        self._release = release
        self._fail_after_release = fail_after_release
        self._blocked = False

    def __enter__(self) -> _BlockingReader:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        _ = (exc_type, exc_value, traceback)
        self._raw.close()
        return False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw, name)

    def read(self, size: int = -1) -> bytes:
        if not self._blocked:
            self._blocked = True
            self._started.set()
            if not self._release.wait(timeout=5.0):
                raise TimeoutError("test did not release the blocked APK read")
            if self._fail_after_release:
                raise OSError("late synthetic read failure")
        return self._raw.read(size)


def _signer() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PixelFlasher test")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(123456789)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def _zip_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return output.getvalue()


def _lp(value: bytes) -> bytes:
    return struct.pack("<I", len(value)) + value


def _content_digest(apk: bytes) -> bytes:
    eocd = apk.rfind(b"PK\x05\x06")
    central = struct.unpack_from("<I", apk, eocd + 16)[0]
    sections = (apk[:central], apk[central:eocd], apk[eocd:])
    chunks: list[bytes] = []
    for section in sections:
        for offset in range(0, len(section), 1024 * 1024):
            chunk = section[offset : offset + 1024 * 1024]
            chunks.append(
                hashlib.sha256(b"\xa5" + struct.pack("<I", len(chunk)) + chunk).digest()
            )
    return hashlib.sha256(
        b"\x5a" + struct.pack("<I", len(chunks)) + b"".join(chunks)
    ).digest()


def _add_v2_signature(
    unsigned_apk: bytes,
    key: rsa.RSAPrivateKey,
    certificate: x509.Certificate,
    *,
    corrupt_signature: bool = False,
) -> bytes:
    algorithm = 0x0103
    digest_record = struct.pack("<I", algorithm) + _lp(_content_digest(unsigned_apk))
    certificate_der = certificate.public_bytes(serialization.Encoding.DER)
    signed_data = (
        _lp(_lp(digest_record))
        + _lp(_lp(certificate_der))
        + _lp(b"")
        + _lp(b"")
    )
    signature = key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
    if corrupt_signature:
        signature = bytes([signature[0] ^ 1]) + signature[1:]
    signature_record = struct.pack("<I", algorithm) + _lp(signature)
    public_key = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    signer = _lp(signed_data) + _lp(_lp(signature_record)) + _lp(public_key)
    scheme_value = _lp(_lp(signer))
    pair = struct.pack("<Q", 4 + len(scheme_value)) + struct.pack("<I", 0x7109871A) + scheme_value
    block_size = len(pair) + 24
    block = (
        struct.pack("<Q", block_size)
        + pair
        + struct.pack("<Q", block_size)
        + b"APK Sig Block 42"
    )
    eocd = unsigned_apk.rfind(b"PK\x05\x06")
    central = struct.unpack_from("<I", unsigned_apk, eocd + 16)[0]
    patched_eocd = bytearray(unsigned_apk[eocd:])
    struct.pack_into("<I", patched_eocd, 16, central + len(block))
    return unsigned_apk[:central] + block + unsigned_apk[central:eocd] + patched_eocd


def _add_v3_signature(
    unsigned_apk: bytes,
    key: rsa.RSAPrivateKey,
    certificate: x509.Certificate,
) -> bytes:
    algorithm = 0x0103
    min_sdk = 28
    max_sdk = 0x7FFFFFFF
    digest_record = struct.pack("<I", algorithm) + _lp(_content_digest(unsigned_apk))
    certificate_der = certificate.public_bytes(serialization.Encoding.DER)
    signed_data = (
        _lp(_lp(digest_record))
        + _lp(_lp(certificate_der))
        + struct.pack("<II", min_sdk, max_sdk)
        + _lp(b"")
    )
    signature = key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
    signature_record = struct.pack("<I", algorithm) + _lp(signature)
    public_key = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    signer = (
        _lp(signed_data)
        + struct.pack("<II", min_sdk, max_sdk)
        + _lp(_lp(signature_record))
        + _lp(public_key)
    )
    scheme_value = _lp(_lp(signer))
    pair = struct.pack("<Q", 4 + len(scheme_value)) + struct.pack("<I", 0xF05368C0) + scheme_value
    block_size = len(pair) + 24
    block = (
        struct.pack("<Q", block_size)
        + pair
        + struct.pack("<Q", block_size)
        + b"APK Sig Block 42"
    )
    eocd = unsigned_apk.rfind(b"PK\x05\x06")
    central = struct.unpack_from("<I", unsigned_apk, eocd + 16)[0]
    patched_eocd = bytearray(unsigned_apk[eocd:])
    struct.pack_into("<I", patched_eocd, 16, central + len(block))
    return unsigned_apk[:central] + block + unsigned_apk[central:eocd] + patched_eocd


def _text_manifest(package_name: str = "com.example.safe") -> bytes:
    return f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{package_name}" />'.encode()


def _write_v2_apk(
    path: Path,
    *,
    manifest: bytes | None = None,
    extra_entries: list[tuple[str, bytes]] | None = None,
) -> tuple[x509.Certificate, bytes]:
    key, certificate = _signer()
    entries = [
        ("AndroidManifest.xml", manifest or _text_manifest()),
        ("classes.dex", b"dex\n035\0test payload"),
    ]
    entries.extend(extra_entries or [])
    apk = _add_v2_signature(_zip_bytes(entries), key, certificate)
    path.write_bytes(apk)
    return certificate, apk


def _utf8_pool_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    assert len(value) < 128 and len(encoded) < 128
    return bytes((len(value), len(encoded))) + encoded + b"\0"


def _binary_manifest(package_name: str) -> bytes:
    strings = ("manifest", "package", package_name)
    encoded = tuple(_utf8_pool_string(value) for value in strings)
    offsets: list[int] = []
    cursor = 0
    for value in encoded:
        offsets.append(cursor)
        cursor += len(value)
    string_header_size = 28
    strings_start = string_header_size + 4 * len(strings)
    string_body = b"".join(encoded)
    string_size = strings_start + len(string_body)
    string_pool = (
        struct.pack(
            "<HHIIIIII",
            0x0001,
            string_header_size,
            string_size,
            len(strings),
            0,
            0x100,
            strings_start,
            0,
        )
        + b"".join(struct.pack("<I", offset) for offset in offsets)
        + string_body
    )
    attribute = struct.pack(
        "<IIIHBBI",
        0xFFFFFFFF,
        1,
        2,
        8,
        0,
        0x03,
        2,
    )
    start_size = 16 + 20 + len(attribute)
    start_element = (
        struct.pack("<HHI", 0x0102, 16, start_size)
        + struct.pack("<II", 1, 0xFFFFFFFF)
        + struct.pack(
            "<IIHHHHHH",
            0xFFFFFFFF,
            0,
            20,
            20,
            1,
            0,
            0,
            0,
        )
        + attribute
    )
    size = 8 + len(string_pool) + len(start_element)
    return struct.pack("<HHI", 0x0003, 8, size) + string_pool + start_element


def _write_v1_apk(path: Path) -> tuple[x509.Certificate, bytes]:
    key, certificate = _signer()
    payloads = {
        "AndroidManifest.xml": _text_manifest(),
        "classes.dex": b"dex\n035\0v1 payload",
    }
    sections: list[str] = []
    for name, data in payloads.items():
        digest = base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")
        sections.append(f"Name: {name}\r\nSHA-256-Digest: {digest}\r\n\r\n")
    manifest = ("Manifest-Version: 1.0\r\n\r\n" + "".join(sections)).encode("utf-8")
    manifest_digest = base64.b64encode(hashlib.sha256(manifest).digest()).decode("ascii")
    sf = (
        "Signature-Version: 1.0\r\n"
        f"SHA-256-Digest-Manifest: {manifest_digest}\r\n\r\n"
    ).encode("ascii")
    cms = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(sf)
        .add_signer(certificate, key, hashes.SHA256())
        .sign(
            serialization.Encoding.DER,
            [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary],
        )
    )
    apk = _zip_bytes(
        list(payloads.items())
        + [
            ("META-INF/MANIFEST.MF", manifest),
            ("META-INF/CERT.SF", sf),
            ("META-INF/CERT.RSA", cms),
        ]
    )
    path.write_bytes(apk)
    return certificate, apk


def test_v2_text_manifest_returns_immutable_verified_identity(tmp_path: Path) -> None:
    path = tmp_path / "safe.apk"
    certificate, apk = _write_v2_apk(path)

    identity = inspect_apk(path)

    assert identity == ApkIdentity(
        package_name="com.example.safe",
        sha256=hashlib.sha256(apk).hexdigest(),
        signer_sha256=(
            hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest(),
        ),
        schemes=("v2",),
        verified=True,
    )
    with pytest.raises(AttributeError):
        identity.package_name = "com.example.changed"  # type: ignore[misc]


def test_v2_binary_axml_manifest_is_parsed_without_external_tools(tmp_path: Path) -> None:
    path = tmp_path / "binary.apk"
    _write_v2_apk(path, manifest=_binary_manifest("org.example.binary"))

    identity = inspect_apk(path)

    assert identity.package_name == "org.example.binary"
    assert identity.verified


def test_v3_sdk_bound_signer_and_content_are_verified(tmp_path: Path) -> None:
    path = tmp_path / "v3.apk"
    key, certificate = _signer()
    unsigned = _zip_bytes(
        [
            ("AndroidManifest.xml", _text_manifest("org.example.v3")),
            ("classes.dex", b"v3 content"),
        ]
    )
    path.write_bytes(_add_v3_signature(unsigned, key, certificate))

    identity = inspect_apk(path)

    assert identity.package_name == "org.example.v3"
    assert identity.schemes == ("v3",)


def test_v1_cms_and_every_manifest_member_are_verified(tmp_path: Path) -> None:
    path = tmp_path / "v1.apk"
    certificate, apk = _write_v1_apk(path)

    identity = inspect_apk(path)

    assert identity.sha256 == hashlib.sha256(apk).hexdigest()
    assert identity.schemes == ("v1",)
    assert identity.signer_sha256 == (
        hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest(),
    )


def test_user_cancellation_interrupts_apk_hash_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "blocked.apk"
    path.write_bytes(b"large-enough-to-enter-the-hash-loop")
    started = threading.Event()
    release = threading.Event()
    token = CancellationToken()
    real_open = Path.open

    def blocking_open(
        source: Path,
        mode: str = "r",
        buffering: int = -1,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> _BlockingReader:
        return _BlockingReader(
            cast(
                BinaryIO,
                real_open(
                    source,
                    mode,
                    buffering,
                    encoding,
                    errors,
                    newline,
                ),
            ),
            started,
            release,
            fail_after_release=False,
        )

    monkeypatch.setattr(Path, "open", blocking_open)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            inspect_apk,
            path,
            limits=ApkInspectionLimits(io_chunk_size=4),
            cancellation=token,
        )
        try:
            assert started.wait(timeout=2.0)
            token.cancel()
            release.set()
            with pytest.raises(ApkInspectionError) as raised:
                future.result(timeout=2.0)
        finally:
            release.set()

    assert raised.value.code is ApkInspectionCode.CANCELLED
    assert token.reason is CancellationReason.USER


def test_deadline_precedes_late_apk_read_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "late-read-error.apk"
    path.write_bytes(b"read failure must not mask an expired operation deadline")
    started = threading.Event()
    release = threading.Event()
    token = CancellationToken()
    real_open = Path.open

    def blocking_open(
        source: Path,
        mode: str = "r",
        buffering: int = -1,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> _BlockingReader:
        return _BlockingReader(
            cast(
                BinaryIO,
                real_open(
                    source,
                    mode,
                    buffering,
                    encoding,
                    errors,
                    newline,
                ),
            ),
            started,
            release,
            fail_after_release=True,
        )

    monkeypatch.setattr(Path, "open", blocking_open)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            inspect_apk,
            path,
            limits=ApkInspectionLimits(io_chunk_size=4),
            cancellation=token,
        )
        try:
            assert started.wait(timeout=2.0)
            token.set_deadline_at(0.0)
            release.set()
            with pytest.raises(ApkInspectionError) as raised:
                future.result(timeout=2.0)
        finally:
            release.set()

    assert raised.value.code is ApkInspectionCode.CANCELLED
    assert token.reason is CancellationReason.DEADLINE


def test_v2_content_tampering_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "tampered.apk"
    _certificate, apk = _write_v2_apk(path)
    marker = b"dex\n035\0test payload"
    position = apk.index(marker)
    tampered = bytearray(apk)
    tampered[position] ^= 1
    path.write_bytes(tampered)

    with pytest.raises(ApkInspectionError) as raised:
        inspect_apk(path)

    assert raised.value.code is ApkInspectionCode.CONTENT_DIGEST_MISMATCH


def test_v2_invalid_cryptographic_signature_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "bad-signature.apk"
    key, certificate = _signer()
    unsigned = _zip_bytes(
        [("AndroidManifest.xml", _text_manifest()), ("classes.dex", b"signed content")]
    )
    path.write_bytes(
        _add_v2_signature(unsigned, key, certificate, corrupt_signature=True)
    )

    with pytest.raises(ApkInspectionError) as raised:
        inspect_apk(path)

    assert raised.value.code is ApkInspectionCode.SIGNATURE_INVALID


def test_missing_cryptography_dependency_fails_with_typed_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "needs-crypto.apk"
    _write_v2_apk(path)
    real_import = builtins.__import__

    def guarded_import(
        name: str,
        globals: dict[str, object] | None = None,
        locals: dict[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("cryptography deliberately hidden")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", guarded_import)

    with pytest.raises(ApkInspectionError) as raised:
        inspect_apk(path)

    assert raised.value.code is ApkInspectionCode.CRYPTOGRAPHY_UNAVAILABLE


@pytest.mark.parametrize(
    ("entries", "code"),
    [
        (
            [("AndroidManifest.xml", _text_manifest()), ("../classes.dex", b"x")],
            ApkInspectionCode.UNSAFE_ARCHIVE,
        ),
        (
            [
                ("AndroidManifest.xml", _text_manifest()),
                ("androidmanifest.xml", _text_manifest()),
            ],
            ApkInspectionCode.DUPLICATE_ENTRY,
        ),
    ],
)
def test_ambiguous_or_traversing_zip_is_rejected(
    tmp_path: Path,
    entries: list[tuple[str, bytes]],
    code: ApkInspectionCode,
) -> None:
    path = tmp_path / "unsafe.apk"
    path.write_bytes(_zip_bytes(entries))

    with pytest.raises(ApkInspectionError) as raised:
        inspect_apk(path)

    assert raised.value.code is code


def test_manifest_limit_is_enforced_before_parsing(tmp_path: Path) -> None:
    path = tmp_path / "large-manifest.apk"
    _write_v2_apk(path)

    with pytest.raises(ApkInspectionError) as raised:
        inspect_apk(path, limits=ApkInspectionLimits(maximum_manifest_bytes=16))

    assert raised.value.code is ApkInspectionCode.MANIFEST_TOO_LARGE


def test_unsigned_apk_never_returns_unverified_identity(tmp_path: Path) -> None:
    path = tmp_path / "unsigned.apk"
    path.write_bytes(_zip_bytes([("AndroidManifest.xml", _text_manifest())]))

    with pytest.raises(ApkInspectionError) as raised:
        inspect_apk(path)

    assert raised.value.code is ApkInspectionCode.SIGNATURE_MISSING


@given(st.binary(max_size=2048))
@settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_arbitrary_input_never_leaks_raw_parser_exceptions(tmp_path: Path, data: bytes) -> None:
    path = tmp_path / f"fuzz-{hashlib.sha256(data).hexdigest()}.apk"
    path.write_bytes(data)

    try:
        inspect_apk(path)
    except ApkInspectionError:
        pass
    else:
        pytest.fail("arbitrary unsigned input unexpectedly verified")


def test_missing_and_symlink_paths_use_typed_errors(tmp_path: Path) -> None:
    missing = tmp_path / "missing.apk"
    with pytest.raises(ApkInspectionError) as missing_error:
        inspect_apk(missing)
    assert missing_error.value.code is ApkInspectionCode.FILE_NOT_FOUND

    if os.name != "nt":
        target = tmp_path / "target.apk"
        target.write_bytes(b"not an apk")
        link = tmp_path / "link.apk"
        link.symlink_to(target)
        with pytest.raises(ApkInspectionError) as link_error:
            inspect_apk(link)
        assert link_error.value.code is ApkInspectionCode.NOT_REGULAR_FILE


@pytest.mark.parametrize(
    "kwargs",
    [
        {"maximum_apk_bytes": 0},
        {"maximum_entries": 0},
        {"maximum_manifest_bytes": 0},
        {"io_chunk_size": 0},
        {"maximum_compression_ratio": 0.5},
    ],
)
def test_invalid_inspection_limits_are_rejected(kwargs: dict[str, int | float]) -> None:
    with pytest.raises(ValueError):
        ApkInspectionLimits(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"package_name": "invalid"},
        {"sha256": "0" * 63},
        {"signer_sha256": ()},
        {"signer_sha256": ("0" * 64, "0" * 64)},
        {"schemes": ()},
        {"schemes": ("v2", "v2")},
        {"verified": False},
    ],
)
def test_identity_invariants_never_describe_unverified_data(
    kwargs: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "package_name": "com.example.valid",
        "sha256": "0" * 64,
        "signer_sha256": ("1" * 64,),
        "schemes": ("v2",),
        "verified": True,
    }
    values.update(kwargs)
    with pytest.raises(ValueError):
        ApkIdentity(**values)  # type: ignore[arg-type]


def test_invalid_path_file_size_and_directory_fail_with_stable_codes(tmp_path: Path) -> None:
    with pytest.raises(ApkInspectionError) as invalid:
        inspect_apk(object())  # type: ignore[arg-type]
    assert invalid.value.code is ApkInspectionCode.INVALID_PATH

    directory = tmp_path / "directory.apk"
    directory.mkdir()
    with pytest.raises(ApkInspectionError) as unreadable:
        inspect_apk(directory)
    assert unreadable.value.code in {
        ApkInspectionCode.READ_FAILED,
        ApkInspectionCode.NOT_REGULAR_FILE,
    }

    large = tmp_path / "large.apk"
    large.write_bytes(b"1234")
    with pytest.raises(ApkInspectionError) as too_large:
        inspect_apk(large, limits=ApkInspectionLimits(maximum_apk_bytes=3))
    assert too_large.value.code is ApkInspectionCode.FILE_TOO_LARGE


@pytest.mark.parametrize(
    "name",
    ["", "/absolute", "a\\b", "a/../b", "a/./b", "bad\x00name", "e\u0301.txt", "bad\nname"],
)
def test_archive_name_policy_rejects_ambiguous_paths(name: str) -> None:
    with pytest.raises(apk_module._ParseFailure):
        apk_module._safe_archive_name(name)


def test_archive_count_size_compression_and_member_type_limits(tmp_path: Path) -> None:
    too_many = tmp_path / "too-many.apk"
    too_many.write_bytes(
        _zip_bytes([("AndroidManifest.xml", _text_manifest()), ("classes.dex", b"x")])
    )
    with pytest.raises(ApkInspectionError) as entry_error:
        inspect_apk(too_many, limits=ApkInspectionLimits(maximum_entries=1))
    assert entry_error.value.code is ApkInspectionCode.TOO_MANY_ENTRIES

    with pytest.raises(ApkInspectionError) as member_error:
        inspect_apk(
            too_many,
            limits=ApkInspectionLimits(maximum_member_bytes=8),
        )
    assert member_error.value.code is ApkInspectionCode.MEMBER_TOO_LARGE

    compressed = tmp_path / "compressed.apk"
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", b"0" * 4096)
    compressed.write_bytes(output.getvalue())
    with pytest.raises(ApkInspectionError) as ratio_error:
        inspect_apk(
            compressed,
            limits=ApkInspectionLimits(maximum_compression_ratio=2),
        )
    assert ratio_error.value.code is ApkInspectionCode.SUSPICIOUS_COMPRESSION

    nonregular = tmp_path / "symlink-member.apk"
    output = io.BytesIO()
    info = zipfile.ZipInfo("AndroidManifest.xml")
    info.create_system = 3
    info.external_attr = (0o120777 << 16) | 0xA000
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(info, b"target")
    nonregular.write_bytes(output.getvalue())
    with pytest.raises(ApkInspectionError) as type_error:
        inspect_apk(nonregular)
    assert type_error.value.code is ApkInspectionCode.UNSAFE_ARCHIVE


def test_missing_or_invalid_android_manifest_fails_before_signature(tmp_path: Path) -> None:
    missing = tmp_path / "missing-manifest.apk"
    missing.write_bytes(_zip_bytes([("classes.dex", b"x")]))
    with pytest.raises(ApkInspectionError) as missing_error:
        inspect_apk(missing)
    assert missing_error.value.code is ApkInspectionCode.MANIFEST_MISSING

    invalid_values = (
        b"",
        b"<!DOCTYPE manifest><manifest package='com.example.bad'/>",
        b"<application package='com.example.bad'/>",
        b"<manifest />",
        b"<manifest package='invalid'/>",
        b"not binary XML",
    )
    for index, manifest in enumerate(invalid_values):
        path = tmp_path / f"invalid-manifest-{index}.apk"
        key, certificate = _signer()
        path.write_bytes(
            _add_v2_signature(
                _zip_bytes([("AndroidManifest.xml", manifest)]),
                key,
                certificate,
            )
        )
        with pytest.raises(ApkInspectionError) as invalid_error:
            inspect_apk(path)
        assert invalid_error.value.code in {
            ApkInspectionCode.MANIFEST_INVALID,
            ApkInspectionCode.PACKAGE_NAME_INVALID,
        }


def test_binary_manifest_must_use_manifest_as_its_root(tmp_path: Path) -> None:
    malformed = bytearray(_binary_manifest("com.example.binary"))
    # The first string-pool entry is the root element name.
    position = malformed.index(b"manifest\0")
    malformed[position : position + len(b"manifest")] = b"not_root"
    path = tmp_path / "wrong-root.apk"
    key, certificate = _signer()
    path.write_bytes(
        _add_v2_signature(
            _zip_bytes([("AndroidManifest.xml", bytes(malformed))]),
            key,
            certificate,
        )
    )

    with pytest.raises(ApkInspectionError) as raised:
        inspect_apk(path)

    assert raised.value.code is ApkInspectionCode.MANIFEST_INVALID


def test_low_level_length_and_der_parsers_reject_noncanonical_input() -> None:
    reader = apk_module._ByteReader(b"\x02\0\0\0x")
    with pytest.raises(apk_module._ParseFailure):
        reader.length_prefixed()
    with pytest.raises(apk_module._ParseFailure):
        apk_module._length_prefixed_sequence(_lp(b"a") + _lp(b"b"), 1)
    with pytest.raises(apk_module._ParseFailure):
        apk_module._algorithm_records(b"")
    duplicate = _lp(struct.pack("<I", 0x0103) + _lp(b"a")) * 2
    with pytest.raises(apk_module._ParseFailure):
        apk_module._algorithm_records(duplicate)

    invalid_der_values = (
        b"",
        b"\x1f\x00",
        b"\x04\x80",
        b"\x04\x81\x01x",
        b"\x04\x82\x00\x80" + b"x" * 128,
        b"\x04\x02x",
    )
    for value in invalid_der_values:
        with pytest.raises(apk_module._ParseFailure):
            apk_module._der_value(value)
    with pytest.raises(apk_module._ParseFailure):
        apk_module._der_single(b"\x04\x00\x04\x00", 0x04)
    with pytest.raises(apk_module._ParseFailure):
        apk_module._der_integer(apk_module._DerValue(0x02, b"", b"\x80"))
    with pytest.raises(apk_module._ParseFailure):
        apk_module._der_oid(apk_module._DerValue(0x06, b"", b"\x2a\x80"))


def test_v1_incomplete_signature_metadata_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "incomplete-v1.apk"
    path.write_bytes(
        _zip_bytes(
            [
                ("AndroidManifest.xml", _text_manifest()),
                ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n\r\n"),
                ("META-INF/CERT.SF", b"Signature-Version: 1.0\r\n\r\n"),
            ]
        )
    )

    with pytest.raises(ApkInspectionError) as raised:
        inspect_apk(path)

    assert raised.value.code is ApkInspectionCode.SIGNATURE_BLOCK_INVALID


def test_binary_xml_bounds_helpers_are_fail_closed() -> None:
    limits = ApkInspectionLimits(maximum_axml_strings=2, maximum_axml_string_bytes=16)
    malformed_documents = (
        b"\x03\0\x08\0\x09\0\0\0x",
        struct.pack("<HHI", 0x0003, 8, 16) + b"\x01\0\x08\0\x08\0\0\0",
        struct.pack("<HHI", 0x0003, 8, 15) + b"1234567",
    )
    for data in malformed_documents:
        with pytest.raises(apk_module._ParseFailure):
            apk_module._parse_binary_manifest(data, limits)

    with pytest.raises(apk_module._ParseFailure):
        apk_module._chunk_header(b"123", 0, 3)
    with pytest.raises(apk_module._ParseFailure):
        apk_module._chunk_header(struct.pack("<HHI", 1, 7, 8), 0, 8)
    with pytest.raises(apk_module._ParseFailure):
        apk_module._parse_string_pool(b"short", limits)
    invalid_pool = struct.pack("<HHIIIIII", 1, 28, 28, 3, 0, 0x100, 28, 0)
    with pytest.raises(apk_module._ParseFailure):
        apk_module._parse_string_pool(invalid_pool, limits)

    for value in (b"", b"\x80"):
        with pytest.raises(apk_module._ParseFailure):
            apk_module._pool_length8(value, 0, len(value))
    assert apk_module._pool_length8(b"\x81\x02", 0, 2) == (258, 2)
    for value in (b"", b"\x00", b"\x00\x80"):
        with pytest.raises(apk_module._ParseFailure):
            apk_module._pool_length16(value, 0, len(value))
    assert apk_module._pool_length16(b"\x01\x80\x02\0", 0, 4) == (
        (1 << 16) | 2,
        4,
    )
    with pytest.raises(apk_module._ParseFailure):
        apk_module._string_at(("one",), 1)
    assert apk_module._string_at(("one",), 0xFFFFFFFF) is None


def test_binary_xml_string_decoders_validate_lengths_and_terminators() -> None:
    assert apk_module._decode_utf8_pool_string(b"\x01\x01a\0", 0, 4, 8) == "a"
    assert apk_module._decode_utf16_pool_string(b"\x01\0a\0\0\0", 0, 6, 8) == "a"
    invalid_utf8 = (
        b"\x01\x09a\0",
        b"\x01\x01aX",
        b"\x01\x01\xff\0",
        b"\x02\x01a\0",
    )
    for value in invalid_utf8:
        with pytest.raises(apk_module._ParseFailure):
            apk_module._decode_utf8_pool_string(value, 0, len(value), 8)
    invalid_utf16 = (
        b"\x09\0a\0\0\0",
        b"\x01\0a\0XX",
        b"\x01\0\x00\xd8\0\0",
    )
    for value in invalid_utf16:
        with pytest.raises(apk_module._ParseFailure):
            apk_module._decode_utf16_pool_string(value, 0, len(value), 8)


def test_start_element_parser_rejects_invalid_attribute_layouts() -> None:
    strings = ("manifest", "package", "com.example.valid")
    with pytest.raises(apk_module._ParseFailure):
        apk_module._start_element(b"short", 16, strings)

    header = struct.pack("<HHI", 0x0102, 16, 36) + struct.pack("<II", 1, 0xFFFFFFFF)
    invalid_attribute_size = header + struct.pack(
        "<IIHHHHHH", 0xFFFFFFFF, 0, 20, 19, 1, 0, 0, 0
    )
    with pytest.raises(apk_module._ParseFailure):
        apk_module._start_element(invalid_attribute_size, 16, strings)

    invalid_index = header + struct.pack(
        "<IIHHHHHH", 0xFFFFFFFF, 99, 20, 20, 0, 0, 0, 0
    )
    with pytest.raises(apk_module._ParseFailure):
        apk_module._start_element(invalid_index, 16, strings)


def test_jar_manifest_and_digest_helpers_reject_ambiguous_metadata() -> None:
    malformed = (
        b"",
        b"Header: value\0\r\n\r\n",
        b" continuation\r\n\r\n",
        b"No separator\r\n\r\n",
        b"Header: one\r\nHEADER: two\r\n\r\n",
        b"Bad Header: value\r\n\r\n",
    )
    for data in malformed:
        with pytest.raises(apk_module._ParseFailure):
            apk_module._parse_jar_manifest(data)
    with pytest.raises(apk_module._ParseFailure):
        apk_module._decode_manifest_value(b"\xff")
    with pytest.raises(apk_module._ParseFailure):
        apk_module._select_manifest_digest({}, "digest")
    with pytest.raises(apk_module._ParseFailure):
        apk_module._select_manifest_digest({"sha-256-digest": b"!"}, "digest")
    with pytest.raises(apk_module._ParseFailure):
        apk_module._select_manifest_digest(
            {"sha-256-digest": base64.b64encode(b"short")},
            "digest",
        )


def test_sf_section_fallback_and_stripping_protection_are_enforced() -> None:
    manifest = (
        b"Manifest-Version: 1.0\r\n\r\n"
        b"Name: classes.dex\r\n"
        b"SHA-256-Digest: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n"
    )
    manifest_sections = apk_module._parse_jar_manifest(manifest)
    main_digest = base64.b64encode(hashlib.sha256(manifest_sections[0][1]).digest())
    section_digest = base64.b64encode(hashlib.sha256(manifest_sections[1][1]).digest())
    sf = (
        b"Signature-Version: 1.0\r\n"
        b"SHA-256-Digest-Manifest-Main-Attributes: "
        + main_digest
        + b"\r\n\r\nName: classes.dex\r\nSHA-256-Digest: "
        + section_digest
        + b"\r\n\r\n"
    )
    sf_sections = apk_module._parse_jar_manifest(sf)
    apk_module._verify_sf_manifest(sf_sections, manifest_sections, manifest)

    bad_main = list(sf_sections)
    bad_main[0] = (
        {"sha-256-digest-manifest-main-attributes": base64.b64encode(b"x" * 32)},
        bad_main[0][1],
    )
    with pytest.raises(apk_module._ParseFailure):
        apk_module._verify_sf_manifest(tuple(bad_main), manifest_sections, manifest)
    with pytest.raises(apk_module._ParseFailure):
        apk_module._verify_sf_sections(sf_sections[:1], manifest_sections)

    apk_module._enforce_scheme_stripping_protection({}, None)
    for declaration in (b"invalid", b"2", b"3"):
        with pytest.raises(apk_module._ParseFailure):
            apk_module._enforce_scheme_stripping_protection(
                {"x-android-apk-signed": declaration},
                None,
            )


def test_der_integer_oid_and_algorithm_validation_paths() -> None:
    with pytest.raises(apk_module._ParseFailure):
        apk_module._der_integer(apk_module._DerValue(0x04, b"", b"\x01"))
    with pytest.raises(apk_module._ParseFailure):
        apk_module._der_integer(apk_module._DerValue(0x02, b"", b"\0\x01"))
    assert apk_module._der_integer(apk_module._DerValue(0x02, b"", b"\x01")) == 1
    with pytest.raises(apk_module._ParseFailure):
        apk_module._der_oid(apk_module._DerValue(0x04, b"", b"\x2a"))
    with pytest.raises(apk_module._ParseFailure):
        apk_module._der_oid(apk_module._DerValue(0x06, b"", b"\x2a\x80\x01"))
    with pytest.raises(apk_module._ParseFailure):
        apk_module._algorithm_oid(apk_module._DerValue(0x04, b"", b""))
    with pytest.raises(apk_module._ParseFailure):
        apk_module._algorithm_oid(apk_module._DerValue(0x30, b"", b""))


def test_crypto_helpers_reject_invalid_certificates_keys_and_digests() -> None:
    key, certificate = _signer()
    with pytest.raises(apk_module._ParseFailure):
        apk_module._load_x509_certificate(b"not a certificate")
    with pytest.raises(apk_module._ParseFailure):
        apk_module._verify_public_key_encoding(certificate, b"not the public key")
    assert apk_module._hash_algorithm("sha384").name == "sha384"
    assert apk_module._hash_algorithm("sha512").name == "sha512"
    with pytest.raises(apk_module._ParseFailure):
        apk_module._hash_algorithm("sha1")
    signature = key.sign(b"payload", padding.PKCS1v15(), hashes.SHA256())
    with pytest.raises(apk_module._ParseFailure):
        apk_module._verify_signature(certificate, 0x0103, signature, b"changed")
