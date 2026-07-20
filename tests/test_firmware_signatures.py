from __future__ import annotations

import datetime as dt
import hashlib
import tempfile
import zipfile
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID
from hypothesis import given
from hypothesis import strategies as st

from pixelflasher_core.cms_verification import CmsVerificationCode, CmsVerificationError
from pixelflasher_core.firmware import FirmwareKind
from pixelflasher_core.firmware_signatures import (
    FirmwarePackageSignatureVerifier,
    FirmwareTrustStatus,
    PackageSignatureStatus,
)


def _signing_identity() -> tuple[rsa.RSAPrivateKey, x509.Certificate, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PixelFlasher OTA test")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.UTC) - dt.timedelta(days=1))
        .not_valid_after(dt.datetime.now(dt.UTC) + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    digest = hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()
    return key, certificate, digest


def _unsigned_zip(path: Path) -> bytes:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(
            "META-INF/com/android/metadata",
            "ota-type=AB\npre-device=komodo\npost-build-incremental=12345\n",
        )
        archive.writestr("payload.bin", b"payload")
    return path.read_bytes()


def _signed_ota(
    path: Path,
    key: rsa.RSAPrivateKey,
    certificate: x509.Certificate,
    *,
    message: bytes = b"signed by SignApk\0",
) -> None:
    unsigned = _unsigned_zip(path)
    assert unsigned[-22:-18] == b"PK\x05\x06"
    assert unsigned[-2:] == b"\0\0"
    signed_content = unsigned[:-2]
    cms = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(signed_content)
        .add_signer(certificate, key, hashes.SHA256())
        .sign(
            serialization.Encoding.DER,
            [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary],
        )
    )
    signature_start = len(cms) + 6
    comment_size = len(message) + signature_start
    assert comment_size <= 0xFFFF
    footer = (
        signature_start.to_bytes(2, "little")
        + b"\xff\xff"
        + comment_size.to_bytes(2, "little")
    )
    path.write_bytes(
        signed_content
        + comment_size.to_bytes(2, "little")
        + message
        + cms
        + footer
    )


def test_trusted_ota_whole_file_signature_is_accepted(tmp_path: Path) -> None:
    key, certificate, signer = _signing_identity()
    package = tmp_path / "ota.zip"
    _signed_ota(package, key, certificate)

    evidence = FirmwarePackageSignatureVerifier(
        trusted_signer_sha256=(signer,)
    ).verify(
        package,
        kind=FirmwareKind.OTA,
        official_manifest_verified=False,
    )

    assert evidence.status is FirmwareTrustStatus.PACKAGE_VERIFIED
    assert evidence.package_signature is PackageSignatureStatus.VERIFIED
    assert evidence.signer_sha256 == (signer,)
    assert evidence.accepted
    assert evidence.to_public_dict()["sourceAuthentication"] == "trusted_package_signer"


def test_unknown_valid_ota_signer_requires_hash_bound_confirmation(tmp_path: Path) -> None:
    key, certificate, signer = _signing_identity()
    package = tmp_path / "ota.zip"
    _signed_ota(package, key, certificate)

    evidence = FirmwarePackageSignatureVerifier().verify(
        package,
        kind=FirmwareKind.OTA,
        official_manifest_verified=False,
    )

    assert evidence.status is FirmwareTrustStatus.CONFIRMATION_REQUIRED
    assert evidence.signer_sha256 == (signer,)
    confirmed = evidence.confirmed()
    assert confirmed.status is FirmwareTrustStatus.USER_CONFIRMED
    assert confirmed.source_authentication == "user_confirmation"
    assert confirmed.accepted


def test_tampered_signed_ota_is_rejected_without_override(tmp_path: Path) -> None:
    key, certificate, _signer = _signing_identity()
    package = tmp_path / "ota.zip"
    _signed_ota(package, key, certificate)
    tampered = bytearray(package.read_bytes())
    tampered[10] ^= 1
    package.write_bytes(tampered)

    evidence = FirmwarePackageSignatureVerifier().verify(
        package,
        kind=FirmwareKind.OTA,
        official_manifest_verified=True,
    )

    assert evidence.status is FirmwareTrustStatus.REJECTED
    assert evidence.package_signature is PackageSignatureStatus.INVALID
    assert not evidence.accepted


def test_unsigned_official_ota_uses_signed_manifest_evidence(tmp_path: Path) -> None:
    package = tmp_path / "ota.zip"
    _unsigned_zip(package)

    evidence = FirmwarePackageSignatureVerifier().verify(
        package,
        kind=FirmwareKind.OTA,
        official_manifest_verified=True,
    )

    assert evidence.status is FirmwareTrustStatus.MANIFEST_VERIFIED
    assert evidence.package_signature is PackageSignatureStatus.UNSIGNED
    assert evidence.source_authentication == "signed_manifest"
    assert evidence.accepted


def test_user_supplied_unsigned_factory_requires_confirmation(tmp_path: Path) -> None:
    package = tmp_path / "factory.zip"
    _unsigned_zip(package)

    evidence = FirmwarePackageSignatureVerifier().verify(
        package,
        kind=FirmwareKind.FACTORY,
        official_manifest_verified=False,
    )

    assert evidence.status is FirmwareTrustStatus.CONFIRMATION_REQUIRED
    assert evidence.package_signature is PackageSignatureStatus.NOT_APPLICABLE
    assert evidence.confirmation_required


def test_invalid_signature_footer_is_fail_closed(tmp_path: Path) -> None:
    key, certificate, _signer = _signing_identity()
    package = tmp_path / "ota.zip"
    _signed_ota(package, key, certificate)
    content = bytearray(package.read_bytes())
    content[-6:-4] = b"\x01\x00"
    package.write_bytes(content)

    evidence = FirmwarePackageSignatureVerifier().verify(
        package,
        kind=FirmwareKind.OTA,
        official_manifest_verified=False,
    )

    assert evidence.status is FirmwareTrustStatus.REJECTED
    assert evidence.code == "firmware_signature_footer_invalid"


def test_cancelled_streaming_verification_is_explicit(tmp_path: Path) -> None:
    key, certificate, _signer = _signing_identity()
    package = tmp_path / "ota.zip"
    _signed_ota(package, key, certificate)

    class Cancelled:
        cancelled = True

    with pytest.raises(CmsVerificationError) as raised:
        FirmwarePackageSignatureVerifier().verify(
            package,
            kind=FirmwareKind.OTA,
            official_manifest_verified=False,
            cancellation=Cancelled(),
        )
    assert raised.value.code is CmsVerificationCode.CANCELLED


@given(st.binary(max_size=4096))
def test_arbitrary_ota_footer_data_never_becomes_implicitly_trusted(
    content: bytes,
) -> None:
    with tempfile.TemporaryDirectory() as directory:
        package = Path(directory) / "fuzzed.zip"
        package.write_bytes(content)

        evidence = FirmwarePackageSignatureVerifier().verify(
            package,
            kind=FirmwareKind.OTA,
            official_manifest_verified=False,
        )

        assert evidence.status in {
            FirmwareTrustStatus.CONFIRMATION_REQUIRED,
            FirmwareTrustStatus.REJECTED,
        }
        assert not evidence.accepted
