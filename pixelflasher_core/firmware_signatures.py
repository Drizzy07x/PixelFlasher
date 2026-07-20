"""Authenticity policy for factory, OTA, and custom firmware packages."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path

from .cms_verification import (
    CmsVerificationCode,
    CmsVerificationError,
    verify_detached_cms_stream,
)
from .firmware import FirmwareKind

__all__ = (
    "FirmwarePackageSignatureVerifier",
    "FirmwareTrustEvidence",
    "FirmwareTrustStatus",
    "PackageSignatureStatus",
)

_EOCD = b"PK\x05\x06"
_EOCD_HEADER_SIZE = 22
_FOOTER_SIZE = 6
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class FirmwareTrustStatus(StrEnum):
    MANIFEST_VERIFIED = "manifest_verified"
    PACKAGE_VERIFIED = "package_verified"
    CONFIRMATION_REQUIRED = "confirmation_required"
    USER_CONFIRMED = "user_confirmed"
    REJECTED = "rejected"


class PackageSignatureStatus(StrEnum):
    VERIFIED = "verified"
    UNSIGNED = "unsigned"
    NOT_APPLICABLE = "not_applicable"
    INVALID = "invalid"


@dataclass(frozen=True, slots=True)
class FirmwareTrustEvidence:
    status: FirmwareTrustStatus
    package_signature: PackageSignatureStatus
    source_authentication: str
    code: str
    signer_sha256: tuple[str, ...] = ()
    confirmation_required: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "signer_sha256", tuple(self.signer_sha256))
        if self.source_authentication not in {
            "signed_manifest",
            "trusted_package_signer",
            "user_confirmation",
            "none",
        }:
            raise ValueError("unsupported firmware source authentication")
        if not self.code or not re.fullmatch(r"[a-z0-9_]+", self.code):
            raise ValueError("firmware trust code must be a stable identifier")
        if any(not _DIGEST.fullmatch(value) for value in self.signer_sha256):
            raise ValueError("firmware signer identities must be SHA-256 digests")
        if tuple(dict.fromkeys(self.signer_sha256)) != self.signer_sha256:
            raise ValueError("firmware signer identities must not repeat")
        if self.confirmation_required is not (
            self.status is FirmwareTrustStatus.CONFIRMATION_REQUIRED
        ):
            raise ValueError("firmware confirmation flag and status disagree")

    @property
    def accepted(self) -> bool:
        return self.status in {
            FirmwareTrustStatus.MANIFEST_VERIFIED,
            FirmwareTrustStatus.PACKAGE_VERIFIED,
            FirmwareTrustStatus.USER_CONFIRMED,
        }

    def confirmed(self) -> FirmwareTrustEvidence:
        if self.status is not FirmwareTrustStatus.CONFIRMATION_REQUIRED:
            raise ValueError("only unrecognized firmware can be confirmed")
        return replace(
            self,
            status=FirmwareTrustStatus.USER_CONFIRMED,
            source_authentication="user_confirmation",
            code="firmware_trust_user_confirmed",
            confirmation_required=False,
        )

    def to_public_dict(self) -> dict[str, object]:
        evidence = ["archive_sha256_bound"]
        if self.source_authentication == "signed_manifest":
            evidence.extend(("signed_catalog_manifest", "manifest_size_and_sha256_matched"))
        elif self.source_authentication == "trusted_package_signer":
            evidence.extend(("ota_whole_file_signature", "trusted_signer_matched"))
        elif self.source_authentication == "user_confirmation":
            evidence.append("one_time_hash_bound_confirmation")
        if self.package_signature is PackageSignatureStatus.VERIFIED:
            evidence.append("ota_whole_file_signature_verified")
        return {
            "status": self.status.value,
            "packageSignature": self.package_signature.value,
            "sourceAuthentication": self.source_authentication,
            "code": self.code,
            "signerSha256": list(self.signer_sha256),
            "confirmationRequired": self.confirmation_required,
            "evidence": evidence,
        }


class FirmwarePackageSignatureVerifier:
    """Verify OTA whole-file signatures and decide whether trust is sufficient."""

    def __init__(
        self,
        *,
        trusted_signer_sha256: tuple[str, ...] = (),
        io_chunk_size: int = 1024 * 1024,
    ) -> None:
        trusted = tuple(dict.fromkeys(value.casefold() for value in trusted_signer_sha256))
        if any(not _DIGEST.fullmatch(value) for value in trusted):
            raise ValueError("trusted firmware signer identities must be SHA-256 digests")
        if isinstance(io_chunk_size, bool) or not isinstance(io_chunk_size, int) or io_chunk_size <= 0:
            raise ValueError("firmware signature chunk size must be positive")
        self.trusted_signer_sha256 = frozenset(trusted)
        self.io_chunk_size = io_chunk_size

    def verify(
        self,
        path: str | os.PathLike[str],
        *,
        kind: FirmwareKind,
        official_manifest_verified: bool,
        cancellation: object | None = None,
    ) -> FirmwareTrustEvidence:
        if not isinstance(kind, FirmwareKind):
            raise TypeError("kind must be FirmwareKind")
        if not isinstance(official_manifest_verified, bool):
            raise TypeError("official_manifest_verified must be a boolean")
        if kind is not FirmwareKind.OTA:
            if official_manifest_verified:
                return FirmwareTrustEvidence(
                    FirmwareTrustStatus.MANIFEST_VERIFIED,
                    PackageSignatureStatus.NOT_APPLICABLE,
                    "signed_manifest",
                    "firmware_manifest_verified",
                )
            return FirmwareTrustEvidence(
                FirmwareTrustStatus.CONFIRMATION_REQUIRED,
                PackageSignatureStatus.NOT_APPLICABLE,
                "none",
                "firmware_package_signature_not_applicable",
                confirmation_required=True,
            )

        package = self._verify_ota(path, cancellation=cancellation)
        if package.status is FirmwareTrustStatus.REJECTED:
            return package
        if official_manifest_verified:
            return replace(
                package,
                status=FirmwareTrustStatus.MANIFEST_VERIFIED,
                source_authentication="signed_manifest",
                code="firmware_manifest_verified",
                confirmation_required=False,
            )
        if package.package_signature is PackageSignatureStatus.VERIFIED and set(
            package.signer_sha256
        ).intersection(self.trusted_signer_sha256):
            return replace(
                package,
                status=FirmwareTrustStatus.PACKAGE_VERIFIED,
                source_authentication="trusted_package_signer",
                code="firmware_package_signature_trusted",
                confirmation_required=False,
            )
        return replace(
            package,
            status=FirmwareTrustStatus.CONFIRMATION_REQUIRED,
            source_authentication="none",
            code=(
                "firmware_package_signer_unrecognized"
                if package.package_signature is PackageSignatureStatus.VERIFIED
                else "firmware_package_unsigned"
            ),
            confirmation_required=True,
        )

    def _verify_ota(
        self,
        path: str | os.PathLike[str],
        *,
        cancellation: object | None,
    ) -> FirmwareTrustEvidence:
        candidate = Path(path)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(candidate, flags)
        descriptor_open = True
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode):
                return self._rejected("firmware_signature_source_invalid")
            stream = os.fdopen(descriptor, "rb")
            descriptor_open = False
            with stream:
                if details.st_size < _FOOTER_SIZE:
                    return self._unsigned()
                stream.seek(-_FOOTER_SIZE, os.SEEK_END)
                footer = stream.read(_FOOTER_SIZE)
                if len(footer) != _FOOTER_SIZE or footer[2:4] != b"\xff\xff":
                    return self._unsigned()
                signature_start = int.from_bytes(footer[0:2], "little")
                comment_size = int.from_bytes(footer[4:6], "little")
                if (
                    signature_start <= _FOOTER_SIZE
                    or signature_start > comment_size
                    or details.st_size < comment_size + _EOCD_HEADER_SIZE
                ):
                    return self._rejected("firmware_signature_footer_invalid")
                eocd_offset = details.st_size - comment_size - _EOCD_HEADER_SIZE
                stream.seek(eocd_offset)
                eocd = stream.read(comment_size + _EOCD_HEADER_SIZE)
                if (
                    len(eocd) != comment_size + _EOCD_HEADER_SIZE
                    or eocd[:4] != _EOCD
                    or _EOCD in eocd[4:]
                ):
                    return self._rejected("firmware_signature_eocd_invalid")
                cms_size = signature_start - _FOOTER_SIZE
                cms_offset = details.st_size - signature_start
                stream.seek(cms_offset)
                cms = stream.read(cms_size)
                if len(cms) != cms_size:
                    return self._rejected("firmware_signature_block_truncated")
                signed_length = eocd_offset + _EOCD_HEADER_SIZE - 2
                stream.seek(0)
                try:
                    signers = verify_detached_cms_stream(
                        cms,
                        stream,
                        signed_length,
                        chunk_size=self.io_chunk_size,
                        cancellation=cancellation,  # type: ignore[arg-type]
                    )
                except CmsVerificationError as error:
                    if error.code is CmsVerificationCode.CANCELLED:
                        raise
                    return self._rejected(error.code.value)
                after = os.fstat(stream.fileno())
                if (
                    after.st_size != details.st_size
                    or after.st_mtime_ns != details.st_mtime_ns
                    or getattr(after, "st_ino", 0) != getattr(details, "st_ino", 0)
                ):
                    return self._rejected("firmware_signature_source_changed")
                return FirmwareTrustEvidence(
                    FirmwareTrustStatus.CONFIRMATION_REQUIRED,
                    PackageSignatureStatus.VERIFIED,
                    "none",
                    "firmware_package_signer_unrecognized",
                    signers,
                    confirmation_required=True,
                )
        except OSError:
            return self._rejected("firmware_signature_read_failed")
        finally:
            if descriptor_open:
                os.close(descriptor)

    @staticmethod
    def _unsigned() -> FirmwareTrustEvidence:
        return FirmwareTrustEvidence(
            FirmwareTrustStatus.CONFIRMATION_REQUIRED,
            PackageSignatureStatus.UNSIGNED,
            "none",
            "firmware_package_unsigned",
            confirmation_required=True,
        )

    @staticmethod
    def _rejected(code: str) -> FirmwareTrustEvidence:
        return FirmwareTrustEvidence(
            FirmwareTrustStatus.REJECTED,
            PackageSignatureStatus.INVALID,
            "none",
            code,
        )
