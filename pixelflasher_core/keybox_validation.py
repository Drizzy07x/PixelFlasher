"""Local, bounded Android keybox validation with authenticated revocation evidence."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO, Protocol, cast
from xml.etree import ElementTree

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed448,
    ed25519,
    padding,
    rsa,
)


class CancellationProbe(Protocol):
    @property
    def cancelled(self) -> bool: ...


class KeyboxStatus(StrEnum):
    VALID = "valid"
    UNVERIFIED = "unverified"
    REVOKED = "revoked"
    EXPIRED = "expired"
    SOFTWARE_ATTESTATION = "software_attestation"
    INVALID = "invalid"


class KeyboxAnalysisStatus(StrEnum):
    SUCCESS = "SUCCESS"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class KeyboxAnalysisCode(StrEnum):
    ANALYZED = "keybox_analyzed"
    CANCELLED = "keybox_analysis_cancelled"
    SOURCE_INVALID = "keybox_source_invalid"


@dataclass(frozen=True, slots=True)
class KeyboxValidationLimits:
    maximum_file_bytes: int = 4 * 1024 * 1024
    maximum_xml_nodes: int = 10_000
    maximum_keyboxes: int = 16
    maximum_certificates_per_chain: int = 6
    maximum_pem_bytes: int = 128 * 1024
    io_chunk_size: int = 1024 * 1024

    def __post_init__(self) -> None:
        if any(
            value <= 0
            for value in (
                self.maximum_file_bytes,
                self.maximum_xml_nodes,
                self.maximum_keyboxes,
                self.maximum_certificates_per_chain,
                self.maximum_pem_bytes,
                self.io_chunk_size,
            )
        ):
            raise ValueError("keybox validation limits must be positive")


@dataclass(frozen=True, slots=True)
class KeyboxRevocationEvidence:
    source_id: str
    key_id: str
    issued_at: datetime
    expires_at: datetime
    revoked_serials: frozenset[str]


class KeyboxRevocationProvider(Protocol):
    def load(self, *, now: datetime) -> KeyboxRevocationEvidence | None: ...


class UnavailableKeyboxRevocationProvider:
    def load(self, *, now: datetime) -> KeyboxRevocationEvidence | None:
        del now
        return None


class KeyboxRevocationError(ValueError):
    pass


class SignedKeyboxRevocationProvider:
    """Read one exact, Ed25519-signed revocation snapshot from local storage."""

    _FIELDS = frozenset(
        {
            "schemaVersion",
            "sourceId",
            "keyId",
            "issuedAt",
            "expiresAt",
            "entries",
            "signature",
        }
    )

    def __init__(
        self,
        path: str | Path,
        keys: Mapping[str, ed25519.Ed25519PublicKey],
        *,
        maximum_bytes: int = 16 * 1024 * 1024,
        maximum_entries: int = 250_000,
    ) -> None:
        if maximum_bytes <= 0 or maximum_entries <= 0:
            raise ValueError("revocation snapshot limits must be positive")
        if not keys:
            raise ValueError("at least one pinned revocation key is required")
        self.path = Path(path)
        self.keys = dict(keys)
        self.maximum_bytes = maximum_bytes
        self.maximum_entries = maximum_entries

    def load(self, *, now: datetime) -> KeyboxRevocationEvidence:
        current = _aware_utc(now)
        try:
            raw = self.path.read_bytes()
        except OSError as error:
            raise KeyboxRevocationError("revocation snapshot is unavailable") from error
        if not raw or len(raw) > self.maximum_bytes:
            raise KeyboxRevocationError("revocation snapshot size is invalid")
        try:
            decoded: object = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise KeyboxRevocationError("revocation snapshot JSON is invalid") from error
        if not isinstance(decoded, dict):
            raise KeyboxRevocationError("revocation snapshot schema is invalid")
        document = cast(dict[str, object], decoded)
        if set(document) != self._FIELDS:
            raise KeyboxRevocationError("revocation snapshot schema is invalid")
        if document.get("schemaVersion") != 1:
            raise KeyboxRevocationError("revocation snapshot version is unsupported")
        source_id = document.get("sourceId")
        key_id = document.get("keyId")
        if (
            not isinstance(source_id, str)
            or not 1 <= len(source_id) <= 128
            or not source_id.isprintable()
            or not isinstance(key_id, str)
            or key_id not in self.keys
        ):
            raise KeyboxRevocationError("revocation snapshot identity is invalid")
        issued_at = _parse_timestamp(document.get("issuedAt"))
        expires_at = _parse_timestamp(document.get("expiresAt"))
        if (
            expires_at <= issued_at
            or expires_at - issued_at > timedelta(days=31)
            or issued_at > current + timedelta(minutes=5)
            or current >= expires_at
        ):
            raise KeyboxRevocationError("revocation snapshot validity window is invalid")
        entries_value = document.get("entries")
        if not isinstance(entries_value, list):
            raise KeyboxRevocationError("revocation snapshot entries are invalid")
        entries = cast(list[object], entries_value)
        if len(entries) > self.maximum_entries:
            raise KeyboxRevocationError("revocation snapshot entries are invalid")
        normalized: list[str] = []
        for entry in entries:
            if not isinstance(entry, str) or not re.fullmatch(r"[0-9a-f]{1,40}", entry):
                raise KeyboxRevocationError("revocation snapshot serial is invalid")
            normalized.append(entry.lstrip("0") or "0")
        if len(normalized) != len(set(normalized)):
            raise KeyboxRevocationError("revocation snapshot repeats a serial")
        signature_text = document.get("signature")
        if not isinstance(signature_text, str):
            raise KeyboxRevocationError("revocation snapshot signature is invalid")
        try:
            signature = base64.b64decode(signature_text, validate=True)
        except ValueError as error:
            raise KeyboxRevocationError("revocation snapshot signature is invalid") from error
        signed: dict[str, object] = dict(document)
        signed.pop("signature")
        canonical = json.dumps(
            signed,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        try:
            self.keys[key_id].verify(signature, canonical)
        except Exception as error:
            raise KeyboxRevocationError("revocation snapshot signature is invalid") from error
        return KeyboxRevocationEvidence(
            source_id,
            key_id,
            issued_at,
            expires_at,
            frozenset(normalized),
        )


@dataclass(frozen=True, slots=True)
class KeyboxFileReport:
    display_name: str
    sha256: str
    size_bytes: int
    status: KeyboxStatus
    structure_valid: bool
    cryptographic_valid: bool
    keybox_count: int
    algorithms: tuple[str, ...]
    certificate_count: int
    expired: bool
    expiring_soon: bool
    software_attestation: bool
    revocation_status: str
    issues: tuple[str, ...]

    def to_public_dict(self) -> dict[str, object]:
        return {
            "displayName": self.display_name,
            "sha256": self.sha256,
            "sizeBytes": self.size_bytes,
            "status": self.status.value,
            "structureValid": self.structure_valid,
            "cryptographicValid": self.cryptographic_valid,
            "keyboxCount": self.keybox_count,
            "algorithms": list(self.algorithms),
            "certificateCount": self.certificate_count,
            "expired": self.expired,
            "expiringSoon": self.expiring_soon,
            "softwareAttestation": self.software_attestation,
            "revocationStatus": self.revocation_status,
            "issues": list(self.issues),
        }


@dataclass(frozen=True, slots=True)
class KeyboxAnalysisResult:
    status: KeyboxAnalysisStatus
    code: KeyboxAnalysisCode
    message: str
    report: KeyboxFileReport | None = None

    @property
    def ok(self) -> bool:
        return self.status is KeyboxAnalysisStatus.SUCCESS and self.report is not None


class _Cancelled(Exception):
    pass


class _InvalidKeybox(Exception):
    def __init__(self, issue: str) -> None:
        super().__init__(issue)
        self.issue = issue


class KeyboxValidationService:
    def __init__(
        self,
        revocation_provider: KeyboxRevocationProvider | None = None,
        limits: KeyboxValidationLimits | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.revocation_provider = (
            revocation_provider or UnavailableKeyboxRevocationProvider()
        )
        self.limits = limits or KeyboxValidationLimits()
        self._clock = clock or (lambda: datetime.now(UTC))

    def revocation_evidence(self) -> tuple[KeyboxRevocationEvidence | None, str]:
        try:
            evidence = self.revocation_provider.load(now=_aware_utc(self._clock()))
        except (KeyboxRevocationError, OSError, ValueError):
            return None, "revocation_evidence_invalid"
        return (
            (evidence, "")
            if evidence is not None
            else (None, "revocation_evidence_unavailable")
        )

    def analyze(
        self,
        display_name: str,
        source: BinaryIO,
        *,
        evidence: KeyboxRevocationEvidence | None,
        revocation_issue: str = "",
        cancellation: CancellationProbe | None = None,
    ) -> KeyboxAnalysisResult:
        safe_name = _display_name(display_name)
        data = bytearray()
        digest = hashlib.sha256()
        try:
            while True:
                _check_cancelled(cancellation)
                chunk = source.read(self.limits.io_chunk_size)
                if not chunk:
                    break
                if not isinstance(chunk, bytes):
                    raise _InvalidKeybox("source_not_bytes")
                data.extend(chunk)
                if len(data) > self.limits.maximum_file_bytes:
                    raise _InvalidKeybox("file_too_large")
                digest.update(chunk)
            _check_cancelled(cancellation)
            report = self._analyze_bytes(
                safe_name,
                bytes(data),
                digest.hexdigest(),
                evidence,
                revocation_issue,
                cancellation,
            )
            return KeyboxAnalysisResult(
                KeyboxAnalysisStatus.SUCCESS,
                KeyboxAnalysisCode.ANALYZED,
                "keybox analysis completed",
                report,
            )
        except _Cancelled:
            return KeyboxAnalysisResult(
                KeyboxAnalysisStatus.CANCELLED,
                KeyboxAnalysisCode.CANCELLED,
                "keybox analysis was cancelled",
            )
        except _InvalidKeybox as error:
            report = KeyboxFileReport(
                safe_name,
                digest.hexdigest(),
                len(data),
                KeyboxStatus.INVALID,
                False,
                False,
                0,
                (),
                0,
                False,
                False,
                False,
                "unverified",
                (error.issue,),
            )
            return KeyboxAnalysisResult(
                KeyboxAnalysisStatus.SUCCESS,
                KeyboxAnalysisCode.ANALYZED,
                "keybox analysis completed with invalid input",
                report,
            )
        except Exception:
            return KeyboxAnalysisResult(
                KeyboxAnalysisStatus.FAILED,
                KeyboxAnalysisCode.SOURCE_INVALID,
                "keybox analysis failed",
            )

    def _analyze_bytes(
        self,
        display_name: str,
        data: bytes,
        digest: str,
        evidence: KeyboxRevocationEvidence | None,
        revocation_issue: str,
        cancellation: CancellationProbe | None,
    ) -> KeyboxFileReport:
        if not data or b"<!doctype" in data.lower() or b"<!entity" in data.lower():
            raise _InvalidKeybox("unsafe_or_empty_xml")
        try:
            root = ElementTree.fromstring(data)
        except ElementTree.ParseError as error:
            raise _InvalidKeybox("xml_parse_failed") from error
        nodes = tuple(root.iter())
        if len(nodes) > self.limits.maximum_xml_nodes:
            raise _InvalidKeybox("xml_node_limit_exceeded")
        if root.tag != "AndroidAttestation" or set(root.attrib):
            raise _InvalidKeybox("invalid_root")
        expected_node = root.find("NumberOfKeyboxes")
        keyboxes = root.findall("Keybox")
        if (
            expected_node is None
            or set(expected_node.attrib)
            or len(expected_node)
            or len(root) != 1 + len(keyboxes)
        ):
            raise _InvalidKeybox("invalid_keybox_structure")
        expected = _bounded_integer(
            expected_node.text if expected_node is not None else None,
            minimum=1,
            maximum=self.limits.maximum_keyboxes,
            issue="invalid_keybox_count",
        )
        if expected != len(keyboxes):
            raise _InvalidKeybox("keybox_count_mismatch")

        now = _aware_utc(self._clock())
        algorithms_seen: set[str] = set()
        certificate_count = 0
        expired = False
        expiring_soon = False
        software_attestation = False
        revoked = False
        for keybox in keyboxes:
            _check_cancelled(cancellation)
            device_id = keybox.attrib.get("DeviceID", "")
            if not device_id or len(device_id) > 256 or set(keybox.attrib) != {"DeviceID"}:
                raise _InvalidKeybox("invalid_device_id")
            keys = keybox.findall("Key")
            if len(keybox) != len(keys):
                raise _InvalidKeybox("invalid_keybox_children")
            algorithms = [item.attrib.get("algorithm", "").casefold() for item in keys]
            if sorted(algorithms) != ["ecdsa", "rsa"] or len(keys) != 2:
                raise _InvalidKeybox("missing_or_duplicate_algorithms")
            for key_element, algorithm in zip(keys, algorithms, strict=True):
                _check_cancelled(cancellation)
                if set(key_element.attrib) != {"algorithm"}:
                    raise _InvalidKeybox("invalid_key_attributes")
                private_node = key_element.find("PrivateKey")
                chain_node = key_element.find("CertificateChain")
                if (
                    private_node is None
                    or chain_node is None
                    or len(key_element) != 2
                    or set(private_node.attrib)
                    or len(private_node)
                ):
                    raise _InvalidKeybox("missing_private_key_or_chain")
                if set(chain_node.attrib):
                    raise _InvalidKeybox("invalid_chain_attributes")
                count_node = chain_node.find("NumberOfCertificates")
                certificate_nodes = chain_node.findall("Certificate")
                if (
                    count_node is None
                    or set(count_node.attrib)
                    or len(count_node)
                    or len(chain_node) != 1 + len(certificate_nodes)
                    or any(set(node.attrib) or len(node) for node in certificate_nodes)
                ):
                    raise _InvalidKeybox("invalid_certificate_structure")
                expected_certificates = _bounded_integer(
                    count_node.text if count_node is not None else None,
                    minimum=2,
                    maximum=self.limits.maximum_certificates_per_chain,
                    issue="invalid_certificate_count",
                )
                if expected_certificates != len(certificate_nodes):
                    raise _InvalidKeybox("certificate_count_mismatch")
                private_text = _bounded_pem(private_node.text, self.limits.maximum_pem_bytes)
                try:
                    private_key = serialization.load_pem_private_key(
                        private_text,
                        password=None,
                    )
                except Exception as error:
                    raise _InvalidKeybox("invalid_private_key") from error
                certificates: list[x509.Certificate] = []
                for certificate_node in certificate_nodes:
                    certificate_text = _bounded_pem(
                        certificate_node.text,
                        self.limits.maximum_pem_bytes,
                    )
                    try:
                        certificate = x509.load_pem_x509_certificate(certificate_text)
                    except Exception as error:
                        raise _InvalidKeybox("invalid_certificate") from error
                    certificates.append(certificate)
                    certificate_count += 1
                    if now < certificate.not_valid_before_utc or now >= certificate.not_valid_after_utc:
                        expired = True
                    elif certificate.not_valid_after_utc <= now + timedelta(days=30):
                        expiring_soon = True
                    names = f"{certificate.issuer.rfc4514_string()} {certificate.subject.rfc4514_string()}".casefold()
                    if "software attestation" in names:
                        software_attestation = True
                    serial = format(certificate.serial_number, "x").lstrip("0") or "0"
                    if evidence is not None and serial in evidence.revoked_serials:
                        revoked = True
                _validate_algorithm_key(algorithm, private_key, certificates[0])
                _validate_certificate_chain(certificates)
                algorithms_seen.add(algorithm)

        issues: list[str] = []
        if revocation_issue:
            issues.append(revocation_issue)
        if revoked:
            status = KeyboxStatus.REVOKED
            revocation_status = "revoked"
            issues.append("certificate_revoked")
        elif expired:
            status = KeyboxStatus.EXPIRED
            revocation_status = "clear" if evidence is not None else "unverified"
            issues.append("certificate_expired_or_not_yet_valid")
        elif software_attestation:
            status = KeyboxStatus.SOFTWARE_ATTESTATION
            revocation_status = "clear" if evidence is not None else "unverified"
            issues.append("software_attestation_detected")
        elif evidence is None:
            status = KeyboxStatus.UNVERIFIED
            revocation_status = "unverified"
        else:
            status = KeyboxStatus.VALID
            revocation_status = "clear"
        if expiring_soon:
            issues.append("certificate_expiring_soon")
        return KeyboxFileReport(
            display_name,
            digest,
            len(data),
            status,
            True,
            True,
            len(keyboxes),
            tuple(sorted(algorithms_seen)),
            certificate_count,
            expired,
            expiring_soon,
            software_attestation,
            revocation_status,
            tuple(issues),
        )


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC)


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise KeyboxRevocationError("revocation snapshot timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise KeyboxRevocationError("revocation snapshot timestamp is invalid") from error
    return _aware_utc(parsed)


def _display_name(value: str) -> str:
    name = Path(value).name
    if not name or name != value or not name.isprintable() or len(name) > 255:
        raise _InvalidKeybox("invalid_display_name")
    return name


def _bounded_integer(
    value: str | None,
    *,
    minimum: int,
    maximum: int,
    issue: str,
) -> int:
    if value is None or not re.fullmatch(r"[0-9]{1,6}", value.strip()):
        raise _InvalidKeybox(issue)
    number = int(value)
    if not minimum <= number <= maximum:
        raise _InvalidKeybox(issue)
    return number


def _bounded_pem(value: str | None, maximum_bytes: int) -> bytes:
    if value is None:
        raise _InvalidKeybox("missing_pem")
    try:
        encoded = value.strip().encode("ascii", errors="strict")
    except UnicodeError as error:
        raise _InvalidKeybox("invalid_pem_encoding") from error
    if not encoded or len(encoded) > maximum_bytes or b"\0" in encoded:
        raise _InvalidKeybox("invalid_pem_size")
    return encoded


def _validate_algorithm_key(
    algorithm: str,
    private_key: object,
    leaf: x509.Certificate,
) -> None:
    public_key = leaf.public_key()
    if algorithm == "rsa":
        if not isinstance(private_key, rsa.RSAPrivateKey) or not isinstance(
            public_key, rsa.RSAPublicKey
        ):
            raise _InvalidKeybox("algorithm_key_type_mismatch")
    elif algorithm == "ecdsa":
        if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
            public_key, ec.EllipticCurvePublicKey
        ):
            raise _InvalidKeybox("algorithm_key_type_mismatch")
    else:
        raise _InvalidKeybox("unsupported_algorithm")
    if isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        private_public_key = private_key.public_key()
    else:
        raise _InvalidKeybox("algorithm_key_type_mismatch")
    private_public = private_public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    certificate_public = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if private_public != certificate_public:
        raise _InvalidKeybox("private_key_mismatch")


def _validate_certificate_chain(certificates: list[x509.Certificate]) -> None:
    for current, issuer in zip(certificates, certificates[1:], strict=False):
        if current.issuer != issuer.subject:
            raise _InvalidKeybox("certificate_issuer_mismatch")
        _verify_certificate_signature(current, issuer.public_key())
    root = certificates[-1]
    if root.issuer != root.subject:
        raise _InvalidKeybox("root_not_self_issued")
    _verify_certificate_signature(root, root.public_key())


def _verify_certificate_signature(certificate: x509.Certificate, public_key: object) -> None:
    try:
        hash_algorithm = certificate.signature_hash_algorithm
        if isinstance(public_key, rsa.RSAPublicKey):
            if hash_algorithm is None:
                raise _InvalidKeybox("certificate_hash_algorithm_invalid")
            parameters = certificate.signature_algorithm_parameters
            rsa_padding = (
                parameters
                if isinstance(parameters, padding.AsymmetricPadding)
                else padding.PKCS1v15()
            )
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                rsa_padding,
                hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if hash_algorithm is None:
                raise _InvalidKeybox("certificate_hash_algorithm_invalid")
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(hash_algorithm),
            )
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
            )
        else:
            raise _InvalidKeybox("unsupported_certificate_key")
    except _InvalidKeybox:
        raise
    except Exception as error:
        raise _InvalidKeybox("certificate_signature_invalid") from error


def _check_cancelled(cancellation: CancellationProbe | None) -> None:
    if cancellation is not None and cancellation.cancelled:
        raise _Cancelled


__all__ = [
    "KeyboxAnalysisCode",
    "KeyboxAnalysisResult",
    "KeyboxAnalysisStatus",
    "KeyboxFileReport",
    "KeyboxRevocationError",
    "KeyboxRevocationEvidence",
    "KeyboxRevocationProvider",
    "KeyboxStatus",
    "KeyboxValidationLimits",
    "KeyboxValidationService",
    "SignedKeyboxRevocationProvider",
    "UnavailableKeyboxRevocationProvider",
]
