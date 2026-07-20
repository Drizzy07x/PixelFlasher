"""Small, fail-closed detached CMS verifier shared by package inspectors.

Only DER SignedData with SHA-256/384/512 and one of the explicitly supported
RSA, ECDSA, or DSA signature algorithms is accepted.  The streaming entrypoint
keeps multi-gigabyte OTA packages out of Python memory.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, BinaryIO, Final, Protocol

if TYPE_CHECKING:
    from cryptography import x509
    from cryptography.hazmat.primitives.hashes import HashAlgorithm

__all__ = (
    "CmsVerificationCode",
    "CmsVerificationError",
    "verify_detached_cms",
    "verify_detached_cms_stream",
)


class CmsVerificationCode(StrEnum):
    STRUCTURE_INVALID = "cms_structure_invalid"
    SIGNATURE_UNSUPPORTED = "cms_signature_unsupported"
    SIGNATURE_INVALID = "cms_signature_invalid"
    CONTENT_DIGEST_MISMATCH = "cms_content_digest_mismatch"
    CRYPTOGRAPHY_UNAVAILABLE = "cms_cryptography_unavailable"
    CANCELLED = "cms_verification_cancelled"


class CmsVerificationError(RuntimeError):
    def __init__(self, code: CmsVerificationCode, message: str) -> None:
        super().__init__(message)
        self.code = code


class CancellationProbe(Protocol):
    @property
    def cancelled(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class _DerValue:
    tag: int
    encoded: bytes
    content: bytes


@dataclass(frozen=True, slots=True)
class _CmsDocument:
    certificates: tuple[x509.Certificate, ...]
    signers: tuple[_DerValue, ...]


_DIGEST_OIDS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "2.16.840.1.101.3.4.2.1": "sha256",
        "2.16.840.1.101.3.4.2.2": "sha384",
        "2.16.840.1.101.3.4.2.3": "sha512",
    }
)
_RSA_OIDS: Final[Mapping[str, str | None]] = MappingProxyType(
    {
        "1.2.840.113549.1.1.1": None,
        "1.2.840.113549.1.1.11": "sha256",
        "1.2.840.113549.1.1.12": "sha384",
        "1.2.840.113549.1.1.13": "sha512",
    }
)
_ECDSA_OIDS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "1.2.840.10045.4.3.2": "sha256",
        "1.2.840.10045.4.3.3": "sha384",
        "1.2.840.10045.4.3.4": "sha512",
    }
)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def verify_detached_cms(cms: bytes, content: bytes) -> tuple[str, ...]:
    """Verify a bounded in-memory detached CMS payload."""

    if not isinstance(cms, bytes) or not isinstance(content, bytes):
        raise TypeError("cms and content must be bytes")
    document = _parse_document(cms)
    algorithms = _signer_digest_names(document.signers)
    digests = {name: hashlib.new(name, content).digest() for name in algorithms}
    return _verify_document(document, content=content, digests=digests, prehashed=False)


def verify_detached_cms_stream(
    cms: bytes,
    stream: BinaryIO,
    signed_length: int,
    *,
    chunk_size: int = 1024 * 1024,
    cancellation: CancellationProbe | None = None,
) -> tuple[str, ...]:
    """Verify exactly ``signed_length`` bytes from the current stream offset."""

    if not isinstance(cms, bytes):
        raise TypeError("cms must be bytes")
    if isinstance(signed_length, bool) or not isinstance(signed_length, int) or signed_length < 0:
        raise ValueError("signed_length must be a non-negative integer")
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size <= 0:
        raise ValueError("chunk_size must be a positive integer")
    document = _parse_document(cms)
    algorithms = _signer_digest_names(document.signers)
    digesters = {name: hashlib.new(name) for name in algorithms}
    remaining = signed_length
    while remaining:
        _raise_if_cancelled(cancellation)
        chunk = stream.read(min(chunk_size, remaining))
        if not chunk:
            raise CmsVerificationError(
                CmsVerificationCode.STRUCTURE_INVALID,
                "signed content is truncated",
            )
        remaining -= len(chunk)
        for digester in digesters.values():
            digester.update(chunk)
    _raise_if_cancelled(cancellation)
    digests = {name: digester.digest() for name, digester in digesters.items()}
    return _verify_document(document, content=None, digests=digests, prehashed=True)


def _parse_document(cms: bytes) -> _CmsDocument:
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7
    except ImportError as error:
        raise CmsVerificationError(
            CmsVerificationCode.CRYPTOGRAPHY_UNAVAILABLE,
            "cryptography is required to verify CMS signatures",
        ) from error
    outer = _children(_single(cms, 0x30))
    if len(outer) != 2:
        raise _structure("CMS container is invalid")
    content_type, explicit_signed_data = outer
    if _oid(content_type) != "1.2.840.113549.1.7.2" or explicit_signed_data.tag != 0xA0:
        raise _structure("CMS container is not SignedData")
    fields = _children(_single(explicit_signed_data.content, 0x30))
    if len(fields) < 4 or fields[0].tag != 0x02 or fields[1].tag != 0x31 or fields[2].tag != 0x30:
        raise _structure("CMS SignedData is invalid")
    encap = _children(fields[2])
    if not encap or _oid(encap[0]) != "1.2.840.113549.1.7.1" or len(encap) != 1:
        raise _structure("CMS content must be detached data")
    certificates_field = next((field for field in fields[3:] if field.tag == 0xA0), None)
    signer_infos = next((field for field in reversed(fields[3:]) if field.tag == 0x31), None)
    if certificates_field is None or signer_infos is None:
        raise _structure("CMS signer data is missing")
    try:
        certificates = tuple(pkcs7.load_der_pkcs7_certificates(cms))
    except (TypeError, ValueError) as error:
        raise _structure("CMS certificates are invalid") from error
    signers = _children(signer_infos)
    if not certificates or len(certificates) > 64 or not signers or len(signers) > 32:
        raise _structure("CMS signer or certificate count is invalid")
    return _CmsDocument(certificates, signers)


def _signer_digest_names(signers: Sequence[_DerValue]) -> tuple[str, ...]:
    names: list[str] = []
    for signer in signers:
        fields = _children(signer)
        if signer.tag != 0x30 or len(fields) < 5:
            raise _structure("CMS signer is invalid")
        name = _DIGEST_OIDS.get(_algorithm_oid(fields[2]))
        if name is None:
            raise CmsVerificationError(
                CmsVerificationCode.SIGNATURE_UNSUPPORTED,
                "CMS uses a weak or unsupported digest",
            )
        names.append(name)
    return tuple(dict.fromkeys(names))


def _verify_document(
    document: _CmsDocument,
    *,
    content: bytes | None,
    digests: Mapping[str, bytes],
    prehashed: bool,
) -> tuple[str, ...]:
    verified: list[str] = []
    for signer in document.signers:
        certificate = _verify_signer(
            signer,
            document.certificates,
            content=content,
            digests=digests,
            prehashed=prehashed,
        )
        try:
            from cryptography.hazmat.primitives.serialization import Encoding

            encoded = certificate.public_bytes(Encoding.DER)
        except ImportError as error:
            raise CmsVerificationError(
                CmsVerificationCode.CRYPTOGRAPHY_UNAVAILABLE,
                "cryptography is required to verify CMS signatures",
            ) from error
        verified.append(hashlib.sha256(encoded).hexdigest())
    result = tuple(dict.fromkeys(verified))
    if not result or any(not _DIGEST.fullmatch(value) for value in result):
        raise _structure("CMS signer identity is invalid")
    return result


def _verify_signer(
    signer: _DerValue,
    certificates: Sequence[x509.Certificate],
    *,
    content: bytes | None,
    digests: Mapping[str, bytes],
    prehashed: bool,
) -> x509.Certificate:
    fields = _children(signer)
    if signer.tag != 0x30 or len(fields) < 5:
        raise _structure("CMS signer is truncated")
    _integer(fields[0])
    certificate = _certificate_for_sid(fields[1], certificates)
    digest_name = _DIGEST_OIDS.get(_algorithm_oid(fields[2]))
    if digest_name is None or digest_name not in digests:
        raise CmsVerificationError(
            CmsVerificationCode.SIGNATURE_UNSUPPORTED,
            "CMS uses a weak or unsupported digest",
        )
    index = 3
    attributes: _DerValue | None = None
    if fields[index].tag == 0xA0:
        attributes = fields[index]
        index += 1
    if index + 2 > len(fields) or fields[index + 1].tag != 0x04:
        raise _structure("CMS signature fields are missing")
    signature_oid = _algorithm_oid(fields[index])
    signature = fields[index + 1].content
    if attributes is not None:
        _verify_attributes(attributes, digests[digest_name])
        payload = bytes([0x31]) + attributes.encoded[1:]
        _verify_crypto(certificate, signature_oid, digest_name, signature, payload, False)
    elif prehashed:
        _verify_crypto(certificate, signature_oid, digest_name, signature, digests[digest_name], True)
    elif content is not None:
        _verify_crypto(certificate, signature_oid, digest_name, signature, content, False)
    else:  # pragma: no cover - guarded by the two public entrypoints
        raise _structure("CMS content is unavailable")
    return certificate


def _certificate_for_sid(
    sid: _DerValue,
    certificates: Sequence[x509.Certificate],
) -> x509.Certificate:
    if sid.tag == 0x30:
        parts = _children(sid)
        if len(parts) != 2:
            raise _structure("CMS signer identifier is invalid")
        serial = _integer(parts[1])
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
            raise CmsVerificationError(
                CmsVerificationCode.CRYPTOGRAPHY_UNAVAILABLE,
                "cryptography is required to verify CMS signatures",
            ) from error
        found: list[x509.Certificate] = []
        for certificate in certificates:
            try:
                extension = certificate.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_KEY_IDENTIFIER
                ).value
            except x509.ExtensionNotFound:
                continue
            if isinstance(extension, x509.SubjectKeyIdentifier) and hmac.compare_digest(
                extension.digest, sid.content
            ):
                found.append(certificate)
        matches = tuple(found)
    else:
        raise CmsVerificationError(
            CmsVerificationCode.SIGNATURE_UNSUPPORTED,
            "CMS signer identifier is unsupported",
        )
    if len(matches) != 1:
        raise CmsVerificationError(
            CmsVerificationCode.SIGNATURE_INVALID,
            "CMS signer certificate is missing or ambiguous",
        )
    return matches[0]


def _verify_attributes(attributes: _DerValue, content_digest: bytes) -> None:
    found: dict[str, _DerValue] = {}
    for attribute in _children(attributes):
        parts = _children(attribute)
        if attribute.tag != 0x30 or len(parts) != 2 or parts[1].tag != 0x31:
            raise _structure("CMS signed attribute is invalid")
        oid = _oid(parts[0])
        values = _children(parts[1])
        if len(values) != 1 or oid in found:
            raise _structure("CMS signed attribute is ambiguous")
        found[oid] = values[0]
    content_type = found.get("1.2.840.113549.1.9.3")
    message_digest = found.get("1.2.840.113549.1.9.4")
    if (
        content_type is None
        or _oid(content_type) != "1.2.840.113549.1.7.1"
        or message_digest is None
        or message_digest.tag != 0x04
    ):
        raise CmsVerificationError(
            CmsVerificationCode.SIGNATURE_INVALID,
            "CMS required signed attributes are missing",
        )
    if not hmac.compare_digest(message_digest.content, content_digest):
        raise CmsVerificationError(
            CmsVerificationCode.CONTENT_DIGEST_MISMATCH,
            "CMS signed content digest does not match",
        )


def _verify_crypto(
    certificate: x509.Certificate,
    signature_oid: str,
    digest_name: str,
    signature: bytes,
    payload: bytes,
    prehashed: bool,
) -> None:
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa, utils
    except ImportError as error:
        raise CmsVerificationError(
            CmsVerificationCode.CRYPTOGRAPHY_UNAVAILABLE,
            "cryptography is required to verify CMS signatures",
        ) from error
    algorithms: Mapping[str, type[HashAlgorithm]] = {
        "sha256": hashes.SHA256,
        "sha384": hashes.SHA384,
        "sha512": hashes.SHA512,
    }
    digest = algorithms[digest_name]()
    algorithm: Any = utils.Prehashed(digest) if prehashed else digest
    expected_rsa = _RSA_OIDS.get(signature_oid, "missing")
    expected_ec = _ECDSA_OIDS.get(signature_oid)
    try:
        public_key = certificate.public_key()
        if expected_rsa != "missing":
            if expected_rsa is not None and expected_rsa != digest_name:
                raise TypeError("RSA CMS digest algorithms disagree")
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise TypeError("RSA CMS signature requires an RSA key")
            public_key.verify(signature, payload, padding.PKCS1v15(), algorithm)
        elif expected_ec is not None:
            if expected_ec != digest_name or not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise TypeError("ECDSA CMS parameters disagree")
            public_key.verify(signature, payload, ec.ECDSA(algorithm))
        elif signature_oid == "2.16.840.1.101.3.4.3.2":
            if digest_name != "sha256" or not isinstance(public_key, dsa.DSAPublicKey):
                raise TypeError("DSA CMS parameters disagree")
            public_key.verify(signature, payload, algorithm)
        else:
            raise CmsVerificationError(
                CmsVerificationCode.SIGNATURE_UNSUPPORTED,
                "CMS signature algorithm is unsupported",
            )
    except InvalidSignature as error:
        raise CmsVerificationError(
            CmsVerificationCode.SIGNATURE_INVALID,
            "CMS signature is invalid",
        ) from error
    except UnsupportedAlgorithm as error:
        raise CmsVerificationError(
            CmsVerificationCode.SIGNATURE_UNSUPPORTED,
            "CMS signature algorithm is unavailable",
        ) from error
    except (AttributeError, TypeError, ValueError) as error:
        raise _structure("CMS signature key or parameters are invalid") from error


def _value(data: bytes, offset: int = 0) -> tuple[_DerValue, int]:
    if offset < 0 or offset + 2 > len(data):
        raise _structure("CMS value is truncated")
    start = offset
    tag = data[offset]
    offset += 1
    if tag & 0x1F == 0x1F:
        raise CmsVerificationError(
            CmsVerificationCode.SIGNATURE_UNSUPPORTED,
            "CMS high-tag values are unsupported",
        )
    first_length = data[offset]
    offset += 1
    if first_length == 0x80:
        raise CmsVerificationError(
            CmsVerificationCode.SIGNATURE_UNSUPPORTED,
            "indefinite CMS values are unsupported",
        )
    if first_length & 0x80:
        count = first_length & 0x7F
        if count == 0 or count > 4 or offset + count > len(data) or data[offset] == 0:
            raise _structure("CMS length is invalid")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
        if length < 128:
            raise _structure("CMS length is not DER-minimal")
    else:
        length = first_length
    end = offset + length
    if end > len(data):
        raise _structure("CMS value is truncated")
    return _DerValue(tag, data[start:end], data[offset:end]), end


def _children(value: _DerValue) -> tuple[_DerValue, ...]:
    values: list[_DerValue] = []
    offset = 0
    while offset < len(value.content):
        child, offset = _value(value.content, offset)
        values.append(child)
    return tuple(values)


def _single(data: bytes, expected_tag: int) -> _DerValue:
    value, end = _value(data)
    if end != len(data) or value.tag != expected_tag:
        raise _structure("CMS structure is invalid")
    return value


def _integer(value: _DerValue) -> int:
    if value.tag != 0x02 or not value.content or value.content[0] & 0x80:
        raise _structure("CMS integer is invalid")
    if len(value.content) > 1 and value.content[0] == 0 and not value.content[1] & 0x80:
        raise _structure("CMS integer is not minimal")
    return int.from_bytes(value.content, "big")


def _oid(value: _DerValue) -> str:
    if value.tag != 0x06 or not value.content:
        raise _structure("CMS object identifier is invalid")
    first = value.content[0]
    parts = [min(first // 40, 2), first - min(first // 40, 2) * 40]
    current = 0
    continuation = False
    for byte in value.content[1:]:
        if current == 0 and byte == 0x80:
            raise _structure("CMS object identifier is not minimal")
        current = (current << 7) | (byte & 0x7F)
        continuation = bool(byte & 0x80)
        if not continuation:
            parts.append(current)
            current = 0
    if continuation:
        raise _structure("CMS object identifier is truncated")
    return ".".join(str(part) for part in parts)


def _algorithm_oid(value: _DerValue) -> str:
    if value.tag != 0x30:
        raise _structure("CMS algorithm is invalid")
    children = _children(value)
    if not children or len(children) > 2:
        raise _structure("CMS algorithm parameters are invalid")
    return _oid(next(iter(children)))


def _structure(message: str) -> CmsVerificationError:
    return CmsVerificationError(CmsVerificationCode.STRUCTURE_INVALID, message)


def _raise_if_cancelled(cancellation: CancellationProbe | None) -> None:
    if cancellation is not None and cancellation.cancelled:
        raise CmsVerificationError(
            CmsVerificationCode.CANCELLED,
            "CMS verification was cancelled",
        )
