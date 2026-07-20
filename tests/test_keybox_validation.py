from __future__ import annotations

import base64
import json
import tempfile
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from pixelflasher_core import AppCommand, AppSnapshot, AppStateStore, PathGrantStore
from pixelflasher_core.keybox_validation import (
    KeyboxAnalysisStatus,
    KeyboxRevocationError,
    KeyboxRevocationEvidence,
    KeyboxStatus,
    KeyboxValidationLimits,
    KeyboxValidationService,
    SignedKeyboxRevocationProvider,
)
from tests.command_engine_factory import make_test_command_engine

NOW = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)


def _certificate(
    subject_key: object,
    issuer_key: object,
    *,
    subject: str,
    issuer: x509.Name,
    serial: int,
    ca: bool,
    not_before: datetime = NOW - timedelta(days=30),
    not_after: datetime = NOW + timedelta(days=365),
) -> x509.Certificate:
    subject_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    public_key = subject_key.public_key()  # type: ignore[attr-defined]
    return (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())  # type: ignore[arg-type]
    )


def _chain(algorithm: str, serial_base: int) -> tuple[object, tuple[x509.Certificate, ...]]:
    if algorithm == "rsa":
        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        root_key = ec.generate_private_key(ec.SECP256R1())
        leaf_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, f"Hardware {algorithm} Root")]
    )
    root = _certificate(
        root_key,
        root_key,
        subject=f"Hardware {algorithm} Root",
        issuer=root_name,
        serial=serial_base + 1,
        ca=True,
    )
    leaf = _certificate(
        leaf_key,
        root_key,
        subject=f"Hardware {algorithm} Leaf",
        issuer=root.subject,
        serial=serial_base,
        ca=False,
    )
    return leaf_key, (leaf, root)


def _pem_private(key: object) -> str:
    return key.private_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _pem_certificate(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _keybox_xml(
    *,
    mismatched_rsa_key: bool = False,
) -> tuple[bytes, list[int]]:
    rsa_key, rsa_certificates = _chain("rsa", 0xA001)
    ecdsa_key, ecdsa_certificates = _chain("ecdsa", 0xB001)
    if mismatched_rsa_key:
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def key_xml(algorithm: str, key: object, certificates: tuple[x509.Certificate, ...]) -> str:
        certs = "".join(
            f"<Certificate>{_pem_certificate(certificate)}</Certificate>"
            for certificate in certificates
        )
        return (
            f'<Key algorithm="{algorithm}">'
            f"<PrivateKey>{_pem_private(key)}</PrivateKey>"
            "<CertificateChain>"
            f"<NumberOfCertificates>{len(certificates)}</NumberOfCertificates>"
            f"{certs}</CertificateChain></Key>"
        )

    xml = (
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<AndroidAttestation><NumberOfKeyboxes>1</NumberOfKeyboxes>"
        '<Keybox DeviceID="PRIVATE-DEVICE-ID">'
        f"{key_xml('rsa', rsa_key, rsa_certificates)}"
        f"{key_xml('ecdsa', ecdsa_key, ecdsa_certificates)}"
        "</Keybox></AndroidAttestation>"
    ).encode()
    serials = [
        certificate.serial_number
        for certificate in (*rsa_certificates, *ecdsa_certificates)
    ]
    return xml, serials


def _evidence(serials: list[int] | None = None) -> KeyboxRevocationEvidence:
    return KeyboxRevocationEvidence(
        "test-revocations",
        "test-key",
        NOW - timedelta(hours=1),
        NOW + timedelta(days=1),
        frozenset(format(serial, "x") for serial in (serials or [])),
    )


def test_valid_requires_authenticated_revocation_evidence() -> None:
    payload, _serials = _keybox_xml()
    service = KeyboxValidationService(clock=lambda: NOW)

    without_evidence = service.analyze(
        "keybox.xml",
        BytesIO(payload),
        evidence=None,
        revocation_issue="revocation_evidence_unavailable",
    )
    with_evidence = service.analyze(
        "keybox.xml",
        BytesIO(payload),
        evidence=_evidence(),
    )

    assert without_evidence.ok and without_evidence.report is not None
    assert without_evidence.report.status is KeyboxStatus.UNVERIFIED
    assert without_evidence.report.revocation_status == "unverified"
    assert with_evidence.ok and with_evidence.report is not None
    assert with_evidence.report.status is KeyboxStatus.VALID
    assert with_evidence.report.structure_valid
    assert with_evidence.report.cryptographic_valid
    assert with_evidence.report.algorithms == ("ecdsa", "rsa")
    assert with_evidence.report.certificate_count == 4
    assert "PRIVATE-DEVICE-ID" not in repr(with_evidence.report.to_public_dict())
    assert "PRIVATE KEY" not in repr(with_evidence.report.to_public_dict())


def test_revoked_certificate_and_key_mismatch_are_never_valid() -> None:
    payload, serials = _keybox_xml()
    revoked = KeyboxValidationService(clock=lambda: NOW).analyze(
        "keybox.xml",
        BytesIO(payload),
        evidence=_evidence([serials[0]]),
    )
    mismatch_payload, _ = _keybox_xml(mismatched_rsa_key=True)
    mismatch = KeyboxValidationService(clock=lambda: NOW).analyze(
        "keybox.xml",
        BytesIO(mismatch_payload),
        evidence=_evidence(),
    )

    assert revoked.report is not None
    assert revoked.report.status is KeyboxStatus.REVOKED
    assert revoked.report.revocation_status == "revoked"
    assert mismatch.report is not None
    assert mismatch.report.status is KeyboxStatus.INVALID
    assert "private_key_mismatch" in mismatch.report.issues


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"<!DOCTYPE x [<!ENTITY y 'secret'>]><AndroidAttestation>&y;</AndroidAttestation>",
        b"<not-keybox />",
        b"<AndroidAttestation><NumberOfKeyboxes>999</NumberOfKeyboxes></AndroidAttestation>",
    ],
)
def test_unsafe_or_malformed_xml_returns_a_typed_invalid_report(payload: bytes) -> None:
    result = KeyboxValidationService(clock=lambda: NOW).analyze(
        "keybox.xml",
        BytesIO(payload),
        evidence=_evidence(),
    )

    assert result.status is KeyboxAnalysisStatus.SUCCESS
    assert result.report is not None
    assert result.report.status is KeyboxStatus.INVALID
    assert not result.report.structure_valid


def test_size_limit_and_cancellation_fail_closed() -> None:
    limited = KeyboxValidationService(
        limits=KeyboxValidationLimits(maximum_file_bytes=8),
        clock=lambda: NOW,
    ).analyze("keybox.xml", BytesIO(b"x" * 9), evidence=_evidence())

    class Cancelled:
        cancelled = True

    cancelled = KeyboxValidationService(clock=lambda: NOW).analyze(
        "keybox.xml",
        BytesIO(b"anything"),
        evidence=_evidence(),
        cancellation=Cancelled(),
    )

    assert limited.report is not None
    assert limited.report.status is KeyboxStatus.INVALID
    assert limited.report.issues == ("file_too_large",)
    assert cancelled.status is KeyboxAnalysisStatus.CANCELLED


def _signed_manifest(
    private_key: ed25519.Ed25519PrivateKey,
    *,
    entries: list[str],
    expires_at: datetime = NOW + timedelta(days=1),
) -> bytes:
    document: dict[str, object] = {
        "schemaVersion": 1,
        "sourceId": "test-revocations",
        "keyId": "key-1",
        "issuedAt": (NOW - timedelta(hours=1)).isoformat(),
        "expiresAt": expires_at.isoformat(),
        "entries": entries,
    }
    canonical = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    document["signature"] = base64.b64encode(private_key.sign(canonical)).decode("ascii")
    return json.dumps(document).encode("utf-8")


def test_signed_revocation_provider_verifies_signature_window_and_serials(
    tmp_path: Path,
) -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    path = tmp_path / "revocations.json"
    path.write_bytes(_signed_manifest(private_key, entries=["a001", "b001"]))
    provider = SignedKeyboxRevocationProvider(
        path,
        {"key-1": private_key.public_key()},
    )

    evidence = provider.load(now=NOW)

    assert evidence.revoked_serials == frozenset({"a001", "b001"})
    path.write_bytes(path.read_bytes().replace(b"a001", b"a002"))
    with pytest.raises(KeyboxRevocationError):
        provider.load(now=NOW)


def test_expired_signed_revocation_snapshot_is_rejected(tmp_path: Path) -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    path = tmp_path / "expired.json"
    path.write_bytes(
        _signed_manifest(
            private_key,
            entries=[],
            expires_at=NOW - timedelta(seconds=1),
        )
    )
    provider = SignedKeyboxRevocationProvider(
        path,
        {"key-1": private_key.public_key()},
    )

    with pytest.raises(KeyboxRevocationError):
        provider.load(now=NOW)


def test_command_engine_analyzes_bound_files_without_exposing_host_paths() -> None:
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "attestation.xml"
        source.write_bytes(b"<not-keybox />")
        grants = PathGrantStore()
        issued = grants.issue_file(source, purpose="tools.keybox.sources")
        bound = grants.resolve_bound_file(issued.token, purpose="tools.keybox.sources")
        store = AppStateStore(AppSnapshot(revision=0))
        engine = make_test_command_engine(store=store)

        result = engine.execute(
            AppCommand(
                "tools.keybox",
                expected_revision=0,
                operation_id="keybox-command",
                payload={"action": "analyze", "sources": [bound]},
            )
        )

        assert result.ok
        assert result.code == "keybox_analyzed"
        assert result.value is not None
        assert result.value["count"] == 1
        assert result.value["summary"]["invalid"] == 1
        assert result.value["revocationEvidence"] is None
        assert str(source) not in repr(result.to_dict())
        completed = store.snapshot()
        assert completed.revision == 2
        assert completed.active_operation is None
        assert completed.last_result == result


def test_command_engine_rejects_raw_paths_and_target_serials() -> None:
    engine = make_test_command_engine()
    raw = engine.execute(
        AppCommand(
            "tools.keybox",
            expected_revision=0,
            payload={"action": "analyze", "sources": ["C:/private/keybox.xml"]},
        )
    )
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "attestation.xml"
        source.write_bytes(b"<not-keybox />")
        grants = PathGrantStore()
        issued = grants.issue_file(source, purpose="tools.keybox.sources")
        targeted = engine.execute(
            AppCommand(
                "tools.keybox",
                expected_revision=0,
                target_serial="SERIAL",
                payload={
                    "action": "analyze",
                    "sources": [
                        grants.resolve_bound_file(
                            issued.token, purpose="tools.keybox.sources"
                        )
                    ],
                },
            )
        )

    assert raw.code == "keybox_payload_invalid"
    assert targeted.code == "keybox_target_not_allowed"
