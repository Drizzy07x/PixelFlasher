import base64
import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    AppStateStore,
    OperationResult,
    PinnedEd25519Keyring,
    UpdateManifestVerifier,
    UpdateSequenceStore,
    UpdateService,
    UpdateStatus,
    version_is_newer,
)
from tests.command_engine_factory import make_test_command_engine
from ui.public_bridge import PublicProjectionError, project_operation_result

NOW = datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
PUBLIC_KEY = PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)


def signed_manifest(**overrides: object) -> bytes:
    payload: dict[str, object] = {
        "schemaVersion": 1,
        "keyId": "updates-2026",
        "sequence": 12,
        "version": "10.0.0-rc.1",
        "channel": "rc",
        "releaseUrl": "https://github.com/badabing2005/PixelFlasher/releases/tag/v10.0.0-rc.1",
        "publishedAt": "2026-07-20T11:00:00Z",
        "expiresAt": "2026-07-27T11:00:00Z",
    }
    payload.update(overrides)
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return json.dumps(
        {**payload, "signature": base64.b64encode(PRIVATE_KEY.sign(canonical)).decode("ascii")},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class Cancellation:
    def __init__(self, cancelled: bool = False) -> None:
        self.cancelled = cancelled


class Source:
    def __init__(self, document: bytes | BaseException) -> None:
        self.document = document
        self.calls = 0

    def load(self, _cancellation: Cancellation) -> bytes:
        self.calls += 1
        if isinstance(self.document, BaseException):
            raise self.document
        return self.document


class UpdateServiceTests(unittest.TestCase):
    def verifier(self) -> UpdateManifestVerifier:
        return UpdateManifestVerifier(
            PinnedEd25519Keyring({"updates-2026": PUBLIC_KEY}),
            clock=lambda: NOW,
        )

    def test_signed_manifest_reports_update_without_disclosing_release_url(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Source(signed_manifest())
            service = UpdateService(
                "9.2.2",
                source,
                self.verifier(),
                UpdateSequenceStore(Path(directory) / "state.json"),
            )
            result = service.check(Cancellation())

            self.assertEqual(UpdateStatus.SUCCESS, result.status)
            self.assertEqual("update_available", result.code)
            self.assertTrue(result.update_available)
            self.assertEqual("10.0.0-rc.1", result.latest_version)
            self.assertNotIn("http", json.dumps(result.to_public_dict()))
            state = json.loads((Path(directory) / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(12, state["highestSequence"])

    def test_current_version_prerelease_ordering_is_semver_compliant(self):
        self.assertTrue(version_is_newer("10.0.0", "10.0.0-rc.2"))
        self.assertTrue(version_is_newer("10.0.0-rc.10", "10.0.0-rc.2"))
        self.assertTrue(version_is_newer("10.0.0-rc.1", "10.0.0-dev"))
        self.assertFalse(version_is_newer("10.0.0-rc.1", "10.0.0"))
        self.assertFalse(version_is_newer("9.2.2", "9.2.2"))

    def test_signed_stable_manifest_reports_current_stable_release(self):
        with tempfile.TemporaryDirectory() as directory:
            result = UpdateService(
                "10.0.0",
                Source(
                    signed_manifest(
                        version="10.0.0",
                        channel="stable",
                        releaseUrl="https://github.com/badabing2005/PixelFlasher/releases/tag/v10.0.0",
                    )
                ),
                self.verifier(),
                UpdateSequenceStore(Path(directory) / "state.json"),
            ).check(Cancellation())

            self.assertEqual(UpdateStatus.SUCCESS, result.status)
            self.assertEqual("application_current", result.code)
            self.assertFalse(result.update_available)
            self.assertEqual("stable", result.channel)

    def test_expired_tampered_and_non_allowlisted_manifests_fail_closed(self):
        verifier = self.verifier()
        cases = [
            (signed_manifest(expiresAt="2026-07-20T11:59:59Z"), "update_manifest_expired"),
            (signed_manifest(releaseUrl="https://example.com/releases/v10"), "update_release_url_invalid"),
            (signed_manifest()[:-2] + b"x}", "update_manifest_json_invalid"),
        ]
        for document, code in cases:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                result = UpdateService(
                    "9.2.2",
                    Source(document),
                    verifier,
                    UpdateSequenceStore(Path(directory) / "state.json"),
                ).check(Cancellation())
                self.assertEqual(UpdateStatus.FAILED, result.status)
                self.assertEqual(code, result.code)

    def test_persistent_sequence_rejects_rollback_and_equivocation(self):
        with tempfile.TemporaryDirectory() as directory:
            store = UpdateSequenceStore(Path(directory) / "state.json")
            verifier = self.verifier()
            first = UpdateService("9.2.2", Source(signed_manifest(sequence=12)), verifier, store)
            self.assertTrue(first.check(Cancellation()).ok)
            rollback = UpdateService("9.2.2", Source(signed_manifest(sequence=11)), verifier, store)
            self.assertEqual("update_manifest_rollback", rollback.check(Cancellation()).code)
            equivocation = UpdateService(
                "9.2.2",
                Source(signed_manifest(sequence=12, version="10.0.0-rc.2")),
                verifier,
                store,
            )
            self.assertEqual("update_manifest_equivocation", equivocation.check(Cancellation()).code)

    def test_unavailable_offline_and_cancelled_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            state = UpdateSequenceStore(Path(directory) / "state.json")
            unavailable = UpdateService("9.2.2", None, None, state).check(Cancellation())
            self.assertEqual("update_manifest_unavailable", unavailable.code)
            offline = UpdateService("9.2.2", Source(TimeoutError()), self.verifier(), state).check(Cancellation())
            self.assertEqual("update_check_offline", offline.code)
            source = Source(signed_manifest())
            cancelled = UpdateService("9.2.2", source, self.verifier(), state).check(Cancellation(True))
            self.assertEqual(UpdateStatus.CANCELLED, cancelled.status)
            self.assertEqual(0, source.calls)

    def test_command_engine_and_public_projection_expose_only_closed_update_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            service = UpdateService(
                "9.2.2",
                Source(signed_manifest()),
                self.verifier(),
                UpdateSequenceStore(Path(directory) / "state.json"),
            )
            engine = make_test_command_engine(
                store=AppStateStore(AppSnapshot(revision=3)),
                update_service=service,
            )
            result = engine.execute(
                AppCommand("updates.check", expected_revision=3, operation_id="check-updates")
            )

            self.assertTrue(result.ok)
            projected = project_operation_result("updates.check", result)
            self.assertEqual("10.0.0-rc.1", projected["value"]["latestVersion"])
            self.assertNotIn("https://", json.dumps(projected))
            with self.assertRaises(PublicProjectionError):
                project_operation_result(
                    "updates.check",
                    OperationResult.success(
                        "hostile-update",
                        value={"releaseUrl": "https://example.com/private"},
                    ),
                )


if __name__ == "__main__":
    unittest.main()
