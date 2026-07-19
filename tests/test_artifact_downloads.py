from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pixelflasher_core.artifact_downloads import (
    ArtifactCancelledError,
    ArtifactDownloader,
    ArtifactDownloadPolicy,
    ArtifactIntegrityError,
    ArtifactManifestError,
    ArtifactManifestVerifier,
    ArtifactPolicyError,
    ArtifactSignatureError,
    ArtifactTransportError,
    PinnedEd25519Keyring,
    canonical_manifest_bytes,
)

NOW = datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC)
CURRENT_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
NEXT_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(33, 65)))


def public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def signed_manifest(
    content: bytes,
    *,
    private_key: Ed25519PrivateKey = CURRENT_PRIVATE_KEY,
    key_id: str = "release-2026",
    **overrides: object,
) -> bytes:
    fields: dict[str, object] = {
        "keyId": key_id,
        "version": "36.0.2",
        "platform": "windows",
        "arch": "x86_64",
        "license": "Apache-2.0",
        "provenance": "Google Android SDK Platform Tools",
        "url": "https://downloads.example.test/platform-tools.zip",
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
        "expiresAt": "2030-01-01T00:00:00Z",
    }
    fields.update(overrides)
    signature = private_key.sign(canonical_manifest_bytes(fields))
    return json.dumps(
        {**fields, "signature": base64.b64encode(signature).decode("ascii")},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class FakeResponse:
    def __init__(
        self,
        status_code: int,
        *,
        headers: Mapping[str, str] | None = None,
        events: list[bytes | BaseException] | None = None,
    ) -> None:
        self.status_code = status_code
        self.headers = dict(headers or {})
        self.events = list(events or [])
        self.closed = False

    def iter_content(self, chunk_size: int):
        del chunk_size
        for event in self.events:
            if isinstance(event, BaseException):
                raise event
            yield event

    def close(self) -> None:
        self.closed = True


class FakeSession:
    def __init__(self, *responses: FakeResponse | BaseException) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, dict[str, object]]] = []

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.calls.append((url, kwargs))
        if not self.responses:
            raise AssertionError("unexpected network request")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


def verifier(
    *,
    hosts: frozenset[str] = frozenset(
        {"downloads.example.test", "cdn.example.test"}
    ),
    maximum_bytes: int = 1024 * 1024,
    maximum_redirects: int = 5,
) -> ArtifactManifestVerifier:
    return ArtifactManifestVerifier(
        PinnedEd25519Keyring(
            {
                "release-2026": public_bytes(CURRENT_PRIVATE_KEY),
                "release-2027": public_bytes(NEXT_PRIVATE_KEY),
            }
        ),
        ArtifactDownloadPolicy(
            hosts,
            maximum_artifact_bytes=maximum_bytes,
            maximum_redirects=maximum_redirects,
            chunk_size=4,
        ),
        clock=lambda: NOW,
    )


class ArtifactManifestTests(unittest.TestCase):
    def test_canonical_signatures_support_pinned_key_rotation(self):
        current = signed_manifest(b"current")
        following = signed_manifest(
            b"following",
            private_key=NEXT_PRIVATE_KEY,
            key_id="release-2027",
        )
        manifest_verifier = verifier()

        self.assertEqual("release-2026", manifest_verifier.verify(current).key_id)
        self.assertEqual("release-2027", manifest_verifier.verify(following).key_id)
        self.assertEqual(
            frozenset({"release-2026", "release-2027"}),
            manifest_verifier.keyring.key_ids,
        )

        fields = json.loads(current)
        fields.pop("signature")
        self.assertEqual(
            canonical_manifest_bytes(fields),
            canonical_manifest_bytes(dict(reversed(list(fields.items())))),
        )

    def test_tampering_unknown_keys_and_invalid_base64_fail_closed(self):
        manifest_verifier = verifier()
        tampered = json.loads(signed_manifest(b"payload"))
        tampered["version"] = "evil"
        with self.assertRaisesRegex(ArtifactSignatureError, "signature is invalid"):
            manifest_verifier.verify(json.dumps(tampered))

        unknown = signed_manifest(
            b"payload",
            private_key=NEXT_PRIVATE_KEY,
            key_id="unknown-key",
        )
        with self.assertRaisesRegex(ArtifactSignatureError, "unknown signing key"):
            manifest_verifier.verify(unknown)

        invalid = json.loads(signed_manifest(b"payload"))
        invalid["signature"] = "not-base64!"
        with self.assertRaises(ArtifactSignatureError):
            manifest_verifier.verify(json.dumps(invalid))

    def test_expiry_platform_arch_size_and_url_policy_are_enforced(self):
        cases = (
            (
                signed_manifest(b"x", expiresAt="2020-01-01T00:00:00Z"),
                {},
                ArtifactManifestError,
                "manifest_expired",
            ),
            (
                signed_manifest(b"x"),
                {"expected_platform": "linux"},
                ArtifactPolicyError,
                "artifact_platform_mismatch",
            ),
            (
                signed_manifest(b"x"),
                {"expected_arch": "arm64"},
                ArtifactPolicyError,
                "artifact_arch_mismatch",
            ),
            (
                signed_manifest(b"x", url="http://downloads.example.test/file"),
                {},
                ArtifactPolicyError,
                "artifact_url_not_https",
            ),
            (
                signed_manifest(b"x", url="https://evil.example.test/file"),
                {},
                ArtifactPolicyError,
                "artifact_host_not_allowed",
            ),
            (
                signed_manifest(b"0123456789"),
                {},
                ArtifactPolicyError,
                "artifact_size_limit_exceeded",
            ),
        )
        for document, kwargs, error_type, code in cases:
            with self.subTest(code=code):
                active_verifier = verifier(maximum_bytes=5) if "size" in code else verifier()
                with self.assertRaises(error_type) as raised:
                    active_verifier.verify(document, **kwargs)
                self.assertEqual(code, raised.exception.code)

    def test_duplicate_fields_and_noncanonical_hashes_are_rejected(self):
        document = signed_manifest(b"payload").decode("utf-8")
        duplicate = document.replace(
            '"arch":"x86_64",',
            '"arch":"x86_64","arch":"arm64",',
        )
        with self.assertRaises(ArtifactManifestError) as raised:
            verifier().verify(duplicate)
        self.assertEqual("manifest_duplicate_field", raised.exception.code)

        uppercase = signed_manifest(
            b"payload",
            sha256=hashlib.sha256(b"payload").hexdigest().upper(),
        )
        with self.assertRaises(ArtifactManifestError) as raised:
            verifier().verify(uppercase)
        self.assertEqual("manifest_sha256_invalid", raised.exception.code)


class ArtifactDownloaderTests(unittest.TestCase):
    def test_cancellation_preserves_only_etag_bound_partial_and_never_replaces_target(self):
        content = b"cancel-safe-download"
        prefix = content[:8]
        remainder = content[len(prefix) :]
        session = FakeSession(
            FakeResponse(
                200,
                headers={"Content-Length": str(len(content)), "ETag": '"release"'},
                events=[prefix, remainder],
            ),
            FakeResponse(
                206,
                headers={
                    "Content-Length": str(len(remainder)),
                    "Content-Range": f"bytes {len(prefix)}-{len(content) - 1}/{len(content)}",
                    "ETag": '"release"',
                },
                events=[remainder],
            ),
        )
        checks = 0

        def cancelled() -> bool:
            nonlocal checks
            checks += 1
            return checks >= 7

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "tool.zip"
            destination.write_bytes(b"old")
            downloader = ArtifactDownloader(verifier(), session=session)

            with self.assertRaises(ArtifactCancelledError) as raised:
                downloader.download(
                    signed_manifest(content),
                    destination,
                    cancelled=cancelled,
                )

            self.assertEqual("artifact_download_cancelled", raised.exception.code)
            self.assertEqual(b"old", destination.read_bytes())
            self.assertEqual(1, len(list(Path(directory).glob(".*.part"))))

            result = downloader.download(
                signed_manifest(content),
                destination,
                cancelled=lambda: False,
            )
            self.assertTrue(result.resumed)
            self.assertEqual(content, destination.read_bytes())

    def test_cancellation_without_strong_etag_discards_partial(self):
        content = b"cancel-without-resume"
        checks = 0

        def cancelled() -> bool:
            nonlocal checks
            checks += 1
            return checks >= 7

        session = FakeSession(
            FakeResponse(
                200,
                headers={"Content-Length": str(len(content))},
                events=[content[:5], content[5:]],
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "tool.zip"
            with self.assertRaises(ArtifactCancelledError):
                ArtifactDownloader(verifier(), session=session).download(
                    signed_manifest(content),
                    destination,
                    cancelled=cancelled,
                )
            self.assertFalse(destination.exists())
            self.assertEqual([], list(Path(directory).glob(".*.part")))
            self.assertEqual([], list(Path(directory).glob(".*.resume.json")))

    def test_allowed_redirect_download_is_atomic_and_verified_cache_avoids_network(self):
        content = b"verified artifact"
        redirect = FakeResponse(
            302,
            headers={"Location": "https://cdn.example.test/releases/tool.zip"},
        )
        final = FakeResponse(
            200,
            headers={"Content-Length": str(len(content)), "ETag": '"release-1"'},
            events=[content[:5], content[5:]],
        )
        session = FakeSession(redirect, final)
        downloader = ArtifactDownloader(verifier(), session=session)

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "tool.zip"
            first = downloader.download(
                signed_manifest(content),
                destination,
                expected_platform="windows",
                expected_arch="x86_64",
            )
            second = downloader.download(signed_manifest(content), destination)

            self.assertEqual(content, destination.read_bytes())
            self.assertFalse(first.cache_hit)
            self.assertEqual(1, first.redirects)
            self.assertEqual("https://cdn.example.test/releases/tool.zip", first.final_url)
            self.assertTrue(second.cache_hit)
            self.assertEqual(2, len(session.calls))
            self.assertFalse(session.calls[0][1]["allow_redirects"])
            self.assertTrue(redirect.closed)
            self.assertTrue(final.closed)

    def test_redirect_host_and_redirect_limit_are_enforced(self):
        bad_session = FakeSession(
            FakeResponse(302, headers={"Location": "https://evil.example.test/tool"})
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ArtifactPolicyError) as raised:
                ArtifactDownloader(verifier(), session=bad_session).download(
                    signed_manifest(b"x"),
                    Path(directory) / "tool",
                )
            self.assertEqual("artifact_host_not_allowed", raised.exception.code)

        limited = FakeSession(
            FakeResponse(302, headers={"Location": "/one"}),
            FakeResponse(302, headers={"Location": "/two"}),
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ArtifactTransportError) as raised:
                ArtifactDownloader(
                    verifier(maximum_redirects=1),
                    session=limited,
                ).download(signed_manifest(b"x"), Path(directory) / "tool")
            self.assertEqual("artifact_redirect_limit_exceeded", raised.exception.code)

    def test_hash_and_stream_size_mismatches_never_replace_destination(self):
        expected = b"right"
        wrong_hash = FakeSession(
            FakeResponse(200, headers={"Content-Length": "5"}, events=[b"wrong"])
        )
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "tool"
            destination.write_bytes(b"old")
            with self.assertRaises(ArtifactIntegrityError) as raised:
                ArtifactDownloader(verifier(), session=wrong_hash).download(
                    signed_manifest(expected),
                    destination,
                )
            self.assertEqual("artifact_sha256_mismatch", raised.exception.code)
            self.assertEqual(b"old", destination.read_bytes())
            self.assertEqual([], list(Path(directory).glob(".*.part")))

        oversized = FakeSession(FakeResponse(200, events=[b"right", b"extra"]))
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "tool"
            with self.assertRaises(ArtifactIntegrityError) as raised:
                ArtifactDownloader(verifier(), session=oversized).download(
                    signed_manifest(expected),
                    destination,
                )
            self.assertEqual("artifact_size_mismatch", raised.exception.code)
            self.assertFalse(destination.exists())

    def test_interrupted_download_resumes_only_with_the_exact_strong_etag(self):
        content = b"abcdefghijklmnop"
        first_half = content[:7]
        remainder = content[7:]
        session = FakeSession(
            FakeResponse(
                200,
                headers={"Content-Length": str(len(content)), "ETag": '"same"'},
                events=[first_half, requests.ConnectionError("interrupted")],
            ),
            FakeResponse(
                206,
                headers={
                    "Content-Length": str(len(remainder)),
                    "Content-Range": f"bytes {len(first_half)}-{len(content) - 1}/{len(content)}",
                    "ETag": '"same"',
                },
                events=[remainder],
            ),
        )
        downloader = ArtifactDownloader(verifier(), session=session)

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "tool"
            with self.assertRaises(ArtifactTransportError):
                downloader.download(signed_manifest(content), destination)
            self.assertEqual(1, len(list(Path(directory).glob(".*.part"))))
            result = downloader.download(signed_manifest(content), destination)

            self.assertTrue(result.resumed)
            self.assertEqual(content, destination.read_bytes())
            resume_headers = session.calls[1][1]["headers"]
            self.assertEqual(f"bytes={len(first_half)}-", resume_headers["Range"])
            self.assertEqual('"same"', resume_headers["If-Range"])
            self.assertEqual([], list(Path(directory).glob(".*.resume.json")))

    def test_changed_etag_discards_partial_and_restarts_without_range(self):
        content = b"verified-download"
        prefix = content[:6]
        session = FakeSession(
            FakeResponse(
                200,
                headers={"Content-Length": str(len(content)), "ETag": '"old"'},
                events=[prefix, requests.ConnectionError("interrupted")],
            ),
            FakeResponse(
                206,
                headers={
                    "Content-Length": str(len(content) - len(prefix)),
                    "Content-Range": f"bytes {len(prefix)}-{len(content) - 1}/{len(content)}",
                    "ETag": '"new"',
                },
                events=[content[len(prefix) :]],
            ),
            FakeResponse(
                200,
                headers={"Content-Length": str(len(content)), "ETag": '"new"'},
                events=[content],
            ),
        )
        downloader = ArtifactDownloader(verifier(), session=session)

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "tool"
            with self.assertRaises(ArtifactTransportError):
                downloader.download(signed_manifest(content), destination)
            result = downloader.download(signed_manifest(content), destination)

            self.assertFalse(result.resumed)
            self.assertEqual(content, destination.read_bytes())
            self.assertIn("Range", session.calls[1][1]["headers"])
            self.assertNotIn("Range", session.calls[2][1]["headers"])

    def test_weak_etag_is_not_resumable_and_corrupt_cache_is_redownloaded(self):
        content = b"fresh artifact"
        session = FakeSession(
            FakeResponse(
                200,
                headers={"Content-Length": str(len(content)), "ETag": 'W/"weak"'},
                events=[content[:4], requests.ConnectionError("interrupted")],
            ),
            FakeResponse(
                200,
                headers={"Content-Length": str(len(content)), "ETag": '"strong"'},
                events=[content],
            ),
        )
        downloader = ArtifactDownloader(verifier(), session=session)

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "tool"
            with self.assertRaises(ArtifactTransportError):
                downloader.download(signed_manifest(content), destination)
            self.assertEqual([], list(Path(directory).glob(".*.part")))
            destination.write_bytes(b"x" * len(content))
            result = downloader.download(signed_manifest(content), destination)

            self.assertFalse(result.cache_hit)
            self.assertFalse(result.resumed)
            self.assertNotIn("Range", session.calls[1][1]["headers"])
            self.assertEqual(content, destination.read_bytes())


if __name__ == "__main__":
    unittest.main()
