from __future__ import annotations

import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from pixelflasher_core.cancellation import CancellationToken
from pixelflasher_core.module_updates import (
    ModuleUpdateStatus,
    RootModuleUpdateService,
)
from pixelflasher_core.rooting import RootingPlanningError, RootingService, RootModuleInfo


class FakeResponse:
    def __init__(self, body: bytes = b"", *, status: int = 200, headers: dict[str, str] | None = None) -> None:
        self.body = body
        self.status_code = status
        self.headers = headers or {"Content-Length": str(len(body))}
        self.closed = False

    def iter_content(self, chunk_size: int):
        for offset in range(0, len(self.body), max(1, chunk_size)):
            yield self.body[offset : offset + chunk_size]

    def close(self) -> None:
        self.closed = True


class FakeSession:
    def __init__(self, responses: dict[str, list[FakeResponse]]) -> None:
        self.responses = {url: list(values) for url, values in responses.items()}
        self.calls: list[tuple[str, dict[str, object]]] = []

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.calls.append((url, kwargs))
        values = self.responses.get(url, [])
        if not values:
            raise AssertionError(f"unexpected URL: {url}")
        return values.pop(0)


def module_zip(module_id: str, *, version_code: int = 200) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "module.prop",
            f"id={module_id}\nname=Test module\nversion=2.0\nversionCode={version_code}\n",
        )
        archive.writestr("service.sh", "#!/system/bin/sh\n")
    return output.getvalue()


def metadata(zip_url: str, *, version_code: int = 200) -> bytes:
    return json.dumps(
        {
            "version": "2.0",
            "versionCode": version_code,
            "zipUrl": zip_url,
            "changelog": "https://updates.example.test/changelog.md",
        },
        separators=(",", ":"),
    ).encode()


def installed_module(module_id: str = "test_module") -> RootModuleInfo:
    return RootModuleInfo(
        module_id,
        "Test module",
        "1.0",
        100,
        "Test author",
        "Test description",
        "enabled",
        "https://updates.example.test/update.json",
    )


class RootModuleUpdateServiceTests(unittest.TestCase):
    def make_service(self, root: Path, session: FakeSession) -> RootModuleUpdateService:
        rooting = RootingService()
        return RootModuleUpdateService(
            root,
            rooting.inspect_module_zip,
            session=session,
            allowed_hosts=("example.test",),
            host_validator=lambda _host: True,
        )

    def test_prepares_identity_checked_opaque_artifact_without_public_url_or_path(self):
        update_url = "https://updates.example.test/update.json"
        zip_url = "https://downloads.example.test/module.zip"
        archive = module_zip("test_module")
        session = FakeSession(
            {
                update_url: [FakeResponse(metadata(zip_url))],
                zip_url: [FakeResponse(archive)],
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            service = self.make_service(Path(temporary), session)
            result = service.prepare(
                (installed_module(),),
                CancellationToken(),
                target_serial="SERIAL",
            )

            self.assertEqual(ModuleUpdateStatus.SUCCESS, result.status)
            self.assertEqual(1, len(result.entries))
            public = result.to_public_dict()
            serialized = json.dumps(public)
            self.assertNotIn("https://", serialized)
            self.assertNotIn(str(Path(temporary)), serialized)
            entry = result.entries[0]
            self.assertEqual("test_module", entry.module_id)
            self.assertEqual(200, entry.version_code)
            self.assertEqual("unverified-author", entry.trust)
            resolved = service.resolve(
                entry.artifact_id,
                entry.module_id,
                target_serial="SERIAL",
            )
            self.assertTrue(resolved.path.is_file())
            self.assertEqual(entry.sha256, resolved.path.stem)
            with self.assertRaisesRegex(RootingPlanningError, "again"):
                service.resolve(
                    entry.artifact_id,
                    entry.module_id,
                    target_serial="OTHER-SERIAL",
                )
            self.assertTrue(all(call[1].get("allow_redirects") is False for call in session.calls))

    def test_identity_mismatch_is_an_issue_and_never_becomes_resolvable(self):
        update_url = "https://updates.example.test/update.json"
        zip_url = "https://downloads.example.test/module.zip"
        session = FakeSession(
            {
                update_url: [FakeResponse(metadata(zip_url))],
                zip_url: [FakeResponse(module_zip("different_module"))],
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            service = self.make_service(Path(temporary), session)
            result = service.prepare(
                (installed_module(),),
                CancellationToken(),
                target_serial="SERIAL",
            )

            self.assertTrue(result.ok)
            self.assertFalse(result.entries)
            self.assertEqual("root_module_update_identity_mismatch", result.issues[0].code)
            with self.assertRaises(RootingPlanningError):
                service.resolve(
                    "a" * 32,
                    "test_module",
                    target_serial="SERIAL",
                )

    def test_untrusted_redirect_is_rejected_without_following_it(self):
        update_url = "https://updates.example.test/update.json"
        response = FakeResponse(status=302, headers={"Location": "https://127.0.0.1/private"})
        session = FakeSession({update_url: [response]})
        with tempfile.TemporaryDirectory() as temporary:
            result = self.make_service(Path(temporary), session).prepare(
                (installed_module(),),
                CancellationToken(),
                target_serial="SERIAL",
            )

        self.assertTrue(result.ok)
        self.assertEqual("root_module_update_url_untrusted", result.issues[0].code)
        self.assertEqual(1, len(session.calls))
        self.assertTrue(response.closed)

    def test_malformed_port_is_a_typed_issue(self):
        update_url = "https://updates.example.test:invalid/update.json"
        module = RootModuleInfo(
            "test_module",
            "Test module",
            "",
            100,
            "Test author",
            "Test description",
            "enabled",
            update_url,
        )
        with tempfile.TemporaryDirectory() as temporary:
            result = self.make_service(Path(temporary), FakeSession({})).prepare(
                (module,),
                CancellationToken(),
                target_serial="SERIAL",
            )

        self.assertTrue(result.ok)
        self.assertFalse(result.entries)
        self.assertEqual("root_module_update_url_invalid", result.issues[0].code)

    def test_downgrade_metadata_does_not_download_an_archive(self):
        update_url = "https://updates.example.test/update.json"
        zip_url = "https://downloads.example.test/module.zip"
        session = FakeSession({update_url: [FakeResponse(metadata(zip_url, version_code=99))]})
        with tempfile.TemporaryDirectory() as temporary:
            result = self.make_service(Path(temporary), session).prepare(
                (installed_module(),),
                CancellationToken(),
                target_serial="SERIAL",
            )

        self.assertTrue(result.ok)
        self.assertFalse(result.entries)
        self.assertEqual([update_url], [url for url, _kwargs in session.calls])

    def test_cancelled_check_never_promotes_artifacts(self):
        token = CancellationToken()
        token.cancel()
        with tempfile.TemporaryDirectory() as temporary:
            service = self.make_service(Path(temporary), FakeSession({}))
            result = service.prepare(
                (installed_module(),),
                token,
                target_serial="SERIAL",
            )

            self.assertEqual(ModuleUpdateStatus.CANCELLED, result.status)
            with self.assertRaises(RootingPlanningError):
                service.resolve(
                    "a" * 32,
                    "test_module",
                    target_serial="SERIAL",
                )

    def test_resolve_rejects_cache_tampering(self):
        update_url = "https://updates.example.test/update.json"
        zip_url = "https://downloads.example.test/module.zip"
        archive = module_zip("test_module")
        session = FakeSession(
            {
                update_url: [FakeResponse(metadata(zip_url))],
                zip_url: [FakeResponse(archive)],
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            service = self.make_service(Path(temporary), session)
            result = service.prepare(
                (installed_module(),),
                CancellationToken(),
                target_serial="SERIAL",
            )
            entry = result.entries[0]
            resolved = service.resolve(
                entry.artifact_id,
                entry.module_id,
                target_serial="SERIAL",
            )
            resolved.path.write_bytes(b"tampered")

            with self.assertRaisesRegex(RootingPlanningError, "changed"):
                service.resolve(
                    entry.artifact_id,
                    entry.module_id,
                    target_serial="SERIAL",
                )


if __name__ == "__main__":
    unittest.main()
