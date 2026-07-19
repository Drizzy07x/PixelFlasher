import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pixelflasher_core.grants import (
    GrantAccess,
    GrantError,
    GrantTarget,
    PathGrantStore,
    SecretGrantStore,
)


class MutableClock:
    def __init__(self) -> None:
        self.value = 10.0

    def __call__(self) -> float:
        return self.value


class PathGrantStoreTests(unittest.TestCase):
    def test_read_grant_is_session_scoped_reusable_and_hides_path(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "firmware.zip"
            source.write_bytes(b"firmware")
            store = PathGrantStore()

            grant = store.issue_file(source, purpose="firmware.import")
            public = grant.to_public_dict()

            self.assertNotIn(str(source), repr(grant))
            self.assertNotIn("path", public)
            self.assertEqual(source.resolve(), store.resolve(
                grant.token,
                purpose="firmware.import",
                target=GrantTarget.FILE,
                access=GrantAccess.READ,
            ))
            self.assertEqual(source.resolve(), store.resolve(
                grant.token,
                purpose="firmware.import",
                target=GrantTarget.FILE,
                access=GrantAccess.READ,
            ))

    def test_grants_are_bound_to_purpose_scope_and_resource_identity(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "boot.img"
            source.write_bytes(b"boot")
            store = PathGrantStore()
            grant = store.issue_file(source, purpose="boot.import")

            with self.assertRaisesRegex(GrantError, "different purpose") as wrong_purpose:
                store.resolve(
                    grant.token,
                    purpose="firmware.import",
                    target=GrantTarget.FILE,
                    access=GrantAccess.READ,
                )
            self.assertEqual("grant_purpose_mismatch", wrong_purpose.exception.code)

            with self.assertRaises(GrantError) as wrong_scope:
                store.resolve(
                    grant.token,
                    purpose="boot.import",
                    target=GrantTarget.DIRECTORY,
                    access=GrantAccess.READ,
                )
            self.assertEqual("grant_scope_mismatch", wrong_scope.exception.code)

            source.unlink()
            source.mkdir()
            with self.assertRaises(GrantError) as replaced:
                store.resolve(
                    grant.token,
                    purpose="boot.import",
                    target=GrantTarget.FILE,
                    access=GrantAccess.READ,
                )
            self.assertEqual("grant_resource_changed", replaced.exception.code)

    def test_write_grant_is_ttl_bounded_and_consumed_before_use(self):
        clock = MutableClock()
        with TemporaryDirectory() as directory:
            destination = Path(directory) / "support.pfsupport"
            store = PathGrantStore(clock=clock, write_ttl_seconds=5)
            grant = store.issue_file(
                destination,
                purpose="support.export",
                access=GrantAccess.WRITE,
            )

            self.assertEqual(destination.resolve(), store.resolve(
                grant.token,
                purpose="support.export",
                target=GrantTarget.FILE,
                access=GrantAccess.WRITE,
            ))
            with self.assertRaises(GrantError) as replay:
                store.resolve(
                    grant.token,
                    purpose="support.export",
                    target=GrantTarget.FILE,
                    access=GrantAccess.WRITE,
                )
            self.assertEqual("grant_not_found", replay.exception.code)

            expired = store.issue_file(
                destination,
                purpose="support.export",
                access=GrantAccess.WRITE,
            )
            clock.value += 6
            with self.assertRaises(GrantError) as stale:
                store.resolve(
                    expired.token,
                    purpose="support.export",
                    target=GrantTarget.FILE,
                    access=GrantAccess.WRITE,
                )
            self.assertEqual("grant_expired", stale.exception.code)

    def test_write_grant_rejects_destination_created_or_removed_after_selection(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            store = PathGrantStore()

            new_destination = root / "new-support.zip"
            create_grant = store.issue_file(
                new_destination,
                purpose="support.export",
                access=GrantAccess.WRITE,
            )
            new_destination.write_bytes(b"appeared after selection")
            with self.assertRaises(GrantError) as appeared:
                store.resolve(
                    create_grant.token,
                    purpose="support.export",
                    target=GrantTarget.FILE,
                    access=GrantAccess.WRITE,
                )
            self.assertEqual("grant_resource_changed", appeared.exception.code)

            existing_destination = root / "existing-support.zip"
            existing_destination.write_bytes(b"selected")
            overwrite_grant = store.issue_file(
                existing_destination,
                purpose="support.export",
                access=GrantAccess.WRITE,
            )
            existing_destination.unlink()
            with self.assertRaises(GrantError) as removed:
                store.resolve(
                    overwrite_grant.token,
                    purpose="support.export",
                    target=GrantTarget.FILE,
                    access=GrantAccess.WRITE,
                )
            self.assertEqual("grant_resource_changed", removed.exception.code)


class SecretGrantStoreTests(unittest.TestCase):
    def test_secret_is_redacted_one_use_purpose_bound_and_ttl_bounded(self):
        clock = MutableClock()
        store = SecretGrantStore(clock=clock, ttl_seconds=2)
        grant = store.issue("123456", purpose="wifi.pair")

        self.assertNotIn("123456", repr(grant))
        with self.assertRaises(GrantError) as mismatch:
            store.consume(grant.token, purpose="apatch.superkey")
        self.assertEqual("grant_purpose_mismatch", mismatch.exception.code)
        with self.assertRaises(GrantError) as consumed_on_mismatch:
            store.consume(grant.token, purpose="wifi.pair")
        self.assertEqual("grant_not_found", consumed_on_mismatch.exception.code)

        valid = store.issue("abcdef", purpose="apatch.superkey")
        secret = store.consume(valid.token, purpose="apatch.superkey")
        self.assertEqual("SensitiveText([REDACTED])", repr(secret))
        self.assertEqual("abcdef", secret.reveal())
        with self.assertRaises(GrantError):
            store.consume(valid.token, purpose="apatch.superkey")

        expired = store.issue("expired", purpose="wifi.pair")
        clock.value += 3
        with self.assertRaises(GrantError) as stale:
            store.consume(expired.token, purpose="wifi.pair")
        self.assertEqual("grant_expired", stale.exception.code)


if __name__ == "__main__":
    unittest.main()
