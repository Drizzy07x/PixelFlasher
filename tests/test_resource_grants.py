import io
import os
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pixelflasher_core.grants as grant_module
from pixelflasher_core.contracts import is_valid_target_serial
from pixelflasher_core.grants import (
    AtomicWriteOutcomeUnknownError,
    BoundWriteTransaction,
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
    def test_invalid_picker_resources_fail_with_closed_grant_errors(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            store = PathGrantStore()

            with self.assertRaises(GrantError) as missing_read:
                store.issue_file(root / "missing.bin", purpose="partition.source")
            self.assertEqual("grant_resource_invalid", missing_read.exception.code)

            with self.assertRaises(GrantError) as missing_parent:
                store.issue_file(
                    root / "missing" / "partition.img",
                    purpose="partition.destination",
                    access=GrantAccess.WRITE,
                )
            self.assertEqual("grant_parent_invalid", missing_parent.exception.code)

            with self.assertRaises(GrantError) as directory_destination:
                store.issue_file(
                    root,
                    purpose="partition.destination",
                    access=GrantAccess.WRITE,
                )
            self.assertEqual(
                "grant_target_mismatch",
                directory_destination.exception.code,
            )

    def test_target_serial_validation_covers_scoped_ipv6_and_port_bounds(self):
        self.assertTrue(is_valid_target_serial("SERIAL-123"))
        self.assertTrue(is_valid_target_serial("[2001:db8::1]:5555"))
        self.assertTrue(is_valid_target_serial("[fe80::1%wlan0]:5555"))
        self.assertTrue(is_valid_target_serial("[fe80::1%12]:5555"))
        self.assertFalse(is_valid_target_serial("[fe80::1%bad zone]:5555"))
        self.assertFalse(is_valid_target_serial("[2001:db8::1]:0"))
        self.assertFalse(is_valid_target_serial("[2001:db8::1]:65536"))
        self.assertFalse(is_valid_target_serial("[::::]:5555"))

    def test_read_grant_is_session_scoped_reusable_and_hides_path(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "firmware.zip"
            source.write_bytes(b"firmware")
            store = PathGrantStore()

            grant = store.issue_file(source, purpose="firmware.import")
            public = grant.to_public_dict()

            self.assertNotIn(str(source), repr(grant))
            self.assertNotIn("path", public)
            self.assertEqual(
                source.resolve(),
                store.resolve(
                    grant.token,
                    purpose="firmware.import",
                    target=GrantTarget.FILE,
                    access=GrantAccess.READ,
                ),
            )
            self.assertEqual(
                source.resolve(),
                store.resolve(
                    grant.token,
                    purpose="firmware.import",
                    target=GrantTarget.FILE,
                    access=GrantAccess.READ,
                ),
            )

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

    def test_bound_read_file_rejects_path_replacement_after_resolution(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "payload.bin"
            source.write_bytes(b"approved")
            store = PathGrantStore()
            grant = store.issue_file(source, purpose="tools.pushFiles.sources")
            bound = store.resolve_bound_file(
                grant.token,
                purpose="tools.pushFiles.sources",
            )

            replacement = root / "replacement.bin"
            replacement.write_bytes(b"unapproved")
            replacement.replace(source)

            with self.assertRaises(GrantError) as changed:
                bound.open_verified()
            self.assertEqual("grant_resource_changed", changed.exception.code)
            self.assertNotIn(str(source), repr(bound))

    def test_revoke_purpose_only_removes_superseded_picker_resources(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.bin"
            second = root / "second.bin"
            firmware = root / "firmware.zip"
            for path in (first, second, firmware):
                path.write_bytes(path.name.encode())
            store = PathGrantStore()
            push_grants = [store.issue_file(path, purpose="tools.pushFiles.sources") for path in (first, second)]
            firmware_grant = store.issue_file(firmware, purpose="firmware.select")

            self.assertEqual(2, store.revoke_purpose("tools.pushFiles.sources"))
            for grant in push_grants:
                with self.assertRaises(GrantError) as revoked:
                    store.resolve_bound_file(
                        grant.token,
                        purpose="tools.pushFiles.sources",
                    )
                self.assertEqual("grant_not_found", revoked.exception.code)
            self.assertEqual(
                firmware.resolve(),
                store.resolve(
                    firmware_grant.token,
                    purpose="firmware.select",
                    target=GrantTarget.FILE,
                    access=GrantAccess.READ,
                ),
            )

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

            self.assertEqual(
                destination.resolve(),
                store.resolve(
                    grant.token,
                    purpose="support.export",
                    target=GrantTarget.FILE,
                    access=GrantAccess.WRITE,
                ),
            )
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

    def test_atomic_write_transaction_replaces_new_and_existing_destinations(self):
        for existing in (False, True):
            with self.subTest(existing=existing), TemporaryDirectory() as directory:
                destination = Path(directory) / "logcat.txt"
                if existing:
                    destination.write_bytes(b"old contents")
                store = PathGrantStore()
                grant = store.issue_file(
                    destination,
                    purpose="tools.logcat.export",
                    access=GrantAccess.WRITE,
                )
                bound = store.resolve_bound_write_file(
                    grant.token,
                    purpose="tools.logcat.export",
                )

                with bound.begin_atomic_replace() as transaction:
                    transaction.stream.write(b"approved contents")
                    transaction.stream.flush()
                    os.fsync(transaction.stream.fileno())
                    transaction.commit()
                    with transaction.open_committed() as committed:
                        self.assertEqual(b"approved contents", committed.read())

                self.assertEqual(b"approved contents", destination.read_bytes())
                self.assertEqual([], list(Path(directory).glob(".pixelflasher-*")))

    def test_atomic_write_uses_approved_directory_handle_after_path_swap(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            approved_path = root / "selected"
            approved_path.mkdir()
            destination = approved_path / "logcat.txt"
            moved_approved_directory = root / "approved-object"
            store = PathGrantStore()
            grant = store.issue_file(
                destination,
                purpose="tools.logcat.export",
                access=GrantAccess.WRITE,
            )
            bound = store.resolve_bound_write_file(
                grant.token,
                purpose="tools.logcat.export",
            )
            real_open = grant_module._open_bound_write_anchor

            def swap_path_after_anchor(resource):
                anchor = real_open(resource)
                approved_path.rename(moved_approved_directory)
                approved_path.mkdir()
                (approved_path / "attacker-marker.txt").write_text("unapproved", encoding="utf-8")
                return anchor

            with patch(
                "pixelflasher_core.grants._open_bound_write_anchor",
                side_effect=swap_path_after_anchor,
            ):
                with bound.begin_atomic_replace() as transaction:
                    transaction.stream.write(b"raw token=secret-value")
                    transaction.stream.flush()
                    os.fsync(transaction.stream.fileno())
                    transaction.commit()
                    with transaction.open_committed() as committed:
                        self.assertEqual(b"raw token=secret-value", committed.read())

            self.assertEqual(
                b"raw token=secret-value",
                (moved_approved_directory / "logcat.txt").read_bytes(),
            )
            self.assertFalse((approved_path / "logcat.txt").exists())
            self.assertEqual(
                ["attacker-marker.txt"],
                sorted(path.name for path in approved_path.iterdir()),
            )

    def test_atomic_write_rejects_destination_replacement_before_commit(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "logcat.txt"
            destination.write_bytes(b"approved old contents")
            store = PathGrantStore()
            grant = store.issue_file(
                destination,
                purpose="tools.logcat.export",
                access=GrantAccess.WRITE,
            )
            bound = store.resolve_bound_write_file(
                grant.token,
                purpose="tools.logcat.export",
            )

            with bound.begin_atomic_replace() as transaction:
                replacement = root / "replacement.txt"
                replacement.write_bytes(b"attacker contents")
                replacement.replace(destination)
                transaction.stream.write(b"new approved contents")
                transaction.stream.flush()
                os.fsync(transaction.stream.fileno())
                with self.assertRaises(GrantError) as changed:
                    transaction.commit()

            self.assertEqual("grant_resource_changed", changed.exception.code)
            self.assertEqual(b"attacker contents", destination.read_bytes())
            self.assertEqual([], list(root.glob(".pixelflasher-*")))

    @unittest.skipUnless(os.name == "nt", "Windows handle identity contract")
    def test_windows_file_id_info_matches_python_stat_identity(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.txt"
            target.write_bytes(b"identity")
            api = grant_module._win32_api()
            directory_handle = api.open_directory(root)
            try:
                root_stat = root.stat()
                self.assertEqual(
                    (int(root_stat.st_dev), int(root_stat.st_ino), stat.S_IFMT(root_stat.st_mode)),
                    api.identity(directory_handle),
                )
                target_stat = target.stat()
                self.assertEqual(
                    (int(target_stat.st_dev), int(target_stat.st_ino), stat.S_IFMT(target_stat.st_mode)),
                    api.relative_identity(directory_handle, target.name),
                )
            finally:
                api.close_handle(directory_handle)

    def test_transaction_cleanup_does_not_mask_primary_outcome_unknown(self):
        class CleanupFailureBackend:
            stream = io.BytesIO()
            committed = False

            def commit(self):
                raise AssertionError("not used")

            def open_committed(self):
                raise AssertionError("not used")

            def close(self):
                raise RuntimeError("cleanup failed")

        primary = AtomicWriteOutcomeUnknownError("primary publication outcome is unknown")
        with self.assertRaises(AtomicWriteOutcomeUnknownError) as raised:
            with BoundWriteTransaction(CleanupFailureBackend()):
                raise primary
        self.assertIs(primary, raised.exception)

    @unittest.skipIf(os.name == "nt", "POSIX descriptor cleanup contract")
    def test_posix_cleanup_closes_every_descriptor_when_unlink_fails(self):
        with TemporaryDirectory() as directory:
            destination = Path(directory) / "logcat.txt"
            store = PathGrantStore()
            grant = store.issue_file(
                destination,
                purpose="tools.logcat.export",
                access=GrantAccess.WRITE,
            )
            bound = store.resolve_bound_write_file(
                grant.token,
                purpose="tools.logcat.export",
            )
            transaction = bound.begin_atomic_replace()
            backend = transaction._backend
            directory_fd = backend._directory_fd
            staging_fd = backend._staging_fd

            with patch("pixelflasher_core.grants.os.unlink", side_effect=PermissionError("denied")):
                with self.assertRaises(PermissionError):
                    transaction.close()

            for descriptor in (directory_fd, staging_fd):
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    @unittest.skipIf(os.name == "nt", "POSIX durability classification contract")
    def test_posix_directory_fsync_failure_after_publication_is_outcome_unknown(self):
        with TemporaryDirectory() as directory:
            destination = Path(directory) / "logcat.txt"
            store = PathGrantStore()
            grant = store.issue_file(
                destination,
                purpose="tools.logcat.export",
                access=GrantAccess.WRITE,
            )
            bound = store.resolve_bound_write_file(
                grant.token,
                purpose="tools.logcat.export",
            )

            with bound.begin_atomic_replace() as transaction:
                transaction.stream.write(b"durable payload")
                transaction.stream.flush()
                os.fsync(transaction.stream.fileno())
                directory_fd = transaction._backend._directory_fd
                real_fsync = os.fsync

                def fail_anchor_sync(descriptor):
                    if descriptor == directory_fd:
                        raise OSError("directory fsync failed")
                    return real_fsync(descriptor)

                with patch("pixelflasher_core.grants.os.fsync", side_effect=fail_anchor_sync):
                    with self.assertRaises(AtomicWriteOutcomeUnknownError) as raised:
                        transaction.commit()

            self.assertEqual("outcome_unknown", raised.exception.code)
            self.assertEqual(b"durable payload", destination.read_bytes())

    @unittest.skipIf(os.name == "nt", "POSIX exchange rollback contract")
    def test_posix_displaced_mismatch_rolls_back_without_deleting_foreign_inode(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "logcat.txt"
            destination.write_bytes(b"approved old contents")
            replacement = root / "replacement.txt"
            replacement.write_bytes(b"foreign contents")
            store = PathGrantStore()
            grant = store.issue_file(
                destination,
                purpose="tools.logcat.export",
                access=GrantAccess.WRITE,
            )
            bound = store.resolve_bound_write_file(
                grant.token,
                purpose="tools.logcat.export",
            )
            real_exchange = grant_module._posix_exchange
            exchanges = 0

            def attack_then_exchange(source_fd, source_name, destination_fd, destination_name):
                nonlocal exchanges
                if exchanges == 0:
                    replacement.replace(destination)
                exchanges += 1
                return real_exchange(source_fd, source_name, destination_fd, destination_name)

            with self.assertRaises(AtomicWriteOutcomeUnknownError) as raised:
                with (
                    patch(
                        "pixelflasher_core.grants._posix_exchange",
                        side_effect=attack_then_exchange,
                    ),
                    bound.begin_atomic_replace() as transaction,
                ):
                    transaction.stream.write(b"new approved contents")
                    transaction.stream.flush()
                    os.fsync(transaction.stream.fileno())
                    transaction.commit()

            self.assertEqual("outcome_unknown", raised.exception.code)
            self.assertEqual(2, exchanges)
            self.assertEqual(b"foreign contents", destination.read_bytes())
            self.assertEqual([], list(root.glob(".pixelflasher-*")))

    @unittest.skipIf(os.name == "nt", "POSIX exchange preservation contract")
    def test_posix_failed_rollback_preserves_displaced_foreign_inode_in_staging(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "logcat.txt"
            destination.write_bytes(b"approved old contents")
            replacement = root / "replacement.txt"
            replacement.write_bytes(b"foreign contents")
            store = PathGrantStore()
            grant = store.issue_file(
                destination,
                purpose="tools.logcat.export",
                access=GrantAccess.WRITE,
            )
            bound = store.resolve_bound_write_file(
                grant.token,
                purpose="tools.logcat.export",
            )
            real_exchange = grant_module._posix_exchange
            exchanges = 0

            def block_rollback(source_fd, source_name, destination_fd, destination_name):
                nonlocal exchanges
                exchanges += 1
                if exchanges == 1:
                    replacement.replace(destination)
                    return real_exchange(source_fd, source_name, destination_fd, destination_name)
                raise OSError("rollback blocked")

            with self.assertRaises(AtomicWriteOutcomeUnknownError) as raised:
                with (
                    patch(
                        "pixelflasher_core.grants._posix_exchange",
                        side_effect=block_rollback,
                    ),
                    bound.begin_atomic_replace() as transaction,
                ):
                    transaction.stream.write(b"new approved contents")
                    transaction.stream.flush()
                    os.fsync(transaction.stream.fileno())
                    transaction.commit()

            self.assertEqual("outcome_unknown", raised.exception.code)
            staging_directories = list(root.glob(".pixelflasher-*.stage"))
            self.assertEqual(1, len(staging_directories))
            self.assertEqual(
                b"foreign contents",
                (staging_directories[0] / "payload").read_bytes(),
            )
            self.assertEqual(b"new approved contents", destination.read_bytes())

    @unittest.skipIf(os.name == "nt", "POSIX post-publication verification contract")
    def test_posix_open_committed_oserror_is_outcome_unknown(self):
        with TemporaryDirectory() as directory:
            destination = Path(directory) / "logcat.txt"
            store = PathGrantStore()
            grant = store.issue_file(
                destination,
                purpose="tools.logcat.export",
                access=GrantAccess.WRITE,
            )
            bound = store.resolve_bound_write_file(
                grant.token,
                purpose="tools.logcat.export",
            )

            with bound.begin_atomic_replace() as transaction:
                transaction.stream.write(b"published contents")
                transaction.stream.flush()
                os.fsync(transaction.stream.fileno())
                transaction.commit()
                with patch("pixelflasher_core.grants.os.open", side_effect=OSError("open failed")):
                    with self.assertRaises(AtomicWriteOutcomeUnknownError) as raised:
                        transaction.open_committed()

            self.assertEqual("outcome_unknown", raised.exception.code)
            self.assertEqual(b"published contents", destination.read_bytes())


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
