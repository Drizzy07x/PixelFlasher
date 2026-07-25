from __future__ import annotations

import ctypes
import errno
import io
import stat
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

import pixelflasher_core.grants as grants
from pixelflasher_core.grants import (
    AtomicWriteOutcomeUnknownError,
    BoundReadFile,
    BoundWriteFile,
    BoundWriteTransaction,
    GrantAccess,
    GrantError,
    GrantTarget,
    PathGrantStore,
    SecretGrantStore,
    _PosixAtomicWrite,
    _PosixWriteAnchor,
)

REGULAR_A = (1, 10, stat.S_IFREG)
REGULAR_B = (1, 11, stat.S_IFREG)
REGULAR_C = (1, 12, stat.S_IFREG)
DIRECTORY = (1, 20, stat.S_IFDIR)


class FakeStream(io.BytesIO):
    def __init__(self, descriptor: int = 30, *, fail_close: bool = False) -> None:
        super().__init__()
        self.descriptor = descriptor
        self.fail_close = fail_close

    def fileno(self) -> int:
        return self.descriptor

    def close(self) -> None:
        super().close()
        if self.fail_close:
            raise OSError("stream close failed")


def atomic_backend(
    *,
    target_identity: tuple[int, int, int] | None = None,
    stream: FakeStream | None = None,
) -> _PosixAtomicWrite:
    return _PosixAtomicWrite(
        directory_fd=40,
        staging_fd=41,
        staging_name=".pixelflasher-stage",
        staging_identity=DIRECTORY,
        leaf_name="output.img",
        target_identity=target_identity,
        temporary_name="payload",
        temporary_identity=REGULAR_A,
        stream=stream or FakeStream(),
    )


def stat_info(identity: tuple[int, int, int], *, permissions: int = 0) -> SimpleNamespace:
    return SimpleNamespace(
        st_dev=identity[0],
        st_ino=identity[1],
        st_mode=identity[2] | permissions,
        st_uid=1000,
    )


class TestGrantBoundaryUtilities:
    @pytest.mark.parametrize("purpose", ["", " ", "\x00", "x" * 129])
    def test_purpose_rejects_empty_oversized_or_nul_values(self, purpose: str) -> None:
        with pytest.raises(ValueError, match="purpose"):
            grants._validate_purpose(purpose)
        assert grants._validate_purpose("  support.export  ") == "support.export"

    @pytest.mark.parametrize("leaf", ["", ".", "..", "a/b", "a\x00b", "a\\b", "C:name"])
    def test_write_leaf_rejects_path_syntax(self, leaf: str) -> None:
        platform = "nt" if leaf in {"a\\b", "C:name"} else grants.os.name
        with patch.object(grants.os, "name", platform):
            with pytest.raises(GrantError) as raised:
                grants._validated_write_leaf(leaf)
        assert raised.value.code == "grant_target_mismatch"

    def test_relative_identity_and_validation_distinguish_missing_changed_and_non_file(self) -> None:
        with patch.object(grants.os, "stat", side_effect=FileNotFoundError()):
            assert grants._relative_target_identity(1, "output") is None
        with patch.object(grants.os, "stat", return_value=stat_info(REGULAR_A)):
            assert grants._relative_target_identity(1, "output") == REGULAR_A
        with patch.object(grants, "_relative_target_identity", return_value=REGULAR_B):
            with pytest.raises(GrantError, match="changed"):
                grants._validate_relative_target(1, "output", REGULAR_A)
        with patch.object(grants, "_relative_target_identity", return_value=DIRECTORY):
            with pytest.raises(GrantError, match="regular file"):
                grants._validate_relative_target(1, "output", DIRECTORY)

    def test_bound_read_translates_missing_and_changed_open_failures(self) -> None:
        bound = BoundReadFile(Path("input.img"), REGULAR_A)
        with patch.object(grants.os, "open", side_effect=FileNotFoundError()):
            with pytest.raises(GrantError) as missing:
                bound.open_verified()
        assert missing.value.code == "grant_resource_missing"

        with patch.object(grants.os, "open", side_effect=OSError("changed")):
            with pytest.raises(GrantError) as changed:
                bound.open_verified()
        assert changed.value.code == "grant_resource_changed"

    def test_bound_write_closes_anchor_when_transaction_creation_fails(self) -> None:
        bound = BoundWriteFile(Path("output.img"), Path("."), DIRECTORY)
        anchor = Mock()
        anchor.create_transaction.side_effect = OSError("create failed")
        with patch.object(grants, "_open_bound_write_anchor", return_value=anchor):
            with pytest.raises(OSError, match="create failed"):
                bound.begin_atomic_replace()
        anchor.close.assert_called_once_with()


class TestBoundWriteTransactionState:
    class Backend:
        def __init__(self) -> None:
            self.stream = io.BytesIO()
            self.committed = False
            self.closed = 0
            self.opened = io.BytesIO(b"committed")

        def commit(self) -> None:
            self.committed = True

        def open_committed(self):
            return self.opened

        def close(self) -> None:
            self.closed += 1

    def test_transaction_enforces_commit_open_and_close_ordering(self) -> None:
        backend = self.Backend()
        transaction = BoundWriteTransaction(backend)
        assert transaction.stream is backend.stream
        assert transaction.committed is False
        with pytest.raises(ValueError, match="not been committed"):
            transaction.open_committed()

        transaction.commit()
        assert transaction.committed is True
        assert transaction.open_committed() is backend.opened
        with pytest.raises(ValueError, match="already committed"):
            transaction.commit()

        transaction.close()
        transaction.close()
        assert backend.closed == 1
        with pytest.raises(ValueError, match="closed"):
            _ = transaction.stream
        with pytest.raises(ValueError, match="closed"):
            transaction.commit()
        with pytest.raises(ValueError, match="closed"):
            transaction.open_committed()

    def test_context_manager_surfaces_cleanup_failure_without_a_primary_error(self) -> None:
        backend = self.Backend()
        backend.close = Mock(side_effect=OSError("cleanup failed"))
        with pytest.raises(OSError, match="cleanup failed"):
            with BoundWriteTransaction(backend):
                pass


class TestGrantStoreLifecycleBoundaries:
    def test_store_configuration_enum_types_capacity_revoke_and_clear(self) -> None:
        with pytest.raises(ValueError, match="write_ttl"):
            PathGrantStore(write_ttl_seconds=0)
        with pytest.raises(ValueError, match="maximum_grants"):
            PathGrantStore(maximum_grants=0)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "one.bin"
            second = root / "two.bin"
            first.write_bytes(b"one")
            second.write_bytes(b"two")
            store = PathGrantStore(maximum_grants=1)
            grant = store.issue_file(first, purpose="read")
            with pytest.raises(GrantError) as capacity:
                store.issue_file(second, purpose="read")
            assert capacity.value.code == "grant_capacity_reached"
            with pytest.raises(TypeError, match="GrantAccess"):
                store.issue_file(first, purpose="read", access="read")  # type: ignore[arg-type]
            with pytest.raises(TypeError, match="grant enum"):
                store.resolve(
                    grant.token,
                    purpose="read",
                    target="file",  # type: ignore[arg-type]
                    access=GrantAccess.READ,
                )
            assert store.revoke(grant.token) is True
            assert store.revoke(grant.token) is False
            replacement = store.issue_file(first, purpose="read")
            store.clear()
            with pytest.raises(GrantError) as cleared:
                store.resolve(
                    replacement.token,
                    purpose="read",
                    target=GrantTarget.FILE,
                    access=GrantAccess.READ,
                )
            assert cleared.value.code == "grant_not_found"

    def test_directory_write_grant_is_supported_and_identity_bound(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            store = PathGrantStore()
            grant = store.issue_directory(
                root,
                purpose="directory.write",
                access=GrantAccess.WRITE,
            )
            assert (
                store.resolve(
                    grant.token,
                    purpose="directory.write",
                    target=GrantTarget.DIRECTORY,
                    access=GrantAccess.WRITE,
                )
                == root.resolve()
            )

    def test_secret_store_configuration_capacity_revoke_clear_and_public_ttl(self) -> None:
        with pytest.raises(ValueError, match="ttl_seconds"):
            SecretGrantStore(ttl_seconds=0)
        with pytest.raises(ValueError, match="maximum_grants"):
            SecretGrantStore(maximum_grants=0)
        store = SecretGrantStore(clock=lambda: 10, maximum_grants=1)
        with pytest.raises(ValueError, match="non-empty"):
            store.issue("", purpose="secret")
        grant = store.issue("value", purpose="secret")
        assert grant.to_public_dict(now=9)["expiresInSeconds"] == 61
        with pytest.raises(GrantError) as capacity:
            store.issue("other", purpose="secret")
        assert capacity.value.code == "grant_capacity_reached"
        assert store.revoke(grant.token) is True
        assert store.revoke(grant.token) is False
        replacement = store.issue("replacement", purpose="secret")
        store.clear()
        with pytest.raises(GrantError) as cleared:
            store.consume(replacement.token, purpose="secret")
        assert cleared.value.code == "grant_not_found"


class TestPosixAtomicCommit:
    def test_new_destination_is_linked_verified_synced_and_committed(self) -> None:
        backend = atomic_backend()
        with (
            patch.object(grants, "_validate_relative_target") as validate,
            patch.object(
                grants,
                "_relative_target_identity",
                side_effect=[REGULAR_A, REGULAR_A, REGULAR_A],
            ),
            patch.object(grants.os, "link") as link,
            patch.object(grants.os, "unlink") as unlink,
            patch.object(grants.os, "fsync") as fsync,
        ):
            backend.commit()

        assert backend.committed is True
        assert backend.stream is not None
        validate.assert_called_once_with(40, "output.img", None)
        link.assert_called_once()
        unlink.assert_called_once_with("payload", dir_fd=41)
        assert [call.args[0] for call in fsync.call_args_list] == [41, 40]

    def test_existing_destination_is_exchanged_and_displaced_inode_removed(self) -> None:
        backend = atomic_backend(target_identity=REGULAR_B)
        with (
            patch.object(grants, "_validate_relative_target"),
            patch.object(
                grants,
                "_relative_target_identity",
                side_effect=[REGULAR_A, REGULAR_A, REGULAR_B, REGULAR_A],
            ),
            patch.object(grants, "_posix_exchange") as exchange,
            patch.object(grants.os, "unlink") as unlink,
            patch.object(grants.os, "fsync"),
        ):
            backend.commit()

        assert backend.committed is True
        assert backend._staged_cleanup_identity is None
        exchange.assert_called_once_with(41, "payload", 40, "output.img")
        unlink.assert_called_once_with("payload", dir_fd=41)

    def test_commit_rejects_closed_changed_and_raced_new_destinations(self) -> None:
        closed = atomic_backend()
        closed._closed = True
        with pytest.raises(ValueError, match="closed"):
            closed.commit()

        changed = atomic_backend()
        with (
            patch.object(grants, "_validate_relative_target"),
            patch.object(grants, "_relative_target_identity", return_value=REGULAR_B),
        ):
            with pytest.raises(GrantError, match="temporary changed"):
                changed.commit()

        raced = atomic_backend()
        with (
            patch.object(grants, "_validate_relative_target"),
            patch.object(grants, "_relative_target_identity", return_value=REGULAR_A),
            patch.object(grants.os, "link", side_effect=FileExistsError()),
        ):
            with pytest.raises(GrantError, match="destination changed"):
                raced.commit()

    @pytest.mark.parametrize("error_number", [errno.EIO, errno.EPERM])
    def test_exchange_errors_with_unknown_kernel_outcome_are_classified(
        self,
        error_number: int,
    ) -> None:
        backend = atomic_backend(target_identity=REGULAR_B)
        with (
            patch.object(grants, "_validate_relative_target"),
            patch.object(grants, "_relative_target_identity", return_value=REGULAR_A),
            patch.object(
                grants,
                "_posix_exchange",
                side_effect=OSError(error_number, "exchange failed"),
            ),
        ):
            with pytest.raises(AtomicWriteOutcomeUnknownError):
                backend.commit()

    def test_unavailable_exchange_preserves_safe_staged_temporary_for_cleanup(self) -> None:
        backend = atomic_backend(target_identity=REGULAR_B)
        with (
            patch.object(grants, "_validate_relative_target"),
            patch.object(
                grants,
                "_relative_target_identity",
                side_effect=[REGULAR_A, REGULAR_A, REGULAR_B],
            ),
            patch.object(
                grants,
                "_posix_exchange",
                side_effect=OSError(errno.ENOSYS, "unsupported"),
            ),
        ):
            with pytest.raises(OSError) as raised:
                backend.commit()

        assert raised.value.errno == errno.ENOSYS
        assert backend._staged_cleanup_identity == REGULAR_A

    def test_unavailable_exchange_with_ambiguous_names_is_outcome_unknown(self) -> None:
        backend = atomic_backend(target_identity=REGULAR_B)
        with (
            patch.object(grants, "_validate_relative_target"),
            patch.object(
                grants,
                "_relative_target_identity",
                side_effect=[REGULAR_A, REGULAR_C],
            ),
            patch.object(
                grants,
                "_posix_exchange",
                side_effect=OSError(errno.ENOTSUP, "unsupported"),
            ),
        ):
            with pytest.raises(AtomicWriteOutcomeUnknownError):
                backend.commit()

    @pytest.mark.parametrize("rollback", [True, False])
    def test_displaced_identity_mismatch_never_reports_success(self, rollback: bool) -> None:
        backend = atomic_backend(target_identity=REGULAR_B)
        with (
            patch.object(grants, "_validate_relative_target"),
            patch.object(
                grants,
                "_relative_target_identity",
                side_effect=[REGULAR_A, REGULAR_A, REGULAR_C],
            ),
            patch.object(grants, "_posix_exchange"),
            patch.object(backend, "_rollback_exchange", return_value=rollback) as restore,
        ):
            with pytest.raises(AtomicWriteOutcomeUnknownError) as raised:
                backend.commit()

        restore.assert_called_once_with(REGULAR_C)
        assert ("rolled back" in str(raised.value)) is rollback

    def test_post_publication_identity_and_durability_failures_are_unknown(self) -> None:
        changed = atomic_backend()
        with (
            patch.object(grants, "_validate_relative_target"),
            patch.object(
                grants,
                "_relative_target_identity",
                side_effect=[REGULAR_A, REGULAR_B],
            ),
            patch.object(grants.os, "link"),
        ):
            with pytest.raises(AtomicWriteOutcomeUnknownError, match="before it could be verified"):
                changed.commit()

        unsynced = atomic_backend()
        with (
            patch.object(grants, "_validate_relative_target"),
            patch.object(
                grants,
                "_relative_target_identity",
                side_effect=[REGULAR_A, REGULAR_A],
            ),
            patch.object(grants.os, "link"),
            patch.object(grants.os, "unlink"),
            patch.object(grants.os, "fsync", side_effect=OSError("sync failed")),
        ):
            with pytest.raises(AtomicWriteOutcomeUnknownError):
                unsynced.commit()

        swapped_after_sync = atomic_backend()
        with (
            patch.object(grants, "_validate_relative_target"),
            patch.object(
                grants,
                "_relative_target_identity",
                side_effect=[REGULAR_A, REGULAR_A, REGULAR_B],
            ),
            patch.object(grants.os, "link"),
            patch.object(grants.os, "unlink"),
            patch.object(grants.os, "fsync"),
        ):
            with pytest.raises(AtomicWriteOutcomeUnknownError, match="durability"):
                swapped_after_sync.commit()


class TestPosixAtomicRollbackAndVerification:
    def test_rollback_requires_stable_names_and_restores_original_destination(self) -> None:
        backend = atomic_backend(target_identity=REGULAR_B)
        assert backend._rollback_exchange(None) is False

        with patch.object(
            grants,
            "_relative_target_identity",
            side_effect=[REGULAR_B, REGULAR_C],
        ):
            assert backend._rollback_exchange(REGULAR_C) is False

        with (
            patch.object(
                grants,
                "_relative_target_identity",
                side_effect=[REGULAR_A, REGULAR_C, REGULAR_C, REGULAR_A],
            ),
            patch.object(grants, "_posix_exchange") as exchange,
        ):
            assert backend._rollback_exchange(REGULAR_C) is True

        exchange.assert_called_once()
        assert backend._published is False
        assert backend._staged_cleanup_identity == REGULAR_A

    def test_rollback_returns_false_when_exchange_fails_or_verification_changes(self) -> None:
        failed = atomic_backend(target_identity=REGULAR_B)
        with (
            patch.object(
                grants,
                "_relative_target_identity",
                side_effect=[REGULAR_A, REGULAR_C],
            ),
            patch.object(grants, "_posix_exchange", side_effect=OSError("failed")),
        ):
            assert failed._rollback_exchange(REGULAR_C) is False

        changed = atomic_backend(target_identity=REGULAR_B)
        with (
            patch.object(
                grants,
                "_relative_target_identity",
                side_effect=[REGULAR_A, REGULAR_C, REGULAR_B, REGULAR_B],
            ),
            patch.object(grants, "_posix_exchange"),
        ):
            assert changed._rollback_exchange(REGULAR_C) is False

    def test_open_committed_is_identity_bound(self) -> None:
        backend = atomic_backend()
        with pytest.raises(ValueError, match="not been committed"):
            backend.open_committed()

        backend._committed = True
        with patch.object(grants.os, "open", side_effect=OSError("gone")):
            with pytest.raises(AtomicWriteOutcomeUnknownError):
                backend.open_committed()

        opened = Mock()
        backend = atomic_backend()
        backend._committed = True
        with (
            patch.object(grants.os, "open", return_value=50),
            patch.object(
                grants.os,
                "fstat",
                side_effect=[stat_info(REGULAR_A), stat_info(REGULAR_A)],
            ),
            patch.object(grants, "_relative_target_identity", return_value=REGULAR_A),
            patch.object(grants.os, "fdopen", return_value=opened),
        ):
            assert backend.open_committed() is opened

        mismatched = atomic_backend()
        mismatched._committed = True
        with (
            patch.object(grants.os, "open", return_value=51),
            patch.object(
                grants.os,
                "fstat",
                side_effect=[stat_info(REGULAR_B), stat_info(REGULAR_A)],
            ),
            patch.object(grants, "_relative_target_identity", return_value=REGULAR_B),
            patch.object(grants.os, "close") as close,
        ):
            with pytest.raises(AtomicWriteOutcomeUnknownError):
                mismatched.open_committed()
        close.assert_called_once_with(51)


class TestPosixAtomicCleanup:
    def test_close_removes_only_identity_bound_temporary_and_staging_directory(self) -> None:
        backend = atomic_backend()
        with (
            patch.object(
                grants,
                "_relative_target_identity",
                side_effect=[REGULAR_A, DIRECTORY],
            ),
            patch.object(grants.os, "unlink") as unlink,
            patch.object(grants.os, "rmdir") as rmdir,
            patch.object(grants.os, "close") as close,
        ):
            backend.close()
            backend.close()

        unlink.assert_called_once_with("payload", dir_fd=41)
        rmdir.assert_called_once_with(".pixelflasher-stage", dir_fd=40)
        assert [call.args[0] for call in close.call_args_list] == [41, 40]

    def test_close_tolerates_already_missing_names(self) -> None:
        backend = atomic_backend()
        with (
            patch.object(
                grants,
                "_relative_target_identity",
                side_effect=[FileNotFoundError(), FileNotFoundError()],
            ),
            patch.object(grants.os, "close"),
        ):
            backend.close()

        assert backend._staged_cleanup_identity is None

    def test_close_attempts_every_cleanup_step_and_raises_first_error(self) -> None:
        backend = atomic_backend(stream=FakeStream(fail_close=True))
        with (
            patch.object(
                grants,
                "_relative_target_identity",
                side_effect=[REGULAR_A, DIRECTORY],
            ),
            patch.object(grants.os, "unlink", side_effect=OSError("unlink failed")),
            patch.object(grants.os, "close", side_effect=OSError("close failed")) as close,
            patch.object(grants.os, "rmdir", side_effect=OSError("rmdir failed")),
        ):
            with pytest.raises(OSError, match="stream close failed"):
                backend.close()

        assert close.call_count == 2


class TestPosixWriteAnchor:
    def test_anchor_open_is_identity_bound(self) -> None:
        destination = BoundWriteFile(
            Path("C:/approved/output.img"),
            Path("C:/approved"),
            DIRECTORY,
        )
        with (
            patch.object(grants.os, "open", return_value=60),
            patch.object(grants.os, "fstat", return_value=stat_info(DIRECTORY)),
        ):
            anchor = _PosixWriteAnchor(destination)
        assert anchor._descriptor == 60

        with patch.object(grants.os, "close") as close:
            anchor.close()
            anchor.close()
        close.assert_called_once_with(60)

    @pytest.mark.parametrize(
        ("open_error", "code"),
        [
            (FileNotFoundError(), "grant_resource_missing"),
            (OSError("changed"), "grant_resource_changed"),
        ],
    )
    def test_anchor_open_translates_path_failures(
        self,
        open_error: OSError,
        code: str,
    ) -> None:
        destination = BoundWriteFile(Path("output"), Path("parent"), DIRECTORY)
        with patch.object(grants.os, "open", side_effect=open_error):
            with pytest.raises(GrantError) as raised:
                _PosixWriteAnchor(destination)
        assert raised.value.code == code

    def test_anchor_open_closes_identity_mismatch(self) -> None:
        destination = BoundWriteFile(Path("output"), Path("parent"), DIRECTORY)
        with (
            patch.object(grants.os, "open", return_value=61),
            patch.object(grants.os, "fstat", return_value=stat_info(REGULAR_A)),
            patch.object(grants.os, "close") as close,
        ):
            with pytest.raises(GrantError, match="parent changed"):
                _PosixWriteAnchor(destination)
        close.assert_called_once_with(61)

    def test_create_transaction_builds_private_regular_staging_file(self) -> None:
        anchor = object.__new__(_PosixWriteAnchor)
        anchor._descriptor = 70
        stream = FakeStream(72)
        with (
            patch.object(grants, "_validate_relative_target"),
            patch.object(grants.secrets, "token_hex", return_value="f" * 64),
            patch.object(grants.os, "mkdir"),
            patch.object(
                grants,
                "_relative_target_identity",
                return_value=DIRECTORY,
            ),
            patch.object(grants.os, "open", side_effect=[71, 72]),
            patch.object(
                grants.os,
                "fstat",
                side_effect=[stat_info(DIRECTORY, permissions=0o700), stat_info(REGULAR_A)],
            ),
            patch.object(grants.os, "fdopen", return_value=stream),
            patch.object(grants.os, "geteuid", return_value=1000, create=True),
        ):
            backend = anchor.create_transaction("output.img", None)

        assert isinstance(backend, _PosixAtomicWrite)
        assert anchor._descriptor == -1
        assert backend._directory_fd == 70
        assert backend._staging_fd == 71
        assert backend._stream is stream

    def test_create_transaction_rejects_transferred_anchor_and_exhausted_names(self) -> None:
        anchor = object.__new__(_PosixWriteAnchor)
        anchor._descriptor = -1
        with pytest.raises(ValueError, match="transferred"):
            anchor.create_transaction("output.img", None)

        anchor._descriptor = 70
        with (
            patch.object(grants, "_validate_relative_target"),
            patch.object(grants.secrets, "token_hex", return_value="f" * 64),
            patch.object(grants.os, "mkdir", side_effect=FileExistsError()),
        ):
            with pytest.raises(FileExistsError, match="allocate"):
                anchor.create_transaction("output.img", None)

    def test_create_transaction_cleans_insecure_staging_state(self) -> None:
        anchor = object.__new__(_PosixWriteAnchor)
        anchor._descriptor = 70
        with (
            patch.object(grants, "_validate_relative_target"),
            patch.object(grants.os, "mkdir"),
            patch.object(
                grants,
                "_relative_target_identity",
                side_effect=[DIRECTORY, DIRECTORY],
            ),
            patch.object(grants.os, "open", return_value=71),
            patch.object(
                grants.os,
                "fstat",
                return_value=stat_info(DIRECTORY, permissions=0o777),
            ),
            patch.object(grants.os, "close") as close,
            patch.object(grants.os, "rmdir") as rmdir,
            patch.object(grants.os, "geteuid", return_value=1000, create=True),
        ):
            with pytest.raises(GrantError, match="staging directory changed"):
                anchor.create_transaction("output.img", None)

        close.assert_called_once_with(71)
        rmdir.assert_called_once()


class FakeRename:
    def __init__(self, result: int) -> None:
        self.result = result
        self.argtypes = None
        self.restype = None
        self.calls: list[tuple[object, ...]] = []

    def __call__(self, *args: object) -> int:
        self.calls.append(args)
        return self.result


class TestPosixExchange:
    @pytest.mark.parametrize(
        ("platform", "attribute"),
        [("linux", "renameat2"), ("darwin", "renameatx_np")],
    )
    def test_exchange_calls_the_platform_atomic_rename(
        self,
        platform: str,
        attribute: str,
    ) -> None:
        rename = FakeRename(0)
        library = SimpleNamespace(**{attribute: rename})
        with (
            patch.object(grants.sys, "platform", platform),
            patch.object(ctypes, "CDLL", return_value=library),
        ):
            grants._posix_exchange(1, "source", 2, "destination")

        assert len(rename.calls) == 1
        assert rename.calls[0][0] == 1
        assert rename.calls[0][2] == 2

    def test_exchange_rejects_missing_apis_unsupported_platform_and_errno(self) -> None:
        with (
            patch.object(grants.sys, "platform", "linux"),
            patch.object(ctypes, "CDLL", return_value=SimpleNamespace()),
        ):
            with pytest.raises(OSError) as missing:
                grants._posix_exchange(1, "a", 2, "b")
        assert missing.value.errno == errno.ENOSYS

        with (
            patch.object(grants.sys, "platform", "win32"),
            patch.object(ctypes, "CDLL", return_value=SimpleNamespace()),
        ):
            with pytest.raises(OSError) as unsupported:
                grants._posix_exchange(1, "a", 2, "b")
        assert unsupported.value.errno == errno.ENOTSUP

        rename = FakeRename(-1)
        with (
            patch.object(grants.sys, "platform", "linux"),
            patch.object(ctypes, "CDLL", return_value=SimpleNamespace(renameat2=rename)),
            patch.object(ctypes, "get_errno", return_value=errno.EPERM),
        ):
            with pytest.raises(OSError) as failed:
                grants._posix_exchange(1, "a", 2, "b")
        assert failed.value.errno == errno.EPERM
