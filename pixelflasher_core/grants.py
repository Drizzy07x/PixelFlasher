"""Opaque, purpose-bound grants for native resources and ephemeral secrets.

The WebView is intentionally never trusted with filesystem paths or long-lived
credentials.  A native host issues an opaque token after the user selects a
resource; backend services resolve that token only for the exact command
purpose for which it was created.
"""

from __future__ import annotations

import errno
import os
import secrets
import stat
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Any, BinaryIO, Protocol, Self, cast

from .contracts import JSONValue, SensitiveText


class GrantAccess(StrEnum):
    READ = "read"
    WRITE = "write"


class GrantTarget(StrEnum):
    FILE = "file"
    DIRECTORY = "directory"


class GrantError(RuntimeError):
    """A stable, UI-safe grant rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class AtomicWriteOutcomeUnknownError(GrantError):
    """A durable publication may have happened before the reported failure."""

    def __init__(self, message: str = "atomic publication outcome could not be verified") -> None:
        super().__init__("outcome_unknown", message)


_Identity = tuple[int, int, int]


class _AtomicWriteBackend(Protocol):
    @property
    def stream(self) -> BinaryIO: ...

    @property
    def committed(self) -> bool: ...

    def commit(self) -> None: ...

    def open_committed(self) -> BinaryIO: ...

    def close(self) -> None: ...


class BoundWriteTransaction:
    """Atomic write transaction anchored to the approved directory object.

    The implementation never uses the approved pathname after acquiring the
    directory capability.  POSIX operations are relative to a directory file
    descriptor.  Windows operations use native handle-relative create and
    handle-based rename primitives, so junction or ancestor swaps cannot move
    the write into a different directory.
    """

    def __init__(self, backend: _AtomicWriteBackend) -> None:
        self._backend = backend
        self._closed = False

    @property
    def stream(self) -> BinaryIO:
        if self._closed:
            raise ValueError("atomic write transaction is closed")
        return self._backend.stream

    @property
    def committed(self) -> bool:
        return self._backend.committed

    def commit(self) -> None:
        if self._closed:
            raise ValueError("atomic write transaction is closed")
        if self._backend.committed:
            raise ValueError("atomic write transaction is already committed")
        self._backend.commit()

    def open_committed(self) -> BinaryIO:
        if self._closed:
            raise ValueError("atomic write transaction is closed")
        if not self._backend.committed:
            raise ValueError("atomic write transaction has not been committed")
        return self._backend.open_committed()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._backend.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, traceback
        try:
            self.close()
        except BaseException:
            if exc_value is None:
                raise


def _validate_purpose(purpose: str) -> str:
    normalized = str(purpose).strip()
    if not normalized or len(normalized) > 128 or "\x00" in normalized:
        raise ValueError("purpose must be a non-empty, NUL-free string up to 128 characters")
    return normalized


def _identity(path: Path) -> _Identity:
    info = path.stat()
    return _stat_identity(info)


def _stat_identity(info: os.stat_result) -> _Identity:
    return (int(info.st_dev), int(info.st_ino), stat.S_IFMT(info.st_mode))


@dataclass(frozen=True, slots=True)
class BoundReadFile:
    """A native-file selection bound to the resource approved by the user."""

    path: Path = field(repr=False)
    _target_identity: _Identity = field(repr=False)

    def open_verified(self) -> BinaryIO:
        """Open the approved inode without trusting the pathname a second time."""

        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags)
        except FileNotFoundError as error:
            raise GrantError(
                "grant_resource_missing",
                "selected resource no longer exists",
            ) from error
        except OSError as error:
            raise GrantError(
                "grant_resource_changed",
                "selected file changed after approval",
            ) from error
        try:
            if _stat_identity(os.fstat(descriptor)) != self._target_identity:
                raise GrantError(
                    "grant_resource_changed",
                    "selected file changed after approval",
                )
            stream = os.fdopen(descriptor, "rb")
        except Exception:
            os.close(descriptor)
            raise
        return stream


@dataclass(frozen=True, slots=True)
class BoundWriteFile:
    """One-use native destination bound to the path approved by the user."""

    path: Path = field(repr=False)
    _anchor: Path = field(repr=False)
    _anchor_identity: _Identity = field(repr=False)
    _target_identity: _Identity | None = field(default=None, repr=False)

    @property
    def name(self) -> str:
        return self.path.name

    def begin_atomic_replace(self) -> BoundWriteTransaction:
        """Create a private temporary file relative to the approved directory.

        The returned transaction owns the directory capability until it is
        closed.  A successful ``commit()`` atomically publishes the staged
        inode under the approved leaf name without resolving ``path`` again.
        """

        leaf_name = _validated_write_leaf(self.name)
        anchor = _open_bound_write_anchor(self)
        try:
            backend = anchor.create_transaction(leaf_name, self._target_identity)
        except Exception:
            anchor.close()
            raise
        return BoundWriteTransaction(backend)


class _WriteAnchor(Protocol):
    def create_transaction(
        self,
        leaf_name: str,
        target_identity: _Identity | None,
    ) -> _AtomicWriteBackend: ...

    def close(self) -> None: ...


def _validated_write_leaf(name: str) -> str:
    if (
        not name
        or name in {".", ".."}
        or "\x00" in name
        or "/" in name
        or (os.name == "nt" and ("\\" in name or ":" in name))
    ):
        raise GrantError("grant_target_mismatch", "selected destination name is not a safe file name")
    return name


def _relative_target_identity(directory_fd: int, leaf_name: str) -> _Identity | None:
    try:
        info = os.stat(leaf_name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    return _stat_identity(info)


def _validate_relative_target(
    directory_fd: int,
    leaf_name: str,
    expected: _Identity | None,
) -> None:
    actual = _relative_target_identity(directory_fd, leaf_name)
    if actual != expected:
        raise GrantError("grant_resource_changed", "selected destination changed after approval")
    if actual is not None and not stat.S_ISREG(actual[2]):
        raise GrantError("grant_resource_changed", "selected destination is not a regular file")


class _PosixWriteAnchor:
    def __init__(self, destination: BoundWriteFile) -> None:
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(destination._anchor, flags)
        except FileNotFoundError as error:
            raise GrantError(
                "grant_resource_missing",
                "selected destination parent is no longer available",
            ) from error
        except OSError as error:
            raise GrantError(
                "grant_resource_changed",
                "selected destination parent changed after approval",
            ) from error
        try:
            if _stat_identity(os.fstat(descriptor)) != destination._anchor_identity:
                raise GrantError(
                    "grant_resource_changed",
                    "selected destination parent changed after approval",
                )
        except Exception:
            os.close(descriptor)
            raise
        self._descriptor = descriptor

    def create_transaction(
        self,
        leaf_name: str,
        target_identity: _Identity | None,
    ) -> _AtomicWriteBackend:
        if self._descriptor < 0:
            raise ValueError("directory capability was already transferred")
        _validate_relative_target(self._descriptor, leaf_name, target_identity)
        staging_name = ""
        for _attempt in range(32):
            staging_name = f".pixelflasher-{secrets.token_hex(32)}.stage"
            try:
                os.mkdir(staging_name, 0o700, dir_fd=self._descriptor)
                break
            except FileExistsError:
                continue
        else:
            raise FileExistsError("could not allocate a private atomic-write staging directory")

        staging_identity = _relative_target_identity(self._descriptor, staging_name)
        staging_fd = -1
        temporary_fd = -1
        temporary_name = "payload"
        temporary_linked = False
        try:
            directory_flags = os.O_RDONLY
            directory_flags |= getattr(os, "O_CLOEXEC", 0)
            directory_flags |= getattr(os, "O_DIRECTORY", 0)
            directory_flags |= getattr(os, "O_NOFOLLOW", 0)
            staging_fd = os.open(staging_name, directory_flags, dir_fd=self._descriptor)
            staging_info = os.fstat(staging_fd)
            get_effective_user_id = cast(Callable[[], int] | None, getattr(os, "geteuid", None))
            if (
                _stat_identity(staging_info) != staging_identity
                or not stat.S_ISDIR(staging_info.st_mode)
                or stat.S_IMODE(staging_info.st_mode) & 0o077
                or (get_effective_user_id is not None and int(staging_info.st_uid) != int(get_effective_user_id()))
            ):
                raise GrantError(
                    "grant_resource_changed",
                    "atomic-write staging directory changed before use",
                )

            file_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
            file_flags |= getattr(os, "O_BINARY", 0)
            file_flags |= getattr(os, "O_CLOEXEC", 0)
            file_flags |= getattr(os, "O_NOFOLLOW", 0)
            temporary_fd = os.open(
                temporary_name,
                file_flags,
                0o600,
                dir_fd=staging_fd,
            )
            temporary_linked = True
            temporary_identity = _stat_identity(os.fstat(temporary_fd))
            if not stat.S_ISREG(temporary_identity[2]):
                raise GrantError("grant_resource_changed", "atomic-write temporary is not a regular file")
            stream = cast(BinaryIO, os.fdopen(temporary_fd, "w+b"))
            temporary_fd = -1
        except Exception:
            try:
                if temporary_fd >= 0:
                    os.close(temporary_fd)
            finally:
                try:
                    if temporary_linked and staging_fd >= 0:
                        os.unlink(temporary_name, dir_fd=staging_fd)
                finally:
                    if staging_fd >= 0:
                        os.close(staging_fd)
                    try:
                        current = _relative_target_identity(self._descriptor, staging_name)
                        if current == staging_identity:
                            os.rmdir(staging_name, dir_fd=self._descriptor)
                    except OSError:
                        pass
            raise
        directory_fd = self._descriptor
        self._descriptor = -1
        return _PosixAtomicWrite(
            directory_fd,
            staging_fd,
            staging_name,
            cast(_Identity, staging_identity),
            leaf_name,
            target_identity,
            temporary_name,
            temporary_identity,
            stream,
        )

    def close(self) -> None:
        if self._descriptor >= 0:
            os.close(self._descriptor)
            self._descriptor = -1


class _PosixAtomicWrite:
    def __init__(
        self,
        directory_fd: int,
        staging_fd: int,
        staging_name: str,
        staging_identity: _Identity,
        leaf_name: str,
        target_identity: _Identity | None,
        temporary_name: str,
        temporary_identity: _Identity,
        stream: BinaryIO,
    ) -> None:
        self._directory_fd = directory_fd
        self._staging_fd = staging_fd
        self._staging_name = staging_name
        self._staging_identity = staging_identity
        self._leaf_name = leaf_name
        self._target_identity = target_identity
        self._temporary_name = temporary_name
        self._temporary_identity = temporary_identity
        self._stream = stream
        self._staged_cleanup_identity: _Identity | None = temporary_identity
        self._published = False
        self._committed = False
        self._closed = False

    @property
    def stream(self) -> BinaryIO:
        return self._stream

    @property
    def committed(self) -> bool:
        return self._committed

    def commit(self) -> None:
        if self._closed:
            raise ValueError("atomic-write backend is closed")
        _validate_relative_target(self._directory_fd, self._leaf_name, self._target_identity)
        temporary_identity = _relative_target_identity(self._staging_fd, self._temporary_name)
        if temporary_identity != self._temporary_identity:
            raise GrantError("grant_resource_changed", "atomic-write temporary changed before commit")

        if self._target_identity is None:
            try:
                os.link(
                    self._temporary_name,
                    self._leaf_name,
                    src_dir_fd=self._staging_fd,
                    dst_dir_fd=self._directory_fd,
                    follow_symlinks=False,
                )
            except FileExistsError as error:
                raise GrantError(
                    "grant_resource_changed",
                    "selected destination changed before publication",
                ) from error
            self._published = True
        else:
            # Once exchange enters the kernel, the staging name may refer to
            # the displaced destination.  Cleanup must not unlink it until its
            # identity has been proven safe to remove.
            self._staged_cleanup_identity = None
            try:
                _posix_exchange(
                    self._staging_fd,
                    self._temporary_name,
                    self._directory_fd,
                    self._leaf_name,
                )
            except OSError as error:
                if error.errno in {errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EINVAL}:
                    if (
                        _relative_target_identity(self._staging_fd, self._temporary_name) == self._temporary_identity
                        and _relative_target_identity(self._directory_fd, self._leaf_name) == self._target_identity
                    ):
                        self._staged_cleanup_identity = self._temporary_identity
                        raise
                    raise AtomicWriteOutcomeUnknownError() from error
                raise AtomicWriteOutcomeUnknownError() from error
            self._published = True

        try:
            installed = _relative_target_identity(self._directory_fd, self._leaf_name)
            if installed != self._temporary_identity:
                raise AtomicWriteOutcomeUnknownError("published destination changed before it could be verified")
            if self._target_identity is not None:
                displaced = _relative_target_identity(self._staging_fd, self._temporary_name)
                if displaced != self._target_identity:
                    if self._rollback_exchange(displaced):
                        raise AtomicWriteOutcomeUnknownError(
                            "destination changed at publication; the exchange was rolled back"
                        )
                    raise AtomicWriteOutcomeUnknownError("approved destination changed at the atomic exchange boundary")
                self._staged_cleanup_identity = self._target_identity
            os.unlink(self._temporary_name, dir_fd=self._staging_fd)
            self._staged_cleanup_identity = None
            os.fsync(self._staging_fd)
            os.fsync(self._directory_fd)
            if _relative_target_identity(self._directory_fd, self._leaf_name) != self._temporary_identity:
                raise AtomicWriteOutcomeUnknownError("published destination changed before durability was confirmed")
        except AtomicWriteOutcomeUnknownError:
            raise
        except Exception as error:
            raise AtomicWriteOutcomeUnknownError() from error
        self._committed = True

    def _rollback_exchange(self, displaced_identity: _Identity | None) -> bool:
        if displaced_identity is None:
            return False
        try:
            if (
                _relative_target_identity(self._directory_fd, self._leaf_name) != self._temporary_identity
                or _relative_target_identity(self._staging_fd, self._temporary_name) != displaced_identity
            ):
                return False
            _posix_exchange(
                self._staging_fd,
                self._temporary_name,
                self._directory_fd,
                self._leaf_name,
            )
            if (
                _relative_target_identity(self._directory_fd, self._leaf_name) != displaced_identity
                or _relative_target_identity(self._staging_fd, self._temporary_name) != self._temporary_identity
            ):
                return False
        except OSError:
            return False
        self._published = False
        self._staged_cleanup_identity = self._temporary_identity
        return True

    def open_committed(self) -> BinaryIO:
        if not self._committed:
            raise ValueError("atomic write has not been committed")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self._leaf_name, flags, dir_fd=self._directory_fd)
        except OSError as error:
            raise AtomicWriteOutcomeUnknownError(
                "written destination changed before verification",
            ) from error
        try:
            installed = _stat_identity(os.fstat(descriptor))
            staged = _stat_identity(os.fstat(self._stream.fileno()))
            current = _relative_target_identity(self._directory_fd, self._leaf_name)
            if installed != staged or current != staged or not stat.S_ISREG(installed[2]):
                raise AtomicWriteOutcomeUnknownError(
                    "written destination changed before verification",
                )
            return cast(BinaryIO, os.fdopen(descriptor, "rb"))
        except Exception:
            os.close(descriptor)
            raise

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        cleanup_error: BaseException | None = None
        try:
            self._stream.close()
        except BaseException as error:
            cleanup_error = error
        try:
            cleanup_identity = self._staged_cleanup_identity
            if (
                cleanup_identity is not None
                and _relative_target_identity(self._staging_fd, self._temporary_name) == cleanup_identity
            ):
                os.unlink(self._temporary_name, dir_fd=self._staging_fd)
                self._staged_cleanup_identity = None
        except FileNotFoundError:
            self._staged_cleanup_identity = None
        except BaseException as error:
            if cleanup_error is None:
                cleanup_error = error
        try:
            os.close(self._staging_fd)
        except BaseException as error:
            if cleanup_error is None:
                cleanup_error = error
        try:
            current = _relative_target_identity(self._directory_fd, self._staging_name)
            if current == self._staging_identity:
                os.rmdir(self._staging_name, dir_fd=self._directory_fd)
        except FileNotFoundError:
            pass
        except BaseException as error:
            if cleanup_error is None:
                cleanup_error = error
        try:
            os.close(self._directory_fd)
        except BaseException as error:
            if cleanup_error is None:
                cleanup_error = error
        if cleanup_error is not None:
            raise cleanup_error


def _posix_exchange(
    source_directory_fd: int,
    source_name: str,
    destination_directory_fd: int,
    destination_name: str,
) -> None:
    """Atomically exchange two dirfd-relative names on Linux or macOS."""

    import ctypes

    ctypes_api: Any = ctypes
    library: Any = ctypes_api.CDLL(None, use_errno=True)
    encoded_source = os.fsencode(source_name)
    encoded_destination = os.fsencode(destination_name)
    if sys.platform.startswith("linux"):
        rename = getattr(library, "renameat2", None)
        if rename is None:
            raise OSError(errno.ENOSYS, "atomic exchange is unavailable")
        rename.argtypes = [
            ctypes_api.c_int,
            ctypes_api.c_char_p,
            ctypes_api.c_int,
            ctypes_api.c_char_p,
            ctypes_api.c_uint,
        ]
        rename.restype = ctypes_api.c_int
        result = int(
            rename(
                source_directory_fd,
                encoded_source,
                destination_directory_fd,
                encoded_destination,
                0x00000002,  # RENAME_EXCHANGE
            )
        )
    elif sys.platform == "darwin":
        rename = getattr(library, "renameatx_np", None)
        if rename is None:
            raise OSError(errno.ENOSYS, "atomic exchange is unavailable")
        rename.argtypes = [
            ctypes_api.c_int,
            ctypes_api.c_char_p,
            ctypes_api.c_int,
            ctypes_api.c_char_p,
            ctypes_api.c_uint,
        ]
        rename.restype = ctypes_api.c_int
        result = int(
            rename(
                source_directory_fd,
                encoded_source,
                destination_directory_fd,
                encoded_destination,
                0x00000002,  # RENAME_SWAP
            )
        )
    else:
        raise OSError(errno.ENOTSUP, "atomic exchange is unsupported on this platform")
    if result != 0:
        error_number = int(ctypes_api.get_errno())
        raise OSError(error_number, os.strerror(error_number))


class _Win32Api:
    """Small typed facade over the handle-relative NT file operations we need."""

    _FILE_READ_DATA = 0x0001
    _FILE_WRITE_DATA = 0x0002
    _FILE_TRAVERSE = 0x0020
    _FILE_READ_ATTRIBUTES = 0x0080
    _FILE_WRITE_ATTRIBUTES = 0x0100
    _DELETE = 0x00010000
    _SYNCHRONIZE = 0x00100000
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _FILE_SHARE_DELETE = 0x00000004
    _OPEN_EXISTING = 3
    _FILE_CREATE = 2
    _FILE_OPEN = 1
    _FILE_ATTRIBUTE_TEMPORARY = 0x00000100
    _FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
    _FILE_NON_DIRECTORY_FILE = 0x00000040
    _FILE_OPEN_REPARSE_POINT = 0x00200000
    _OBJ_CASE_INSENSITIVE = 0x00000040
    _FILE_ID_INFO_CLASS = 18
    _FILE_RENAME_INFORMATION_CLASS = 10
    _FILE_DISPOSITION_INFO_CLASS = 4
    _DUPLICATE_SAME_ACCESS = 0x00000002

    def __init__(self) -> None:
        import ctypes
        import msvcrt
        from ctypes import wintypes

        ctypes_api: Any = ctypes
        wintypes_api: Any = wintypes
        self._ctypes = ctypes_api
        self._msvcrt: Any = msvcrt
        self._wintypes = wintypes_api

        class _UnicodeString(ctypes_api.Structure):
            _fields_ = [
                ("Length", wintypes_api.USHORT),
                ("MaximumLength", wintypes_api.USHORT),
                ("Buffer", wintypes_api.LPWSTR),
            ]

        class _ObjectAttributes(ctypes_api.Structure):
            _fields_ = [
                ("Length", wintypes_api.ULONG),
                ("RootDirectory", wintypes_api.HANDLE),
                ("ObjectName", ctypes_api.POINTER(_UnicodeString)),
                ("Attributes", wintypes_api.ULONG),
                ("SecurityDescriptor", wintypes_api.LPVOID),
                ("SecurityQualityOfService", wintypes_api.LPVOID),
            ]

        class _IoStatusUnion(ctypes_api.Union):
            _fields_ = [("Status", ctypes_api.c_long), ("Pointer", wintypes_api.LPVOID)]

        class _IoStatusBlock(ctypes_api.Structure):
            _fields_ = [("Value", _IoStatusUnion), ("Information", ctypes_api.c_size_t)]

        class _FileId128(ctypes_api.Structure):
            _fields_ = [("Identifier", ctypes_api.c_ubyte * 16)]

        class _FileIdInfo(ctypes_api.Structure):
            _fields_ = [("VolumeSerialNumber", ctypes_api.c_ulonglong), ("FileId", _FileId128)]

        class _ByHandleFileInformation(ctypes_api.Structure):
            _fields_ = [
                ("dwFileAttributes", wintypes_api.DWORD),
                ("ftCreationTime", wintypes_api.FILETIME),
                ("ftLastAccessTime", wintypes_api.FILETIME),
                ("ftLastWriteTime", wintypes_api.FILETIME),
                ("dwVolumeSerialNumber", wintypes_api.DWORD),
                ("nFileSizeHigh", wintypes_api.DWORD),
                ("nFileSizeLow", wintypes_api.DWORD),
                ("nNumberOfLinks", wintypes_api.DWORD),
                ("nFileIndexHigh", wintypes_api.DWORD),
                ("nFileIndexLow", wintypes_api.DWORD),
            ]

        class _FileRenameInformation(ctypes_api.Structure):
            _fields_ = [
                ("ReplaceIfExists", wintypes_api.BOOLEAN),
                ("RootDirectory", wintypes_api.HANDLE),
                ("FileNameLength", wintypes_api.ULONG),
                ("FileName", wintypes_api.WCHAR * 1),
            ]

        class _FileDispositionInfo(ctypes_api.Structure):
            _fields_ = [("DeleteFile", wintypes_api.BOOL)]

        self._UnicodeString = _UnicodeString
        self._ObjectAttributes = _ObjectAttributes
        self._IoStatusBlock = _IoStatusBlock
        self._FileIdInfo = _FileIdInfo
        self._ByHandleFileInformation = _ByHandleFileInformation
        self._FileRenameInformation = _FileRenameInformation
        self._FileDispositionInfo = _FileDispositionInfo

        kernel32: Any = ctypes_api.WinDLL("kernel32", use_last_error=True)
        ntdll: Any = ctypes_api.WinDLL("ntdll")
        self._kernel32 = kernel32
        self._ntdll = ntdll
        kernel32.CreateFileW.argtypes = [
            wintypes_api.LPCWSTR,
            wintypes_api.DWORD,
            wintypes_api.DWORD,
            wintypes_api.LPVOID,
            wintypes_api.DWORD,
            wintypes_api.DWORD,
            wintypes_api.HANDLE,
        ]
        kernel32.CreateFileW.restype = wintypes_api.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes_api.HANDLE]
        kernel32.CloseHandle.restype = wintypes_api.BOOL
        kernel32.GetFileInformationByHandle.argtypes = [
            wintypes_api.HANDLE,
            ctypes_api.POINTER(_ByHandleFileInformation),
        ]
        kernel32.GetFileInformationByHandle.restype = wintypes_api.BOOL
        kernel32.GetFileInformationByHandleEx.argtypes = [
            wintypes_api.HANDLE,
            ctypes_api.c_int,
            wintypes_api.LPVOID,
            wintypes_api.DWORD,
        ]
        kernel32.GetFileInformationByHandleEx.restype = wintypes_api.BOOL
        kernel32.GetCurrentProcess.restype = wintypes_api.HANDLE
        kernel32.DuplicateHandle.argtypes = [
            wintypes_api.HANDLE,
            wintypes_api.HANDLE,
            wintypes_api.HANDLE,
            ctypes_api.POINTER(wintypes_api.HANDLE),
            wintypes_api.DWORD,
            wintypes_api.BOOL,
            wintypes_api.DWORD,
        ]
        kernel32.DuplicateHandle.restype = wintypes_api.BOOL
        kernel32.SetFileInformationByHandle.argtypes = [
            wintypes_api.HANDLE,
            ctypes_api.c_int,
            wintypes_api.LPVOID,
            wintypes_api.DWORD,
        ]
        kernel32.SetFileInformationByHandle.restype = wintypes_api.BOOL
        ntdll.NtCreateFile.argtypes = [
            ctypes_api.POINTER(wintypes_api.HANDLE),
            wintypes_api.ULONG,
            ctypes_api.POINTER(_ObjectAttributes),
            ctypes_api.POINTER(_IoStatusBlock),
            wintypes_api.LPVOID,
            wintypes_api.ULONG,
            wintypes_api.ULONG,
            wintypes_api.ULONG,
            wintypes_api.ULONG,
            wintypes_api.LPVOID,
            wintypes_api.ULONG,
        ]
        ntdll.NtCreateFile.restype = ctypes_api.c_long
        ntdll.NtSetInformationFile.argtypes = [
            wintypes_api.HANDLE,
            ctypes_api.POINTER(_IoStatusBlock),
            wintypes_api.LPVOID,
            wintypes_api.ULONG,
            wintypes_api.ULONG,
        ]
        ntdll.NtSetInformationFile.restype = ctypes_api.c_long
        ntdll.RtlNtStatusToDosError.argtypes = [ctypes_api.c_long]
        ntdll.RtlNtStatusToDosError.restype = wintypes_api.ULONG
        self._invalid_handle = ctypes_api.c_void_p(-1).value

    def _last_error(self) -> OSError:
        return cast(OSError, self._ctypes.WinError(self._ctypes.get_last_error()))

    def _raise_nt_error(self, status: int) -> None:
        if status < 0:
            code = int(self._ntdll.RtlNtStatusToDosError(status))
            raise cast(OSError, self._ctypes.WinError(code))

    def close_handle(self, handle: int) -> None:
        if not self._kernel32.CloseHandle(handle):
            raise self._last_error()

    def open_directory(self, path: Path) -> int:
        handle = self._kernel32.CreateFileW(
            str(path),
            self._FILE_READ_ATTRIBUTES | self._FILE_TRAVERSE | self._SYNCHRONIZE,
            self._FILE_SHARE_READ | self._FILE_SHARE_WRITE | self._FILE_SHARE_DELETE,
            None,
            self._OPEN_EXISTING,
            self._FILE_FLAG_BACKUP_SEMANTICS | self._FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if handle == self._invalid_handle:
            raise self._last_error()
        return int(handle)

    def identity(self, handle: int) -> _Identity:
        file_id = self._FileIdInfo()
        if not self._kernel32.GetFileInformationByHandleEx(
            handle,
            self._FILE_ID_INFO_CLASS,
            self._ctypes.byref(file_id),
            self._ctypes.sizeof(file_id),
        ):
            raise self._last_error()
        basic = self._ByHandleFileInformation()
        if not self._kernel32.GetFileInformationByHandle(handle, self._ctypes.byref(basic)):
            raise self._last_error()
        identifier = bytes(file_id.FileId.Identifier)
        inode = int.from_bytes(identifier[:8], "little", signed=False)
        file_type = stat.S_IFDIR if basic.dwFileAttributes & self._FILE_ATTRIBUTE_DIRECTORY else stat.S_IFREG
        return (int(file_id.VolumeSerialNumber), inode, file_type)

    def _relative_open(
        self,
        directory_handle: int,
        leaf_name: str,
        *,
        desired_access: int,
        share_access: int,
        disposition: int,
        attributes: int = 0,
    ) -> int:
        name_buffer = self._ctypes.create_unicode_buffer(leaf_name)
        encoded_length = len(leaf_name.encode("utf-16-le"))
        unicode_name = self._UnicodeString(
            encoded_length,
            encoded_length + 2,
            self._ctypes.cast(name_buffer, self._wintypes.LPWSTR),
        )
        object_attributes = self._ObjectAttributes(
            self._ctypes.sizeof(self._ObjectAttributes),
            directory_handle,
            self._ctypes.pointer(unicode_name),
            self._OBJ_CASE_INSENSITIVE,
            None,
            None,
        )
        io_status = self._IoStatusBlock()
        handle = self._wintypes.HANDLE()
        status = int(
            self._ntdll.NtCreateFile(
                self._ctypes.byref(handle),
                desired_access,
                self._ctypes.byref(object_attributes),
                self._ctypes.byref(io_status),
                None,
                attributes,
                share_access,
                disposition,
                (self._FILE_SYNCHRONOUS_IO_NONALERT | self._FILE_NON_DIRECTORY_FILE | self._FILE_OPEN_REPARSE_POINT),
                None,
                0,
            )
        )
        self._raise_nt_error(status)
        if handle.value is None:
            raise OSError("NtCreateFile returned no handle")
        return int(handle.value)

    def relative_identity(self, directory_handle: int, leaf_name: str) -> _Identity | None:
        try:
            handle = self._relative_open(
                directory_handle,
                leaf_name,
                desired_access=self._FILE_READ_ATTRIBUTES | self._SYNCHRONIZE,
                share_access=self._FILE_SHARE_READ | self._FILE_SHARE_WRITE | self._FILE_SHARE_DELETE,
                disposition=self._FILE_OPEN,
            )
        except OSError as error:
            if getattr(error, "winerror", None) in {2, 3}:
                return None
            raise
        try:
            return self.identity(handle)
        finally:
            self.close_handle(handle)

    def create_temporary(self, directory_handle: int, leaf_name: str) -> int:
        return self._relative_open(
            directory_handle,
            leaf_name,
            desired_access=(
                self._FILE_READ_DATA
                | self._FILE_WRITE_DATA
                | self._FILE_READ_ATTRIBUTES
                | self._FILE_WRITE_ATTRIBUTES
                | self._DELETE
                | self._SYNCHRONIZE
            ),
            # Exclusive sharing prevents another process from reading,
            # replacing or unlinking the staged log before commit.
            share_access=0,
            disposition=self._FILE_CREATE,
            attributes=self._FILE_ATTRIBUTE_TEMPORARY,
        )

    def stream_from_handle(self, handle: int, mode: str) -> BinaryIO:
        flags = int(getattr(os, "O_BINARY", 0)) | (os.O_RDWR if "+" in mode else os.O_RDONLY)
        try:
            descriptor = int(self._msvcrt.open_osfhandle(handle, flags))
        except Exception:
            self.close_handle(handle)
            raise
        try:
            return cast(BinaryIO, os.fdopen(descriptor, mode))
        except Exception:
            os.close(descriptor)
            raise

    def raw_handle(self, stream: BinaryIO) -> int:
        return int(self._msvcrt.get_osfhandle(stream.fileno()))

    def rename_in_place(self, handle: int, leaf_name: str) -> None:
        encoded_name = leaf_name.encode("utf-16-le")
        file_name_offset = int(self._FileRenameInformation.FileName.offset)
        buffer_size = file_name_offset + len(encoded_name) + 2
        buffer = self._ctypes.create_string_buffer(buffer_size)
        information = self._FileRenameInformation.from_buffer(buffer)
        information.ReplaceIfExists = 1
        information.RootDirectory = None
        information.FileNameLength = len(encoded_name)
        self._ctypes.memmove(
            self._ctypes.addressof(buffer) + file_name_offset,
            encoded_name,
            len(encoded_name),
        )
        io_status = self._IoStatusBlock()
        status = int(
            self._ntdll.NtSetInformationFile(
                handle,
                self._ctypes.byref(io_status),
                buffer,
                buffer_size,
                self._FILE_RENAME_INFORMATION_CLASS,
            )
        )
        self._raise_nt_error(status)

    def duplicate_as_reader(self, handle: int) -> BinaryIO:
        process = self._kernel32.GetCurrentProcess()
        duplicate = self._wintypes.HANDLE()
        if not self._kernel32.DuplicateHandle(
            process,
            handle,
            process,
            self._ctypes.byref(duplicate),
            0,
            False,
            self._DUPLICATE_SAME_ACCESS,
        ):
            raise self._last_error()
        if duplicate.value is None:
            raise OSError("DuplicateHandle returned no handle")
        stream = self.stream_from_handle(int(duplicate.value), "rb")
        stream.seek(0)
        return stream

    def mark_delete(self, handle: int) -> None:
        disposition = self._FileDispositionInfo(True)
        if not self._kernel32.SetFileInformationByHandle(
            handle,
            self._FILE_DISPOSITION_INFO_CLASS,
            self._ctypes.byref(disposition),
            self._ctypes.sizeof(disposition),
        ):
            raise self._last_error()


_win32_api_instance: _Win32Api | None = None
_WIN32_API_LOCK = threading.Lock()


def _win32_api() -> _Win32Api:
    global _win32_api_instance
    with _WIN32_API_LOCK:
        if _win32_api_instance is None:
            _win32_api_instance = _Win32Api()
        return _win32_api_instance


class _Win32WriteAnchor:
    def __init__(self, destination: BoundWriteFile) -> None:
        api = _win32_api()
        try:
            handle = api.open_directory(destination._anchor)
        except FileNotFoundError as error:
            raise GrantError(
                "grant_resource_missing",
                "selected destination parent is no longer available",
            ) from error
        except OSError as error:
            raise GrantError(
                "grant_resource_changed",
                "selected destination parent changed after approval",
            ) from error
        try:
            if api.identity(handle) != destination._anchor_identity:
                raise GrantError(
                    "grant_resource_changed",
                    "selected destination parent changed after approval",
                )
        except Exception:
            api.close_handle(handle)
            raise
        self._api = api
        self._handle = handle

    def _validate_target(self, leaf_name: str, expected: _Identity | None) -> None:
        try:
            actual = self._api.relative_identity(self._handle, leaf_name)
        except OSError as error:
            raise GrantError(
                "grant_resource_changed",
                "selected destination changed after approval",
            ) from error
        if actual != expected:
            raise GrantError("grant_resource_changed", "selected destination changed after approval")
        if actual is not None and not stat.S_ISREG(actual[2]):
            raise GrantError("grant_resource_changed", "selected destination is not a regular file")

    def create_transaction(
        self,
        leaf_name: str,
        target_identity: _Identity | None,
    ) -> _AtomicWriteBackend:
        if self._handle < 0:
            raise ValueError("directory capability was already transferred")
        self._validate_target(leaf_name, target_identity)
        temporary_handle = -1
        for _attempt in range(32):
            try:
                temporary_handle = self._api.create_temporary(
                    self._handle,
                    f".pixelflasher-{secrets.token_hex(32)}.tmp",
                )
                break
            except OSError as error:
                if getattr(error, "winerror", None) in {80, 183}:
                    continue
                raise
        if temporary_handle < 0:
            raise FileExistsError("could not allocate a private atomic-write temporary")
        try:
            temporary_identity = self._api.identity(temporary_handle)
            if not stat.S_ISREG(temporary_identity[2]):
                raise GrantError("grant_resource_changed", "atomic-write temporary is not a regular file")
            stream = self._api.stream_from_handle(temporary_handle, "w+b")
        except Exception:
            try:
                self._api.mark_delete(temporary_handle)
            finally:
                self._api.close_handle(temporary_handle)
            raise
        directory_handle = self._handle
        self._handle = -1
        return _Win32AtomicWrite(
            self._api,
            directory_handle,
            leaf_name,
            target_identity,
            temporary_identity,
            stream,
        )

    def close(self) -> None:
        if self._handle >= 0:
            self._api.close_handle(self._handle)
            self._handle = -1


class _Win32AtomicWrite:
    def __init__(
        self,
        api: _Win32Api,
        directory_handle: int,
        leaf_name: str,
        target_identity: _Identity | None,
        temporary_identity: _Identity,
        stream: BinaryIO,
    ) -> None:
        self._api = api
        self._directory_handle = directory_handle
        self._leaf_name = leaf_name
        self._target_identity = target_identity
        self._temporary_identity = temporary_identity
        self._stream = stream
        self._committed = False
        self._closed = False

    @property
    def stream(self) -> BinaryIO:
        return self._stream

    @property
    def committed(self) -> bool:
        return self._committed

    def _validate_target(self) -> None:
        try:
            actual = self._api.relative_identity(self._directory_handle, self._leaf_name)
        except OSError as error:
            raise GrantError(
                "grant_resource_changed",
                "selected destination changed after approval",
            ) from error
        if actual != self._target_identity:
            raise GrantError("grant_resource_changed", "selected destination changed after approval")

    def commit(self) -> None:
        if self._closed:
            raise ValueError("atomic-write backend is closed")
        self._validate_target()
        handle = self._api.raw_handle(self._stream)
        if self._api.identity(handle) != self._temporary_identity:
            raise GrantError("grant_resource_changed", "atomic-write temporary changed before commit")
        # A simple name with RootDirectory=NULL tells NT to rename this open
        # file inside its current directory.  No pathname component is
        # resolved, even if the directory or one of its ancestors was swapped.
        self._api.rename_in_place(handle, self._leaf_name)
        self._committed = True

    def open_committed(self) -> BinaryIO:
        if not self._committed:
            raise ValueError("atomic write has not been committed")
        handle = self._api.raw_handle(self._stream)
        if self._api.identity(handle) != self._temporary_identity:
            raise GrantError(
                "grant_resource_changed",
                "written destination changed before verification",
            )
        return self._api.duplicate_as_reader(handle)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        cleanup_error: BaseException | None = None
        if not self._committed:
            try:
                self._api.mark_delete(self._api.raw_handle(self._stream))
            except BaseException as error:
                cleanup_error = error
        try:
            self._stream.close()
        finally:
            try:
                self._api.close_handle(self._directory_handle)
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
        if cleanup_error is not None:
            raise cleanup_error


def _open_bound_write_anchor(destination: BoundWriteFile) -> _WriteAnchor:
    if os.name == "nt":
        return _Win32WriteAnchor(destination)
    return _PosixWriteAnchor(destination)


@dataclass(frozen=True, slots=True)
class PathGrant:
    token: str
    purpose: str
    target: GrantTarget
    access: GrantAccess
    issued_at: float
    expires_at: float | None
    consume_once: bool
    _path: Path = field(repr=False)
    _anchor: Path = field(repr=False)
    _anchor_identity: tuple[int, int, int] = field(repr=False)
    _target_identity: tuple[int, int, int] | None = field(default=None, repr=False)

    def to_public_dict(self, *, now: float | None = None) -> dict[str, JSONValue]:
        remaining: int | None = None
        if self.expires_at is not None:
            current = time.monotonic() if now is None else now
            remaining = max(0, int(self.expires_at - current))
        return {
            "grant": self.token,
            "purpose": self.purpose,
            "target": self.target.value,
            "access": self.access.value,
            "consumeOnce": self.consume_once,
            "expiresInSeconds": remaining,
        }


class PathGrantStore:
    """Session-owned path grants with one-use write semantics."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        write_ttl_seconds: float = 300.0,
        maximum_grants: int = 256,
    ) -> None:
        if write_ttl_seconds <= 0:
            raise ValueError("write_ttl_seconds must be positive")
        if maximum_grants <= 0:
            raise ValueError("maximum_grants must be positive")
        self._clock = clock
        self._write_ttl_seconds = float(write_ttl_seconds)
        self._maximum_grants = int(maximum_grants)
        self._grants: dict[str, PathGrant] = {}
        self._lock = threading.RLock()

    def issue_file(
        self,
        path: str | Path,
        *,
        purpose: str,
        access: GrantAccess = GrantAccess.READ,
    ) -> PathGrant:
        return self._issue(path, purpose=purpose, target=GrantTarget.FILE, access=access)

    def issue_directory(
        self,
        path: str | Path,
        *,
        purpose: str,
        access: GrantAccess = GrantAccess.READ,
    ) -> PathGrant:
        return self._issue(
            path,
            purpose=purpose,
            target=GrantTarget.DIRECTORY,
            access=access,
        )

    def _issue(
        self,
        path: str | Path,
        *,
        purpose: str,
        target: GrantTarget,
        access: GrantAccess,
    ) -> PathGrant:
        purpose = _validate_purpose(purpose)
        if not isinstance(access, GrantAccess):
            raise TypeError("access must be GrantAccess")
        supplied = Path(path).expanduser()

        if access is GrantAccess.READ:
            try:
                resolved = supplied.resolve(strict=True)
            except (OSError, RuntimeError, ValueError) as error:
                raise GrantError(
                    "grant_resource_invalid",
                    "selected resource is unavailable",
                ) from error
            if target is GrantTarget.FILE and not resolved.is_file():
                raise GrantError("grant_target_mismatch", "selected resource is not a file")
            if target is GrantTarget.DIRECTORY and not resolved.is_dir():
                raise GrantError("grant_target_mismatch", "selected resource is not a directory")
            anchor = resolved
            target_identity = _identity(resolved)
            expires_at = None
            consume_once = False
        else:
            if target is GrantTarget.DIRECTORY:
                try:
                    resolved = supplied.resolve(strict=True)
                except (OSError, RuntimeError, ValueError) as error:
                    raise GrantError(
                        "grant_resource_invalid",
                        "selected resource is unavailable",
                    ) from error
                if not resolved.is_dir():
                    raise GrantError("grant_target_mismatch", "selected resource is not a directory")
                anchor = resolved
                target_identity = _identity(resolved)
            else:
                try:
                    parent = supplied.parent.resolve(strict=True)
                except (OSError, RuntimeError, ValueError) as error:
                    raise GrantError(
                        "grant_parent_invalid",
                        "selected destination has no valid parent",
                    ) from error
                if not parent.is_dir():
                    raise GrantError("grant_parent_invalid", "selected destination has no valid parent")
                resolved = parent / supplied.name
                if resolved.exists() and not resolved.is_file():
                    raise GrantError(
                        "grant_target_mismatch",
                        "selected destination is not a file",
                    )
                anchor = parent
                target_identity = _identity(resolved) if resolved.exists() else None
            expires_at = self._clock() + self._write_ttl_seconds
            consume_once = True

        grant = PathGrant(
            token=secrets.token_urlsafe(32),
            purpose=purpose,
            target=target,
            access=access,
            issued_at=self._clock(),
            expires_at=expires_at,
            consume_once=consume_once,
            _path=resolved,
            _anchor=anchor,
            _anchor_identity=_identity(anchor),
            _target_identity=target_identity,
        )
        with self._lock:
            self._purge_expired_locked()
            if len(self._grants) >= self._maximum_grants:
                raise GrantError("grant_capacity_reached", "too many active native resource grants")
            self._grants[grant.token] = grant
        return grant

    def resolve(
        self,
        token: str,
        *,
        purpose: str,
        target: GrantTarget,
        access: GrantAccess,
    ) -> Path:
        grant = self._resolve_grant(
            token,
            purpose=purpose,
            target=target,
            access=access,
        )
        return grant._path

    def resolve_bound_file(self, token: str, *, purpose: str) -> BoundReadFile:
        """Resolve a reusable read grant while retaining its approved identity."""

        grant = self._resolve_grant(
            token,
            purpose=purpose,
            target=GrantTarget.FILE,
            access=GrantAccess.READ,
        )
        if grant._target_identity is None:
            raise GrantError(
                "grant_resource_changed",
                "selected file changed after approval",
            )
        return BoundReadFile(grant._path, grant._target_identity)

    def resolve_bound_write_file(self, token: str, *, purpose: str) -> BoundWriteFile:
        """Consume and retain the identity of one approved write destination."""

        grant = self._resolve_grant(
            token,
            purpose=purpose,
            target=GrantTarget.FILE,
            access=GrantAccess.WRITE,
        )
        return BoundWriteFile(
            grant._path,
            grant._anchor,
            grant._anchor_identity,
            grant._target_identity,
        )

    def _resolve_grant(
        self,
        token: str,
        *,
        purpose: str,
        target: GrantTarget,
        access: GrantAccess,
    ) -> PathGrant:
        purpose = _validate_purpose(purpose)
        if not isinstance(target, GrantTarget) or not isinstance(access, GrantAccess):
            raise TypeError("target and access must use their grant enum types")
        with self._lock:
            grant = self._grants.get(str(token))
            if grant is None:
                raise GrantError("grant_not_found", "native resource grant is unknown or already consumed")
            if grant.expires_at is not None and self._clock() >= grant.expires_at:
                self._grants.pop(grant.token, None)
                raise GrantError("grant_expired", "native resource grant has expired")
            if grant.purpose != purpose:
                raise GrantError("grant_purpose_mismatch", "native resource grant has a different purpose")
            if grant.target is not target or grant.access is not access:
                raise GrantError("grant_scope_mismatch", "native resource grant has a different scope")
            if grant.consume_once:
                self._grants.pop(grant.token, None)

        self._revalidate(grant)
        return grant

    def revoke(self, token: str) -> bool:
        with self._lock:
            return self._grants.pop(str(token), None) is not None

    def revoke_purpose(self, purpose: str) -> int:
        """Revoke resources superseded by a newer native selection."""

        normalized = _validate_purpose(purpose)
        with self._lock:
            tokens = [token for token, grant in self._grants.items() if grant.purpose == normalized]
            for token in tokens:
                self._grants.pop(token, None)
        return len(tokens)

    def clear(self) -> None:
        with self._lock:
            self._grants.clear()

    def _revalidate(self, grant: PathGrant) -> None:
        try:
            if _identity(grant._anchor) != grant._anchor_identity:
                raise GrantError("grant_resource_changed", "selected resource changed after approval")
            if grant.target is GrantTarget.FILE and grant.access is GrantAccess.READ:
                if not grant._path.is_file() or _identity(grant._path) != grant._target_identity:
                    raise GrantError("grant_resource_changed", "selected file changed after approval")
            elif grant.target is GrantTarget.DIRECTORY:
                if not grant._path.is_dir() or _identity(grant._path) != grant._target_identity:
                    raise GrantError("grant_resource_changed", "selected directory changed after approval")
            elif grant.target is GrantTarget.FILE and grant.access is GrantAccess.WRITE:
                exists = grant._path.exists()
                if exists != (grant._target_identity is not None):
                    raise GrantError(
                        "grant_resource_changed",
                        "selected destination changed after approval",
                    )
                if exists and _identity(grant._path) != grant._target_identity:
                    raise GrantError(
                        "grant_resource_changed",
                        "selected destination changed after approval",
                    )
        except FileNotFoundError as error:
            raise GrantError("grant_resource_missing", "selected resource no longer exists") from error

    def _purge_expired_locked(self) -> None:
        now = self._clock()
        expired = [
            token for token, grant in self._grants.items() if grant.expires_at is not None and now >= grant.expires_at
        ]
        for token in expired:
            self._grants.pop(token, None)


@dataclass(frozen=True, slots=True)
class SecretGrant:
    token: str
    purpose: str
    issued_at: float
    expires_at: float
    _secret: SensitiveText = field(repr=False)

    def to_public_dict(self, *, now: float | None = None) -> dict[str, JSONValue]:
        current = time.monotonic() if now is None else now
        return {
            "grant": self.token,
            "purpose": self.purpose,
            "consumeOnce": True,
            "expiresInSeconds": max(0, int(self.expires_at - current)),
        }


class SecretGrantStore:
    """Small one-use vault for credentials crossing the native bridge."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        ttl_seconds: float = 60.0,
        maximum_grants: int = 32,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if maximum_grants <= 0:
            raise ValueError("maximum_grants must be positive")
        self._clock = clock
        self._ttl_seconds = float(ttl_seconds)
        self._maximum_grants = int(maximum_grants)
        self._grants: dict[str, SecretGrant] = {}
        self._lock = threading.RLock()

    def issue(self, secret: str, *, purpose: str) -> SecretGrant:
        purpose = _validate_purpose(purpose)
        if not isinstance(secret, str) or not secret:
            raise ValueError("secret must be a non-empty string")
        now = self._clock()
        grant = SecretGrant(
            token=secrets.token_urlsafe(32),
            purpose=purpose,
            issued_at=now,
            expires_at=now + self._ttl_seconds,
            _secret=SensitiveText(secret),
        )
        with self._lock:
            self._purge_expired_locked()
            if len(self._grants) >= self._maximum_grants:
                raise GrantError("grant_capacity_reached", "too many active secret grants")
            self._grants[grant.token] = grant
        return grant

    def consume(self, token: str, *, purpose: str) -> SensitiveText:
        purpose = _validate_purpose(purpose)
        with self._lock:
            grant = self._grants.pop(str(token), None)
        if grant is None:
            raise GrantError("grant_not_found", "secret grant is unknown or already consumed")
        if self._clock() >= grant.expires_at:
            raise GrantError("grant_expired", "secret grant has expired")
        if grant.purpose != purpose:
            raise GrantError("grant_purpose_mismatch", "secret grant has a different purpose")
        return grant._secret

    def revoke(self, token: str) -> bool:
        with self._lock:
            return self._grants.pop(str(token), None) is not None

    def clear(self) -> None:
        with self._lock:
            self._grants.clear()

    def _purge_expired_locked(self) -> None:
        now = self._clock()
        for token in [token for token, grant in self._grants.items() if now >= grant.expires_at]:
            self._grants.pop(token, None)
