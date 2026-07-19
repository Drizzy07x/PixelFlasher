"""Opaque, purpose-bound grants for native resources and ephemeral secrets.

The WebView is intentionally never trusted with filesystem paths or long-lived
credentials.  A native host issues an opaque token after the user selects a
resource; backend services resolve that token only for the exact command
purpose for which it was created.
"""

from __future__ import annotations

import os
import secrets
import stat
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO

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


def _validate_purpose(purpose: str) -> str:
    normalized = str(purpose).strip()
    if not normalized or len(normalized) > 128 or "\x00" in normalized:
        raise ValueError("purpose must be a non-empty, NUL-free string up to 128 characters")
    return normalized


def _identity(path: Path) -> tuple[int, int, int]:
    info = path.stat()
    return _stat_identity(info)


def _stat_identity(info: os.stat_result) -> tuple[int, int, int]:
    return (int(info.st_dev), int(info.st_ino), stat.S_IFMT(info.st_mode))


@dataclass(frozen=True, slots=True)
class BoundReadFile:
    """A native-file selection bound to the resource approved by the user."""

    path: Path = field(repr=False)
    _target_identity: tuple[int, int, int] = field(repr=False)

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
            resolved = supplied.resolve(strict=True)
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
                resolved = supplied.resolve(strict=True)
                if not resolved.is_dir():
                    raise GrantError("grant_target_mismatch", "selected resource is not a directory")
                anchor = resolved
                target_identity = _identity(resolved)
            else:
                parent = supplied.parent.resolve(strict=True)
                if not parent.is_dir():
                    raise GrantError("grant_parent_invalid", "selected destination has no valid parent")
                resolved = parent / supplied.name
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
            tokens = [
                token
                for token, grant in self._grants.items()
                if grant.purpose == normalized
            ]
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
            token
            for token, grant in self._grants.items()
            if grant.expires_at is not None and now >= grant.expires_at
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
