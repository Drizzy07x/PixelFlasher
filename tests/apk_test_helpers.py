"""Small verified-identity test double for services consuming APK inspection."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol

from pixelflasher_core.apk_inspection import ApkIdentity, ApkInspectionError


class _CancellationProbe(Protocol):
    @property
    def cancelled(self) -> bool: ...


class FakeVerifiedApkInspector:
    """Return a typed verified identity while keeping cryptography unit-local."""

    def __init__(
        self,
        package_name: str = "org.pixelflasher.test",
        *,
        package_names: Mapping[str | os.PathLike[str], str] | None = None,
        error: ApkInspectionError | None = None,
        identity_sha256: str | None = None,
    ) -> None:
        self.package_name = package_name
        self.package_names = {
            os.path.normcase(str(Path(path).resolve())): value for path, value in (package_names or {}).items()
        }
        self.error = error
        self.identity_sha256 = identity_sha256

    def inspect(
        self,
        path: str | os.PathLike[str],
        *,
        cancellation: _CancellationProbe | None = None,
    ) -> ApkIdentity:
        _ = cancellation
        if self.error is not None:
            raise self.error
        source = Path(path).resolve(strict=True)
        package_name = self.package_names.get(
            os.path.normcase(str(source)),
            self.package_name,
        )
        return ApkIdentity(
            package_name=package_name,
            sha256=(
                self.identity_sha256
                if self.identity_sha256 is not None
                else hashlib.sha256(source.read_bytes()).hexdigest()
            ),
            signer_sha256=("a" * 64,),
            schemes=("v2",),
            verified=True,
        )


__all__ = ["FakeVerifiedApkInspector"]
