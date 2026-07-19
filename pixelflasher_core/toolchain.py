"""Platform-tools discovery and version validation without presentation imports."""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from .contracts import ProcessRequest, ToolchainInfo
from .executor import CancellationToken, ProcessTransport, SubprocessTransport

_VERSION_PATTERN = re.compile(r"(?<!\d)(\d+)\.(\d+)\.(\d+)(?:[-\w.]*)?")


def parse_platform_tools_version(output: str) -> tuple[int, int, int] | None:
    """Return the most relevant semantic version from adb/fastboot output."""

    matches = [
        (int(match.group(1)), int(match.group(2)), int(match.group(3)))
        for match in _VERSION_PATTERN.finditer(output)
    ]
    if not matches:
        return None
    # adb prints protocol version 1.0.41 before the package version. The
    # platform-tools package version is the highest semantic version present.
    return max(matches)


def format_platform_tools_version(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


@dataclass(frozen=True, slots=True)
class ToolchainCheck:
    info: ToolchainInfo
    code: str = "ok"
    message: str = ""

    @property
    def ok(self) -> bool:
        return self.info.ready and self.code == "ok"


class ToolchainService:
    """Locate adb/fastboot together and reject missing, stale, or mixed pairs."""

    def __init__(
        self,
        transport: ProcessTransport | None = None,
        *,
        configured_path: str | os.PathLike[str] | None = None,
        minimum_version: tuple[int, int, int] = (33, 0, 3),
        version_timeout_seconds: float = 5.0,
    ) -> None:
        self.transport = transport or SubprocessTransport()
        self.configured_path = Path(configured_path).expanduser() if configured_path else None
        self.minimum_version = minimum_version
        self.version_timeout_seconds = version_timeout_seconds

    def discover(
        self,
        configured_path: str | os.PathLike[str] | None = None,
        *,
        cancellation: CancellationToken | None = None,
    ) -> ToolchainCheck:
        token = cancellation or CancellationToken()
        requested = Path(configured_path).expanduser() if configured_path else self.configured_path
        resolved = self._resolve_pair(requested)
        if isinstance(resolved, ToolchainCheck):
            return resolved
        adb, fastboot = resolved

        adb_check = self._read_version(adb, (str(adb), "version"), token)
        if isinstance(adb_check, ToolchainCheck):
            return adb_check
        fastboot_check = self._read_version(fastboot, (str(fastboot), "--version"), token)
        if isinstance(fastboot_check, ToolchainCheck):
            return fastboot_check
        adb_version, fastboot_version = adb_check, fastboot_check

        if adb_version != fastboot_version:
            return ToolchainCheck(
                ToolchainInfo(str(adb), str(fastboot), "", False),
                "tool_version_mismatch",
                (
                    f"adb {format_platform_tools_version(adb_version)} and fastboot "
                    f"{format_platform_tools_version(fastboot_version)} are from different releases"
                ),
            )
        if adb_version < self.minimum_version:
            return ToolchainCheck(
                ToolchainInfo(
                    str(adb),
                    str(fastboot),
                    format_platform_tools_version(adb_version),
                    False,
                ),
                "tool_version_unsupported",
                (
                    f"platform-tools {format_platform_tools_version(adb_version)} is older than "
                    f"{format_platform_tools_version(self.minimum_version)}"
                ),
            )
        return ToolchainCheck(
            ToolchainInfo(
                str(adb),
                str(fastboot),
                format_platform_tools_version(adb_version),
                True,
            )
        )

    def _resolve_pair(
        self,
        configured_path: Path | None,
    ) -> tuple[Path, Path] | ToolchainCheck:
        if configured_path is not None:
            candidate = configured_path.resolve()
            if not candidate.exists():
                return ToolchainCheck(
                    ToolchainInfo(),
                    "toolchain_path_invalid",
                    f"platform-tools path does not exist: {candidate}",
                )
            directory = candidate if candidate.is_dir() else candidate.parent
            adb = self._tool_in_directory(directory, "adb")
            fastboot = self._tool_in_directory(directory, "fastboot")
        else:
            adb_match = shutil.which("adb")
            fastboot_match = shutil.which("fastboot")
            adb = Path(adb_match).resolve() if adb_match else None
            fastboot = Path(fastboot_match).resolve() if fastboot_match else None

        if adb is None or fastboot is None or not adb.is_file() or not fastboot.is_file():
            return ToolchainCheck(
                ToolchainInfo(str(adb or ""), str(fastboot or ""), "", False),
                "tool_missing",
                "adb and fastboot must both be present in the same configured toolchain or PATH",
            )
        if adb.parent != fastboot.parent:
            return ToolchainCheck(
                ToolchainInfo(str(adb), str(fastboot), "", False),
                "toolchain_directory_mismatch",
                "adb and fastboot must come from the same Platform Tools directory",
            )
        if os.name != "nt" and (not os.access(adb, os.X_OK) or not os.access(fastboot, os.X_OK)):
            return ToolchainCheck(
                ToolchainInfo(str(adb), str(fastboot), "", False),
                "tool_not_executable",
                "adb and fastboot must be executable",
            )
        return adb, fastboot

    @staticmethod
    def _tool_in_directory(directory: Path, name: str) -> Path | None:
        candidates = (directory / f"{name}.exe", directory / name)
        return next((candidate.resolve() for candidate in candidates if candidate.is_file()), None)

    def _read_version(
        self,
        executable: Path,
        argv: tuple[str, ...],
        cancellation: CancellationToken,
    ) -> tuple[int, int, int] | ToolchainCheck:
        empty = ToolchainInfo(
            str(executable) if executable.name.lower().startswith("adb") else "",
            str(executable) if executable.name.lower().startswith("fastboot") else "",
            "",
            False,
        )
        if cancellation.cancelled:
            return ToolchainCheck(empty, "cancelled", "toolchain validation was cancelled")
        try:
            outcome = self.transport.run(
                ProcessRequest(argv, timeout_seconds=self.version_timeout_seconds),
                cancellation,
            )
        except Exception as error:
            return ToolchainCheck(
                empty,
                "tool_execution_failed",
                f"could not execute {executable.name}: {error}",
            )
        if outcome.cancelled or cancellation.cancelled:
            return ToolchainCheck(empty, "cancelled", "toolchain validation was cancelled")
        if outcome.timed_out:
            return ToolchainCheck(empty, "tool_timeout", f"{executable.name} version check timed out")
        if outcome.returncode != 0:
            return ToolchainCheck(
                empty,
                "tool_version_failed",
                f"{executable.name} version check exited with status {outcome.returncode}",
            )
        output = f"{outcome.stdout}\n{outcome.stderr}"
        expected_marker = (
            "Android Debug Bridge version"
            if executable.stem.casefold() == "adb"
            else "fastboot version"
        )
        version = parse_platform_tools_version(output)
        if version is None:
            return ToolchainCheck(
                empty,
                "tool_version_malformed",
                f"could not parse {executable.name} version output",
            )
        if expected_marker.casefold() not in output.casefold():
            return ToolchainCheck(
                empty,
                "tool_version_unverified",
                f"{executable.name} did not provide recognizable version evidence",
            )
        return version


# Concise public name retained alongside the explicit service name.
Toolchain = ToolchainService
