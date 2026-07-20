"""Closed packaged smoke for the isolated Legacy Raw host-shell boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, cast

from constants import VERSION
from pixelflasher_core import (
    AppCommand,
    CancellationToken,
    CommandExecutor,
    MyToolsError,
    MyToolsRepository,
    MyToolsService,
    PathGrantStore,
)
from ui_smoke_contract import normalized_architecture, normalized_platform

LEGACY_RAW_SMOKE_SCHEMA_VERSION = 2
LEGACY_RAW_SMOKE_MAXIMUM_OUTPUT_BYTES = 64 * 1024


class LegacyRawSmokeError(ValueError):
    """The packaged Legacy Raw probe or its receipt is invalid."""


def fixed_probe_executable() -> Path:
    if sys.platform.startswith("win"):
        executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "whoami.exe"
    else:
        executable = Path("/usr/bin/id")
    if not executable.is_file():
        raise LegacyRawSmokeError("the fixed Legacy Raw smoke executable is unavailable")
    return executable.resolve(strict=True)


def create_legacy_raw_smoke_receipt(
    *,
    shell: str,
    probe_executable: str,
    output: bytes,
    safe_output: bytes,
    safe_profile_reloaded: bool,
) -> dict[str, Any]:
    if shell not in {"cmd", "zsh", "sh"}:
        raise LegacyRawSmokeError("Legacy Raw shell is invalid")
    if probe_executable not in {"whoami.exe", "id"}:
        raise LegacyRawSmokeError("Legacy Raw probe executable is invalid")
    if not output or len(output) > LEGACY_RAW_SMOKE_MAXIMUM_OUTPUT_BYTES:
        raise LegacyRawSmokeError("Legacy Raw smoke output is invalid")
    if not safe_output or len(safe_output) > LEGACY_RAW_SMOKE_MAXIMUM_OUTPUT_BYTES:
        raise LegacyRawSmokeError("safe argv smoke output is invalid")
    if safe_profile_reloaded is not True:
        raise LegacyRawSmokeError("safe argv profile reload was not proven")
    safe_probe = "whoami-user" if normalized_platform() == "windows" else "id-effective-user"
    return {
        "schemaVersion": LEGACY_RAW_SMOKE_SCHEMA_VERSION,
        "status": "passed",
        "applicationVersion": VERSION,
        "platform": normalized_platform(),
        "architecture": normalized_architecture(),
        "processBits": struct.calcsize("P") * 8,
        "shell": shell,
        "probeExecutable": probe_executable,
        "outputBytes": len(output),
        "outputSha256": hashlib.sha256(output).hexdigest(),
        "safeArgvProbe": safe_probe,
        "safeArgvOutputBytes": len(safe_output),
        "safeArgvOutputSha256": hashlib.sha256(safe_output).hexdigest(),
        "safeArgvProfileReloaded": safe_profile_reloaded,
        "safeArgvNoShell": True,
        "safeArgvCompleted": True,
        "persistentPermission": True,
        "incorrectPermissionRejected": True,
        "incorrectRunRejected": True,
        "exactRunCompleted": True,
        "cleanShutdown": True,
    }


def validate_legacy_raw_smoke_receipt(
    receipt: dict[str, Any],
    *,
    expected_platform: str | None = None,
    expected_architecture: str | None = None,
) -> dict[str, Any]:
    expected_keys = {
        "schemaVersion",
        "status",
        "applicationVersion",
        "platform",
        "architecture",
        "processBits",
        "shell",
        "probeExecutable",
        "outputBytes",
        "outputSha256",
        "safeArgvProbe",
        "safeArgvOutputBytes",
        "safeArgvOutputSha256",
        "safeArgvProfileReloaded",
        "safeArgvNoShell",
        "safeArgvCompleted",
        "persistentPermission",
        "incorrectPermissionRejected",
        "incorrectRunRejected",
        "exactRunCompleted",
        "cleanShutdown",
    }
    if set(receipt) != expected_keys:
        raise LegacyRawSmokeError("Legacy Raw receipt fields do not match the closed schema")
    if (
        receipt.get("schemaVersion") != LEGACY_RAW_SMOKE_SCHEMA_VERSION
        or receipt.get("status") != "passed"
        or not isinstance(receipt.get("applicationVersion"), str)
        or not receipt["applicationVersion"]
        or receipt.get("processBits") not in {32, 64}
    ):
        raise LegacyRawSmokeError("Legacy Raw receipt identity is invalid")
    platform_name = receipt.get("platform")
    shell = receipt.get("shell")
    executable = receipt.get("probeExecutable")
    safe_probe = receipt.get("safeArgvProbe")
    expected_shell = "cmd" if platform_name == "windows" else "zsh" if platform_name == "macos" else "sh"
    if platform_name not in {"windows", "macos", "linux"}:
        raise LegacyRawSmokeError("Legacy Raw receipt platform is invalid")
    if shell != expected_shell or executable != ("whoami.exe" if platform_name == "windows" else "id"):
        raise LegacyRawSmokeError("Legacy Raw receipt did not prove the native host shell")
    if safe_probe != ("whoami-user" if platform_name == "windows" else "id-effective-user"):
        raise LegacyRawSmokeError("personal tools receipt did not prove the native safe argv probe")
    size = receipt.get("outputBytes")
    digest = receipt.get("outputSha256")
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or not 1 <= size <= LEGACY_RAW_SMOKE_MAXIMUM_OUTPUT_BYTES
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise LegacyRawSmokeError("Legacy Raw receipt output evidence is invalid")
    safe_size = receipt.get("safeArgvOutputBytes")
    safe_digest = receipt.get("safeArgvOutputSha256")
    if (
        isinstance(safe_size, bool)
        or not isinstance(safe_size, int)
        or not 1 <= safe_size <= LEGACY_RAW_SMOKE_MAXIMUM_OUTPUT_BYTES
        or not isinstance(safe_digest, str)
        or len(safe_digest) != 64
        or any(character not in "0123456789abcdef" for character in safe_digest)
    ):
        raise LegacyRawSmokeError("safe argv receipt output evidence is invalid")
    for field in (
        "safeArgvProfileReloaded",
        "safeArgvNoShell",
        "safeArgvCompleted",
        "persistentPermission",
        "incorrectPermissionRejected",
        "incorrectRunRejected",
        "exactRunCompleted",
        "cleanShutdown",
    ):
        if receipt.get(field) is not True:
            raise LegacyRawSmokeError(f"Legacy Raw receipt did not prove {field}")
    if expected_platform is not None and platform_name != expected_platform:
        raise LegacyRawSmokeError(f"expected platform {expected_platform!r}, got {platform_name!r}")
    if expected_architecture is not None and receipt.get("architecture") != expected_architecture:
        raise LegacyRawSmokeError(
            f"expected architecture {expected_architecture!r}, got {receipt.get('architecture')!r}"
        )
    return dict(receipt)


def load_legacy_raw_smoke_receipt(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LegacyRawSmokeError("Legacy Raw smoke receipt is missing or invalid JSON") from exc
    if not isinstance(value, dict):
        raise LegacyRawSmokeError("Legacy Raw smoke receipt must be a JSON object")
    return cast(dict[str, Any], value)


def write_legacy_raw_smoke_receipt(path: Path, receipt: dict[str, Any]) -> None:
    validate_legacy_raw_smoke_receipt(receipt)
    destination = path.expanduser().absolute()
    parent = destination.parent
    if destination.exists() and destination.is_symlink():
        raise LegacyRawSmokeError("Legacy Raw receipt destination cannot be a symlink")
    if not parent.is_dir() or parent.is_symlink():
        raise LegacyRawSmokeError("Legacy Raw receipt parent must be a real directory")
    payload = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    descriptor, name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        if os.name != "nt":
            directory_descriptor = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def _expect_error(action: Callable[[], object], code: str) -> None:
    try:
        action()
    except MyToolsError as exc:
        if exc.code == code:
            return
        raise LegacyRawSmokeError("Legacy Raw smoke returned an unexpected policy error") from exc
    raise LegacyRawSmokeError("Legacy Raw smoke accepted an incorrect confirmation")


def run_packaged_legacy_raw_smoke(report: Path) -> dict[str, Any]:
    executable = fixed_probe_executable()
    with tempfile.TemporaryDirectory(prefix="pixelflasher-legacy-raw-smoke-") as directory:
        root = Path(directory).resolve(strict=True)
        command_executable = executable
        if os.name == "nt":
            spaced_directory = root / "probe with spaces"
            spaced_directory.mkdir()
            command_executable = spaced_directory / executable.name
            shutil.copyfile(executable, command_executable)
        legacy = root / "mytools.json"
        store = root / "my-tools-v2.json"
        legacy.write_text(
            json.dumps(
                {
                    "tools": {
                        "smoke": {
                            "title": "Packaged Legacy Raw smoke",
                            "command": str(command_executable),
                            "arguments": "",
                            "directory": str(root),
                            "enabled": True,
                        }
                    }
                }
            ),
            encoding="iso-8859-1",
        )
        service = MyToolsService(
            MyToolsRepository(store, legacy_path=legacy),
            CommandExecutor(),
            allowed_legacy_cwd_roots=(root,),
        )
        grants = PathGrantStore()
        safe_grant = grants.issue_file(executable, purpose="tools.myTools.executable")
        safe_spec = service.repository.save(
            title="Packaged safe argv smoke",
            executable=grants.resolve_bound_file(
                safe_grant.token,
                purpose="tools.myTools.executable",
            ),
            arguments=("/user", "/fo", "csv", "/nh") if os.name == "nt" else ("-u",),
            enabled=True,
        )
        service = MyToolsService(
            MyToolsRepository(store, legacy_path=legacy),
            CommandExecutor(),
            allowed_legacy_cwd_roots=(root,),
        )
        safe_spec = service.repository.get(safe_spec.tool_id)
        safe_result = service.run(
            AppCommand(
                "tools.myTools",
                expected_revision=0,
                payload={"action": "run", "toolId": safe_spec.tool_id},
                operation_id="packaged-safe-argv-smoke",
            ),
            safe_spec.tool_id,
            CancellationToken(),
        )
        safe_output = safe_result.stdout.encode("utf-8", errors="replace")
        if not safe_result.ok or safe_result.code != "my_tool_completed" or not safe_output.strip():
            raise LegacyRawSmokeError("packaged safe argv personal tool did not complete successfully")
        spec = service.repository.get_legacy("legacy:smoke")
        _expect_error(
            lambda: service.set_legacy_permission(
                spec.legacy_id,
                granted=True,
                confirmation_text="ALLOW RAW WRONG",
            ),
            "legacy_raw_permission_confirmation_required",
        )
        service.set_legacy_permission(
            spec.legacy_id,
            granted=True,
            confirmation_text=service.legacy_permission_confirmation(spec),
        )
        service = MyToolsService(
            MyToolsRepository(store, legacy_path=legacy),
            CommandExecutor(),
            allowed_legacy_cwd_roots=(root,),
        )
        spec = service.repository.get_legacy(spec.legacy_id)
        if not spec.permission_granted:
            raise LegacyRawSmokeError("Legacy Raw permission did not survive repository reload")
        command = AppCommand(
            "tools.myTools.legacyRun",
            expected_revision=0,
            payload={"toolId": spec.legacy_id},
            operation_id="packaged-legacy-raw-smoke",
        )
        _expect_error(
            lambda: service.run_legacy(
                command,
                spec.legacy_id,
                "RUN RAW WRONG",
                CancellationToken(),
            ),
            "legacy_raw_run_confirmation_required",
        )
        result = service.run_legacy(
            command,
            spec.legacy_id,
            service.legacy_run_confirmation(spec),
            CancellationToken(),
        )
        output = result.stdout.encode("utf-8", errors="replace")
        if not result.ok or result.code != "legacy_raw_completed" or not output.strip():
            raise LegacyRawSmokeError("packaged Legacy Raw command did not complete successfully")
        shell = "cmd" if os.name == "nt" else "zsh" if sys.platform == "darwin" else "sh"
        receipt = create_legacy_raw_smoke_receipt(
            shell=shell,
            probe_executable=executable.name,
            output=output,
            safe_output=safe_output,
            safe_profile_reloaded=True,
        )
    write_legacy_raw_smoke_receipt(report, receipt)
    return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-raw-smoke-report", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        receipt = run_packaged_legacy_raw_smoke(args.legacy_raw_smoke_report)
    except LegacyRawSmokeError as exc:
        print(f"Packaged Legacy Raw smoke failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "LEGACY_RAW_SMOKE_MAXIMUM_OUTPUT_BYTES",
    "LEGACY_RAW_SMOKE_SCHEMA_VERSION",
    "LegacyRawSmokeError",
    "create_legacy_raw_smoke_receipt",
    "fixed_probe_executable",
    "load_legacy_raw_smoke_receipt",
    "run_packaged_legacy_raw_smoke",
    "validate_legacy_raw_smoke_receipt",
    "write_legacy_raw_smoke_receipt",
]
