"""Closed packaged pseudo-terminal smoke contract.

The public ADB terminal service can launch only ``adb -s SERIAL shell``.  This
diagnostic exercises the same packaged PTY adapter without Android hardware by
launching one fixed, read-only operating-system identity executable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import tempfile
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from constants import VERSION
from pixelflasher_core.adb_terminal import (
    TerminalBackend,
    TerminalProcess,
    WindowsConPtyBackend,
    native_terminal_backend,
)
from smoke_receipt_schema import (
    PTY_SMOKE_MAXIMUM_OUTPUT_BYTES,
    PTY_SMOKE_SCHEMA_VERSION,
    PtySmokeError,
    load_pty_smoke_receipt,
    validate_pty_smoke_receipt,
)
from ui_smoke_contract import normalized_architecture, normalized_platform


def fixed_probe_argv() -> tuple[str, ...]:
    """Return one fixed read-only executable and never caller-provided argv."""

    if sys.platform.startswith("win"):
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        executable = system_root / "System32" / "whoami.exe"
    else:
        executable = Path("/usr/bin/id")
    if not executable.is_file():
        raise PtySmokeError("the fixed PTY smoke executable is unavailable")
    return (str(executable),)


def execute_pty_probe(
    backend: TerminalBackend,
    argv: tuple[str, ...],
    *,
    timeout_seconds: float,
) -> tuple[bytes, int]:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 1 <= timeout_seconds <= 30
    ):
        raise PtySmokeError("PTY smoke timeout must be between 1 and 30 seconds")
    if len(argv) != 1 or not Path(argv[0]).is_file():
        raise PtySmokeError("PTY smoke argv must contain one existing executable")

    completed = threading.Event()
    output = bytearray()
    output_lock = threading.RLock()
    exit_code: list[int | None] = []
    overflow = False

    def on_output(chunk: bytes) -> None:
        nonlocal overflow
        if not isinstance(chunk, bytes) or not chunk:
            return
        with output_lock:
            remaining = PTY_SMOKE_MAXIMUM_OUTPUT_BYTES - len(output)
            if len(chunk) > remaining:
                overflow = True
                return
            output.extend(chunk)

    def on_exit(code: int | None) -> None:
        exit_code.append(code)
        completed.set()

    process: TerminalProcess | None = None
    started = threading.Event()
    abandoned = threading.Event()
    start_lock = threading.RLock()
    started_processes: list[TerminalProcess] = []
    start_errors: list[Exception] = []

    def start_process() -> None:
        try:
            candidate = backend.start(
                argv,
                columns=80,
                rows=24,
                on_output=on_output,
                on_exit=on_exit,
            )
        except Exception as exc:
            start_errors.append(exc)
        else:
            with start_lock:
                clean_up = abandoned.is_set()
                if not clean_up:
                    started_processes.append(candidate)
            if clean_up:
                try:
                    candidate.terminate()
                except Exception:
                    pass
        finally:
            started.set()

    started_at = time.monotonic()
    cleanup_error: Exception | None = None
    try:
        threading.Thread(
            target=start_process,
            name="PixelFlasherPtySmokeStart",
            daemon=True,
        ).start()
        if not started.wait(float(timeout_seconds)):
            with start_lock:
                abandoned.set()
                late_processes = tuple(started_processes)
                started_processes.clear()
            for late_process in late_processes:
                try:
                    late_process.terminate()
                except Exception:
                    pass
            raise PtySmokeError("packaged PTY process start timed out")
        if start_errors:
            raise PtySmokeError("packaged PTY process could not be started") from start_errors[0]
        if len(started_processes) != 1:
            raise PtySmokeError("packaged PTY process start did not return one process")
        process = started_processes[0]
        remaining = float(timeout_seconds) - (time.monotonic() - started_at)
        if remaining <= 0 or not completed.wait(remaining):
            raise PtySmokeError("packaged PTY process timed out")
    except PtySmokeError:
        raise
    except Exception as exc:
        raise PtySmokeError("packaged PTY process could not be started") from exc
    finally:
        if process is not None:
            try:
                process.terminate()
            except Exception as exc:
                cleanup_error = exc

    if cleanup_error is not None:
        raise PtySmokeError("packaged PTY process cleanup failed") from cleanup_error

    with output_lock:
        captured = bytes(output)
    if overflow:
        raise PtySmokeError("packaged PTY output exceeded its bound")
    if exit_code != [0]:
        raise PtySmokeError("packaged PTY process did not exit successfully")
    if not captured.strip():
        raise PtySmokeError("packaged PTY process produced no output")
    return captured, 0


def create_pty_smoke_receipt(
    *,
    backend: str,
    probe_executable: str,
    output: bytes,
    exit_code: int,
) -> dict[str, Any]:
    if backend not in {"conpty", "posix-pty"}:
        raise PtySmokeError("PTY backend is invalid")
    if probe_executable not in {"whoami.exe", "id"}:
        raise PtySmokeError("PTY probe executable is invalid")
    if not output or len(output) > PTY_SMOKE_MAXIMUM_OUTPUT_BYTES:
        raise PtySmokeError("PTY smoke output is invalid")
    if exit_code != 0:
        raise PtySmokeError("PTY smoke exit code is invalid")
    return {
        "schemaVersion": PTY_SMOKE_SCHEMA_VERSION,
        "status": "passed",
        "applicationVersion": VERSION,
        "platform": normalized_platform(),
        "architecture": normalized_architecture(),
        "processBits": struct.calcsize("P") * 8,
        "backend": backend,
        "probeExecutable": probe_executable,
        "outputBytes": len(output),
        "outputSha256": hashlib.sha256(output).hexdigest(),
        "exitCode": exit_code,
        "outputObserved": True,
        "cleanShutdown": True,
    }


def write_pty_smoke_receipt(path: Path, receipt: dict[str, Any]) -> None:
    validate_pty_smoke_receipt(receipt)
    destination = path.expanduser().absolute()
    parent = destination.parent
    if destination.exists() and destination.is_symlink():
        raise PtySmokeError("PTY smoke receipt destination cannot be a symlink")
    if not parent.is_dir() or parent.is_symlink():
        raise PtySmokeError("PTY smoke receipt parent must be a real directory")
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
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def run_packaged_pty_smoke(report: Path, *, timeout_seconds: float = 10) -> dict[str, Any]:
    backend = native_terminal_backend()
    argv = fixed_probe_argv()
    output, exit_code = execute_pty_probe(backend, argv, timeout_seconds=timeout_seconds)
    backend_name = "conpty" if isinstance(backend, WindowsConPtyBackend) else "posix-pty"
    receipt = create_pty_smoke_receipt(
        backend=backend_name,
        probe_executable=Path(argv[0]).name,
        output=output,
        exit_code=exit_code,
    )
    write_pty_smoke_receipt(report, receipt)
    return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pty-smoke-report", type=Path, required=True)
    parser.add_argument("--pty-smoke-timeout", type=float, default=10)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        receipt = run_packaged_pty_smoke(
            args.pty_smoke_report,
            timeout_seconds=args.pty_smoke_timeout,
        )
    except PtySmokeError as exc:
        print(f"Packaged PTY smoke failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "PTY_SMOKE_MAXIMUM_OUTPUT_BYTES",
    "PTY_SMOKE_SCHEMA_VERSION",
    "PtySmokeError",
    "create_pty_smoke_receipt",
    "execute_pty_probe",
    "fixed_probe_argv",
    "load_pty_smoke_receipt",
    "run_packaged_pty_smoke",
    "validate_pty_smoke_receipt",
    "write_pty_smoke_receipt",
]
