"""Headless, fail-closed compilation for bounded Android utility commands.

The WebView supplies semantic intent only.  This service resolves the selected
device and validated toolchain from :class:`AppSnapshot`, validates a small
allow-list of options, and emits argv-only :class:`OperationPlan` instances.
It deliberately does not expose a general-purpose ADB shell.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ElementTree
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Protocol, cast

from .contracts import (
    AppCommand,
    AppSnapshot,
    DeviceInfo,
    FileArtifact,
    OperationPlan,
    OperationPostcondition,
    OperationResult,
    OperationRisk,
    OperationStatus,
    ProcessRequest,
    ProgressPhase,
    SensitiveText,
)
from .executor import CancellationReason, CancellationToken, TransportOutcome
from .grants import (
    AtomicWriteOutcomeUnknownError,
    BoundReadFile,
    BoundWriteFile,
    GrantError,
)

DEVICE_TOOL_COMMANDS = frozenset(
    {
        "tools.logcat",
        "tools.pushFiles",
        "tools.adbShell",
        "tools.scrcpy",
        "tools.wifi",
        "tools.wifi.status",
        "tools.wifi.discover",
        "device.inspect",
    }
)

_LOGCAT_BUFFERS = frozenset({"main", "system", "radio", "events", "crash", "all"})
_LOGCAT_FORMATS = frozenset(
    {
        "brief",
        "epoch",
        "long",
        "monotonic",
        "process",
        "raw",
        "tag",
        "thread",
        "threadtime",
        "time",
    }
)
_LOGCAT_PRIORITIES = {
    "v": "V",
    "verbose": "V",
    "d": "D",
    "debug": "D",
    "i": "I",
    "info": "I",
    "w": "W",
    "warn": "W",
    "warning": "W",
    "e": "E",
    "error": "E",
    "f": "F",
    "fatal": "F",
    "s": "S",
    "silent": "S",
}
_LOGCAT_TAG_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_LOGCAT_MODES = frozenset({"snapshot", "stream"})
_LOGCAT_REDACTION_PROFILES = frozenset({"strict", "standard", "none"})
_LOGCAT_OUTPUT_LIMIT = 16 * 1024 * 1024
_LOGCAT_LINE_LIMIT_BYTES = 4_096
_LOGCAT_STDERR_LIMIT = 64 * 1_024
_LOGCAT_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_LOGCAT_UNSAFE_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_LOGCAT_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_LOGCAT_MAC = re.compile(r"(?i)(?<![0-9A-F])(?:[0-9A-F]{2}:){5}[0-9A-F]{2}(?![0-9A-F])")
_LOGCAT_SENSITIVE_HEADER = re.compile(
    r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key)"
    r"\s*:\s*[^\r\n]*"
)
_LOGCAT_QUOTED_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)(?P<prefix>[\"'](?:access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"token|password|passwd|secret|api[_-]?key)[\"']\s*:\s*)"
    r"(?P<quote>[\"'])(?:\\.|(?!(?P=quote)).)*(?P=quote)"
)
_LOGCAT_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)(?P<prefix>[\"']?\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"token|password|passwd|secret|api[_-]?key)\b[\"']?\s*[:=]\s*)"
    r"(?![\"'])[^\s,;}]+"
)
_LOGCAT_AUTH_SECRET = re.compile(r"(?i)\b(Bearer|Basic)\s+[^\s,;]+")
_LOGCAT_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_LOGCAT_IPV4 = re.compile(
    r"(?<![A-Za-z0-9])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{1,5})?(?![A-Za-z0-9])"
)
_LOGCAT_IPV6 = re.compile(r"\[[0-9A-Fa-f:]{2,}\](?::\d{1,5})?")
_LOGCAT_PATH_TAIL = r"[^\r\n,;|\"'<>()[\]{}]+"
_LOGCAT_DEVICE_PATH = re.compile(
    rf"(?<![A-Za-z0-9_:/])/(?:data|sdcard|storage|system|vendor|product)/{_LOGCAT_PATH_TAIL}"
)
_LOGCAT_WINDOWS_HOST_PATH = re.compile(
    rf"(?i)(?<![A-Za-z0-9_])(?:[A-Z]:[\\/]|\\\\){_LOGCAT_PATH_TAIL}"
)
_LOGCAT_PATH_CONSTRUCTOR = re.compile(
    r"(?i)\b(?:WindowsPath|PosixPath|PurePath)\([^)]*\)"
)
_LOGCAT_POSIX_PATH = re.compile(
    rf"(?<![A-Za-z0-9_:/])/(?!/){_LOGCAT_PATH_TAIL}"
)
_LOGCAT_PUBLIC_ANDROID_PATH_PREFIXES = (
    "/data/",
    "/dev/",
    "/metadata/",
    "/mnt/",
    "/odm/",
    "/proc/",
    "/product/",
    "/sdcard/",
    "/storage/",
    "/sys/",
    "/system/",
    "/vendor/",
)

_PUSH_DESTINATIONS = frozenset({"/data/local/tmp/", "/sdcard/Download/"})
_REMOTE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_PUSH_FILES = 32
_PUSH_OUTPUT_LIMIT = 64 * 1_024
_PAIRING_CODE_PATTERN = re.compile(r"^[0-9]{6}$")
_MDNS_DAEMON_PATTERN = re.compile(r"^mdns daemon version \[([1-9][0-9]{0,5})\]$")
_MDNS_SERVICES_HEADER = "List of discovered mdns services"
_MDNS_INSTANCE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_MDNS_SERVICE_TYPES = {
    "_adb-tls-pairing._tcp": "pairing",
    "_adb-tls-connect._tcp": "connect",
    "_adb._tcp": "legacy",
}
_MDNS_LOCAL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_MDNS_CHECK_OUTPUT_LIMIT = 1_024
_MDNS_SERVICES_OUTPUT_LIMIT = 255 * 1_024
_MDNS_AGGREGATE_OUTPUT_LIMIT = _MDNS_CHECK_OUTPUT_LIMIT + _MDNS_SERVICES_OUTPUT_LIMIT
_MDNS_MAX_ROWS = 256
_MDNS_MAX_LINE_BYTES = 512
_WIFI_PAIR_OUTPUT_LIMIT = 64 * 1_024
_GETPROP_LINE_PATTERN = re.compile(r"^\[([A-Za-z0-9_.-]{1,128})\]: \[(.*)\]$")
_INSPECTION_ACTIONS = frozenset({"properties", "screenXml", "bootloaderVersions", "pifPrint"})
_GETPROP_OUTPUT_LIMIT = 1024 * 1024
_SCREEN_XML_OUTPUT_LIMIT = 2 * 1024 * 1024
_GETPROP_PROPERTY_LIMIT = 8192
_GETPROP_VALUE_LIMIT = 16 * 1024
_SCREEN_XML_NODE_LIMIT = 20_000
_SCREEN_XML_DEPTH_LIMIT = 128
_SCREEN_XML_ATTRIBUTE_LIMIT = 64
_SCREEN_XML_ATTRIBUTE_VALUE_LIMIT = 16 * 1024
_SCREEN_XML_STATUS_LINES = frozenset(
    {
        "UI hierarchy dumped to: /dev/tty",
        # Android's uiautomator has emitted this typo for years.
        "UI hierchary dumped to: /dev/tty",
    }
)
_SENSITIVE_PROPERTY_FRAGMENTS = frozenset(
    {
        "android_id",
        "bluetooth.address",
        "iccid",
        "imei",
        "imsi",
        "mac_address",
        "macaddr",
        "meid",
        "pairing",
        "password",
        "serialno",
        "subscriber",
        "token",
        "wifi.mac",
    }
)
_PIF_PROPERTY_CANDIDATES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("MANUFACTURER", ("ro.product.manufacturer", "ro.product.system.manufacturer", "ro.product.vendor.manufacturer")),
    ("MODEL", ("ro.product.model", "ro.product.system.model", "ro.product.vendor.model")),
    ("FINGERPRINT", ("ro.build.fingerprint", "ro.system.build.fingerprint", "ro.vendor.build.fingerprint")),
    ("BRAND", ("ro.product.brand", "ro.product.system.brand", "ro.product.vendor.brand")),
    ("PRODUCT", ("ro.product.name", "ro.product.system.name", "ro.product.vendor.name")),
    ("DEVICE", ("ro.product.device", "ro.product.system.device", "ro.product.vendor.device", "ro.build.product")),
    ("RELEASE", ("ro.build.version.release",)),
    ("ID", ("ro.build.id",)),
    ("INCREMENTAL", ("ro.build.version.incremental",)),
    ("TYPE", ("ro.build.type",)),
    ("TAGS", ("ro.build.tags",)),
    ("SECURITY_PATCH", ("ro.build.version.security_patch", "ro.vendor.build.security_patch")),
    (
        "DEVICE_INITIAL_SDK_INT",
        (
            "ro.product.first_api_level",
            "ro.board.first_api_level",
            "ro.board.api_level",
            "ro.build.version.sdk",
        ),
    ),
)
_SCRCPY_EXECUTABLE_NAMES = frozenset({"scrcpy", "scrcpy.exe"})
_MACH_EXECUTABLE_MAGICS = frozenset(
    {
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    }
)

_EXECUTION_PROCESS = "process"
_EXECUTION_LAUNCH = "managed-launch"
_EXECUTION_SECRET_PROCESS = "secret-stdin"
_EXECUTION_LOGCAT_STREAM = "logcat-stream"

DeviceToolProgress = Callable[
    [ProgressPhase, str, int | None, int | None, int | None, str | None],
    None,
]


@dataclass(frozen=True, slots=True)
class LaunchOutcome:
    """A successfully created managed child process."""

    pid: int

    def __post_init__(self) -> None:
        if not isinstance(self.pid, int) or isinstance(self.pid, bool) or self.pid <= 0:
            raise ValueError("launched process pid must be a positive integer")


class ProcessLauncher(Protocol):
    """Injectable non-shell boundary for long-lived GUI processes."""

    def launch(self, request: ProcessRequest) -> LaunchOutcome: ...

    def terminate(self, pid: int) -> bool: ...

    def shutdown(self) -> None: ...


class SecretProcessRunner(Protocol):
    """Injectable boundary which sends one secret through process stdin."""

    def run(
        self,
        request: ProcessRequest,
        secret: str,
        cancellation: CancellationToken,
    ) -> TransportOutcome: ...

    def shutdown(self) -> None: ...


LogcatLineHandler = Callable[[str], str]


@dataclass(frozen=True, slots=True)
class LogcatStreamOutcome:
    """Bounded, already-sanitized output from one incremental logcat child."""

    returncode: int | None
    lines: tuple[str, ...] = ()
    cancelled: bool = False
    timed_out: bool = False
    duration_completed: bool = False
    line_limit_reached: bool = False
    output_limited: bool = False
    truncated_lines: int = 0


class LogcatStreamRunner(Protocol):
    def run(
        self,
        request: ProcessRequest,
        cancellation: CancellationToken,
        *,
        max_lines: int,
        line_handler: LogcatLineHandler,
    ) -> LogcatStreamOutcome: ...

    def shutdown(self) -> None: ...


class ManagedProcessTerminationError(RuntimeError):
    """A child process could not be stopped and remains tracked for shutdown."""


class LogcatExportVerificationError(OSError):
    """A committed Logcat export did not match the redacted payload."""


class ManagedProcessLauncher:
    """Start argv-only GUI children and reap or terminate them on shutdown."""

    startup_grace_seconds = 0.1

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._children: dict[int, subprocess.Popen[bytes]] = {}
        self._closed = False

    def launch(self, request: ProcessRequest) -> LaunchOutcome:
        environment = None
        if request.env:
            environment = os.environ.copy()
            environment.update(dict(request.env))
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if sys.platform.startswith("win") else 0
        with self._lock:
            if self._closed:
                raise RuntimeError("process launcher has shut down")
            self._reap_finished()
            process = subprocess.Popen(  # noqa: S603 - reviewed argv, shell disabled
                list(request.argv),
                cwd=request.cwd,
                env=environment,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=not sys.platform.startswith("win"),
                creationflags=creationflags,
            )
            try:
                returncode = process.wait(timeout=self.startup_grace_seconds)
            except subprocess.TimeoutExpired:
                returncode = None
            if returncode is not None:
                raise RuntimeError(f"managed process exited during launch with status {returncode}")
            self._children[process.pid] = process
        return LaunchOutcome(process.pid)

    def terminate(self, pid: int) -> bool:
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            return False
        with self._lock:
            process = self._children.get(pid)
            if process is None:
                return False
            if not self._stop_child(process):
                return False
            self._children.pop(pid, None)
            return True

    def shutdown(self) -> None:
        with self._lock:
            self._closed = True
            for pid, process in tuple(self._children.items()):
                if self._stop_child(process):
                    self._children.pop(pid, None)

    def _reap_finished(self) -> None:
        finished = [pid for pid, process in self._children.items() if process.poll() is not None]
        for pid in finished:
            self._children.pop(pid, None)

    @staticmethod
    def _stop_child(process: subprocess.Popen[bytes]) -> bool:
        if process.poll() is not None:
            return True
        if os.name == "nt":
            flags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
            try:
                subprocess.run(  # noqa: S603 - fixed system argv and owned PID
                    ("taskkill.exe", "/PID", str(process.pid), "/T", "/F"),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=2,
                    shell=False,
                    creationflags=flags,
                )
            except (OSError, subprocess.SubprocessError):
                try:
                    process.kill()
                except OSError:
                    return process.poll() is not None
        else:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                return True
            except OSError:
                try:
                    process.terminate()
                except OSError:
                    return process.poll() is not None
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            try:
                if os.name == "nt":
                    process.kill()
                else:
                    os.killpg(process.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                return False
        return process.poll() is not None


class SubprocessLogcatStreamRunner:
    """Read logcat incrementally with hard duration, line and byte bounds."""

    poll_interval_seconds = 0.05
    read_chunk_bytes = 16 * 1_024

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._children: dict[int, subprocess.Popen[bytes]] = {}
        self._closed = False

    def run(
        self,
        request: ProcessRequest,
        cancellation: CancellationToken,
        *,
        max_lines: int,
        line_handler: LogcatLineHandler,
    ) -> LogcatStreamOutcome:
        if not 1 <= max_lines <= 10_000:
            raise ValueError("max_lines must be between 1 and 10000")
        if request.timeout_seconds is None:
            raise ValueError("streaming logcat requires a bounded duration")
        output_limit = min(
            request.output_limit_bytes or _LOGCAT_OUTPUT_LIMIT,
            _LOGCAT_OUTPUT_LIMIT,
        )
        if cancellation.cancelled:
            return LogcatStreamOutcome(
                None,
                cancelled=cancellation.reason is CancellationReason.USER,
                timed_out=cancellation.reason is CancellationReason.DEADLINE,
            )
        environment = None
        if request.env:
            environment = os.environ.copy()
            environment.update(dict(request.env))
        with self._lock:
            if self._closed:
                raise RuntimeError("logcat stream runner has shut down")
            self._reap_finished()
            process: subprocess.Popen[bytes] = subprocess.Popen(  # noqa: S603
                list(request.argv),
                cwd=request.cwd,
                env=environment,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                start_new_session=not sys.platform.startswith("win"),
                creationflags=(
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                    if sys.platform.startswith("win")
                    else 0
                ),
            )
            self._children[process.pid] = process
        assert process.stdout is not None
        assert process.stderr is not None
        stdout_stream = process.stdout
        stderr_stream = process.stderr

        lines: list[str] = []
        lines_lock = threading.Lock()
        stop_requested = threading.Event()
        line_limit_reached = threading.Event()
        output_limited = threading.Event()
        reader_failed = threading.Event()
        truncated_lines = 0
        captured_bytes = 0
        pending = bytearray()
        pending_truncated = False

        def emit_pending() -> None:
            nonlocal pending_truncated, truncated_lines
            if stop_requested.is_set():
                return
            raw_line = bytes(pending).decode(request.encoding, errors="replace")
            pending.clear()
            if raw_line.endswith("\r"):
                raw_line = raw_line[:-1]
            if pending_truncated:
                truncated_lines += 1
                pending_truncated = False
            try:
                safe_line = line_handler(raw_line)
            except Exception:
                reader_failed.set()
                stop_requested.set()
                return
            if not isinstance(safe_line, str):
                reader_failed.set()
                stop_requested.set()
                return
            with lines_lock:
                if len(lines) >= max_lines:
                    stop_requested.set()
                    return
                lines.append(safe_line)
                if len(lines) >= max_lines:
                    line_limit_reached.set()
                    stop_requested.set()

        def collect_stdout() -> None:
            nonlocal captured_bytes, pending_truncated
            try:
                while not stop_requested.is_set():
                    chunk = os.read(stdout_stream.fileno(), self.read_chunk_bytes)
                    if not chunk:
                        break
                    captured_bytes += len(chunk)
                    if captured_bytes > output_limit:
                        output_limited.set()
                        stop_requested.set()
                        break
                    for byte in chunk:
                        if stop_requested.is_set():
                            break
                        if byte == 0x0A:
                            emit_pending()
                        elif len(pending) < _LOGCAT_LINE_LIMIT_BYTES:
                            pending.append(byte)
                        else:
                            pending_truncated = True
                if pending and not stop_requested.is_set():
                    emit_pending()
            except (OSError, ValueError):
                if process.poll() is None and not stop_requested.is_set():
                    reader_failed.set()
                    stop_requested.set()

        stderr_bytes = 0

        def drain_stderr() -> None:
            nonlocal stderr_bytes
            try:
                while not stop_requested.is_set():
                    chunk = os.read(stderr_stream.fileno(), self.read_chunk_bytes)
                    if not chunk:
                        return
                    stderr_bytes += len(chunk)
                    if stderr_bytes > _LOGCAT_STDERR_LIMIT:
                        output_limited.set()
                        stop_requested.set()
                        return
            except (OSError, ValueError):
                return

        readers = (
            threading.Thread(
                target=collect_stdout,
                name="pixelflasher-logcat-stdout",
                daemon=True,
            ),
            threading.Thread(
                target=drain_stderr,
                name="pixelflasher-logcat-stderr",
                daemon=True,
            ),
        )
        for reader in readers:
            reader.start()

        duration_deadline = time.monotonic() + request.timeout_seconds
        cancelled = False
        timed_out = False
        duration_completed = False
        forced_stop = False
        while process.poll() is None:
            if cancellation.cancelled:
                cancelled = cancellation.reason is CancellationReason.USER
                timed_out = cancellation.reason is CancellationReason.DEADLINE
                forced_stop = True
                break
            if output_limited.is_set() or reader_failed.is_set():
                forced_stop = True
                break
            if stop_requested.is_set():
                duration_completed = True
                forced_stop = True
                break
            if time.monotonic() >= duration_deadline:
                duration_completed = True
                stop_requested.set()
                forced_stop = True
                break
            cancellation.wait(self.poll_interval_seconds)

        if forced_stop and process.poll() is None and not ManagedProcessLauncher._stop_child(process):
            # The child must remain tracked for a later shutdown retry, but its
            # reader callbacks must not keep publishing progress after the
            # operation has already failed terminally.
            stop_requested.set()
            raise ManagedProcessTerminationError(
                "logcat stream could not be terminated and remains tracked"
            )
        for reader in readers:
            reader.join(timeout=1)
        for stream, reader in zip((stdout_stream, stderr_stream), readers, strict=True):
            if reader.is_alive():
                stream.close()
                reader.join(timeout=1)
        with self._lock:
            if process.poll() is not None:
                self._children.pop(process.pid, None)
        if reader_failed.is_set():
            raise RuntimeError("logcat stream reader failed")
        with lines_lock:
            captured_lines = tuple(lines)
        return LogcatStreamOutcome(
            process.returncode,
            captured_lines,
            cancelled=cancelled,
            timed_out=timed_out,
            duration_completed=duration_completed,
            line_limit_reached=line_limit_reached.is_set(),
            output_limited=output_limited.is_set(),
            truncated_lines=truncated_lines,
        )

    def shutdown(self) -> None:
        with self._lock:
            self._closed = True
            for pid, process in tuple(self._children.items()):
                if ManagedProcessLauncher._stop_child(process):
                    self._children.pop(pid, None)

    def _reap_finished(self) -> None:
        for pid, process in tuple(self._children.items()):
            if process.poll() is not None:
                self._children.pop(pid, None)


class SubprocessSecretRunner:
    """Run one argv-only process while keeping a credential out of argv/env."""

    poll_interval_seconds = 0.05
    default_output_limit_bytes = 64 * 1_024
    read_chunk_bytes = 16 * 1_024

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._children: dict[int, subprocess.Popen[bytes]] = {}
        self._closed = False

    def run(
        self,
        request: ProcessRequest,
        secret: str,
        cancellation: CancellationToken,
    ) -> TransportOutcome:
        environment = None
        if request.env:
            environment = os.environ.copy()
            environment.update(dict(request.env))
        limit = request.output_limit_bytes or self.default_output_limit_bytes
        with self._lock:
            if self._closed:
                raise RuntimeError("secret process runner has shut down")
            self._reap_finished()
            process: subprocess.Popen[bytes] = subprocess.Popen(  # noqa: S603 - reviewed argv, shell disabled
                list(request.argv),
                cwd=request.cwd,
                env=environment,
                shell=False,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                start_new_session=not sys.platform.startswith("win"),
                creationflags=(
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                    if sys.platform.startswith("win")
                    else 0
                ),
            )
            self._children[process.pid] = process
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        stdout_buffer = bytearray()
        stderr_buffer = bytearray()
        capture_lock = threading.Lock()
        output_limited = threading.Event()
        captured_bytes = 0

        def collect(stream: BinaryIO, target: bytearray) -> None:
            nonlocal captured_bytes
            while True:
                with capture_lock:
                    chunk_size = min(
                        self.read_chunk_bytes,
                        max(1, limit - captured_bytes + 1),
                    )
                try:
                    chunk = os.read(stream.fileno(), chunk_size)
                except OSError:
                    return
                if not chunk:
                    return
                with capture_lock:
                    remaining = max(0, limit - captured_bytes)
                    accepted = min(len(chunk), remaining)
                    if accepted:
                        target.extend(chunk[:accepted])
                        captured_bytes += accepted
                    if accepted != len(chunk):
                        output_limited.set()
                        return

        readers = (
            threading.Thread(
                target=collect,
                args=(process.stdout, stdout_buffer),
                name="pixelflasher-secret-stdout-capture",
                daemon=True,
            ),
            threading.Thread(
                target=collect,
                args=(process.stderr, stderr_buffer),
                name="pixelflasher-secret-stderr-capture",
                daemon=True,
            ),
        )
        for reader in readers:
            reader.start()

        encoded_secret = (secret + "\n").encode(request.encoding, errors="replace")
        try:
            process.stdin.write(encoded_secret)
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            encoded_secret = b""
            try:
                process.stdin.close()
            except OSError:
                pass

        deadline = time.monotonic() + request.timeout_seconds if request.timeout_seconds is not None else None
        cancelled = False
        timed_out = False
        termination_failed = False
        while process.poll() is None:
            if output_limited.is_set():
                termination_failed = not self._stop_process(process)
                break
            if cancellation.cancelled:
                cancelled = cancellation.reason is CancellationReason.USER
                timed_out = cancellation.reason is CancellationReason.DEADLINE
                termination_failed = not self._stop_process(process)
                break
            if deadline is not None and time.monotonic() >= deadline:
                timed_out = True
                termination_failed = not self._stop_process(process)
                break
            cancellation.wait(self.poll_interval_seconds)

        if termination_failed and process.poll() is None:
            raise ManagedProcessTerminationError(
                "secret process could not be terminated and remains tracked"
            )

        for reader in readers:
            reader.join(timeout=1)
        for stream, reader in zip((process.stdout, process.stderr), readers, strict=True):
            if reader.is_alive():
                stream.close()
                reader.join(timeout=1)

        with self._lock:
            if process.poll() is not None:
                self._children.pop(process.pid, None)

        return TransportOutcome(
            process.returncode,
            stdout_buffer.decode(request.encoding, errors="replace"),
            stderr_buffer.decode(request.encoding, errors="replace"),
            cancelled=cancelled,
            timed_out=timed_out,
            output_limited=output_limited.is_set(),
        )

    @staticmethod
    def _stop_process(process: subprocess.Popen[bytes]) -> bool:
        return ManagedProcessLauncher._stop_child(process)

    def shutdown(self) -> None:
        with self._lock:
            self._closed = True
            for pid, process in tuple(self._children.items()):
                if self._stop_process(process):
                    self._children.pop(pid, None)

    def _reap_finished(self) -> None:
        for pid, process in tuple(self._children.items()):
            if process.poll() is not None:
                self._children.pop(pid, None)


class DeviceToolPlanningError(ValueError):
    """Typed validation failure suitable for conversion to ``OperationResult``."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class DeviceInspectionParseError(ValueError):
    """A bounded inspection response failed its typed parser."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class MdnsDiscoveryParseError(ValueError):
    """Untrusted ADB mDNS output failed the closed discovery contract."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _mdns_endpoint(value: str) -> tuple[str, int, str] | None:
    host, separator, raw_port = value.rpartition(":")
    if not separator or not host or ":" in host:
        return None
    if not raw_port.isascii() or not raw_port.isdecimal():
        return None
    port = int(raw_port)
    if not 1 <= port <= 65_535 or str(port) != raw_port:
        return None
    try:
        address = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        return None
    if str(address) != host:
        return None
    if address.is_loopback or address.is_multicast or address.is_unspecified or address.is_reserved:
        return None
    if not any(address in network for network in _MDNS_LOCAL_NETWORKS):
        return None
    endpoint = f"{address}:{port}"
    return str(address), port, endpoint


def parse_adb_mdns_discovery(output: str) -> dict[str, object]:
    """Parse bounded, unauthenticated LAN announcements into a closed DTO.

    The two expected command responses are concatenated by ``CommandExecutor``:
    ``adb mdns check`` followed by ``adb mdns services``.  Announcements are
    suggestions only; this function never changes selection or connection
    state and deliberately omits all raw process output.
    """

    if not isinstance(output, str):
        raise MdnsDiscoveryParseError(
            "wifi_mdns_output_invalid",
            "ADB mDNS output must be decoded text",
        )
    if "\x00" in output or "\ufffd" in output:
        raise MdnsDiscoveryParseError(
            "wifi_mdns_output_invalid",
            "ADB mDNS output contains invalid text",
        )
    encoded_size = len(output.encode("utf-8"))
    if encoded_size > _MDNS_AGGREGATE_OUTPUT_LIMIT:
        raise MdnsDiscoveryParseError(
            "wifi_mdns_output_too_large",
            "ADB mDNS output exceeds the backend limit",
        )
    if "\r" in output.replace("\r\n", ""):
        raise MdnsDiscoveryParseError(
            "wifi_mdns_output_invalid",
            "ADB mDNS output contains an invalid line ending",
        )
    lines = output.replace("\r\n", "\n").splitlines()
    if len(lines) < 2:
        raise MdnsDiscoveryParseError(
            "wifi_mdns_unavailable",
            "ADB mDNS discovery is unavailable",
        )
    if len(lines) > _MDNS_MAX_ROWS + 2:
        raise MdnsDiscoveryParseError(
            "wifi_mdns_row_limit_exceeded",
            "ADB mDNS returned too many service rows",
        )
    if _MDNS_DAEMON_PATTERN.fullmatch(lines[0]) is None:
        raise MdnsDiscoveryParseError(
            "wifi_mdns_unavailable",
            "ADB mDNS discovery is unavailable",
        )
    if lines[1] != _MDNS_SERVICES_HEADER:
        raise MdnsDiscoveryParseError(
            "wifi_mdns_header_invalid",
            "ADB mDNS returned an unexpected services header",
        )

    discovered: dict[tuple[str, str], dict[str, object]] = {}
    discarded_count = 0
    for line in lines[2:]:
        if len(line.encode("utf-8")) > _MDNS_MAX_LINE_BYTES:
            raise MdnsDiscoveryParseError(
                "wifi_mdns_line_too_large",
                "ADB mDNS returned an oversized service row",
            )
        if not line or any(
            (ord(character) < 32 and character != "\t") or ord(character) == 127
            for character in line
        ):
            raise MdnsDiscoveryParseError(
                "wifi_mdns_output_invalid",
                "ADB mDNS returned invalid service text",
            )
        parts = line.split("\t")
        if len(parts) != 3:
            discarded_count += 1
            continue
        instance, raw_service_type, raw_endpoint = parts
        service_type = _MDNS_SERVICE_TYPES.get(raw_service_type)
        endpoint = _mdns_endpoint(raw_endpoint)
        if (
            _MDNS_INSTANCE_PATTERN.fullmatch(instance) is None
            or service_type is None
            or endpoint is None
        ):
            discarded_count += 1
            continue
        host, port, canonical_endpoint = endpoint
        identity = (service_type, canonical_endpoint)
        if identity in discovered:
            discarded_count += 1
            continue
        service_id = hashlib.sha256(
            f"{service_type}\0{canonical_endpoint}".encode("ascii")
        ).hexdigest()
        discovered[identity] = {
            "id": service_id,
            "instance": instance,
            "serviceType": service_type,
            "host": host,
            "port": port,
            "endpoint": canonical_endpoint,
            "addressFamily": "ipv4",
        }

    services = sorted(
        discovered.values(),
        key=lambda item: (
            cast(str, item["serviceType"]),
            cast(str, item["endpoint"]),
            cast(str, item["instance"]),
        ),
    )
    return {
        "action": "discover",
        "count": len(services),
        "services": services,
        "discardedCount": discarded_count,
        "bounded": True,
    }


def _bounded_output_bytes(value: str, *, maximum: int, kind: str) -> None:
    if not isinstance(value, str):
        raise DeviceInspectionParseError(
            f"{kind}_output_invalid",
            f"{kind} output must be decoded text",
        )
    if "\x00" in value:
        raise DeviceInspectionParseError(
            f"{kind}_output_invalid",
            f"{kind} output contains a NUL byte",
        )
    if len(value.encode("utf-8")) > maximum:
        raise DeviceInspectionParseError(
            f"{kind}_output_too_large",
            f"{kind} output exceeds the backend limit",
        )


def parse_bounded_getprop(output: str) -> dict[str, str]:
    """Parse one full ``getprop`` response without accepting ambiguous lines."""

    _bounded_output_bytes(output, maximum=_GETPROP_OUTPUT_LIMIT, kind="getprop")
    lines = output.replace("\r\n", "\n").replace("\r", "\n").splitlines()
    if len(lines) > _GETPROP_PROPERTY_LIMIT:
        raise DeviceInspectionParseError(
            "getprop_property_limit_exceeded",
            "getprop returned too many property lines",
        )

    properties: dict[str, str] = {}
    for raw_line in lines:
        if not raw_line:
            continue
        match = _GETPROP_LINE_PATTERN.fullmatch(raw_line)
        if match is None:
            raise DeviceInspectionParseError(
                "getprop_format_invalid",
                "getprop returned a malformed property line",
            )
        key, value = match.groups()
        if key in properties:
            raise DeviceInspectionParseError(
                "getprop_property_duplicate",
                "getprop returned a duplicate property name",
            )
        if len(value.encode("utf-8")) > _GETPROP_VALUE_LIMIT or any(ord(character) < 32 for character in value):
            raise DeviceInspectionParseError(
                "getprop_value_invalid",
                "getprop returned an invalid property value",
            )
        properties[key] = value

    if not properties:
        raise DeviceInspectionParseError(
            "getprop_empty",
            "getprop returned no properties",
        )
    return dict(sorted(properties.items()))


def _property_is_sensitive(key: str) -> bool:
    normalized = key.casefold().replace("-", "_")
    return any(fragment in normalized for fragment in _SENSITIVE_PROPERTY_FRAGMENTS)


def _first_property(properties: Mapping[str, str], candidates: Sequence[str]) -> str:
    for candidate in candidates:
        value = properties.get(candidate, "").strip()
        if value and value.casefold() not in {"generic", "mainline", "unknown"}:
            return value
    return ""


def _properties_inspection_value(properties: Mapping[str, str]) -> dict[str, object]:
    redacted_keys = tuple(key for key in properties if _property_is_sensitive(key))
    public_properties = {key: "[REDACTED]" if key in redacted_keys else value for key, value in properties.items()}
    summary = {
        "manufacturer": _first_property(
            properties,
            ("ro.product.manufacturer", "ro.product.vendor.manufacturer"),
        ),
        "model": _first_property(
            properties,
            ("ro.product.model", "ro.product.vendor.model"),
        ),
        "codename": _first_property(
            properties,
            ("ro.product.device", "ro.build.product"),
        ),
        "androidVersion": _first_property(properties, ("ro.build.version.release",)),
        "build": _first_property(
            properties,
            ("ro.build.display.id", "ro.build.id"),
        ),
        "securityPatch": _first_property(
            properties,
            ("ro.build.version.security_patch",),
        ),
        "bootloader": _first_property(
            properties,
            ("ro.bootloader", "ro.boot.bootloader", "ro.bootloader.version"),
        ),
    }
    return {
        "action": "properties",
        "count": len(public_properties),
        "properties": public_properties,
        "redactedKeys": list(redacted_keys),
        "summary": summary,
    }


def _bootloader_versions_value(properties: Mapping[str, str]) -> dict[str, object]:
    candidates = (
        "ro.bootloader",
        "ro.boot.bootloader",
        "ro.bootloader.version",
        "ro.product.bootloader",
    )
    versions = {
        key: properties[key].strip()
        for key in candidates
        if properties.get(key, "").strip() and properties[key].strip().casefold() != "unknown"
    }
    if not versions:
        raise DeviceInspectionParseError(
            "bootloader_version_unavailable",
            "the device did not report a bootloader version through ADB properties",
        )
    return {
        "action": "bootloaderVersions",
        "source": "adb_getprop",
        "current": next(iter(versions.values())),
        "versions": versions,
        "slot": _first_property(
            properties,
            ("ro.boot.slot_suffix", "ro.boot.slot"),
        ).removeprefix("_"),
    }


def _pif_print_value(properties: Mapping[str, str]) -> dict[str, object]:
    profile = {field: _first_property(properties, candidates) for field, candidates in _PIF_PROPERTY_CANDIDATES}
    first_api = profile["DEVICE_INITIAL_SDK_INT"]
    if not first_api.isdecimal() or not 1 <= int(first_api) <= 10_000:
        raise DeviceInspectionParseError(
            "pif_print_invalid_api_level",
            "the device did not report a valid initial API level",
        )
    # Play Integrity Fork's v5 profile format deliberately caps this field.
    profile["DEVICE_INITIAL_SDK_INT"] = str(min(int(first_api), 32))
    required = {
        "MANUFACTURER",
        "MODEL",
        "FINGERPRINT",
        "PRODUCT",
        "DEVICE",
        "SECURITY_PATCH",
        "DEVICE_INITIAL_SDK_INT",
    }
    missing = sorted(field for field in required if not profile[field])
    if missing:
        raise DeviceInspectionParseError(
            "pif_print_incomplete",
            f"the device is missing required PIF property {missing[0]}",
        )
    filtered = {key: value for key, value in profile.items() if value}
    return {
        "action": "pifPrint",
        "format": "playintegrityfork-v5-compatible",
        "profile": filtered,
        "json": json.dumps(filtered, ensure_ascii=False, indent=2),
    }


def parse_bounded_screen_xml(output: str) -> dict[str, object]:
    """Validate and sanitize one fixed uiautomator ``/dev/tty`` response."""

    _bounded_output_bytes(
        output,
        maximum=_SCREEN_XML_OUTPUT_LIMIT,
        kind="screen_xml",
    )
    normalized = output.lstrip("\ufeff")
    normalized_lower = normalized.casefold()
    if "<!doctype" in normalized_lower or "<!entity" in normalized_lower:
        raise DeviceInspectionParseError(
            "screen_xml_declaration_forbidden",
            "uiautomator XML declarations are not allowed",
        )
    declaration_start = normalized.find("<?xml")
    hierarchy_start = normalized.find("<hierarchy")
    starts = tuple(index for index in (declaration_start, hierarchy_start) if index >= 0)
    if not starts:
        raise DeviceInspectionParseError(
            "screen_xml_missing",
            "uiautomator did not return a hierarchy document",
        )
    xml_start = min(starts)
    closing = "</hierarchy>"
    closing_index = normalized.rfind(closing)
    if closing_index < xml_start:
        raise DeviceInspectionParseError(
            "screen_xml_incomplete",
            "uiautomator returned an incomplete hierarchy document",
        )
    xml_end = closing_index + len(closing)
    outside_lines = normalized[:xml_start].splitlines() + normalized[xml_end:].splitlines()
    if any(line.strip() not in _SCREEN_XML_STATUS_LINES for line in outside_lines if line.strip()):
        raise DeviceInspectionParseError(
            "screen_xml_wrapper_invalid",
            "uiautomator returned unexpected text outside the hierarchy document",
        )
    xml_text = normalized[xml_start:xml_end]
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as error:
        raise DeviceInspectionParseError(
            "screen_xml_invalid",
            "uiautomator returned malformed XML",
        ) from error
    if root.tag != "hierarchy":
        raise DeviceInspectionParseError(
            "screen_xml_root_invalid",
            "uiautomator XML must use a hierarchy root",
        )

    node_count = 0
    redacted_fields = 0
    pending: list[tuple[ElementTree.Element, int]] = [(root, 0)]
    while pending:
        element, depth = pending.pop()
        node_count += 1
        if node_count > _SCREEN_XML_NODE_LIMIT:
            raise DeviceInspectionParseError(
                "screen_xml_node_limit_exceeded",
                "uiautomator XML contains too many nodes",
            )
        if depth > _SCREEN_XML_DEPTH_LIMIT:
            raise DeviceInspectionParseError(
                "screen_xml_depth_limit_exceeded",
                "uiautomator XML is nested too deeply",
            )
        if len(element.attrib) > _SCREEN_XML_ATTRIBUTE_LIMIT:
            raise DeviceInspectionParseError(
                "screen_xml_attribute_limit_exceeded",
                "uiautomator XML contains too many attributes on one node",
            )
        for name, value in element.attrib.items():
            if (
                not name
                or len(name) > 128
                or any(ord(character) < 32 for character in name)
                or len(value.encode("utf-8")) > _SCREEN_XML_ATTRIBUTE_VALUE_LIMIT
                or any(ord(character) < 32 for character in value)
            ):
                raise DeviceInspectionParseError(
                    "screen_xml_attribute_invalid",
                    "uiautomator XML contains an invalid attribute",
                )
        if element.attrib.get("password", "").casefold() == "true":
            for name in ("text", "content-desc"):
                if element.attrib.get(name):
                    element.attrib[name] = "[REDACTED]"
                    redacted_fields += 1
        children = list(element)
        pending.extend((child, depth + 1) for child in reversed(children))

    serialized = ElementTree.tostring(
        root,
        encoding="unicode",
        short_empty_elements=True,
    )
    document = f'<?xml version="1.0" encoding="UTF-8"?>\n{serialized}'
    _bounded_output_bytes(
        document,
        maximum=_SCREEN_XML_OUTPUT_LIMIT,
        kind="screen_xml",
    )
    return {
        "action": "screenXml",
        "xml": document,
        "sha256": hashlib.sha256(document.encode("utf-8")).hexdigest(),
        "nodeCount": node_count,
        "redactedFields": redacted_fields,
    }


@dataclass(frozen=True, slots=True)
class PushFileReceipt:
    """Route-free metadata bound to one verified push source and destination."""

    display_name: str
    destination: str
    sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        if _REMOTE_NAME_PATTERN.fullmatch(self.display_name) is None:
            raise ValueError("push receipt display name is invalid")
        if not any(
            self.destination == f"{root}{self.display_name}"
            for root in _PUSH_DESTINATIONS
        ):
            raise ValueError("push receipt destination is invalid")
        if len(self.sha256) != 64 or any(
            character not in "0123456789abcdef"
            for character in self.sha256.casefold()
        ):
            raise ValueError("push receipt SHA-256 is invalid")
        if (
            not isinstance(self.size_bytes, int)
            or isinstance(self.size_bytes, bool)
            or not 0 <= self.size_bytes <= 9_007_199_254_740_991
        ):
            raise ValueError("push receipt size is invalid")
        object.__setattr__(self, "sha256", self.sha256.casefold())

    def to_dict(self) -> dict[str, object]:
        return {
            "displayName": self.display_name,
            "destination": self.destination,
            "sha256": self.sha256,
            "sizeBytes": self.size_bytes,
            "verified": True,
        }


@dataclass(frozen=True, slots=True)
class _PushSource:
    path: Path
    grant: BoundReadFile | None = None


@dataclass(frozen=True, slots=True)
class DeviceToolCompilation:
    """A compiled plan plus safety metadata owned by the backend."""

    plan: OperationPlan
    action: str
    device_write: bool = False
    destructive: bool = False
    requires_confirmation: bool = False
    execution: str = _EXECUTION_PROCESS
    endpoint: str = ""
    pairing_code: SensitiveText | None = None
    push_files: tuple[PushFileReceipt, ...] = ()
    logcat_mode: str = ""
    logcat_redaction: str = ""
    logcat_max_lines: int = 0
    export_destination: BoundWriteFile | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "push_files", tuple(self.push_files))
        if any(not isinstance(item, PushFileReceipt) for item in self.push_files):
            raise TypeError("push file receipts must be typed values")
        if self.action == "pushFiles" and not self.push_files:
            raise ValueError("push compilation requires file receipts")
        if self.action != "pushFiles" and self.push_files:
            raise ValueError("push file receipts are valid only for pushFiles")
        if self.action == "logcat":
            if self.logcat_mode not in _LOGCAT_MODES:
                raise ValueError("logcat compilation mode is invalid")
            if self.logcat_redaction not in _LOGCAT_REDACTION_PROFILES:
                raise ValueError("logcat compilation redaction profile is invalid")
            if not 1 <= self.logcat_max_lines <= 10_000:
                raise ValueError("logcat compilation line limit is invalid")
        elif any(
            (
                self.logcat_mode,
                self.logcat_redaction,
                self.logcat_max_lines,
                self.export_destination,
            )
        ):
            raise ValueError("logcat metadata is valid only for logcat")

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "device_write": self.device_write,
            "destructive": self.destructive,
            "requires_confirmation": self.requires_confirmation,
            "execution": self.execution,
            "endpoint": self.endpoint,
            "push_files": [item.to_dict() for item in self.push_files],
            "logcat_mode": self.logcat_mode,
            "logcat_redaction": self.logcat_redaction,
            "logcat_max_lines": self.logcat_max_lines,
            "export": self.export_destination is not None,
            "plan": self.plan.to_dict(),
        }


class DeviceToolsService:
    """Compile and execute bounded utilities through backend-owned boundaries."""

    def __init__(
        self,
        *,
        hash_chunk_size: int = 1024 * 1024,
        scrcpy_executable: str | Path | None = None,
        process_launcher: ProcessLauncher | None = None,
        secret_runner: SecretProcessRunner | None = None,
        logcat_stream_runner: LogcatStreamRunner | None = None,
    ) -> None:
        if not isinstance(hash_chunk_size, int) or isinstance(hash_chunk_size, bool):
            raise TypeError("hash_chunk_size must be an integer")
        if hash_chunk_size <= 0:
            raise ValueError("hash_chunk_size must be positive")
        self.hash_chunk_size = hash_chunk_size
        self.scrcpy_executable = Path(scrcpy_executable).expanduser() if scrcpy_executable is not None else None
        self.process_launcher = process_launcher or ManagedProcessLauncher()
        self.secret_runner = secret_runner or SubprocessSecretRunner()
        self.logcat_stream_runner = logcat_stream_runner or SubprocessLogcatStreamRunner()

    def compile(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        cancellation: CancellationToken | None = None,
        progress: DeviceToolProgress | None = None,
    ) -> DeviceToolCompilation:
        if command.kind not in DEVICE_TOOL_COMMANDS:
            raise DeviceToolPlanningError(
                "device_tool_command_unsupported",
                f"unsupported device-tool command: {command.kind}",
            )
        if command.kind == "tools.adbShell":
            raise DeviceToolPlanningError(
                "adb_shell_unsupported",
                "arbitrary ADB shell input is not supported by the typed device-tools service",
            )

        self._revision(command, snapshot)
        if command.kind == "tools.wifi.discover":
            return self._compile_wifi_discovery(command, snapshot, self._adb(snapshot))
        if command.kind == "tools.wifi":
            return self._compile_wifi(command, snapshot, self._adb(snapshot))
        device = self._device(command, snapshot)
        adb = self._adb(snapshot)
        if command.kind == "tools.scrcpy":
            self._check_planning_cancelled(cancellation)
            compilation = self._compile_scrcpy(command, snapshot, device)
            self._check_planning_cancelled(cancellation)
            return compilation
        if command.kind == "device.inspect":
            return self._compile_inspection(command, snapshot, device, adb)
        if command.kind == "tools.wifi.status":
            return self._compile_wifi_status(command, snapshot, device, adb)
        if command.kind == "tools.logcat":
            self._check_planning_cancelled(cancellation)
            compilation = self._compile_logcat(command, snapshot, device, adb)
            self._check_planning_cancelled(cancellation)
            return compilation
        return self._compile_push_files(
            command,
            snapshot,
            device,
            adb,
            cancellation=cancellation,
            progress=progress,
        )

    @staticmethod
    def _check_planning_cancelled(cancellation: CancellationToken | None) -> None:
        if cancellation is not None and cancellation.cancelled:
            raise DeviceToolPlanningError(
                "device_tool_cancelled",
                "device tool planning was cancelled",
            )

    def _compile_inspection(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
    ) -> DeviceToolCompilation:
        self._validate_payload(command, {"serial", "action"})
        action = command.payload.get("action")
        if not isinstance(action, str) or action not in _INSPECTION_ACTIONS:
            raise DeviceToolPlanningError(
                "device_inspection_action_invalid",
                "action must be exactly properties, screenXml, bootloaderVersions, or pifPrint",
            )
        if action == "screenXml":
            request = ProcessRequest(
                (
                    adb,
                    "-s",
                    device.serial,
                    "exec-out",
                    "uiautomator",
                    "dump",
                    "/dev/tty",
                ),
                timeout_seconds=30.0,
            )
        else:
            # One complete getprop call is safer and more consistent than
            # constructing shell expressions for each report field.
            request = ProcessRequest(
                (adb, "-s", device.serial, "shell", "getprop"),
                timeout_seconds=15.0,
            )
        return DeviceToolCompilation(
            self._base_plan(
                snapshot,
                device,
                (request,),
                label=f"Inspect {action} for {device.serial}",
            ),
            f"inspect.{action}",
        )

    def _compile_scrcpy(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
    ) -> DeviceToolCompilation:
        self._validate_payload(command, {"serial"})
        executable, artifact = self._scrcpy_artifact()
        request = ProcessRequest(
            (str(executable), "--serial", device.serial),
            cwd=str(executable.parent),
        )
        plan = self._base_plan(
            snapshot,
            device,
            (request,),
            label=f"Launch scrcpy for {device.serial}",
            artifacts=(artifact,),
        )
        # This typed command owns only the local client launch, not subsequent
        # interactive input inside scrcpy.  It is therefore read-only with
        # respect to PixelFlasher's canonical device state. execute_special()
        # still refuses SUCCESS unless the managed process returns a live PID.
        return DeviceToolCompilation(
            plan,
            "scrcpy",
            execution=_EXECUTION_LAUNCH,
        )

    def _compile_wifi_discovery(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        adb: str,
    ) -> DeviceToolCompilation:
        self._validate_payload(command, set())
        requests = (
            ProcessRequest(
                (adb, "mdns", "check"),
                timeout_seconds=5.0,
                output_limit_bytes=_MDNS_CHECK_OUTPUT_LIMIT,
            ),
            ProcessRequest(
                (adb, "mdns", "services"),
                timeout_seconds=10.0,
                output_limit_bytes=_MDNS_SERVICES_OUTPUT_LIMIT,
            ),
        )
        return DeviceToolCompilation(
            self._host_plan(
                snapshot,
                requests,
                label="Discover bounded ADB mDNS services",
            ),
            "wifi.discover",
        )

    def _compile_wifi(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        adb: str,
    ) -> DeviceToolCompilation:
        self._validate_payload(
            command,
            {"action", "host", "port", "pairingCode"},
        )
        raw_action = command.payload.get("action")
        if not isinstance(raw_action, str):
            raise DeviceToolPlanningError(
                "wifi_action_invalid",
                "action must be exactly pair, connect, or disconnect",
            )
        action = raw_action.strip().casefold()
        if action not in {"pair", "connect", "disconnect"}:
            raise DeviceToolPlanningError(
                "wifi_action_invalid",
                "action must be exactly pair, connect, or disconnect",
            )

        endpoint = self._wifi_endpoint(
            command.payload.get("host"),
            command.payload.get("port"),
        )
        raw_pairing_code = command.payload.get("pairingCode")
        if action != "pair" and raw_pairing_code is not None:
            raise DeviceToolPlanningError(
                "wifi_pairing_code_unexpected",
                "pairingCode is accepted only for the pair action",
            )

        pairing_code: SensitiveText | None = None
        execution = _EXECUTION_PROCESS
        if action == "pair":
            if not isinstance(raw_pairing_code, SensitiveText) or not _PAIRING_CODE_PATTERN.fullmatch(
                raw_pairing_code.reveal()
            ):
                raise DeviceToolPlanningError(
                    "wifi_pairing_code_invalid",
                    "pairingCode must contain exactly six decimal digits",
                )
            pairing_code = raw_pairing_code
            execution = _EXECUTION_SECRET_PROCESS

        request = ProcessRequest(
            (adb, action, endpoint),
            timeout_seconds=30.0,
            output_limit_bytes=(_WIFI_PAIR_OUTPUT_LIMIT if action == "pair" else None),
        )
        postcondition = (
            OperationPostcondition(
                "adb_wifi_pairing_recorded",
                {"endpoint": endpoint},
                "bounded ADB pairing returned exact endpoint-bound success evidence",
            )
            if action == "pair"
            else OperationPostcondition(
                "adb_wifi_endpoint_state",
                {
                    "endpoint": endpoint,
                    "connected": action == "connect",
                },
                "the requested ADB-over-Wi-Fi endpoint state is observable",
            )
        )
        return DeviceToolCompilation(
            self._host_plan(
                snapshot,
                (request,),
                label=f"ADB Wi-Fi {action} {endpoint}",
                risk=OperationRisk.MUTATING,
                postconditions=(postcondition,),
                data_behavior=("pairing_state" if action == "pair" else "connection_state"),
            ),
            f"wifi.{action}",
            device_write=action == "pair",
            execution=execution,
            endpoint=endpoint,
            pairing_code=pairing_code,
        )

    def _compile_wifi_status(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
    ) -> DeviceToolCompilation:
        self._validate_payload(command, {"serial"})
        request = ProcessRequest(
            (adb, "-s", device.serial, "get-state"),
            timeout_seconds=10.0,
            output_limit_bytes=1_024,
        )
        return DeviceToolCompilation(
            self._base_plan(
                snapshot,
                device,
                (request,),
                label=f"Read ADB status for {device.serial}",
            ),
            "wifi.status",
        )

    def execute_special(
        self,
        compilation: DeviceToolCompilation,
        operation_id: str,
        cancellation: CancellationToken,
        progress: DeviceToolProgress | None = None,
    ) -> OperationResult:
        """Cross one special boundary without exposing secrets or orphaning tests."""

        if compilation.execution == _EXECUTION_LOGCAT_STREAM:
            if compilation.action != "logcat" or compilation.logcat_mode != "stream":
                return OperationResult.failed(
                    operation_id,
                    code="device_tool_execution_invalid",
                    message="logcat streaming requires a typed stream plan",
                )
            if cancellation.cancelled:
                return self._logcat_stopped(operation_id, cancellation)
            redacted_count = 0
            emitted = 0
            sanitized_truncated = False
            handled_lines: list[str] = []

            def handle_line(raw_line: str) -> str:
                nonlocal emitted, redacted_count, sanitized_truncated
                safe_line, changed, line_truncated = self._sanitize_logcat_line(
                    raw_line,
                    compilation.plan.target_serial or "",
                    compilation.logcat_redaction,
                )
                emitted += 1
                if changed:
                    redacted_count += 1
                sanitized_truncated = sanitized_truncated or line_truncated
                handled_lines.append(safe_line)
                if progress is not None:
                    progress(
                        ProgressPhase.RUNNING,
                        safe_line,
                        min(99, int((emitted / compilation.logcat_max_lines) * 100)),
                        emitted,
                        compilation.logcat_max_lines,
                        None,
                    )
                return safe_line

            try:
                outcome = self.logcat_stream_runner.run(
                    compilation.plan.request,
                    cancellation,
                    max_lines=compilation.logcat_max_lines,
                    line_handler=handle_line,
                )
            except ManagedProcessTerminationError:
                return OperationResult.failed(
                    operation_id,
                    code="managed_process_termination_failed",
                    message="logcat cancellation could not terminate the managed process",
                )
            except Exception:
                return OperationResult.failed(
                    operation_id,
                    code="logcat_stream_failed",
                    message="the bounded logcat stream could not be executed",
                )
            outcome_valid = isinstance(outcome, LogcatStreamOutcome)
            if outcome_valid:
                outcome_valid = bool(
                    isinstance(outcome.lines, tuple)
                    and outcome.lines == tuple(handled_lines)
                    and len(outcome.lines) <= compilation.logcat_max_lines
                    and (
                        outcome.returncode is None
                        or isinstance(outcome.returncode, int)
                        and not isinstance(outcome.returncode, bool)
                    )
                    and all(
                        isinstance(value, bool)
                        for value in (
                            outcome.cancelled,
                            outcome.timed_out,
                            outcome.duration_completed,
                            outcome.line_limit_reached,
                            outcome.output_limited,
                        )
                    )
                    and isinstance(outcome.truncated_lines, int)
                    and not isinstance(outcome.truncated_lines, bool)
                    and 0 <= outcome.truncated_lines <= len(outcome.lines)
                    and sum(
                        (outcome.cancelled, outcome.timed_out, outcome.output_limited)
                    )
                    <= 1
                    and not (
                        (outcome.cancelled or outcome.timed_out)
                        and outcome.duration_completed
                    )
                    and (
                        not outcome.line_limit_reached
                        or outcome.duration_completed
                        and len(outcome.lines) == compilation.logcat_max_lines
                    )
                )
            if not outcome_valid:
                return OperationResult.failed(
                    operation_id,
                    code="logcat_stream_result_invalid",
                    message="logcat stream returned output outside its typed boundary",
                )
            if outcome.cancelled or cancellation.reason is CancellationReason.USER:
                return OperationResult.cancelled(
                    operation_id,
                    code="cancelled",
                    message="logcat streaming was cancelled",
                )
            if outcome.timed_out or cancellation.reason is CancellationReason.DEADLINE:
                return OperationResult.failed(
                    operation_id,
                    code="timed_out",
                    message="logcat streaming exceeded the command deadline",
                )
            if outcome.output_limited:
                return OperationResult.failed(
                    operation_id,
                    code="output_limit_exceeded",
                    message="logcat streaming exceeded its output limit",
                    exit_code=outcome.returncode,
                )
            if not outcome.duration_completed:
                return OperationResult.failed(
                    operation_id,
                    code="logcat_stream_ended",
                    message="ADB logcat exited before the bounded stream completed",
                    exit_code=outcome.returncode,
                )
            provisional = OperationResult.success(
                operation_id,
                exit_code=0,
                value={
                    "lines": list(outcome.lines),
                    "redactedCount": redacted_count,
                    "truncated": (
                        outcome.line_limit_reached
                        or outcome.output_limited
                        or outcome.truncated_lines > 0
                        or sanitized_truncated
                    ),
                },
            )
            return self._complete_logcat(
                compilation,
                provisional,
                cancellation,
                pre_sanitized=True,
            )

        if compilation.execution == _EXECUTION_LAUNCH:
            if compilation.action != "scrcpy":
                return OperationResult.failed(
                    operation_id,
                    code="device_tool_execution_invalid",
                    message="managed launch is not valid for this device-tool action",
                )
            if cancellation.cancelled:
                return OperationResult.cancelled(
                    operation_id,
                    code="cancelled",
                    message="scrcpy launch was cancelled",
                )
            try:
                outcome = self.process_launcher.launch(compilation.plan.request)
                pid = outcome.pid
                if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
                    raise ValueError("launcher returned an invalid pid")
            except Exception:
                return OperationResult.failed(
                    operation_id,
                    code="scrcpy_launch_failed",
                    message="scrcpy could not be launched",
                )
            if cancellation.cancelled:
                try:
                    terminated = self.process_launcher.terminate(pid)
                except Exception:
                    terminated = False
                if not terminated:
                    return OperationResult.failed(
                        operation_id,
                        code="managed_process_termination_failed",
                        message="scrcpy cancellation could not terminate the managed process",
                    )
                return OperationResult.cancelled(
                    operation_id,
                    code="cancelled",
                    message="scrcpy launch was cancelled",
                )
            return OperationResult.success(
                operation_id,
                code="scrcpy_launched",
                message="scrcpy launched for the selected device",
                value={
                    "action": "scrcpy",
                    "targetSerial": compilation.plan.target_serial,
                    "pid": pid,
                },
            )

        if compilation.execution == _EXECUTION_SECRET_PROCESS:
            if compilation.action != "wifi.pair" or compilation.pairing_code is None:
                return OperationResult.failed(
                    operation_id,
                    code="device_tool_execution_invalid",
                    message="secret stdin execution is not valid for this device-tool action",
                )
            if cancellation.cancelled:
                return OperationResult.cancelled(
                    operation_id,
                    code="cancelled",
                    message="Wi-Fi pairing was cancelled",
                )
            try:
                outcome = self.secret_runner.run(
                    compilation.plan.request,
                    compilation.pairing_code.reveal(),
                    cancellation,
                )
                if not isinstance(outcome, TransportOutcome):
                    raise TypeError("secret runner returned an invalid outcome")
            except ManagedProcessTerminationError:
                return OperationResult.failed(
                    operation_id,
                    code="managed_process_termination_failed",
                    message="ADB Wi-Fi pairing cancellation could not terminate the managed process",
                )
            except Exception:
                return OperationResult.failed(
                    operation_id,
                    code="wifi_pair_failed",
                    message="the secure ADB pairing process could not be started",
                )
            if outcome.cancelled or cancellation.cancelled:
                return OperationResult.cancelled(
                    operation_id,
                    code="cancelled",
                    message="Wi-Fi pairing was cancelled",
                )
            if outcome.timed_out:
                return OperationResult.failed(
                    operation_id,
                    code="wifi_pair_timed_out",
                    message="ADB Wi-Fi pairing timed out",
                    exit_code=outcome.returncode,
                )
            if outcome.output_limited:
                return OperationResult.failed(
                    operation_id,
                    code="output_limit_exceeded",
                    message="ADB Wi-Fi pairing exceeded its output limit",
                    exit_code=outcome.returncode,
                )
            if outcome.returncode != 0:
                return OperationResult.failed(
                    operation_id,
                    code="wifi_pair_failed",
                    message="ADB Wi-Fi pairing failed",
                    exit_code=outcome.returncode,
                )
            provisional = OperationResult.success(
                operation_id,
                stdout=outcome.stdout,
                stderr=outcome.stderr,
            )
            return self.finalize_result(compilation, provisional, redact_output=True)

        return OperationResult.failed(
            operation_id,
            code="device_tool_execution_invalid",
            message="the requested device-tool action has no special executor",
        )

    def cleanup_cancelled_special(
        self,
        compilation: DeviceToolCompilation,
        result: OperationResult,
        cancellation: CancellationToken,
    ) -> OperationResult:
        """Release a launched resource when the runner observes late cancellation."""

        if (
            compilation.execution != _EXECUTION_LAUNCH
            or compilation.action != "scrcpy"
            or not cancellation.cancelled
            or not result.ok
        ):
            return result
        raw_value = cast(object, result.value)
        pid: object = None
        if isinstance(raw_value, Mapping):
            pid = cast(Mapping[object, object], raw_value).get("pid")
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            return OperationResult.failed(
                result.operation_id,
                code="managed_process_termination_failed",
                message="scrcpy cancellation could not identify the managed process",
            )
        try:
            terminated = self.process_launcher.terminate(pid)
        except Exception:
            terminated = False
        if not terminated:
            return OperationResult.failed(
                result.operation_id,
                code="managed_process_termination_failed",
                message="scrcpy cancellation could not terminate the managed process",
            )
        return result

    def finalize_result(
        self,
        compilation: DeviceToolCompilation,
        result: OperationResult,
        *,
        redact_output: bool = False,
    ) -> OperationResult:
        """Convert ADB Wi-Fi output into an explicit, bridge-safe result."""

        if not compilation.action.startswith("wifi."):
            return result
        action = compilation.action.partition(".")[2]
        if action == "discover":
            return self._finalize_wifi_discovery(result)
        if result.status is OperationStatus.CANCELLED or result.code in {
            "outcome_unknown",
            "postcondition_mismatch",
            "postcondition_unverified",
        }:
            return result
        if not result.ok:
            return OperationResult.failed(
                result.operation_id,
                code=f"wifi_{action}_failed",
                message=f"ADB Wi-Fi {action} failed",
                exit_code=result.exit_code,
                stdout="" if redact_output else result.stdout,
                stderr="" if redact_output else result.stderr,
            )

        output_lines = tuple(
            line.strip().casefold()
            for line in (*result.stdout.splitlines(), *result.stderr.splitlines())
            if line.strip()
        )
        endpoint = compilation.endpoint.casefold()
        failure_tokens = ("failed", "cannot", "unable", "error")
        has_failure = any(token in line for line in output_lines for token in failure_tokens)
        if action == "status":
            succeeded = result.stdout.strip().casefold() == "device" and not result.stderr.strip()
        elif action == "pair":
            success_pattern = re.compile(
                rf"^(?:enter pairing code:\s*)?successfully paired to "
                rf"{re.escape(endpoint)}(?:\s+\[[^\r\n]*\])?$"
            )
            succeeded = any(success_pattern.fullmatch(line) is not None for line in output_lines)
        elif action == "connect":
            succeeded = any(
                line in {f"connected to {endpoint}", f"already connected to {endpoint}"} for line in output_lines
            )
        else:
            succeeded = any(line == f"disconnected {endpoint}" for line in output_lines)
        succeeded = succeeded and not has_failure
        if not succeeded:
            return OperationResult.failed(
                result.operation_id,
                code=f"wifi_{action}_failed",
                message=f"ADB Wi-Fi {action} did not return a verified success response",
                exit_code=result.exit_code,
                stdout="" if redact_output else result.stdout,
                stderr="" if redact_output else result.stderr,
            )

        value: dict[str, object] = {"action": action}
        if compilation.plan.target_serial is not None:
            value["targetSerial"] = compilation.plan.target_serial
        if compilation.endpoint:
            value["endpoint"] = compilation.endpoint
        if action == "pair":
            # The secret-bearing protocol output has been validated above and
            # is deliberately discarded. This boolean is the only evidence
            # handed to OperationRunner; it contains neither the code nor raw
            # stdout/stderr.
            value["protocolVerified"] = True
        if action == "status":
            value["state"] = "device"
        return OperationResult.success(
            result.operation_id,
            code=f"wifi_{action}_succeeded",
            message=f"ADB Wi-Fi {action} succeeded",
            exit_code=result.exit_code,
            stdout="" if redact_output else result.stdout,
            stderr="" if redact_output else result.stderr,
            value=value,
        )

    @staticmethod
    def _finalize_wifi_discovery(result: OperationResult) -> OperationResult:
        if result.status is OperationStatus.CANCELLED:
            return OperationResult.cancelled(
                result.operation_id,
                code="cancelled",
                message="Wireless ADB discovery was cancelled",
            )
        if not result.ok:
            if result.code == "output_limit_exceeded":
                code = "output_limit_exceeded"
                message = "Wireless ADB discovery exceeded its output limit"
            elif result.code == "timed_out":
                code = "wifi_mdns_timed_out"
                message = "Wireless ADB discovery timed out"
            else:
                code = "wifi_mdns_discovery_failed"
                message = "Wireless ADB discovery failed"
            return OperationResult.failed(
                result.operation_id,
                code=code,
                message=message,
                exit_code=result.exit_code,
            )
        if result.stderr:
            return OperationResult.failed(
                result.operation_id,
                code="wifi_mdns_stderr_unexpected",
                message="Wireless ADB discovery returned unexpected diagnostics",
                exit_code=result.exit_code,
            )
        try:
            value = parse_adb_mdns_discovery(result.stdout)
        except MdnsDiscoveryParseError as error:
            return OperationResult.failed(
                result.operation_id,
                code=error.code,
                message=str(error),
                exit_code=result.exit_code,
            )
        return OperationResult.success(
            result.operation_id,
            code="wifi_mdns_discovery_succeeded",
            message=f"Discovered {value['count']} wireless ADB service(s)",
            exit_code=result.exit_code,
            value=value,
        )

    def finalize_inspection(
        self,
        compilation: DeviceToolCompilation,
        result: OperationResult,
    ) -> OperationResult:
        """Parse one inspection response and discard raw device output."""

        if not compilation.action.startswith("inspect."):
            return OperationResult.failed(
                result.operation_id,
                code="device_inspection_compilation_invalid",
                message="inspection finalization received a non-inspection plan",
            )
        if result.status is OperationStatus.CANCELLED:
            return OperationResult.cancelled(
                result.operation_id,
                code=result.code,
                message=result.message,
            )
        if not result.ok:
            return OperationResult.failed(
                result.operation_id,
                code=result.code,
                message=result.message,
                exit_code=result.exit_code,
            )
        if result.stderr.strip():
            return OperationResult.failed(
                result.operation_id,
                code="device_inspection_stderr_unexpected",
                message="the device inspection command returned unexpected diagnostics",
                exit_code=result.exit_code,
            )

        action = compilation.action.removeprefix("inspect.")
        try:
            if action == "screenXml":
                value = parse_bounded_screen_xml(result.stdout)
            else:
                properties = parse_bounded_getprop(result.stdout)
                if action == "properties":
                    value = _properties_inspection_value(properties)
                elif action == "bootloaderVersions":
                    value = _bootloader_versions_value(properties)
                elif action == "pifPrint":
                    value = _pif_print_value(properties)
                else:
                    raise DeviceInspectionParseError(
                        "device_inspection_action_invalid",
                        "the compiled inspection action is unsupported",
                    )
        except DeviceInspectionParseError as error:
            return OperationResult.failed(
                result.operation_id,
                code=error.code,
                message=str(error),
                exit_code=result.exit_code,
            )
        value["targetSerial"] = compilation.plan.target_serial
        return OperationResult.success(
            result.operation_id,
            code=f"device_inspection_{action}_succeeded",
            message=f"device {action} inspection succeeded",
            exit_code=result.exit_code,
            value=value,
        )

    def finalize_logcat(
        self,
        compilation: DeviceToolCompilation,
        result: OperationResult,
        cancellation: CancellationToken,
    ) -> OperationResult:
        """Sanitize a snapshot and optionally commit only its safe form."""

        return self._complete_logcat(
            compilation,
            result,
            cancellation,
            pre_sanitized=False,
        )

    def _complete_logcat(
        self,
        compilation: DeviceToolCompilation,
        result: OperationResult,
        cancellation: CancellationToken,
        *,
        pre_sanitized: bool,
    ) -> OperationResult:
        if compilation.action != "logcat":
            return OperationResult.failed(
                result.operation_id,
                code="logcat_compilation_invalid",
                message="logcat finalization received a non-logcat plan",
            )
        if cancellation.cancelled:
            return self._logcat_stopped(result.operation_id, cancellation)
        if result.status is OperationStatus.CANCELLED:
            return OperationResult.cancelled(
                result.operation_id,
                code=result.code,
                message=result.message,
            )
        if not result.ok:
            return OperationResult.failed(
                result.operation_id,
                code=result.code,
                message=result.message,
                exit_code=result.exit_code,
            )

        lines: list[str] = []
        redacted_count = 0
        truncated = False
        if pre_sanitized:
            raw_value = cast(object, result.value)
            if not isinstance(raw_value, Mapping):
                return OperationResult.failed(
                    result.operation_id,
                    code="logcat_stream_result_invalid",
                    message="logcat stream returned an invalid typed result",
                )
            values = cast(Mapping[object, object], raw_value)
            if set(values) != {"lines", "redactedCount", "truncated"}:
                return OperationResult.failed(
                    result.operation_id,
                    code="logcat_stream_result_invalid",
                    message="logcat stream returned unexpected metadata",
                )
            raw_lines = cast(object, values.get("lines"))
            if not isinstance(raw_lines, (tuple, list)):
                return OperationResult.failed(
                    result.operation_id,
                    code="logcat_stream_result_invalid",
                    message="logcat stream returned invalid lines",
                )
            line_values = cast(tuple[object, ...] | list[object], raw_lines)
            if any(not isinstance(line, str) for line in line_values):
                return OperationResult.failed(
                    result.operation_id,
                    code="logcat_stream_result_invalid",
                    message="logcat stream returned invalid lines",
                )
            lines = [line for line in line_values if isinstance(line, str)]
            if len(lines) > compilation.logcat_max_lines:
                return OperationResult.failed(
                    result.operation_id,
                    code="logcat_stream_result_invalid",
                    message="logcat stream exceeded its line limit",
                )
            for line in lines:
                safe_line, changed, line_truncated = self._sanitize_logcat_line(
                    line,
                    compilation.plan.target_serial or "",
                    compilation.logcat_redaction,
                )
                if changed or line_truncated or safe_line != line:
                    return OperationResult.failed(
                        result.operation_id,
                        code="logcat_stream_result_invalid",
                        message="logcat stream returned an unsafe line",
                    )
            raw_redacted = values.get("redactedCount", 0)
            if (
                not isinstance(raw_redacted, int)
                or isinstance(raw_redacted, bool)
                or not 0 <= raw_redacted <= len(lines)
            ):
                return OperationResult.failed(
                    result.operation_id,
                    code="logcat_stream_result_invalid",
                    message="logcat stream returned invalid redaction metadata",
                )
            redacted_count = raw_redacted
            raw_truncated = values.get("truncated")
            if not isinstance(raw_truncated, bool):
                return OperationResult.failed(
                    result.operation_id,
                    code="logcat_stream_result_invalid",
                    message="logcat stream returned invalid truncation metadata",
                )
            truncated = raw_truncated
        else:
            source_lines = result.stdout.split("\n")
            if source_lines and source_lines[-1] == "":
                source_lines.pop()
            if len(source_lines) > compilation.logcat_max_lines:
                source_lines = source_lines[: compilation.logcat_max_lines]
                truncated = True
            for raw_line in source_lines:
                if cancellation.cancelled:
                    return self._logcat_stopped(result.operation_id, cancellation)
                safe_line, changed, line_truncated = self._sanitize_logcat_line(
                    raw_line,
                    compilation.plan.target_serial or "",
                    compilation.logcat_redaction,
                )
                lines.append(safe_line)
                if changed:
                    redacted_count += 1
                truncated = truncated or line_truncated

        text = "\n".join(lines)
        if len(text.encode("utf-8")) > _LOGCAT_OUTPUT_LIMIT:
            return OperationResult.failed(
                result.operation_id,
                code="logcat_stream_result_invalid",
                message="logcat result exceeded its aggregate output limit",
            )
        export_value: dict[str, object] | None = None
        if compilation.export_destination is not None:
            try:
                export_value = self._export_logcat(
                    compilation.export_destination,
                    text,
                    cancellation,
                )
            except InterruptedError:
                return self._logcat_stopped(result.operation_id, cancellation)
            except GrantError as error:
                return OperationResult.failed(
                    result.operation_id,
                    code=error.code,
                    message=str(error),
                )
            except LogcatExportVerificationError:
                return OperationResult.failed(
                    result.operation_id,
                    code="postcondition_mismatch",
                    message="the committed logcat export did not match its receipt",
                )
            except OSError:
                return OperationResult.failed(
                    result.operation_id,
                    code="logcat_export_failed",
                    message="the redacted logcat export could not be written",
                )

        value: dict[str, object] = {
            "targetSerial": compilation.plan.target_serial,
            "mode": compilation.logcat_mode,
            "lineCount": len(lines),
            "lines": lines,
            "text": text,
            "redaction": compilation.logcat_redaction,
            "redactedCount": redacted_count,
            "bounded": True,
            "truncated": truncated,
        }
        if export_value is not None:
            value["export"] = export_value
        code = (
            "logcat_stream_completed"
            if compilation.logcat_mode == "stream"
            else "logcat_collected"
        )
        return OperationResult.success(
            result.operation_id,
            code=code,
            message=f"collected {len(lines)} bounded log line(s)",
            exit_code=result.exit_code,
            value=value,
        )

    @staticmethod
    def _logcat_stopped(
        operation_id: str,
        cancellation: CancellationToken,
    ) -> OperationResult:
        if cancellation.reason is CancellationReason.DEADLINE:
            return OperationResult.failed(
                operation_id,
                code="timed_out",
                message="logcat collection exceeded the command deadline",
            )
        return OperationResult.cancelled(
            operation_id,
            code="cancelled",
            message="logcat collection was cancelled",
        )

    @staticmethod
    def _sanitize_logcat_line(
        raw_line: str,
        serial: str,
        profile: str,
    ) -> tuple[str, bool, bool]:
        original = raw_line
        line_truncated = False
        safe = _LOGCAT_ANSI_ESCAPE.sub("", raw_line)
        safe = _LOGCAT_UNSAFE_CONTROL.sub("", safe)
        encoded = safe.encode("utf-8", errors="replace")
        if len(encoded) > _LOGCAT_LINE_LIMIT_BYTES:
            line_truncated = True
            safe = encoded[:_LOGCAT_LINE_LIMIT_BYTES].decode(
                "utf-8", errors="ignore"
            )
        # Host-like paths are never allowed across the public bridge, even
        # when an Expert explicitly disables PII redaction.
        safe = _LOGCAT_WINDOWS_HOST_PATH.sub("<host-path>", safe)
        safe = _LOGCAT_PATH_CONSTRUCTOR.sub("<host-path>", safe)

        def redact_host_path(match: re.Match[str]) -> str:
            path = match.group(0)
            if any(
                path == prefix[:-1] or path.startswith(prefix)
                for prefix in _LOGCAT_PUBLIC_ANDROID_PATH_PREFIXES
            ):
                return path
            return "<host-path>"

        safe = _LOGCAT_POSIX_PATH.sub(redact_host_path, safe)
        if profile != "none":
            if serial:
                safe = safe.replace(serial, "<serial>")
            safe = _LOGCAT_SENSITIVE_HEADER.sub(
                lambda match: f"{match.group(1)}: <redacted>", safe
            )
            safe = _LOGCAT_AUTH_SECRET.sub(
                lambda match: f"{match.group(1)} <redacted>", safe
            )
            safe = _LOGCAT_JWT.sub("<token>", safe)
            safe = _LOGCAT_QUOTED_SENSITIVE_ASSIGNMENT.sub(
                lambda match: (
                    f"{match.group('prefix')}{match.group('quote')}"
                    f"<redacted>{match.group('quote')}"
                ),
                safe,
            )
            safe = _LOGCAT_SENSITIVE_ASSIGNMENT.sub(
                lambda match: f"{match.group('prefix')}<redacted>", safe
            )
        if profile == "strict":
            safe = _LOGCAT_EMAIL.sub("<email>", safe)
            safe = _LOGCAT_MAC.sub("<mac-address>", safe)
            safe = _LOGCAT_IPV4.sub("<network-address>", safe)
            safe = _LOGCAT_IPV6.sub("<network-address>", safe)
            safe = _LOGCAT_DEVICE_PATH.sub("<device-path>", safe)
        final_bytes = safe.encode("utf-8", errors="replace")
        if len(final_bytes) > _LOGCAT_LINE_LIMIT_BYTES:
            line_truncated = True
            safe = final_bytes[:_LOGCAT_LINE_LIMIT_BYTES].decode(
                "utf-8", errors="ignore"
            )
        return safe, safe != original, line_truncated

    @staticmethod
    def _export_logcat(
        destination: BoundWriteFile,
        text: str,
        cancellation: CancellationToken,
    ) -> dict[str, object]:
        if cancellation.cancelled:
            raise InterruptedError("logcat export was cancelled")
        payload = text.encode("utf-8")
        expected_digest = hashlib.sha256(payload).hexdigest()
        with destination.begin_atomic_replace() as transaction:
            stream = transaction.stream
            for offset in range(0, len(payload), 64 * 1_024):
                if cancellation.cancelled:
                    raise InterruptedError("logcat export was cancelled")
                stream.write(payload[offset : offset + 64 * 1_024])
            stream.flush()
            os.fsync(stream.fileno())
            if cancellation.cancelled:
                raise InterruptedError("logcat export was cancelled")
            transaction.commit()
            actual_digest = hashlib.sha256()
            actual_size = 0
            with transaction.open_committed() as committed:
                while chunk := committed.read(64 * 1_024):
                    if cancellation.cancelled:
                        raise AtomicWriteOutcomeUnknownError(
                            "logcat export was cancelled after atomic publication"
                        )
                    actual_size += len(chunk)
                    if actual_size > len(payload):
                        raise LogcatExportVerificationError(
                            "committed logcat export exceeds its expected size"
                        )
                    actual_digest.update(chunk)
            if actual_size != len(payload) or not hmac.compare_digest(
                actual_digest.hexdigest(),
                expected_digest,
            ):
                raise LogcatExportVerificationError(
                    "committed logcat export differs from its redacted payload"
                )
        return {
            "fileName": destination.name,
            "sha256": expected_digest,
            "size": len(payload),
        }

    def shutdown(self) -> None:
        """Terminate every managed child owned by this service."""

        for boundary in (
            self.process_launcher,
            self.secret_runner,
            self.logcat_stream_runner,
        ):
            try:
                boundary.shutdown()
            except Exception:
                pass

    def _compile_logcat(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
    ) -> DeviceToolCompilation:
        self._validate_payload(
            command,
            {
                "serial",
                "mode",
                "buffers",
                "format",
                "filters",
                "maxLines",
                "timeoutSeconds",
                "redaction",
                "exportDestination",
            },
        )
        mode = self._logcat_mode(command.payload.get("mode"))
        buffers = self._logcat_buffers(command.payload.get("buffers"))
        output_format = self._logcat_format(command.payload.get("format"))
        filters = self._logcat_filters(command.payload.get("filters"))
        redaction = self._logcat_redaction(command.payload.get("redaction"))
        max_lines = self._bounded_integer(
            command.payload.get("maxLines", 1000),
            field="maxLines",
            minimum=1,
            maximum=10_000,
        )
        timeout_seconds = self._bounded_number(
            command.payload.get("timeoutSeconds", 30),
            field="timeoutSeconds",
            minimum=1,
            maximum=120,
        )
        raw_destination = command.payload.get("exportDestination")
        if raw_destination is not None and not isinstance(raw_destination, BoundWriteFile):
            raise DeviceToolPlanningError(
                "logcat_export_grant_required",
                "logcat export requires an opaque native write grant",
            )
        export_destination = (
            raw_destination if isinstance(raw_destination, BoundWriteFile) else None
        )

        buffer_argv = tuple(argument for buffer in buffers for argument in ("-b", buffer))
        filter_argv = tuple(f"{tag}:{priority}" for tag, priority in filters)
        logcat_argv = (
            (
                "logcat",
                "-d",
                *buffer_argv,
                "-v",
                output_format,
                "-t",
                str(max_lines),
                *filter_argv,
            )
            if mode == "snapshot"
            else (
                "logcat",
                *buffer_argv,
                "-v",
                output_format,
                *filter_argv,
            )
        )
        request = ProcessRequest(
            (
                adb,
                "-s",
                device.serial,
                *logcat_argv,
            ),
            timeout_seconds=timeout_seconds,
            output_limit_bytes=_LOGCAT_OUTPUT_LIMIT,
        )
        plan = self._base_plan(
            snapshot,
            device,
            (request,),
            label=(
                f"Collect up to {max_lines} log lines from {device.serial}"
                if mode == "snapshot"
                else f"Stream up to {max_lines} log lines from {device.serial}"
            ),
            risk=(
                OperationRisk.MUTATING
                if export_destination is not None
                else OperationRisk.READ_ONLY
            ),
            postconditions=(
                (
                    OperationPostcondition(
                        "host_artifact_written",
                        {
                            "path": str(export_destination.path),
                            "minimumBytes": 0,
                            "maximumBytes": _LOGCAT_OUTPUT_LIMIT,
                        },
                        "the redacted log export is present within its byte bound",
                    ),
                )
                if export_destination is not None
                else ()
            ),
            data_behavior=(
                "host_write"
                if export_destination is not None
                else "preserve"
            ),
        )
        return DeviceToolCompilation(
            plan,
            "logcat",
            execution=(
                _EXECUTION_PROCESS
                if mode == "snapshot"
                else _EXECUTION_LOGCAT_STREAM
            ),
            logcat_mode=mode,
            logcat_redaction=redaction,
            logcat_max_lines=max_lines,
            export_destination=export_destination,
        )

    def _compile_push_files(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
        *,
        cancellation: CancellationToken | None,
        progress: DeviceToolProgress | None,
    ) -> DeviceToolCompilation:
        self._validate_payload(command, {"serial", "paths", "destination"})
        destination = command.payload.get("destination")
        if not isinstance(destination, str) or destination not in _PUSH_DESTINATIONS:
            raise DeviceToolPlanningError(
                "push_destination_invalid",
                "destination must be exactly /data/local/tmp/ or /sdcard/Download/",
            )

        paths = self._push_paths(command.payload.get("paths"))
        token = cancellation or CancellationToken()
        artifacts: list[FileArtifact] = []
        receipts: list[PushFileReceipt] = []
        total = len(paths)
        try:
            for index, source in enumerate(paths, start=1):
                path = source.path
                if token.cancelled:
                    raise InterruptedError("push source hashing was cancelled")
                if progress is not None:
                    progress(
                        ProgressPhase.STARTED,
                        f"Preparing file {index} of {total}",
                        int(((index - 1) / total) * 10),
                        index,
                        total,
                        path.name,
                    )
                artifact, size_bytes = self._file_artifact_with_size(
                    path,
                    role="push-source",
                    cancellation=token,
                    grant=source.grant,
                )
                artifacts.append(artifact)
                receipts.append(
                    PushFileReceipt(
                        path.name,
                        f"{destination}{path.name}",
                        artifact.sha256,
                        size_bytes,
                    )
                )
        except InterruptedError as error:
            code = (
                "push_timed_out"
                if token.reason is CancellationReason.DEADLINE
                else "push_cancelled"
            )
            raise DeviceToolPlanningError(code, str(error)) from None

        artifact_values = tuple(artifacts)
        requests = tuple(
            ProcessRequest(
                (
                    adb,
                    "-s",
                    device.serial,
                    "push",
                    str(source.path),
                    f"{destination}{source.path.name}",
                ),
                timeout_seconds=600.0,
                output_limit_bytes=_PUSH_OUTPUT_LIMIT,
            )
            for source in paths
        )
        plan = self._base_plan(
            snapshot,
            device,
            requests,
            label=f"Push {len(paths)} file(s) to {device.serial}",
            artifacts=artifact_values,
            risk=OperationRisk.MUTATING,
            postconditions=(
                OperationPostcondition(
                    "remote_files_written",
                    {
                        "mode": "adb",
                        "hashes": {
                            f"{destination}{source.path.name}": artifact.sha256
                            for source, artifact in zip(paths, artifact_values, strict=True)
                        },
                    },
                    "every remote file matches its backend-verified source hash",
                ),
            ),
            data_behavior="user_file_write",
        )
        return DeviceToolCompilation(
            plan,
            "pushFiles",
            device_write=True,
            requires_confirmation=True,
            push_files=tuple(receipts),
        )

    @staticmethod
    def _logcat_mode(raw_mode: object) -> str:
        if raw_mode is None:
            return "snapshot"
        if not isinstance(raw_mode, str):
            raise DeviceToolPlanningError(
                "logcat_mode_invalid",
                "logcat mode must be a string",
            )
        mode = raw_mode.strip().casefold()
        if mode not in _LOGCAT_MODES:
            raise DeviceToolPlanningError(
                "logcat_mode_invalid",
                "logcat mode must be exactly snapshot or stream",
            )
        return mode

    @staticmethod
    def _logcat_redaction(raw_redaction: object) -> str:
        if raw_redaction is None:
            return "strict"
        if not isinstance(raw_redaction, str):
            raise DeviceToolPlanningError(
                "logcat_redaction_invalid",
                "logcat redaction profile must be a string",
            )
        profile = raw_redaction.strip().casefold()
        if profile not in _LOGCAT_REDACTION_PROFILES:
            raise DeviceToolPlanningError(
                "logcat_redaction_invalid",
                "logcat redaction must be exactly strict, standard, or none",
            )
        return profile

    @staticmethod
    def _logcat_buffers(raw_buffers: object) -> tuple[str, ...]:
        if raw_buffers is None:
            return ("main",)
        if not isinstance(raw_buffers, Sequence) or isinstance(raw_buffers, (str, bytes)):
            raise DeviceToolPlanningError(
                "logcat_buffer_invalid",
                "buffers must be an array of allow-listed buffer names",
            )
        buffer_values = cast(Sequence[object], raw_buffers)
        if not 1 <= len(buffer_values) <= 6:
            raise DeviceToolPlanningError(
                "logcat_buffer_invalid",
                "between 1 and 6 log buffers are required",
            )
        normalized: list[str] = []
        for raw_buffer in buffer_values:
            if not isinstance(raw_buffer, str):
                raise DeviceToolPlanningError(
                    "logcat_buffer_invalid",
                    "log buffer names must be strings",
                )
            buffer = raw_buffer.strip().casefold()
            if buffer not in _LOGCAT_BUFFERS:
                raise DeviceToolPlanningError(
                    "logcat_buffer_invalid",
                    f"unsupported log buffer: {raw_buffer}",
                )
            if buffer in normalized:
                raise DeviceToolPlanningError(
                    "logcat_buffer_ambiguous",
                    f"duplicate log buffer: {buffer}",
                )
            normalized.append(buffer)
        if "all" in normalized and len(normalized) != 1:
            raise DeviceToolPlanningError(
                "logcat_buffer_ambiguous",
                "the all buffer cannot be combined with individual buffers",
            )
        return tuple(normalized)

    @staticmethod
    def _logcat_format(raw_format: object) -> str:
        if raw_format is None:
            return "threadtime"
        if not isinstance(raw_format, str):
            raise DeviceToolPlanningError(
                "logcat_format_invalid",
                "logcat format must be a string",
            )
        output_format = raw_format.strip().casefold()
        if output_format not in _LOGCAT_FORMATS:
            raise DeviceToolPlanningError(
                "logcat_format_invalid",
                f"unsupported logcat format: {raw_format}",
            )
        return output_format

    @staticmethod
    def _logcat_filters(raw_filters: object) -> tuple[tuple[str, str], ...]:
        if raw_filters is None:
            return ()
        if isinstance(raw_filters, Mapping):
            filter_values = tuple(cast(Mapping[object, object], raw_filters).items())
        elif isinstance(raw_filters, Sequence) and not isinstance(
            raw_filters, (str, bytes)
        ):
            parsed: list[tuple[object, object]] = []
            for raw_filter in cast(Sequence[object], raw_filters):
                if not isinstance(raw_filter, str):
                    raise DeviceToolPlanningError(
                        "logcat_filter_invalid",
                        "logcat filter entries must be strings",
                    )
                tag, separator, priority = raw_filter.rpartition(":")
                if not separator or not tag or not priority:
                    raise DeviceToolPlanningError(
                        "logcat_filter_invalid",
                        "logcat filters must use the Tag:priority form",
                    )
                parsed.append((tag, priority))
            filter_values = tuple(parsed)
        else:
            raise DeviceToolPlanningError(
                "logcat_filter_invalid",
                "filters must be an array of Tag:priority strings",
            )
        if len(filter_values) > 32:
            raise DeviceToolPlanningError(
                "logcat_filter_invalid",
                "at most 32 logcat filters are allowed",
            )
        normalized: dict[str, tuple[str, str]] = {}
        for raw_tag, raw_priority in filter_values:
            if not isinstance(raw_tag, str) or (raw_tag != "*" and not _LOGCAT_TAG_PATTERN.fullmatch(raw_tag)):
                raise DeviceToolPlanningError(
                    "logcat_filter_invalid",
                    f"invalid logcat tag: {raw_tag!r}",
                )
            if not isinstance(raw_priority, str):
                raise DeviceToolPlanningError(
                    "logcat_filter_invalid",
                    f"priority for {raw_tag!r} must be a string",
                )
            priority = _LOGCAT_PRIORITIES.get(raw_priority.strip().casefold())
            if priority is None:
                raise DeviceToolPlanningError(
                    "logcat_filter_invalid",
                    f"unsupported priority for {raw_tag!r}: {raw_priority}",
                )
            key = raw_tag.casefold()
            if key in normalized:
                raise DeviceToolPlanningError(
                    "logcat_filter_ambiguous",
                    f"duplicate logcat tag: {raw_tag}",
                )
            normalized[key] = (raw_tag, priority)

        named = sorted(
            (value for key, value in normalized.items() if key != "*"),
            key=lambda item: item[0].casefold(),
        )
        if named and "*" not in normalized:
            named.append(("*", "S"))
        elif "*" in normalized:
            named.append(normalized["*"])
        return tuple(named)

    def _push_paths(self, raw_paths: object) -> tuple[_PushSource, ...]:
        if not isinstance(raw_paths, Sequence) or isinstance(raw_paths, (str, bytes)):
            raise DeviceToolPlanningError(
                "push_paths_invalid",
                f"paths must be an array containing between 1 and {MAX_PUSH_FILES} files",
            )
        path_values = cast(Sequence[object], raw_paths)
        if not 1 <= len(path_values) <= MAX_PUSH_FILES:
            raise DeviceToolPlanningError(
                "push_paths_invalid",
                f"between 1 and {MAX_PUSH_FILES} file paths are required",
            )

        canonical_paths: list[_PushSource] = []
        seen_paths: set[str] = set()
        seen_remote_names: set[str] = set()
        for raw_path in path_values:
            grant = raw_path if isinstance(raw_path, BoundReadFile) else None
            if grant is not None:
                path = grant.path
            elif isinstance(raw_path, str) and raw_path.strip():
                expanded = Path(raw_path).expanduser()
                if not expanded.is_absolute():
                    raise DeviceToolPlanningError(
                        "push_path_ambiguous",
                        "relative push paths are not accepted",
                    )
                try:
                    path = expanded.resolve(strict=True)
                except (OSError, RuntimeError, ValueError) as error:
                    raise DeviceToolPlanningError("push_path_invalid", str(error)) from error
                if not path.is_file():
                    raise DeviceToolPlanningError(
                        "push_path_invalid",
                        f"push source is not a regular file: {path}",
                    )
            else:
                raise DeviceToolPlanningError(
                    "push_path_invalid",
                    "each push path must be a native grant or non-empty string",
                )
            if not _REMOTE_NAME_PATTERN.fullmatch(path.name) or path.name in {".", ".."}:
                raise DeviceToolPlanningError(
                    "push_name_invalid",
                    f"file name is not safe for a fixed remote destination: {path.name}",
                )

            canonical_key = os.path.normcase(str(path))
            if canonical_key in seen_paths:
                raise DeviceToolPlanningError(
                    "push_path_ambiguous",
                    f"the same canonical source was selected more than once: {path}",
                )
            remote_key = path.name.casefold()
            if remote_key in seen_remote_names:
                raise DeviceToolPlanningError(
                    "push_path_ambiguous",
                    f"multiple sources map to the same remote file name: {path.name}",
                )
            seen_paths.add(canonical_key)
            seen_remote_names.add(remote_key)
            canonical_paths.append(_PushSource(path, grant))
        return tuple(canonical_paths)

    def _scrcpy_artifact(self) -> tuple[Path, FileArtifact]:
        configured = self.scrcpy_executable
        if configured is None:
            raise DeviceToolPlanningError(
                "scrcpy_not_configured",
                "a backend-owned scrcpy executable has not been configured",
            )
        if not configured.is_absolute():
            raise DeviceToolPlanningError(
                "scrcpy_path_invalid",
                "the configured scrcpy executable must use an absolute path",
            )
        try:
            executable = configured.resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as error:
            raise DeviceToolPlanningError("scrcpy_path_invalid", str(error)) from error
        if not executable.is_file() or executable.name.casefold() not in _SCRCPY_EXECUTABLE_NAMES:
            raise DeviceToolPlanningError(
                "scrcpy_path_invalid",
                "the configured path is not a regular scrcpy executable",
            )
        if not sys.platform.startswith("win") and not os.access(executable, os.X_OK):
            raise DeviceToolPlanningError(
                "scrcpy_not_executable",
                "the configured scrcpy file is not executable",
            )
        try:
            with executable.open("rb") as stream:
                header = stream.read(4)
        except OSError as error:
            raise DeviceToolPlanningError("scrcpy_read_failed", str(error)) from error
        valid_header = (
            header.startswith(b"MZ")
            if sys.platform.startswith("win")
            else (header == b"\x7fELF" or header.startswith(b"#!") or header in _MACH_EXECUTABLE_MAGICS)
        )
        if not valid_header:
            raise DeviceToolPlanningError(
                "scrcpy_format_invalid",
                "the configured scrcpy file does not match a supported executable format",
            )
        return executable, self._file_artifact(executable, role="scrcpy-executable")

    @staticmethod
    def _wifi_endpoint(raw_host: object, raw_port: object) -> str:
        if not isinstance(raw_host, str) or not raw_host.strip():
            raise DeviceToolPlanningError(
                "wifi_host_invalid",
                "host must be a numeric IPv4 or IPv6 address",
            )
        host = raw_host.strip()
        if any(character in host for character in "[]%"):
            raise DeviceToolPlanningError(
                "wifi_host_invalid",
                "host must not contain brackets, a zone identifier, or delimiters",
            )
        try:
            address = ipaddress.ip_address(host)
        except ValueError as error:
            raise DeviceToolPlanningError(
                "wifi_host_invalid",
                "host must be a numeric IPv4 or IPv6 address",
            ) from error
        if address.is_unspecified or address.is_multicast:
            raise DeviceToolPlanningError(
                "wifi_host_invalid",
                "unspecified and multicast addresses are not valid ADB endpoints",
            )
        if not isinstance(raw_port, int) or isinstance(raw_port, bool) or not 1 <= raw_port <= 65535:
            raise DeviceToolPlanningError(
                "wifi_port_invalid",
                "port must be an integer between 1 and 65535",
            )
        normalized_host = address.compressed
        return f"[{normalized_host}]:{raw_port}" if address.version == 6 else f"{normalized_host}:{raw_port}"

    def _file_artifact(self, path: Path, *, role: str) -> FileArtifact:
        artifact, _size_bytes = self._file_artifact_with_size(path, role=role)
        return artifact

    def _file_artifact_with_size(
        self,
        path: Path,
        *,
        role: str,
        cancellation: CancellationToken | None = None,
        grant: BoundReadFile | None = None,
    ) -> tuple[FileArtifact, int]:
        code_prefix = "scrcpy" if role == "scrcpy-executable" else "push"
        try:
            digest = hashlib.sha256()
            stream_context = grant.open_verified() if grant is not None else path.open("rb")
            with stream_context as stream:
                before = os.fstat(stream.fileno())
                while chunk := stream.read(self.hash_chunk_size):
                    if cancellation is not None and cancellation.cancelled:
                        raise InterruptedError("artifact hashing was cancelled")
                    digest.update(chunk)
                after_open = os.fstat(stream.fileno())
            after = path.stat()
        except InterruptedError:
            raise
        except GrantError as error:
            raise DeviceToolPlanningError(error.code, str(error)) from error
        except OSError as error:
            raise DeviceToolPlanningError(f"{code_prefix}_hash_failed", str(error)) from error
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after_open = (
            after_open.st_dev,
            after_open.st_ino,
            after_open.st_size,
            after_open.st_mtime_ns,
        )
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_after_open or identity_before != identity_after:
            raise DeviceToolPlanningError(
                f"{code_prefix}_hash_changed",
                f"source changed while it was being hashed: {path}",
            )
        return FileArtifact(str(path), digest.hexdigest(), role), after.st_size

    @staticmethod
    def _bounded_integer(
        raw_value: object,
        *,
        field: str,
        minimum: int,
        maximum: int,
    ) -> int:
        if not isinstance(raw_value, int) or isinstance(raw_value, bool):
            raise DeviceToolPlanningError(
                "logcat_limit_invalid",
                f"{field} must be an integer",
            )
        if not minimum <= raw_value <= maximum:
            raise DeviceToolPlanningError(
                "logcat_limit_invalid",
                f"{field} must be between {minimum} and {maximum}",
            )
        return raw_value

    @staticmethod
    def _bounded_number(
        raw_value: object,
        *,
        field: str,
        minimum: float,
        maximum: float,
    ) -> float:
        if not isinstance(raw_value, (int, float)) or isinstance(raw_value, bool):
            raise DeviceToolPlanningError(
                "logcat_timeout_invalid",
                f"{field} must be a number",
            )
        value = float(raw_value)
        if not minimum <= value <= maximum:
            raise DeviceToolPlanningError(
                "logcat_timeout_invalid",
                f"{field} must be between {minimum:g} and {maximum:g}",
            )
        return value

    @staticmethod
    def _device(command: AppCommand, snapshot: AppSnapshot) -> DeviceInfo:
        raw_serial = command.payload.get("serial")
        if raw_serial is not None and (not isinstance(raw_serial, str) or not raw_serial.strip()):
            raise DeviceToolPlanningError(
                "target_serial_invalid",
                "payload.serial must be a non-empty string",
            )
        payload_serial = raw_serial.strip() if isinstance(raw_serial, str) else None
        if command.target_serial and payload_serial and command.target_serial != payload_serial:
            raise DeviceToolPlanningError(
                "ambiguous_target_serial",
                "command and payload target different devices",
            )
        serial = command.target_serial or payload_serial or snapshot.selected_serial
        if not serial:
            raise DeviceToolPlanningError(
                "target_serial_required",
                "one selected device is required",
            )
        if serial not in snapshot.selected_serials:
            raise DeviceToolPlanningError(
                "target_serial_changed",
                "target serial is no longer selected",
            )
        device = next((item for item in snapshot.devices if item.serial == serial), None)
        if device is None or not device.online:
            raise DeviceToolPlanningError(
                "device_disconnected",
                "target device is not online",
            )
        if device.mode != "adb":
            raise DeviceToolPlanningError(
                "adb_device_required",
                "device tools require a device in adb mode",
            )
        return device

    @staticmethod
    def _adb(snapshot: AppSnapshot) -> str:
        if not snapshot.toolchain.ready or not snapshot.toolchain.adb:
            raise DeviceToolPlanningError(
                "toolchain_not_ready",
                "validated adb is required",
            )
        return snapshot.toolchain.adb

    @staticmethod
    def _revision(command: AppCommand, snapshot: AppSnapshot) -> None:
        if command.expected_revision is None:
            raise DeviceToolPlanningError(
                "revision_required",
                "expected_revision is required",
            )
        if command.expected_revision != snapshot.revision:
            raise DeviceToolPlanningError(
                "stale_revision",
                (f"state revision changed: expected {command.expected_revision}, current {snapshot.revision}"),
            )

    @staticmethod
    def _host_plan(
        snapshot: AppSnapshot,
        requests: tuple[ProcessRequest, ...],
        *,
        label: str,
        risk: OperationRisk = OperationRisk.READ_ONLY,
        postconditions: tuple[OperationPostcondition, ...] = (),
        data_behavior: str = "preserve",
    ) -> OperationPlan:
        return OperationPlan(
            requests=requests,
            label=label,
            risk=risk,
            postconditions=postconditions,
            snapshot_revision=snapshot.revision,
            firmware_hash=snapshot.firmware.hash,
            boot_hash=snapshot.boot.hash,
            data_behavior=data_behavior,
            plan_revision=snapshot.plan.revision,
            fingerprint=snapshot.plan.fingerprint,
        )

    @staticmethod
    def _base_plan(
        snapshot: AppSnapshot,
        device: DeviceInfo,
        requests: tuple[ProcessRequest, ...],
        *,
        label: str,
        artifacts: tuple[FileArtifact, ...] = (),
        risk: OperationRisk = OperationRisk.READ_ONLY,
        postconditions: tuple[OperationPostcondition, ...] = (),
        data_behavior: str = "preserve",
    ) -> OperationPlan:
        return OperationPlan(
            requests=requests,
            label=label,
            risk=risk,
            postconditions=postconditions,
            snapshot_revision=snapshot.revision,
            target_serial=device.serial,
            expected_codename=device.codename,
            expected_device_state=device.mode,
            firmware_hash=snapshot.firmware.hash,
            boot_hash=snapshot.boot.hash,
            data_behavior=data_behavior,
            plan_revision=snapshot.plan.revision,
            fingerprint=snapshot.plan.fingerprint,
            artifacts=artifacts,
        )

    @staticmethod
    def _validate_payload(command: AppCommand, allowed: set[str]) -> None:
        unknown = set(command.payload) - allowed
        if unknown:
            raise DeviceToolPlanningError(
                "invalid_device_tool_payload",
                f"unsupported semantic field: {sorted(unknown)[0]}",
            )


__all__ = [
    "DEVICE_TOOL_COMMANDS",
    "MAX_PUSH_FILES",
    "DeviceToolCompilation",
    "DeviceToolProgress",
    "DeviceToolPlanningError",
    "DeviceToolsService",
    "DeviceInspectionParseError",
    "MdnsDiscoveryParseError",
    "LaunchOutcome",
    "LogcatStreamOutcome",
    "LogcatStreamRunner",
    "ManagedProcessTerminationError",
    "ManagedProcessLauncher",
    "ProcessLauncher",
    "PushFileReceipt",
    "SecretProcessRunner",
    "SubprocessSecretRunner",
    "SubprocessLogcatStreamRunner",
    "parse_bounded_getprop",
    "parse_bounded_screen_xml",
    "parse_adb_mdns_discovery",
]
