"""Typed, read-only diagnostics for Android OTA state.

The browser selects a semantic diagnostic only.  This module binds it to the
canonical ADB device and revision, emits fixed argv, and converts process
output into bounded public DTOs.  Cancelling or resetting an OTA is
intentionally absent here: that mutation requires its own verified runner and
postcondition contract.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

from .contracts import (
    AppCommand,
    AppSnapshot,
    DeviceInfo,
    OperationPlan,
    OperationResult,
    OperationRisk,
    ProcessRequest,
)

OTA_CERTIFICATES_COMMAND = "device.ota.certificates"
OTA_LOGS_COMMAND = "device.ota.logs"
OTA_DIAGNOSTIC_COMMANDS = frozenset(
    {OTA_CERTIFICATES_COMMAND, OTA_LOGS_COMMAND}
)

_CERTIFICATE_ENTRY_LIMIT = 1_024
_CERTIFICATE_OUTPUT_LIMIT = 256 * 1_024
_CERTIFICATE_NAME_LIMIT = 256
_LOG_LINE_LIMIT = 5_000
_LOG_OUTPUT_LIMIT = 8 * 1_024 * 1_024
_LOG_LINE_LENGTH_LIMIT = 4_096
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_UNSAFE_LOG_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_SENSITIVE_HEADER = re.compile(
    r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key)"
    r"\s*:\s*[^\r\n]*"
)
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b("
    r"access[_-]?token|refresh[_-]?token|id[_-]?token|token|"
    r"password|passwd|secret|api[_-]?key|x-goog-signature|x-goog-credential"
    r")\b\s*[:=]\s*.*$"
)
_AUTH_SCHEME_SECRET = re.compile(r"(?i)\b(Bearer|Basic)\s+.*$")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_IPV4_ADDRESS = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{1,5})?"
    r"(?![A-Za-z0-9])"
)
_BRACKETED_IPV6_ADDRESS = re.compile(r"\[[0-9A-Fa-f:]{2,}\](?::\d{1,5})?")
_ABSOLUTE_DEVICE_PATH = re.compile(r"(?<![A-Za-z0-9_:/])/[^\s,;]+")
_WINDOWS_STYLE_PATH = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(?:[A-Z]:[\\/]|\\\\)[^\s,;]+"
)
_PATH_CONSTRUCTOR = re.compile(
    r"(?i)\b(?:WindowsPath|PosixPath|PurePath)\([^)]*\)"
)
_UNZIP_LIST_ENTRY = re.compile(
    r"^\s*\d+\s+\d{1,4}[-/]\d{1,2}[-/]\d{1,4}\s+"
    r"\d{1,2}:\d{2}\s+(.+?)\s*$"
)
_CERTIFICATE_SUFFIXES = (".pem", ".cer", ".crt", ".der")


class OtaDiagnosticPlanningError(ValueError):
    """A semantic OTA diagnostic cannot be compiled safely."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OtaDiagnosticParseError(ValueError):
    """ADB returned malformed or oversized OTA diagnostic output."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class OtaDiagnosticCompilation:
    """One immutable diagnostic plan plus its bounded parser parameters."""

    plan: OperationPlan
    action: str
    maximum_lines: int


class OtaDiagnosticsService:
    """Compile and finalize read-only OTA diagnostics below the WebView."""

    def compile(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
    ) -> OtaDiagnosticCompilation:
        if command.kind not in OTA_DIAGNOSTIC_COMMANDS:
            raise OtaDiagnosticPlanningError(
                "ota_diagnostic_command_unsupported",
                f"unsupported OTA diagnostic command: {command.kind}",
            )
        self._revision(command, snapshot)
        device = self._device(command, snapshot)
        adb = self._adb(snapshot)
        if command.kind == OTA_CERTIFICATES_COMMAND:
            return self._compile_certificates(command, snapshot, device, adb)
        return self._compile_logs(command, snapshot, device, adb)

    def finalize(
        self,
        compilation: OtaDiagnosticCompilation,
        result: OperationResult,
    ) -> OperationResult:
        """Return a closed DTO or a typed parser failure, never implicit success."""

        if not result.ok:
            # ADB can echo device-controlled diagnostics on failure.  Keep the
            # typed terminal metadata while ensuring raw OTA output never
            # survives in canonical state, logs, or a later support package.
            return replace(result, stdout="", stderr="")
        try:
            if compilation.action == "certificates":
                value = self._parse_certificates(result.stdout)
                code = "ota_certificates_inspected"
                message = f"found {value['count']} OTA certificate entries"
            elif compilation.action == "logs":
                value = self._parse_logs(
                    result.stdout,
                    serial=compilation.plan.target_serial or "",
                    maximum_lines=compilation.maximum_lines,
                )
                code = "ota_update_engine_logs_collected"
                message = f"collected {value['lineCount']} update_engine log line(s)"
            else:
                raise OtaDiagnosticParseError(
                    "ota_diagnostic_action_invalid",
                    "the OTA diagnostic action is not recognized",
                )
        except OtaDiagnosticParseError as error:
            return OperationResult.failed(
                result.operation_id,
                code=error.code,
                message=str(error),
                exit_code=result.exit_code,
            )
        return replace(
            result,
            code=code,
            message=message,
            stdout="",
            stderr="",
            value=value,
        )

    def _compile_certificates(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
    ) -> OtaDiagnosticCompilation:
        self._validate_payload(command, {"serial"})
        # Direct argv preserves unzip's remote exit status.  In particular,
        # this deliberately avoids ``unzip | head`` where a successful head
        # process can mask a corrupt or unreadable archive.
        request = ProcessRequest(
            (
                adb,
                "-s",
                device.serial,
                "shell",
                "unzip",
                "-l",
                "/system/etc/security/otacerts.zip",
            ),
            timeout_seconds=30.0,
            output_limit_bytes=_CERTIFICATE_OUTPUT_LIMIT,
        )
        return OtaDiagnosticCompilation(
            self._base_plan(
                snapshot,
                device,
                request,
                label=f"Inspect OTA certificates on {device.serial}",
            ),
            "certificates",
            _CERTIFICATE_ENTRY_LIMIT,
        )

    def _compile_logs(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
    ) -> OtaDiagnosticCompilation:
        self._validate_payload(command, {"serial", "maxLines", "timeoutSeconds"})
        maximum_lines = self._bounded_integer(
            command.payload.get("maxLines", 1_000),
            field="maxLines",
            minimum=1,
            maximum=_LOG_LINE_LIMIT,
        )
        timeout_seconds = self._bounded_integer(
            command.payload.get("timeoutSeconds", 30),
            field="timeoutSeconds",
            minimum=1,
            maximum=120,
        )
        request = ProcessRequest(
            (
                adb,
                "-s",
                device.serial,
                "logcat",
                "-d",
                "-v",
                "threadtime",
                "-t",
                str(maximum_lines),
                "update_engine:V",
                "update_engine_client:V",
                "*:S",
            ),
            timeout_seconds=float(timeout_seconds),
            output_limit_bytes=_LOG_OUTPUT_LIMIT,
        )
        return OtaDiagnosticCompilation(
            self._base_plan(
                snapshot,
                device,
                request,
                label=f"Collect update_engine logs from {device.serial}",
            ),
            "logs",
            maximum_lines,
        )

    @staticmethod
    def _parse_certificates(stdout: str) -> dict[str, object]:
        if len(stdout.encode("utf-8", errors="replace")) > _CERTIFICATE_OUTPUT_LIMIT:
            raise OtaDiagnosticParseError(
                "ota_certificates_output_oversized",
                "the OTA certificate listing exceeded its safety limit",
            )
        raw_lines = tuple(
            line.rstrip()
            for line in stdout.replace("\r", "").splitlines()
            if line.strip()
        )
        if len(raw_lines) > _CERTIFICATE_ENTRY_LIMIT + 8:
            raise OtaDiagnosticParseError(
                "ota_certificates_output_oversized",
                "the OTA certificate listing contains too many entries",
            )
        entries: list[str] = []
        for line in raw_lines:
            matched = _UNZIP_LIST_ENTRY.match(line)
            if matched is None:
                continue
            entry = matched.group(1).strip()
            if entry.endswith("/"):
                directory = entry[:-1]
                if not OtaDiagnosticsService._safe_certificate_entry(directory):
                    raise OtaDiagnosticParseError(
                        "ota_certificate_entry_invalid",
                        "the OTA certificate listing contains an unsafe entry",
                    )
                continue
            if not OtaDiagnosticsService._safe_certificate_entry(entry):
                raise OtaDiagnosticParseError(
                    "ota_certificate_entry_invalid",
                    "the OTA certificate listing contains an unsafe entry",
                )
            if entry.casefold().endswith(_CERTIFICATE_SUFFIXES):
                entries.append(entry)
        if len(entries) > _CERTIFICATE_ENTRY_LIMIT:
            raise OtaDiagnosticParseError(
                "ota_certificates_output_oversized",
                "the OTA certificate listing contains too many entries",
            )
        if not entries:
            raise OtaDiagnosticParseError(
                "ota_certificates_unverified",
                "the ROM did not expose any OTA certificate entries",
            )
        return {
            "action": "certificates",
            # Listing otacerts proves the certificate archive is populated; it
            # does not by itself cryptographically verify the installed build.
            "archivePresent": True,
            "count": len(entries),
            "entries": entries,
            "bounded": True,
        }

    @staticmethod
    def _safe_certificate_entry(entry: str) -> bool:
        if (
            not entry
            or len(entry.encode("utf-8", errors="replace")) > _CERTIFICATE_NAME_LIMIT
            or "\x00" in entry
            or "\\" in entry
            or entry.startswith("/")
            or any(part in {"", ".", ".."} for part in entry.split("/"))
        ):
            return False
        return all(character.isprintable() for character in entry)

    @staticmethod
    def _parse_logs(
        stdout: str,
        *,
        serial: str,
        maximum_lines: int,
    ) -> dict[str, object]:
        if len(stdout.encode("utf-8", errors="replace")) > _LOG_OUTPUT_LIMIT:
            raise OtaDiagnosticParseError(
                "ota_logs_output_oversized",
                "the update_engine log output exceeded its safety limit",
            )
        raw_lines = tuple(line for line in stdout.replace("\r", "").splitlines() if line.strip())
        if len(raw_lines) > maximum_lines:
            raise OtaDiagnosticParseError(
                "ota_logs_output_oversized",
                "the update_engine log output contains more lines than requested",
            )
        lines: list[str] = []
        redacted_count = 0
        for raw_line in raw_lines:
            line_changed = False
            clean = _ANSI_ESCAPE.sub("", raw_line)
            safe_controls = _UNSAFE_LOG_CONTROL.sub("", clean)
            if safe_controls != clean:
                line_changed = True
            clean = safe_controls
            encoded = clean.encode("utf-8", errors="replace")
            if len(encoded) > _LOG_LINE_LENGTH_LIMIT:
                clean = encoded[:_LOG_LINE_LENGTH_LIMIT].decode("utf-8", errors="ignore")
                line_changed = True
            if "update_engine" not in clean.casefold():
                continue
            redacted = OtaDiagnosticsService._redact_log_line(clean, serial)
            if redacted != clean:
                line_changed = True
            if line_changed:
                redacted_count += 1
            lines.append(redacted)
        return {
            "action": "logs",
            "lineCount": len(lines),
            "lines": lines,
            "redactedCount": redacted_count,
            "bounded": True,
        }

    @staticmethod
    def _redact_log_line(line: str, serial: str) -> str:
        redacted = line.replace(serial, "<serial>") if serial else line
        redacted = _SENSITIVE_HEADER.sub(
            lambda match: f"{match.group(1)}: <redacted>",
            redacted,
        )
        redacted = _AUTH_SCHEME_SECRET.sub(
            lambda match: f"{match.group(1)} <redacted>",
            redacted,
        )
        redacted = _JWT.sub("<token>", redacted)
        redacted = _EMAIL.sub("<email>", redacted)
        redacted = _SENSITIVE_ASSIGNMENT.sub(
            lambda match: f"{match.group(1)}=<redacted>",
            redacted,
        )
        redacted = _IPV4_ADDRESS.sub("<network-address>", redacted)
        redacted = _BRACKETED_IPV6_ADDRESS.sub("<network-address>", redacted)
        redacted = _PATH_CONSTRUCTOR.sub("<device-path>", redacted)
        redacted = _WINDOWS_STYLE_PATH.sub("<device-path>", redacted)
        return _ABSOLUTE_DEVICE_PATH.sub("<device-path>", redacted)

    @staticmethod
    def _revision(command: AppCommand, snapshot: AppSnapshot) -> None:
        if command.expected_revision is None:
            raise OtaDiagnosticPlanningError(
                "revision_required",
                "expected_revision is required",
            )
        if command.expected_revision != snapshot.revision:
            raise OtaDiagnosticPlanningError(
                "stale_revision",
                (
                    f"state revision changed: expected {command.expected_revision}, "
                    f"current {snapshot.revision}"
                ),
            )

    @staticmethod
    def _device(command: AppCommand, snapshot: AppSnapshot) -> DeviceInfo:
        raw_serial = command.payload.get("serial")
        if raw_serial is not None and (
            not isinstance(raw_serial, str) or not raw_serial.strip()
        ):
            raise OtaDiagnosticPlanningError(
                "target_serial_invalid",
                "payload.serial must be a non-empty string",
            )
        payload_serial = raw_serial.strip() if isinstance(raw_serial, str) else None
        if command.target_serial and payload_serial and command.target_serial != payload_serial:
            raise OtaDiagnosticPlanningError(
                "ambiguous_target_serial",
                "command and payload target different devices",
            )
        serial = command.target_serial or payload_serial or snapshot.selected_serial
        if not serial:
            raise OtaDiagnosticPlanningError(
                "target_serial_required",
                "one selected device is required",
            )
        if serial not in snapshot.selected_serials:
            raise OtaDiagnosticPlanningError(
                "target_serial_changed",
                "target serial is no longer selected",
            )
        device = next((item for item in snapshot.devices if item.serial == serial), None)
        if device is None or not device.online:
            raise OtaDiagnosticPlanningError(
                "device_disconnected",
                "target device is not online",
            )
        if device.mode != "adb":
            raise OtaDiagnosticPlanningError(
                "adb_device_required",
                "OTA diagnostics require a device in adb mode",
            )
        return device

    @staticmethod
    def _adb(snapshot: AppSnapshot) -> str:
        if not snapshot.toolchain.ready or not snapshot.toolchain.adb:
            raise OtaDiagnosticPlanningError(
                "toolchain_not_ready",
                "validated adb is required",
            )
        return snapshot.toolchain.adb

    @staticmethod
    def _base_plan(
        snapshot: AppSnapshot,
        device: DeviceInfo,
        request: ProcessRequest,
        *,
        label: str,
    ) -> OperationPlan:
        return OperationPlan(
            requests=(request,),
            label=label,
            risk=OperationRisk.READ_ONLY,
            snapshot_revision=snapshot.revision,
            target_serial=device.serial,
            expected_codename=device.codename,
            expected_device_state=device.mode,
            firmware_hash=snapshot.firmware.hash,
            boot_hash=snapshot.boot.hash,
            data_behavior="preserve",
            plan_revision=snapshot.plan.revision,
            fingerprint=snapshot.plan.fingerprint,
        )

    @staticmethod
    def _validate_payload(command: AppCommand, allowed: set[str]) -> None:
        unknown = set(command.payload) - allowed
        if unknown:
            raise OtaDiagnosticPlanningError(
                "invalid_ota_diagnostic_payload",
                f"unsupported semantic field: {sorted(unknown)[0]}",
            )

    @staticmethod
    def _bounded_integer(
        value: object,
        *,
        field: str,
        minimum: int,
        maximum: int,
    ) -> int:
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not minimum <= value <= maximum
        ):
            raise OtaDiagnosticPlanningError(
                "invalid_ota_diagnostic_payload",
                f"{field} must be an integer from {minimum} to {maximum}",
            )
        return value


__all__ = [
    "OTA_CERTIFICATES_COMMAND",
    "OTA_DIAGNOSTIC_COMMANDS",
    "OTA_LOGS_COMMAND",
    "OtaDiagnosticCompilation",
    "OtaDiagnosticParseError",
    "OtaDiagnosticPlanningError",
    "OtaDiagnosticsService",
]
