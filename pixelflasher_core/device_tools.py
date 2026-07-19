"""Headless, fail-closed compilation for bounded Android utility commands.

The WebView supplies semantic intent only.  This service resolves the selected
device and validated toolchain from :class:`AppSnapshot`, validates a small
allow-list of options, and emits argv-only :class:`OperationPlan` instances.
It deliberately does not expose a general-purpose ADB shell.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ElementTree
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

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
    SensitiveText,
)
from .executor import CancellationToken, TransportOutcome

DEVICE_TOOL_COMMANDS = frozenset(
    {
        "tools.logcat",
        "tools.pushFiles",
        "tools.adbShell",
        "tools.scrcpy",
        "tools.wifi",
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

_PUSH_DESTINATIONS = frozenset({"/data/local/tmp/", "/sdcard/Download/"})
_REMOTE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
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

    def shutdown(self) -> None: ...


class SecretProcessRunner(Protocol):
    """Injectable boundary which sends one secret through process stdin."""

    def run(
        self,
        request: ProcessRequest,
        secret: str,
        cancellation: CancellationToken,
    ) -> TransportOutcome: ...


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

    def shutdown(self) -> None:
        with self._lock:
            self._closed = True
            children = tuple(self._children.values())
            self._children.clear()
        for process in children:
            if process.poll() is not None:
                continue
            try:
                process.terminate()
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                    process.wait(timeout=1)
                except (OSError, subprocess.TimeoutExpired):
                    continue

    def _reap_finished(self) -> None:
        finished = [pid for pid, process in self._children.items() if process.poll() is not None]
        for pid in finished:
            self._children.pop(pid, None)


class SubprocessSecretRunner:
    """Run one argv-only process while keeping a credential out of argv/env."""

    poll_interval_seconds = 0.05

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
        process = subprocess.Popen(  # noqa: S603 - reviewed argv, shell disabled
            list(request.argv),
            cwd=request.cwd,
            env=environment,
            shell=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding=request.encoding,
            errors="replace",
        )
        assert process.stdin is not None
        try:
            process.stdin.write(secret + "\n")
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass
            process.stdin = None

        deadline = time.monotonic() + request.timeout_seconds if request.timeout_seconds is not None else None
        while True:
            if cancellation.cancelled:
                stdout, stderr = self._terminate(process)
                return TransportOutcome(process.returncode, stdout, stderr, cancelled=True)
            if deadline is not None and time.monotonic() >= deadline:
                stdout, stderr = self._terminate(process)
                return TransportOutcome(process.returncode, stdout, stderr, timed_out=True)
            try:
                stdout, stderr = process.communicate(timeout=self.poll_interval_seconds)
            except subprocess.TimeoutExpired:
                continue
            return TransportOutcome(process.returncode, stdout, stderr)

    @staticmethod
    def _terminate(process: subprocess.Popen[str]) -> tuple[str, str]:
        process.terminate()
        try:
            return process.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            return process.communicate()


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

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "device_write": self.device_write,
            "destructive": self.destructive,
            "requires_confirmation": self.requires_confirmation,
            "execution": self.execution,
            "endpoint": self.endpoint,
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
    ) -> None:
        if not isinstance(hash_chunk_size, int) or isinstance(hash_chunk_size, bool):
            raise TypeError("hash_chunk_size must be an integer")
        if hash_chunk_size <= 0:
            raise ValueError("hash_chunk_size must be positive")
        self.hash_chunk_size = hash_chunk_size
        self.scrcpy_executable = Path(scrcpy_executable).expanduser() if scrcpy_executable is not None else None
        self.process_launcher = process_launcher or ManagedProcessLauncher()
        self.secret_runner = secret_runner or SubprocessSecretRunner()

    def compile(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
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
        device = self._device(command, snapshot)
        adb = self._adb(snapshot)
        if command.kind == "tools.scrcpy":
            return self._compile_scrcpy(command, snapshot, device)
        if command.kind == "device.inspect":
            return self._compile_inspection(command, snapshot, device, adb)
        if command.kind == "tools.wifi":
            return self._compile_wifi(command, snapshot, device, adb)
        if command.kind == "tools.logcat":
            return self._compile_logcat(command, snapshot, device, adb)
        return self._compile_push_files(command, snapshot, device, adb)

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
        device: DeviceInfo,
        adb: str,
    ) -> DeviceToolCompilation:
        self._validate_payload(
            command,
            {"serial", "action", "host", "port", "pairingCode"},
        )
        raw_action = command.payload.get("action")
        if not isinstance(raw_action, str):
            raise DeviceToolPlanningError(
                "wifi_action_invalid",
                "action must be exactly pair, connect, disconnect, or status",
            )
        action = raw_action.strip().casefold()
        if action not in {"pair", "connect", "disconnect", "status"}:
            raise DeviceToolPlanningError(
                "wifi_action_invalid",
                "action must be exactly pair, connect, disconnect, or status",
            )

        if action == "status":
            unexpected = set(command.payload) & {"host", "port", "pairingCode"}
            if unexpected:
                raise DeviceToolPlanningError(
                    "wifi_status_payload_invalid",
                    f"status does not accept {sorted(unexpected)[0]}",
                )
            request = ProcessRequest(
                (adb, "-s", device.serial, "get-state"),
                timeout_seconds=10.0,
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
        )
        postcondition = (
            OperationPostcondition(
                "adb_wifi_pairing_recorded",
                {"endpoint": endpoint},
                "the ADB pairing record is independently observable",
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
            self._base_plan(
                snapshot,
                device,
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

    def execute_special(
        self,
        compilation: DeviceToolCompilation,
        operation_id: str,
        cancellation: CancellationToken,
    ) -> OperationResult:
        """Cross one special boundary without exposing secrets or orphaning tests."""

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

        value: dict[str, object] = {
            "action": action,
            "targetSerial": compilation.plan.target_serial,
        }
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

    def shutdown(self) -> None:
        """Terminate managed scrcpy children owned by this service."""

        try:
            self.process_launcher.shutdown()
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
            {"serial", "buffers", "format", "filters", "maxLines", "timeoutSeconds"},
        )
        buffers = self._logcat_buffers(command.payload.get("buffers"))
        output_format = self._logcat_format(command.payload.get("format"))
        filters = self._logcat_filters(command.payload.get("filters"))
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

        buffer_argv = tuple(argument for buffer in buffers for argument in ("-b", buffer))
        filter_argv = tuple(f"{tag}:{priority}" for tag, priority in filters)
        request = ProcessRequest(
            (
                adb,
                "-s",
                device.serial,
                "logcat",
                "-d",
                *buffer_argv,
                "-v",
                output_format,
                "-t",
                str(max_lines),
                *filter_argv,
            ),
            timeout_seconds=timeout_seconds,
        )
        plan = self._base_plan(
            snapshot,
            device,
            (request,),
            label=f"Collect up to {max_lines} log lines from {device.serial}",
        )
        return DeviceToolCompilation(plan, "logcat")

    def _compile_push_files(
        self,
        command: AppCommand,
        snapshot: AppSnapshot,
        device: DeviceInfo,
        adb: str,
    ) -> DeviceToolCompilation:
        self._validate_payload(command, {"serial", "paths", "destination"})
        destination = command.payload.get("destination")
        if not isinstance(destination, str) or destination not in _PUSH_DESTINATIONS:
            raise DeviceToolPlanningError(
                "push_destination_invalid",
                "destination must be exactly /data/local/tmp/ or /sdcard/Download/",
            )

        paths = self._push_paths(command.payload.get("paths"))
        artifacts = tuple(self._file_artifact(path, role="push-source") for path in paths)
        requests = tuple(
            ProcessRequest(
                (
                    adb,
                    "-s",
                    device.serial,
                    "push",
                    str(path),
                    f"{destination}{path.name}",
                ),
                timeout_seconds=600.0,
            )
            for path in paths
        )
        plan = self._base_plan(
            snapshot,
            device,
            requests,
            label=f"Push {len(paths)} file(s) to {device.serial}",
            artifacts=artifacts,
            risk=OperationRisk.MUTATING,
            postconditions=(
                OperationPostcondition(
                    "remote_files_written",
                    {
                        "mode": "adb",
                        "hashes": {
                            f"{destination}{path.name}": artifact.sha256
                            for path, artifact in zip(paths, artifacts, strict=True)
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
        )

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
        if not isinstance(raw_filters, Mapping):
            raise DeviceToolPlanningError(
                "logcat_filter_invalid",
                "filters must be an object mapping tags to priorities",
            )
        filter_values = cast(Mapping[object, object], raw_filters)
        if len(filter_values) > 32:
            raise DeviceToolPlanningError(
                "logcat_filter_invalid",
                "at most 32 logcat filters are allowed",
            )
        normalized: dict[str, tuple[str, str]] = {}
        for raw_tag, raw_priority in filter_values.items():
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

    def _push_paths(self, raw_paths: object) -> tuple[Path, ...]:
        if not isinstance(raw_paths, Sequence) or isinstance(raw_paths, (str, bytes)):
            raise DeviceToolPlanningError(
                "push_paths_invalid",
                "paths must be an array containing between 1 and 32 files",
            )
        path_values = cast(Sequence[object], raw_paths)
        if not 1 <= len(path_values) <= 32:
            raise DeviceToolPlanningError(
                "push_paths_invalid",
                "between 1 and 32 file paths are required",
            )

        canonical_paths: list[Path] = []
        seen_paths: set[str] = set()
        seen_remote_names: set[str] = set()
        for raw_path in path_values:
            if not isinstance(raw_path, str) or not raw_path.strip():
                raise DeviceToolPlanningError(
                    "push_path_invalid",
                    "each push path must be a non-empty string",
                )
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
            canonical_paths.append(path)
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
        code_prefix = "scrcpy" if role == "scrcpy-executable" else "push"
        try:
            before = path.stat()
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                while chunk := stream.read(self.hash_chunk_size):
                    digest.update(chunk)
            after = path.stat()
        except OSError as error:
            raise DeviceToolPlanningError(f"{code_prefix}_hash_failed", str(error)) from error
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_after:
            raise DeviceToolPlanningError(
                f"{code_prefix}_hash_changed",
                f"source changed while it was being hashed: {path}",
            )
        return FileArtifact(str(path), digest.hexdigest(), role)

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
    ) -> OperationPlan:
        return OperationPlan(
            requests=requests,
            label=label,
            risk=OperationRisk.READ_ONLY,
            snapshot_revision=snapshot.revision,
            firmware_hash=snapshot.firmware.hash,
            boot_hash=snapshot.boot.hash,
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
    "DeviceToolCompilation",
    "DeviceToolPlanningError",
    "DeviceToolsService",
    "DeviceInspectionParseError",
    "MdnsDiscoveryParseError",
    "LaunchOutcome",
    "ManagedProcessLauncher",
    "ProcessLauncher",
    "SecretProcessRunner",
    "SubprocessSecretRunner",
    "parse_bounded_getprop",
    "parse_bounded_screen_xml",
    "parse_adb_mdns_discovery",
]
