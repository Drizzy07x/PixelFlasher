"""Bounded postcondition observation for device- and host-scoped mutations."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, runtime_checkable

from .contracts import ProcessRequest, ToolchainInfo, is_valid_target_serial
from .devices import DeviceService, parse_fastboot_getvar
from .executor import CancellationToken, ProcessTransport, TransportOutcome
from .ota_diagnostics import OtaDiagnosticParseError, parse_update_engine_status

_REMOTE_PATH_PATTERN = re.compile(r"^/(?:[A-Za-z0-9._+-]{1,128}/)*[A-Za-z0-9._+-]{1,128}$")
_PARTITION_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_PACKAGE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$")
_REPORTED_PACKAGE_PATH_PATTERN = re.compile(r"^/(?:[A-Za-z0-9._+~=@%:-]{1,160}/)*[A-Za-z0-9._+~=@%:-]{1,160}$")
_MODULE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
_SU_POLICY_STATE_PATTERN = re.compile(r"^(?:absent|(?:allow|deny):[01]:[01]:\d{1,10})$")
_SU_POLICY_ROW_PATTERN = re.compile(r"^PF_SU\|(\d{1,10})\|([12])\|([01])\|([01])\|(\d{1,10})$")
_FASTBOOT_FETCH_PATTERN = re.compile(r"(?mi)^\s*fetch(?:\s|:)")
_MAX_PROPERTY_OUTPUT_BYTES = 4 * 1024
_MAX_REMOTE_HASH_OUTPUT_BYTES = 64 * 1024
_MAX_FASTBOOT_OUTPUT_BYTES = 64 * 1024
_MAX_ADB_INVENTORY_OUTPUT_BYTES = 64 * 1024
_MAX_HELP_OUTPUT_BYTES = 128 * 1024
_MAX_OTA_STATUS_OUTPUT_BYTES = 64 * 1024
_DEFAULT_MAX_PARTITION_BYTES = 128 * 1024 * 1024
_DEFAULT_MAX_HASH_TARGETS = 16
_DEFAULT_MAX_REMOTE_HASH_TARGETS = 32


class ObservationStatus(StrEnum):
    VERIFIED = "verified"
    MISMATCH = "mismatch"
    UNVERIFIED = "unverified"
    DISCONNECTED = "disconnected"
    CANCELLED = "cancelled"


class ObservationProbeUnavailable(RuntimeError):
    """A fixed failure for evidence that cannot become available by polling."""


def _empty_hashes() -> Mapping[str, str]:
    return {}


def _empty_mismatches() -> Mapping[str, tuple[object, object]]:
    return {}


def _empty_booleans() -> Mapping[str, bool]:
    return {}


def _empty_int_strings() -> Mapping[int, str]:
    return {}


@dataclass(frozen=True, slots=True)
class DeviceObservation:
    serial: str
    connected: bool = True
    mode: str | None = None
    slot: str | None = None
    bootloader: str | None = None
    boot_completed: bool | None = None
    build: str | None = None
    remote_hashes: Mapping[str, str] = field(default_factory=_empty_hashes)
    partition_hashes: Mapping[str, str] = field(default_factory=_empty_hashes)
    packages: Mapping[str, bool] = field(default_factory=_empty_booleans)
    package_states: Mapping[str, str] = field(default_factory=_empty_hashes)
    adb_endpoints: Mapping[str, bool] = field(default_factory=_empty_booleans)
    root_modules: Mapping[str, str] = field(default_factory=_empty_hashes)
    magisk_denylist: Mapping[str, bool] = field(default_factory=_empty_booleans)
    magisk_su_policies: Mapping[int, str] = field(default_factory=_empty_int_strings)
    erased_partitions: Mapping[str, bool] = field(default_factory=_empty_booleans)
    safe_mode: bool | None = None
    ota_idle: bool | None = None

    def __post_init__(self) -> None:
        if self.safe_mode is not None and not isinstance(self.safe_mode, bool):
            raise TypeError("observed safe mode state must be a boolean or null")
        if self.ota_idle is not None and not isinstance(self.ota_idle, bool):
            raise TypeError("observed OTA idle state must be a boolean or null")
        if any(not isinstance(value, bool) for value in self.packages.values()):
            raise TypeError("observed package states must be booleans")
        if any(not isinstance(value, str) for value in self.package_states.values()):
            raise TypeError("observed package lifecycle states must be strings")
        if any(not isinstance(value, bool) for value in self.adb_endpoints.values()):
            raise TypeError("observed ADB endpoint states must be booleans")
        if any(not isinstance(value, str) for value in self.root_modules.values()):
            raise TypeError("observed root module states must be strings")
        if any(
            not isinstance(package, str)
            or _PACKAGE_PATTERN.fullmatch(package) is None
            or not isinstance(value, bool)
            for package, value in self.magisk_denylist.items()
        ):
            raise TypeError("observed Magisk denylist states must be booleans")
        if any(
            not isinstance(uid, int)
            or isinstance(uid, bool)
            or not isinstance(value, str)
            or _SU_POLICY_STATE_PATTERN.fullmatch(value) is None
            for uid, value in self.magisk_su_policies.items()
        ):
            raise TypeError("observed Magisk SU policies are invalid")
        if any(not isinstance(value, bool) for value in self.erased_partitions.values()):
            raise TypeError("observed erased partition states must be booleans")
        object.__setattr__(self, "remote_hashes", MappingProxyType(dict(self.remote_hashes)))
        object.__setattr__(self, "partition_hashes", MappingProxyType(dict(self.partition_hashes)))
        object.__setattr__(self, "packages", MappingProxyType(dict(self.packages)))
        object.__setattr__(
            self,
            "package_states",
            MappingProxyType(dict(self.package_states)),
        )
        object.__setattr__(
            self,
            "adb_endpoints",
            MappingProxyType(dict(self.adb_endpoints)),
        )
        object.__setattr__(self, "root_modules", MappingProxyType(dict(self.root_modules)))
        object.__setattr__(
            self,
            "magisk_denylist",
            MappingProxyType(dict(self.magisk_denylist)),
        )
        object.__setattr__(
            self,
            "magisk_su_policies",
            MappingProxyType(dict(self.magisk_su_policies)),
        )
        object.__setattr__(
            self,
            "erased_partitions",
            MappingProxyType(dict(self.erased_partitions)),
        )


@dataclass(frozen=True, slots=True)
class HostObservation:
    """Bounded evidence about host-owned ADB daemon state."""

    adb_endpoints: Mapping[str, bool] = field(default_factory=_empty_booleans)

    def __post_init__(self) -> None:
        if any(
            not isinstance(endpoint, str) or not isinstance(value, bool)
            for endpoint, value in self.adb_endpoints.items()
        ):
            raise TypeError("observed host ADB endpoint states are invalid")
        object.__setattr__(
            self,
            "adb_endpoints",
            MappingProxyType(dict(self.adb_endpoints)),
        )


@dataclass(frozen=True, slots=True)
class HostPostconditionSpec:
    """Postconditions that can be proven without a selected device."""

    timeout_seconds: float
    expected_adb_endpoints: Mapping[str, bool] = field(default_factory=_empty_booleans)

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("host postcondition timeout must be positive")
        if not self.expected_adb_endpoints:
            raise ValueError("host postconditions require at least one ADB endpoint")
        if any(
            not isinstance(endpoint, str)
            or not ProcessDeviceObservationProbe.safe_adb_endpoint(endpoint)
            or not isinstance(value, bool)
            for endpoint, value in self.expected_adb_endpoints.items()
        ):
            raise ValueError("expected host ADB endpoint state is invalid")
        object.__setattr__(
            self,
            "expected_adb_endpoints",
            MappingProxyType(dict(self.expected_adb_endpoints)),
        )


@dataclass(frozen=True, slots=True)
class PostconditionSpec:
    serial: str
    timeout_seconds: float
    expected_mode: str | None = None
    expected_slot: str | None = None
    expected_bootloader: str | None = None
    expected_boot_completed: bool | None = None
    expected_build: str | None = None
    remote_hashes: Mapping[str, str] = field(default_factory=_empty_hashes)
    partition_hashes: Mapping[str, str] = field(default_factory=_empty_hashes)
    expected_packages: Mapping[str, bool] = field(default_factory=_empty_booleans)
    expected_package_states: Mapping[str, str] = field(default_factory=_empty_hashes)
    expected_adb_endpoints: Mapping[str, bool] = field(default_factory=_empty_booleans)
    expected_root_modules: Mapping[str, str] = field(default_factory=_empty_hashes)
    expected_magisk_denylist: Mapping[str, bool] = field(default_factory=_empty_booleans)
    expected_magisk_su_policies: Mapping[int, str] = field(default_factory=_empty_int_strings)
    erased_partitions: tuple[str, ...] = ()
    expected_safe_mode: bool | None = None
    expected_ota_idle: bool | None = None

    def __post_init__(self) -> None:
        if not self.serial:
            raise ValueError("postcondition serial is required")
        if self.timeout_seconds <= 0:
            raise ValueError("postcondition timeout must be positive")
        if self.expected_slot not in {None, "a", "b"}:
            raise ValueError("expected slot must be a, b, or null")
        if self.expected_safe_mode is not None and not isinstance(
            self.expected_safe_mode,
            bool,
        ):
            raise TypeError("expected safe mode state must be a boolean or null")
        if self.expected_ota_idle is not None and not isinstance(
            self.expected_ota_idle,
            bool,
        ):
            raise TypeError("expected OTA idle state must be a boolean or null")
        if any(not isinstance(value, bool) for value in self.expected_packages.values()):
            raise TypeError("expected package states must be booleans")
        allowed_package_states = {
            "absent",
            "installed",
            "enabled",
            "disabled",
            "running",
            "stopped",
        }
        if any(
            not isinstance(value, str) or value not in allowed_package_states
            for value in self.expected_package_states.values()
        ):
            raise ValueError("expected package lifecycle state is invalid")
        if any(
            not isinstance(endpoint, str)
            or not ProcessDeviceObservationProbe.safe_adb_endpoint(endpoint)
            or not isinstance(value, bool)
            for endpoint, value in self.expected_adb_endpoints.items()
        ):
            raise ValueError("expected ADB endpoint state is invalid")
        allowed_module_states = {
            "absent",
            "installed",
            "enabled",
            "disabled",
            "pending_remove",
        }
        if any(
            not isinstance(value, str) or value not in allowed_module_states
            for value in self.expected_root_modules.values()
        ):
            raise ValueError("expected root module state is invalid")
        if any(
            not isinstance(package, str)
            or _PACKAGE_PATTERN.fullmatch(package) is None
            or not isinstance(listed, bool)
            for package, listed in self.expected_magisk_denylist.items()
        ):
            raise ValueError("expected Magisk denylist state is invalid")
        if any(
            not isinstance(uid, int)
            or isinstance(uid, bool)
            or not 0 <= uid <= 2_147_483_647
            or not isinstance(state, str)
            or _SU_POLICY_STATE_PATTERN.fullmatch(state) is None
            for uid, state in self.expected_magisk_su_policies.items()
        ):
            raise ValueError("expected Magisk SU policy is invalid")
        if any(not isinstance(value, str) or not value for value in self.erased_partitions) or len(
            self.erased_partitions
        ) != len(set(self.erased_partitions)):
            raise ValueError("erased partitions must contain unique non-empty names")
        object.__setattr__(self, "remote_hashes", MappingProxyType(dict(self.remote_hashes)))
        object.__setattr__(self, "partition_hashes", MappingProxyType(dict(self.partition_hashes)))
        object.__setattr__(
            self,
            "expected_packages",
            MappingProxyType(dict(self.expected_packages)),
        )
        object.__setattr__(
            self,
            "expected_package_states",
            MappingProxyType(dict(self.expected_package_states)),
        )
        object.__setattr__(
            self,
            "expected_adb_endpoints",
            MappingProxyType(dict(self.expected_adb_endpoints)),
        )
        object.__setattr__(
            self,
            "expected_root_modules",
            MappingProxyType(dict(self.expected_root_modules)),
        )
        object.__setattr__(
            self,
            "expected_magisk_denylist",
            MappingProxyType(dict(self.expected_magisk_denylist)),
        )
        object.__setattr__(
            self,
            "expected_magisk_su_policies",
            MappingProxyType(dict(self.expected_magisk_su_policies)),
        )
        object.__setattr__(self, "erased_partitions", tuple(self.erased_partitions))


@dataclass(frozen=True, slots=True)
class ObservationResult:
    status: ObservationStatus
    code: str
    message: str
    attempts: int
    mismatches: Mapping[str, tuple[object, object]] = field(default_factory=_empty_mismatches)
    missing: tuple[str, ...] = ()
    observation: DeviceObservation | HostObservation | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "mismatches", MappingProxyType(dict(self.mismatches)))
        object.__setattr__(self, "missing", tuple(self.missing))

    @property
    def verified(self) -> bool:
        return self.status is ObservationStatus.VERIFIED


class ObservationProbe(Protocol):
    def observe(self, serial: str) -> DeviceObservation | None: ...


@runtime_checkable
class SpecObservationProbe(Protocol):
    """Optional extension for probes that can collect requested hash evidence."""

    def observe_spec(
        self,
        spec: PostconditionSpec,
        cancellation: CancellationToken,
    ) -> DeviceObservation | None: ...


@runtime_checkable
class HostSpecObservationProbe(Protocol):
    """Optional probe extension for application-scoped ADB evidence."""

    def observe_host_spec(
        self,
        spec: HostPostconditionSpec,
        cancellation: CancellationToken,
    ) -> HostObservation | None: ...


ToolchainProvider = Callable[[], ToolchainInfo]


@dataclass(frozen=True, slots=True)
class _ProbeAttempt:
    observation: DeviceObservation | None = None
    explicitly_absent: bool = False


class ProcessDeviceObservationProbe:
    """Collect bounded postcondition evidence through exact ADB/fastboot argv.

    Every device query is bound to the requested serial and crosses a
    ProcessTransport as an argv tuple. No host shell or UI state is used.
    Unsupported, malformed, oversized, or incomplete evidence is omitted so
    that PostconditionObserver fails closed.
    """

    def __init__(
        self,
        device_service: DeviceService,
        toolchain_provider: ToolchainProvider,
        *,
        command_timeout_seconds: float = 4.0,
        max_partition_bytes: int = _DEFAULT_MAX_PARTITION_BYTES,
        max_hash_targets: int = _DEFAULT_MAX_HASH_TARGETS,
        max_remote_hash_targets: int = _DEFAULT_MAX_REMOTE_HASH_TARGETS,
        temporary_root: str | Path | None = None,
    ) -> None:
        if command_timeout_seconds <= 0:
            raise ValueError("observer command timeout must be positive")
        if max_partition_bytes <= 0:
            raise ValueError("observer partition limit must be positive")
        if max_hash_targets <= 0:
            raise ValueError("observer hash target limit must be positive")
        if max_remote_hash_targets <= 0:
            raise ValueError("observer remote hash target limit must be positive")
        self.device_service = device_service
        self.transport: ProcessTransport = device_service.transport
        self.toolchain_provider = toolchain_provider
        self.command_timeout_seconds = float(command_timeout_seconds)
        self.max_partition_bytes = int(max_partition_bytes)
        self.max_hash_targets = int(max_hash_targets)
        self.max_remote_hash_targets = int(max_remote_hash_targets)
        self.temporary_root = Path(temporary_root).resolve() if temporary_root is not None else None

    def observe(self, serial: str) -> DeviceObservation | None:
        """Retain the original probe protocol for connection-only callers."""

        try:
            spec = PostconditionSpec(serial, self.command_timeout_seconds)
        except (TypeError, ValueError):
            return None
        try:
            return self.observe_spec(spec, CancellationToken())
        except ObservationProbeUnavailable:
            return None

    def observe_spec(
        self,
        spec: PostconditionSpec,
        cancellation: CancellationToken,
    ) -> DeviceObservation | None:
        serial = spec.serial
        if not is_valid_target_serial(serial):
            raise ObservationProbeUnavailable("postcondition serial is invalid")
        if cancellation.cancelled:
            return None
        try:
            toolchain = self.toolchain_provider()
        except Exception:
            raise ObservationProbeUnavailable("postcondition toolchain is unavailable") from None
        if (
            not isinstance(toolchain, ToolchainInfo)
            or not toolchain.ready
            or not toolchain.adb
            or not toolchain.fastboot
        ):
            raise ObservationProbeUnavailable("postcondition toolchain is unavailable")

        timeout = min(self.command_timeout_seconds, spec.timeout_seconds)
        adb = self._observe_adb(spec, toolchain, cancellation, timeout)
        if adb.observation is not None:
            return adb.observation
        fastboot = self._observe_fastboot(spec, toolchain, cancellation, timeout)
        if fastboot.observation is not None:
            return fastboot.observation
        if adb.explicitly_absent and fastboot.explicitly_absent:
            return DeviceObservation(serial, connected=False)
        return None

    def observe_host_spec(
        self,
        spec: HostPostconditionSpec,
        cancellation: CancellationToken,
    ) -> HostObservation | None:
        if cancellation.cancelled:
            return None
        try:
            toolchain = self.toolchain_provider()
        except Exception:
            raise ObservationProbeUnavailable("host postcondition toolchain is unavailable") from None
        if not isinstance(toolchain, ToolchainInfo) or not toolchain.ready or not toolchain.adb:
            raise ObservationProbeUnavailable("host postcondition toolchain is unavailable")
        timeout = min(self.command_timeout_seconds, spec.timeout_seconds)
        endpoints = self._adb_endpoint_states(
            spec,
            toolchain,
            cancellation,
            timeout,
        )
        return HostObservation(endpoints) if endpoints else None

    def _observe_adb(
        self,
        spec: PostconditionSpec,
        toolchain: ToolchainInfo,
        token: CancellationToken,
        timeout: float,
    ) -> _ProbeAttempt:
        state_outcome = self._run(
            (toolchain.adb, "-s", spec.serial, "get-state"),
            token,
            timeout,
        )
        if not self._successful(state_outcome, _MAX_PROPERTY_OUTPUT_BYTES):
            return _ProbeAttempt(explicitly_absent=self._explicit_absence(state_outcome, spec.serial))
        assert state_outcome is not None
        raw_state = self._single_value(state_outcome.stdout)
        state = raw_state.casefold() if raw_state is not None else None
        if state not in {"device", "recovery", "sideload"}:
            return _ProbeAttempt()

        mode = {"device": "adb", "recovery": "recovery", "sideload": "sideload"}[state]
        properties_available = state != "sideload"
        if state == "device":
            boot_mode = self._adb_property(
                toolchain,
                spec.serial,
                "ro.bootmode",
                token,
                timeout,
            )
            if boot_mode is not None and boot_mode.casefold() == "recovery":
                mode = "recovery"

        slot: str | None = None
        bootloader: str | None = None
        boot_completed: bool | None = None
        safe_mode: bool | None = None
        build: str | None = None
        ota_idle: bool | None = None
        if properties_available and spec.expected_slot is not None:
            raw_slot = self._adb_property(
                toolchain,
                spec.serial,
                "ro.boot.slot_suffix",
                token,
                timeout,
            )
            normalized_slot = raw_slot.lstrip("_").casefold() if raw_slot is not None else ""
            slot = normalized_slot if normalized_slot in {"a", "b"} else None
        if properties_available and spec.expected_bootloader is not None:
            locked = self._adb_property(
                toolchain,
                spec.serial,
                "ro.boot.flash.locked",
                token,
                timeout,
            )
            bootloader = self._locked_state(locked)
            if bootloader is None:
                vbmeta = self._adb_property(
                    toolchain,
                    spec.serial,
                    "ro.boot.vbmeta.device_state",
                    token,
                    timeout,
                )
                normalized_vbmeta = vbmeta.casefold() if vbmeta is not None else None
                if normalized_vbmeta in {"locked", "unlocked"}:
                    bootloader = normalized_vbmeta
        if properties_available and spec.expected_boot_completed is not None:
            completed = self._adb_property(
                toolchain,
                spec.serial,
                "sys.boot_completed",
                token,
                timeout,
            )
            if completed in {"0", "1"}:
                boot_completed = completed == "1"
        if properties_available and spec.expected_safe_mode is not None:
            raw_safe_mode = self._adb_property(
                toolchain,
                spec.serial,
                "ro.sys.safemode",
                token,
                timeout,
            )
            if raw_safe_mode in {"0", "1"}:
                safe_mode = raw_safe_mode == "1"
        if properties_available and spec.expected_build is not None:
            raw_build = self._adb_property(
                toolchain,
                spec.serial,
                "ro.build.id",
                token,
                timeout,
            )
            if raw_build and self._safe_property(raw_build):
                build = raw_build
        if mode == "adb" and spec.expected_ota_idle is not None:
            ota_idle = self._ota_idle(
                toolchain,
                spec.serial,
                token,
                timeout,
            )

        remote_hashes = self._remote_hashes(
            spec,
            toolchain,
            mode,
            token,
            timeout,
        )
        return _ProbeAttempt(
            DeviceObservation(
                spec.serial,
                connected=True,
                mode=mode,
                slot=slot,
                bootloader=bootloader,
                boot_completed=boot_completed,
                safe_mode=safe_mode,
                build=build,
                ota_idle=ota_idle,
                remote_hashes=remote_hashes,
                packages=self._packages(spec, toolchain, mode, token, timeout),
                package_states=self._package_states(
                    spec,
                    toolchain,
                    mode,
                    token,
                    timeout,
                ),
                adb_endpoints=self._adb_endpoint_states(
                    spec,
                    toolchain,
                    token,
                    timeout,
                ),
                root_modules=self._root_modules(
                    spec,
                    toolchain,
                    mode,
                    token,
                    timeout,
                ),
                magisk_denylist=self._magisk_denylist_states(
                    spec,
                    toolchain,
                    mode,
                    token,
                    timeout,
                ),
                magisk_su_policies=self._magisk_su_policies(
                    spec,
                    toolchain,
                    mode,
                    token,
                    timeout,
                ),
            )
        )

    def _observe_fastboot(
        self,
        spec: PostconditionSpec,
        toolchain: ToolchainInfo,
        token: CancellationToken,
        timeout: float,
    ) -> _ProbeAttempt:
        userspace_outcome = self._run(
            (toolchain.fastboot, "-s", spec.serial, "getvar", "is-userspace"),
            token,
            timeout,
        )
        userspace = self._fastboot_value(userspace_outcome, "is-userspace")
        if userspace is not None:
            normalized_userspace = self._boolean(userspace)
            mode = (
                "fastbootd" if normalized_userspace is True else "fastboot" if normalized_userspace is False else None
            )
        else:
            mode = None

        if mode is None:
            product_outcome = self._run(
                (toolchain.fastboot, "-s", spec.serial, "getvar", "product"),
                token,
                timeout,
            )
            if self._fastboot_value(product_outcome, "product") is None:
                return _ProbeAttempt(
                    explicitly_absent=self._explicit_absence(
                        userspace_outcome,
                        spec.serial,
                    )
                    or self._explicit_absence(product_outcome, spec.serial)
                )
            # Legacy bootloaders can omit is-userspace; fastbootd implements it.
            mode = "fastboot"

        slot: str | None = None
        bootloader: str | None = None
        if spec.expected_slot is not None:
            slot_value = self._fastboot_getvar(
                toolchain,
                spec.serial,
                "current-slot",
                token,
                timeout,
            )
            normalized_slot = slot_value.casefold() if slot_value is not None else None
            slot = normalized_slot if normalized_slot in {"a", "b"} else None
        if spec.expected_bootloader is not None:
            unlocked = self._fastboot_getvar(
                toolchain,
                spec.serial,
                "unlocked",
                token,
                timeout,
            )
            unlocked_value = self._boolean(unlocked)
            if unlocked_value is not None:
                bootloader = "unlocked" if unlocked_value else "locked"

        partition_hashes = self._partition_hashes(
            spec,
            toolchain,
            token,
            timeout,
        )
        return _ProbeAttempt(
            DeviceObservation(
                spec.serial,
                connected=True,
                mode=mode,
                slot=slot,
                bootloader=bootloader,
                partition_hashes=partition_hashes,
                erased_partitions=self._erased_partitions(
                    spec,
                    toolchain,
                    token,
                    timeout,
                ),
            )
        )

    def _remote_hashes(
        self,
        spec: PostconditionSpec,
        toolchain: ToolchainInfo,
        mode: str,
        token: CancellationToken,
        timeout: float,
    ) -> dict[str, str]:
        names = tuple(spec.remote_hashes)
        if mode not in {"adb", "recovery"} or len(names) > self.max_remote_hash_targets:
            return {}
        if not names or token.cancelled or any(
            not self._safe_remote_path(remote_path) for remote_path in names
        ):
            return {}
        for command in (("sha256sum",), ("toybox", "sha256sum")):
            outcome = self._run(
                (
                    toolchain.adb,
                    "-s",
                    spec.serial,
                    "shell",
                    *command,
                    "--",
                    *names,
                ),
                token,
                timeout,
                output_limit_bytes=_MAX_REMOTE_HASH_OUTPUT_BYTES,
            )
            observed = self._parse_remote_hashes(outcome, names)
            if len(observed) == len(names):
                return observed
        return {}

    def _packages(
        self,
        spec: PostconditionSpec,
        toolchain: ToolchainInfo,
        mode: str,
        token: CancellationToken,
        timeout: float,
    ) -> dict[str, bool]:
        names = tuple(spec.expected_packages)
        if mode != "adb" or len(names) > self.max_hash_targets:
            return {}
        observed: dict[str, bool] = {}
        for package_name in names:
            if token.cancelled or len(package_name) > 255 or _PACKAGE_PATTERN.fullmatch(package_name) is None:
                continue
            outcome = self._run(
                (
                    toolchain.adb,
                    "-s",
                    spec.serial,
                    "shell",
                    "pm",
                    "path",
                    package_name,
                ),
                token,
                timeout,
            )
            installed = self._package_installed(outcome)
            if installed is not None:
                observed[package_name] = installed
        return observed

    def _package_states(
        self,
        spec: PostconditionSpec,
        toolchain: ToolchainInfo,
        mode: str,
        token: CancellationToken,
        timeout: float,
    ) -> dict[str, str]:
        states = tuple(spec.expected_package_states.items())
        if mode != "adb" or len(states) > self.max_hash_targets:
            return {}
        observed: dict[str, str] = {}
        for package_name, expected_state in states:
            if token.cancelled or len(package_name) > 255 or _PACKAGE_PATTERN.fullmatch(package_name) is None:
                continue
            installed = self._package_installed(
                self._run(
                    (
                        toolchain.adb,
                        "-s",
                        spec.serial,
                        "shell",
                        "pm",
                        "path",
                        package_name,
                    ),
                    token,
                    timeout,
                )
            )
            if installed is None:
                continue
            if not installed:
                observed[package_name] = "absent"
                continue
            if expected_state in {"absent", "installed"}:
                observed[package_name] = "installed"
                continue
            if expected_state in {"enabled", "disabled"}:
                flag = "-e" if expected_state == "enabled" else "-d"
                matches = self._package_list_contains(
                    self._run(
                        (
                            toolchain.adb,
                            "-s",
                            spec.serial,
                            "shell",
                            "pm",
                            "list",
                            "packages",
                            "--user",
                            "0",
                            flag,
                            package_name,
                        ),
                        token,
                        timeout,
                    ),
                    package_name,
                )
                if matches is not None:
                    observed[package_name] = (
                        expected_state if matches else "disabled" if expected_state == "enabled" else "enabled"
                    )
                continue
            process_state = self._package_process_state(
                self._run(
                    (
                        toolchain.adb,
                        "-s",
                        spec.serial,
                        "shell",
                        "pidof",
                        package_name,
                    ),
                    token,
                    timeout,
                )
            )
            if process_state is not None:
                observed[package_name] = process_state
        return observed

    def _root_modules(
        self,
        spec: PostconditionSpec,
        toolchain: ToolchainInfo,
        mode: str,
        token: CancellationToken,
        timeout: float,
    ) -> dict[str, str]:
        modules = tuple(spec.expected_root_modules.items())
        if mode != "adb" or len(modules) > self.max_hash_targets:
            return {}
        if not self._root_available(
            toolchain,
            spec.serial,
            token,
            timeout,
        ):
            return {}
        observed: dict[str, str] = {}
        for module_id, expected_state in modules:
            if token.cancelled or _MODULE_PATTERN.fullmatch(module_id) is None:
                continue
            module_root = f"/data/adb/modules/{module_id}"
            exists = self._root_test(
                toolchain,
                spec.serial,
                f"test -d {module_root}",
                token,
                timeout,
            )
            if exists is None:
                continue
            if not exists:
                observed[module_id] = "absent"
                continue
            if expected_state == "installed":
                observed[module_id] = "installed"
                continue
            disabled = self._root_test(
                toolchain,
                spec.serial,
                f"test -e {module_root}/disable",
                token,
                timeout,
            )
            pending_remove = self._root_test(
                toolchain,
                spec.serial,
                f"test -e {module_root}/remove",
                token,
                timeout,
            )
            if disabled is None or pending_remove is None:
                continue
            observed[module_id] = "pending_remove" if pending_remove else "disabled" if disabled else "enabled"
        return observed

    def _magisk_denylist_states(
        self,
        spec: PostconditionSpec,
        toolchain: ToolchainInfo,
        mode: str,
        token: CancellationToken,
        timeout: float,
    ) -> dict[str, bool]:
        packages = tuple(spec.expected_magisk_denylist)
        if mode != "adb" or not packages or len(packages) > self.max_hash_targets:
            return {}
        if not self._root_available(toolchain, spec.serial, token, timeout):
            return {}
        outcome = self._run(
            (
                toolchain.adb,
                "-s",
                spec.serial,
                "shell",
                "su",
                "-c",
                "magisk --denylist ls",
            ),
            token,
            timeout,
            output_limit_bytes=_MAX_ADB_INVENTORY_OUTPUT_BYTES,
        )
        if not self._successful(outcome, _MAX_ADB_INVENTORY_OUTPUT_BYTES):
            return {}
        assert outcome is not None
        listed: set[str] = set()
        for raw_line in outcome.stdout.splitlines():
            package = raw_line.strip().split("|", 1)[0]
            if _PACKAGE_PATTERN.fullmatch(package) is not None:
                listed.add(package)
        return {package: package in listed for package in packages}

    def _magisk_su_policies(
        self,
        spec: PostconditionSpec,
        toolchain: ToolchainInfo,
        mode: str,
        token: CancellationToken,
        timeout: float,
    ) -> dict[int, str]:
        policies = tuple(spec.expected_magisk_su_policies)
        if mode != "adb" or not policies or len(policies) > self.max_hash_targets:
            return {}
        if not self._root_available(toolchain, spec.serial, token, timeout):
            return {}
        observed: dict[int, str] = {}
        for uid in policies:
            if token.cancelled:
                break
            sql = (
                "SELECT 'PF_SU|' || uid || '|' || policy || '|' || logging || "
                "'|' || notification || '|' || until FROM policies "
                f"WHERE uid = {uid};"
            )
            outcome = self._run(
                (
                    toolchain.adb,
                    "-s",
                    spec.serial,
                    "shell",
                    "su",
                    "-c",
                    f'magisk --sqlite "{sql}"',
                ),
                token,
                timeout,
                output_limit_bytes=_MAX_PROPERTY_OUTPUT_BYTES,
            )
            if not self._successful(outcome, _MAX_PROPERTY_OUTPUT_BYTES):
                continue
            assert outcome is not None
            lines = tuple(line.strip() for line in outcome.stdout.splitlines() if line.strip())
            if not lines:
                observed[uid] = "absent"
                continue
            if len(lines) != 1:
                continue
            match = _SU_POLICY_ROW_PATTERN.fullmatch(lines[0])
            if match is None or int(match.group(1)) != uid:
                continue
            policy = "allow" if match.group(2) == "2" else "deny"
            observed[uid] = (
                f"{policy}:{match.group(3)}:{match.group(4)}:{int(match.group(5))}"
            )
        return observed

    def _adb_endpoint_states(
        self,
        spec: PostconditionSpec | HostPostconditionSpec,
        toolchain: ToolchainInfo,
        token: CancellationToken,
        timeout: float,
    ) -> dict[str, bool]:
        endpoints = tuple(spec.expected_adb_endpoints)
        if not endpoints or len(endpoints) > self.max_hash_targets:
            return {}
        if token.cancelled or any(not self.safe_adb_endpoint(item) for item in endpoints):
            return {}
        outcome = self._run(
            (toolchain.adb, "devices", "-l"),
            token,
            timeout,
            output_limit_bytes=_MAX_ADB_INVENTORY_OUTPUT_BYTES,
        )
        listed = self._parse_adb_device_states(outcome)
        if listed is None:
            return {}
        return {endpoint: listed.get(endpoint) == "device" for endpoint in endpoints}

    @staticmethod
    def safe_adb_endpoint(endpoint: str) -> bool:
        if not isinstance(endpoint, str) or not 3 <= len(endpoint) <= 128:
            return False
        host, separator, raw_port = endpoint.rpartition(":")
        if not separator or not host or not raw_port.isascii() or not raw_port.isdigit():
            return False
        try:
            address = ipaddress.ip_address(host.removeprefix("[").removesuffix("]"))
            port = int(raw_port)
        except ValueError:
            return False
        return not address.is_unspecified and not address.is_multicast and 1 <= port <= 65535

    @staticmethod
    def _parse_adb_device_states(
        outcome: TransportOutcome | None,
    ) -> dict[str, str] | None:
        if not ProcessDeviceObservationProbe._successful(
            outcome,
            _MAX_FASTBOOT_OUTPUT_BYTES,
        ):
            return None
        assert outcome is not None
        if outcome.stderr.strip():
            return None
        lines = tuple(line.rstrip() for line in outcome.stdout.replace("\r", "").splitlines() if line.strip())
        if not lines or lines[0].strip() != "List of devices attached":
            return None
        states: dict[str, str] = {}
        for line in lines[1:]:
            fields = line.split()
            if len(fields) < 2:
                return None
            serial, state = fields[:2]
            if not serial or serial in states or not state.isascii():
                return None
            states[serial] = state
        return states

    def _root_available(
        self,
        toolchain: ToolchainInfo,
        serial: str,
        token: CancellationToken,
        timeout: float,
    ) -> bool:
        outcome = self._run(
            (
                toolchain.adb,
                "-s",
                serial,
                "shell",
                "su",
                "-c",
                "id -u",
            ),
            token,
            timeout,
        )
        return (
            self._successful(outcome, _MAX_PROPERTY_OUTPUT_BYTES)
            and outcome is not None
            and not outcome.stderr.strip()
            and outcome.stdout.strip() == "0"
        )

    def _root_test(
        self,
        toolchain: ToolchainInfo,
        serial: str,
        remote_command: str,
        token: CancellationToken,
        timeout: float,
    ) -> bool | None:
        outcome = self._run(
            (
                toolchain.adb,
                "-s",
                serial,
                "shell",
                "su",
                "-c",
                remote_command,
            ),
            token,
            timeout,
        )
        if (
            outcome is None
            or outcome.cancelled
            or outcome.timed_out
            or len(outcome.stdout.encode("utf-8", errors="replace"))
            + len(outcome.stderr.encode("utf-8", errors="replace"))
            > _MAX_PROPERTY_OUTPUT_BYTES
            or outcome.stdout.strip()
            or outcome.stderr.strip()
        ):
            return None
        if outcome.returncode == 0:
            return True
        if outcome.returncode == 1:
            return False
        return None

    def _partition_hashes(
        self,
        spec: PostconditionSpec,
        toolchain: ToolchainInfo,
        token: CancellationToken,
        timeout: float,
    ) -> dict[str, str]:
        names = tuple(spec.partition_hashes)
        if not names or len(names) > self.max_hash_targets:
            return {}
        observed: dict[str, str] = {}
        fetch_supported: bool | None = None
        for partition in names:
            if token.cancelled or not self._safe_partition(partition):
                continue
            size = self._partition_size(
                toolchain,
                spec.serial,
                partition,
                token,
                timeout,
            )
            if size is None or size <= 0 or size > self.max_partition_bytes:
                continue
            if fetch_supported is None:
                fetch_supported = self._fetch_supported(
                    toolchain,
                    spec.serial,
                    token,
                    timeout,
                )
            if not fetch_supported:
                break
            digest = self._fetch_partition_hash(
                toolchain,
                spec.serial,
                partition,
                size,
                token,
                timeout,
            )
            if digest is not None:
                observed[partition] = digest
        return observed

    def _erased_partitions(
        self,
        spec: PostconditionSpec,
        toolchain: ToolchainInfo,
        token: CancellationToken,
        timeout: float,
    ) -> dict[str, bool]:
        names = spec.erased_partitions
        if not names or len(names) > self.max_hash_targets:
            return {}
        observed: dict[str, bool] = {}
        fetch_supported: bool | None = None
        for partition in names:
            if token.cancelled or not self._safe_partition(partition):
                continue
            size = self._partition_size(
                toolchain,
                spec.serial,
                partition,
                token,
                timeout,
            )
            if size is None or size <= 0 or size > self.max_partition_bytes:
                continue
            if fetch_supported is None:
                fetch_supported = self._fetch_supported(
                    toolchain,
                    spec.serial,
                    token,
                    timeout,
                )
            if not fetch_supported:
                break
            erased = self._fetch_partition_erased(
                toolchain,
                spec.serial,
                partition,
                size,
                token,
                timeout,
            )
            if erased is not None:
                observed[partition] = erased
        return observed

    def _partition_size(
        self,
        toolchain: ToolchainInfo,
        serial: str,
        partition: str,
        token: CancellationToken,
        timeout: float,
    ) -> int | None:
        variable = f"partition-size:{partition}"
        outcome = self._run(
            (toolchain.fastboot, "-s", serial, "getvar", variable),
            token,
            timeout,
        )
        if not self._successful(outcome, _MAX_FASTBOOT_OUTPUT_BYTES):
            return None
        assert outcome is not None
        pattern = re.compile(rf"^(?:\(bootloader\)\s*)?{re.escape(variable)}:\s*(0x[0-9a-fA-F]+|[0-9]+)\s*$")
        for line in f"{outcome.stdout}\n{outcome.stderr}".replace("\r", "").splitlines():
            match = pattern.fullmatch(line.strip())
            if match is None:
                continue
            try:
                return int(match.group(1), 0)
            except ValueError:
                return None
        return None

    def _fetch_supported(
        self,
        toolchain: ToolchainInfo,
        serial: str,
        token: CancellationToken,
        timeout: float,
    ) -> bool:
        outcome = self._run(
            (toolchain.fastboot, "-s", serial, "help"),
            token,
            timeout,
        )
        if not self._successful(outcome, _MAX_HELP_OUTPUT_BYTES):
            return False
        assert outcome is not None
        return _FASTBOOT_FETCH_PATTERN.search(f"{outcome.stdout}\n{outcome.stderr}") is not None

    def _fetch_partition_hash(
        self,
        toolchain: ToolchainInfo,
        serial: str,
        partition: str,
        expected_size: int,
        token: CancellationToken,
        timeout: float,
    ) -> str | None:
        try:
            with tempfile.TemporaryDirectory(
                prefix="pixelflasher-observer-",
                dir=str(self.temporary_root) if self.temporary_root is not None else None,
            ) as directory:
                root = Path(directory).resolve(strict=True)
                destination = root / "partition.img"
                if destination.resolve().parent != root:
                    return None
                outcome = self._run(
                    (
                        toolchain.fastboot,
                        "-s",
                        serial,
                        "fetch",
                        partition,
                        str(destination),
                    ),
                    token,
                    timeout,
                )
                if not self._successful(outcome, _MAX_FASTBOOT_OUTPUT_BYTES):
                    return None
                if (
                    not destination.is_file()
                    or destination.is_symlink()
                    or destination.resolve(strict=True).parent != root
                ):
                    return None
                if destination.stat().st_size != expected_size:
                    return None
                return self._bounded_file_sha256(destination, expected_size)
        except OSError:
            return None

    def _fetch_partition_erased(
        self,
        toolchain: ToolchainInfo,
        serial: str,
        partition: str,
        expected_size: int,
        token: CancellationToken,
        timeout: float,
    ) -> bool | None:
        try:
            with tempfile.TemporaryDirectory(
                prefix="pixelflasher-observer-",
                dir=str(self.temporary_root) if self.temporary_root is not None else None,
            ) as directory:
                root = Path(directory).resolve(strict=True)
                destination = root / "partition.img"
                if destination.resolve().parent != root:
                    return None
                outcome = self._run(
                    (
                        toolchain.fastboot,
                        "-s",
                        serial,
                        "fetch",
                        partition,
                        str(destination),
                    ),
                    token,
                    timeout,
                )
                if not self._successful(outcome, _MAX_FASTBOOT_OUTPUT_BYTES):
                    return None
                if (
                    not destination.is_file()
                    or destination.is_symlink()
                    or destination.resolve(strict=True).parent != root
                    or destination.stat().st_size != expected_size
                ):
                    return None
                return self._bounded_erased_content(destination, expected_size)
        except OSError:
            return None

    def _adb_property(
        self,
        toolchain: ToolchainInfo,
        serial: str,
        name: str,
        token: CancellationToken,
        timeout: float,
    ) -> str | None:
        outcome = self._run(
            (toolchain.adb, "-s", serial, "shell", "getprop", name),
            token,
            timeout,
        )
        if not self._successful(outcome, _MAX_PROPERTY_OUTPUT_BYTES):
            return None
        assert outcome is not None
        value = self._single_value(outcome.stdout)
        return value if value is not None and self._safe_property(value) else None

    def _ota_idle(
        self,
        toolchain: ToolchainInfo,
        serial: str,
        token: CancellationToken,
        timeout: float,
    ) -> bool | None:
        outcome = self._run(
            (
                toolchain.adb,
                "-s",
                serial,
                "shell",
                "update_engine_client",
                "--status",
            ),
            token,
            timeout,
            output_limit_bytes=_MAX_OTA_STATUS_OUTPUT_BYTES,
        )
        if not self._successful(outcome, _MAX_OTA_STATUS_OUTPUT_BYTES):
            return None
        assert outcome is not None
        try:
            status = parse_update_engine_status(outcome.stdout)
        except OtaDiagnosticParseError:
            return None
        idle = status.get("idle")
        return idle if isinstance(idle, bool) else None

    def _fastboot_getvar(
        self,
        toolchain: ToolchainInfo,
        serial: str,
        variable: str,
        token: CancellationToken,
        timeout: float,
    ) -> str | None:
        return self._fastboot_value(
            self._run(
                (toolchain.fastboot, "-s", serial, "getvar", variable),
                token,
                timeout,
            ),
            variable,
        )

    @staticmethod
    def _fastboot_value(
        outcome: TransportOutcome | None,
        variable: str,
    ) -> str | None:
        if not ProcessDeviceObservationProbe._successful(
            outcome,
            _MAX_FASTBOOT_OUTPUT_BYTES,
        ):
            return None
        assert outcome is not None
        return parse_fastboot_getvar(
            f"{outcome.stdout}\n{outcome.stderr}",
            variable,
        )

    def _run(
        self,
        argv: tuple[str, ...],
        token: CancellationToken,
        timeout: float,
        *,
        output_limit_bytes: int | None = None,
    ) -> TransportOutcome | None:
        if token.cancelled:
            return None
        try:
            return self.transport.run(
                ProcessRequest(
                    argv,
                    timeout_seconds=timeout,
                    output_limit_bytes=output_limit_bytes,
                ),
                token,
            )
        except Exception:
            return None

    @staticmethod
    def _successful(outcome: TransportOutcome | None, max_bytes: int) -> bool:
        if outcome is None or outcome.returncode != 0 or outcome.cancelled or outcome.timed_out:
            return False
        return (
            len(outcome.stdout.encode("utf-8", errors="replace"))
            + len(outcome.stderr.encode("utf-8", errors="replace"))
            <= max_bytes
        )

    @staticmethod
    def _explicit_absence(
        outcome: TransportOutcome | None,
        serial: str,
    ) -> bool:
        if outcome is None or outcome.cancelled or outcome.timed_out or outcome.returncode == 0:
            return False
        message = f"{outcome.stdout}\n{outcome.stderr}".strip().casefold()
        serial_value = serial.casefold()
        return message in {
            "error: device not found",
            f"error: device '{serial_value}' not found",
            f"adb: device '{serial_value}' not found",
            f"fastboot: error: device '{serial_value}' not found",
            "fastboot: error: no devices/emulators found",
        }

    @staticmethod
    def _single_value(output: str) -> str | None:
        normalized = output.replace("\r", "").strip()
        if not normalized or "\n" in normalized or "\x00" in normalized:
            return None
        return normalized

    @staticmethod
    def _safe_property(value: str) -> bool:
        return 0 < len(value) <= 256 and "\x00" not in value and all(character.isprintable() for character in value)

    @staticmethod
    def _locked_state(value: str | None) -> str | None:
        value = value.casefold() if value is not None else None
        if value in {"1", "true", "locked"}:
            return "locked"
        if value in {"0", "false", "unlocked"}:
            return "unlocked"
        return None

    @staticmethod
    def _boolean(value: str | None) -> bool | None:
        if value is None:
            return None
        normalized = value.strip().casefold()
        if normalized in {"1", "true", "yes", "y", "unlocked"}:
            return True
        if normalized in {"0", "false", "no", "n", "locked"}:
            return False
        return None

    @staticmethod
    def _safe_remote_path(path: str) -> bool:
        return (
            len(path) <= 512
            and _REMOTE_PATH_PATTERN.fullmatch(path) is not None
            and all(part not in {".", ".."} for part in path.split("/"))
        )

    @staticmethod
    def _safe_partition(partition: str) -> bool:
        return _PARTITION_PATTERN.fullmatch(partition) is not None

    @staticmethod
    def _parse_remote_hashes(
        outcome: TransportOutcome | None,
        remote_paths: tuple[str, ...],
    ) -> dict[str, str]:
        if not ProcessDeviceObservationProbe._successful(
            outcome,
            _MAX_REMOTE_HASH_OUTPUT_BYTES,
        ):
            return {}
        assert outcome is not None
        expected = set(remote_paths)
        lines = tuple(
            line.strip()
            for line in outcome.stdout.replace("\r", "").splitlines()
            if line.strip()
        )
        if len(lines) != len(expected) or outcome.stderr.strip():
            return {}
        observed: dict[str, str] = {}
        for line in lines:
            match = re.fullmatch(r"([0-9a-fA-F]{64})\s+\*?(.+)", line)
            if match is None:
                return {}
            digest, remote_path = match.groups()
            if remote_path not in expected or remote_path in observed:
                return {}
            observed[remote_path] = digest.casefold()
        return observed if observed.keys() == expected else {}

    @staticmethod
    def _package_installed(outcome: TransportOutcome | None) -> bool | None:
        if not ProcessDeviceObservationProbe._successful(
            outcome,
            _MAX_PROPERTY_OUTPUT_BYTES,
        ):
            return None
        assert outcome is not None
        if outcome.stderr.strip():
            return None
        lines = tuple(line.strip() for line in outcome.stdout.replace("\r", "").splitlines() if line.strip())
        if not lines:
            return False
        return (
            True
            if all(
                line.startswith("package:/")
                and len(line) <= 1024
                and _REPORTED_PACKAGE_PATH_PATTERN.fullmatch(line.removeprefix("package:")) is not None
                for line in lines
            )
            else None
        )

    @staticmethod
    def _package_list_contains(
        outcome: TransportOutcome | None,
        package_name: str,
    ) -> bool | None:
        if not ProcessDeviceObservationProbe._successful(
            outcome,
            _MAX_PROPERTY_OUTPUT_BYTES,
        ):
            return None
        assert outcome is not None
        if outcome.stderr.strip():
            return None
        lines = tuple(line.strip() for line in outcome.stdout.replace("\r", "").splitlines() if line.strip())
        if any(not line.startswith("package:") for line in lines):
            return None
        return f"package:{package_name}" in lines

    @staticmethod
    def _package_process_state(outcome: TransportOutcome | None) -> str | None:
        if outcome is None or outcome.cancelled or outcome.timed_out:
            return None
        if len(outcome.stdout.encode("utf-8", errors="replace")) > _MAX_PROPERTY_OUTPUT_BYTES:
            return None
        if outcome.stderr.strip():
            return None
        output = outcome.stdout.strip()
        if outcome.returncode == 1 and not output:
            return "stopped"
        if outcome.returncode != 0 or not output:
            return None
        pids = output.split()
        if not pids or any(not pid.isascii() or not pid.isdigit() for pid in pids):
            return None
        return "running"

    @staticmethod
    def _bounded_file_sha256(path: Path, expected_size: int) -> str | None:
        if expected_size <= 0:
            return None
        digest = hashlib.sha256()
        remaining = expected_size
        try:
            with path.open("rb") as stream:
                while remaining:
                    chunk = stream.read(min(1024 * 1024, remaining))
                    if not chunk:
                        return None
                    remaining -= len(chunk)
                    digest.update(chunk)
                if stream.read(1):
                    return None
        except OSError:
            return None
        return digest.hexdigest()

    @staticmethod
    def _bounded_erased_content(path: Path, expected_size: int) -> bool | None:
        if expected_size <= 0:
            return None
        remaining = expected_size
        erased = True
        try:
            with path.open("rb") as stream:
                while remaining:
                    chunk = stream.read(min(1024 * 1024, remaining))
                    if not chunk:
                        return None
                    remaining -= len(chunk)
                    if erased and any(value not in {0x00, 0xFF} for value in chunk):
                        erased = False
                if stream.read(1):
                    return None
        except OSError:
            return None
        return erased


class PostconditionObserver:
    """Poll read-only evidence until every promised postcondition is proven."""

    def __init__(
        self,
        probe: ObservationProbe | SpecObservationProbe,
        *,
        poll_interval_seconds: float = 0.5,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if poll_interval_seconds <= 0:
            raise ValueError("poll interval must be positive")
        self.probe = probe
        self.poll_interval_seconds = float(poll_interval_seconds)
        self._clock = clock
        self._sleeper = sleeper

    def verify(
        self,
        spec: PostconditionSpec,
        cancellation: CancellationToken | None = None,
    ) -> ObservationResult:
        token = cancellation or CancellationToken()
        deadline = self._clock() + spec.timeout_seconds
        attempts = 0
        last_observation: DeviceObservation | None = None
        last_mismatches: dict[str, tuple[object, object]] = {}
        last_missing: tuple[str, ...] = ()

        while True:
            if token.cancelled:
                return ObservationResult(
                    ObservationStatus.CANCELLED,
                    "postcondition_cancelled",
                    "postcondition observation was cancelled",
                    attempts,
                    last_mismatches,
                    last_missing,
                    last_observation,
                )
            attempts += 1
            try:
                if isinstance(self.probe, SpecObservationProbe):
                    observation = self.probe.observe_spec(spec, token)
                else:
                    observation = self.probe.observe(spec.serial)
            except ObservationProbeUnavailable:
                return ObservationResult(
                    ObservationStatus.UNVERIFIED,
                    "postcondition_unverified",
                    "required device evidence is unavailable",
                    attempts,
                    missing=("probe",),
                )
            if observation is not None:
                last_observation = observation
                last_mismatches, last_missing = self._compare(spec, observation)
                if observation.connected and not last_mismatches and not last_missing:
                    return ObservationResult(
                        ObservationStatus.VERIFIED,
                        "postcondition_verified",
                        "all operation postconditions were verified",
                        attempts,
                        observation=observation,
                    )

            now = self._clock()
            if now >= deadline:
                if last_observation is not None and not last_observation.connected:
                    return ObservationResult(
                        ObservationStatus.DISCONNECTED,
                        "postcondition_disconnected",
                        "the target device disconnected during postcondition observation",
                        attempts,
                        last_mismatches,
                        last_missing,
                        last_observation,
                    )
                if last_mismatches:
                    return ObservationResult(
                        ObservationStatus.MISMATCH,
                        "postcondition_mismatch",
                        "observed device state does not match the operation plan",
                        attempts,
                        last_mismatches,
                        last_missing,
                        last_observation,
                    )
                return ObservationResult(
                    ObservationStatus.UNVERIFIED,
                    "postcondition_unverified",
                    "required device state could not be observed",
                    attempts,
                    missing=last_missing or ("device",),
                    observation=last_observation,
                )
            self._sleeper(min(self.poll_interval_seconds, max(0.0, deadline - now)))

    def verify_host(
        self,
        spec: HostPostconditionSpec,
        cancellation: CancellationToken | None = None,
    ) -> ObservationResult:
        """Poll only host-owned ADB inventory; never infer a target serial."""

        token = cancellation or CancellationToken()
        deadline = self._clock() + spec.timeout_seconds
        attempts = 0
        last_observation: HostObservation | None = None
        last_mismatches: dict[str, tuple[object, object]] = {}
        last_missing: tuple[str, ...] = ()

        while True:
            if token.cancelled:
                return ObservationResult(
                    ObservationStatus.CANCELLED,
                    "postcondition_cancelled",
                    "host postcondition observation was cancelled",
                    attempts,
                    last_mismatches,
                    last_missing,
                    last_observation,
                )
            attempts += 1
            if not isinstance(self.probe, HostSpecObservationProbe):
                return ObservationResult(
                    ObservationStatus.UNVERIFIED,
                    "postcondition_unverified",
                    "required host evidence is unavailable",
                    attempts,
                    missing=("probe",),
                )
            try:
                observation = self.probe.observe_host_spec(spec, token)
            except ObservationProbeUnavailable:
                return ObservationResult(
                    ObservationStatus.UNVERIFIED,
                    "postcondition_unverified",
                    "required host evidence is unavailable",
                    attempts,
                    missing=("probe",),
                )
            if observation is not None:
                last_observation = observation
                last_mismatches, last_missing = self._compare_host(spec, observation)
                if not last_mismatches and not last_missing:
                    return ObservationResult(
                        ObservationStatus.VERIFIED,
                        "postcondition_verified",
                        "all host operation postconditions were verified",
                        attempts,
                        observation=observation,
                    )

            now = self._clock()
            if now >= deadline:
                if last_mismatches:
                    return ObservationResult(
                        ObservationStatus.MISMATCH,
                        "postcondition_mismatch",
                        "observed host state does not match the operation plan",
                        attempts,
                        last_mismatches,
                        last_missing,
                        last_observation,
                    )
                return ObservationResult(
                    ObservationStatus.UNVERIFIED,
                    "postcondition_unverified",
                    "required host state could not be observed",
                    attempts,
                    missing=last_missing or ("host",),
                    observation=last_observation,
                )
            self._sleeper(min(self.poll_interval_seconds, max(0.0, deadline - now)))

    @staticmethod
    def _compare_host(
        spec: HostPostconditionSpec,
        observation: HostObservation,
    ) -> tuple[dict[str, tuple[object, object]], tuple[str, ...]]:
        mismatches: dict[str, tuple[object, object]] = {}
        missing: list[str] = []
        for endpoint, expected in spec.expected_adb_endpoints.items():
            actual = observation.adb_endpoints.get(endpoint)
            key = f"adb_endpoint:{endpoint}"
            if actual is None:
                missing.append(key)
            elif actual is not expected:
                mismatches[key] = (expected, actual)
        return mismatches, tuple(missing)

    @staticmethod
    def _compare(
        spec: PostconditionSpec,
        observation: DeviceObservation,
    ) -> tuple[dict[str, tuple[object, object]], tuple[str, ...]]:
        mismatches: dict[str, tuple[object, object]] = {}
        missing: list[str] = []

        if observation.serial != spec.serial:
            mismatches["serial"] = (spec.serial, observation.serial)
        if not observation.connected:
            missing.append("connection")

        scalar_fields = (
            ("mode", spec.expected_mode, observation.mode),
            ("slot", spec.expected_slot, observation.slot),
            ("bootloader", spec.expected_bootloader, observation.bootloader),
            ("boot_completed", spec.expected_boot_completed, observation.boot_completed),
            ("safe_mode", spec.expected_safe_mode, observation.safe_mode),
            ("build", spec.expected_build, observation.build),
            ("ota_idle", spec.expected_ota_idle, observation.ota_idle),
        )
        for name, expected, actual in scalar_fields:
            if expected is None:
                continue
            if actual is None:
                missing.append(name)
            elif actual != expected:
                mismatches[name] = (expected, actual)

        for name, expected in spec.remote_hashes.items():
            actual = observation.remote_hashes.get(name)
            key = f"remote_hash:{name}"
            if actual is None:
                missing.append(key)
            elif actual.casefold() != expected.casefold():
                mismatches[key] = (expected.casefold(), actual.casefold())

        for name, expected in spec.partition_hashes.items():
            actual = observation.partition_hashes.get(name)
            key = f"partition_hash:{name}"
            if actual is None:
                missing.append(key)
            elif actual.casefold() != expected.casefold():
                mismatches[key] = (expected.casefold(), actual.casefold())

        for package_name, expected in spec.expected_packages.items():
            actual = observation.packages.get(package_name)
            key = f"package:{package_name}"
            if actual is None:
                missing.append(key)
            elif actual is not expected:
                mismatches[key] = (expected, actual)

        for package_name, expected in spec.expected_package_states.items():
            actual = observation.package_states.get(package_name)
            key = f"package_state:{package_name}"
            if actual is None:
                missing.append(key)
            elif actual != expected:
                mismatches[key] = (expected, actual)

        for endpoint, expected in spec.expected_adb_endpoints.items():
            actual = observation.adb_endpoints.get(endpoint)
            key = f"adb_endpoint:{endpoint}"
            if actual is None:
                missing.append(key)
            elif actual is not expected:
                mismatches[key] = (expected, actual)

        for module_id, expected in spec.expected_root_modules.items():
            actual = observation.root_modules.get(module_id)
            key = f"root_module:{module_id}"
            if actual is None:
                missing.append(key)
            elif actual != expected:
                mismatches[key] = (expected, actual)

        for package_name, expected in spec.expected_magisk_denylist.items():
            actual = observation.magisk_denylist.get(package_name)
            key = f"magisk_denylist:{package_name}"
            if actual is None:
                missing.append(key)
            elif actual is not expected:
                mismatches[key] = (expected, actual)

        for uid, expected in spec.expected_magisk_su_policies.items():
            actual = observation.magisk_su_policies.get(uid)
            key = f"magisk_su_policy:{uid}"
            if actual is None:
                missing.append(key)
            elif actual != expected:
                mismatches[key] = (expected, actual)

        for partition in spec.erased_partitions:
            actual = observation.erased_partitions.get(partition)
            key = f"partition_erased:{partition}"
            if actual is None:
                missing.append(key)
            elif actual is not True:
                mismatches[key] = (True, actual)

        return mismatches, tuple(missing)
