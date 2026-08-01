"""Pure device parsers, typed scanning, and cancelable hotplug polling."""

from __future__ import annotations

import re
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from math import isfinite

from .contracts import DeviceInfo, ProcessRequest, ToolchainInfo
from .executor import CancellationToken, ProcessTransport, SubprocessTransport, TransportOutcome

_GETPROP_PATTERN = re.compile(r"^\[([^]]+)]\s*:\s*\[(.*)]$")
_BATTERY_LEVEL_PATTERN = re.compile(r"^\s*level\s*:\s*(\d+)\s*$", re.IGNORECASE)
_FASTBOOT_GETVAR_PATTERN = re.compile(
    r"^(?:\(bootloader\)\s*)?([a-z0-9_.-]+)\s*:\s*(.*?)\s*$",
    re.IGNORECASE,
)
_ADB_ONLINE_MODES = frozenset({"adb", "recovery", "sideload"})
_PROPERTY_SAFE_MODES = frozenset({"adb", "recovery"})
_FASTBOOT_MODES = frozenset({"fastboot", "fastbootd"})
_FASTBOOT_GETVARS = ("current-slot", "unlocked", "is-userspace")
_ADB_MAPPED_STATES = frozenset({"device", "recovery", "sideload", "unauthorized", "offline"})
# Transient handshake states resolve within one poll and are not worth a warning.
_ADB_TRANSIENT_STATES = frozenset({"host", "authorizing", "connecting"})
_ADB_STATE_TOKEN_PATTERN = re.compile(r"^[a-z][a-z0-9._-]{0,31}$")
_MDNS_ADB_SERVICE_SUFFIXES = (
    "._adb-tls-connect._tcp",
    "._adb-tls-pairing._tcp",
    "._adb._tcp",
)
_KERNEL_RELEASE_PATTERN = re.compile(
    r"^(?P<major>[1-9][0-9]*)\.(?P<minor>[0-9]+)(?:\.[0-9]+)?[^\r\n]*?-android(?P<android>[0-9]{2})-",
    re.IGNORECASE,
)
_ARCHITECTURE_ALIASES = {
    "aarch64": "arm64",
    "arm64": "arm64",
    "arm64-v8a": "arm64",
    "armeabi": "arm",
    "armeabi-v7a": "arm",
    "armv7l": "arm",
    "arm": "arm",
    "amd64": "x86_64",
    "x86_64": "x86_64",
    "i386": "x86",
    "i686": "x86",
    "x86": "x86",
}


def _no_excluded_serials() -> frozenset[str]:
    return frozenset()


def _iter_adb_rows(output: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for raw_line in output.replace("\r", "").splitlines():
        line = raw_line.strip()
        if (
            not line
            or line.startswith("List of devices")
            or line.startswith("*")
            or line.lower().startswith("adb server")
        ):
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        rows.append(fields)
    return rows


def parse_adb_devices(output: str) -> tuple[DeviceInfo, ...]:
    devices: dict[str, DeviceInfo] = {}
    for fields in _iter_adb_rows(output):
        serial, adb_state = fields[0], fields[1].lower()
        if adb_state == "device":
            mode = "adb"
        elif adb_state in _ADB_MAPPED_STATES:
            mode = adb_state
        else:
            continue
        attributes = _parse_attributes(fields[2:])
        model = attributes.get("model", "").replace("_", " ")
        codename = attributes.get("device", "") or attributes.get("product", "")
        devices[serial] = DeviceInfo(
            serial=serial,
            model=model,
            codename=codename,
            mode=mode,
            online=mode in _ADB_ONLINE_MODES,
            name=model or codename or serial,
            connection=_connection_for_adb(serial, attributes),
        )
    return tuple(devices[key] for key in sorted(devices, key=str.casefold))


def parse_adb_device_warnings(output: str) -> tuple[str, ...]:
    """Report adb rows naming a device that cannot be mapped to a usable mode.

    ``parse_adb_devices`` drops such rows on purpose, because an unusable
    target must never reach the planner, but without a diagnostic a phone
    blocked by missing USB permissions vanishes with no visible reason.
    """

    warnings: list[str] = []
    for fields in _iter_adb_rows(output):
        serial, adb_state = fields[0], fields[1].lower()
        if adb_state in _ADB_MAPPED_STATES or adb_state in _ADB_TRANSIENT_STATES:
            continue
        if len(serial) > 256 or not serial.isprintable():
            continue
        if " ".join(fields[1:]).casefold().startswith("no permissions"):
            warning = f"adb:no_permissions:{serial}"
        elif _ADB_STATE_TOKEN_PATTERN.match(adb_state):
            warning = f"adb:unknown_state:{serial}:{adb_state}"
        else:
            continue
        if warning not in warnings:
            warnings.append(warning)
    return tuple(warnings)


def parse_fastboot_devices(output: str) -> tuple[DeviceInfo, ...]:
    devices: dict[str, DeviceInfo] = {}
    for raw_line in output.replace("\r", "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("< waiting for") or line.startswith("fastboot:"):
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        serial, state = fields[0], fields[1].lower()
        if state not in {"fastboot", "fastbootd", "offline"}:
            continue
        attributes = _parse_attributes(fields[2:])
        devices[serial] = DeviceInfo(
            serial=serial,
            model=attributes.get("product", "").replace("_", " "),
            codename=attributes.get("product", ""),
            mode=state,
            online=state in _FASTBOOT_MODES,
            name=(attributes.get("product", "").replace("_", " ") or serial),
            connection="USB",
        )
    return tuple(devices[key] for key in sorted(devices, key=str.casefold))


def parse_fastboot_getvar(output: str, variable: str) -> str | None:
    """Extract one exact fastboot variable from stdout/stderr text."""

    expected = variable.strip().casefold()
    if not expected:
        raise ValueError("variable must be a non-empty string")
    for raw_line in output.replace("\r", "").splitlines():
        match = _FASTBOOT_GETVAR_PATTERN.match(raw_line.strip())
        if match and match.group(1).casefold() == expected:
            value = match.group(2).strip()
            return value or None
    return None


def parse_getprop(output: str) -> dict[str, str]:
    properties: dict[str, str] = {}
    for raw_line in output.replace("\r", "").splitlines():
        match = _GETPROP_PATTERN.match(raw_line.strip())
        if match:
            properties[match.group(1)] = match.group(2)
    return properties


def parse_battery_level(output: str) -> int | None:
    for raw_line in output.replace("\r", "").splitlines():
        match = _BATTERY_LEVEL_PATTERN.match(raw_line)
        if match:
            level = int(match.group(1))
            return level if 0 <= level <= 100 else None
    return None


def normalize_device_architecture(value: object) -> str:
    """Return one closed device architecture name or an empty value."""

    if not isinstance(value, str):
        return ""
    candidate = value.split(",", 1)[0].strip().casefold()
    return _ARCHITECTURE_ALIASES.get(candidate, "")


def derive_android_kmi(kernel_release: object) -> str:
    """Derive the stable Android GKI KMI generation from ``uname -r``."""

    if not isinstance(kernel_release, str):
        return ""
    candidate = kernel_release.strip()
    if not candidate or len(candidate) > 256 or not candidate.isprintable():
        return ""
    match = _KERNEL_RELEASE_PATTERN.match(candidate)
    if match is None:
        return ""
    return f"android{match.group('android')}-{match.group('major')}.{match.group('minor')}"


def merge_device_inventories(
    adb_devices: tuple[DeviceInfo, ...],
    fastboot_devices: tuple[DeviceInfo, ...],
) -> tuple[DeviceInfo, ...]:
    merged = {device.serial: device for device in adb_devices}
    for device in fastboot_devices:
        previous = merged.get(device.serial)
        if previous is not None:
            device = replace(
                device,
                model=device.model or previous.model,
                codename=device.codename or previous.codename,
                slot=device.slot or previous.slot,
                name=device.name or previous.name,
                android_version=device.android_version or previous.android_version,
                build=device.build or previous.build,
                security_patch=device.security_patch or previous.security_patch,
                bootloader=(
                    device.bootloader
                    if device.bootloader != "unknown"
                    else previous.bootloader
                ),
                battery=device.battery if device.battery is not None else previous.battery,
                connection=device.connection or previous.connection,
            )
        merged[device.serial] = device
    return tuple(merged[key] for key in sorted(merged, key=str.casefold))


def merge_device_history(
    devices: tuple[DeviceInfo, ...],
    previous_devices: tuple[DeviceInfo, ...],
) -> tuple[DeviceInfo, ...]:
    """Keep stable identity metadata while requiring fresh operational state.

    Slot and bootloader state deliberately never fall back to history.  Those
    fields gate destructive operations and stale values must not become proof
    that a transition or lock-state change occurred.
    """

    previous_by_serial = {device.serial: device for device in previous_devices}
    merged: list[DeviceInfo] = []
    for device in devices:
        previous = previous_by_serial.get(device.serial)
        if previous is None:
            merged.append(device)
            continue
        is_fastboot = device.mode in _FASTBOOT_MODES
        name = device.name
        if not name or name == device.serial or (is_fastboot and previous.name):
            name = previous.name or previous.model or previous.codename or name
        merged.append(
            replace(
                device,
                model=(previous.model if is_fastboot and previous.model else device.model)
                or previous.model,
                codename=device.codename or previous.codename,
                name=name,
                android_version=device.android_version or previous.android_version,
                build=device.build or previous.build,
                security_patch=device.security_patch or previous.security_patch,
                battery=device.battery if device.battery is not None else previous.battery,
                connection=device.connection or previous.connection,
            )
        )
    return tuple(merged)


def canonicalize_device_inventory(
    devices: Sequence[DeviceInfo],
) -> tuple[DeviceInfo, ...]:
    """Validate and deterministically order one record per exact serial."""

    if isinstance(devices, (str, bytes)):
        raise TypeError("devices must be a sequence of DeviceInfo values")
    by_serial: dict[str, DeviceInfo] = {}
    for device in devices:
        if not isinstance(device, DeviceInfo):
            raise TypeError("devices must contain only DeviceInfo values")
        if not device.serial or device.serial != device.serial.strip():
            raise ValueError("device serials must be non-empty and trimmed")
        if device.serial in by_serial:
            raise ValueError(f"duplicate device serial: {device.serial}")
        by_serial[device.serial] = device
    return tuple(
        by_serial[serial]
        for serial in sorted(by_serial, key=lambda value: (value.casefold(), value))
    )


def reconcile_device_selection(
    devices: Sequence[DeviceInfo],
    selected_serials: Sequence[str],
    primary_serial: str | None,
) -> tuple[tuple[str, ...], str | None]:
    """Drop vanished selections while retaining deterministic user order.

    Newly discovered devices are never selected implicitly. If the previous
    primary vanished, the first still-present serial in the user's prior
    selection order becomes primary.
    """

    if isinstance(selected_serials, (str, bytes)):
        raise TypeError("selected_serials must be a sequence of strings")
    inventory = canonicalize_device_inventory(devices)
    available = frozenset(device.serial for device in inventory)
    retained: list[str] = []
    for serial in selected_serials:
        if not isinstance(serial, str):
            raise TypeError("selected_serials must contain only strings")
        if serial and serial in available and serial not in retained:
            retained.append(serial)

    primary = primary_serial if primary_serial in available else None
    if primary is not None and primary not in retained:
        retained.insert(0, primary)
    if primary is None and retained:
        primary = retained[0]
    return tuple(retained), primary


@dataclass(frozen=True, slots=True)
class DeviceScanResult:
    devices: tuple[DeviceInfo, ...]
    successful_sources: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    cancelled: bool = False
    discovered_devices: tuple[DeviceInfo, ...] = ()

    @property
    def observed_devices(self) -> tuple[DeviceInfo, ...]:
        """Return all basic discoveries with enriched eligible rows overlaid."""

        if not self.discovered_devices:
            return self.devices
        by_serial = {device.serial: device for device in self.discovered_devices}
        by_serial.update({device.serial: device for device in self.devices})
        return canonicalize_device_inventory(tuple(by_serial.values()))

    @property
    def ok(self) -> bool:
        return bool(self.successful_sources) and not self.cancelled

    def to_dict(self) -> dict[str, object]:
        return {
            "devices": [device.to_dict() for device in self.devices],
            "successful_sources": list(self.successful_sources),
            "warnings": list(self.warnings),
            "cancelled": self.cancelled,
        }


class DeviceService:
    def __init__(
        self,
        transport: ProcessTransport | None = None,
        *,
        scan_timeout_seconds: float = 8.0,
        property_timeout_seconds: float = 4.0,
        fastboot_property_timeout_seconds: float = 4.0,
        battery_timeout_seconds: float = 3.0,
        kernel_timeout_seconds: float = 4.0,
        root_timeout_seconds: float = 4.0,
    ) -> None:
        self.transport = transport or SubprocessTransport()
        self.scan_timeout_seconds = scan_timeout_seconds
        self.property_timeout_seconds = property_timeout_seconds
        self.fastboot_property_timeout_seconds = fastboot_property_timeout_seconds
        self.battery_timeout_seconds = battery_timeout_seconds
        self.kernel_timeout_seconds = kernel_timeout_seconds
        self.root_timeout_seconds = root_timeout_seconds

    def scan(
        self,
        toolchain: ToolchainInfo,
        *,
        include_properties: bool = True,
        include_battery: bool = True,
        previous_devices: tuple[DeviceInfo, ...] = (),
        excluded_serials: frozenset[str] = frozenset(),
        cancellation: CancellationToken | None = None,
    ) -> DeviceScanResult:
        token = cancellation or CancellationToken()
        if not isinstance(excluded_serials, frozenset) or any(
            not isinstance(serial, str) or not serial for serial in excluded_serials
        ):
            raise TypeError("excluded_serials must be a frozenset of serials")
        if not toolchain.ready or not toolchain.adb or not toolchain.fastboot:
            return DeviceScanResult((), warnings=("toolchain_not_ready",))

        warnings: list[str] = []
        successful: list[str] = []
        adb_devices: tuple[DeviceInfo, ...] = ()
        fastboot_devices: tuple[DeviceInfo, ...] = ()

        adb_outcome = self._run(
            ProcessRequest(
                (toolchain.adb, "devices", "-l"),
                timeout_seconds=self.scan_timeout_seconds,
            ),
            token,
            "adb",
            warnings,
        )
        if token.cancelled or (adb_outcome is not None and adb_outcome.cancelled):
            return DeviceScanResult((), tuple(successful), tuple(warnings), True)
        if adb_outcome is not None and adb_outcome.returncode == 0 and not adb_outcome.timed_out:
            adb_devices = parse_adb_devices(adb_outcome.stdout)
            warnings.extend(parse_adb_device_warnings(adb_outcome.stdout))
            successful.append("adb")

        fastboot_outcome = self._run(
            ProcessRequest(
                (toolchain.fastboot, "devices", "-l"),
                timeout_seconds=self.scan_timeout_seconds,
            ),
            token,
            "fastboot",
            warnings,
        )
        if token.cancelled or (fastboot_outcome is not None and fastboot_outcome.cancelled):
            return DeviceScanResult(adb_devices, tuple(successful), tuple(warnings), True)
        if (
            fastboot_outcome is not None
            and fastboot_outcome.returncode == 0
            and not fastboot_outcome.timed_out
        ):
            fastboot_devices = parse_fastboot_devices(fastboot_outcome.stdout)
            successful.append("fastboot")

        discovered_devices = merge_device_inventories(adb_devices, fastboot_devices)
        devices = tuple(
            device
            for device in discovered_devices
            if device.serial not in excluded_serials
        )
        if "fastboot" in successful:
            devices = self._enrich_fastboot(devices, toolchain, token, warnings)
        if include_properties and "adb" in successful:
            devices = self._enrich_properties(
                devices,
                toolchain,
                token,
                warnings,
                include_battery=include_battery,
            )
        devices = merge_device_history(devices, previous_devices)
        return DeviceScanResult(
            devices,
            tuple(successful),
            tuple(warnings),
            token.cancelled,
            discovered_devices,
        )

    def _enrich_fastboot(
        self,
        devices: tuple[DeviceInfo, ...],
        toolchain: ToolchainInfo,
        token: CancellationToken,
        warnings: list[str],
    ) -> tuple[DeviceInfo, ...]:
        enriched: list[DeviceInfo] = []
        for device in devices:
            if token.cancelled or not device.online or device.mode not in _FASTBOOT_MODES:
                enriched.append(device)
                continue
            values: dict[str, str] = {}
            for variable in _FASTBOOT_GETVARS:
                outcome = self._run(
                    ProcessRequest(
                        (toolchain.fastboot, "-s", device.serial, "getvar", variable),
                        timeout_seconds=self.fastboot_property_timeout_seconds,
                    ),
                    token,
                    f"fastboot:{device.serial}:{variable}",
                    warnings,
                )
                if token.cancelled:
                    break
                if (
                    outcome is not None
                    and outcome.returncode == 0
                    and not outcome.timed_out
                    and not outcome.cancelled
                ):
                    value = parse_fastboot_getvar(
                        f"{outcome.stdout}\n{outcome.stderr}",
                        variable,
                    )
                    if value is not None:
                        values[variable] = value

            slot_value = values.get("current-slot", "").strip().casefold()
            slot = slot_value if slot_value in {"a", "b"} else ""
            unlocked = _fastboot_bool(values.get("unlocked"))
            userspace = _fastboot_bool(values.get("is-userspace"))
            bootloader = (
                "unlocked" if unlocked is True else "locked" if unlocked is False else "unknown"
            )
            enriched.append(
                replace(
                    device,
                    mode=(
                        "fastbootd"
                        if userspace is True
                        or (userspace is None and device.mode == "fastbootd")
                        else "fastboot"
                    ),
                    slot=slot,
                    bootloader=bootloader,
                )
            )
        return tuple(enriched)

    def _enrich_properties(
        self,
        devices: tuple[DeviceInfo, ...],
        toolchain: ToolchainInfo,
        token: CancellationToken,
        warnings: list[str],
        *,
        include_battery: bool,
    ) -> tuple[DeviceInfo, ...]:
        enriched: list[DeviceInfo] = []
        for device in devices:
            if token.cancelled or not device.online or device.mode not in _PROPERTY_SAFE_MODES:
                enriched.append(device)
                continue
            outcome = self._run(
                ProcessRequest(
                    (toolchain.adb, "-s", device.serial, "shell", "getprop"),
                    timeout_seconds=self.property_timeout_seconds,
                ),
                token,
                f"properties:{device.serial}",
                warnings,
            )
            if outcome is None or outcome.returncode != 0 or outcome.timed_out or outcome.cancelled:
                enriched.append(device)
                continue
            properties = parse_getprop(outcome.stdout)
            boot_mode = properties.get("ro.bootmode", "").strip().casefold()
            mode = "recovery" if boot_mode == "recovery" else device.mode
            model = properties.get("ro.product.model", "").strip() or device.model
            codename = (
                properties.get("ro.product.device", "").strip()
                or properties.get("ro.build.product", "").strip()
                or device.codename
            )
            slot = properties.get("ro.boot.slot_suffix", "").strip().lstrip("_") or device.slot
            name = (
                properties.get("ro.product.marketname", "").strip()
                or model
                or codename
                or device.name
                or device.serial
            )
            android_version = (
                properties.get("ro.build.version.release", "").strip()
                or device.android_version
            )
            build = properties.get("ro.build.id", "").strip() or device.build
            security_patch = (
                properties.get("ro.build.version.security_patch", "").strip()
                or device.security_patch
            )
            architecture = normalize_device_architecture(
                properties.get("ro.product.cpu.abi")
                or properties.get("ro.product.cpu.abilist")
            )
            property_kernel = (
                properties.get("ro.kernel.version", "").strip()
                or properties.get("ro.boot.kernel_version", "").strip()
            )
            kernel_release = property_kernel
            kernel_outcome = self._run(
                ProcessRequest(
                    (toolchain.adb, "-s", device.serial, "shell", "uname", "-r"),
                    timeout_seconds=self.kernel_timeout_seconds,
                ),
                token,
                f"kernel:{device.serial}",
                warnings,
            )
            if (
                kernel_outcome is not None
                and kernel_outcome.returncode == 0
                and not kernel_outcome.timed_out
                and not kernel_outcome.cancelled
            ):
                observed_kernel = kernel_outcome.stdout.strip()
                if (
                    observed_kernel
                    and len(observed_kernel) <= 256
                    and observed_kernel.isprintable()
                    and not any(character.isspace() for character in observed_kernel)
                ):
                    kernel_release = observed_kernel
            bootloader = _bootloader_state(properties, device.bootloader)
            battery = device.battery
            if include_battery and device.mode == "adb" and not token.cancelled:
                battery_outcome = self._run(
                    ProcessRequest(
                        (toolchain.adb, "-s", device.serial, "shell", "dumpsys", "battery"),
                        timeout_seconds=self.battery_timeout_seconds,
                    ),
                    token,
                    f"battery:{device.serial}",
                    warnings,
                )
                if (
                    battery_outcome is not None
                    and battery_outcome.returncode == 0
                    and not battery_outcome.timed_out
                    and not battery_outcome.cancelled
                ):
                    battery = parse_battery_level(battery_outcome.stdout)
            root = self._root_available(device, toolchain, token) if device.mode == "adb" else False
            enriched.append(
                replace(
                    device,
                    mode=mode,
                    model=model,
                    codename=codename,
                    slot=slot,
                    root=root,
                    name=name,
                    android_version=android_version,
                    build=build,
                    security_patch=security_patch,
                    bootloader=bootloader,
                    battery=battery,
                    architecture=architecture,
                    kernel_release=kernel_release,
                    kmi=derive_android_kmi(kernel_release),
                )
            )
        return tuple(enriched)

    def _root_available(
        self,
        device: DeviceInfo,
        toolchain: ToolchainInfo,
        token: CancellationToken,
    ) -> bool:
        """Return whether the shell can obtain uid 0, failing closed."""

        if token.cancelled:
            return False
        # A non-zero exit is the normal answer on a stock device, so this probe
        # never contributes to the user visible scan warnings.
        probe_warnings: list[str] = []
        outcome = self._run(
            ProcessRequest(
                (toolchain.adb, "-s", device.serial, "shell", "su", "-c", "id -u"),
                timeout_seconds=self.root_timeout_seconds,
            ),
            token,
            f"root:{device.serial}",
            probe_warnings,
        )
        return (
            outcome is not None
            and outcome.returncode == 0
            and not outcome.timed_out
            and not outcome.cancelled
            and not outcome.stderr.strip()
            and outcome.stdout.strip() == "0"
        )

    def _run(
        self,
        request: ProcessRequest,
        token: CancellationToken,
        source: str,
        warnings: list[str],
    ) -> TransportOutcome | None:
        try:
            outcome = self.transport.run(request, token)
        except Exception as error:
            warnings.append(f"{source}:error:{error}")
            return None
        if outcome.timed_out:
            warnings.append(f"{source}:timeout")
        elif outcome.cancelled:
            warnings.append(f"{source}:cancelled")
        elif outcome.returncode != 0:
            warnings.append(f"{source}:exit:{outcome.returncode}")
        return outcome


class DevicePoller:
    """Poll device state on a worker thread until stopped; never imports wx.

    The poller retains identity-only history across disconnects, suppresses
    duplicate observations, and does not turn a failed scanner into a false
    hot-unplug event.
    """

    def __init__(
        self,
        service: DeviceService,
        toolchain_provider: Callable[[], ToolchainInfo],
        listener: Callable[[DeviceScanResult], None],
        *,
        interval_seconds: float = 2.0,
        include_properties: bool = False,
        history_limit: int = 256,
        excluded_serials_provider: Callable[[], frozenset[str]] | None = None,
    ) -> None:
        if not isfinite(interval_seconds) or interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        if (
            not isinstance(history_limit, int)
            or isinstance(history_limit, bool)
            or history_limit <= 0
        ):
            raise ValueError("history_limit must be a positive integer")
        self.service = service
        self.toolchain_provider = toolchain_provider
        self.listener = listener
        self.interval_seconds = interval_seconds
        self.include_properties = include_properties
        self.history_limit = history_limit
        self.excluded_serials_provider = (
            excluded_serials_provider or _no_excluded_serials
        )
        self._cancellation = CancellationToken()
        self._paused = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()
        self._identity_history: dict[str, DeviceInfo] = {}
        self._last_devices: tuple[DeviceInfo, ...] | None = None

    def start(self) -> bool:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            if self._cancellation.cancelled:
                self._cancellation = CancellationToken()
            self._thread = threading.Thread(
                target=self.run,
                name="pixelflasher-device-poller",
                daemon=True,
            )
            self._thread.start()
            return True

    def stop(self, timeout_seconds: float = 5.0) -> bool:
        if not isfinite(timeout_seconds) or timeout_seconds < 0:
            raise ValueError("timeout_seconds must be finite and non-negative")
        self._cancellation.cancel()
        self._wake.set()
        with self._lock:
            thread = self._thread
        if thread is threading.current_thread():
            return True
        if thread is not None:
            thread.join(timeout_seconds)
        return thread is None or not thread.is_alive()

    def close(self, timeout_seconds: float = 5.0) -> bool:
        """Bounded lifecycle alias suitable for composition-root shutdown."""

        return self.stop(timeout_seconds)

    @property
    def running(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    @property
    def paused(self) -> bool:
        return self._paused.is_set()

    def pause(self) -> bool:
        """Pause future polls without destroying the owned worker thread."""

        if self._paused.is_set():
            return False
        self._paused.set()
        self._wake.set()
        return True

    def resume(self) -> bool:
        """Resume polling and wake the worker immediately."""

        if not self._paused.is_set():
            return False
        # A paused runtime deliberately clears its visible inventory. Force the
        # first resumed observation through even when the USB topology itself
        # did not change while scanning was paused.
        with self._lock:
            self._last_devices = None
        self._paused.clear()
        self._wake.set()
        return True

    def refresh(self) -> None:
        """Wake an active, unpaused poller for an immediate policy refresh."""

        if not self._paused.is_set():
            # Policy changes (for example enabled -> all) can change the visible
            # inventory without changing adb/fastboot output.
            with self._lock:
                self._last_devices = None
            self._wake.set()

    def invalidate_observation(self) -> None:
        """Retry an uncommitted observation after the normal poll interval."""

        with self._lock:
            self._last_devices = None

    def run(self) -> None:
        try:
            while not self._cancellation.cancelled:
                if self._paused.is_set():
                    self._wake.wait()
                    self._wake.clear()
                    continue
                with self._lock:
                    history = tuple(self._identity_history.values())
                    previous_observation = self._last_devices
                try:
                    excluded_serials = self.excluded_serials_provider()
                    result = self.service.scan(
                        self.toolchain_provider(),
                        include_properties=self.include_properties,
                        previous_devices=history,
                        excluded_serials=excluded_serials,
                        cancellation=self._cancellation,
                    )
                except Exception:
                    if self._wait_interval():
                        break
                    continue
                if result.cancelled:
                    break
                if not result.successful_sources:
                    if self._wait_interval():
                        break
                    continue

                observed_devices = _preserve_failed_source_inventory(
                    result.observed_devices,
                    previous_observation or (),
                    result.successful_sources,
                )
                visible_devices = tuple(
                    device
                    for device in observed_devices
                    if device.serial not in excluded_serials
                )
                result = replace(
                    result,
                    devices=visible_devices,
                    discovered_devices=observed_devices,
                )
                self._remember_identity(observed_devices)
                if observed_devices != previous_observation:
                    with self._lock:
                        self._last_devices = observed_devices
                    try:
                        self.listener(result)
                    except Exception:
                        pass
                if self._wait_interval():
                    break
        finally:
            with self._lock:
                if self._thread is threading.current_thread():
                    self._thread = None

    def _wait_interval(self) -> bool:
        self._wake.wait(self.interval_seconds)
        self._wake.clear()
        return self._cancellation.cancelled

    def _remember_identity(self, devices: tuple[DeviceInfo, ...]) -> None:
        with self._lock:
            for device in devices:
                self._identity_history.pop(device.serial, None)
                self._identity_history[device.serial] = device
            while len(self._identity_history) > self.history_limit:
                oldest = next(iter(self._identity_history))
                del self._identity_history[oldest]


def _preserve_failed_source_inventory(
    devices: tuple[DeviceInfo, ...],
    previous_devices: tuple[DeviceInfo, ...],
    successful_sources: tuple[str, ...],
) -> tuple[DeviceInfo, ...]:
    """Retain only the source family that was not observed successfully."""

    by_serial = {device.serial: device for device in devices}
    successful = frozenset(successful_sources)
    for previous in previous_devices:
        is_fastboot = previous.mode in _FASTBOOT_MODES
        source = "fastboot" if is_fastboot else "adb"
        if source not in successful:
            by_serial.setdefault(previous.serial, previous)
    return canonicalize_device_inventory(tuple(by_serial.values()))


def _parse_attributes(fields: list[str]) -> dict[str, str]:
    attributes: dict[str, str] = {}
    for field in fields:
        key, separator, value = field.partition(":")
        if separator and key and value:
            attributes[key.lower()] = value
    return attributes


def _connection_for_adb(serial: str, attributes: dict[str, str]) -> str:
    if "usb" in attributes:
        return "USB"
    if serial.startswith("emulator-"):
        return "USB"
    if ":" in serial:
        return "Wi-Fi"
    # Wireless debugging serials are mDNS instance names carrying no colon.
    if serial.casefold().rstrip(".").endswith(_MDNS_ADB_SERVICE_SUFFIXES):
        return "Wi-Fi"
    return "USB"


def _bootloader_state(properties: dict[str, str], fallback: str) -> str:
    flash_locked = properties.get("ro.boot.flash.locked", "").strip().casefold()
    if flash_locked in {"1", "true", "locked"}:
        return "locked"
    if flash_locked in {"0", "false", "unlocked"}:
        return "unlocked"
    vbmeta_state = properties.get("ro.boot.vbmeta.device_state", "").strip().casefold()
    if vbmeta_state in {"locked", "unlocked"}:
        return vbmeta_state
    return fallback if fallback in {"locked", "unlocked"} else "unknown"


def _fastboot_bool(value: str | None) -> bool | None:
    normalized = value.strip().casefold() if value is not None else ""
    if normalized in {"1", "true", "yes", "y", "unlocked"}:
        return True
    if normalized in {"0", "false", "no", "n", "locked"}:
        return False
    return None
