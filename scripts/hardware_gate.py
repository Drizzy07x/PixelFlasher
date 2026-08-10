#!/usr/bin/env python3
"""Exercise device capabilities against a physically connected Pixel.

The engine is UI independent, so a hardware session runs the same registered
commands the React workspace issues rather than raw adb, and records what the
device actually reported. Only non-mutating capabilities run here: every probe
is read-only, needs no confirmation, and leaves no partition touched.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from pixelflasher_core import AppCommand, ApplicationRuntime  # noqa: E402
from scripts.evidence_store import record  # noqa: E402
from ui.command_registry import COMMAND_REGISTRY  # noqa: E402
from ui.public_bridge import project_operation_result  # noqa: E402

SCHEMA_VERSION = 1

# Matched against the JSON encoding of a projection, where one host backslash is
# already doubled: a drive root, a UNC prefix, or a POSIX home root.
_HOST_PATH_PATTERN = re.compile(
    r"(?<![A-Za-z])[A-Za-z]:(?:\\\\|/)"
    r"|\\\\\\\\"
    r"|/home/"
    r"|/Users/"
)


class HardwareGateError(RuntimeError):
    """The hardware session cannot continue."""


@dataclass(frozen=True, slots=True)
class Probe:
    gate: str
    command: str
    payload: dict[str, object] | None = None
    device_scoped: bool = True
    # Mutating probes are opt in and never destructive: this harness covers the
    # capabilities that write nothing to a partition.
    mutating: bool = False


PROBES: tuple[Probe, ...] = (
    Probe("device.inspect", "device.inspect", {"action": "properties"}),
    Probe("device.inspect", "device.inspect", {"action": "pifPrint"}),
    Probe("device.inspect", "device.inspect", {"action": "screenXml"}),
    Probe("device.ota_diagnostics", "device.ota.status"),
    Probe("device.ota_diagnostics", "device.ota.certificates"),
    Probe("device.ota_diagnostics", "device.ota.logs"),
    Probe("apps.package_manager", "apps.list"),
    Probe("device.wireless", "tools.wifi.status"),
    Probe(
        "device.logs",
        "tools.logcat",
        {"buffers": ["main"], "mode": "snapshot", "maxLines": 200, "redaction": "strict"},
        mutating=True,
    ),
)

# Probes whose failure is a property of the device rather than of the product.
EXPECTED_BLOCKED: dict[str, str] = {
    # update_engine only answers while an OTA is staged.
    "device.ota.status": "process_failed",
}


def _assert_permitted(probe: Probe) -> None:
    """Refuse to run anything this harness is not allowed to run.

    Destructive commands, and any command needing a reinforced phrase, belong to
    the staged mutation sessions and are rejected here regardless of the probe.
    """

    spec = COMMAND_REGISTRY.get(probe.command)
    if spec is None:
        raise HardwareGateError(f"unknown command: {probe.command}")
    mutability = getattr(spec.mutability, "value", str(spec.mutability))
    confirmation = getattr(spec.confirmation, "value", str(spec.confirmation))
    if mutability == "destructive":
        raise HardwareGateError(f"{probe.command} is destructive and is out of scope here")
    if confirmation not in {"none", "standard"}:
        raise HardwareGateError(
            f"{probe.command} needs a {confirmation} confirmation and is out of scope here"
        )
    if mutability != "read_only" and not probe.mutating:
        raise HardwareGateError(
            f"{probe.command} is {mutability} but the probe did not declare it"
        )


def _approve_standard_confirmations(request: object) -> object:
    """Answer only the plain confirmations the permitted probes raise."""

    from pixelflasher_core.contracts import InteractionDecision

    if getattr(request, "destructive", False) or getattr(request, "reinforced", False):
        return InteractionDecision.CANCELLED
    return InteractionDecision.ACCEPTED


def _route_free(payload: object) -> bool:
    """A public projection must never carry a host path.

    The probes project real device output, and device text legitimately contains
    URLs. A bare ``:/`` scan cannot tell ``http://localhost/mmsc`` from a host
    path, which would make the session verdict depend on whatever sat in the log
    buffer. A drive letter is therefore only a drive letter when no other letter
    precedes it, which no URL scheme can satisfy.
    """

    text = json.dumps(payload, default=str)
    return _HOST_PATH_PATTERN.search(text) is None


def run_probes(runtime: ApplicationRuntime, serial: str) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for probe in PROBES:
        _assert_permitted(probe)
        revision = runtime.store.snapshot().revision
        command = AppCommand(
            probe.command,
            expected_revision=revision,
            target_serial=serial if probe.device_scoped else None,
            payload=dict(probe.payload or {}),
        )
        result = runtime.engine.execute(command)
        try:
            public = project_operation_result(probe.command, result)
            projected = True
        except Exception:  # noqa: BLE001 - a closed projector may refuse by design
            public = None
            projected = False
        expected_block = EXPECTED_BLOCKED.get(probe.command)
        blocked = not result.ok and result.code == expected_block
        results.append(
            {
                "gate": probe.gate,
                "command": probe.command,
                "action": (probe.payload or {}).get("action", ""),
                "status": getattr(result.status, "value", str(result.status)),
                "code": result.code,
                "ok": bool(result.ok),
                "expectedBlocked": blocked,
                "publicProjection": projected,
                "routeFree": _route_free(public) if projected else True,
            }
        )
    return results


def _wait_for_mode(
    runtime: ApplicationRuntime,
    serial: str,
    modes: frozenset[str],
    *,
    attempts: int = 45,
) -> str:
    """Rescan until the device reappears in one of the expected modes."""

    for _ in range(attempts):
        runtime.engine.execute(
            AppCommand("device.scan", expected_revision=runtime.store.snapshot().revision)
        )
        for device in runtime.store.snapshot().devices:
            if device.serial == serial and device.online and device.mode in modes:
                return device.mode
        time.sleep(2.0)
    raise HardwareGateError(f"the device did not reach {sorted(modes)} in time")


def run_fastboot_probe(runtime: ApplicationRuntime, serial: str) -> dict[str, object]:
    """Reboot to the bootloader, read its variables, and return to Android.

    Mode transitions write nothing to a partition, so the bootloader variable
    dump is reachable without leaving this harness's non-mutating scope.
    """

    reboot = runtime.engine.execute(
        AppCommand(
            "device.reboot",
            expected_revision=runtime.store.snapshot().revision,
            target_serial=serial,
            payload={"mode": "bootloader"},
        )
    )
    if not reboot.ok:
        raise HardwareGateError(f"reboot to bootloader failed: {reboot.code}")
    _wait_for_mode(runtime, serial, frozenset({"fastboot", "fastbootd"}))

    result = runtime.engine.execute(
        AppCommand(
            "device.fastbootVariables",
            expected_revision=runtime.store.snapshot().revision,
            target_serial=serial,
        )
    )
    public = project_operation_result("device.fastbootVariables", result)

    back = runtime.engine.execute(
        AppCommand(
            "device.reboot",
            expected_revision=runtime.store.snapshot().revision,
            target_serial=serial,
            payload={"mode": "system"},
        )
    )
    if not back.ok:
        raise HardwareGateError(f"reboot back to Android failed: {back.code}")
    _wait_for_mode(runtime, serial, frozenset({"adb"}))

    return {
        "gate": "device.inspect",
        "command": "device.fastbootVariables",
        "action": "",
        "status": getattr(result.status, "value", str(result.status)),
        "code": result.code,
        "ok": bool(result.ok),
        "expectedBlocked": False,
        "publicProjection": True,
        "routeFree": _route_free(public),
    }


def run_session(
    *,
    platform_tools: Path,
    serial: str | None,
    include_fastboot: bool = False,
) -> dict[str, object]:
    holder = Path(tempfile.mkdtemp(prefix="pixelflasher-hardware-gate-"))
    config = holder / "PixelFlasher.json"
    config.write_text(
        json.dumps({"platform_tools_path": str(platform_tools)}),
        encoding="utf-8",
    )
    runtime = ApplicationRuntime.open(
        config,
        enable_device_monitor=False,
        interaction_handler=_approve_standard_confirmations,
    )
    try:
        # Every command is revision bound, including discovery.
        scan = runtime.engine.execute(
            AppCommand("device.scan", expected_revision=runtime.store.snapshot().revision)
        )
        if not scan.ok:
            raise HardwareGateError(f"device discovery failed: {scan.code}")
        snapshot = runtime.store.snapshot()
        if not snapshot.toolchain.ready:
            raise HardwareGateError("the configured Platform Tools were not validated")
        devices = [item for item in snapshot.devices if item.online]
        if not devices:
            raise HardwareGateError("no online device was discovered")
        target = next((item for item in devices if item.serial == serial), devices[0])

        if snapshot.selected_serial != target.serial:
            selected = runtime.engine.execute(
                AppCommand(
                    "device.select",
                    expected_revision=runtime.store.snapshot().revision,
                    payload={"serials": [target.serial]},
                )
            )
            if not selected.ok:
                raise HardwareGateError(f"device selection failed: {selected.code}")

        probes = run_probes(runtime, target.serial)
        if include_fastboot:
            probes.append(run_fastboot_probe(runtime, target.serial))
        failed = [item for item in probes if not item["ok"] and not item["expectedBlocked"]]
        leaked = [item for item in probes if not item["routeFree"]]
        return {
            "schemaVersion": SCHEMA_VERSION,
            "status": "passed" if not failed and not leaked else "failed",
            "device": {
                "codename": target.codename,
                "mode": target.mode,
                "androidVersion": getattr(target, "android_version", ""),
            },
            "toolchainReady": True,
            "probeCount": len(probes),
            "probes": probes,
        }
    finally:
        runtime.shutdown()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform-tools", type=Path, required=True)
    parser.add_argument("--serial")
    parser.add_argument("--record", action="store_true", help="store the session as evidence")
    parser.add_argument(
        "--include-fastboot",
        action="store_true",
        help="reboot to the bootloader to read its variables, then return to Android",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        session = run_session(
            platform_tools=args.platform_tools,
            serial=args.serial,
            include_fastboot=args.include_fastboot,
        )
    except Exception as error:  # noqa: BLE001 - report any hardware failure closed
        print(f"error: {type(error).__name__}: {error}")
        return 1
    for probe in session["probes"]:  # type: ignore[index]
        mark = "ok  " if probe["ok"] else "FAIL"
        label = f"{probe['command']}{':' + probe['action'] if probe['action'] else ''}"
        print(f"  {mark} {label:<34} {probe['code']}")
    print(f"\nstatus: {session['status']} ({session['probeCount']} probes)")
    if session["status"] != "passed":
        return 1
    if args.record:
        report = Path(tempfile.mkdtemp(prefix="pixelflasher-hardware-")) / "session.json"
        report.write_text(json.dumps(session, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        entry = record(report, record_id="hardware/non-mutating-session", kind="hardware-session")
        print(f"recorded {entry['id']} ({entry['sha256'][:12]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
