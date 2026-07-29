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
import sys
import tempfile
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


class HardwareGateError(RuntimeError):
    """The hardware session cannot continue."""


@dataclass(frozen=True, slots=True)
class Probe:
    gate: str
    command: str
    payload: dict[str, object] | None = None
    device_scoped: bool = True


PROBES: tuple[Probe, ...] = (
    Probe("device.inspect", "device.inspect", {"action": "properties"}),
    Probe("device.inspect", "device.inspect", {"action": "pifPrint"}),
    Probe("device.inspect", "device.inspect", {"action": "screenXml"}),
    Probe("device.ota_diagnostics", "device.ota.status"),
    Probe("device.ota_diagnostics", "device.ota.certificates"),
    Probe("device.ota_diagnostics", "device.ota.logs"),
    Probe("apps.package_manager", "apps.list"),
    Probe("device.wireless", "tools.wifi.status"),
)

# Probes whose failure is a property of the device rather than of the product.
EXPECTED_BLOCKED: dict[str, str] = {
    # update_engine only answers while an OTA is staged.
    "device.ota.status": "process_failed",
}


def _assert_non_mutating(probe: Probe) -> None:
    """Refuse to run anything this harness is not allowed to run."""

    spec = COMMAND_REGISTRY.get(probe.command)
    if spec is None:
        raise HardwareGateError(f"unknown command: {probe.command}")
    mutability = getattr(spec.mutability, "value", str(spec.mutability))
    confirmation = getattr(spec.confirmation, "value", str(spec.confirmation))
    if mutability != "read_only" or confirmation != "none":
        raise HardwareGateError(
            f"{probe.command} is {mutability}/{confirmation}; this harness runs read-only probes only"
        )


def _route_free(payload: object) -> bool:
    """A public projection must never carry a host path."""

    text = json.dumps(payload, default=str)
    markers = (":\\\\", ":/", "/home/", "/Users/", "\\\\\\\\")
    return not any(marker in text for marker in markers)


def run_probes(runtime: ApplicationRuntime, serial: str) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for probe in PROBES:
        _assert_non_mutating(probe)
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


def run_session(*, platform_tools: Path, serial: str | None) -> dict[str, object]:
    holder = Path(tempfile.mkdtemp(prefix="pixelflasher-hardware-gate-"))
    config = holder / "PixelFlasher.json"
    config.write_text(
        json.dumps({"platform_tools_path": str(platform_tools)}),
        encoding="utf-8",
    )
    runtime = ApplicationRuntime.open(config, enable_device_monitor=False)
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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        session = run_session(platform_tools=args.platform_tools, serial=args.serial)
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
