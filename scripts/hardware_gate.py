#!/usr/bin/env python3
"""Exercise the read-only device path against a physically connected Pixel.

The engine is UI independent, so a hardware session runs the same registered
commands the React workspace issues rather than raw adb, and records what the
device actually reported. This covers the non-mutating gates only; flashing,
patching and bootloader changes are deliberately out of scope here.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from pixelflasher_core import AppCommand, ApplicationRuntime  # noqa: E402
from scripts.evidence_store import record  # noqa: E402

SCHEMA_VERSION = 1


class HardwareGateError(RuntimeError):
    """The hardware session cannot continue."""


def _result_summary(result: object) -> dict[str, object]:
    status = getattr(result, "status", None)
    return {
        "status": getattr(status, "value", str(status)),
        "code": getattr(result, "code", ""),
        "ok": bool(getattr(result, "ok", False)),
    }


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

        observations: dict[str, object] = {
            "scan": _result_summary(scan),
            "deviceCount": len(devices),
            "mode": target.mode,
            "codename": target.codename,
        }
        return {
            "schemaVersion": SCHEMA_VERSION,
            "status": "passed",
            "toolchainReady": True,
            "observations": observations,
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
    print(json.dumps(session, indent=2, sort_keys=True))
    if args.record:
        report = Path(tempfile.mkdtemp(prefix="pixelflasher-hardware-")) / "session.json"
        report.write_text(json.dumps(session, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        entry = record(report, record_id="hardware/device-discovery", kind="hardware-session")
        print(f"recorded {entry['id']} ({entry['sha256'][:12]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
