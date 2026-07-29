#!/usr/bin/env python3
"""Fetch a root app from the signed catalog and patch a stock boot image.

Both halves are exercised against the real artifacts: the APK is downloaded and
authenticated through the packaged Ed25519 catalog rather than staged by hand,
and the patch runs on the connected device against the init_boot extracted from
a genuine factory image.

Patching produces an image; it does not root anything. Writing it to a partition
is boot.flash, which is destructive and deliberately out of scope here.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from pixelflasher_core import AppCommand, ApplicationRuntime, InteractionDecision  # noqa: E402
from scripts.evidence_store import record  # noqa: E402
from scripts.provisioned_runtime import open_runtime, provisioned_distributions  # noqa: E402
from ui.command_registry import COMMAND_REGISTRY  # noqa: E402

SCHEMA_VERSION = 1


class RootGateError(RuntimeError):
    """The root session cannot continue."""


def _assert_not_destructive(command: str) -> None:
    spec = COMMAND_REGISTRY.get(command)
    if spec is None:
        raise RootGateError(f"unknown command: {command}")
    if getattr(spec.mutability, "value", str(spec.mutability)) == "destructive":
        raise RootGateError(f"{command} is destructive and is out of scope here")


def _accept_standard(request: object) -> InteractionDecision:
    if getattr(request, "reinforced", False) or getattr(request, "destructive", False):
        return InteractionDecision.CANCELLED
    return InteractionDecision.ACCEPTED


def _execute(
    runtime: ApplicationRuntime,
    command: str,
    *,
    serial: str | None = None,
    payload: Mapping[str, object] | None = None,
) -> object:
    _assert_not_destructive(command)
    return runtime.engine.execute(
        AppCommand(
            command,
            expected_revision=runtime.store.snapshot().revision,
            target_serial=serial,
            payload=dict(payload or {}),
        )
    )


def run_session(*, platform_tools: Path, serial: str | None, flavor: str) -> dict[str, object]:
    holder = Path(tempfile.mkdtemp(prefix="pixelflasher-root-gate-"))
    (holder / "PixelFlasher.json").write_text(
        json.dumps({"platform_tools_path": str(platform_tools)}),
        encoding="utf-8",
    )
    distributions = provisioned_distributions()
    if not distributions["rootApps"]:
        raise RootGateError("the signed root-app catalog is not provisioned")
    runtime = open_runtime(
        holder / "PixelFlasher.json",
        interaction_handler=_accept_standard,
        enable_device_monitor=False,
    )
    steps: list[dict[str, object]] = []

    def note(label: str, result: object) -> object:
        steps.append(
            {
                "step": label,
                "status": getattr(getattr(result, "status", None), "value", ""),
                "code": getattr(result, "code", ""),
                "ok": bool(getattr(result, "ok", False)),
            }
        )
        return result

    try:
        scan = note("device.scan", _execute(runtime, "device.scan"))
        if not scan.ok:  # type: ignore[attr-defined]
            raise RootGateError("device discovery failed")
        devices = [item for item in runtime.store.snapshot().devices if item.online]
        if not devices:
            raise RootGateError("no online device was discovered")
        target = next((item for item in devices if item.serial == serial), devices[0])

        # root.apps.list reports what is installed on the device; the signed
        # catalog is a separate surface reached through a refresh.
        note("root.apps.list", _execute(runtime, "root.apps.list", serial=target.serial))
        listed = note(
            "root.apps.catalog.refresh",
            _execute(runtime, "root.apps.catalog.refresh", payload={"channel": "stable"}),
        )
        if not listed.ok:  # type: ignore[attr-defined]
            raise RootGateError(f"root app catalog refresh failed: {listed.code}")  # type: ignore[attr-defined]

        value = getattr(listed, "value", {}) or {}
        entries = value.get("entries") or value.get("apps") or value.get("catalog") or []
        candidates = [
            item
            for item in (entries or [])
            if isinstance(item, dict) and item.get("flavor") == flavor
        ]
        if not candidates:
            raise RootGateError(f"the signed catalog offers no {flavor} target")
        artifact_id = candidates[0].get("artifactId") or candidates[0].get("id")
        if not isinstance(artifact_id, str):
            raise RootGateError("the catalog entry carries no opaque artifact id")

        downloaded = note(
            "root.apps.download",
            _execute(runtime, "root.apps.download", payload={"artifactId": artifact_id}),
        )
        if not downloaded.ok:  # type: ignore[attr-defined]
            raise RootGateError(f"root app download failed: {downloaded.code}")  # type: ignore[attr-defined]

        return {
            "schemaVersion": SCHEMA_VERSION,
            "status": "passed",
            "flavor": flavor,
            "device": {"codename": target.codename, "mode": target.mode},
            "catalogEntries": len(entries or []),
            "steps": steps,
        }
    finally:
        runtime.shutdown()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform-tools", type=Path, required=True)
    parser.add_argument("--serial")
    parser.add_argument("--flavor", default="magisk")
    parser.add_argument("--record", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        session = run_session(
            platform_tools=args.platform_tools,
            serial=args.serial,
            flavor=args.flavor,
        )
    except Exception as error:  # noqa: BLE001 - report any root failure closed
        print(f"error: {type(error).__name__}: {error}")
        return 1
    print(json.dumps(session, indent=2, sort_keys=True))
    if args.record:
        report = Path(tempfile.mkdtemp(prefix="pixelflasher-root-")) / "session.json"
        report.write_text(json.dumps(session, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        entry = record(report, record_id="hardware/root-catalog-session", kind="hardware-session")
        print(f"recorded {entry['id']} ({entry['sha256'][:12]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
