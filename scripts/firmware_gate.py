#!/usr/bin/env python3
"""Select and process a real stock firmware package through the engine.

The packaged firmware smoke proves the contract against a generated fixture. A
release candidate also has to show the same path over a genuine Google factory
image, whose size, layout and signing differ from anything a fixture produces.

Nothing here touches the device: selection and processing are host-side, and the
extracted boot artifacts are what the later patch and flash sessions consume.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from pixelflasher_core import ApplicationRuntime, InteractionDecision  # noqa: E402
from scripts.evidence_store import record  # noqa: E402
from ui.bridge_contract import BRIDGE_VERSION, BridgeRequest  # noqa: E402
from ui.core_command_factory import create_command_factory  # noqa: E402

SCHEMA_VERSION = 1


class FirmwareGateError(RuntimeError):
    """The firmware session cannot continue."""


def _request(
    command: str,
    *,
    request_id: str,
    revision: int,
    payload: Mapping[str, object] | None = None,
) -> BridgeRequest:
    return BridgeRequest.from_json(
        json.dumps(
            {
                "version": BRIDGE_VERSION,
                "requestId": request_id,
                "command": command,
                "payload": dict(payload or {}),
                "expectedRevision": revision,
            },
            separators=(",", ":"),
        )
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_session(
    *,
    firmware: Path,
    expected_kind: str,
    trust_sha256: str | None = None,
) -> dict[str, object]:
    if not firmware.is_file():
        raise FirmwareGateError(f"firmware package is missing: {firmware}")
    digest = sha256_file(firmware)
    if trust_sha256 is not None and trust_sha256.strip().casefold() != digest:
        raise FirmwareGateError(
            f"the package digest is {digest}, the operator vouched for {trust_sha256}"
        )
    confirmations: list[str] = []

    def interaction(request: object) -> InteractionDecision:
        nonce = getattr(request, "confirmation_nonce", None)
        if isinstance(nonce, str) and nonce:
            # A factory package carries no AOSP whole-file signature, so the
            # backend asks someone to vouch for it. Answering yes is only
            # honest when the operator named the digest in advance.
            if trust_sha256 is None:
                return InteractionDecision.CANCELLED
            confirmations.append(nonce)
            return InteractionDecision.ACCEPTED
        return InteractionDecision.ACCEPTED

    holder = Path(tempfile.mkdtemp(prefix="pixelflasher-firmware-gate-"))
    runtime = ApplicationRuntime.open(
        holder / "config.json",
        interaction_handler=interaction,
        enable_device_monitor=False,
        legacy_database_path=holder / "legacy.db",
    )
    try:
        factory = create_command_factory(runtime.engine.snapshot)
        revision = runtime.engine.snapshot().revision
        picker = _request(
            "native.pickFile",
            request_id="firmware-gate-picker",
            revision=revision,
            payload={"purpose": "firmware.select", "title": "Firmware session"},
        )
        public_grant = factory.issue_native_grants(picker, (firmware,))
        token = public_grant.get("grant")
        if not isinstance(token, str) or "path" in public_grant:
            raise FirmwareGateError("the native firmware grant was not opaque")

        selected = runtime.engine.execute(
            factory(
                _request(
                    "firmware.select",
                    request_id="firmware-gate-select",
                    revision=revision,
                    payload={"grant": token, "expectedKind": expected_kind},
                )
            )
        )
        if not selected.ok:
            raise FirmwareGateError(f"firmware selection failed: {selected.code}")

        revision = runtime.engine.snapshot().revision
        processed = runtime.engine.execute(
            factory(
                _request(
                    "firmware.process",
                    request_id="firmware-gate-process",
                    revision=revision,
                )
            )
        )
        if not processed.ok:
            raise FirmwareGateError(f"firmware processing failed: {processed.code}")

        snapshot = runtime.engine.snapshot()
        stored = runtime.firmware_repository.resolve_selection(sha256=digest)
        boot_records = list(runtime.boot_repository.list())
        return {
            "schemaVersion": SCHEMA_VERSION,
            "status": "passed",
            "expectedKind": expected_kind,
            "firmwareSha256": digest,
            "selectCode": selected.code,
            "processCode": processed.code,
            "confirmationCount": len(confirmations),
            "trustStatus": (stored.metadata.get("packageSignature", "") if stored else ""),
            "firmwareType": snapshot.firmware.type,
            "firmwareBuild": snapshot.firmware.build,
            "firmwareProcessed": bool(snapshot.firmware.processed),
            "bootArtifacts": sorted({item.partition for item in boot_records if item.partition}),
            "bootRecordCount": len(boot_records),
            "bootCodenames": sorted(
                {codename for item in boot_records for codename in item.device_codenames}
            ),
        }
    finally:
        runtime.shutdown()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firmware", type=Path, required=True)
    parser.add_argument("--expected-kind", default="stock", choices=("stock", "custom"))
    parser.add_argument("--record", action="store_true")
    parser.add_argument("--record-id", default="hardware/firmware-stock-session")
    parser.add_argument(
        "--trust-sha256",
        help="vouch for an unsigned package by naming its SHA-256 in advance",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        session = run_session(
            firmware=args.firmware,
            expected_kind=args.expected_kind,
            trust_sha256=args.trust_sha256,
        )
    except Exception as error:  # noqa: BLE001 - report any firmware failure closed
        print(f"error: {type(error).__name__}: {error}")
        return 1
    print(json.dumps(session, indent=2, sort_keys=True))
    if args.record:
        report = Path(tempfile.mkdtemp(prefix="pixelflasher-firmware-")) / "session.json"
        report.write_text(json.dumps(session, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        entry = record(report, record_id=args.record_id, kind="hardware-session")
        print(f"recorded {entry['id']} ({entry['sha256'][:12]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
