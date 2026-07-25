from __future__ import annotations

from dataclasses import replace

import pytest

from pixelflasher_core.contracts import (
    AppCommand,
    AppSnapshot,
    BootInfo,
    CommandKind,
    DeviceInfo,
    FirmwareInfo,
    FlashPlan,
    OperationBatch,
    OperationPlan,
    OperationPostcondition,
    OperationRisk,
    ProcessRequest,
)
from pixelflasher_core.safety import SafetyPolicy

NOW = 1_000.0
SERIAL = "SERIAL-A"


def _request(*argv: str) -> ProcessRequest:
    return ProcessRequest(tuple(argv))


def _plan(**changes: object) -> OperationPlan:
    values: dict[str, object] = {
        "requests": (_request("fastboot", "-s", SERIAL, "getvar", "product"),),
        "created": NOW - 10,
        "expires": NOW + 100,
        "risk": OperationRisk.DESTRUCTIVE,
        "postconditions": (
            OperationPostcondition(
                "device_reachable",
                {"mode": "fastboot"},
                "target remains reachable",
            ),
        ),
        "target_serial": SERIAL,
        "expected_codename": "akita",
        "expected_device_state": "fastboot",
        "expected_architecture": "arm64",
        "expected_kmi": "android14-5.15",
        "firmware_hash": "F1",
        "boot_hash": "B1",
        "plan_revision": 3,
        "fingerprint": "P1",
    }
    values.update(changes)
    return OperationPlan(**values)


def _snapshot(
    *,
    devices: tuple[DeviceInfo, ...] | None = None,
    selected_serials: tuple[str, ...] = (SERIAL,),
    revision: int = 7,
) -> AppSnapshot:
    return AppSnapshot(
        revision=revision,
        devices=(
            devices
            if devices is not None
            else (
                DeviceInfo(
                    SERIAL,
                    codename="akita",
                    mode="fastboot",
                    architecture="arm64",
                    kmi="android14-5.15",
                ),
            )
        ),
        selected_serials=selected_serials,
        selected_serial=selected_serials[0] if selected_serials else None,
        firmware=FirmwareInfo(hash="F1"),
        boot=BootInfo(hash="B1"),
        plan=FlashPlan(revision=3, fingerprint="P1"),
    )


def _decision(
    plan: OperationPlan | None = None,
    *,
    snapshot: AppSnapshot | None = None,
    policy: SafetyPolicy | None = None,
    **changes: object,
):
    values: dict[str, object] = {
        "kind": CommandKind.FLASH_EXECUTE,
        "expected_revision": 7,
        "target_serial": SERIAL,
        "operation_plan": _plan() if plan is None else plan,
    }
    values.update(changes)
    return (policy or SafetyPolicy(clock=lambda: NOW)).evaluate(
        AppCommand(**values),
        snapshot or _snapshot(),
    )


@pytest.mark.parametrize(
    ("kind", "change", "expected"),
    (
        ("firmware.process", {"payload": {"unexpected": True}}, "invalid_firmware_process_payload"),
        ("firmware.process", {"operation_plan": _plan()}, "untrusted_operation_plan"),
        ("firmware.process", {"target_serial": SERIAL}, "firmware_process_target_not_allowed"),
        ("support.create", {"operation_plan": _plan()}, "untrusted_operation_plan"),
        ("support.create", {"target_serial": SERIAL}, "support_target_not_allowed"),
        ("tools.avb", {"operation_plan": _plan()}, "untrusted_operation_plan"),
        ("tools.avb", {"target_serial": SERIAL}, "avb_target_not_allowed"),
        ("tools.xml", {"operation_plan": _plan()}, "untrusted_operation_plan"),
        ("tools.xml", {"target_serial": SERIAL}, "xml_target_not_allowed"),
        ("tools.keybox", {"operation_plan": _plan()}, "untrusted_operation_plan"),
        ("tools.keybox", {"target_serial": SERIAL}, "keybox_target_not_allowed"),
        ("tools.myTools", {"operation_plan": _plan()}, "untrusted_operation_plan"),
        ("tools.myTools.legacyPermission", {"target_serial": SERIAL}, "my_tools_target_not_allowed"),
        ("backups.list", {"operation_plan": _plan()}, "untrusted_operation_plan"),
        ("backups.delete", {"target_serial": SERIAL}, "backup_inventory_target_not_allowed"),
    ),
)
def test_local_commands_reject_foreign_plans_and_targets(
    kind: str,
    change: dict[str, object],
    expected: str,
) -> None:
    values: dict[str, object] = {"kind": kind, "expected_revision": 7}
    values.update(change)
    decision = SafetyPolicy(clock=lambda: NOW).evaluate(AppCommand(**values), _snapshot())
    assert not decision.allowed
    assert decision.code == expected


@pytest.mark.parametrize(
    "kind",
    (
        "firmware.process",
        "support.create",
        "tools.avb",
        "tools.xml",
        "tools.keybox",
        "tools.myTools",
        "backups.list",
    ),
)
def test_local_commands_without_foreign_execution_context_reach_revision_policy(
    kind: str,
) -> None:
    decision = SafetyPolicy(clock=lambda: NOW).evaluate(
        AppCommand(kind, expected_revision=7),
        _snapshot(),
    )
    assert decision.allowed
    assert decision.code == "allowed"


@pytest.mark.parametrize(
    ("plan", "snapshot", "command_changes", "expected"),
    (
        (_plan(), _snapshot(selected_serials=()), {}, "device_not_selected"),
        (_plan(target_serial=None), _snapshot(), {"target_serial": None}, "plan_target_serial_required"),
        (_plan(), _snapshot(), {"target_serial": None}, "command_target_serial_required"),
        (_plan(), _snapshot(), {"target_serial": "SERIAL-B"}, "ambiguous_target_serial"),
        (_plan(target_serial="SERIAL-B"), _snapshot(), {"target_serial": "SERIAL-B"}, "target_serial_changed"),
        (_plan(expires=NOW - 1), _snapshot(), {}, "plan_expired"),
        (_plan(created=NOW + 2, expires=NOW + 100), _snapshot(), {}, "plan_created_in_future"),
        (
            _plan(),
            _snapshot(devices=(DeviceInfo(SERIAL, mode="offline", online=False),)),
            {},
            "device_disconnected",
        ),
        (_plan(), _snapshot(devices=()), {}, "device_state_unavailable"),
        (
            _plan(expected_device_state="adb"),
            _snapshot(),
            {},
            "device_state_changed",
        ),
        (
            _plan(expected_device_state="", expected_codename="akita"),
            _snapshot(devices=(DeviceInfo(SERIAL, mode="fastboot"),)),
            {},
            "device_codename_unavailable",
        ),
        (_plan(expected_codename="shiba"), _snapshot(), {}, "device_codename_changed"),
        (
            _plan(expected_architecture="arm64"),
            _snapshot(devices=(DeviceInfo(SERIAL, codename="akita", mode="fastboot"),)),
            {},
            "device_architecture_unavailable",
        ),
        (_plan(expected_architecture="x86_64"), _snapshot(), {}, "device_architecture_changed"),
        (
            _plan(expected_kmi="android14-5.15"),
            _snapshot(
                devices=(
                    DeviceInfo(
                        SERIAL,
                        codename="akita",
                        mode="fastboot",
                        architecture="arm64",
                    ),
                )
            ),
            {},
            "device_kmi_unavailable",
        ),
        (_plan(expected_kmi="android15-6.1"), _snapshot(), {}, "device_kmi_changed"),
        (_plan(snapshot_revision=6), _snapshot(), {}, "snapshot_revision_changed"),
    ),
)
def test_destructive_plan_revalidation_reports_each_boundary(
    plan: OperationPlan,
    snapshot: AppSnapshot,
    command_changes: dict[str, object],
    expected: str,
) -> None:
    decision = _decision(plan, snapshot=snapshot, **command_changes)
    assert not decision.allowed
    assert decision.code == expected


def test_revision_confirmation_and_destructive_classification_boundaries() -> None:
    policy = SafetyPolicy(clock=lambda: NOW)
    dry = _plan(dry_run=True, requests=(), postconditions=())
    assert not policy.is_destructive(
        AppCommand(CommandKind.FLASH_EXECUTE, operation_plan=dry)
    )
    assert policy.is_destructive(AppCommand("custom", destructive=True))
    assert policy.is_destructive(AppCommand(CommandKind.FLASH_EXECUTE))
    assert policy.is_destructive(AppCommand("custom", operation_plan=_plan()))

    missing_revision = policy.evaluate(AppCommand("updates.check"), _snapshot())
    assert missing_revision.code == "revision_required"

    non_destructive = policy.evaluate(
        AppCommand(
            "custom.confirm",
            requires_confirmation=True,
            operation_id="confirm",
        ),
        _snapshot(),
    )
    assert non_destructive.allowed
    assert non_destructive.interaction is not None
    assert non_destructive.interaction.title == "Confirm device operation"
    assert non_destructive.interaction.message == "Run 'custom.confirm'?"


def _confirmed_batch(plan: OperationPlan | None = None) -> OperationBatch:
    candidate = OperationBatch(
        (plan or _plan(data_behavior="wipe"),),
        created=NOW - 5,
        expires=NOW + 50,
        confirmation_nonce="batch-nonce",
    )
    return replace(candidate, confirmation_token=candidate.confirmation_challenge())


def test_batch_revalidation_covers_time_integrity_snapshot_and_child_failures() -> None:
    policy = SafetyPolicy(clock=lambda: NOW)
    valid = _confirmed_batch()

    expired = replace(valid, created=NOW - 100, expires=NOW - 1)
    assert policy.evaluate_batch(expired, _snapshot()).code == "batch_expired"

    future = replace(valid, created=NOW + 2, expires=NOW + 20)
    assert policy.evaluate_batch(future, _snapshot()).code == "batch_created_in_future"

    tampered = _confirmed_batch()
    object.__setattr__(tampered, "fingerprint", "0" * 64)
    assert policy.evaluate_batch(tampered, _snapshot()).code == "batch_fingerprint_changed"

    unconfirmed = replace(valid, confirmation_token=None)
    assert policy.evaluate_batch(unconfirmed, _snapshot()).code == "batch_confirmation_required"

    assert policy.evaluate_batch(valid, {}).code == "batch_snapshot_unavailable"

    invalid_child = _confirmed_batch(_plan(firmware_hash="F2", data_behavior="wipe"))
    failed_child = policy.evaluate_batch(invalid_child, {SERIAL: _snapshot()})
    assert not failed_child.allowed
    assert failed_child.code == "firmware_hash_changed"
    assert failed_child.message.startswith(f"{SERIAL}:")

    allowed_single = policy.evaluate_batch(valid, _snapshot())
    assert allowed_single.allowed
    assert allowed_single.interaction is not None
    assert allowed_single.interaction.expected_revision == 7

    allowed_mapping = policy.evaluate_batch(valid, {SERIAL: _snapshot()})
    assert allowed_mapping.allowed
    assert allowed_mapping.interaction is not None
    assert allowed_mapping.interaction.expected_revision == 7


def test_reinforced_confirmation_handles_absent_dry_and_safe_plans() -> None:
    policy = SafetyPolicy()
    assert not policy.requires_reinforced_confirmation(AppCommand("custom"))
    assert not policy.requires_reinforced_confirmation(
        AppCommand("custom", operation_plan=_plan(dry_run=True, requests=(), postconditions=()))
    )
    safe = OperationPlan(
        requests=(_request("adb", "devices"),),
        risk=OperationRisk.READ_ONLY,
        data_behavior="preserve",
    )
    assert not policy.requires_reinforced_confirmation(
        AppCommand("custom", operation_plan=safe)
    )
