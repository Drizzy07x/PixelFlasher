"""Thread-safe canonical application state store."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from threading import RLock
from typing import cast
from uuid import uuid4

from .contracts import (
    ActiveOperation,
    AppSnapshot,
    BootInfo,
    BootloaderLockEvidence,
    DeviceInfo,
    FirmwareInfo,
    OperationResult,
)
from .devices import canonicalize_device_inventory, reconcile_device_selection

StateListener = Callable[[AppSnapshot], None]
StateChangePreparer = Callable[[AppSnapshot], Mapping[str, object]]
StateSideEffect = Callable[[AppSnapshot, AppSnapshot], None]


class StaleRevisionError(RuntimeError):
    def __init__(self, expected: int, actual: int):
        super().__init__(f"expected revision {expected}, current revision is {actual}")
        self.expected = expected
        self.actual = actual


class Subscription:
    def __init__(self, cancel_callback: Callable[[], None]):
        self._cancel_callback = cancel_callback
        self._lock = RLock()
        self._cancelled = False

    def cancel(self) -> None:
        with self._lock:
            if self._cancelled:
                return
            self._cancelled = True
        self._cancel_callback()

    def __call__(self) -> None:
        """Cancel the subscription through the public callable contract."""

        self.cancel()

    def __enter__(self) -> Subscription:
        return self

    def __exit__(
        self,
        _exception_type: object,
        _exception: object,
        _traceback: object,
    ) -> None:
        self.cancel()


class AppStateStore:
    """Owns the single revisioned snapshot and publishes immutable replacements."""

    _UPDATABLE_FIELDS = frozenset(
        {
            "devices",
            "preferences",
            "selected_serials",
            "selected_serial",
            "firmware",
            "boot",
            "plan",
            "toolchain",
            "bootloader_lock_evidence",
        }
    )

    def __init__(self, initial: AppSnapshot | None = None):
        self._lock = RLock()
        self._snapshot = initial or AppSnapshot()
        self._listeners: dict[str, StateListener] = {}

    def snapshot(self) -> AppSnapshot:
        with self._lock:
            return self._snapshot

    def subscribe(self, listener: StateListener, *, emit_current: bool = False) -> Subscription:
        listener_id = uuid4().hex
        with self._lock:
            self._listeners[listener_id] = listener
            current = self._snapshot

        if emit_current:
            listener(current)

        def cancel() -> None:
            with self._lock:
                self._listeners.pop(listener_id, None)

        return Subscription(cancel)

    def update(
        self,
        *,
        expected_revision: int | None = None,
        **changes: object,
    ) -> AppSnapshot:
        with self._lock:
            current = self._snapshot
            self._assert_revision(current, expected_revision)
            updated = self._updated_snapshot(current, changes)
            self._snapshot = updated
            listeners = tuple(self._listeners.values())
        self._publish(listeners, updated)
        return updated

    def transactional_update(
        self,
        *,
        expected_revision: int | None,
        prepare: StateChangePreparer,
        side_effect: StateSideEffect,
    ) -> AppSnapshot:
        """Promote state only after one locked side effect succeeds.

        Revision validation, change preparation, replacement validation, the
        durable side effect, and snapshot promotion all occur while holding the
        canonical-state lock. The replacement is fully constructed before the
        side effect begins. If either callback raises, no state is promoted and
        no subscriber is notified.
        """

        if not callable(prepare) or not callable(side_effect):
            raise TypeError("prepare and side_effect must be callable")
        with self._lock:
            current = self._snapshot
            self._assert_revision(current, expected_revision)
            raw_changes = prepare(current)
            if not isinstance(raw_changes, Mapping):
                raise TypeError("transaction prepare must return a mapping")
            changes = dict(raw_changes)
            updated = self._updated_snapshot(current, changes)
            side_effect(current, updated)
            self._snapshot = updated
            listeners = tuple(self._listeners.values())
        self._publish(listeners, updated)
        return updated

    def _updated_snapshot(
        self,
        current: AppSnapshot,
        changes: Mapping[str, object],
    ) -> AppSnapshot:
        prepared = dict(changes)
        unknown = set(prepared) - self._UPDATABLE_FIELDS
        if unknown:
            raise ValueError(f"unsupported state fields: {', '.join(sorted(unknown))}")
        next_revision = current.revision + 1
        if "bootloader_lock_evidence" not in prepared:
            prepared["bootloader_lock_evidence"] = ()
        else:
            raw_evidence = prepared["bootloader_lock_evidence"]
            if not isinstance(raw_evidence, (tuple, list)):
                raise TypeError("bootloader_lock_evidence must be a sequence")
            evidence_items = cast(
                tuple[object, ...] | list[object],
                raw_evidence,
            )
            if any(
                not isinstance(evidence, BootloaderLockEvidence)
                for evidence in evidence_items
            ):
                raise TypeError(
                    "bootloader_lock_evidence must contain BootloaderLockEvidence values"
                )
            evidence_values = tuple(
                evidence
                for evidence in evidence_items
                if isinstance(evidence, BootloaderLockEvidence)
            )
            if any(
                evidence.snapshot_revision != next_revision
                for evidence in evidence_values
            ):
                raise ValueError(
                    "bootloader lock evidence must bind to the resulting snapshot revision"
                )
            prepared["bootloader_lock_evidence"] = evidence_values
        return replace(current, revision=next_revision, **prepared)

    def reconcile_devices(
        self,
        devices: Sequence[DeviceInfo],
        *,
        expected_revision: int | None = None,
    ) -> AppSnapshot:
        """Atomically apply an inventory and repair the multi-selection.

        This path is intentionally idempotent: an unchanged hotplug scan does
        not consume a revision or wake presentation subscribers.
        """

        inventory = canonicalize_device_inventory(devices)
        with self._lock:
            current = self._snapshot
            self._assert_revision(current, expected_revision)
            selected, primary = reconcile_device_selection(
                inventory,
                current.selected_serials,
                current.selected_serial,
            )
            if (
                inventory == current.devices
                and selected == current.selected_serials
                and primary == current.selected_serial
            ):
                return current
            updated = replace(
                current,
                revision=current.revision + 1,
                devices=inventory,
                selected_serials=selected,
                selected_serial=primary,
                bootloader_lock_evidence=(),
            )
            self._snapshot = updated
            listeners = tuple(self._listeners.values())
        self._publish(listeners, updated)
        return updated

    def begin_operation(
        self,
        operation_id: str,
        *,
        expected_revision: int,
        kind: str = "",
        label: str = "",
        target_serial: str | None = None,
    ) -> AppSnapshot:
        with self._lock:
            current = self._snapshot
            self._assert_revision(current, expected_revision)
            if current.active_operation is not None:
                raise ValueError(f"operation already active: {operation_id}")
            updated = replace(
                current,
                revision=current.revision + 1,
                active_operation=ActiveOperation(
                    operation_id,
                    kind,
                    label,
                    target_serial,
                ),
                bootloader_lock_evidence=(
                    current.bootloader_lock_evidence
                    if kind == "device.bootloader.lock"
                    else ()
                ),
            )
            self._snapshot = updated
            listeners = tuple(self._listeners.values())
        self._publish(listeners, updated)
        return updated

    def complete_operation(
        self,
        result: OperationResult,
        *,
        expected_revision: int | None = None,
        firmware: FirmwareInfo | None = None,
        boot: BootInfo | None = None,
    ) -> AppSnapshot:
        """Atomically close an operation and promote verified canonical state."""

        if firmware is not None and not isinstance(firmware, FirmwareInfo):
            raise TypeError("firmware must be FirmwareInfo or null")
        if boot is not None and not isinstance(boot, BootInfo):
            raise TypeError("boot must be BootInfo or null")
        if (firmware is not None or boot is not None) and not result.ok:
            raise ValueError("canonical state can be promoted only by a successful operation")
        with self._lock:
            current = self._snapshot
            self._assert_revision(current, expected_revision)
            active = current.active_operation
            if (firmware is not None or boot is not None) and (
                active is None or active.operation_id != result.operation_id
            ):
                raise ValueError(
                    "verified canonical state must belong to the active operation"
                )
            if active is not None and active.operation_id == result.operation_id:
                active = None
            changes: dict[str, object] = {
                "revision": current.revision + 1,
                "active_operation": active,
                "last_result": result,
                "bootloader_lock_evidence": (),
            }
            if boot is not None:
                changes["boot"] = boot
            if firmware is not None:
                changes["firmware"] = firmware
            updated = replace(
                current,
                **changes,
            )
            self._snapshot = updated
            listeners = tuple(self._listeners.values())
        self._publish(listeners, updated)
        return updated

    @staticmethod
    def _assert_revision(snapshot: AppSnapshot, expected_revision: int | None) -> None:
        if expected_revision is not None and snapshot.revision != expected_revision:
            raise StaleRevisionError(expected_revision, snapshot.revision)

    @staticmethod
    def _publish(listeners: tuple[StateListener, ...], snapshot: AppSnapshot) -> None:
        for listener in listeners:
            try:
                listener(snapshot)
            except Exception:
                # One presentation subscriber must not corrupt canonical state or
                # prevent other subscribers from observing the revision.
                continue
