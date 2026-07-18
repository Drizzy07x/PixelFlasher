"""Thread-safe canonical application state store."""

from __future__ import annotations

from dataclasses import replace
from threading import RLock
from typing import Callable
from uuid import uuid4

from .contracts import (
    ActiveOperation,
    AppSnapshot,
    BootloaderLockEvidence,
    BootInfo,
    DeviceInfo,
    FirmwareInfo,
    FlashPlan,
    OperationResult,
    ToolchainInfo,
)


StateListener = Callable[[AppSnapshot], None]


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

    def __enter__(self) -> "Subscription":
        return self

    def __exit__(self, *_args) -> None:
        self.cancel()


class AppStateStore:
    """Owns the single revisioned snapshot and publishes immutable replacements."""

    _UPDATABLE_FIELDS = frozenset(
        {
            "devices",
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

    def update(self, *, expected_revision: int | None = None, **changes) -> AppSnapshot:
        unknown = set(changes) - self._UPDATABLE_FIELDS
        if unknown:
            raise ValueError(f"unsupported state fields: {', '.join(sorted(unknown))}")
        with self._lock:
            current = self._snapshot
            self._assert_revision(current, expected_revision)
            next_revision = current.revision + 1
            if "bootloader_lock_evidence" not in changes:
                changes["bootloader_lock_evidence"] = ()
            else:
                evidence_values = tuple(changes["bootloader_lock_evidence"])
                if any(
                    not isinstance(evidence, BootloaderLockEvidence)
                    for evidence in evidence_values
                ):
                    raise TypeError(
                        "bootloader_lock_evidence must contain BootloaderLockEvidence values"
                    )
                if any(
                    evidence.snapshot_revision != next_revision
                    for evidence in evidence_values
                ):
                    raise ValueError(
                        "bootloader lock evidence must bind to the resulting snapshot revision"
                    )
                changes["bootloader_lock_evidence"] = evidence_values
            updated = replace(current, revision=next_revision, **changes)
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
    ) -> AppSnapshot:
        with self._lock:
            current = self._snapshot
            self._assert_revision(current, expected_revision)
            if current.active_operation is not None:
                raise ValueError(f"operation already active: {operation_id}")
            updated = replace(
                current,
                revision=current.revision + 1,
                active_operation=ActiveOperation(operation_id, kind, label),
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
            changes = {
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
