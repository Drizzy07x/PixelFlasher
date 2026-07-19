"""Stateful process-boundary fake for active-slot postcondition tests.

Unlike an argv recorder, this fake keeps a separate device-side slot value.
The mutation request may succeed without changing that value, allowing tests
to prove that a zero fastboot exit code is not treated as postcondition proof.
"""

from __future__ import annotations

from pixelflasher_core.contracts import ProcessRequest, ToolchainInfo
from pixelflasher_core.devices import DeviceService
from pixelflasher_core.executor import CancellationToken, TransportOutcome
from pixelflasher_core.observer import (
    PostconditionObserver,
    ProcessDeviceObservationProbe,
)


class DeterministicClock:
    def __init__(self) -> None:
        self.now = 0.0

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class StatefulSlotTransport:
    """Model one fastboot device and its independently observable slot."""

    def __init__(
        self,
        serial: str,
        *,
        active_slot: str = "a",
        switch_applies: bool = True,
        slot_evidence_available: bool = True,
        reconnect_cycles: int = 0,
    ) -> None:
        if active_slot not in {"a", "b"}:
            raise ValueError("active_slot must be a or b")
        if reconnect_cycles < 0:
            raise ValueError("reconnect_cycles cannot be negative")
        self.serial = serial
        self.active_slot = active_slot
        self.switch_applies = switch_applies
        self.slot_evidence_available = slot_evidence_available
        self.reconnect_cycles = reconnect_cycles
        self._fastboot_absence_responses = 0
        self.calls: list[ProcessRequest] = []

    def run(
        self,
        request: ProcessRequest,
        cancellation: CancellationToken,
    ) -> TransportOutcome:
        self.calls.append(request)
        if cancellation.cancelled:
            return TransportOutcome(None, cancelled=True)
        argv = request.argv
        if len(argv) < 4 or argv[1:3] != ("-s", self.serial):
            return TransportOutcome(1, stderr="serial mismatch")
        if argv[0] == "ADB":
            return TransportOutcome(
                1,
                stderr=f"error: device '{self.serial}' not found",
            )
        if argv[0] != "FASTBOOT":
            return TransportOutcome(1, stderr="unexpected executable")

        if len(argv) == 4 and argv[3].startswith("--set-active="):
            target = argv[3].partition("=")[2]
            if target not in {"a", "b"}:
                return TransportOutcome(1, stderr="invalid slot")
            if self.switch_applies:
                self.active_slot = target
            # Each observation cycle probes is-userspace and then product.
            # Failing both simulates the bounded disconnect/reconnect window.
            self._fastboot_absence_responses = self.reconnect_cycles * 2
            return TransportOutcome(0, stderr=f"Setting current slot to '{target}'\nOKAY\n")

        if self._fastboot_absence_responses:
            self._fastboot_absence_responses -= 1
            return TransportOutcome(
                1,
                stderr=f"fastboot: error: device '{self.serial}' not found",
            )
        if argv[3:] == ("getvar", "is-userspace"):
            return TransportOutcome(0, stderr="(bootloader) is-userspace: no\n")
        if argv[3:] == ("getvar", "product"):
            return TransportOutcome(0, stderr="(bootloader) product: akita\n")
        if argv[3:] == ("getvar", "current-slot"):
            if not self.slot_evidence_available:
                return TransportOutcome(1, stderr="FAILED (remote: variable unavailable)\n")
            return TransportOutcome(
                0,
                stderr=f"(bootloader) current-slot: {self.active_slot}\n",
            )
        return TransportOutcome(1, stderr="unexpected fastboot request")


def make_slot_observer(
    transport: StatefulSlotTransport,
    *,
    clock: DeterministicClock | None = None,
) -> PostconditionObserver:
    timer = clock or DeterministicClock()
    toolchain = ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True)
    probe = ProcessDeviceObservationProbe(
        DeviceService(transport),
        lambda: toolchain,
        command_timeout_seconds=0.1,
    )
    return PostconditionObserver(
        probe,
        poll_interval_seconds=0.05,
        clock=timer.clock,
        sleeper=timer.sleep,
    )
