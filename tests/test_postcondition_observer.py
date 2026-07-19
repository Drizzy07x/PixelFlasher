import unittest

from pixelflasher_core.executor import CancellationToken
from pixelflasher_core.observer import (
    DeviceObservation,
    ObservationStatus,
    PostconditionObserver,
    PostconditionSpec,
)


class FakeTime:
    def __init__(self) -> None:
        self.now = 0.0

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class SequenceProbe:
    def __init__(self, values):
        self.values = list(values)
        self.calls = []

    def observe(self, serial):
        self.calls.append(serial)
        if not self.values:
            return None
        if len(self.values) == 1:
            return self.values[0]
        return self.values.pop(0)


class PostconditionObserverTests(unittest.TestCase):
    def observer(self, probe, timer):
        return PostconditionObserver(
            probe,
            poll_interval_seconds=1,
            clock=timer.clock,
            sleeper=timer.sleep,
        )

    def test_transitional_states_are_polled_until_all_evidence_matches(self):
        timer = FakeTime()
        probe = SequenceProbe(
            [
                None,
                DeviceObservation("SERIAL", mode="fastboot", slot="a"),
                DeviceObservation(
                    "SERIAL",
                    mode="adb",
                    slot="b",
                    bootloader="unlocked",
                    boot_completed=True,
                    safe_mode=True,
                    build="BP2A",
                    remote_hashes={"/sdcard/file": "ABCD"},
                    partition_hashes={"boot_b": "1234"},
                ),
            ]
        )
        result = self.observer(probe, timer).verify(
            PostconditionSpec(
                "SERIAL",
                5,
                expected_mode="adb",
                expected_slot="b",
                expected_bootloader="unlocked",
                expected_boot_completed=True,
                expected_safe_mode=True,
                expected_build="BP2A",
                remote_hashes={"/sdcard/file": "abcd"},
                partition_hashes={"boot_b": "1234"},
            )
        )

        self.assertEqual(ObservationStatus.VERIFIED, result.status)
        self.assertEqual(3, result.attempts)
        self.assertEqual(["SERIAL"] * 3, probe.calls)

    def test_safe_mode_evidence_is_typed_and_fails_closed(self):
        verified_timer = FakeTime()
        verified = self.observer(
            SequenceProbe(
                [
                    DeviceObservation(
                        "SERIAL",
                        mode="adb",
                        boot_completed=True,
                        safe_mode=True,
                    )
                ]
            ),
            verified_timer,
        ).verify(
            PostconditionSpec(
                "SERIAL",
                1,
                expected_mode="adb",
                expected_boot_completed=True,
                expected_safe_mode=True,
            )
        )
        self.assertEqual(ObservationStatus.VERIFIED, verified.status)

        mismatch_timer = FakeTime()
        mismatch = self.observer(
            SequenceProbe([DeviceObservation("SERIAL", mode="adb", safe_mode=False)]),
            mismatch_timer,
        ).verify(PostconditionSpec("SERIAL", 1, expected_safe_mode=True))
        self.assertEqual(ObservationStatus.MISMATCH, mismatch.status)
        self.assertEqual((True, False), mismatch.mismatches["safe_mode"])

        missing_timer = FakeTime()
        missing = self.observer(
            SequenceProbe([DeviceObservation("SERIAL", mode="adb")]),
            missing_timer,
        ).verify(PostconditionSpec("SERIAL", 1, expected_safe_mode=True))
        self.assertEqual(ObservationStatus.UNVERIFIED, missing.status)
        self.assertEqual(("safe_mode",), missing.missing)

        with self.assertRaises(TypeError):
            PostconditionSpec("SERIAL", 1, expected_safe_mode=1)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            DeviceObservation("SERIAL", safe_mode=1)  # type: ignore[arg-type]

    def test_deadline_distinguishes_mismatch_from_missing_evidence(self):
        mismatch_timer = FakeTime()
        mismatch = self.observer(
            SequenceProbe([DeviceObservation("SERIAL", mode="adb", slot="a")]),
            mismatch_timer,
        ).verify(PostconditionSpec("SERIAL", 2, expected_mode="fastboot", expected_slot="b"))
        self.assertEqual(ObservationStatus.MISMATCH, mismatch.status)
        self.assertEqual("postcondition_mismatch", mismatch.code)
        self.assertEqual(("fastboot", "adb"), mismatch.mismatches["mode"])

        missing_timer = FakeTime()
        missing = self.observer(
            SequenceProbe([DeviceObservation("SERIAL", mode="fastboot")]),
            missing_timer,
        ).verify(PostconditionSpec("SERIAL", 2, expected_mode="fastboot", expected_slot="b"))
        self.assertEqual(ObservationStatus.UNVERIFIED, missing.status)
        self.assertEqual(("slot",), missing.missing)

    def test_cancelled_observation_is_explicit_and_never_reports_success(self):
        timer = FakeTime()
        token = CancellationToken()
        token.cancel()
        result = self.observer(SequenceProbe([]), timer).verify(
            PostconditionSpec("SERIAL", 5, expected_mode="adb"),
            token,
        )

        self.assertEqual(ObservationStatus.CANCELLED, result.status)
        self.assertEqual("postcondition_cancelled", result.code)
        self.assertEqual(0, result.attempts)


if __name__ == "__main__":
    unittest.main()
