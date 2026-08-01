from __future__ import annotations

import hashlib
import subprocess
import sys
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    BootInfo,
    DeviceInfo,
    FileArtifact,
    FirmwareInfo,
    FlashPlan,
    OperationPlanner,
    OperationRunner,
    ProcessedArtifactRepository,
    ToolchainInfo,
)
from pixelflasher_core.contracts import OperationPlan, ProcessRequest
from pixelflasher_core.executor import CancellationToken, SubprocessTransport
from pixelflasher_core.observer import ObservationStatus
from pixelflasher_core.operation_runner import OperationRunner as Runner
from pixelflasher_core.operation_runner import _ArtifactStageError
from tests.test_production_postcondition_observer import (
    FakeTime,
    StatefulDeviceTransport,
)
from tests.test_production_postcondition_observer import observer as production_observer

SERIAL = "ABCDEF123456"
BUILD = "AP4A.250105.002"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compile_factory_flash(root: Path, *, partitions: tuple[str, ...] = ("boot", "init_boot")) -> OperationPlan:
    """Compile the plan the flash wizard actually produces for a factory image."""

    package = root / "factory.zip"
    package.write_bytes(b"factory")
    firmware = FirmwareInfo(str(package), "factory", BUILD, digest(package), True, True)
    repository = ProcessedArtifactRepository()
    repository.register(
        tuple(
            FileArtifact(
                str((root / f"{partition}.img").resolve()),
                digest(_write(root / f"{partition}.img", partition.encode("ascii"))),
                f"partition:{partition}",
            )
            for partition in partitions
        ),
        firmware_hash=firmware.hash,
    )
    plan = FlashPlan(
        "factory",
        {"verify": True, "noReboot": False},
        revision=0,
        fingerprint="fix-observer",
        dry_run=False,
    )
    snapshot = AppSnapshot(
        devices=(
            DeviceInfo(
                SERIAL,
                codename="akita",
                mode="fastboot",
                online=True,
                bootloader="unlocked",
            ),
        ),
        selected_serial=SERIAL,
        firmware=firmware,
        boot=BootInfo(),
        plan=plan,
        toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
    )
    compilation = OperationPlanner(artifact_repository=repository).compile(
        AppCommand(
            kind="flash.execute",
            expected_revision=snapshot.revision,
            target_serial=SERIAL,
            payload={},
        ),
        snapshot,
    )
    assert compilation.ok, compilation.code
    assert compilation.plan is not None
    return compilation.plan


def _write(path: Path, content: bytes) -> Path:
    path.write_bytes(content)
    return path


class FlashPostconditionEndToEndTests(unittest.TestCase):
    """planner -> _postcondition_spec -> production observer, never tested before."""

    def test_flash_plan_is_verified_from_the_bootloader_the_flash_leaves_behind(self) -> None:
        with TemporaryDirectory() as directory:
            plan = compile_factory_flash(Path(directory))
            spec = OperationRunner()._postcondition_spec(plan)
            transport = StatefulDeviceTransport(mode="fastboot", fetch_supported=False)

            result = production_observer(transport, timer=FakeTime()).verify(spec)

            self.assertEqual(ObservationStatus.VERIFIED, result.status)
            self.assertEqual((), result.missing)

    def test_flash_plan_is_verified_from_the_system_it_booted(self) -> None:
        with TemporaryDirectory() as directory:
            plan = compile_factory_flash(Path(directory))
            spec = OperationRunner()._postcondition_spec(plan)
            transport = StatefulDeviceTransport(
                mode="adb",
                properties={"ro.build.id": BUILD},
            )

            result = production_observer(transport, timer=FakeTime()).verify(spec)

            self.assertEqual(ObservationStatus.VERIFIED, result.status)
            self.assertEqual((), result.missing)

    def test_a_system_reporting_another_build_still_fails_the_flash(self) -> None:
        with TemporaryDirectory() as directory:
            plan = compile_factory_flash(Path(directory))
            spec = OperationRunner()._postcondition_spec(plan)
            transport = StatefulDeviceTransport(
                mode="adb",
                properties={"ro.build.id": "SOMETHING.ELSE"},
            )

            result = production_observer(transport, timer=FakeTime()).verify(spec)

            self.assertEqual(ObservationStatus.MISMATCH, result.status)
            self.assertEqual((BUILD, "SOMETHING.ELSE"), result.mismatches["flashed_build"])

    def test_flash_evidence_is_bound_to_the_argv_the_plan_will_run(self) -> None:
        with TemporaryDirectory() as directory:
            plan = compile_factory_flash(Path(directory))
            spec = OperationRunner()._postcondition_spec(plan)

            # Read-back digests are neither obtainable nor sound for a firmware
            # flash, so they must not be demanded as device evidence.
            self.assertEqual({}, dict(spec.partition_hashes))
            self.assertIsNone(spec.expected_build)
            self.assertEqual(BUILD, spec.flashed_build)

            unbacked = OperationPlan(
                requests=(ProcessRequest(("fastboot", "-s", SERIAL, "reboot")),),
                target_serial=SERIAL,
                postconditions=plan.postconditions,
            )
            with self.assertRaises(ValueError):
                OperationRunner()._postcondition_spec(unbacked)


class ArtifactStagingCapacityTests(unittest.TestCase):
    def test_a_stage_smaller_than_the_firmware_fails_before_the_copy(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            image = _write(root / "super.img", b"x" * 4096)
            plan = OperationPlan(
                requests=(ProcessRequest(("fastboot", "flash", "super", str(image))),),
                target_serial=SERIAL,
                artifacts=(
                    FileArtifact(str(image), digest(image), "partition:super"),
                    FileArtifact(str(image), digest(image), "partition:super"),
                ),
            )
            copies: list[Path] = []

            def record(
                source: Path,
                destination: Path,
                expected_sha256: str,
                token: CancellationToken,
            ) -> None:
                copies.append(source)

            with (
                patch("pixelflasher_core.operation_runner.shutil.disk_usage") as usage,
                patch.object(Runner, "_copy_verified_artifact", staticmethod(record)),
            ):
                usage.return_value = type("Usage", (), {"total": 0, "used": 0, "free": 4095})()
                with self.assertRaises(_ArtifactStageError) as failure:
                    Runner._stage_artifacts(plan, CancellationToken())

            self.assertEqual("artifact_stage_no_space", failure.exception.code)
            # The requirement is measured over distinct paths, not repeated ones.
            self.assertIn("4096 bytes", str(failure.exception))
            self.assertEqual([], copies)

    def test_an_unmeasurable_volume_never_blocks_a_flash(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            image = _write(root / "boot.img", b"boot")
            plan = OperationPlan(
                requests=(ProcessRequest(("fastboot", "flash", "boot", str(image))),),
                target_serial=SERIAL,
                artifacts=(FileArtifact(str(image), digest(image), "partition:boot"),),
            )
            with patch(
                "pixelflasher_core.operation_runner.shutil.disk_usage",
                side_effect=OSError("unsupported filesystem"),
            ):
                staged_plan, stage = Runner._stage_artifacts(plan, CancellationToken())
            try:
                self.assertNotEqual(plan.requests[0].argv, staged_plan.requests[0].argv)
            finally:
                Runner._cleanup_artifact_stage(stage)

    def test_an_exhausted_volume_names_the_cause_without_leaking_a_path(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = _write(root / "boot.img", b"boot")
            destination = root / "staged.img"
            with (
                patch(
                    "pixelflasher_core.operation_runner.os.open",
                    side_effect=OSError(28, "No space left on device", str(destination)),
                ),
                self.assertRaises(_ArtifactStageError) as failure,
            ):
                Runner._copy_verified_artifact(
                    source,
                    destination,
                    digest(source),
                    CancellationToken(),
                )

            self.assertEqual("artifact_stage_no_space", failure.exception.code)
            self.assertNotIn(str(destination), str(failure.exception))

    def test_other_stage_failures_report_their_errno_symbol(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = _write(root / "boot.img", b"boot")
            with (
                patch(
                    "pixelflasher_core.operation_runner.os.open",
                    side_effect=OSError(13, "Permission denied", str(root / "staged.img")),
                ),
                self.assertRaises(_ArtifactStageError) as failure,
            ):
                Runner._copy_verified_artifact(
                    source,
                    root / "staged.img",
                    digest(source),
                    CancellationToken(),
                )

            self.assertEqual("artifact_stage_failed", failure.exception.code)
            self.assertIn("EACCES", str(failure.exception))


ABANDONED: list[subprocess.Popen[bytes]] = []


class AbandonedReaderTransport(SubprocessTransport):
    """Reproduce a child that outlives termination while still holding its pipe."""

    @classmethod
    def _stop_process(cls, process: subprocess.Popen[bytes]) -> None:
        ABANDONED.append(process)


class BoundedCaptureReaderOwnershipTests(unittest.TestCase):
    def test_a_live_reader_keeps_its_pipe_and_the_caller_still_returns(self) -> None:
        ABANDONED.clear()
        transport = AbandonedReaderTransport()
        request = ProcessRequest(
            (
                sys.executable,
                "-c",
                "import sys, time; sys.stdout.write('hello'); sys.stdout.flush(); time.sleep(30)",
            ),
            timeout_seconds=0.3,
            output_limit_bytes=1_024,
        )

        started = time.monotonic()
        outcome = transport.run(request, CancellationToken())
        elapsed = time.monotonic() - started

        self.assertEqual(1, len(ABANDONED))
        process = ABANDONED[0]
        stdout, stderr = process.stdout, process.stderr
        assert stdout is not None and stderr is not None
        try:
            self.assertTrue(outcome.timed_out)
            self.assertEqual("hello", outcome.stdout)
            self.assertLess(elapsed, 3.0)
            # The capture thread is still parked in os.read on this pipe.
            # Closing it from here is what corrupts output on POSIX and wedges
            # the engine thread on Windows.
            self.assertFalse(stdout.closed)
            self.assertFalse(stderr.closed)
        finally:
            process.kill()
            process.wait(timeout=5)

    def test_a_finished_reader_still_has_its_pipe_released(self) -> None:
        transport = SubprocessTransport()
        request = ProcessRequest(
            (sys.executable, "-c", "import sys; sys.stdout.write('done')"),
            timeout_seconds=10.0,
            output_limit_bytes=1_024,
        )

        outcome = transport.run(request, CancellationToken())

        self.assertEqual(0, outcome.returncode)
        self.assertEqual("done", outcome.stdout)
        self.assertFalse(outcome.timed_out)


if __name__ == "__main__":
    unittest.main()
