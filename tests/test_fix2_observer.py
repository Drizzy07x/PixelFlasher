from __future__ import annotations

import hashlib
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

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
from pixelflasher_core.contracts import OperationPlan, OperationPostcondition, ProcessRequest
from pixelflasher_core.firmware import FirmwareInspector
from pixelflasher_core.observer import ObservationStatus
from tests.test_production_postcondition_observer import (
    FakeTime,
    StatefulDeviceTransport,
)
from tests.test_production_postcondition_observer import observer as production_observer

SERIAL = "ABCDEF123456"
# Exactly how Google names the inner archive of a Pixel factory package.
FACTORY_BUILD = "ap4a.241205.013"
DEVICE_BUILD = "AP4A.241205.013"


def factory_firmware(root: Path) -> FirmwareInfo:
    """Derive the firmware metadata from a realistically named factory zip."""

    inner = root / f"image-raven-{FACTORY_BUILD}.zip"
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("boot.img", b"boot")
        archive.writestr("init_boot.img", b"init_boot")
    package = root / f"raven-{FACTORY_BUILD}-factory-1dea0f70.zip"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("flash-all.sh", "#!/bin/sh\n")
        archive.writestr("flash-all.bat", "@echo off\n")
        archive.writestr(f"raven-{FACTORY_BUILD}/{inner.name}", inner.read_bytes())
    inspection = FirmwareInspector().inspect(package)
    assert inspection.ok, inspection.message
    return inspection.to_firmware_info(processed=True)


def compile_factory_flash(root: Path, *, no_reboot: bool) -> OperationPlan:
    firmware = factory_firmware(root)
    partitions = ("boot", "init_boot")
    repository = ProcessedArtifactRepository()
    artifacts = []
    for partition in partitions:
        image = root / f"{partition}.img"
        image.write_bytes(partition.encode("ascii"))
        artifacts.append(
            FileArtifact(
                str(image.resolve()),
                hashlib.sha256(image.read_bytes()).hexdigest(),
                f"partition:{partition}",
            )
        )
    repository.register(tuple(artifacts), firmware_hash=firmware.hash)
    snapshot = AppSnapshot(
        devices=(
            DeviceInfo(
                SERIAL,
                codename="raven",
                mode="fastboot",
                online=True,
                bootloader="unlocked",
            ),
        ),
        selected_serial=SERIAL,
        firmware=firmware,
        boot=BootInfo(),
        plan=FlashPlan(
            "factory",
            {"verify": True, "noReboot": no_reboot},
            revision=0,
            fingerprint="fix2-observer",
            dry_run=False,
        ),
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


class FlashedBuildCaseTests(unittest.TestCase):
    """The two spellings of one build must not fail a healthy flash."""

    def test_inspector_derived_build_matches_the_uppercase_device_property(self) -> None:
        with TemporaryDirectory() as directory:
            plan = compile_factory_flash(Path(directory), no_reboot=False)
            spec = OperationRunner()._postcondition_spec(plan)
            # The expectation comes from the zip name, never from a constant.
            self.assertEqual(FACTORY_BUILD, spec.flashed_build)
            transport = StatefulDeviceTransport(
                mode="adb",
                properties={"ro.build.id": DEVICE_BUILD},
            )

            result = production_observer(transport, timer=FakeTime()).verify(spec)

            self.assertEqual(ObservationStatus.VERIFIED, result.status)
            self.assertEqual({}, dict(result.mismatches))

    def test_a_genuinely_different_build_still_fails_the_flash(self) -> None:
        with TemporaryDirectory() as directory:
            plan = compile_factory_flash(Path(directory), no_reboot=False)
            spec = OperationRunner()._postcondition_spec(plan)
            transport = StatefulDeviceTransport(
                mode="adb",
                properties={"ro.build.id": "AP3A.241005.015"},
            )

            result = production_observer(transport, timer=FakeTime()).verify(spec)

            self.assertEqual(ObservationStatus.MISMATCH, result.status)
            self.assertEqual(
                (FACTORY_BUILD, "AP3A.241005.015"),
                result.mismatches["flashed_build"],
            )


class FlashTerminalModeTests(unittest.TestCase):
    """A flash that stays in the bootloader must prove it stayed there."""

    def test_a_no_reboot_flash_binds_the_bootloader_it_promises(self) -> None:
        with TemporaryDirectory() as directory:
            plan = compile_factory_flash(Path(directory), no_reboot=True)
            spec = OperationRunner()._postcondition_spec(plan)

            self.assertEqual("fastboot", spec.expected_mode)

    def test_a_no_reboot_flash_is_not_verified_by_any_live_session(self) -> None:
        with TemporaryDirectory() as directory:
            plan = compile_factory_flash(Path(directory), no_reboot=True)
            spec = OperationRunner()._postcondition_spec(plan)
            transport = StatefulDeviceTransport(
                mode="adb",
                properties={"ro.build.id": DEVICE_BUILD},
            )

            result = production_observer(transport, timer=FakeTime()).verify(spec)

            self.assertEqual(ObservationStatus.MISMATCH, result.status)
            self.assertEqual(("fastboot", "adb"), result.mismatches["mode"])

    def test_a_no_reboot_flash_is_verified_from_that_bootloader(self) -> None:
        with TemporaryDirectory() as directory:
            plan = compile_factory_flash(Path(directory), no_reboot=True)
            spec = OperationRunner()._postcondition_spec(plan)
            transport = StatefulDeviceTransport(mode="fastboot", fetch_supported=False)

            result = production_observer(transport, timer=FakeTime()).verify(spec)

            self.assertEqual(ObservationStatus.VERIFIED, result.status)

    def test_a_rebooting_flash_binds_no_mode_on_purpose(self) -> None:
        with TemporaryDirectory() as directory:
            plan = compile_factory_flash(Path(directory), no_reboot=False)
            spec = OperationRunner()._postcondition_spec(plan)

            # Binding "adb" here would fail every boot slower than the
            # observation budget, so only the build is compared.
            self.assertIsNone(spec.expected_mode)
            self.assertEqual(FACTORY_BUILD, spec.flashed_build)

    def test_terminal_mode_follows_the_last_transition_the_plan_emits(self) -> None:
        runner = OperationRunner()
        cases = (
            ((("FASTBOOT", "-s", SERIAL, "flash", "boot", "boot.img"),), "fastboot", "fastboot"),
            ((("FASTBOOT", "-s", SERIAL, "flash", "boot", "boot.img"),), "fastbootd", "fastbootd"),
            (
                (
                    ("FASTBOOT", "-s", SERIAL, "reboot", "fastboot"),
                    ("FASTBOOT", "-s", SERIAL, "wait-for-device"),
                    ("FASTBOOT", "-s", SERIAL, "flash", "system", "system.img"),
                ),
                "fastboot",
                "fastbootd",
            ),
            (
                (
                    ("FASTBOOT", "-s", SERIAL, "flash", "bootloader", "bootloader.img"),
                    ("FASTBOOT", "-s", SERIAL, "reboot-bootloader"),
                ),
                "fastbootd",
                "fastboot",
            ),
            ((("FASTBOOT", "-s", SERIAL, "reboot"),), "fastboot", None),
            ((("FASTBOOT", "-s", SERIAL, "boot", "patched.img"),), "fastboot", None),
        )
        for argvs, start, expected in cases:
            with self.subTest(argvs=argvs, start=start):
                plan = OperationPlan(
                    requests=tuple(ProcessRequest(argv) for argv in argvs),
                    target_serial=SERIAL,
                    expected_device_state=start,
                )
                self.assertEqual(expected, runner._flash_terminal_mode(plan))

    def test_a_flashed_boot_partition_is_not_read_as_a_live_boot(self) -> None:
        plan = OperationPlan(
            requests=(ProcessRequest(("FASTBOOT", "-s", SERIAL, "flash", "boot", "boot.img")),),
            target_serial=SERIAL,
            expected_device_state="fastboot",
            postconditions=(
                OperationPostcondition("flash_applied", {"partitions": ("boot",)}),
            ),
        )

        self.assertEqual("fastboot", OperationRunner()._flash_terminal_mode(plan))


if __name__ == "__main__":
    unittest.main()
