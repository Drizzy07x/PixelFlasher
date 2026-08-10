"""A patch target is decided by the ramdisk it carries, not by its name.

Every supported provider rewrites a ramdisk: Magisk patches it directly and the
KernelSU-family patchers install their LKM into it. A device with an init_boot
partition ships a kernel-only boot image, so requiring the partition to be named
"boot" aims every LKM patcher at an image with nothing to patch.

Measured on a Pixel 9 Pro XL factory image, CP2A.260705.006:

    boot.img       header v4  kernel 16606832  ramdisk        0
    init_boot.img  header v4  kernel        0  ramdisk  2670961

Patching that kernel-only boot.img with KernelSU-Next succeeded, produced a
397861-byte ramdisk inside a partition whose ramdisk the bootloader never loads,
flashed cleanly, and booted with no root present.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from pixelflasher_core.boot_patch import BootPatchPlanningError, _ramdisk_bytes
from tests.test_boot_patch_service import BootPatchServiceTests


def boot_image(*, kernel: int, ramdisk: int, version: int = 4) -> bytes:
    """A boot image header carrying the declared sizes, padded to one page."""

    header = bytearray(4096)
    header[0:8] = b"ANDROID!"
    header[8:12] = kernel.to_bytes(4, "little")
    if version >= 3:
        header[12:16] = ramdisk.to_bytes(4, "little")
    else:
        header[16:20] = ramdisk.to_bytes(4, "little")
    header[40:44] = version.to_bytes(4, "little")
    return bytes(header)


class RamdiskHeaderTests(unittest.TestCase):
    def test_reads_the_ramdisk_size_of_a_v4_header(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "init_boot.img"
            path.write_bytes(boot_image(kernel=0, ramdisk=2670961))
            self.assertEqual(2670961, _ramdisk_bytes(path))

    def test_reads_the_ramdisk_size_of_a_legacy_header(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "boot.img"
            path.write_bytes(boot_image(kernel=100, ramdisk=200, version=2))
            self.assertEqual(200, _ramdisk_bytes(path))

    def test_reports_a_kernel_only_image_as_carrying_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "boot.img"
            path.write_bytes(boot_image(kernel=16606832, ramdisk=0))
            self.assertEqual(0, _ramdisk_bytes(path))

    def test_declines_to_judge_a_payload_that_is_not_a_boot_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "boot.img"
            path.write_bytes(b"not a boot image at all")
            self.assertIsNone(_ramdisk_bytes(path))

    def test_declines_to_judge_a_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertIsNone(_ramdisk_bytes(Path(directory) / "absent.img"))


class RamdiskPatchRuleTests(unittest.TestCase):
    # Borrow the service/snapshot builders without inheriting the suite they
    # belong to, which would re-run every BootPatchService test under this name.
    builders = BootPatchServiceTests("test_runner_selection_is_exactly_bound_to_architecture_and_kmi")

    def compile_for(self, root: Path, flavor: str, image: bytes, partition: str):
        boot = root / f"{partition}.img"
        boot.write_bytes(image)
        service, app, _, _ = self.builders.make_service(root, flavor)
        return service.compile(
            self.builders.command(flavor, app.id, root / "patched.img"),
            self.builders.make_snapshot(boot, partition=partition),
        )

    def test_a_kernel_only_boot_image_is_refused_for_every_flavor(self) -> None:
        for flavor in ("magisk", "kernelsu", "kernelsu-next", "sukisu", "wild-ksu"):
            with self.subTest(flavor=flavor), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(BootPatchPlanningError) as raised:
                    self.compile_for(
                        Path(directory),
                        flavor,
                        boot_image(kernel=16606832, ramdisk=0),
                        "boot",
                    )
                self.assertEqual("boot_image_has_no_ramdisk", raised.exception.code)

    def test_an_init_boot_image_with_a_ramdisk_is_accepted_by_every_flavor(self) -> None:
        for flavor in ("magisk", "kernelsu", "kernelsu-next", "sukisu", "wild-ksu"):
            with self.subTest(flavor=flavor), tempfile.TemporaryDirectory() as directory:
                compilation = self.compile_for(
                    Path(directory),
                    flavor,
                    boot_image(kernel=0, ramdisk=2670961),
                    "init_boot",
                )
                self.assertEqual(("init_boot",), compilation.plan.partitions)

    def test_a_boot_image_that_still_carries_its_ramdisk_is_accepted(self) -> None:
        # Devices without an init_boot partition keep both in boot.
        with tempfile.TemporaryDirectory() as directory:
            compilation = self.compile_for(
                Path(directory),
                "kernelsu",
                boot_image(kernel=16606832, ramdisk=2670961),
                "boot",
            )
            self.assertEqual(("boot",), compilation.plan.partitions)


if __name__ == "__main__":
    unittest.main()
