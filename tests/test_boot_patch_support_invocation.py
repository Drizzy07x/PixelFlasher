"""The pushed support binary must be invocable as the BusyBox multiplexer.

`pf_boot_patch.sh` re-enters through the pinned BusyBox ash so provider scripts
get one deterministic shell. BusyBox resolves its applet from the basename of
argv[0] and only acts as a multiplexer when that basename is a known applet
name, so a content-addressed basename makes the re-entry die with
"applet not found" and exit 127 before anything is patched.

Observed on a Pixel 9 Pro XL: identical binary, identical arguments.

    /data/local/tmp/pf-patch-support-00-deadbeef ash -c 'echo HOLA'
        -> pf-patch-support-00-deadbeef: applet not found      exit 127
    /data/local/tmp/busybox ash -c 'echo HOLA'
        -> HOLA                                                exit 0

The existing service tests register bundles with no support artifacts at all, so
none of them ever compiles the request that carries this path.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from posixpath import basename

from pixelflasher_core.boot_patch import BootPatchService, PatchToolBundle
from pixelflasher_core.contracts import (
    AppCommand,
    AppSnapshot,
    BootInfo,
    DeviceInfo,
    FileArtifact,
    ModernPreferences,
    ToolchainInfo,
)
from pixelflasher_core.rooting import RootAppSource, RootingService
from tests.apk_test_helpers import FakeVerifiedApkInspector
from tests.test_boot_patch_service import PROVIDERS, sha256, write_apk

FLAVOR = "kernelsu-next"
SUPPORT_PREFIX = "/data/local/tmp/pf-patch-support-"


class SupportBinaryInvocationTests(unittest.TestCase):
    def compile_plan(self, root: Path):
        apk = root / f"{FLAVOR}.apk"
        apk_bytes = write_apk(apk, PROVIDERS[FLAVOR])
        rooting = RootingService(
            (
                RootAppSource(
                    str(apk),
                    PROVIDERS[FLAVOR],
                    "stable",
                    "1.0",
                    "official",
                    sha256(apk_bytes),
                    architecture="universal",
                ),
            ),
            hash_chunk_size=2,
            apk_inspector=FakeVerifiedApkInspector(),
        )
        app = rooting.root_app_inventory()[0]

        runner = root / "runner"
        runner.write_bytes(b"runner")
        support = root / "busybox_arm64-v8a"
        support.write_bytes(b"busybox multiplexer stand-in")

        bundle = PatchToolBundle(
            FLAVOR,
            app.id,
            FileArtifact(str(runner.resolve()), sha256(runner.read_bytes()), f"patch-runner:{FLAVOR}"),
            support_artifacts=(
                FileArtifact(
                    str(support.resolve()),
                    sha256(support.read_bytes()),
                    "patch-support:busybox",
                ),
            ),
        )
        service = BootPatchService(rooting, (bundle,), hash_chunk_size=2)

        boot = root / "boot.img"
        boot.write_bytes(b"stock boot image")
        snapshot = AppSnapshot(
            revision=5,
            devices=(DeviceInfo("SERIAL", codename="akita", mode="adb", online=True),),
            selected_serial="SERIAL",
            boot=BootInfo("stock", str(boot), sha256(boot.read_bytes()), "boot", False),
            preferences=ModernPreferences(),
            toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
        )
        command = AppCommand(
            "boot.patch",
            expected_revision=5,
            target_serial="SERIAL",
            payload={
                "flavor": FLAVOR,
                "appId": app.id,
                "destination": str(root / "patched.img"),
            },
            operation_id="patch-operation",
        )
        return service.compile(command, snapshot), support

    @staticmethod
    def support_paths(compilation) -> tuple[str, ...]:
        for request in compilation.plan.requests:
            if "--support" in request.argv:
                return tuple(
                    request.argv[index + 1]
                    for index, item in enumerate(request.argv)
                    if item == "--support" and index + 1 < len(request.argv)
                )
        return ()

    def test_support_binary_is_pushed_under_the_busybox_applet_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            compilation, _support = self.compile_plan(Path(directory))
            paths = self.support_paths(compilation)
            self.assertEqual(1, len(paths))
            self.assertEqual(
                "busybox",
                basename(paths[0]),
                "BusyBox resolves its applet from argv[0]; any other basename exits 127",
            )

    def test_support_path_stays_content_addressed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            compilation, support = self.compile_plan(Path(directory))
            path = self.support_paths(compilation)[0]
            # The runner refuses any support path outside this prefix.
            self.assertTrue(path.startswith(SUPPORT_PREFIX), path)
            self.assertIn(sha256(support.read_bytes())[:16], path)

    def test_support_binary_is_pushed_to_the_path_the_runner_receives(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            compilation, support = self.compile_plan(Path(directory))
            declared = self.support_paths(compilation)[0]
            pushed = [
                request.argv
                for request in compilation.plan.requests
                if len(request.argv) >= 6 and request.argv[3] == "push"
                and request.argv[4] == str(support.resolve())
            ]
            self.assertEqual(1, len(pushed))
            self.assertEqual(declared, pushed[0][5])

    def test_cleanup_reaches_the_pushed_support_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            compilation, _support = self.compile_plan(Path(directory))
            cleanup = compilation.plan.requests[-1].argv
            self.assertIn("rm", cleanup)
            path = self.support_paths(compilation)[0]
            parent = path.rsplit("/", 1)[0]
            self.assertIn(parent, cleanup, f"cleanup must remove the support directory: {cleanup}")
            self.assertIn("-rf", cleanup, "a directory needs a recursive removal")


if __name__ == "__main__":
    unittest.main()
