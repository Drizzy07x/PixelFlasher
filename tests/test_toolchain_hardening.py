import stat
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from pixelflasher_core.executor import FakeProcessTransport, TransportOutcome
from pixelflasher_core.toolchain import ToolchainService


def write_tool_pair(directory: Path) -> tuple[Path, Path]:
    adb = directory / "adb.exe"
    fastboot = directory / "fastboot.exe"
    adb.write_bytes(b"")
    fastboot.write_bytes(b"")
    adb.chmod(adb.stat().st_mode | stat.S_IXUSR)
    fastboot.chmod(fastboot.stat().st_mode | stat.S_IXUSR)
    return adb.resolve(), fastboot.resolve()


class ToolchainHardeningTests(TestCase):
    def test_path_discovery_rejects_tools_from_different_directories(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            adb_root = root / "adb-tools"
            fastboot_root = root / "fastboot-tools"
            adb_root.mkdir()
            fastboot_root.mkdir()
            adb, _unused_fastboot = write_tool_pair(adb_root)
            _unused_adb, fastboot = write_tool_pair(fastboot_root)
            transport = FakeProcessTransport([])

            with patch(
                "pixelflasher_core.toolchain.shutil.which",
                side_effect=lambda name: str(adb if name == "adb" else fastboot),
            ):
                check = ToolchainService(transport).discover()

            self.assertFalse(check.ok)
            self.assertEqual("toolchain_directory_mismatch", check.code)
            self.assertEqual([], transport.calls)

    def test_exit_zero_with_unrelated_semver_is_not_version_evidence(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            write_tool_pair(root)
            transport = FakeProcessTransport([TransportOutcome(0, "unrelated 36.0.0")])

            check = ToolchainService(transport).discover(root)

            self.assertFalse(check.ok)
            self.assertEqual("tool_version_unverified", check.code)
