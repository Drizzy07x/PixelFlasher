import contextlib
import io
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from phone import Device
from runtime import run_shell, run_shell2

PF_MODULES_SOURCE = Path("pf_modules.py")
PHONE_SOURCE = Path("phone.py")
MAIN_SOURCE = Path("Main.py")


class PhoneExecutionPathTests(unittest.TestCase):
    def test_switch_slot_continues_after_adb_reboot_to_bootloader(self):
        device = Device("ABC123", "adb", "adb")
        device.props.upsert("current-slot", "a")
        device.props.upsert("bootloader_current-slot", "a")

        states = iter(("adb", "fastboot"))
        device.get_device_state = lambda: next(states)
        device.reboot_bootloader = lambda: 0
        device.refresh_phone_mode = lambda: setattr(device, "mode", "f.b")
        device.clear_device_selection = lambda: None

        with (
            patch("phone.get_adb", return_value="adb"),
            patch("phone.get_fastboot", return_value="fastboot"),
            patch("phone.update_phones"),
            patch("phone.run_shell", return_value=subprocess.CompletedProcess(args="", returncode=0, stdout="", stderr="")) as run_shell,
        ):
            with contextlib.redirect_stdout(io.StringIO()):
                result = device.switch_slot(timeout=1)

        self.assertIsInstance(result, subprocess.CompletedProcess)
        run_shell.assert_called_once()
        self.assertIn("--set-active=b", run_shell.call_args.args[0])

    def test_switch_slot_stops_when_bootloader_reboot_fails(self):
        device = Device("ABC123", "adb", "adb")
        device.get_device_state = lambda: "adb"
        device.reboot_bootloader = lambda: -1
        device.clear_device_selection = lambda: None

        with (
            patch("phone.get_adb", return_value="adb"),
            patch("phone.get_fastboot", return_value="fastboot"),
            patch("phone.bootloader_issue_message"),
            patch("phone.update_phones"),
            patch("phone.run_shell") as run_shell,
        ):
            with contextlib.redirect_stdout(io.StringIO()):
                result = device.switch_slot(timeout=1)

        self.assertEqual(-1, result)
        run_shell.assert_not_called()

    def test_run_shell2_timeout_handles_silent_process(self):
        command = f'"{sys.executable}" -c "import time; time.sleep(2)"'

        start = time.time()
        with contextlib.redirect_stdout(io.StringIO()):
            result = run_shell2(command, timeout=0.5)
        elapsed = time.time() - start

        self.assertEqual(-1, result.returncode)
        self.assertLess(elapsed, 5)

    def test_run_shell_timeout_handles_silent_process(self):
        command = f'"{sys.executable}" -c "import time; time.sleep(2)"'

        start = time.time()
        with contextlib.redirect_stdout(io.StringIO()):
            result = run_shell(command, timeout=0.5)
        elapsed = time.time() - start

        self.assertEqual(-1, result.returncode)
        self.assertLess(elapsed, 5)

    def test_reboot_fastboot_fails_when_fastbootd_wait_times_out(self):
        device = Device("ABC123", "adb", "adb")
        device.get_device_state = lambda: "adb"
        device.fastboot_wait_for_bootloader = lambda timeout=60: -1

        with (
            patch("phone.get_adb", return_value="adb"),
            patch("phone.get_fastboot", return_value="fastboot"),
            patch("phone.update_phones"),
            patch("phone.run_shell", return_value=subprocess.CompletedProcess(args="", returncode=0, stdout="", stderr="")),
        ):
            with contextlib.redirect_stdout(io.StringIO()):
                result = device.reboot_fastboot(timeout=1)

        self.assertEqual(-1, result)

    def test_flash_engine_keeps_dry_run_and_wipe_guards_intact(self):
        source = PF_MODULES_SOURCE.read_text(encoding="utf-8")

        self.assertNotIn("flash_mode == 'Wipe'", source)
        self.assertNotIn('flash_mode == "Wipe"', source)
        self.assertIn("self.config.flash_mode != 'wipeData'", source)
        self.assertIn(
            "(self.config.disable_verity or self.config.disable_verification) and os.path.exists(vbmeta_file) and self.config.flash_mode != 'dryRun'",
            source,
        )
        self.assertNotIn("os.chdir(package_dir_full)", source)
        self.assertIn("directory=package_dir_full", source)
        self.assertIn("_sdk_major_version(get_sdk_version())", source)
        self.assertIn("sdk_major_version is not None and sdk_major_version < 34", source)
        self.assertIn("flash_boot_timeout = 15 * 60", source)
        self.assertIn("run_shell2(theCmd, chcp=cp, timeout=flash_boot_timeout)", source)
        self.assertNotIn("timeout = None", source)
        self.assertIn("wait_for_device=not wipe_flag", source)

    def test_patch_boot_fallback_keeps_configured_phone_path(self):
        source = PF_MODULES_SOURCE.read_text(encoding="utf-8")

        self.assertIn("phone_path = configured_phone_path", source)
        self.assertIn("phone_path = fallback_phone_path", source)
        self.assertNotIn("self.config.phone_path = fallback_phone_path", source)
        self.assertIn("Looking for {patched_img} in {phone_path}", source)

    def test_phone_reboot_paths_treat_wait_timeouts_as_failures(self):
        source = PHONE_SOURCE.read_text(encoding="utf-8")

        self.assertNotIn("res2 == 1", source)
        self.assertIn("wait_for_device=True", source)
        self.assertIn("if timeout and wait_for_device", source)
        self.assertIn("probe_timeout = min(timeout, 5) if timeout is not None else None", source)
        self.assertIn("command_timeout = max(0.1, min(5, remaining))", source)
        self.assertIn("will time out and abort this step", source)

    def test_classic_ui_no_longer_warns_about_forever_hangs(self):
        source = MAIN_SOURCE.read_text(encoding="utf-8")

        self.assertNotIn("wait forever", source)
        self.assertNotIn("appear hung", source)
        self.assertIn("PixelFlasher will time out and abort if fastboot does not respond.", source)
        self.assertIn("PixelFlasher will time out and abort if adb does not detect the device.", source)


if __name__ == "__main__":
    unittest.main()
