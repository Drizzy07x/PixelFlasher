import contextlib
import io
import subprocess
import unittest
from unittest.mock import patch

from phone import Device


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


if __name__ == "__main__":
    unittest.main()
