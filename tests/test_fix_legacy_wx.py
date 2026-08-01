"""Regression tests for the legacy wxPython packet (BUG-01, 18, 19, 20, 22, 42)."""

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import wx

import backup_manager
import Main
import partition_manager
from phone import Device


# -----------------------------------------------------------------------------
#  BUG-01  Partition Manager "Erase" was a silent no-op
# -----------------------------------------------------------------------------
class EraseIsNeverSilentTests(unittest.TestCase):
    def test_erase_partition_refuses_loudly_and_touches_nothing(self):
        device = Device("ABC123", "adb", "adb")
        device.reboot_bootloader = MagicMock(return_value=0)
        device.refresh_phone_mode = MagicMock()

        with (
            patch("phone.get_adb", return_value="adb"),
            patch("phone.get_fastboot", return_value="fastboot"),
            patch("phone.run_shell") as run_shell,
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                res = device.erase_partition("boot")

        self.assertEqual(-1, res)
        run_shell.assert_not_called()
        device.reboot_bootloader.assert_not_called()
        self.assertIn("not supported", output.getvalue())

    def test_erase_reports_the_failure_and_aborts_without_prompting(self):
        stub = _PartitionManagerStub()
        stub.device.erase_partition = MagicMock(return_value=-1)

        with patch("partition_manager.wx.MessageDialog") as message_dialog:
            with contextlib.redirect_stdout(io.StringIO()):
                res = partition_manager.PartitionManager.Erase(stub, "boot")

        self.assertEqual(-1, res)
        self.assertTrue(stub.abort)
        message_dialog.assert_not_called()

    def test_checking_a_partition_never_arms_the_erase_button(self):
        stub = _PartitionManagerStub()
        partition_manager.PartitionManager.EnableDisableButton(stub, True)

        self.assertEqual([False], stub.erase_button.states)
        self.assertEqual([True], stub.dump_partition.states)


# -----------------------------------------------------------------------------
#  BUG-22  Dump ignored pull_file's result and deleted the on device dump anyway
# -----------------------------------------------------------------------------
class DumpFailureTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.folder = self.tempdir.name
        self.destination = os.path.join(self.folder, "boot.img")

    def _dump(self, stub):
        with patch("partition_manager.wx.Cursor"):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                res = partition_manager.PartitionManager.Dump(stub, "boot", True)
        return res, output.getvalue()

    def test_failed_pull_keeps_the_device_dump_and_aborts(self):
        stub = _PartitionManagerStub()
        stub.downloadFolder = self.folder
        Path(self.destination).write_bytes(b"previous good dump")

        def pull_file(remote, local):
            # mirror Device.pull_file, which deletes the destination before pulling
            if os.path.exists(local):
                os.remove(local)
            return -1

        stub.device.pull_file = MagicMock(side_effect=pull_file)
        res, output = self._dump(stub)

        self.assertEqual(-1, res)
        self.assertTrue(stub.abort)
        # the on device dump must survive so the user can retry
        self.assertEqual(1, stub.device.delete.call_count)
        self.assertIn("/data/local/tmp/boot.img", output)
        # and the previous local dump must not be destroyed by the failed pull
        self.assertEqual(b"previous good dump", Path(self.destination).read_bytes())
        self.assertFalse(os.path.exists(f"{self.destination}.tmp"))

    def test_successful_pull_still_saves_and_cleans_the_device(self):
        stub = _PartitionManagerStub()
        stub.downloadFolder = self.folder

        def pull_file(remote, local):
            Path(local).write_bytes(b"fresh dump")
            return 0

        stub.device.pull_file = MagicMock(side_effect=pull_file)
        res, _output = self._dump(stub)

        self.assertEqual(0, res)
        self.assertFalse(stub.abort)
        self.assertEqual(2, stub.device.delete.call_count)
        self.assertEqual(b"fresh dump", Path(self.destination).read_bytes())


# -----------------------------------------------------------------------------
#  BUG-18  the device id was parsed from the root symbol instead of the serial
# -----------------------------------------------------------------------------
class DeviceIdParsingTests(unittest.TestCase):
    LABEL = "✗  (adb)   28221FDH2000AB           panther     UP1A.231005.007          "

    def test_device_id_is_the_serial_token(self):
        self.assertEqual("28221FDH2000AB", Main.PixelFlasher._device_id_from_label(None, self.LABEL))

    def test_malformed_rows_do_not_raise(self):
        for label in ("", None, "ERROR", "✗  (adb)"):
            self.assertEqual("", Main.PixelFlasher._device_id_from_label(None, label))

    def test_runtime_device_lookup_uses_the_serial(self):
        stub = _FrameStub()
        stub.device_choice = _ChoiceStub([self.LABEL], selection=self.LABEL)
        stub._select_runtime_phone = MagicMock(return_value=True)

        with (
            patch("Main.get_phone", return_value=None),
            patch("Main.update_phones") as update_phones,
        ):
            self.assertTrue(Main.PixelFlasher._ensure_runtime_device_loaded(stub))

        update_phones.assert_called_once_with("28221FDH2000AB")
        stub._select_runtime_phone.assert_called_once_with("28221FDH2000AB")

    def test_selecting_the_choice_by_id_matches_the_serial_column(self):
        stub = _FrameStub()
        stub.device_choice = _ChoiceStub(["ERROR", self.LABEL])

        Main.PixelFlasher._select_device_choice_by_id(stub, "28221FDH2000AB")

        self.assertEqual([1], stub.device_choice.selections)

    def test_selecting_the_choice_by_id_ignores_an_empty_id(self):
        stub = _FrameStub()
        stub.device_choice = _ChoiceStub(["", self.LABEL])

        Main.PixelFlasher._select_device_choice_by_id(stub, "")

        self.assertEqual([], stub.device_choice.selections)


# -----------------------------------------------------------------------------
#  BUG-19  Google Images downloads had no timeout and raced the cancel button
# -----------------------------------------------------------------------------
class DownloadWithProgressTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.destination = os.path.join(self.tempdir.name, "image.zip")

    def _start(self, chunks):
        menu = _GoogleImagesMenuStub()
        response = MagicMock()
        response.headers = {'content-length': '8'}
        response.iter_content.return_value = chunks
        with (
            patch("Main.wx.CallAfter"),
            patch("Main.requests.get", return_value=response) as requests_get,
            patch("Main.threading.Thread") as thread,
        ):
            Main.GoogleImagesBaseMenu.download_with_progress(
                menu, "https://dl.google.com/image.zip", self.destination, lambda: None)
        return menu, requests_get, thread

    def test_download_is_bounded_by_a_timeout_on_a_daemon_thread(self):
        menu, requests_get, thread = self._start([b"abcd"])

        self.assertTrue(thread.call_args.kwargs['daemon'])
        with contextlib.redirect_stdout(io.StringIO()):
            with (
                patch("Main.wx.CallAfter"),
                patch("Main.requests.get", requests_get),
            ):
                thread.call_args.kwargs['target']()

        self.assertEqual((10, 60), requests_get.call_args.kwargs['timeout'])

    def test_cancel_does_not_close_the_file_under_the_writer(self):
        menu, requests_get, thread = self._start([b"abcd", b"efgh"])
        # deliver the Cancel click while a write is in flight, which is what makes the
        # GUI thread closing the worker's file handle observable
        state = {'cancel': menu.cancel_button.handler, 'delivered': False}
        real_open = open

        class _CancelOnWrite:
            def __init__(self, handle):
                self._handle = handle

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self._handle.close()
                return False

            def write(self, data):
                if not state['delivered']:
                    state['delivered'] = True
                    state['cancel'](None)
                return self._handle.write(data)

            def close(self):
                self._handle.close()

        def fake_open(path, mode, *args, **kwargs):
            return _CancelOnWrite(real_open(path, mode, *args, **kwargs))

        with contextlib.redirect_stdout(io.StringIO()) as output:
            with (
                patch("Main.wx.CallAfter"),
                patch("Main.requests.get", requests_get),
                patch("builtins.open", fake_open),
            ):
                thread.call_args.kwargs['target']()

        self.assertTrue(state['delivered'])
        self.assertNotIn("Download error", output.getvalue())
        self.assertIn("Download cancelled", output.getvalue())
        self.assertFalse(os.path.exists(self.destination))


# -----------------------------------------------------------------------------
#  BUG-42  "Show Progress Window" read an attribute that is never assigned
# -----------------------------------------------------------------------------
class ShowProgressWindowTests(unittest.TestCase):
    def test_running_download_window_is_shown(self):
        menu = _GoogleImagesMenuStub()
        menu.parent.download_progress_window = MagicMock()

        Main.GoogleImagesBaseMenu.on_show_progress_window(menu, None)

        menu.parent.download_progress_window.Show.assert_called_once()
        menu.parent.toast.assert_not_called()

    def test_toast_when_there_is_no_window(self):
        menu = _GoogleImagesMenuStub()

        Main.GoogleImagesBaseMenu.on_show_progress_window(menu, None)

        menu.parent.toast.assert_called_once()

    def test_destroyed_window_falls_back_to_the_toast(self):
        menu = _GoogleImagesMenuStub()
        window = MagicMock()
        window.Show.side_effect = RuntimeError("wrapped C/C++ object has been deleted")
        menu.parent.download_progress_window = window

        Main.GoogleImagesBaseMenu.on_show_progress_window(menu, None)

        menu.parent.toast.assert_called_once()
        self.assertIsNone(menu.parent.download_progress_window)


# -----------------------------------------------------------------------------
#  BUG-20  the Magisk backup fallback tested a stale return code
# -----------------------------------------------------------------------------
class BackupFallbackTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.boot_image = os.path.join(self.tempdir.name, "boot.img")
        Path(self.boot_image).write_bytes(b"boot image")

    def _add_backup(self, zip_and_push_result):
        stub = _BackupManagerStub()
        stub.ZipAndPush = MagicMock(return_value=zip_and_push_result)
        with patch("backup_manager.wx.FileDialog", _fake_file_dialog(self.boot_image)):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                backup_manager.BackupManager.OnAddBackup(stub, None)
        return stub, output.getvalue()

    def test_successful_fallback_refreshes_and_does_not_abort(self):
        stub, output = self._add_backup(0)

        stub.ZipAndPush.assert_called_once()
        stub.Refresh.assert_called_once()
        self.assertNotIn("Aborting", output)

    def test_failed_fallback_aborts_without_refreshing(self):
        stub, output = self._add_backup(-1)

        stub.Refresh.assert_not_called()
        self.assertIn("Aborting", output)

    def test_zip_and_push_reports_success_explicitly(self):
        stub = _BackupManagerStub()
        stub.device.create_dir = MagicMock(return_value=0)
        stub.device.push_file = MagicMock(return_value=0)

        with (
            patch("backup_manager.get_config_path", return_value=self.tempdir.name),
            patch("backup_manager.os.path.exists", return_value=True),
        ):
            os.makedirs(os.path.join(self.tempdir.name, 'tmp'), exist_ok=True)
            with contextlib.redirect_stdout(io.StringIO()):
                res = backup_manager.BackupManager.ZipAndPush(stub, self.boot_image, "abc123")

        self.assertEqual(0, res)


# -----------------------------------------------------------------------------
#  stubs
# -----------------------------------------------------------------------------
class _ButtonStub:
    def __init__(self):
        self.states = []

    def Enable(self, state):
        self.states.append(state)


class _ChoiceStub:
    def __init__(self, items, selection=""):
        self.items = items
        self.selection = selection
        self.selections = []

    def GetItems(self):
        return self.items

    def GetStringSelection(self):
        return self.selection

    def SetSelection(self, index):
        self.selections.append(index)


class _ConfigStub:
    device = ""


class _FrameStub:
    def __init__(self):
        self.config = _ConfigStub()

    def _device_id_from_label(self, label):
        return Main.PixelFlasher._device_id_from_label(self, label)

    def _select_device_choice_by_id(self, device_id):
        return Main.PixelFlasher._select_device_choice_by_id(self, device_id)


class _PartitionManagerStub:
    def __init__(self):
        self.abort = False
        self.downloadFolder = None
        self.erase_button = _ButtonStub()
        self.dump_partition = _ButtonStub()
        self.device = MagicMock()
        self.device.delete.return_value = 0
        self.device.dump_partition.return_value = (0, "/data/local/tmp/boot.img")

    def SetCursor(self, cursor):
        pass


class _CancelButtonStub:
    def __init__(self):
        self.handler = None

    def Bind(self, event, handler):
        self.handler = handler


class _ProgressWindowStub:
    def __init__(self, cancel_button):
        self.cancel_button = cancel_button

    def add_download(self, url, filename):
        return MagicMock(), self.cancel_button

    def remove_download(self, url):
        pass


class _GoogleImagesMenuStub:
    def __init__(self):
        self.cancel_button = _CancelButtonStub()
        self.progress = _ProgressWindowStub(self.cancel_button)
        self.parent = MagicMock()
        del self.parent.download_progress_window
        self.parent.get_progress_window.return_value = self.progress

    def get_progress_window(self):
        return self.progress


class _BackupManagerStub:
    def __init__(self):
        self.device = MagicMock()
        self.device.push_file.return_value = 0
        self.device.run_magisk_migration.return_value = -1
        self.device.magisk_backups = {}
        self.sha1 = None
        self.Refresh = MagicMock()

    def _on_spin(self, state):
        pass


def _fake_file_dialog(path):
    class _FileDialog:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def ShowModal(self):
            return wx.ID_OK

        def GetPath(self):
            return path

    return _FileDialog


if __name__ == '__main__':
    unittest.main()
