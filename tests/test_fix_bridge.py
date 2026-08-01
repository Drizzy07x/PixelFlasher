"""Regression tests for the shared host-path boundary (BUG-16/17/39)."""

from __future__ import annotations

import unittest

from pixelflasher_core import OperationResult
from pixelflasher_core.device_tools import (
    PUBLIC_ANDROID_PATH_PREFIXES,
    DeviceToolsService,
)
from ui.public_bridge import (
    _ANDROID_PATH_PREFIXES,
    _is_host_path_string,
    _public_result_summary,
    ensure_public_json,
    project_operation_result,
    safe_public_message,
)


class SharedAndroidPathAllowListTests(unittest.TestCase):
    def test_bridge_and_core_share_one_allow_list_object(self):
        self.assertIs(PUBLIC_ANDROID_PATH_PREFIXES, _ANDROID_PATH_PREFIXES)

    def test_modern_android_roots_are_device_paths(self):
        for path in (
            "/system_ext/priv-app/SystemUI/SystemUI.apk",
            "/apex/com.android.art/javalib/core-oj.jar",
            "/vendor_dlkm/lib/modules/touch.ko",
            "/system_dlkm/lib/modules/zram.ko",
        ):
            with self.subTest(path=path):
                self.assertFalse(_is_host_path_string(path))

    def test_host_roots_are_still_rejected(self):
        for path in (
            "/home/alice/PixelFlasher/private.zip",
            "/tmp/pixelflasher/private.zip",
            "/cache/private.zip",
            "/oem/private.zip",
            "/postinstall/private.zip",
            r"C:\Users\Alice\private.zip",
        ):
            with self.subTest(path=path):
                self.assertTrue(_is_host_path_string(path))


class AppsListProjectionTests(unittest.TestCase):
    def test_packages_under_system_ext_keep_their_public_value(self):
        result = OperationResult.success(
            "apps-list",
            message="Listed packages.",
            value={
                "packages": [
                    {
                        "package": "com.android.systemui",
                        "apk_path": "/system_ext/priv-app/SystemUI/SystemUI.apk",
                        "uid": 10001,
                    }
                ]
            },
        )

        public = project_operation_result("apps.list", result)

        self.assertIn("value", public)
        self.assertEqual(1, public["value"]["count"])
        self.assertEqual(
            "/system_ext/priv-app/SystemUI/SystemUI.apk",
            public["value"]["packages"][0]["apk_path"],
        )


class MyToolsProjectionTests(unittest.TestCase):
    def _legacy(self, preview: str) -> dict[str, object]:
        return {
            "id": "legacy:0",
            "title": "My Tool",
            "mode": "legacyRaw",
            "displayName": "adbfix.exe",
            "sha256": "",
            "arguments": [],
            "enabled": True,
            "permissionGranted": True,
            "blockedReason": "",
            "commandPreview": preview,
            "fingerprint": "a" * 64,
            "workingDirectory": "default",
        }

    def test_migrated_legacy_tool_survives_with_a_basename_preview(self):
        source = self._legacy(r'"C:\Tools\adbfix.exe" --serial ABC')
        result = OperationResult.success(
            "my-tools",
            value={"schemaVersion": 2, "tools": [], "legacyRaw": [source], "revision": 3},
        )

        public = project_operation_result("tools.myTools", result)

        preview = public["value"]["legacyRaw"][0]["commandPreview"]
        self.assertEqual('"adbfix.exe" --serial ABC', preview)
        self.assertNotIn("C:\\Tools", preview)
        # The stored record must not be mutated by the display-only projection.
        self.assertEqual(r'"C:\Tools\adbfix.exe" --serial ABC', source["commandPreview"])

    def test_relative_legacy_preview_is_left_verbatim(self):
        result = OperationResult.success(
            "my-tools",
            value={
                "schemaVersion": 2,
                "tools": [],
                "legacyRaw": [self._legacy('"tool.exe" --literal')],
                "revision": 3,
            },
        )

        public = project_operation_result("tools.myTools", result)

        self.assertEqual(
            '"tool.exe" --literal',
            public["value"]["legacyRaw"][0]["commandPreview"],
        )

    def test_safe_argv_arguments_with_host_paths_are_kept_not_rejected(self):
        result = OperationResult.success(
            "my-tools",
            value={
                "schemaVersion": 2,
                "tools": [
                    {
                        "id": "0" * 32,
                        "title": "Fix",
                        "mode": "safeArgv",
                        "displayName": "tool.exe",
                        "sha256": "a" * 64,
                        "arguments": ["--input", "D:/roms/boot.img", "--out", "/sdcard/x"],
                        "enabled": True,
                    }
                ],
                "legacyRaw": [],
                "revision": 4,
            },
        )

        public = project_operation_result("tools.myTools", result)

        # The editor prefills from this row and posts it straight back to disk,
        # so a placeholder here would overwrite the stored argument.
        self.assertEqual(
            ["--input", "D:/roms/boot.img", "--out", "/sdcard/x"],
            public["value"]["tools"][0]["arguments"],
        )


class SafePublicMessageTests(unittest.TestCase):
    def test_cause_survives_when_a_host_path_is_redacted(self):
        message = safe_public_message(
            r"cannot open C:\Users\Alice\boot.img: permission denied",
            fallback="The operation could not be completed.",
        )

        self.assertEqual("cannot open <host-path>: permission denied", message)

    def test_bare_host_path_message_still_falls_back(self):
        self.assertEqual(
            "FALLBACK",
            safe_public_message("/home/alice/private.zip", fallback="FALLBACK"),
        )

    def test_snapshot_last_result_keeps_the_redacted_cause(self):
        summary = _public_result_summary(
            OperationResult.failed(
                "flash",
                code="io_error",
                message=r"cannot open C:\Users\Alice\boot.img: permission denied",
            )
        )

        self.assertEqual("cannot open <host-path>: permission denied", summary["message"])

    def test_device_path_message_is_untouched(self):
        self.assertEqual(
            "pushed to /sdcard/Download/boot.img",
            safe_public_message(
                "pushed to /sdcard/Download/boot.img", fallback="FALLBACK"
            ),
        )


class LogcatSanitizerBoundaryTests(unittest.TestCase):
    def test_trailing_path_is_not_hidden_behind_an_allow_listed_path(self):
        line = (
            "01-01 00:00:00.000  1000  1000 I Foo     : "
            "loaded /data/local/tmp/a.so /system_ext/lib64/b.so ok"
        )

        safe, _redacted, _truncated = DeviceToolsService._sanitize_logcat_line(
            line, "ABC123", "standard"
        )

        self.assertEqual(line, safe)
        self.assertFalse(_is_host_path_string(safe))
        ensure_public_json([safe])

    def test_host_path_after_a_device_path_is_redacted_whole(self):
        line = "I Foo: /data/x /home/Alice Smith/token end"

        safe, redacted, _truncated = DeviceToolsService._sanitize_logcat_line(
            line, "ABC123", "none"
        )

        self.assertTrue(redacted)
        self.assertIn("/data/x", safe)
        self.assertNotIn("Alice", safe)
        self.assertNotIn("Smith", safe)
        self.assertFalse(_is_host_path_string(safe))
        ensure_public_json([safe])

    def test_device_path_after_a_host_path_is_preserved(self):
        line = "I Foo: /home/alice/token /data/local/tmp/device.txt"

        safe, redacted, _truncated = DeviceToolsService._sanitize_logcat_line(
            line, "ABC123", "none"
        )

        self.assertTrue(redacted)
        self.assertIn("/data/local/tmp/device.txt", safe)
        self.assertNotIn("/home/alice", safe)
        self.assertFalse(_is_host_path_string(safe))


if __name__ == "__main__":
    unittest.main()
