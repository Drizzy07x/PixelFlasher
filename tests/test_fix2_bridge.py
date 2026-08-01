"""Round-2 regressions for the personal-tool and logcat host-path boundaries.

BLOCKING-02: the projected personal-tool row is the object the editor prefills
and posts back, so a redacted argument was written to disk on the next save.
IMPORTANT-02: the RUN RAW consent text must still name the binary it authorizes
and must not mangle Windows switches.
IMPORTANT-03: the core logcat sanitizer and the WebView boundary must share one
Windows/UNC grammar, or a sanitized line still fails the boundary and the whole
capture is discarded.
"""

from __future__ import annotations

import json
import unittest

from pixelflasher_core import OperationResult
from pixelflasher_core.device_tools import (
    PUBLIC_UNC_PATH,
    PUBLIC_WINDOWS_PATH,
    DeviceToolsService,
)
from ui.public_bridge import (
    _UNC_PATH,
    _WINDOWS_PATH,
    PublicProjectionError,
    _is_host_path_string,
    ensure_public_json,
    project_operation_result,
)


def _safe_tool(**overrides: object) -> dict[str, object]:
    tool: dict[str, object] = {
        "id": "0" * 32,
        "title": "Fix",
        "mode": "safeArgv",
        "displayName": "tool.exe",
        "sha256": "a" * 64,
        "arguments": ["--input", "D:/roms/boot.img", "--out", "/sdcard/x"],
        "enabled": True,
    }
    tool.update(overrides)
    return tool


def _legacy_tool(preview: str) -> dict[str, object]:
    return {
        "id": "legacy:0",
        "title": "My Tool",
        "mode": "legacyRaw",
        "displayName": "Legacy 9.x",
        "sha256": "",
        "arguments": [],
        "enabled": True,
        "permissionGranted": True,
        "blockedReason": "",
        "commandPreview": preview,
        "fingerprint": "a" * 64,
        "workingDirectory": "default",
    }


def _project(tools: list[dict[str, object]], legacy: list[dict[str, object]]) -> dict:
    result = OperationResult.success(
        "my-tools",
        value={
            "schemaVersion": 2,
            "tools": tools,
            "legacyRaw": legacy,
            "revision": 7,
        },
    )
    return project_operation_result("tools.myTools", result)["value"]


class PersonalToolWriteBackTests(unittest.TestCase):
    def test_arguments_reach_the_editor_losslessly(self):
        value = _project([_safe_tool()], [])

        self.assertEqual(
            ["--input", "D:/roms/boot.img", "--out", "/sdcard/x"],
            value["tools"][0]["arguments"],
        )

    def test_title_reaches_the_editor_losslessly(self):
        value = _project([_safe_tool(title=r"Patch C:\roms")], [])

        self.assertEqual(r"Patch C:\roms", value["tools"][0]["title"])

    def test_projection_never_mutates_the_stored_record(self):
        tool = _safe_tool()
        arguments = list(tool["arguments"])

        _project([tool], [])

        self.assertEqual(arguments, tool["arguments"])

    def test_projected_row_is_json_encodable(self):
        value = _project([_safe_tool()], [_legacy_tool(r'"C:\Tools\adbfix.exe" -s A')])

        encoded = json.loads(json.dumps(value))

        self.assertEqual(
            ["--input", "D:/roms/boot.img", "--out", "/sdcard/x"],
            encoded["tools"][0]["arguments"],
        )
        self.assertEqual('"adbfix.exe" -s A', encoded["legacyRaw"][0]["commandPreview"])

    def test_oversized_argument_still_fails_the_boundary(self):
        with self.assertRaises(PublicProjectionError):
            _project([_safe_tool(arguments=["x" * 2_049])], [])


class LegacyConsentPreviewTests(unittest.TestCase):
    def test_preview_names_the_authorized_binary(self):
        value = _project([], [_legacy_tool(r'"C:\Tools\adbfix.exe" --serial ABC')])

        preview = value["legacyRaw"][0]["commandPreview"]

        self.assertEqual('"adbfix.exe" --serial ABC', preview)
        self.assertNotIn("C:\\Tools", preview)

    def test_windows_switches_survive_untouched(self):
        value = _project([], [_legacy_tool('"cmd.exe" /c echo hi')])

        self.assertEqual(
            '"cmd.exe" /c echo hi',
            value["legacyRaw"][0]["commandPreview"],
        )

    def test_two_tools_with_the_same_arguments_stay_distinguishable(self):
        first = _legacy_tool(r'"C:\Tools\a.exe" --serial ABC')
        second = _legacy_tool(r'"D:\Other\b.exe" --serial ABC')
        second["id"] = "legacy:1"

        value = _project([], [first, second])

        self.assertNotEqual(
            value["legacyRaw"][0]["commandPreview"],
            value["legacyRaw"][1]["commandPreview"],
        )


class SharedWindowsGrammarTests(unittest.TestCase):
    def test_bridge_and_core_share_one_windows_grammar_object(self):
        self.assertIs(PUBLIC_WINDOWS_PATH, _WINDOWS_PATH)
        self.assertIs(PUBLIC_UNC_PATH, _UNC_PATH)

    def test_glued_drive_prefix_is_redacted_and_accepted(self):
        line = r"I Foo: cfg_C:\Users\Alice\secret.txt done"

        safe, redacted, _truncated = DeviceToolsService._sanitize_logcat_line(
            line, "ABC123", "none"
        )

        self.assertTrue(redacted)
        self.assertNotIn("Alice", safe)
        self.assertFalse(_is_host_path_string(safe))
        ensure_public_json([safe])

    def test_bare_drive_prefix_is_redacted_and_accepted(self):
        line = "I Foo: free space on C:\\"

        safe, redacted, _truncated = DeviceToolsService._sanitize_logcat_line(
            line, "ABC123", "none"
        )

        self.assertTrue(redacted)
        self.assertFalse(_is_host_path_string(safe))
        ensure_public_json([safe])

    def test_glued_unc_path_is_redacted_and_accepted(self):
        line = r"I Foo: see cfg_\\server\share\x.txt end"

        safe, redacted, _truncated = DeviceToolsService._sanitize_logcat_line(
            line, "ABC123", "none"
        )

        self.assertTrue(redacted)
        self.assertNotIn("server", safe)
        self.assertFalse(_is_host_path_string(safe))
        ensure_public_json([safe])

    def test_device_paths_are_still_untouched(self):
        line = "I Foo: loaded /data/local/tmp/a.so /system_ext/lib64/b.so ok"

        safe, redacted, _truncated = DeviceToolsService._sanitize_logcat_line(
            line, "ABC123", "standard"
        )

        self.assertEqual(line, safe)
        self.assertFalse(redacted)


if __name__ == "__main__":
    unittest.main()
