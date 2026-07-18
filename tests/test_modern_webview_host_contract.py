import json
from pathlib import Path
import tempfile
import unittest

from ui.pages.modern_webview_host import (
    _is_allowed_local_url,
    _jsonable,
    _limit_bridge_payload,
    _register_support_destination_result,
    _safe_wildcard,
)


class ModernWebViewHostContractTests(unittest.TestCase):
    def test_navigation_is_restricted_to_the_bundled_asset_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            asset = root / "assets" / "app.js"
            asset.parent.mkdir()
            asset.write_text("", encoding="utf-8")

            self.assertTrue(_is_allowed_local_url(asset.as_uri(), root))
            self.assertTrue(_is_allowed_local_url("about:blank", root))
            self.assertFalse(_is_allowed_local_url("https://example.com", root))
            self.assertFalse(_is_allowed_local_url((root.parent / "secret.txt").as_uri(), root))

    def test_file_filter_builder_only_accepts_simple_extensions(self):
        wildcard = _safe_wildcard(
            [
                {"label": "Android packages", "extensions": ["zip", ".img", "*.apk"]},
                {"label": "Unsafe|label", "extensions": ["../exe", "tar.gz"]},
            ]
        )

        self.assertIn("*.zip;*.img;*.apk", wildcard)
        self.assertNotIn("../", wildcard)
        self.assertNotIn("tar.gz", wildcard)
        self.assertTrue(wildcard.endswith("All files (*.*)|*.*"))

    def test_json_conversion_never_emits_python_objects(self):
        value = _jsonable({"path": Path("firmware.zip"), "items": (1, 2)})

        self.assertEqual({"path": "firmware.zip", "items": [1, 2]}, value)
        json.dumps(value)

    def test_outbound_logs_are_bounded_before_script_injection(self):
        bounded = _limit_bridge_payload({"stdout": "x" * 40_000, "message": "ok"})

        self.assertLess(len(bounded["stdout"]), 40_000)
        self.assertIn("truncated", bounded["stdout"])
        self.assertEqual("ok", bounded["message"])

    def test_support_picker_path_is_exchanged_for_an_opaque_one_use_id(self):
        class Engine:
            def __init__(self):
                self.calls = []

            def register_support_destination(self, path, *, allow_overwrite=False):
                self.calls.append((path, allow_overwrite))
                return "A" * 43

        engine = Engine()
        result = _register_support_destination_result(
            engine,
            {
                "status": "SUCCESS",
                "data": {"path": "C:/Users/private/support.zip"},
            },
        )

        self.assertEqual([("C:/Users/private/support.zip", True)], engine.calls)
        self.assertEqual("A" * 43, result["data"]["destinationId"])
        self.assertEqual("support.zip", result["data"]["displayName"])
        self.assertNotIn("path", result["data"])
        self.assertNotIn("private", json.dumps(result))

    def test_support_picker_registration_failures_do_not_leak_paths_or_errors(self):
        class Engine:
            @staticmethod
            def register_support_destination(_path, *, allow_overwrite=False):
                raise OSError("C:/Users/private/support.zip is unavailable")

        result = _register_support_destination_result(
            Engine(),
            {"status": "SUCCESS", "data": {"path": "C:/Users/private/support.zip"}},
        )

        self.assertEqual("FAILED", result["status"])
        self.assertEqual("support_destination_invalid", result["code"])
        self.assertNotIn("private", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
