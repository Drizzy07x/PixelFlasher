import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from scripts.export_gettext_json import (
    build_export_files,
    discover_catalogs,
    export_catalogs,
    main,
)

EXPECTED_LOCALES = ("en", "es", "fr", "it", "zh_CN", "zh_TW")
EXPECTED_MESSAGE_COUNT = 1645
EXPECTED_WEB_MESSAGE_COUNT = 675
EXPECTED_WEB_TRANSLATED_COUNTS = {
    "en": 62,
    "es": 555,
    "fr": 555,
    "it": 555,
    "zh_CN": 555,
    "zh_TW": 555,
}


class GettextJsonExportTests(unittest.TestCase):
    def test_discovers_every_current_catalog_in_stable_order(self):
        catalogs = discover_catalogs(Path("locale"))

        self.assertEqual(EXPECTED_LOCALES, tuple(locale for locale, _ in catalogs))
        self.assertTrue(all(path.name == "pixelflasher.po" for _, path in catalogs))

    def test_export_is_complete_and_uses_source_fallback(self):
        files = build_export_files(Path("locale"))
        manifest = json.loads(files["manifest.json"])

        self.assertEqual(1, manifest["schemaVersion"])
        self.assertEqual("pixelflasher", manifest["domain"])
        self.assertEqual("en", manifest["fallbackLocale"])
        self.assertEqual(
            list(EXPECTED_LOCALES),
            [entry["locale"] for entry in manifest["locales"]],
        )

        english = json.loads(files["en.json"])
        simplified_chinese = json.loads(files["zh_CN.json"])
        self.assertEqual(EXPECTED_MESSAGE_COUNT, len(english))
        self.assertEqual(set(english), set(simplified_chinese))
        self.assertEqual("Yes", english["Yes"])
        self.assertEqual("是", simplified_chinese["Yes"])
        self.assertTrue(all(value for value in simplified_chinese.values()))

        for entry in manifest["locales"]:
            content = files[entry["file"]]
            self.assertEqual(EXPECTED_MESSAGE_COUNT, entry["messageCount"])
            self.assertEqual(EXPECTED_WEB_MESSAGE_COUNT, entry["webMessageCount"])
            self.assertEqual(
                EXPECTED_WEB_TRANSLATED_COUNTS[entry["locale"]],
                entry["webTranslatedCount"],
            )
            self.assertEqual(hashlib.sha256(content).hexdigest(), entry["sha256"])

    def test_repeated_exports_are_byte_for_byte_reproducible(self):
        first = build_export_files(Path("locale"))
        second = build_export_files(Path("locale"))

        self.assertEqual(first, second)
        self.assertNotIn(str(Path.cwd()), first["manifest.json"].decode("utf-8"))
        self.assertNotIn("generatedAt", first["manifest.json"].decode("utf-8"))

    def test_check_mode_detects_stale_or_unexpected_json(self):
        with tempfile.TemporaryDirectory(prefix="pf-i18n-export-") as tmp:
            output = Path(tmp)
            export_catalogs(Path("locale"), output)
            export_catalogs(Path("locale"), output, check=True)

            (output / "es.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "es.json"):
                export_catalogs(Path("locale"), output, check=True)

            export_catalogs(Path("locale"), output)
            (output / "obsolete.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "unexpected:obsolete.json"):
                export_catalogs(Path("locale"), output, check=True)

    def test_cli_returns_nonzero_for_missing_catalogs(self):
        with tempfile.TemporaryDirectory(prefix="pf-empty-locale-") as locale_tmp:
            with tempfile.TemporaryDirectory(prefix="pf-i18n-output-") as output_tmp:
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    result = main(
                        [
                            "--locale-dir",
                            locale_tmp,
                            "--output-dir",
                            output_tmp,
                        ]
                    )
                self.assertEqual(1, result)
                self.assertIn("No pixelflasher.po catalogs found", output.getvalue())


if __name__ == "__main__":
    unittest.main()
