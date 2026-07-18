import re
import unittest

import polib

from scripts.sync_react_gettext import (
    EXPECTED_LOCALES,
    catalog_paths,
    load_react_messages,
    missing_react_messages,
    react_translation_coverage,
)


EXPECTED_TRANSLATED_COUNTS = {
    "en": 0,
    "es": 283,
    "fr": 283,
    "it": 283,
    "zh_CN": 283,
    "zh_TW": 283,
}
TRANSLATED_LOCALES = ("es", "fr", "it", "zh_CN", "zh_TW")
EXPECTED_WEB_CONTEXT_COUNT = 267
PLACEHOLDER_PATTERN = re.compile(r"\{[A-Za-z][A-Za-z0-9_]*\}")


class ReactGettextCoverageTests(unittest.TestCase):
    def test_every_react_msgid_is_owned_by_all_six_gettext_catalogs(self):
        messages = load_react_messages()
        paths = catalog_paths()

        self.assertEqual(EXPECTED_LOCALES, tuple(locale for locale, _path in paths))
        self.assertGreater(len(messages), 100)
        self.assertEqual(len(messages), len({message.key for message in messages}))
        for locale, path in paths:
            with self.subTest(locale=locale):
                self.assertEqual((), missing_react_messages(path, messages))

    def test_react_translation_baseline_distinguishes_keys_from_real_translations(self):
        messages = load_react_messages()
        for locale, path in catalog_paths():
            with self.subTest(locale=locale):
                coverage = react_translation_coverage(path, messages)
                self.assertEqual(len(messages), coverage.message_count)
                self.assertEqual(
                    EXPECTED_TRANSLATED_COUNTS[locale],
                    coverage.translated_count,
                )
                self.assertEqual(
                    len(messages) - EXPECTED_TRANSLATED_COUNTS[locale],
                    coverage.fallback_count,
                )

    def test_every_web_context_is_translated_and_preserves_placeholders(self):
        paths = dict(catalog_paths())
        english = polib.pofile(str(paths["en"]), encoding="utf-8", wrapwidth=0)
        expected = {
            (entry.msgctxt, entry.msgid)
            for entry in english
            if entry.msgctxt and entry.msgctxt.startswith("web.") and not entry.obsolete
        }
        self.assertEqual(EXPECTED_WEB_CONTEXT_COUNT, len(expected))

        for locale in TRANSLATED_LOCALES:
            catalog = polib.pofile(str(paths[locale]), encoding="utf-8", wrapwidth=0)
            entries = {
                (entry.msgctxt, entry.msgid): entry
                for entry in catalog
                if entry.msgctxt and entry.msgctxt.startswith("web.") and not entry.obsolete
            }
            with self.subTest(locale=locale):
                self.assertEqual(expected, set(entries))
            for key, entry in entries.items():
                with self.subTest(locale=locale, context=key[0]):
                    self.assertTrue(entry.msgstr.strip(), "translation is empty")
                    self.assertFalse(entry.fuzzy, "translation is fuzzy")
                    self.assertEqual(
                        sorted(PLACEHOLDER_PATTERN.findall(entry.msgid)),
                        sorted(PLACEHOLDER_PATTERN.findall(entry.msgstr)),
                    )


if __name__ == "__main__":
    unittest.main()
