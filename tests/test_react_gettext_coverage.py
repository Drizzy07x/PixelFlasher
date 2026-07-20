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
    "en": 48,
    "es": 560,
    "fr": 560,
    "it": 560,
    "zh_CN": 560,
    "zh_TW": 560,
}
TRANSLATED_LOCALES = ("es", "fr", "it", "zh_CN", "zh_TW")
EXPECTED_WEB_CONTEXT_COUNT = 661
EXPECTED_SOURCE_FALLBACK_CONTEXTS = {
    # Official firmware catalog/download UI awaits the next coordinated
    # translation pass and uses its canonical English source in the meantime.
    "web.firmware.officialCatalog",
    "web.firmware.channel",
    "web.firmware.canary",
    "web.firmware.refreshCatalog",
    "web.firmware.catalogDeviceRequired",
    "web.firmware.catalogFailed",
    "web.firmware.catalogEmpty",
    "web.firmware.provenance",
    "web.firmware.downloadSelect",
    # Firmware verification receipts are source-fallback until the next
    # coordinated six-locale translation pass.
    "web.firmware.verificationTitle",
    "web.firmware.verificationDetail",
    "web.firmware.compatibility",
    "web.firmware.compatibility.matched",
    "web.firmware.compatibility.unverified",
    "web.firmware.compatibility.not_checked",
    "web.firmware.detectedDevice",
    "web.firmware.evidenceCount",
    "web.firmware.invalidInspection",
    "web.firmware.importStock",
    "web.firmware.importCustom",
    # update_engine status preflight landed after the reviewed 2026-07-19
    # translation pass and falls back to its canonical English msgid.
    "web.device.otaStatus",
    "web.device.otaStatusDetail",
    "web.device.otaState",
    "web.device.otaStatusProgress",
    "web.device.otaIdle",
    "web.device.otaIdleYes",
    "web.device.otaIdleNo",
    "web.device.otaLastError",
    "web.apps.apkFiles",
    "web.apps.chooseApk",
    "web.apps.replace",
    "web.apps.replaceDetail",
    "web.apps.grantPermissions",
    "web.apps.grantPermissionsDetail",
    "web.apps.allowDowngrade",
    "web.apps.allowDowngradeDetail",
    "web.apps.allowTest",
    "web.apps.allowTestDetail",
    # APK install completion landed after the reviewed 2026-07-18 translation
    # pass. All six PO catalogs own these msgids and intentionally use the
    # English source fallback until translators review them.
    "web.apps.forceQueryable",
    "web.apps.forceQueryableDetail",
    "web.apps.bypassLowTargetSdk",
    "web.apps.bypassLowTargetSdkDetail",
    "web.apps.installOptions",
    "web.apps.installGuard",
    "web.apps.picking",
    "web.apps.installing",
    "web.apps.cancelling",
    "web.apps.cancelInstall",
    "web.apps.installCancelled",
    "web.apps.installFailed",
    "web.apps.installSucceeded",
    "web.apps.inventoryRefreshFailed",
    # Device inspection landed after the reviewed 2026-07-18 translation pass.
    # All six PO catalogs own these msgids; non-English catalogs intentionally
    # use the English source fallback until translators review them.
    "web.device.inspectTitle",
    "web.device.inspectDetail",
    "web.device.inspectGuard",
    "web.device.inspectProperties",
    "web.device.inspectPropertiesDetail",
    "web.device.inspectScreenXml",
    "web.device.inspectScreenXmlDetail",
    "web.device.inspectBootloaderVersions",
    "web.device.inspectBootloaderVersionsDetail",
    "web.device.inspectPifProfile",
    "web.device.inspectPifProfileDetail",
    "web.device.inspectRunning",
    "web.device.inspectCancelling",
    "web.device.inspectCancel",
    "web.device.inspectCancelled",
    "web.device.inspectFailed",
    "web.device.inspectCopy",
    "web.device.inspectCopied",
    "web.device.inspectCopyFailed",
    "web.device.inspectManufacturer",
    "web.device.inspectSecurityPatch",
    "web.device.inspectEntries",
    "web.device.inspectRedacted",
    "web.device.inspectNodes",
    "web.device.inspectRedactedFields",
    "web.device.inspectDigest",
    "web.device.inspectCurrentVersion",
    "web.device.inspectSource",
    "web.device.inspectActiveSlot",
    "web.device.inspectAblSource",
    "web.device.inspectMatchesAndroid",
    "web.device.inspectSlot",
    "web.device.inspectExtractedVersion",
    "web.device.inspectFullVersion",
    # Boot inventory is source-fallback until the next reviewed translation pass.
    "web.boot.inventoryTitle",
    "web.boot.inventoryDetail",
    "web.boot.inventoryEmpty",
    "web.boot.inventoryLoad",
    "web.boot.import",
    "web.boot.imageFiles",
    "web.boot.partition",
    "web.boot.use",
    "web.boot.patched",
    "web.boot.stock",
    "web.boot.integrityFailed",
    "web.boot.provenance",
    "web.boot.deletePrompt",
    "web.boot.deleteConfirm",
    "web.boot.deleteFailed",
    "web.boot.cleanupDeferred",
    "web.root.appChannel",
    "web.root.appCatalog",
    "web.root.appDownload",
    "web.root.appAvailable",
    # Typed Scrcpy options landed after the reviewed 2026-07-19 translation
    # pass. They use source fallback until all five translated catalogs are
    # reviewed together.
    "web.tools.scrcpyOptionsDetail",
    "web.tools.scrcpyMaxSize",
    "web.tools.scrcpyMaxFps",
    "web.tools.scrcpyBitRate",
    "web.tools.scrcpyWindowOptions",
    "web.tools.scrcpyFullscreen",
    "web.tools.scrcpyAlwaysOnTop",
    "web.tools.scrcpyStayAwake",
    "web.tools.scrcpyTurnScreenOff",
    "web.tools.scrcpyShowTouches",
    "web.tools.scrcpyNoAudio",
    "web.tools.scrcpyLaunch",
    "web.tools.scrcpyInstall",
    "web.tools.scrcpyInstallDetail",
}
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
                    self.assertFalse(entry.fuzzy, "translation is fuzzy")
                    if entry.msgctxt in EXPECTED_SOURCE_FALLBACK_CONTEXTS:
                        self.assertFalse(
                            entry.msgstr.strip(),
                            "unreviewed translation must use the documented source fallback",
                        )
                        continue
                    self.assertTrue(entry.msgstr.strip(), "translation is empty")
                    self.assertEqual(
                        sorted(PLACEHOLDER_PATTERN.findall(entry.msgid)),
                        sorted(PLACEHOLDER_PATTERN.findall(entry.msgstr)),
                    )


if __name__ == "__main__":
    unittest.main()
