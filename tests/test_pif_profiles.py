from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from pixelflasher_core.pif_profiles import (
    PifFavoritesRepository,
    PifProfileError,
    PifProfileTransformer,
)


class PifProfileTransformerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.transformer = PifProfileTransformer()

    def test_normalizes_props_derives_fingerprint_fields_and_sets_first_api(self):
        result = self.transformer.transform(
            "ro.product.manufacturer=Google\n"
            "ro.product.model=Pixel 9\n"
            "ro.build.fingerprint=google/tokay/tokay:16/BP2A.250705.008/123:user/release-keys\n"
            "custom.keep=yes\n",
            input_format="prop", output_format="json", normalize=True,
            keep_unknown=False, sort_keys=True, first_api=35,
        )
        value = json.loads(result.content)
        self.assertEqual(value["MANUFACTURER"], "Google")
        self.assertEqual(value["MODEL"], "Pixel 9")
        self.assertEqual(value["BRAND"], "google")
        self.assertEqual(value["PRODUCT"], "tokay")
        self.assertEqual(value["DEVICE"], "tokay")
        self.assertEqual(value["ID"], "BP2A.250705.008")
        self.assertEqual(value["FIRST_API_LEVEL"], "35")
        self.assertNotIn("custom.keep", value)
        self.assertEqual(result.sha256, hashlib.sha256(result.content.encode()).hexdigest())
        self.assertTrue(result.to_public_dict()["bounded"])

    def test_round_trips_json_and_prop_without_losing_scalar_fields(self):
        prop = self.transformer.transform(
            '{"BRAND":"google","MODEL":"Pixel 9","FIRST_API_LEVEL":35}',
            input_format="json", output_format="prop", sort_keys=True,
        )
        self.assertEqual(prop.content, "BRAND=google\nFIRST_API_LEVEL=35\nMODEL=Pixel 9\n")
        restored = self.transformer.transform(
            prop.content, input_format="prop", output_format="json", sort_keys=True,
        )
        self.assertEqual(json.loads(restored.content), {
            "BRAND": "google", "FIRST_API_LEVEL": "35", "MODEL": "Pixel 9",
        })

    def test_framework_patcher_uses_fixed_allow_list(self):
        result = self.transformer.transform(
            '{"BRAND":"google","PRIVATE":"secret"}',
            input_format="json", output_format="framework_patcher",
        )
        self.assertIn('map.put("BRAND", "google");', result.content)
        self.assertNotIn("PRIVATE", result.content)
        self.assertEqual(result.content.count("map.put"), 12)

    def test_rejects_nested_duplicate_control_and_oversized_documents(self):
        invalid = (
            ('{"nested":{"value":1}}', "json"),
            ("BRAND=one\nBRAND=two\n", "prop"),
            ("BRAND=goo\x00gle", "prop"),
            ("BRAND=" + "x" * (32 * 1024), "prop"),
        )
        for content, input_format in invalid:
            with self.subTest(content=content[:20]):
                with self.assertRaises(PifProfileError):
                    self.transformer.transform(
                        content, input_format=input_format, output_format="json"  # type: ignore[arg-type]
                    )

    def test_rejects_invalid_first_api_and_multiline_prop_output(self):
        for value in (0, 100, True):
            with self.subTest(value=value), self.assertRaises(PifProfileError):
                self.transformer.transform(
                    '{"BRAND":"google"}', input_format="json", output_format="json",
                    first_api=value,  # type: ignore[arg-type]
                )
        with self.assertRaises(PifProfileError):
            self.transformer.transform(
                '{"BRAND":"line\\nvalue"}', input_format="json", output_format="prop"
            )


class PifFavoritesRepositoryTests(unittest.TestCase):
    def test_save_get_list_delete_and_reload_are_hash_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "favorites.json"
            repository = PifFavoritesRepository(path)
            favorite = repository.save("Pixel 9", '{"MODEL":"Pixel 9","BRAND":"google"}')
            self.assertEqual(repository.revision, 1)
            self.assertEqual(repository.get(favorite.favorite_id), favorite)
            self.assertEqual(repository.list(), (favorite,))
            self.assertEqual(favorite.to_metadata_dict()["size"], len(favorite.content.encode()))
            reopened = PifFavoritesRepository(path)
            self.assertEqual(reopened.get(favorite.favorite_id), favorite)
            self.assertEqual(reopened.delete(favorite.favorite_id), favorite)
            self.assertEqual(reopened.revision, 2)
            self.assertEqual(reopened.list(), ())

    def test_duplicate_content_updates_label_without_duplicate_row(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = PifFavoritesRepository(Path(directory) / "favorites.json")
            first = repository.save("First", '{"BRAND":"google","MODEL":"Pixel"}')
            second = repository.save("Second", '{ "MODEL": "Pixel", "BRAND": "google" }')
            self.assertEqual(first.favorite_id, second.favorite_id)
            self.assertEqual(first.created_at, second.created_at)
            self.assertEqual(repository.list()[0].label, "Second")
            self.assertEqual(repository.revision, 2)

    def test_imports_valid_legacy_rows_once_and_skips_invalid_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy = root / "favorite_pifs.json"
            legacy.write_bytes(json.dumps({
                "old": {"label": "Legacy Pixel", "date_added": "2025-01-02 03:04:05",
                        "pif": {"BRAND": "google", "MODEL": "Pixel"}},
                "nested": {"label": "Bad", "pif": {"nested": {"bad": True}}},
                "bad": {"label": "\u0000", "pif": {"BRAND": "bad"}},
            }, ensure_ascii=False).encode("latin-1"))
            path = root / "modern" / "favorites.json"
            repository = PifFavoritesRepository(path, legacy_path=legacy)
            self.assertEqual([item.label for item in repository.list()], ["Legacy Pixel"])
            self.assertEqual(repository.revision, 1)
            legacy.write_text("{}", encoding="utf-8")
            self.assertEqual(
                [item.label for item in PifFavoritesRepository(path, legacy_path=legacy).list()],
                ["Legacy Pixel"],
            )

    def test_corrupt_or_tampered_repository_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "favorites.json"
            path.write_text('{"schemaVersion":1}', encoding="utf-8")
            with self.assertRaises(PifProfileError):
                PifFavoritesRepository(path)
            content = '{\n  "BRAND": "google"\n}\n'
            path.write_text(json.dumps({"schemaVersion": 1, "revision": 1, "favorites": [{
                "favoriteId": "a" * 64, "label": "Tampered",
                "createdAt": "2025-01-01T00:00:00+00:00", "sha256": "a" * 64,
                "content": content,
            }]}), encoding="utf-8")
            with self.assertRaises(PifProfileError):
                PifFavoritesRepository(path)

    def test_label_and_ids_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = PifFavoritesRepository(Path(directory) / "favorites.json")
            for label in ("", "x" * 129, "bad\nlabel"):
                with self.subTest(label=label[:10]), self.assertRaises(PifProfileError):
                    repository.save(label, '{"BRAND":"google"}')
            with self.assertRaises(PifProfileError):
                repository.delete("../favorite")


if __name__ == "__main__":
    unittest.main()
