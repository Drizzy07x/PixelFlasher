import tempfile
import unittest
from pathlib import Path

from scripts.verify_webview_bundle import verify_bundle


class WebViewBundleVerifierTests(unittest.TestCase):
    def _bundle(self, root: Path, *, html: str, script: str = "window.ready = true;") -> Path:
        assets = root / "assets"
        assets.mkdir(parents=True)
        (root / "index.html").write_text(html, encoding="utf-8")
        (assets / "app.js").write_text(script, encoding="utf-8")
        (assets / "app.css").write_text("body { background: #000; }", encoding="utf-8")
        return root

    @staticmethod
    def _html(script_type: str = "") -> str:
        type_attribute = f' type="{script_type}"' if script_type else ""
        return (
            "<!doctype html><html><head>"
            '<link rel="stylesheet" href="./assets/app.css">'
            "</head><body>"
            f'<script{type_attribute} src="./assets/app.js"></script>'
            "</body></html>"
        )

    def test_accepts_classic_local_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = self._bundle(Path(directory), html=self._html())
            checked = verify_bundle(bundle)
            self.assertEqual(
                ["assets/app.css", "assets/app.js", "index.html"],
                [path.relative_to(bundle).as_posix() for path in checked],
            )

    def test_rejects_module_script_and_import_meta(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module_bundle = self._bundle(root / "module", html=self._html("module"))
            with self.assertRaisesRegex(ValueError, "type=module"):
                verify_bundle(module_bundle)

            import_meta_bundle = self._bundle(
                root / "import-meta",
                html=self._html(),
                script="const base = import . meta.url;",
            )
            with self.assertRaisesRegex(ValueError, "import.meta"):
                verify_bundle(import_meta_bundle)

    def test_rejects_remote_missing_and_escaping_assets(self):
        invalid_references = (
            "https://example.test/app.js",
            "./assets/missing.js",
            "../outside.js",
        )
        for reference in invalid_references:
            with self.subTest(reference=reference), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                html = self._html().replace("./assets/app.js", reference)
                bundle = self._bundle(root / "bundle", html=html)
                with self.assertRaises(ValueError):
                    verify_bundle(bundle)

    def test_rejects_remote_or_missing_css_urls(self):
        for value in ("https://example.test/font.woff2", "./missing.png"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                bundle = self._bundle(Path(directory), html=self._html())
                (bundle / "assets" / "app.css").write_text(
                    f"body {{ background-image: url('{value}'); }}",
                    encoding="utf-8",
                )
                with self.assertRaises(ValueError):
                    verify_bundle(bundle)


if __name__ == "__main__":
    unittest.main()
