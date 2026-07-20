import unittest
from pathlib import Path

PACKAGE_WORKFLOWS = {
    Path(".github/workflows/windows.yml"): ".\\build.bat",
    Path(".github/workflows/windows_2019.yml"): ".\\build.bat",
    Path(".github/workflows/windows-arm64.yml"): "build-on-win-arm64.spec",
    Path(".github/workflows/mac.yml"): "./build.sh",
    Path(".github/workflows/ubuntu_24_04.yml"): "./build.sh",
    Path(".github/workflows/ubuntu_22_04.yml"): "./build.sh",
    Path(".github/workflows/appimage-x86_64.yml"): "./build.sh",
}

PACKAGE_SPECS = (
    Path("build-on-win.spec"),
    Path("build-on-win-arm64.spec"),
    Path("build-on-mac.spec"),
    Path("build-on-mac-intel-only.spec"),
    Path("build-on-linux.spec"),
)

FRONTEND_BUILDER = Path("scripts/build_frontend.py")
LOCAL_BUILD_SCRIPTS = (Path("build.sh"), Path("build.bat"))

LOCALE_ASSETS = (
    "manifest.json",
    "en.json",
    "es.json",
    "fr.json",
    "it.json",
    "zh_CN.json",
    "zh_TW.json",
)
TERMINAL_ASSETS = (
    "ui/web/dist/assets/adb-terminal.js",
    "ui/web/dist/assets/adb-terminal.css",
)
PACKAGED_PTY_WORKFLOWS = (
    Path(".github/workflows/windows.yml"),
    Path(".github/workflows/windows-arm64.yml"),
    Path(".github/workflows/mac.yml"),
    Path(".github/workflows/ubuntu_24_04.yml"),
    Path(".github/workflows/ubuntu_22_04.yml"),
    Path(".github/workflows/appimage-x86_64.yml"),
)


class PackagedWebAssetTests(unittest.TestCase):
    def test_every_desktop_package_builds_react_before_pyinstaller(self):
        builder = FRONTEND_BUILDER.read_text(encoding="utf-8")
        self.assertIn('EXPECTED_NODE_VERSION = "v24.14.0"', builder)
        self.assertIn('EXPECTED_PNPM_VERSION = "11.9.0"', builder)
        self.assertIn('"install", "--frozen-lockfile"', builder)
        self.assertIn('"build"', builder)
        self.assertIn("verify_react_bridge_commands.py", builder)
        self.assertIn("export_gettext_json.py", builder)
        self.assertIn("verify_webview_bundle.py", builder)

        for path, package_command in PACKAGE_WORKFLOWS.items():
            source = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertIn("node-version: '24.14.0'", source)
                self.assertIn("corepack prepare pnpm@11.9.0 --activate", source)
                self.assertIn("scripts/build_frontend.py", source)
                self.assertIn("ui/web/dist/index.html", source)
                self.assertLess(
                    source.index("scripts/build_frontend.py"),
                    source.index(package_command),
                )

    def test_local_packaging_scripts_prebuild_or_reverify_before_pyinstaller(self):
        for path in LOCAL_BUILD_SCRIPTS:
            source = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertIn("scripts/build_frontend.py", source.replace("\\", "/"))
                self.assertIn("PIXELFLASHER_FRONTEND_PREBUILT", source)
                self.assertIn("--check-only", source)
                self.assertIn("verify_platform_tools_catalog.py", source)
                self.assertLess(
                    source.replace("\\", "/").index("scripts/build_frontend.py"),
                    source.casefold().index("pyinstaller"),
                )

    def test_v10_release_builds_require_the_signed_platform_tools_matrix(self):
        shell_source = Path("build.sh").read_text(encoding="utf-8")
        windows_source = Path(".github/workflows/windows.yml").read_text(encoding="utf-8")
        arm_source = Path(".github/workflows/windows-arm64.yml").read_text(encoding="utf-8")
        self.assertIn("GITHUB_REF:-} == refs/tags/v10.*", shell_source)
        self.assertIn("PIXELFLASHER_REQUIRE_SIGNED_PLATFORM_TOOLS=1", shell_source)
        self.assertIn("PIXELFLASHER_REQUIRE_SIGNED_PLATFORM_TOOLS", windows_source)
        self.assertIn("refs/tags/v10.*", windows_source)
        self.assertIn("refs/tags/v10.*", arm_source)
        self.assertIn("verify_platform_tools_catalog.py", arm_source)

    def test_every_desktop_package_inspects_the_final_pyinstaller_archive(self):
        for path in PACKAGE_WORKFLOWS:
            source = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertTrue(
                    "archive_viewer" in source or "pyi-archive-viewer" in source
                )
                self.assertIn("ui/web/dist/index.html", source)
                for terminal_asset in TERMINAL_ASSETS:
                    self.assertIn(terminal_asset, source)
                for locale_asset in LOCALE_ASSETS:
                    self.assertIn(f"ui/web/dist/i18n/{locale_asset}", source)

    def test_every_pyinstaller_spec_bundles_the_built_web_tree(self):
        for path in PACKAGE_SPECS:
            source = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertIn("'ui/web/dist', 'ui/web/dist'", source)
                self.assertIn(
                    "'resources/platform-tools', 'resources/platform-tools'",
                    source,
                )

    def test_every_release_platform_executes_the_packaged_pty_smoke(self):
        for path in PACKAGED_PTY_WORKFLOWS:
            source = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertIn("--pty-smoke-report", source)
                self.assertIn("--pty-smoke-timeout", source)
                self.assertIn("scripts/verify_pty_smoke.py", source)


if __name__ == "__main__":
    unittest.main()
