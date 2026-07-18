import unittest
from pathlib import Path

UBUNTU_24 = Path(".github/workflows/ubuntu_24_04.yml")
UBUNTU_SMOKE = Path(".github/workflows/ubuntu-smoke.yml")
UBUNTU_22 = Path(".github/workflows/ubuntu_22_04.yml")
APPIMAGE = Path(".github/workflows/appimage-x86_64.yml")
LINUX_WORKFLOWS = (UBUNTU_24, UBUNTU_SMOKE, UBUNTU_22, APPIMAGE)


class LinuxDeliveryContractTests(unittest.TestCase):
    def test_linux_workflows_keep_their_job_contracts(self):
        for path in LINUX_WORKFLOWS:
            with self.subTest(path=path):
                source = path.read_text(encoding="utf-8")
                self.assertIn("\njobs:\n", source)
                self.assertIn("runs-on: ubuntu-", source)

    def test_system_wx_jobs_install_the_separate_webview_package(self):
        for path in (UBUNTU_24, UBUNTU_SMOKE):
            source = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertIn("python3-wxgtk4.0", source)
                self.assertIn("python3-wxgtk-webview4.0", source)

    def test_every_linux_ui_job_constructs_the_webkit_backend(self):
        for path in LINUX_WORKFLOWS:
            source = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertIn("import wx.html2 as html2", source)
                self.assertIn("WebViewBackendWebKit", source)
                self.assertIn("WebView.IsBackendAvailable", source)
                self.assertIn("html2.WebView.New", source)
                self.assertIn("xvfb-run", source)

    def test_source_smoke_launches_the_unflagged_default_entrypoint(self):
        source = UBUNTU_SMOKE.read_text(encoding="utf-8")

        self.assertIn("needs: frontend_smoke", source)
        self.assertIn("actions/download-artifact@v7", source)
        self.assertIn("actions/upload-artifact@v7", source)
        self.assertIn("path: ui/web/dist", source)
        self.assertEqual(2, source.count("needs: frontend_smoke"))
        self.assertEqual(2, source.count("actions/download-artifact@v7"))
        self.assertEqual(1, source.count("actions/upload-artifact@v7"))
        downloads = [
            position
            for position in range(len(source))
            if source.startswith("actions/download-artifact@v7", position)
        ]
        self.assertLess(downloads[0], source.index("python PixelFlasher.py --self-test"))
        self.assertLess(downloads[1], source.index("Launch the real default modern entrypoint"))
        self.assertIn("Launch the real default modern entrypoint", source)
        self.assertIn('"$2" PixelFlasher.py >"$3" 2>&1 &', source)
        self.assertIn(
            'xdotool search --sync --onlyvisible --name "PixelFlasher"', source
        )
        self.assertIn("Modern UI WebView is not available", source)

    def test_each_linux_artifact_is_launched_through_its_default_entrypoint(self):
        expected_artifacts = {
            UBUNTU_24: "dist/PixelFlasher_Ubuntu_24_04",
            UBUNTU_22: "dist/PixelFlasher_Ubuntu_22_04",
            APPIMAGE: "dist/PixelFlasher-x86_64.AppImage",
        }

        for path, artifact in expected_artifacts.items():
            source = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertIn(artifact, source)
                self.assertIn(
                    'xdotool search --sync --onlyvisible --name "PixelFlasher"',
                    source,
                )
                self.assertIn("Modern UI WebView is not available", source)
                self.assertNotIn(f"{artifact} --modern-", source)

    def test_each_linux_artifact_builds_and_bundles_the_locked_react_ui(self):
        for path in (UBUNTU_24, UBUNTU_22, APPIMAGE):
            source = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertIn("node-version: '24.14.0'", source)
                self.assertIn("pnpm@11.9.0", source)
                self.assertIn("scripts/build_frontend.py", source)
                self.assertIn("PIXELFLASHER_FRONTEND_PREBUILT=1 ./build.sh", source)
                self.assertLess(
                    source.index("scripts/build_frontend.py"),
                    source.index("./build.sh"),
                )

    def test_frontend_smoke_uses_locked_tooling_and_packages_gettext(self):
        source = UBUNTU_SMOKE.read_text(encoding="utf-8")

        self.assertIn("frontend_smoke:", source)
        self.assertIn("node-version: '24.14.0'", source)
        self.assertIn("pnpm@11.9.0", source)
        self.assertIn("pnpm install --frozen-lockfile", source)
        self.assertIn("pnpm test", source)
        self.assertIn("pnpm build", source)
        self.assertIn("scripts/verify_react_bridge_commands.py", source)
        self.assertIn(
            "--output-dir ui/web/public/i18n --check",
            source,
        )
        self.assertIn(
            "--output-dir ui/web/dist/i18n --check",
            source,
        )
        self.assertIn("scripts/verify_webview_bundle.py ui/web/dist", source)

    def test_obsolete_preview_flags_and_modules_never_return_to_workflows(self):
        forbidden = (
            "--modern-dashboard-preview",
            "--flash-wizard-preview",
            "--flash-wizard-demo",
            "ui/theme.py",
            "ui/icons.py",
            "ui/components/models.py",
            "ui/pages/dashboard.py",
            "ui/pages/dashboard_app.py",
            "ui/pages/dashboard_compact.py",
            "ui/pages/flash_wizard.py",
            "ui/pages/flash_wizard_app.py",
            "ui/pages/flash_wizard_demo.py",
            "ui/pages/flash_wizard_details.py",
            "ui/pages/flash_wizard_model.py",
            "ui/pages/flash_wizard_state_adapter.py",
        )
        for path in Path(".github/workflows").glob("*.yml"):
            source = path.read_text(encoding="utf-8")
            for value in forbidden:
                with self.subTest(path=path, value=value):
                    self.assertNotIn(value, source)


if __name__ == "__main__":
    unittest.main()
