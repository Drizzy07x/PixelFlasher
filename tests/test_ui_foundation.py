import unittest

from ui.components import DeviceStatus, FirmwareInfo, QuickAction, StatusLevel
from ui.icons import ICON_REGISTRY, load_svg, validate_icon_registry
from ui.theme import get_theme, status_color


class UiFoundationTests(unittest.TestCase):
    def test_themes_load(self):
        self.assertEqual(get_theme("light").name, "light")
        self.assertEqual(get_theme("dark").name, "dark")
        self.assertNotEqual(get_theme("light").palette.background, get_theme("dark").palette.background)

    def test_status_color_maps_known_states(self):
        self.assertEqual(status_color("ready"), get_theme("light").palette.success)
        self.assertEqual(status_color("failed"), get_theme("light").palette.danger)

    def test_icon_registry_is_complete(self):
        self.assertGreaterEqual(len(ICON_REGISTRY), 12)
        self.assertEqual(validate_icon_registry(), [])
        self.assertIn("<svg", load_svg("dashboard"))

    def test_view_models_are_safe(self):
        device = DeviceStatus(display_name="Pixel", serial="ABCDEF123456")
        self.assertTrue(device.connected)
        self.assertIn("…", device.redacted_serial())

        firmware = FirmwareInfo(path="/tmp/factory.zip", size_bytes=1024 * 1024)
        self.assertEqual(firmware.filename, "factory.zip")
        self.assertIn("MB", firmware.size_label)

        action = QuickAction("flash", "Flash", "Flash selected image", "flash", StatusLevel.WARNING, dangerous=True)
        self.assertTrue(action.requires_confirmation())


if __name__ == "__main__":
    unittest.main()
