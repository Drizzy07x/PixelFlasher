import unittest

try:
    from ui.pages.dashboard import _dashboard_action_button_label, _dashboard_quick_actions
except ModuleNotFoundError as exc:
    if exc.name == "wx":
        raise unittest.SkipTest("wxPython is not available")
    raise


class ModernDashboardCopySafetyTests(unittest.TestCase):
    def test_quick_action_titles_are_legacy_explicit(self):
        titles = {action.key: action.title for action in _dashboard_quick_actions()}

        self.assertEqual("Open legacy patch", titles["patch"])
        self.assertEqual("Open legacy flash", titles["flash"])
        self.assertEqual("Use legacy scan", titles["scan"])
        self.assertEqual("Create diagnostics", titles["support"])

    def test_button_labels_do_not_use_generic_run(self):
        labels = [_dashboard_action_button_label(action.key) for action in _dashboard_quick_actions()]

        self.assertNotIn("Run", labels)
        self.assertIn("Use legacy", labels)
        self.assertIn("Open guarded flow", labels)
        self.assertIn("Create diagnostics", labels)

    def test_flash_action_stays_marked_dangerous(self):
        actions = {action.key: action for action in _dashboard_quick_actions()}

        self.assertTrue(actions["flash"].dangerous)
        self.assertTrue(actions["flash"].requires_confirmation())


if __name__ == "__main__":
    unittest.main()
