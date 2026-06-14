import unittest

from ui.pages.modern_action_bridge import action_by_id
from ui.pages.modern_action_feedback import (
    BLOCKED,
    SAFE,
    WARNING,
    blocked_navigation_feedback,
    classic_handoff_feedback,
    disabled_action_feedback,
    guarded_action_canceled_feedback,
    guarded_action_opening_feedback,
    preview_action_feedback,
)


class ModernActionFeedbackTests(unittest.TestCase):
    def test_navigation_and_classic_handoff_feedback_are_safe_copy(self):
        blocked = blocked_navigation_feedback()
        classic = classic_handoff_feedback()

        self.assertEqual(BLOCKED, blocked.tone)
        self.assertIn("Blocked unknown or external navigation", blocked.message)
        self.assertIn("No action was run", blocked.message)
        self.assertEqual(WARNING, classic.tone)
        self.assertIn("guarded legacy flow", classic.message)

    def test_preview_feedback_describes_no_device_changes(self):
        action = action_by_id("open_modern_shell")

        self.assertIsNotNone(action)
        feedback = preview_action_feedback(action)
        self.assertEqual(SAFE, feedback.tone)
        self.assertIn("Open Modern Shell", feedback.message)
        self.assertIn("No device changes", feedback.message)

    def test_disabled_feedback_stays_blocked(self):
        action = action_by_id("disabled_wipe")

        self.assertIsNotNone(action)
        feedback = disabled_action_feedback(action)
        self.assertEqual(BLOCKED, feedback.tone)
        self.assertIn("disabled in Modern UI", feedback.message)
        self.assertIn("No device changes", feedback.message)

    def test_guarded_feedback_distinguishes_cancel_and_opening(self):
        action = action_by_id("guarded_legacy_flash_flow")

        self.assertIsNotNone(action)
        canceled = guarded_action_canceled_feedback(action)
        opening = guarded_action_opening_feedback(action)
        self.assertEqual(WARNING, canceled.tone)
        self.assertEqual(WARNING, opening.tone)
        self.assertIn("canceled", canceled.message)
        self.assertIn("No legacy flow opened", canceled.message)
        self.assertIn("opening existing guarded legacy flow", opening.message)


if __name__ == "__main__":
    unittest.main()
