import unittest

from ui.pages.modern_action_bridge import action_by_id
from ui.pages.modern_action_feedback import (
    BLOCKED,
    SAFE,
    WARNING,
    action_completed_feedback,
    action_started_feedback,
    action_unavailable_feedback,
    blocked_navigation_feedback,
    disabled_action_feedback,
    guarded_action_canceled_feedback,
    navigation_action_feedback,
)


class ModernActionFeedbackTests(unittest.TestCase):
    def test_navigation_feedback_is_short_and_product_ready(self):
        blocked = blocked_navigation_feedback()
        action = action_by_id("open_modern_shell")
        opened = navigation_action_feedback(action)

        self.assertEqual(BLOCKED, blocked.tone)
        self.assertEqual("Navigation stayed inside the PixelFlasher workspace.", blocked.message)
        self.assertEqual(SAFE, opened.tone)
        self.assertEqual("Open Device: opened.", opened.message)

    def test_unavailable_and_disabled_feedback_stay_blocked(self):
        disabled = disabled_action_feedback(action_by_id("disabled_wipe"))
        unavailable = action_unavailable_feedback(action_by_id("scan_devices"))

        self.assertEqual(BLOCKED, disabled.tone)
        self.assertIn("select the required device or firmware first", disabled.message)
        self.assertEqual(BLOCKED, unavailable.tone)
        self.assertIn("connect the required state", unavailable.message)

    def test_guarded_feedback_distinguishes_cancel_and_completion(self):
        action = action_by_id("flash_device")

        canceled = guarded_action_canceled_feedback(action)
        started = action_started_feedback(action)
        completed = action_completed_feedback(action)

        self.assertEqual(WARNING, canceled.tone)
        self.assertEqual("Flash Device: canceled.", canceled.message)
        self.assertEqual(WARNING, started.tone)
        self.assertEqual("Flash Device: working...", started.message)
        self.assertEqual(SAFE, completed.tone)
        self.assertEqual("Flash Device: complete.", completed.message)


if __name__ == "__main__":
    unittest.main()
