import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.verify_ui_smoke import main as verify_main
from ui_smoke_contract import (
    UI_SMOKE_TASK_ROUTES,
    UiSmokeReceiptError,
    create_ui_smoke_receipt,
    load_ui_smoke_receipt,
    normalized_architecture,
    normalized_platform,
    validate_ui_smoke_receipt,
    write_ui_smoke_receipt,
)

JOURNEY = {
    "taskRoutes": list(UI_SMOKE_TASK_ROUTES),
    "keyboardRouteNavigation": True,
    "focusTransferredToHeading": True,
    "persistentDocument": True,
}


class UiSmokeReceiptTests(unittest.TestCase):
    def test_receipt_is_atomic_closed_and_self_validating(self):
        with tempfile.TemporaryDirectory(prefix="pf-ui-smoke-") as directory:
            destination = Path(directory) / "receipt.json"
            written = write_ui_smoke_receipt(
                destination,
                bridge_revision=7,
                journey=JOURNEY,
            )
            loaded = load_ui_smoke_receipt(destination)

            self.assertEqual(written, loaded)
            self.assertEqual(7, loaded["bridgeRevision"])
            self.assertEqual([], list(Path(directory).glob("*.tmp")))
            self.assertEqual(loaded, validate_ui_smoke_receipt(loaded))

    def test_validation_rejects_unknown_fields_and_unproven_shutdown(self):
        receipt = create_ui_smoke_receipt(bridge_revision=0, journey=JOURNEY)
        receipt["unexpected"] = True
        with self.assertRaisesRegex(UiSmokeReceiptError, "closed schema"):
            validate_ui_smoke_receipt(receipt)

        receipt = create_ui_smoke_receipt(bridge_revision=0, journey=JOURNEY)
        receipt["cleanShutdown"] = False
        with self.assertRaisesRegex(UiSmokeReceiptError, "clean shutdown"):
            validate_ui_smoke_receipt(receipt)

    def test_receipt_rejects_incomplete_or_unproven_ui_journeys(self):
        incomplete = {**JOURNEY, "taskRoutes": list(UI_SMOKE_TASK_ROUTES[:-1])}
        with self.assertRaisesRegex(UiSmokeReceiptError, "every task route"):
            create_ui_smoke_receipt(bridge_revision=0, journey=incomplete)

        receipt = create_ui_smoke_receipt(bridge_revision=0, journey=JOURNEY)
        receipt["focusTransferredToHeading"] = False
        with self.assertRaisesRegex(UiSmokeReceiptError, "focus transfer"):
            validate_ui_smoke_receipt(receipt)

    def test_platform_and_architecture_aliases_are_normalized(self):
        with patch("ui_smoke_contract.platform.system", return_value="Darwin"):
            self.assertEqual("macos", normalized_platform())
        for machine, expected in (("AMD64", "x86_64"), ("aarch64", "arm64")):
            with self.subTest(machine=machine), patch(
                "ui_smoke_contract.platform.machine",
                return_value=machine,
            ):
                self.assertEqual(expected, normalized_architecture())

    def test_verifier_checks_expected_native_target(self):
        with tempfile.TemporaryDirectory(prefix="pf-ui-smoke-cli-") as directory:
            destination = Path(directory) / "receipt.json"
            write_ui_smoke_receipt(
                destination,
                bridge_revision=1,
                journey=JOURNEY,
            )
            self.assertEqual(
                0,
                verify_main(
                    [
                        "--report",
                        str(destination),
                        "--expect-platform",
                        normalized_platform(),
                        "--expect-architecture",
                        normalized_architecture(),
                    ]
                ),
            )

            payload = json.loads(destination.read_text(encoding="utf-8"))
            payload["bridgeVersion"] = 1
            destination.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(
                1,
                verify_main(
                    [
                        "--report",
                        str(destination),
                        "--expect-platform",
                        normalized_platform(),
                        "--expect-architecture",
                        normalized_architecture(),
                    ]
                ),
            )


if __name__ == "__main__":
    unittest.main()
