import json
import tempfile
import unittest
from pathlib import Path

from firmware_smoke_contract import (
    FirmwareSmokeError,
    run_packaged_firmware_smoke,
    validate_firmware_smoke_receipt,
)
from scripts.verify_firmware_smoke import main as verify_main
from ui_smoke_contract import normalized_architecture, normalized_platform


class FirmwareSmokeTests(unittest.TestCase):
    def test_packaged_cycle_is_closed_route_free_and_self_validating(self):
        with tempfile.TemporaryDirectory(prefix="pf-firmware-smoke-test-") as directory:
            report = Path(directory) / "receipt.json"
            receipt = run_packaged_firmware_smoke(report)

            self.assertEqual(receipt, json.loads(report.read_text(encoding="utf-8")))
            self.assertEqual("firmware_selected", receipt["selectCode"])
            self.assertEqual("firmware_processed", receipt["processCode"])
            self.assertEqual("user_confirmed", receipt["trustStatus"])
            self.assertEqual("init_boot", receipt["bootFlavor"])
            serialized = json.dumps(receipt)
            self.assertNotIn(str(Path(directory)), serialized)
            self.assertNotIn("factory-smoke.zip", serialized)
            self.assertEqual(receipt, validate_firmware_smoke_receipt(receipt))

    def test_receipt_rejects_unknown_fields_and_unproven_boundaries(self):
        with tempfile.TemporaryDirectory(prefix="pf-firmware-smoke-test-") as directory:
            report = Path(directory) / "receipt.json"
            receipt = run_packaged_firmware_smoke(report)

            hostile = {**receipt, "path": "C:/private/firmware.zip"}
            with self.assertRaisesRegex(FirmwareSmokeError, "closed schema"):
                validate_firmware_smoke_receipt(hostile)

            for field in ("grantBoundary", "confirmationBound", "cleanShutdown"):
                with self.subTest(field=field):
                    invalid = {**receipt, field: False}
                    with self.assertRaises(FirmwareSmokeError):
                        validate_firmware_smoke_receipt(invalid)

    def test_verifier_checks_the_native_target(self):
        with tempfile.TemporaryDirectory(prefix="pf-firmware-smoke-test-") as directory:
            report = Path(directory) / "receipt.json"
            run_packaged_firmware_smoke(report)

            self.assertEqual(
                0,
                verify_main(
                    [
                        "--report",
                        str(report),
                        "--expect-platform",
                        normalized_platform(),
                        "--expect-architecture",
                        normalized_architecture(),
                    ]
                ),
            )
            payload = json.loads(report.read_text(encoding="utf-8"))
            payload["trustStatus"] = "confirmation_required"
            report.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(
                1,
                verify_main(
                    [
                        "--report",
                        str(report),
                        "--expect-platform",
                        normalized_platform(),
                        "--expect-architecture",
                        normalized_architecture(),
                    ]
                ),
            )


if __name__ == "__main__":
    unittest.main()
