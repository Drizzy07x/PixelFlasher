import json
import tempfile
import unittest
from pathlib import Path

from scripts.verify_support_smoke import main as verify_main
from support_smoke_contract import (
    SupportSmokeError,
    run_packaged_support_smoke,
    validate_support_smoke_receipt,
)
from ui_smoke_contract import normalized_architecture, normalized_platform


class SupportSmokeTests(unittest.TestCase):
    def test_packaged_cycle_proves_v1_v2_crypto_redaction_and_tamper_rejection(self):
        with tempfile.TemporaryDirectory(prefix="pf-support-smoke-test-") as directory:
            report = Path(directory) / "receipt.json"
            receipt = run_packaged_support_smoke(report)

            self.assertEqual(receipt, json.loads(report.read_text(encoding="utf-8")))
            for field in (
                "v2Write", "v2Read", "v1Read", "rsaOaepSha256", "aes256Gcm",
                "redactionVerified", "tamperRejected", "routeFree", "processComplete",
            ):
                with self.subTest(field=field):
                    self.assertIs(receipt[field], True)
            self.assertNotIn(str(Path(directory)), json.dumps(receipt))
            self.assertEqual(receipt, validate_support_smoke_receipt(receipt))

    def test_receipt_rejects_unknown_fields_and_unproven_boundaries(self):
        with tempfile.TemporaryDirectory(prefix="pf-support-smoke-test-") as directory:
            report = Path(directory) / "receipt.json"
            receipt = run_packaged_support_smoke(report)
            with self.assertRaisesRegex(SupportSmokeError, "closed schema"):
                validate_support_smoke_receipt({**receipt, "path": "C:/private/support.pfsupport"})
            for field in ("v1Read", "v2Read", "redactionVerified", "tamperRejected"):
                with self.subTest(field=field), self.assertRaises(SupportSmokeError):
                    validate_support_smoke_receipt({**receipt, field: False})

    def test_verifier_checks_the_native_target(self):
        with tempfile.TemporaryDirectory(prefix="pf-support-smoke-test-") as directory:
            report = Path(directory) / "receipt.json"
            run_packaged_support_smoke(report)
            arguments = [
                "--report", str(report),
                "--expect-platform", normalized_platform(),
                "--expect-architecture", normalized_architecture(),
            ]
            self.assertEqual(0, verify_main(arguments))
            payload = json.loads(report.read_text(encoding="utf-8"))
            payload["tamperRejected"] = False
            report.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(1, verify_main(arguments))


if __name__ == "__main__":
    unittest.main()
