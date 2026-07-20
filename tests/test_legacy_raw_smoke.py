import json
import tempfile
import unittest
from pathlib import Path

from legacy_raw_smoke_contract import (
    LegacyRawSmokeError,
    create_legacy_raw_smoke_receipt,
    load_legacy_raw_smoke_receipt,
    run_packaged_legacy_raw_smoke,
    validate_legacy_raw_smoke_receipt,
    write_legacy_raw_smoke_receipt,
)
from ui_smoke_contract import normalized_architecture, normalized_platform


class LegacyRawSmokeTests(unittest.TestCase):
    def receipt(self):
        platform_name = normalized_platform()
        return create_legacy_raw_smoke_receipt(
            shell="cmd" if platform_name == "windows" else "zsh" if platform_name == "macos" else "sh",
            probe_executable="whoami.exe" if platform_name == "windows" else "id",
            output=b"bounded identity\n",
        )

    def test_closed_receipt_round_trip_and_identity_validation(self):
        receipt = self.receipt()
        validated = validate_legacy_raw_smoke_receipt(
            receipt,
            expected_platform=normalized_platform(),
            expected_architecture=normalized_architecture(),
        )
        self.assertEqual(receipt, validated)
        for field, value in (
            ("shell", "powershell"),
            ("outputSha256", "x" * 64),
            ("incorrectRunRejected", False),
        ):
            with self.subTest(field=field), self.assertRaises(LegacyRawSmokeError):
                validate_legacy_raw_smoke_receipt({**receipt, field: value})
        with self.assertRaises(LegacyRawSmokeError):
            validate_legacy_raw_smoke_receipt({**receipt, "extra": True})

    def test_atomic_writer_rejects_non_object_and_loads_closed_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "legacy-raw-smoke.json"
            write_legacy_raw_smoke_receipt(report, self.receipt())
            self.assertEqual(self.receipt(), load_legacy_raw_smoke_receipt(report))
            report.write_text(json.dumps([]), encoding="utf-8")
            with self.assertRaises(LegacyRawSmokeError):
                load_legacy_raw_smoke_receipt(report)

    def test_real_packaged_boundary_uses_fixed_probe_and_persistent_permission(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "legacy-raw-smoke.json"

            receipt = run_packaged_legacy_raw_smoke(report)

            self.assertEqual("passed", receipt["status"])
            self.assertTrue(receipt["persistentPermission"])
            self.assertTrue(receipt["incorrectPermissionRejected"])
            self.assertTrue(receipt["incorrectRunRejected"])
            self.assertEqual(receipt, load_legacy_raw_smoke_receipt(report))
            self.assertNotIn(str(Path.home()), json.dumps(receipt))


if __name__ == "__main__":
    unittest.main()
