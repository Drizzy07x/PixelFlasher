import hashlib
import unittest

from pixelflasher_core import OperationResult
from ui.public_bridge import PublicProjectionError, project_operation_result

COMMAND = "tools.logcat"


def logcat_value(*, exported: bool = False) -> dict[str, object]:
    lines = [
        "07-19 10:00:00.100 I/ActivityManager: ready",
        "07-19 10:00:00.200 W/Auth: <redacted>",
    ]
    text = "\n".join(lines)
    value: dict[str, object] = {
        "targetSerial": "ABC123",
        "mode": "snapshot",
        "lineCount": len(lines),
        "lines": lines,
        "text": text,
        "redaction": "strict",
        "redactedCount": 1,
        "bounded": True,
        "truncated": False,
    }
    if exported:
        payload = text.encode("utf-8")
        value["export"] = {
            "fileName": "PixelFlasher-logcat.txt",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        }
    return value


class LogcatPublicContractTests(unittest.TestCase):
    def project(self, value: object) -> dict[str, object]:
        return project_operation_result(
            COMMAND,
            OperationResult.success("logcat-contract", value=value),
        )

    def test_projects_only_the_closed_bounded_result(self) -> None:
        for exported in (False, True):
            with self.subTest(exported=exported):
                value = logcat_value(exported=exported)
                public = self.project(value)

                self.assertEqual(value, public["value"])
                self.assertNotIn("stdout", public)
                self.assertNotIn("stderr", public)

    def test_success_requires_a_complete_typed_value(self) -> None:
        with self.assertRaises(PublicProjectionError):
            project_operation_result(
                COMMAND,
                OperationResult.success("logcat-contract"),
            )

        required = logcat_value()
        for field in tuple(required):
            with self.subTest(field=field):
                malformed = {key: value for key, value in required.items() if key != field}
                with self.assertRaises(PublicProjectionError):
                    self.project(malformed)

    def test_rejects_expanded_or_internally_inconsistent_results(self) -> None:
        value = logcat_value()
        invalid_values = (
            {**value, "rawOutput": "private"},
            {**value, "targetSerial": "bad serial"},
            {**value, "mode": "continuous"},
            {**value, "redaction": "custom"},
            {**value, "bounded": False},
            {**value, "lineCount": 1},
            {**value, "redactedCount": 3},
            {**value, "text": "different"},
            {**value, "lines": ["safe\x00unsafe"], "lineCount": 1, "text": "safe\x00unsafe"},
        )
        for malformed in invalid_values:
            with self.subTest(malformed=malformed):
                with self.assertRaises(PublicProjectionError):
                    self.project(malformed)

    def test_verifies_export_name_hash_and_exact_utf8_size(self) -> None:
        value = logcat_value(exported=True)
        receipt = dict(value["export"])  # type: ignore[arg-type]
        invalid_receipts = (
            {**receipt, "fileName": "C:\\private\\logcat.txt"},
            {**receipt, "sha256": "0" * 64},
            {**receipt, "size": int(receipt["size"]) + 1},
            {**receipt, "path": "logcat.txt"},
        )
        for malformed in invalid_receipts:
            with self.subTest(malformed=malformed):
                with self.assertRaises(PublicProjectionError):
                    self.project({**value, "export": malformed})


if __name__ == "__main__":
    unittest.main()
