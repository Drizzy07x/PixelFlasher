from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from pixelflasher_core.contracts import AppCommand, AppSnapshot, DeviceInfo, ToolchainInfo
from pixelflasher_core.ota_diagnostics import (
    OTA_RESET_COMMAND,
    OTA_RUNNER_DIGEST_PATH,
    OTA_RUNNER_RESOURCE_PATH,
    OtaDiagnosticPlanningError,
    OtaDiagnosticsService,
)
from scripts.build_ota_runner import (
    LOCK_PATH,
    OUTPUT_PATH,
    OtaRunnerBuildError,
    _reproducibility_report,
    _verified_r8,
)


class OtaRunnerArtifactTests(unittest.TestCase):
    def test_reproducibility_report_binds_matching_bytes_to_candidate(self) -> None:
        report = json.loads(
            _reproducibility_report(OUTPUT_PATH.read_bytes(), "a" * 40)
        )

        self.assertEqual("passed", report["status"])
        self.assertEqual("a" * 40, report["candidateCommit"])
        self.assertEqual(report["packagedSha256"], report["rebuiltSha256"])

    def test_reproducibility_report_rejects_noncanonical_candidate(self) -> None:
        with self.assertRaisesRegex(OtaRunnerBuildError, "full lowercase"):
            _reproducibility_report(OUTPUT_PATH.read_bytes(), "abc")

    def test_reproducibility_report_rejects_different_rebuild(self) -> None:
        with self.assertRaisesRegex(OtaRunnerBuildError, "digests differ"):
            _reproducibility_report(b"not the packaged dex", "a" * 40)

    def test_committed_dex_is_hash_bound_and_does_not_bundle_framework_stubs(self) -> None:
        dex = OTA_RUNNER_RESOURCE_PATH.read_bytes()
        expected = OTA_RUNNER_DIGEST_PATH.read_text(encoding="ascii").strip()

        self.assertTrue(dex.startswith(b"dex\n"))
        self.assertEqual(hashlib.sha256(dex).hexdigest(), expected)
        self.assertIn(b"com/pixelflasher/ota/Runner", dex)
        self.assertNotIn(b"android/os/UpdateEngine.java", dex)

    def test_toolchain_lock_binds_google_r8_and_android_8_minimum(self) -> None:
        lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))

        self.assertEqual(1, lock["schemaVersion"])
        self.assertEqual(26, lock["minimumAndroidApi"])
        self.assertEqual(8, lock["javaRelease"])
        self.assertEqual(
            "https://dl.google.com/dl/android/maven2/com/android/tools/r8/"
            "9.1.31/r8-9.1.31.jar",
            lock["r8"]["url"],
        )
        self.assertRegex(lock["r8"]["sha256"], r"^[0-9a-f]{64}$")

    def test_locked_r8_rejects_tampered_local_tool(self) -> None:
        lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory(prefix="pf-ota-r8-") as directory:
            tampered = Path(directory) / "r8.jar"
            tampered.write_bytes(b"not r8")
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                _verified_r8(lock, tampered, Path(directory))

    def test_reset_planning_rejects_tampered_runner(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-ota-runner-") as directory:
            root = Path(directory)
            runner = root / "runner.dex"
            digest = root / "runner.sha256"
            runner.write_bytes(b"dex\n035\x00tampered")
            digest.write_text("0" * 64 + "\n", encoding="ascii")
            service = OtaDiagnosticsService(
                runner_path=runner,
                runner_digest_path=digest,
            )
            snapshot = AppSnapshot(
                revision=3,
                devices=(
                    DeviceInfo(
                        "SERIAL",
                        codename="akita",
                        mode="adb",
                        root=True,
                        online=True,
                    ),
                ),
                selected_serial="SERIAL",
                toolchain=ToolchainInfo("ADB", "FASTBOOT", "37.0.0", True),
            )
            command = AppCommand(
                OTA_RESET_COMMAND,
                expected_revision=3,
                target_serial="SERIAL",
            )

            with self.assertRaises(OtaDiagnosticPlanningError) as context:
                service.compile(command, snapshot)

            self.assertEqual("ota_runner_hash_mismatch", context.exception.code)


if __name__ == "__main__":
    unittest.main()
