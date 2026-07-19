import unittest

from pixelflasher_core.contracts import (
    AppCommand,
    AppSnapshot,
    DeviceInfo,
    OperationResult,
    OperationRisk,
    ToolchainInfo,
)
from pixelflasher_core.ota_diagnostics import (
    OTA_CERTIFICATES_COMMAND,
    OTA_LOGS_COMMAND,
    OtaDiagnosticPlanningError,
    OtaDiagnosticsService,
)
from ui.public_bridge import project_operation_result


def unzip_listing(*entries: str) -> str:
    rows = "".join(
        f"      1675  2026-07-18 12:00   {entry}\n" for entry in entries
    )
    return (
        "Archive:  /system/etc/security/otacerts.zip\n"
        "  Length      Date    Time    Name\n"
        "---------  ---------- -----   ----\n"
        f"{rows}"
        "---------                     -------\n"
    )


HOST_PATH_SHAPES = (
    r"C:\Users\Alice\PixelFlasher\private.zip",
    r"C:/Users/Alice/PixelFlasher/private.zip",
    r"[C:\Users\Alice\PixelFlasher\private.zip]",
    r"\\build-server\private-share\firmware.zip",
    "/home/alice/PixelFlasher/private.zip",
    "/Users/alice/PixelFlasher/private.zip",
    "/tmp/pixelflasher/private.zip",
    "/root/pixelflasher/private.zip",
    "/etc/pixelflasher/private.conf",
    "/usr/local/pixelflasher/private.bin",
    "/run/user/1000/pixelflasher/private.sock",
    r"WindowsPath('C:\Users\Alice\private.zip')",
    "PosixPath('/home/alice/private.zip')",
    "PurePath('/home/alice/private.zip')",
)


class OtaDiagnosticsServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.snapshot = AppSnapshot(
            revision=17,
            devices=(
                DeviceInfo(
                    "SERIAL-OTA",
                    codename="akita",
                    mode="adb",
                    online=True,
                ),
            ),
            selected_serial="SERIAL-OTA",
            toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
        )
        self.service = OtaDiagnosticsService()

    def compile(self, kind: str, payload: dict[str, object] | None = None):
        return self.service.compile(
            AppCommand(
                kind,
                expected_revision=self.snapshot.revision,
                target_serial="SERIAL-OTA",
                payload=payload or {},
            ),
            self.snapshot,
        )

    def test_certificates_compile_fixed_serial_bound_bounded_argv(self) -> None:
        compilation = self.compile(OTA_CERTIFICATES_COMMAND)

        self.assertEqual(
            (
                "ADB",
                "-s",
                "SERIAL-OTA",
                "shell",
                "unzip",
                "-l",
                "/system/etc/security/otacerts.zip",
            ),
            compilation.plan.request.argv,
        )
        self.assertEqual(30.0, compilation.plan.request.timeout_seconds)
        self.assertEqual(256 * 1_024, compilation.plan.request.output_limit_bytes)
        self.assertIs(OperationRisk.READ_ONLY, compilation.plan.risk)
        self.assertEqual(17, compilation.plan.snapshot_revision)
        self.assertEqual("akita", compilation.plan.expected_codename)
        self.assertEqual("adb", compilation.plan.expected_device_state)
        self.assertEqual((), compilation.plan.postconditions)

    def test_logs_compile_exact_filter_and_strict_bounds(self) -> None:
        compilation = self.compile(
            OTA_LOGS_COMMAND,
            {"maxLines": 250, "timeoutSeconds": 12},
        )

        self.assertEqual(
            (
                "ADB",
                "-s",
                "SERIAL-OTA",
                "logcat",
                "-d",
                "-v",
                "threadtime",
                "-t",
                "250",
                "update_engine:V",
                "update_engine_client:V",
                "*:S",
            ),
            compilation.plan.request.argv,
        )
        self.assertEqual(12.0, compilation.plan.request.timeout_seconds)
        self.assertEqual(8 * 1_024 * 1_024, compilation.plan.request.output_limit_bytes)
        for payload in (
            {"maxLines": 0},
            {"maxLines": 5_001},
            {"maxLines": True},
            {"timeoutSeconds": 0},
            {"timeoutSeconds": 121},
            {"filter": "*:*"},
        ):
            with self.subTest(payload=payload), self.assertRaises(
                OtaDiagnosticPlanningError
            ):
                self.compile(OTA_LOGS_COMMAND, payload)

    def test_target_revision_mode_and_toolchain_are_fail_closed(self) -> None:
        cases = (
            (
                AppCommand(
                    OTA_LOGS_COMMAND,
                    expected_revision=16,
                    target_serial="SERIAL-OTA",
                ),
                self.snapshot,
                "stale_revision",
            ),
            (
                AppCommand(
                    OTA_LOGS_COMMAND,
                    expected_revision=17,
                    target_serial="OTHER",
                ),
                self.snapshot,
                "target_serial_changed",
            ),
            (
                AppCommand(
                    OTA_LOGS_COMMAND,
                    expected_revision=17,
                    target_serial="SERIAL-OTA",
                ),
                AppSnapshot(
                    revision=17,
                    devices=(DeviceInfo("SERIAL-OTA", mode="recovery"),),
                    selected_serial="SERIAL-OTA",
                    toolchain=self.snapshot.toolchain,
                ),
                "adb_device_required",
            ),
            (
                AppCommand(
                    OTA_LOGS_COMMAND,
                    expected_revision=17,
                    target_serial="SERIAL-OTA",
                ),
                AppSnapshot(
                    revision=17,
                    devices=(DeviceInfo("SERIAL-OTA", mode="adb"),),
                    selected_serial="SERIAL-OTA",
                ),
                "toolchain_not_ready",
            ),
        )
        for command, snapshot, code in cases:
            with self.subTest(code=code), self.assertRaises(
                OtaDiagnosticPlanningError
            ) as raised:
                self.service.compile(command, snapshot)
            self.assertEqual(code, raised.exception.code)

    def test_certificates_finalize_closed_typed_inventory(self) -> None:
        compilation = self.compile(OTA_CERTIFICATES_COMMAND)
        result = self.service.finalize(
            compilation,
            OperationResult.success(
                "ota-certificates",
                stdout=unzip_listing(
                    "META-INF/com/android/otacert.x509.pem",
                    "releasekey.x509.pem",
                ),
            ),
        )

        self.assertTrue(result.ok)
        self.assertEqual("ota_certificates_inspected", result.code)
        self.assertEqual(
            {
                "action": "certificates",
                "archivePresent": True,
                "count": 2,
                "entries": [
                    "META-INF/com/android/otacert.x509.pem",
                    "releasekey.x509.pem",
                ],
                "bounded": True,
            },
            result.value,
        )

    def test_certificates_reject_empty_traversal_and_oversized_output(self) -> None:
        compilation = self.compile(OTA_CERTIFICATES_COMMAND)
        cases = (
            ("", "ota_certificates_unverified"),
            (unzip_listing("../releasekey.x509.pem"), "ota_certificate_entry_invalid"),
            (unzip_listing("/system/releasekey.x509.pem"), "ota_certificate_entry_invalid"),
            (unzip_listing("é" * 129 + ".pem"), "ota_certificate_entry_invalid"),
            ("x" * (256 * 1024 + 1), "ota_certificates_output_oversized"),
        )
        for stdout, code in cases:
            with self.subTest(code=code):
                result = self.service.finalize(
                    compilation,
                    OperationResult.success("ota-certificates", stdout=stdout),
                )
                self.assertFalse(result.ok)
                self.assertEqual(code, result.code)

    def test_logs_finalize_filters_bounds_and_redacts(self) -> None:
        compilation = self.compile(OTA_LOGS_COMMAND, {"maxLines": 4})
        result = self.service.finalize(
            compilation,
            OperationResult.success(
                "ota-logs",
                stdout=(
                    "07-18 I ActivityManager: ignore@example.com token=visible\n"
                    "07-18 I update_engine: serial=SERIAL-OTA user@example.com token=visible\n"
                    "\x1b[31m07-18 E update_engine_client: password:visible\x1b[0m\n"
                ),
            ),
        )

        self.assertTrue(result.ok)
        self.assertEqual("ota_update_engine_logs_collected", result.code)
        self.assertEqual(
            [
                "07-18 I update_engine: serial=<serial> <email> token=<redacted>",
                "07-18 E update_engine_client: password=<redacted>",
            ],
            result.value["lines"],
        )
        self.assertEqual(2, result.value["lineCount"])
        self.assertEqual(2, result.value["redactedCount"])
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)

    def test_logs_remove_controls_and_redact_common_credentials_and_addresses(self) -> None:
        compilation = self.compile(OTA_LOGS_COMMAND, {"maxLines": 7})
        result = self.service.finalize(
            compilation,
            OperationResult.success(
                "ota-logs",
                stdout=(
                    "update_engine: Authorization: Bearer TOPSECRET\n"
                    "update_engine: access_token=TOPSECRET user@example.com\n"
                    "update_engine: X-Goog-Signature=SECRET\n"
                    "update_engine: password=TOP SECRET\n"
                    "update_engine: peer 192.0.2.10:5555\n"
                    "update_engine: mounting /postinstall\n"
                    "update_engine:\x07 safe\n"
                ),
                stderr="private failure detail",
            ),
        )

        self.assertTrue(result.ok)
        rendered = "\n".join(result.value["lines"])
        self.assertNotIn("TOPSECRET", rendered)
        self.assertNotIn("SECRET", rendered)
        self.assertNotIn("example.com", rendered)
        self.assertNotIn("192.0.2.10", rendered)
        self.assertNotIn("\x07", rendered)
        self.assertIn("Authorization: <redacted>", rendered)
        self.assertIn("<network-address>", rendered)
        self.assertIn("mounting <device-path>", rendered)
        self.assertEqual(7, result.value["redactedCount"])
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)
        public = project_operation_result(OTA_LOGS_COMMAND, result)
        self.assertEqual(result.value, public["value"])

    def test_logs_sanitize_every_host_path_shape_before_public_projection(self) -> None:
        compilation = self.compile(
            OTA_LOGS_COMMAND,
            {"maxLines": len(HOST_PATH_SHAPES)},
        )
        result = self.service.finalize(
            compilation,
            OperationResult.success(
                "ota-logs",
                stdout="".join(
                    f"update_engine: route={route}\n" for route in HOST_PATH_SHAPES
                ),
            ),
        )

        self.assertTrue(result.ok)
        public = project_operation_result(OTA_LOGS_COMMAND, result)
        self.assertEqual(result.value, public["value"])
        rendered = "\n".join(result.value["lines"])
        for route in HOST_PATH_SHAPES:
            with self.subTest(route=route):
                self.assertNotIn(route, rendered)

    def test_logs_enforce_the_per_line_limit_in_utf8_bytes(self) -> None:
        compilation = self.compile(OTA_LOGS_COMMAND, {"maxLines": 1})
        result = self.service.finalize(
            compilation,
            OperationResult.success(
                "ota-logs",
                stdout="update_engine: " + "é" * 2_100 + "\n",
            ),
        )

        self.assertTrue(result.ok)
        self.assertEqual(1, result.value["lineCount"])
        self.assertLessEqual(len(result.value["lines"][0].encode("utf-8")), 4_096)
        self.assertEqual(1, result.value["redactedCount"])

    def test_logs_reject_more_lines_than_requested(self) -> None:
        compilation = self.compile(OTA_LOGS_COMMAND, {"maxLines": 1})
        result = self.service.finalize(
            compilation,
            OperationResult.success(
                "ota-logs",
                stdout="update_engine: one\nupdate_engine: two\n",
            ),
        )
        self.assertFalse(result.ok)
        self.assertEqual("ota_logs_output_oversized", result.code)

    def test_process_failure_is_preserved_without_parser_success(self) -> None:
        compilation = self.compile(OTA_LOGS_COMMAND)
        failure = OperationResult.failed(
            "ota-logs",
            code="timed_out",
            message="process timed out",
            stdout="update_engine: access_token=TOPSECRET",
            stderr="Authorization: Bearer TOPSECRET",
        )
        scrubbed = self.service.finalize(compilation, failure)
        self.assertEqual(failure.status, scrubbed.status)
        self.assertEqual(failure.code, scrubbed.code)
        self.assertEqual("", scrubbed.stdout)
        self.assertEqual("", scrubbed.stderr)


if __name__ == "__main__":
    unittest.main()
