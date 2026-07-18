import hashlib
import tempfile
import unittest
from pathlib import Path

from pixelflasher_core.contracts import (
    AppCommand,
    AppSnapshot,
    DeviceInfo,
    ToolchainInfo,
)
from pixelflasher_core.packages import (
    PackagePlanningError,
    PackageService,
    parse_package_list,
)


class PackageServiceTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = AppSnapshot(
            devices=(DeviceInfo("SERIAL", mode="adb", online=True),),
            selected_serial="SERIAL",
            toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
        )
        self.service = PackageService(hash_chunk_size=2)

    def compile(self, kind, payload):
        return self.service.compile(
            AppCommand(
                kind,
                expected_revision=self.snapshot.revision,
                target_serial="SERIAL",
                payload=payload,
            ),
            self.snapshot,
        )

    def test_list_scope_compiles_exact_serial_bound_argv(self):
        compilation = self.compile("apps.list", {"scope": "user"})

        self.assertEqual(
            (
                "ADB",
                "-s",
                "SERIAL",
                "shell",
                "pm",
                "list",
                "packages",
                "-f",
                "-U",
                "-3",
            ),
            compilation.plan.request.argv,
        )
        self.assertFalse(compilation.requires_confirmation)

    def test_destructive_multi_package_action_is_deterministic(self):
        compilation = self.compile(
            "apps.action",
            {
                "action": "uninstall",
                "packages": ["com.example.beta", "com.example.alpha"],
                "options": {"keepData": True},
            },
        )

        self.assertTrue(compilation.destructive)
        self.assertTrue(compilation.requires_confirmation)
        self.assertEqual(
            [
                (
                    "ADB",
                    "-s",
                    "SERIAL",
                    "shell",
                    "pm",
                    "uninstall",
                    "-k",
                    "--user",
                    "0",
                    "com.example.beta",
                ),
                (
                    "ADB",
                    "-s",
                    "SERIAL",
                    "shell",
                    "pm",
                    "uninstall",
                    "-k",
                    "--user",
                    "0",
                    "com.example.alpha",
                ),
            ],
            [request.argv for request in compilation.plan.requests],
        )

    def test_package_names_and_payload_fields_cannot_inject_shell_syntax(self):
        for package in (
            "com.example.good;rm",
            "com.example.$(bad)",
            "com.example.good bad",
        ):
            with self.subTest(package=package):
                with self.assertRaisesRegex(PackagePlanningError, "package name"):
                    self.compile(
                        "apps.action",
                        {"action": "disable", "package": package},
                    )

        with self.assertRaisesRegex(PackagePlanningError, "unsupported semantic field"):
            self.compile(
                "apps.action",
                {
                    "action": "enable",
                    "package": "com.example.good",
                    "argv": ["rm", "-rf"],
                },
            )

    def test_permissions_is_read_only_and_uses_dumpsys(self):
        compilation = self.compile(
            "apps.action",
            {"action": "permissions", "package": "com.example.app"},
        )

        self.assertFalse(compilation.destructive)
        self.assertFalse(compilation.requires_confirmation)
        self.assertEqual(
            (
                "ADB",
                "-s",
                "SERIAL",
                "shell",
                "dumpsys",
                "package",
                "com.example.app",
            ),
            compilation.plan.request.argv,
        )

    def test_install_hashes_canonical_apk_and_orders_allowlisted_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "sample.apk"
            apk.write_bytes(b"verified apk")

            compilation = self.compile(
                "apps.action",
                {
                    "action": "install",
                    "path": str(apk),
                    "options": {
                        "replace": True,
                        "grantPermissions": True,
                        "allowDowngrade": False,
                        "bypassLowTargetSdk": True,
                    },
                },
            )

            self.assertEqual(
                (
                    "ADB",
                    "-s",
                    "SERIAL",
                    "install",
                    "-r",
                    "-g",
                    "--bypass-low-target-sdk-block",
                    str(apk.resolve()),
                ),
                compilation.plan.request.argv,
            )
            self.assertEqual(
                hashlib.sha256(b"verified apk").hexdigest(),
                compilation.plan.artifacts[0].sha256,
            )

    def test_install_rejects_non_apk_and_non_boolean_options(self):
        with tempfile.TemporaryDirectory() as directory:
            text = Path(directory) / "payload.txt"
            text.write_text("not an apk", encoding="utf-8")
            with self.assertRaisesRegex(PackagePlanningError, "existing .apk"):
                self.compile(
                    "apps.action",
                    {"action": "install", "path": str(text)},
                )

            apk = Path(directory) / "payload.apk"
            apk.write_bytes(b"apk")
            with self.assertRaisesRegex(PackagePlanningError, "must be a boolean"):
                self.compile(
                    "apps.action",
                    {
                        "action": "install",
                        "path": str(apk),
                        "options": {"replace": "yes"},
                    },
                )

    def test_requires_selected_online_adb_device_and_validated_toolchain(self):
        cases = (
            (
                AppSnapshot(
                    devices=(DeviceInfo("SERIAL", mode="fastboot"),),
                    selected_serial="SERIAL",
                    toolchain=self.snapshot.toolchain,
                ),
                "adb_device_required",
            ),
            (
                AppSnapshot(
                    devices=(DeviceInfo("SERIAL", mode="adb"),),
                    selected_serial="SERIAL",
                    toolchain=ToolchainInfo(),
                ),
                "toolchain_not_ready",
            ),
        )
        for snapshot, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(PackagePlanningError) as raised:
                    self.service.compile(
                        AppCommand(
                            "apps.list",
                            expected_revision=0,
                            target_serial="SERIAL",
                        ),
                        snapshot,
                    )
                self.assertEqual(code, raised.exception.code)


class PackageListParserTests(unittest.TestCase):
    def test_parser_handles_paths_uids_duplicates_and_malformed_rows(self):
        parsed = parse_package_list(
            "package:/data/app/alpha/base.apk=com.example.alpha uid:10123\n"
            "package:com.example.beta uid:10124\n"
            "noise\n"
            "package:/bad/path=invalid uid:not-a-number\n"
            "package:/new/path.apk=com.example.alpha uid:20200\n"
        )

        self.assertEqual(
            ["com.example.alpha", "com.example.beta"],
            [item.package for item in parsed],
        )
        self.assertEqual("/new/path.apk", parsed[0].apk_path)
        self.assertEqual(20200, parsed[0].uid)
        self.assertEqual(10124, parsed[1].uid)


if __name__ == "__main__":
    unittest.main()
