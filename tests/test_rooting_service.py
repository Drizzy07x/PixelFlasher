import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from pixelflasher_core.contracts import (
    AppCommand,
    AppSnapshot,
    DeviceInfo,
    OperationStatus,
    ToolchainInfo,
)
from pixelflasher_core.executor import (
    CancellationToken,
    CommandExecutor,
    FakeProcessTransport,
    TransportOutcome,
)
from pixelflasher_core.rooting import (
    RootAppSource,
    RootingPlanningError,
    RootingService,
    parse_root_module_list,
)


def write_apk(path: Path, payload: bytes = b"manifest") -> bytes:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", payload)
        archive.writestr("classes.dex", b"dex")
    return path.read_bytes()


def write_module_zip(
    path: Path,
    extra_members: dict[str, bytes] | None = None,
) -> bytes:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("module.prop", b"id=test_module\nname=Test Module\n")
        archive.writestr("service.sh", b"#!/system/bin/sh\n")
        for name, contents in (extra_members or {}).items():
            archive.writestr(name, contents)
    return path.read_bytes()


class RootingServiceTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = AppSnapshot(
            revision=9,
            devices=(DeviceInfo("SERIAL", mode="adb", root=True, online=True),),
            selected_serial="SERIAL",
            toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
        )

    def command(self, kind, payload=None, *, revision=9, target="SERIAL"):
        return AppCommand(
            kind,
            expected_revision=revision,
            target_serial=target,
            payload=payload or {},
        )

    def test_local_root_app_inventory_has_hash_and_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            magisk = root / "Magisk.apk"
            apatch = root / "APatch.apk"
            magisk_bytes = write_apk(magisk, b"magisk")
            apatch_bytes = write_apk(apatch, b"apatch")
            magisk_hash = hashlib.sha256(magisk_bytes).hexdigest()
            service = RootingService(
                (
                    RootAppSource(
                        str(magisk),
                        "Magisk",
                        "stable",
                        "30.7",
                        "official",
                        magisk_hash,
                    ),
                    RootAppSource(
                        str(apatch),
                        "APatch",
                        "release",
                        "11039",
                        "user-import",
                    ),
                ),
                hash_chunk_size=2,
            )

            compilation = service.compile(
                AppCommand("root.apps.list", expected_revision=9),
                AppSnapshot(revision=9),
            )

            self.assertIsNone(compilation.plan)
            self.assertEqual(
                ["APatch", "Magisk"],
                [item.provider for item in compilation.root_apps],
            )
            self.assertEqual(
                [
                    hashlib.sha256(apatch_bytes).hexdigest(),
                    magisk_hash,
                ],
                [item.sha256 for item in compilation.root_apps],
            )
            self.assertEqual(
                ["user-import", "official"],
                [item.provenance for item in compilation.root_apps],
            )
            self.assertTrue(
                all(len(item.id) == 64 for item in compilation.root_apps)
            )

    def test_verified_inventory_requires_and_revalidates_backend_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "Magisk.apk"
            write_apk(apk)
            cases = (
                ("", "root_app_expected_hash_required"),
                ("0" * 64, "root_app_hash_mismatch"),
                ("bad", "root_app_expected_hash_invalid"),
            )
            for expected_hash, code in cases:
                with self.subTest(code=code):
                    service = RootingService(
                        (
                            RootAppSource(
                                str(apk),
                                "Magisk",
                                "stable",
                                "30.7",
                                "official",
                                expected_hash,
                            ),
                        )
                    )
                    with self.assertRaises(RootingPlanningError) as raised:
                        service.root_app_inventory()
                    self.assertEqual(code, raised.exception.code)

    def test_root_app_install_uses_backend_id_canonical_path_and_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "Magisk stable.apk"
            apk_bytes = write_apk(apk)
            digest = hashlib.sha256(apk_bytes).hexdigest()
            service = RootingService(
                (
                    RootAppSource(
                        str(apk),
                        "Magisk",
                        "stable",
                        "30.7",
                        "official",
                        digest,
                    ),
                )
            )
            app = service.root_app_inventory()[0]

            compilation = service.compile(
                self.command("root.apps.install", {"appId": app.id}),
                self.snapshot,
            )

            self.assertEqual(
                (
                    "ADB",
                    "-s",
                    "SERIAL",
                    "install",
                    "-r",
                    str(apk.resolve()),
                ),
                compilation.plan.request.argv,
            )
            self.assertEqual(digest, compilation.plan.artifacts[0].sha256)
            self.assertEqual(str(apk.resolve()), compilation.plan.artifacts[0].path)
            self.assertTrue(compilation.device_write)
            self.assertFalse(compilation.destructive)
            self.assertTrue(compilation.requires_confirmation)

    def test_root_app_install_rejects_ui_path_hash_and_unknown_id(self):
        service = RootingService()
        cases = (
            ({"appId": "0" * 64}, "root_app_not_found"),
            ({"appId": "bad"}, "root_app_id_invalid"),
            (
                {"appId": "0" * 64, "path": "C:/evil.apk"},
                "invalid_rooting_payload",
            ),
            (
                {"appId": "0" * 64, "sha256": "0" * 64},
                "invalid_rooting_payload",
            ),
        )
        for payload, code in cases:
            with self.subTest(payload=payload):
                with self.assertRaises(RootingPlanningError) as raised:
                    service.compile(
                        self.command("root.apps.install", payload),
                        self.snapshot,
                    )
                self.assertEqual(code, raised.exception.code)

    def test_module_list_uses_one_fixed_root_argv(self):
        compilation = RootingService().compile(
            self.command("root.modules.list"),
            self.snapshot,
        )

        self.assertEqual(
            (
                "ADB",
                "-s",
                "SERIAL",
                "shell",
                "su",
                "-c",
                "ls -1 /data/adb/modules",
            ),
            compilation.plan.request.argv,
        )
        self.assertFalse(compilation.device_write)
        self.assertFalse(compilation.requires_confirmation)

    def test_module_state_actions_compile_exact_allowlisted_commands(self):
        expected = {
            "enable": (
                "rm -f /data/adb/modules/zygisk_next/disable "
                "/data/adb/modules/zygisk_next/remove"
            ),
            "disable": "touch /data/adb/modules/zygisk_next/disable",
            "remove": "touch /data/adb/modules/zygisk_next/remove",
        }
        for action, remote_command in expected.items():
            with self.subTest(action=action):
                compilation = RootingService().compile(
                    self.command(
                        "root.modules.action",
                        {"action": action, "moduleId": "zygisk_next"},
                    ),
                    self.snapshot,
                )
                self.assertEqual(
                    (
                        "ADB",
                        "-s",
                        "SERIAL",
                        "shell",
                        "su",
                        "-c",
                        remote_command,
                    ),
                    compilation.plan.request.argv,
                )
                self.assertTrue(compilation.device_write)
                self.assertTrue(compilation.requires_confirmation)
                self.assertEqual(action == "remove", compilation.destructive)

    def test_module_id_and_action_injection_are_rejected(self):
        service = RootingService()
        cases = (
            ({"action": "remove", "moduleId": "../module"}, "root_module_id_invalid"),
            ({"action": "disable", "moduleId": "good;reboot"}, "root_module_id_invalid"),
            ({"action": "runAction", "moduleId": "good"}, "root_module_action_invalid"),
            (
                {"action": "remove", "moduleId": "good", "command": "rm -rf /"},
                "invalid_rooting_payload",
            ),
            (
                {"action": "remove", "moduleId": "good", "path": "module.zip"},
                "root_module_target_ambiguous",
            ),
        )
        for payload, code in cases:
            with self.subTest(payload=payload):
                with self.assertRaises(RootingPlanningError) as raised:
                    service.compile(
                        self.command("root.modules.action", payload),
                        self.snapshot,
                    )
                self.assertEqual(code, raised.exception.code)

    def test_module_install_validates_zip_hash_and_exact_three_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / "safe module.zip"
            module_bytes = write_module_zip(module)
            digest = hashlib.sha256(module_bytes).hexdigest()
            remote = f"/data/local/tmp/pixelflasher-module-{digest[:16]}.zip"

            compilation = RootingService(hash_chunk_size=2).compile(
                self.command(
                    "root.modules.action",
                    {"action": "install", "path": str(module)},
                ),
                self.snapshot,
            )

            self.assertEqual(
                [
                    ("ADB", "-s", "SERIAL", "push", str(module.resolve()), remote),
                    (
                        "ADB",
                        "-s",
                        "SERIAL",
                        "shell",
                        "su",
                        "-c",
                        f"magisk --install-module {remote}",
                    ),
                    ("ADB", "-s", "SERIAL", "shell", "rm", "-f", remote),
                ],
                [request.argv for request in compilation.plan.requests],
            )
            self.assertEqual(digest, compilation.plan.artifacts[0].sha256)
            self.assertTrue(compilation.device_write)
            self.assertTrue(compilation.destructive)
            self.assertTrue(compilation.requires_confirmation)

    def test_module_zip_rejects_archive_traversal_and_missing_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            traversal = root / "traversal.zip"
            write_module_zip(traversal, {"../escaped.sh": b"bad"})
            missing = root / "missing.zip"
            with zipfile.ZipFile(missing, "w") as archive:
                archive.writestr("service.sh", b"script")

            cases = (
                (traversal, "root_module_zip_unsafe"),
                (missing, "root_module_zip_invalid"),
            )
            for path, code in cases:
                with self.subTest(path=path):
                    with self.assertRaises(RootingPlanningError) as raised:
                        RootingService().compile(
                            self.command(
                                "root.modules.action",
                                {"action": "install", "path": str(path)},
                            ),
                            self.snapshot,
                        )
                    self.assertEqual(code, raised.exception.code)

    def test_host_path_traversal_relative_and_wrong_suffix_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wrong = root / "module.apk"
            wrong.write_bytes(b"not zip")
            traversal = root / "nested" / ".." / "module.zip"
            cases = (
                ("relative.zip", "root_module_zip_invalid"),
                (str(traversal), "rooting_path_traversal"),
                (str(wrong), "root_module_zip_invalid"),
            )
            for path, code in cases:
                with self.subTest(path=path):
                    with self.assertRaises(RootingPlanningError) as raised:
                        RootingService().compile(
                            self.command(
                                "root.modules.action",
                                {"action": "install", "path": path},
                            ),
                            self.snapshot,
                        )
                    self.assertEqual(code, raised.exception.code)

    def test_module_operations_require_current_revision_adb_root_and_toolchain(self):
        command = self.command("root.modules.list")
        cases = (
            (AppCommand("root.modules.list", target_serial="SERIAL"), self.snapshot, "revision_required"),
            (self.command("root.modules.list", revision=8), self.snapshot, "stale_revision"),
            (
                command,
                AppSnapshot(
                    revision=9,
                    devices=(DeviceInfo("SERIAL", mode="fastboot", root=True),),
                    selected_serial="SERIAL",
                    toolchain=self.snapshot.toolchain,
                ),
                "adb_device_required",
            ),
            (
                command,
                AppSnapshot(
                    revision=9,
                    devices=(DeviceInfo("SERIAL", mode="adb", root=False),),
                    selected_serial="SERIAL",
                    toolchain=self.snapshot.toolchain,
                ),
                "root_access_required",
            ),
            (
                command,
                AppSnapshot(
                    revision=9,
                    devices=(DeviceInfo("SERIAL", mode="adb", root=True),),
                    selected_serial="SERIAL",
                    toolchain=ToolchainInfo(),
                ),
                "toolchain_not_ready",
            ),
        )
        for candidate, snapshot, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(RootingPlanningError) as raised:
                    RootingService().compile(candidate, snapshot)
                self.assertEqual(code, raised.exception.code)

    def test_serial_mismatch_and_unknown_list_fields_fail_closed(self):
        with self.assertRaises(RootingPlanningError) as raised:
            RootingService().compile(
                AppCommand(
                    "root.modules.list",
                    expected_revision=9,
                    target_serial="SERIAL",
                    payload={"serial": "OTHER"},
                ),
                self.snapshot,
            )
        self.assertEqual("ambiguous_target_serial", raised.exception.code)

        with self.assertRaises(RootingPlanningError) as raised:
            RootingService().compile(
                AppCommand(
                    "root.apps.list",
                    expected_revision=9,
                    payload={"url": "https://untrusted.example/app.apk"},
                ),
                AppSnapshot(revision=9),
            )
        self.assertEqual("invalid_rooting_payload", raised.exception.code)

    def test_planning_and_process_cancellation_are_explicit(self):
        token = CancellationToken()
        token.cancel()
        with self.assertRaises(RootingPlanningError) as raised:
            RootingService().compile(
                self.command("root.modules.list"),
                self.snapshot,
                token,
            )
        self.assertEqual("rooting_cancelled", raised.exception.code)

        compilation = RootingService().compile(
            self.command(
                "root.modules.action",
                {"action": "disable", "moduleId": "zygisk_next"},
            ),
            self.snapshot,
        )
        transport = FakeProcessTransport([TransportOutcome(0)])
        result = CommandExecutor(transport).execute(
            self.command("root.modules.action"),
            compilation.plan,
            token,
        )
        self.assertEqual(OperationStatus.CANCELLED, result.status)
        self.assertEqual([], transport.calls)


class RootModuleParserTests(unittest.TestCase):
    def test_parser_sorts_deduplicates_and_drops_untrusted_rows(self):
        parsed = parse_root_module_list(
            "zygisk_next\nplay_integrity_fix\n../escape\n"
            "good;touch /tmp/pwn\nzygisk_next\n"
        )

        self.assertEqual(
            ["play_integrity_fix", "zygisk_next"],
            [module.id for module in parsed],
        )


if __name__ == "__main__":
    unittest.main()
