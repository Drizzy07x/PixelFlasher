import hashlib
import os
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path

from pixelflasher_core.apk_inspection import (
    ApkIdentity,
    ApkInspectionCode,
    ApkInspectionError,
)
from pixelflasher_core.cancellation import CancellationToken
from pixelflasher_core.contracts import (
    AppCommand,
    AppSnapshot,
    DeviceInfo,
    InteractionDecision,
    OperationRisk,
    ToolchainInfo,
)
from pixelflasher_core.executor import CommandExecutor, FakeProcessTransport, TransportOutcome
from pixelflasher_core.packages import (
    CancellationProbe,
    PackageCompilation,
    PackagePlanningError,
    PackageResultError,
    PackageService,
    parse_package_list,
    parse_package_permissions,
)
from pixelflasher_core.store import AppStateStore
from tests.artifact_stage_assertions import assert_exact_or_staged_argv
from tests.command_engine_factory import make_test_command_engine


class StubApkInspector:
    def inspect(
        self,
        path: str | os.PathLike[str],
        *,
        cancellation: CancellationProbe | None = None,
    ) -> ApkIdentity:
        _ = cancellation
        source = Path(path)
        return ApkIdentity(
            "com.example.verified",
            hashlib.sha256(source.read_bytes()).hexdigest(),
            ("c" * 64,),
            ("v2",),
            True,
        )


class PackageServiceTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = AppSnapshot(
            revision=4,
            devices=(DeviceInfo("SERIAL", codename="akita", mode="adb", online=True),),
            selected_serial="SERIAL",
            toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
        )
        self.service = PackageService(
            hash_chunk_size=2,
            apk_inspector=StubApkInspector(),
        )

    def compile(
        self,
        kind: str,
        payload: Mapping[str, object],
    ) -> PackageCompilation:
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
        self.assertIs(OperationRisk.READ_ONLY, compilation.plan.risk)
        self.assertEqual((), compilation.plan.postconditions)

    def test_apk_inspection_cancellation_is_reported_before_plan_creation(self):
        token = CancellationToken()

        class CancellingInspector(StubApkInspector):
            def inspect(
                self,
                path: str | os.PathLike[str],
                *,
                cancellation: CancellationProbe | None = None,
            ) -> ApkIdentity:
                _ = path
                if cancellation is not token:
                    raise AssertionError(
                        "PackageService did not forward its cancellation token"
                    )
                token.cancel()
                raise ApkInspectionError(
                    ApkInspectionCode.CANCELLED,
                    "inspection cancelled inside APK I/O",
                )

        service = PackageService(
            hash_chunk_size=2,
            apk_inspector=CancellingInspector(),
        )
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "verified.apk"
            apk.write_bytes(b"verified")

            with self.assertRaises(PackagePlanningError) as raised:
                service.compile(
                    AppCommand(
                        "apps.action",
                        expected_revision=4,
                        target_serial="SERIAL",
                        payload={"action": "install", "path": str(apk)},
                    ),
                    self.snapshot,
                    token,
                )

        self.assertEqual("package_cancelled", raised.exception.code)

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
        self.assertIs(OperationRisk.DESTRUCTIVE, compilation.plan.risk)
        self.assertEqual(
            ("package_state", {"packages": ("com.example.beta", "com.example.alpha"), "state": "absent"}),
            (
                compilation.plan.postconditions[0].kind,
                dict(compilation.plan.postconditions[0].expected),
            ),
        )
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
        self.assertIs(OperationRisk.READ_ONLY, compilation.plan.risk)
        self.assertEqual((), compilation.plan.postconditions)
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

    def test_permissions_requires_one_package_and_parses_a_bounded_report(self):
        with self.assertRaises(PackagePlanningError) as multiple:
            self.compile(
                "apps.action",
                {
                    "action": "permissions",
                    "packages": ["com.example.one", "com.example.two"],
                },
            )
        self.assertEqual("package_permissions_target_invalid", multiple.exception.code)

        output = """Packages:
  Package [com.example.app] (123):
    requested permissions:
      android.permission.CAMERA
      android.permission.POST_NOTIFICATIONS
    runtime permissions:
      android.permission.CAMERA: granted=true, flags=[ USER_SENSITIVE_WHEN_GRANTED ]
      android.permission.POST_NOTIFICATIONS: granted=false, flags=[ USER_SENSITIVE_WHEN_DENIED ]
"""
        report = parse_package_permissions(output, "com.example.app")
        self.assertEqual(
            ("android.permission.CAMERA", "android.permission.POST_NOTIFICATIONS"),
            report["requested"],
        )
        self.assertEqual(("android.permission.CAMERA",), report["runtimeGranted"])
        self.assertEqual(
            ("android.permission.POST_NOTIFICATIONS",), report["runtimeDenied"]
        )
        self.assertTrue(report["bounded"])

        for hostile, code in (
            (output.replace("com.example.app", "com.example.other", 1), "package_permissions_unverified"),
            ("x" * (512 * 1024 + 1), "package_permissions_oversized"),
        ):
            with self.subTest(code=code), self.assertRaises(PackageResultError) as rejected:
                parse_package_permissions(hostile, "com.example.app")
            self.assertEqual(code, rejected.exception.code)

    def test_permissions_engine_returns_only_the_typed_report(self):
        output = """Packages:
  Package [com.example.app] (123):
    requested permissions:
      android.permission.CAMERA
    runtime permissions:
      android.permission.CAMERA: granted=true, flags=[]
"""
        transport = FakeProcessTransport([TransportOutcome(0, stdout=output)])
        engine = make_test_command_engine(
            store=AppStateStore(self.snapshot),
            executor=CommandExecutor(transport),
            package_service=self.service,
        )

        result = engine.execute(
            AppCommand(
                "apps.action",
                expected_revision=self.snapshot.revision,
                target_serial="SERIAL",
                payload={"action": "permissions", "package": "com.example.app"},
            )
        )

        self.assertTrue(result.ok)
        self.assertEqual("package_permissions_returned", result.code)
        self.assertEqual("permissions", result.value["action"])
        self.assertEqual("com.example.app", result.value["report"]["package"])
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)

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
            self.assertIs(OperationRisk.MUTATING, compilation.plan.risk)
            self.assertEqual(
                "package_state",
                compilation.plan.postconditions[0].kind,
            )
            self.assertEqual(
                {
                    "packages": ("com.example.verified",),
                    "state": "installed",
                },
                dict(compilation.plan.postconditions[0].expected),
            )
            self.assertIsNotNone(compilation.apk_identity)
            self.assertEqual(
                "com.example.verified",
                compilation.to_dict()["apkIdentity"]["packageName"],
            )

    def test_mutating_actions_declare_observable_package_state(self):
        cases = (
            ("enable", "enabled", OperationRisk.MUTATING),
            ("disable", "disabled", OperationRisk.MUTATING),
            ("forceStop", "stopped", OperationRisk.MUTATING),
            ("launch", "running", OperationRisk.MUTATING),
        )
        for action, expected_state, risk in cases:
            with self.subTest(action=action):
                compilation = self.compile(
                    "apps.action",
                    {"action": action, "package": "com.example.application"},
                )

                self.assertIs(risk, compilation.plan.risk)
                self.assertEqual(4, compilation.plan.snapshot_revision)
                self.assertEqual("akita", compilation.plan.expected_codename)
                self.assertEqual("package_state", compilation.plan.postconditions[0].kind)
                self.assertEqual(
                    {
                        "packages": ("com.example.application",),
                        "state": expected_state,
                    },
                    dict(compilation.plan.postconditions[0].expected),
                )

    def test_clear_data_requires_exact_process_evidence_and_installed_state(self):
        compilation = self.compile(
            "apps.action",
            {
                "action": "clearData",
                "packages": ["com.example.alpha", "com.example.beta"],
            },
        )

        self.assertTrue(compilation.destructive)
        self.assertIs(OperationRisk.DESTRUCTIVE, compilation.plan.risk)
        self.assertEqual(
            ("package_data_cleared", "package_state"),
            tuple(item.kind for item in compilation.plan.postconditions),
        )
        self.assertEqual(
            {
                "packages": ("com.example.alpha", "com.example.beta"),
                "successCount": 2,
            },
            dict(compilation.plan.postconditions[0].expected),
        )
        self.assertEqual(
            {
                "packages": ("com.example.alpha", "com.example.beta"),
                "state": "installed",
            },
            dict(compilation.plan.postconditions[1].expected),
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

    def test_install_propagates_typed_signature_failure_without_compiling_argv(self):
        class RejectingInspector:
            def inspect(
                self,
                path: str | os.PathLike[str],
                *,
                cancellation: CancellationProbe | None = None,
            ) -> ApkIdentity:
                _ = path
                _ = cancellation
                raise ApkInspectionError(
                    ApkInspectionCode.SIGNATURE_MISSING,
                    "APK has no verified signature",
                )

        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "unsigned.apk"
            apk.write_bytes(b"not signed")
            service = PackageService(apk_inspector=RejectingInspector())

            with self.assertRaises(PackagePlanningError) as raised:
                service.compile(
                    AppCommand(
                        "apps.action",
                        expected_revision=self.snapshot.revision,
                        target_serial="SERIAL",
                        payload={"action": "install", "path": str(apk)},
                    ),
                    self.snapshot,
                )

            self.assertEqual("apk_signature_missing", raised.exception.code)

    def test_verified_install_executes_and_observes_the_exact_manifest_package(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "verified.apk"
            apk.write_bytes(b"signed fixture boundary")
            transport = FakeProcessTransport([TransportOutcome(0, stdout="Success\n")])
            observed: list[tuple[str, object]] = []

            def observe(_plan, condition, _snapshot):
                observed.append((condition.kind, dict(condition.expected)))
                return True

            engine = make_test_command_engine(
                store=AppStateStore(self.snapshot),
                executor=CommandExecutor(transport),
                package_service=self.service,
                interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
                postcondition_observer=observe,
            )

            result = engine.execute(
                AppCommand(
                    "apps.action",
                    expected_revision=self.snapshot.revision,
                    target_serial="SERIAL",
                    payload={"action": "install", "path": str(apk)},
                )
            )

            self.assertTrue(result.ok)
            self.assertEqual("apps_action_succeeded", result.code)
            self.assertEqual("com.example.verified", result.value["apkIdentity"]["packageName"])
            self.assertEqual(
                [
                    (
                        "package_state",
                        {
                            "packages": ("com.example.verified",),
                            "state": "installed",
                        },
                    )
                ],
                observed,
            )
            assert_exact_or_staged_argv(
                self,
                [("ADB", "-s", "SERIAL", "install", str(apk.resolve()))],
                transport.calls,
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
