import base64
import hashlib
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import NoReturn

from pixelflasher_core.apk_inspection import ApkInspectionCode, ApkInspectionError
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
    CancellationProbe,
    RootAppSource,
    RootingPlanningError,
    RootingService,
    parse_pi_analysis,
    parse_pif_inventory,
    parse_root_module_list,
)
from tests.apk_test_helpers import FakeVerifiedApkInspector


def module_record(
    module_id: str,
    *,
    state: str = "enabled",
    name: str = "Module",
    version: str = "1.0",
    version_code: str = "1",
    author: str = "PixelFlasher",
    description: str = "Test module",
    update_url: str = "",
) -> str:
    encoded = [
        base64.b64encode(value.encode("utf-8")).decode("ascii")
        for value in (name, version, author, description, update_url)
    ]
    return "|".join(
        ["PF_RM", module_id, state, encoded[0], encoded[1], version_code, *encoded[2:]]
    )


def pi_analysis_output(*, keybox_present: bool = True) -> str:
    def encode(value: str) -> str:
        return base64.b64encode(value.encode("utf-8")).decode("ascii")
    config_kinds = (
        "pif_custom_json",
        "pif_custom_prop",
        "pif_module_json",
        "pif_legacy_json",
        "pif_app_replace",
        "pif_scripts_only",
        "tricky_spoof",
        "tricky_target",
        "tricky_security_patch",
        "tricky_tee",
        "targeted_targets",
        "keybox",
    )
    lines = [
        "PF_PI|schema|1",
        "PF_PI|root|verified",
        "PF_PI|testKeys|false",
        "PF_PI|overlayVisible|true",
        f"PF_PI|package|gms|true|{encode('25.20.33')}|252033000",
        "PF_PI|package|play_store|false||0",
        f"PF_PI|module|{encode('playintegrityfix')}|enabled",
        f"PF_PI|module|{encode('tricky_store')}|disabled",
    ]
    for kind in config_kinds:
        if kind == "keybox" and keybox_present:
            lines.append("PF_PI|config|keybox|present|2048|-")
        elif kind == "pif_custom_json":
            lines.append(f"PF_PI|config|{kind}|present|512|{'a' * 64}")
        else:
            lines.append(f"PF_PI|config|{kind}|absent|0|-")
    lines.extend(
        (
            "PF_PI|targetCount|2",
            "PF_PI|denylistCount|5",
            "PF_PI|droidGuardVmCount|1",
            "PF_PI|complete|1",
        )
    )
    return "\n".join(lines)


def pif_inventory_output(*, targets: tuple[str, ...] = ("com.google.android.gms",)) -> str:
    specs = (
        ("pif.custom_json", "playintegrityfix", "json"),
        ("pif.custom_prop", "playintegrityfix", "prop"),
        ("pif.module_json", "playintegrityfix", "json"),
        ("pif.legacy_json", "playintegrityfix", "json"),
        ("pif.app_replace", "playintegrityfix", "list"),
        ("pif.scripts_only", "playintegrityfix", "marker"),
        ("tricky.spoof", "tricky_store", "prop"),
        ("tricky.target", "tricky_store", "list"),
        ("tricky.security_patch", "tricky_store", "text"),
        ("tricky.tee", "tricky_store", "text"),
        ("targeted.targets", "targetedfix", "list"),
    )
    lines = ["PF_PIF|schema|1", "PF_PIF|root|verified"]
    for index, (profile_id, module, profile_format) in enumerate(specs):
        state, size, digest = ("present", "128", "a" * 64) if index == 0 else ("absent", "0", "-")
        lines.append(
            f"PF_PIF|profile|{profile_id}|{module}|{profile_format}|{state}|{size}|{digest}"
        )
    for package_name in targets:
        encoded = base64.b64encode(package_name.encode()).decode()
        lines.append(f"PF_PIF|target|{encoded}|json|present|64|{'b' * 64}")
    lines.append("PF_PIF|complete|1")
    return "\n".join(lines)


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
            devices=(
                DeviceInfo(
                    "SERIAL",
                    codename="akita",
                    mode="adb",
                    root=True,
                    online=True,
                    build="AP4A.260101.001",
                ),
            ),
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

    def test_shizuku_start_uses_only_backend_owned_paths_and_requires_observation(self):
        compilation = RootingService().compile(
            self.command(
                "tools.shizuku",
                {"serial": "SERIAL", "action": "start"},
            ),
            self.snapshot,
        )

        self.assertEqual("recovery.shizuku", compilation.action)
        self.assertTrue(compilation.device_write)
        self.assertTrue(compilation.requires_confirmation)
        assert compilation.plan is not None
        request = compilation.plan.requests[0]
        self.assertEqual(("ADB", "-s", "SERIAL", "shell", "sh", "-c"), request.argv[:6])
        self.assertIn("moe.shizuku.privileged.api", request.argv[6])
        self.assertIn("/data/app/*/base.apk", request.argv[6])
        self.assertIn("getprop ro.product.cpu.abi", request.argv[6])
        self.assertIn("x86_64", request.argv[6])
        self.assertEqual("shizuku_state", compilation.plan.postconditions[0].kind)
        self.assertEqual({"running": True}, compilation.plan.postconditions[0].expected)

    def test_shizuku_rejects_aliases_and_non_adb_devices(self):
        service = RootingService()
        with self.assertRaises(RootingPlanningError) as alias:
            service.compile(
                self.command(
                    "tools.shizuku",
                    {"serial": "SERIAL", "action": "run"},
                ),
                self.snapshot,
            )
        self.assertEqual("shizuku_action_invalid", alias.exception.code)

        fastboot = AppSnapshot(
            revision=9,
            devices=(DeviceInfo("SERIAL", mode="fastboot", root=True, online=True),),
            selected_serial="SERIAL",
            toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
        )
        with self.assertRaises(RootingPlanningError) as state:
            service.compile(
                self.command(
                    "tools.shizuku",
                    {"serial": "SERIAL", "action": "start"},
                ),
                fastboot,
            )
        self.assertEqual("adb_device_required", state.exception.code)

    def test_sos_disables_without_deleting_and_binds_reinforced_text(self):
        compilation = RootingService().compile(
            self.command(
                "tools.sos",
                {
                    "serial": "SERIAL",
                    "action": "disableModules",
                    "confirmationText": "SOS SERIAL",
                },
            ),
            self.snapshot,
        )

        self.assertEqual("recovery.sos", compilation.action)
        self.assertTrue(compilation.device_write)
        self.assertFalse(compilation.destructive)
        assert compilation.plan is not None
        request = compilation.plan.requests[0]
        self.assertEqual(("ADB", "-s", "SERIAL", "shell", "su", "-c"), request.argv[:6])
        self.assertIn('touch "$dir/disable"', request.argv[6])
        self.assertNotIn("rm ", request.argv[6])
        self.assertEqual("magisk_modules_state", compilation.plan.postconditions[0].kind)
        self.assertEqual(
            {"allDisabled": True},
            compilation.plan.postconditions[0].expected,
        )

    def test_sos_rejects_wrong_confirmation_and_rootless_device(self):
        payload = {
            "serial": "SERIAL",
            "action": "disableModules",
            "confirmationText": "SOS WRONG",
        }
        with self.assertRaises(RootingPlanningError) as confirmation:
            RootingService().compile(self.command("tools.sos", payload), self.snapshot)
        self.assertEqual("sos_confirmation_required", confirmation.exception.code)

        rootless = AppSnapshot(
            revision=9,
            devices=(DeviceInfo("SERIAL", mode="adb", root=False, online=True),),
            selected_serial="SERIAL",
            toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
        )
        with self.assertRaises(RootingPlanningError) as root:
            RootingService().compile(
                self.command(
                    "tools.sos",
                    {
                        "serial": "SERIAL",
                        "action": "disableModules",
                        "confirmationText": "SOS SERIAL",
                    },
                ),
                rootless,
            )
        self.assertEqual("root_access_required", root.exception.code)

    def test_pi_analysis_compiles_one_fixed_read_only_redacted_probe(self):
        compilation = RootingService().compile(
            self.command(
                "tools.piAnalysis",
                {"serial": "SERIAL", "action": "analyze"},
            ),
            self.snapshot,
        )

        self.assertEqual("pi_analysis", compilation.action)
        self.assertEqual("AP4A.260101.001", compilation.device_build)
        self.assertFalse(compilation.device_write)
        self.assertFalse(compilation.destructive)
        self.assertFalse(compilation.requires_confirmation)
        assert compilation.plan is not None
        request = compilation.plan.request
        self.assertEqual(("ADB", "-s", "SERIAL", "shell", "su", "-c"), request.argv[:6])
        self.assertEqual(256 * 1024, request.output_limit_bytes)
        script = request.argv[6]
        self.assertIn("PF_PI|schema|1", script)
        self.assertIn("/data/adb/tricky_store/keybox.xml", script)
        self.assertIn("hash_allowed", script)
        self.assertIn("targetCount", script)
        self.assertNotIn("cat /data/adb/tricky_store/keybox.xml", script)
        self.assertNotIn("android_id", script.casefold())
        self.assertNotIn("logcat", script.casefold())
        self.assertEqual((), compilation.plan.postconditions)

    def test_pi_analysis_rejects_alias_unknown_fields_and_rootless_device(self):
        service = RootingService()
        for payload, code in (
            ({"serial": "SERIAL", "action": "report"}, "pi_analysis_action_invalid"),
            (
                {"serial": "SERIAL", "action": "analyze", "includeSecrets": True},
                "invalid_rooting_payload",
            ),
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(RootingPlanningError) as raised:
                    service.compile(self.command("tools.piAnalysis", payload), self.snapshot)
                self.assertEqual(code, raised.exception.code)

        rootless = AppSnapshot(
            revision=9,
            devices=(DeviceInfo("SERIAL", codename="akita", mode="adb", root=False),),
            selected_serial="SERIAL",
            toolchain=self.snapshot.toolchain,
        )
        with self.assertRaises(RootingPlanningError) as raised:
            service.compile(
                self.command(
                    "tools.piAnalysis",
                    {"serial": "SERIAL", "action": "analyze"},
                ),
                rootless,
            )
        self.assertEqual("root_access_required", raised.exception.code)

    def test_pif_inventory_is_fixed_read_only_and_excludes_keybox(self):
        compilation = RootingService().compile(
            self.command("root.pif.inventory", {"serial": "SERIAL"}),
            self.snapshot,
        )

        self.assertEqual("pif.inventory", compilation.action)
        self.assertFalse(compilation.device_write)
        assert compilation.plan is not None
        request = compilation.plan.request
        self.assertEqual(("ADB", "-s", "SERIAL", "shell", "su", "-c"), request.argv[:6])
        self.assertEqual(128 * 1024, request.output_limit_bytes)
        script = request.argv[6]
        self.assertIn("PF_PIF|schema|1", script)
        self.assertIn("/data/adb/modules/targetedfix/config/target.txt", script)
        self.assertNotIn("keybox", script.casefold())
        self.assertNotIn("cat ", script)

    def test_pif_inventory_parser_is_closed_ordered_and_hash_verified(self):
        value = parse_pif_inventory(pif_inventory_output())

        self.assertEqual(11, value["count"])
        self.assertEqual(1, value["targetCount"])
        self.assertEqual("pif.custom_json", value["profiles"][0]["id"])
        self.assertEqual("com.google.android.gms", value["targets"][0]["packageName"])
        self.assertNotIn("path", repr(value).casefold())

        malformed = (
            pif_inventory_output().replace("pif.custom_json", "pif.legacy_json", 1),
            pif_inventory_output(targets=("../private",)),
            pif_inventory_output(targets=("com.example.app", "COM.EXAMPLE.APP")),
            pif_inventory_output().replace("PF_PIF|complete|1", "PRIVATE_RAW"),
            pif_inventory_output().replace("a" * 64, "-", 1),
        )
        for output in malformed:
            with self.subTest(output=output[-80:]):
                with self.assertRaises(RootingPlanningError):
                    parse_pif_inventory(output)

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
                apk_inspector=FakeVerifiedApkInspector(),
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
            self.assertTrue(all(len(item.id) == 64 for item in compilation.root_apps))
            self.assertTrue(all(item.signer_sha256 == ("a" * 64,) for item in compilation.root_apps))
            self.assertTrue(all(item.schemes == ("v2",) for item in compilation.root_apps))
            self.assertNotIn("path", compilation.root_apps[0].to_dict())
            self.assertEqual(
                ["a" * 64],
                compilation.root_apps[0].to_dict()["signerSha256"],
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
                        ),
                        apk_inspector=FakeVerifiedApkInspector(),
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
                        "com.topjohnwu.magisk",
                    ),
                ),
                apk_inspector=FakeVerifiedApkInspector("com.topjohnwu.magisk"),
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
            self.assertEqual("mutating", compilation.plan.risk.value)
            self.assertEqual(
                ("root_app_installed",),
                tuple(item.kind for item in compilation.plan.postconditions),
            )
            self.assertEqual(
                "com.topjohnwu.magisk",
                compilation.plan.postconditions[0].expected["packageName"],
            )

    def test_root_app_install_uses_verified_identity_when_metadata_omits_package(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "Magisk.apk"
            digest = hashlib.sha256(
                write_apk(
                    apk,
                    b'<manifest package="com.topjohnwu.magisk" />',
                )
            ).hexdigest()
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
                ),
                apk_inspector=FakeVerifiedApkInspector("com.topjohnwu.magisk"),
            )
            app = service.root_app_inventory()[0]

            compilation = service.compile(
                self.command("root.apps.install", {"appId": app.id}),
                self.snapshot,
            )

            self.assertEqual("com.topjohnwu.magisk", app.package_name)
            self.assertEqual(
                "com.topjohnwu.magisk",
                compilation.plan.postconditions[0].expected["packageName"],
            )

    def test_root_app_metadata_package_must_match_verified_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "Magisk.apk"
            digest = hashlib.sha256(write_apk(apk)).hexdigest()
            service = RootingService(
                (
                    RootAppSource(
                        str(apk),
                        "Magisk",
                        "stable",
                        "30.7",
                        "official",
                        digest,
                        "com.topjohnwu.magisk",
                    ),
                ),
                apk_inspector=FakeVerifiedApkInspector("com.evil.repacked"),
            )

            with self.assertRaises(RootingPlanningError) as raised:
                service.root_app_inventory()

            self.assertEqual("root_app_package_mismatch", raised.exception.code)

    def test_inventory_uses_inspector_digest_without_a_second_service_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "imported.apk"
            write_apk(apk)
            inspected_digest = "b" * 64
            service = RootingService(
                (
                    RootAppSource(
                        str(apk),
                        "Magisk",
                        "imported",
                        "30.7",
                        "user-import",
                    ),
                ),
                apk_inspector=FakeVerifiedApkInspector(
                    identity_sha256=inspected_digest,
                ),
            )

            app = service.root_app_inventory()[0]

            self.assertEqual(inspected_digest, app.sha256)
            self.assertNotEqual(
                hashlib.sha256(apk.read_bytes()).hexdigest(),
                app.sha256,
            )

    def test_unsigned_apk_signature_failure_and_source_change_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "Magisk.apk"
            digest = hashlib.sha256(
                write_apk(
                    apk,
                    b'<manifest package="com.topjohnwu.magisk" />',
                )
            ).hexdigest()
            source = RootAppSource(
                str(apk),
                "Magisk",
                "stable",
                "30.7",
                "official",
                digest,
            )

            with self.assertRaises(RootingPlanningError) as unsigned:
                RootingService((source,)).root_app_inventory()
            self.assertEqual("apk_signature_missing", unsigned.exception.code)

            for inspection_code in (
                ApkInspectionCode.SIGNATURE_INVALID,
                ApkInspectionCode.SOURCE_CHANGED,
            ):
                with self.subTest(code=inspection_code.value):
                    inspector = FakeVerifiedApkInspector(
                        error=ApkInspectionError(inspection_code, "verification failed")
                    )
                    with self.assertRaises(RootingPlanningError) as raised:
                        RootingService(
                            (source,),
                            apk_inspector=inspector,
                        ).root_app_inventory()
                    self.assertEqual(inspection_code.value, raised.exception.code)

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
            ("ADB", "-s", "SERIAL", "shell", "su", "-c"),
            compilation.plan.request.argv[:6],
        )
        script = compilation.plan.request.argv[6]
        self.assertIn("for dir in /data/adb/modules/*", script)
        self.assertIn("module.prop", script)
        self.assertIn("base64", script)
        self.assertIn("PF_RM|%s|%s", script)
        self.assertEqual(256 * 1024, compilation.plan.request.output_limit_bytes)
        self.assertFalse(compilation.device_write)
        self.assertFalse(compilation.requires_confirmation)

    def test_module_state_actions_compile_exact_allowlisted_commands(self):
        expected = {
            "enable": ("rm -f /data/adb/modules/zygisk_next/disable /data/adb/modules/zygisk_next/remove"),
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
                self.assertEqual(
                    "destructive" if action == "remove" else "mutating",
                    compilation.plan.risk.value,
                )
                postcondition = compilation.plan.postconditions[0]
                self.assertEqual("root_module_state", postcondition.kind)
                self.assertEqual("zygisk_next", postcondition.expected["moduleId"])

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
            self.assertEqual("destructive", compilation.plan.risk.value)
            self.assertEqual(
                ("root_module_state",),
                tuple(item.kind for item in compilation.plan.postconditions),
            )

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

    def test_root_app_inspection_uses_same_token_and_normalizes_cancellation(self):
        token = CancellationToken()

        class CancellingInspector:
            def inspect(
                self,
                path: str | os.PathLike[str],
                *,
                cancellation: CancellationProbe | None = None,
            ) -> NoReturn:
                _ = path
                if cancellation is not token:
                    raise AssertionError(
                        "RootingService did not forward its cancellation token"
                    )
                token.cancel()
                raise ApkInspectionError(
                    ApkInspectionCode.CANCELLED,
                    "inspection cancelled inside APK I/O",
                )

        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "Magisk.apk"
            write_apk(apk)
            service = RootingService(
                (
                    RootAppSource(
                        str(apk),
                        "Magisk",
                        "stable",
                        "30.7",
                        "user-import",
                    ),
                ),
                apk_inspector=CancellingInspector(),
            )

            with self.assertRaises(RootingPlanningError) as raised:
                service.compile(
                    AppCommand("root.apps.list", expected_revision=9),
                    AppSnapshot(revision=9),
                    token,
                )

        self.assertEqual("rooting_cancelled", raised.exception.code)


class RootModuleParserTests(unittest.TestCase):
    def test_parser_returns_sorted_bounded_metadata_without_update_url(self):
        parsed = parse_root_module_list(
            "\n".join(
                (
                    module_record("zygisk_next", state="disabled", name="Zygisk Next"),
                    module_record(
                        "play_integrity_fix",
                        name="Play Integrity Fix",
                        version="19.1",
                        version_code="19100",
                        update_url="https://example.test/update.json",
                    ),
                )
            )
        )

        self.assertEqual(
            ["play_integrity_fix", "zygisk_next"],
            [module.id for module in parsed],
        )
        self.assertEqual("Play Integrity Fix", parsed[0].name)
        self.assertEqual(19100, parsed[0].version_code)
        self.assertEqual("https://example.test/update.json", parsed[0].update_url)
        self.assertEqual("available", parsed[0].to_dict()["updateMetadata"])

    def test_parser_rejects_malformed_duplicate_and_unsafe_metadata(self):
        cases = (
            "../escape",
            module_record("zygisk_next") + "\n" + module_record("ZYGISK_NEXT"),
            module_record("zygisk_next", update_url="http://example.test/update.json"),
            module_record("zygisk_next", version_code="1;reboot"),
            "PF_RM|zygisk_next|enabled|not-base64|||||",
        )
        for output in cases:
            with self.subTest(output=output):
                with self.assertRaises(RootingPlanningError) as raised:
                    parse_root_module_list(output)
                self.assertEqual("root_module_list_malformed", raised.exception.code)


class PiAnalysisParserTests(unittest.TestCase):
    def test_parser_returns_closed_redacted_report_without_device_identity(self):
        report = parse_pi_analysis(
            pi_analysis_output(),
            device_codename="akita",
            build="AP4A.260101.001",
        )

        self.assertTrue(report["redacted"])
        self.assertTrue(report["complete"])
        self.assertNotIn("SERIAL", repr(report))
        self.assertNotIn("targetSerial", repr(report))
        self.assertNotIn("certificate", repr(report).casefold())
        self.assertEqual(
            {
                "targetedFixTargetCount": 2,
                "magiskDenylistCount": 5,
                "droidGuardVmCount": 1,
            },
            report["signals"],
        )
        configs = {
            str(item["kind"]): item
            for item in report["configs"]  # type: ignore[union-attr]
        }
        self.assertIsNone(configs["keybox"]["sha256"])
        self.assertEqual("a" * 64, configs["pif_custom_json"]["sha256"])
        self.assertEqual(
            ["playintegrityfix", "tricky_store"],
            [item["id"] for item in report["modules"]],  # type: ignore[union-attr]
        )

    def test_parser_rejects_partial_unknown_duplicate_and_secret_keybox_digest(self):
        valid = pi_analysis_output()
        cases = (
            valid.removesuffix("\nPF_PI|complete|1"),
            valid.replace("PF_PI|targetCount|2", "PF_PI|unknown|2"),
            valid.replace(
                "PF_PI|denylistCount|5",
                "PF_PI|denylistCount|5\nPF_PI|denylistCount|5",
            ),
            valid.replace(
                "PF_PI|config|keybox|present|2048|-",
                f"PF_PI|config|keybox|present|2048|{'b' * 64}",
            ),
            valid.replace(
                "PF_PI|config|pif_custom_json|present|512|",
                "PF_PI|config|pif_custom_json|present|4194305|",
            ),
        )
        for output in cases:
            with self.subTest(output=output[-120:]):
                with self.assertRaises(RootingPlanningError):
                    parse_pi_analysis(
                        output,
                        device_codename="akita",
                        build="AP4A.260101.001",
                    )


if __name__ == "__main__":
    unittest.main()
