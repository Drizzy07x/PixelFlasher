import hashlib
import tempfile
import unittest
import zipfile
import sys
from dataclasses import replace
from pathlib import Path

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    AppStateStore,
    BackupService,
    CommandExecutor,
    DeviceInfo,
    DeviceToolsService,
    FakeProcessTransport,
    InteractionDecision,
    LaunchOutcome,
    OperationStatus,
    PackageService,
    PixelFlasherEngine,
    RootAppSource,
    RootingService,
    SafetyPolicy,
    ToolchainInfo,
    TransportOutcome,
)


class RecordingLauncher:
    def __init__(self, *, error=None):
        self.error = error
        self.calls = []
        self.shutdown_called = False

    def launch(self, request):
        self.calls.append(request)
        if self.error is not None:
            raise self.error
        return LaunchOutcome(4242)

    def shutdown(self):
        self.shutdown_called = True


class RecordingSecretRunner:
    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = []

    def run(self, request, secret, cancellation):
        self.calls.append((request, secret))
        return self.outcome


def write_scrcpy_executable(path: Path) -> None:
    path.write_bytes(
        b"MZ\x00\x00fake scrcpy"
        if sys.platform.startswith("win")
        else b"#!/bin/sh\nexit 0\n"
    )
    if not sys.platform.startswith("win"):
        path.chmod(path.stat().st_mode | 0o111)


def snapshot_for(mode: str, *, revision: int = 4, root: bool = False) -> AppSnapshot:
    return AppSnapshot(
        revision=revision,
        devices=(
            DeviceInfo(
                "SERIAL",
                codename="akita",
                mode=mode,
                root=root,
                online=True,
            ),
        ),
        selected_serial="SERIAL",
        toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
    )


def command(kind: str, payload=None, *, revision: int = 4) -> AppCommand:
    return AppCommand(
        kind,
        expected_revision=revision,
        target_serial="SERIAL",
        payload=payload or {},
    )


class BackupCreatingTransport(FakeProcessTransport):
    """Fake process boundary which materializes a successful fetch output."""

    def __init__(self, contents: bytes):
        super().__init__([TransportOutcome(0, "fetched backup\n")])
        self.contents = contents

    def run(self, request, cancellation):
        outcome = super().run(request, cancellation)
        if outcome.returncode == 0 and not outcome.cancelled and not outcome.timed_out:
            Path(request.argv[-1]).write_bytes(self.contents)
        return outcome


def write_root_apk(path: Path, payload: bytes = b"manifest") -> bytes:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", payload)
        archive.writestr("classes.dex", b"dex")
    return path.read_bytes()


def write_root_module(path: Path, module_id: str = "test_module") -> bytes:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "module.prop",
            f"id={module_id}\nname=Test Module\n".encode(),
        )
        archive.writestr("service.sh", b"#!/system/bin/sh\n")
    return path.read_bytes()


class ServiceEngineIntegrationTests(unittest.TestCase):
    def engine_for(
        self,
        mode,
        outcomes,
        *,
        interaction_handler=None,
        root=False,
        rooting_service=None,
        device_tools_service=None,
    ):
        transport = FakeProcessTransport(outcomes)
        engine = PixelFlasherEngine(
            store=AppStateStore(snapshot_for(mode, root=root)),
            executor=CommandExecutor(transport),
            rooting_service=rooting_service,
            device_tools_service=device_tools_service,
            interaction_handler=(
                interaction_handler
                if interaction_handler is not None
                else lambda _request: InteractionDecision.CANCELLED
            ),
        )
        return engine, transport

    def test_apps_list_runs_through_executor_and_stores_parsed_result(self):
        engine, transport = self.engine_for(
            "adb",
            [
                TransportOutcome(
                    0,
                    "package:/data/app/b/base.apk=com.example.beta uid:10124\n"
                    "malformed\n"
                    "package:/data/app/a/base.apk=com.example.alpha uid:10123\n",
                )
            ],
        )

        result = engine.execute(command("apps.list", {"scope": "user"}))

        self.assertEqual(OperationStatus.SUCCESS, result.status)
        self.assertEqual("apps_list_succeeded", result.code)
        self.assertEqual(2, result.value["count"])
        self.assertEqual(
            ["com.example.alpha", "com.example.beta"],
            [item["package"] for item in result.value["packages"]],
        )
        self.assertEqual(
            [
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
                )
            ],
            [request.argv for request in transport.calls],
        )
        self.assertEqual(result, engine.store.snapshot().last_result)

    def test_partition_list_parses_fastboot_stderr_after_success(self):
        engine, transport = self.engine_for(
            "fastboot",
            [
                TransportOutcome(
                    0,
                    stderr=(
                        "(bootloader) partition-type:boot_a: raw\n"
                        "(bootloader) partition-size:boot_a: 0x1000\n"
                        "(bootloader) partition-size:userdata: 8192\n"
                        "(bootloader) partition-size:evil;erase: 0x1\n"
                    ),
                )
            ],
        )

        result = engine.execute(command("partitions.list"))

        self.assertTrue(result.ok)
        self.assertEqual("partitions_list_succeeded", result.code)
        self.assertEqual(
            ["boot_a", "userdata"],
            [item["name"] for item in result.value["partitions"]],
        )
        self.assertEqual(4096, result.value["partitions"][0]["size_bytes"])
        self.assertEqual(
            [("FASTBOOT", "-s", "SERIAL", "getvar", "all")],
            [request.argv for request in transport.calls],
        )

    def test_partition_erase_uses_backend_challenge_before_reinforced_confirmation(self):
        interactions = []
        engine, transport = self.engine_for(
            "fastboot",
            [TransportOutcome(0)],
            interaction_handler=lambda request: interactions.append(request) or InteractionDecision.ACCEPTED,
        )

        challenge = engine.execute(command("partitions.erase", {"partition": "userdata"}))
        required = challenge.value["confirmation"]["required_text"]
        result = engine.execute(
            command(
                "partitions.erase",
                {"partition": "userdata", "confirmationText": required},
            )
        )

        self.assertEqual("confirmation_text_required", challenge.code)
        self.assertEqual("ERASE SERIAL userdata", required)
        self.assertTrue(result.ok)
        self.assertEqual(
            [("FASTBOOT", "-s", "SERIAL", "erase", "userdata")],
            [request.argv for request in transport.calls],
        )
        self.assertEqual(1, len(interactions))
        self.assertTrue(interactions[0].reinforced)

    def test_logcat_returns_bounded_line_model_and_never_uses_shell(self):
        engine, transport = self.engine_for(
            "adb",
            [TransportOutcome(0, "07-18 I/Activity: ready\n07-18 E/System: failed\n")],
        )

        result = engine.execute(
            command(
                "tools.logcat",
                {
                    "buffers": ["main"],
                    "format": "threadtime",
                    "filters": {"Activity": "info"},
                    "maxLines": 25,
                    "timeoutSeconds": 5,
                },
            )
        )

        self.assertTrue(result.ok)
        self.assertEqual("logcat_collected", result.code)
        self.assertEqual(2, result.value["lineCount"])
        self.assertEqual(
            ["07-18 I/Activity: ready", "07-18 E/System: failed"],
            result.value["lines"],
        )
        self.assertEqual(
            (
                "ADB",
                "-s",
                "SERIAL",
                "logcat",
                "-d",
                "-b",
                "main",
                "-v",
                "threadtime",
                "-t",
                "25",
                "Activity:I",
                "*:S",
            ),
            transport.calls[0].argv,
        )
        self.assertNotIn("shell", transport.calls[0].argv)

    def test_scrcpy_launch_is_serial_bound_managed_and_never_uses_executor(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / (
                "scrcpy.exe" if sys.platform.startswith("win") else "scrcpy"
            )
            write_scrcpy_executable(executable)
            launcher = RecordingLauncher()
            service = DeviceToolsService(
                scrcpy_executable=executable,
                process_launcher=launcher,
            )
            engine, transport = self.engine_for(
                "adb",
                [],
                device_tools_service=service,
            )

            result = engine.execute(command("tools.scrcpy"))

            self.assertTrue(result.ok)
            self.assertEqual("scrcpy_launched", result.code)
            self.assertEqual("SERIAL", result.value["targetSerial"])
            self.assertEqual(4242, result.value["pid"])
            self.assertEqual([], transport.calls)
            self.assertEqual(
                [(str(executable.resolve()), "--serial", "SERIAL")],
                [request.argv for request in launcher.calls],
            )
            self.assertEqual(result, engine.store.snapshot().last_result)

            engine.shutdown()
            self.assertTrue(launcher.shutdown_called)

    def test_scrcpy_launch_failure_is_explicit_and_does_not_fake_success(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / (
                "scrcpy.exe" if sys.platform.startswith("win") else "scrcpy"
            )
            write_scrcpy_executable(executable)
            launcher = RecordingLauncher(error=OSError("launch denied"))
            engine, transport = self.engine_for(
                "adb",
                [],
                device_tools_service=DeviceToolsService(
                    scrcpy_executable=executable,
                    process_launcher=launcher,
                ),
            )

            result = engine.execute(command("tools.scrcpy"))

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("scrcpy_launch_failed", result.code)
            self.assertEqual([], transport.calls)
            self.assertEqual(result, engine.store.snapshot().last_result)

    def test_scrcpy_executable_hash_is_revalidated_immediately_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / (
                "scrcpy.exe" if sys.platform.startswith("win") else "scrcpy"
            )
            write_scrcpy_executable(executable)
            launcher = RecordingLauncher()

            class MutatingService(DeviceToolsService):
                def compile(self, command, snapshot):
                    compilation = super().compile(command, snapshot)
                    executable.write_bytes(executable.read_bytes() + b"changed")
                    return compilation

            engine, transport = self.engine_for(
                "adb",
                [],
                device_tools_service=MutatingService(
                    scrcpy_executable=executable,
                    process_launcher=launcher,
                ),
            )

            result = engine.execute(command("tools.scrcpy"))

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("artifact_hash_mismatch", result.code)
            self.assertEqual([], launcher.calls)
            self.assertEqual([], transport.calls)

    def test_wifi_connect_disconnect_and_status_require_verified_adb_output(self):
        cases = (
            (
                {"action": "connect", "host": "192.0.2.10", "port": 5555},
                "connected to 192.0.2.10:5555\n",
                "wifi_connect_succeeded",
            ),
            (
                {"action": "disconnect", "host": "192.0.2.10", "port": 5555},
                "disconnected 192.0.2.10:5555\n",
                "wifi_disconnect_succeeded",
            ),
            ({"action": "status"}, "device\n", "wifi_status_succeeded"),
        )
        for payload, stdout, expected_code in cases:
            with self.subTest(action=payload["action"]):
                engine, transport = self.engine_for(
                    "adb",
                    [TransportOutcome(0, stdout)],
                )
                result = engine.execute(command("tools.wifi", payload))

                self.assertTrue(result.ok)
                self.assertEqual(expected_code, result.code)
                self.assertNotIn("shell", transport.calls[0].argv)
                self.assertEqual("SERIAL", result.value["targetSerial"])

        engine, _transport = self.engine_for(
            "adb",
            [TransportOutcome(0, "failed to connect to 192.0.2.10:5555\n")],
        )
        failed = engine.execute(
            command(
                "tools.wifi",
                {"action": "connect", "host": "192.0.2.10", "port": 5555},
            )
        )
        self.assertEqual(OperationStatus.FAILED, failed.status)
        self.assertEqual("wifi_connect_failed", failed.code)

        engine, _transport = self.engine_for(
            "adb",
            [TransportOutcome(1, stderr="daemon rejected connection")],
        )
        process_failed = engine.execute(
            command(
                "tools.wifi",
                {"action": "connect", "host": "192.0.2.10", "port": 5555},
            )
        )
        self.assertEqual(OperationStatus.FAILED, process_failed.status)
        self.assertEqual("wifi_connect_failed", process_failed.code)

    def test_wifi_pairing_secret_uses_stdin_only_and_is_never_returned(self):
        secret = "123456"
        runner = RecordingSecretRunner(
            TransportOutcome(
                0,
                (
                    "Enter pairing code: Successfully paired to "
                    f"192.0.2.20:37123 [guid=test]\ninput={secret}\n"
                ),
                f"diagnostic repeated {secret}",
            )
        )
        service = DeviceToolsService(secret_runner=runner)
        engine, transport = self.engine_for(
            "adb",
            [],
            device_tools_service=service,
        )
        pairing_command = command(
            "tools.wifi",
            {
                "action": "pair",
                "host": "192.0.2.20",
                "port": 37123,
                "pairingCode": secret,
            },
        )

        result = engine.execute(pairing_command)

        self.assertTrue(result.ok)
        self.assertEqual("wifi_pair_succeeded", result.code)
        self.assertEqual([], transport.calls)
        self.assertEqual(
            ("ADB", "pair", "192.0.2.20:37123"),
            runner.calls[0][0].argv,
        )
        self.assertEqual(secret, runner.calls[0][1])
        self.assertNotIn(secret, str(pairing_command.to_dict()))
        self.assertNotIn(secret, str(result.to_dict()))
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)

    def test_wifi_pairing_false_success_and_process_failure_are_explicit_and_redacted(self):
        secret = "654321"
        for outcome in (
            TransportOutcome(0, f"failed: echoed {secret}"),
            TransportOutcome(1, f"input={secret}", f"rejected {secret}"),
        ):
            with self.subTest(returncode=outcome.returncode):
                runner = RecordingSecretRunner(outcome)
                engine, _transport = self.engine_for(
                    "adb",
                    [],
                    device_tools_service=DeviceToolsService(secret_runner=runner),
                )
                result = engine.execute(
                    command(
                        "tools.wifi",
                        {
                            "action": "pair",
                            "host": "192.0.2.20",
                            "port": 37123,
                            "pairingCode": secret,
                        },
                    )
                )
                self.assertEqual(OperationStatus.FAILED, result.status)
                self.assertEqual("wifi_pair_failed", result.code)
                self.assertNotIn(secret, str(result.to_dict()))
                self.assertEqual("", result.stdout)
                self.assertEqual("", result.stderr)

    def test_push_files_confirms_revalidates_and_returns_verified_mapping(self):
        interactions = []
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "alpha.bin"
            second = Path(directory) / "beta.zip"
            first.write_bytes(b"alpha")
            second.write_bytes(b"beta")
            engine, transport = self.engine_for(
                "adb",
                [
                    TransportOutcome(0, "alpha.bin: 1 file pushed\n"),
                    TransportOutcome(0, "beta.zip: 1 file pushed\n"),
                ],
                interaction_handler=(
                    lambda request: interactions.append(request)
                    or InteractionDecision.ACCEPTED
                ),
            )

            result = engine.execute(
                command(
                    "tools.pushFiles",
                    {
                        "paths": [str(first), str(second)],
                        "destination": "/data/local/tmp/",
                    },
                )
            )

        self.assertTrue(result.ok)
        self.assertEqual("files_pushed", result.code)
        self.assertEqual(2, result.value["count"])
        self.assertEqual(
            ["/data/local/tmp/alpha.bin", "/data/local/tmp/beta.zip"],
            [item["destination"] for item in result.value["files"]],
        )
        self.assertEqual(
            [
                hashlib.sha256(b"alpha").hexdigest(),
                hashlib.sha256(b"beta").hexdigest(),
            ],
            [item["sha256"] for item in result.value["files"]],
        )
        self.assertEqual(1, len(interactions))
        self.assertEqual("SERIAL", interactions[0].target_serial)
        self.assertFalse(interactions[0].destructive)
        self.assertEqual(2, len(transport.calls))

    def test_push_source_changed_during_confirmation_fails_before_process(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "payload.bin"
            source.write_bytes(b"before")

            def mutate_then_accept(_request):
                source.write_bytes(b"after")
                return InteractionDecision.ACCEPTED

            engine, transport = self.engine_for(
                "adb",
                [],
                interaction_handler=mutate_then_accept,
            )
            result = engine.execute(
                command(
                    "tools.pushFiles",
                    {
                        "paths": [str(source)],
                        "destination": "/sdcard/Download/",
                    },
                )
            )

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("artifact_hash_mismatch", result.code)
        self.assertEqual([], transport.calls)

    def test_backup_create_finalizes_output_and_returns_verified_artifact(self):
        contents = b"backend-created boot partition backup"
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "boot_a.img"
            transport = BackupCreatingTransport(contents)
            engine = PixelFlasherEngine(
                store=AppStateStore(snapshot_for("fastboot")),
                executor=CommandExecutor(transport),
            )

            result = engine.execute(
                command(
                    "backups.create",
                    {
                        "partition": "boot",
                        "slot": "a",
                        "destination": str(destination),
                    },
                )
            )

            self.assertTrue(result.ok)
            self.assertEqual("backup_created", result.code)
            self.assertEqual("boot_a", result.value["partition"])
            self.assertEqual("a", result.value["slot"])
            self.assertEqual(str(destination.resolve()), result.value["artifact"]["path"])
            self.assertEqual(
                hashlib.sha256(contents).hexdigest(),
                result.value["artifact"]["sha256"],
            )
            self.assertEqual(
                (
                    "FASTBOOT",
                    "-s",
                    "SERIAL",
                    "fetch",
                    "boot_a",
                    str(destination.resolve()),
                ),
                transport.calls[0].argv,
            )
            self.assertEqual(result, engine.store.snapshot().last_result)

    def test_backup_create_success_without_output_is_an_explicit_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "boot_a.img"
            engine, transport = self.engine_for(
                "fastboot",
                [TransportOutcome(0, "device claimed success")],
            )

            result = engine.execute(
                command(
                    "backups.create",
                    {
                        "partition": "boot",
                        "slot": "a",
                        "destination": str(destination),
                    },
                )
            )

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("backup_output_missing", result.code)
            self.assertEqual(1, len(transport.calls))
            self.assertEqual(result, engine.store.snapshot().last_result)

    def test_backup_create_empty_output_is_never_reported_as_success(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "boot_a.img"
            transport = BackupCreatingTransport(b"")
            engine = PixelFlasherEngine(
                store=AppStateStore(snapshot_for("fastboot")),
                executor=CommandExecutor(transport),
            )

            result = engine.execute(
                command(
                    "backups.create",
                    {
                        "partition": "boot",
                        "slot": "a",
                        "destination": str(destination),
                    },
                )
            )

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("backup_output_empty", result.code)

    def test_backup_restore_uses_backend_risk_metadata_and_verified_artifact(self):
        interactions = []
        contents = b"verified restore image"
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "vendor_boot_b.img"
            image.write_bytes(contents)
            engine, transport = self.engine_for(
                "fastboot",
                [TransportOutcome(0, "finished\n")],
                interaction_handler=(
                    lambda request: interactions.append(request)
                    or InteractionDecision.ACCEPTED
                ),
            )

            # The UI command deliberately carries no risk booleans. The engine
            # must replace them with backend-owned BackupCompilation metadata.
            result = engine.execute(
                command(
                    "backups.restore",
                    {
                        "partition": "vendor_boot",
                        "slot": "b",
                        "path": str(image),
                    },
                )
            )

            self.assertTrue(result.ok)
            self.assertEqual("backup_restored", result.code)
            self.assertEqual("vendor_boot_b", result.value["partition"])
            self.assertEqual(
                hashlib.sha256(contents).hexdigest(),
                result.value["artifact"]["sha256"],
            )
            self.assertEqual(1, len(interactions))
            self.assertTrue(interactions[0].destructive)
            self.assertEqual("SERIAL", interactions[0].target_serial)
            self.assertEqual(
                (
                    "FASTBOOT",
                    "-s",
                    "SERIAL",
                    "flash",
                    "vendor_boot_b",
                    str(image.resolve()),
                ),
                transport.calls[0].argv,
            )

    def test_backup_restore_is_revalidated_after_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "boot_a.img"
            image.write_bytes(b"before")

            def mutate_then_accept(_request):
                image.write_bytes(b"after")
                return InteractionDecision.ACCEPTED

            engine, transport = self.engine_for(
                "fastboot",
                [],
                interaction_handler=mutate_then_accept,
            )
            result = engine.execute(
                command(
                    "backups.restore",
                    {"partition": "boot", "slot": "a", "path": str(image)},
                )
            )

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("artifact_hash_mismatch", result.code)
            self.assertEqual([], transport.calls)

    def test_root_apps_list_is_local_verified_and_stored_explicitly(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "Magisk.apk"
            contents = write_root_apk(apk, b"magisk manifest")
            digest = hashlib.sha256(contents).hexdigest()
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
            engine, transport = self.engine_for(
                "adb",
                [],
                rooting_service=service,
            )

            result = engine.execute(command("root.apps.list"))

            self.assertTrue(result.ok)
            self.assertEqual("root_apps_list_succeeded", result.code)
            self.assertEqual(1, result.value["count"])
            self.assertEqual("Magisk", result.value["apps"][0]["provider"])
            self.assertEqual(digest, result.value["apps"][0]["sha256"])
            self.assertEqual([], transport.calls)
            self.assertEqual(result, engine.store.snapshot().last_result)

    def test_root_app_install_confirms_and_uses_verified_inventory_artifact(self):
        interactions = []
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "Magisk.apk"
            contents = write_root_apk(apk)
            digest = hashlib.sha256(contents).hexdigest()
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
            app_id = service.root_app_inventory()[0].id
            engine, transport = self.engine_for(
                "adb",
                [TransportOutcome(0, "Success\n")],
                rooting_service=service,
                interaction_handler=(
                    lambda request: interactions.append(request)
                    or InteractionDecision.ACCEPTED
                ),
            )

            result = engine.execute(
                command("root.apps.install", {"appId": app_id})
            )

            self.assertTrue(result.ok)
            self.assertEqual("root_app_installed", result.code)
            self.assertEqual(digest, result.value["app"]["sha256"])
            self.assertEqual(1, len(interactions))
            self.assertFalse(interactions[0].destructive)
            self.assertEqual(
                ("ADB", "-s", "SERIAL", "install", "-r", str(apk.resolve())),
                transport.calls[0].argv,
            )

    def test_root_modules_list_parses_only_valid_ids(self):
        engine, transport = self.engine_for(
            "adb",
            [
                TransportOutcome(
                    0,
                    "zygisk_next\nplay_integrity_fix\n../escape\n"
                    "bad;reboot\nzygisk_next\n",
                )
            ],
            root=True,
        )

        result = engine.execute(command("root.modules.list"))

        self.assertTrue(result.ok)
        self.assertEqual("root_modules_list_succeeded", result.code)
        self.assertEqual(
            ["play_integrity_fix", "zygisk_next"],
            [item["id"] for item in result.value["modules"]],
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
            transport.calls[0].argv,
        )

    def test_root_module_state_actions_use_backend_confirmation_metadata(self):
        expected = {
            "enable": ("root_module_enabled", False),
            "disable": ("root_module_disabled", False),
            "remove": ("root_module_removed", True),
        }
        for action, (code, destructive) in expected.items():
            with self.subTest(action=action):
                interactions = []
                engine, transport = self.engine_for(
                    "adb",
                    [TransportOutcome(0)],
                    root=True,
                    interaction_handler=(
                        lambda request: interactions.append(request)
                        or InteractionDecision.ACCEPTED
                    ),
                )

                result = engine.execute(
                    command(
                        "root.modules.action",
                        {"action": action, "moduleId": "zygisk_next"},
                    )
                )

                self.assertTrue(result.ok)
                self.assertEqual(code, result.code)
                self.assertEqual("zygisk_next", result.value["moduleId"])
                self.assertEqual(1, len(interactions))
                self.assertEqual(destructive, interactions[0].destructive)
                self.assertEqual(1, len(transport.calls))

    def test_root_module_install_confirms_destructive_plan_and_returns_hash(self):
        interactions = []
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / "module.zip"
            contents = write_root_module(module, "safe_module")
            digest = hashlib.sha256(contents).hexdigest()
            engine, transport = self.engine_for(
                "adb",
                [TransportOutcome(0), TransportOutcome(0), TransportOutcome(0)],
                root=True,
                interaction_handler=(
                    lambda request: interactions.append(request)
                    or InteractionDecision.ACCEPTED
                ),
            )

            result = engine.execute(
                command(
                    "root.modules.action",
                    {"action": "install", "path": str(module)},
                )
            )

            self.assertTrue(result.ok)
            self.assertEqual("root_module_installed", result.code)
            self.assertEqual("safe_module", result.value["moduleId"])
            self.assertEqual(digest, result.value["artifact"]["sha256"])
            self.assertEqual(1, len(interactions))
            self.assertTrue(interactions[0].destructive)
            self.assertEqual(3, len(transport.calls))

    def test_root_artifact_mutation_and_process_failure_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / "module.zip"
            write_root_module(module)

            def mutate_then_accept(_request):
                module.write_bytes(b"changed")
                return InteractionDecision.ACCEPTED

            engine, transport = self.engine_for(
                "adb",
                [],
                root=True,
                interaction_handler=mutate_then_accept,
            )
            changed = engine.execute(
                command(
                    "root.modules.action",
                    {"action": "install", "path": str(module)},
                )
            )
            self.assertEqual(OperationStatus.FAILED, changed.status)
            self.assertEqual("artifact_hash_mismatch", changed.code)
            self.assertEqual([], transport.calls)

            failed_engine, failed_transport = self.engine_for(
                "adb",
                [TransportOutcome(23, stderr="root denied")],
                root=True,
                interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
            )
            failed = failed_engine.execute(
                command(
                    "root.modules.action",
                    {"action": "disable", "moduleId": "safe_module"},
                )
            )
            self.assertEqual(OperationStatus.FAILED, failed.status)
            self.assertEqual("process_failed", failed.code)
            self.assertEqual("root denied", failed.stderr)
            self.assertEqual(1, len(failed_transport.calls))

    def test_typed_validation_and_process_failures_are_explicit(self):
        engine, transport = self.engine_for("adb", [])
        injected = engine.execute(
            command(
                "apps.action",
                {
                    "action": "disable",
                    "package": "com.example.good;rm",
                },
            )
        )

        self.assertEqual(OperationStatus.FAILED, injected.status)
        self.assertEqual("package_name_invalid", injected.code)
        self.assertEqual([], transport.calls)

        failed_engine, failed_transport = self.engine_for(
            "adb",
            [TransportOutcome(17, "partial", "permission denied")],
        )
        process_failure = failed_engine.execute(command("apps.list"))
        self.assertEqual(OperationStatus.FAILED, process_failure.status)
        self.assertEqual("process_failed", process_failure.code)
        self.assertIsNone(process_failure.value)
        self.assertEqual(1, len(failed_transport.calls))

    def test_arbitrary_adb_shell_is_explicitly_disabled_without_execution(self):
        engine, transport = self.engine_for("adb", [])

        result = engine.execute(
            command("tools.adbShell", {"command": "rm -rf /data/local/tmp"})
        )

        self.assertEqual(OperationStatus.FAILED, result.status)
        self.assertEqual("adb_shell_unsupported", result.code)
        self.assertEqual([], transport.calls)

    def test_service_commands_require_current_revision_before_execution(self):
        engine, transport = self.engine_for("adb", [])

        missing = engine.execute(
            AppCommand("apps.list", target_serial="SERIAL")
        )
        stale = engine.execute(command("tools.logcat", revision=3))

        self.assertEqual("revision_required", missing.code)
        self.assertEqual("stale_revision", stale.code)
        self.assertEqual([], transport.calls)

    def test_safety_policy_itself_revision_guards_service_plans(self):
        snapshot = snapshot_for("adb")
        stale = command("apps.list", revision=3)
        compilation = PackageService().compile(stale, snapshot)
        planned = replace(
            stale,
            operation_plan=compilation.plan,
            destructive=compilation.destructive,
            requires_confirmation=compilation.requires_confirmation,
        )

        decision = SafetyPolicy().evaluate(planned, snapshot)

        self.assertFalse(decision.allowed)
        self.assertEqual("stale_revision", decision.code)

    def test_safety_policy_revision_guards_backup_plans(self):
        snapshot = snapshot_for("fastboot")
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "boot_a.img"
            stale = command(
                "backups.create",
                {
                    "partition": "boot",
                    "slot": "a",
                    "destination": str(destination),
                },
                revision=3,
            )
            # Compile against canonical state to isolate SafetyPolicy's own
            # revision boundary from BackupService's duplicate guard.
            canonical = replace(stale, expected_revision=4)
            compilation = BackupService().compile(canonical, snapshot)
            planned = replace(stale, operation_plan=compilation.plan)

            decision = SafetyPolicy().evaluate(planned, snapshot)

            self.assertFalse(decision.allowed)
            self.assertEqual("stale_revision", decision.code)


if __name__ == "__main__":
    unittest.main()
