import json
import tempfile
import threading
import time
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from pixelflasher_core import (
    AppCommand,
    ApplicationRuntime,
    AppSnapshot,
    CancellationToken,
    DeviceInfo,
    GrantAccess,
    OperationPlan,
    OperationStatus,
    ProcessRequest,
    SafetyPolicy,
    SupportDestinationRegistry,
    SupportPackageError,
    SupportPackageLimits,
    SupportPackageService,
    SupportPackageStatus,
)
from pixelflasher_core.support_v2 import (
    SUPPORT_V2_MAGIC,
    SupportPackageReader,
)
from tests.command_engine_factory import make_test_command_engine as CommandEngine
from ui.bridge_contract import BRIDGE_VERSION, BridgeProtocolError, BridgeRequest
from ui.core_command_factory import create_command_factory

SERIAL = "1A2B3C4D5E6F7G8H"


def support_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_key


def snapshot(revision: int = 0) -> AppSnapshot:
    return AppSnapshot(
        revision=revision,
        devices=(DeviceInfo(SERIAL, model="Pixel", mode="adb"),),
        selected_serials=(SERIAL,),
        selected_serial=SERIAL,
    )


def request(payload, *, revision=0):
    return BridgeRequest.from_json(
        json.dumps(
            {
                "version": BRIDGE_VERSION,
                "requestId": "support-request",
                "command": "support.create",
                "payload": payload,
                "expectedRevision": revision,
            }
        )
    )


class SupportDestinationRegistryTests(unittest.TestCase):
    def test_grants_only_canonical_zip_paths_and_consumes_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = SupportDestinationRegistry()
            token = registry.grant(root / "PixelFlasher-support.zip")

            self.assertNotIn(str(root), token)
            grant = registry.consume(token)
            self.assertEqual((root / "PixelFlasher-support.zip").resolve(), grant.path)
            with self.assertRaises(SupportPackageError) as reused:
                registry.consume(token)
            self.assertEqual("support_destination_not_granted", reused.exception.code)

            for unsafe in (
                Path("relative.zip"),
                root / "support.txt",
                root / ".." / "escape.zip",
                root / "bad\x00name.zip",
            ):
                with self.subTest(unsafe=unsafe):
                    with self.assertRaises(SupportPackageError):
                        registry.grant(unsafe)

    def test_existing_files_require_host_overwrite_grant_and_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "support.zip"
            destination.write_bytes(b"existing")
            registry = SupportDestinationRegistry()
            with self.assertRaises(SupportPackageError) as exists:
                registry.grant(destination)
            self.assertEqual("support_destination_exists", exists.exception.code)
            token = registry.grant(destination, allow_overwrite=True)
            self.assertTrue(registry.consume(token).allow_overwrite)

            target = root / "target.zip"
            target.write_bytes(b"target")
            link = root / "link.zip"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                return
            with self.assertRaises(SupportPackageError) as symlink:
                registry.grant(link, allow_overwrite=True)
            self.assertEqual("support_destination_invalid", symlink.exception.code)

    def test_expired_and_shutdown_grants_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = SupportDestinationRegistry(lifetime_seconds=10)
            with patch("pixelflasher_core.support.time.monotonic", return_value=100):
                token = registry.grant(Path(directory) / "expired.zip")
            with patch("pixelflasher_core.support.time.monotonic", return_value=111):
                with self.assertRaises(SupportPackageError):
                    registry.consume(token)
            registry.shutdown()
            with self.assertRaises(SupportPackageError) as closed:
                registry.grant(Path(directory) / "closed.zip")
            self.assertEqual("support_destination_registry_closed", closed.exception.code)


class SupportPackageServiceTests(unittest.TestCase):
    def _fixture(self, root: Path) -> Path:
        config = root / "PixelFlasher.json"
        config.write_text(
            json.dumps(
                {
                    "device": SERIAL,
                    "firmware_path": str(Path.home() / "Downloads" / "factory.zip"),
                    "api_token": "CONFIG-TOKEN-SECRET",
                    "serial": "OLD-CONFIG-SERIAL",
                    "username": "Private Person",
                    "nested": {"password": "CONFIG-PASSWORD", "email": "person@example.com"},
                }
            ),
            encoding="utf-8",
        )
        (root / "labels.json").write_text(
            json.dumps({"owner": "person@example.com", "serial": SERIAL}),
            encoding="utf-8",
        )
        logs = root / "logs"
        logs.mkdir()
        (logs / f"device-{SERIAL}.log").write_text(
            "\n".join(
                (
                    f"{SERIAL}\tdevice",
                    f"adb -s {SERIAL} shell getprop",
                    "token=LOG-TOKEN-SECRET",
                    "password: LOG-PASSWORD",
                    "contact person@example.com from 192.168.1.50",
                    "ipv6 2001:db8:85a3::8a2e:370:7334",
                    "mac AA:BB:CC:DD:EE:FF",
                    str(Path.home() / "private" / "firmware.zip"),
                )
            ),
            encoding="utf-8",
        )
        (logs / "ignored.apk").write_bytes(b"must-not-be-copied")
        (logs / "binary.log").write_bytes(b"text\x00secret")
        (logs / "structured.json").write_text(
            json.dumps({"token": "STRUCTURED-LOG-SECRET", "owner": "Private Owner"}),
            encoding="utf-8",
        )
        puml = root / "puml"
        puml.mkdir()
        (puml / "trace.puml").write_text(f"serial={SERIAL}\nsecret=PUML-SECRET", encoding="utf-8")
        (root / "PixelFlasher.db").write_bytes(b"legacy-private-database")
        return config

    def test_creates_redacted_bounded_zip_with_complete_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self._fixture(root)
            destination = root / "support-output.zip"
            service = SupportPackageService(config, app_version="10-test")
            token = service.register_destination(destination)

            result = service.create(
                {
                    "destinationId": token,
                    "includeConfig": True,
                    "includeLogs": True,
                    "includeState": True,
                    "includeSystemInfo": True,
                },
                snapshot=snapshot(),
            )

            self.assertEqual(SupportPackageStatus.SUCCESS, result.status)
            self.assertEqual("support_package_created", result.code)
            self.assertEqual("support-output.zip", result.file_name)
            self.assertEqual(64, len(result.sha256))
            self.assertTrue(destination.is_file())
            self.assertEqual([], list(root.glob(".support-output.zip.*.tmp")))

            with zipfile.ZipFile(destination) as archive:
                names = set(archive.namelist())
                self.assertIn("manifest.json", names)
                self.assertIn("config/PixelFlasher.json", names)
                self.assertIn("config/labels.json", names)
                self.assertIn("state/app_snapshot.json", names)
                self.assertIn("system/system_info.json", names)
                self.assertTrue(any(name.startswith("logs/log_") for name in names))
                self.assertNotIn("PixelFlasher.db", names)
                self.assertFalse(any("ignored.apk" in name for name in names))
                combined = b"\n".join(archive.read(name) for name in names).decode(
                    "utf-8", errors="replace"
                )
                manifest = json.loads(archive.read("manifest.json"))

            for private_value in (
                SERIAL,
                "CONFIG-TOKEN-SECRET",
                "CONFIG-PASSWORD",
                "OLD-CONFIG-SERIAL",
                "Private Person",
                "LOG-TOKEN-SECRET",
                "LOG-PASSWORD",
                "PUML-SECRET",
                "STRUCTURED-LOG-SECRET",
                "Private Owner",
                "person@example.com",
                "192.168.1.50",
                "2001:db8:85a3::8a2e:370:7334",
                "AA:BB:CC:DD:EE:FF",
                str(Path.home()),
                "legacy-private-database",
                "must-not-be-copied",
            ):
                with self.subTest(private_value=private_value):
                    self.assertNotIn(private_value, combined)
            self.assertEqual("mandatory", manifest["redaction"])
            self.assertEqual("10-test", manifest["applicationVersion"])
            self.assertTrue(all(item["redacted"] for item in manifest["included"]))
            omissions = {(item["source"], item["reason"]) for item in manifest["omitted"]}
            self.assertIn(("legacy-database", "not_safely_migrated"), omissions)
            self.assertIn(("recursive-file-listing", "pii_risk_not_included"), omissions)
            self.assertIn(("legacy-encrypted-wrapper", "not_migrated"), omissions)
            self.assertTrue(any(reason == "binary_not_allowed" for _source, reason in omissions))

    def test_closed_options_and_missing_or_forged_grants_fail_explicitly(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self._fixture(root)
            service = SupportPackageService(config)

            cases = (
                ({"destinationId": "x" * 43, "path": str(root / "forged.zip")}, "invalid_support_payload"),
                ({"destinationId": "x" * 43, "includeLogs": "yes"}, "invalid_support_payload"),
                (
                    {
                        "destinationId": "x" * 43,
                        "includeConfig": False,
                        "includeLogs": False,
                        "includeState": False,
                        "includeSystemInfo": False,
                    },
                    "invalid_support_payload",
                ),
                ({"destinationId": "x" * 43}, "support_destination_not_granted"),
            )
            for payload, code in cases:
                with self.subTest(payload=payload):
                    result = service.create(payload, snapshot=snapshot())
                    self.assertEqual(SupportPackageStatus.FAILED, result.status)
                    self.assertEqual(code, result.code)

    def test_cancel_before_collection_preserves_destination_and_grant(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self._fixture(root)
            destination = root / "cancelled.zip"
            service = SupportPackageService(config)
            token = service.register_destination(destination)
            cancellation = CancellationToken()
            cancellation.cancel()

            cancelled = service.create(
                {"destinationId": token},
                snapshot=snapshot(),
                cancellation=cancellation,
            )
            self.assertEqual(SupportPackageStatus.CANCELLED, cancelled.status)
            self.assertFalse(destination.exists())

            retried = service.create({"destinationId": token}, snapshot=snapshot())
            self.assertEqual(SupportPackageStatus.SUCCESS, retried.status)
            self.assertTrue(destination.exists())

    def test_atomic_failure_does_not_replace_existing_destination_or_leave_temp(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self._fixture(root)
            destination = root / "existing.zip"
            destination.write_bytes(b"original")
            service = SupportPackageService(config)
            token = service.register_destination(destination, allow_overwrite=True)

            with patch("pixelflasher_core.support.os.replace", side_effect=OSError("commit failed")):
                result = service.create({"destinationId": token}, snapshot=snapshot())

            self.assertEqual(SupportPackageStatus.FAILED, result.status)
            self.assertEqual(b"original", destination.read_bytes())
            self.assertEqual([], list(root.glob(".existing.zip.*.tmp")))

    def test_cancellation_during_zip_write_never_commits_a_partial_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self._fixture(root)
            destination = root / "mid-write-cancel.zip"
            service = SupportPackageService(config)
            token = service.register_destination(destination)
            cancellation = CancellationToken()
            original = zipfile.ZipFile.writestr
            writes = 0

            def cancel_after_first_write(archive, *args, **kwargs):
                nonlocal writes
                result = original(archive, *args, **kwargs)
                writes += 1
                if writes == 1:
                    cancellation.cancel()
                return result

            with patch.object(zipfile.ZipFile, "writestr", new=cancel_after_first_write):
                result = service.create(
                    {"destinationId": token},
                    snapshot=snapshot(),
                    cancellation=cancellation,
                )

            self.assertEqual(SupportPackageStatus.CANCELLED, result.status)
            self.assertEqual("support_package_cancelled", result.code)
            self.assertFalse(destination.exists())
            self.assertEqual([], list(root.glob(".mid-write-cancel.zip.*.tmp")))

    def test_limits_truncate_text_and_never_include_more_than_allowlisted_count(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            config.write_text("{}", encoding="utf-8")
            logs = root / "logs"
            logs.mkdir()
            for index in range(4):
                (logs / f"{index}.log").write_text("secret=VALUE\n" + "x" * 200, encoding="utf-8")
            service = SupportPackageService(
                config,
                limits=SupportPackageLimits(
                    max_config_bytes=1000,
                    max_log_bytes=40,
                    max_log_files=2,
                    max_total_bytes=4000,
                    max_log_depth=2,
                ),
            )
            destination = root / "limited.zip"
            token = service.register_destination(destination)

            result = service.create({"destinationId": token}, snapshot=snapshot())

            self.assertTrue(result.ok)
            with zipfile.ZipFile(destination) as archive:
                manifest = json.loads(archive.read("manifest.json"))
                log_entries = [item for item in manifest["included"] if item["category"] == "logs"]
            self.assertEqual(2, len(log_entries))
            self.assertTrue(all(item["truncated"] for item in log_entries))
            self.assertGreaterEqual(
                sum(item["reason"] == "file_count_limit" for item in manifest["omitted"]),
                2,
            )


class SupportEngineIntegrationTests(unittest.TestCase):
    def test_runtime_registers_native_destination_and_engine_returns_explicit_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            config.write_text(json.dumps({"device": SERIAL, "token": "PRIVATE"}), encoding="utf-8")
            destination = root / "runtime-support.zip"
            private_key, public_key = support_keys()
            runtime = ApplicationRuntime.open(
                config,
                support_recipient_public_key=public_key,
                support_key_id="support-test-2026",
            )
            token = runtime.register_support_destination(destination)

            result = runtime.execute(
                AppCommand(
                    "support.create",
                    expected_revision=runtime.snapshot().revision,
                    payload={
                        "destinationId": token,
                        "includeConfig": True,
                        "includeLogs": False,
                        "includeState": True,
                        "includeSystemInfo": True,
                    },
                )
            )

            self.assertEqual(OperationStatus.SUCCESS, result.status)
            self.assertEqual("support_package_created", result.code)
            self.assertEqual("runtime-support.zip", result.value["fileName"])
            self.assertEqual(2, result.value["schemaVersion"])
            self.assertEqual("support-test-2026", result.value["keyId"])
            self.assertNotIn("path", result.value)
            self.assertTrue(destination.is_file())
            self.assertTrue(destination.read_bytes().startswith(SUPPORT_V2_MAGIC))
            package = SupportPackageReader(private_key).read(destination)
            self.assertEqual("support-test-2026", package.key_id)
            self.assertEqual(result, runtime.snapshot().last_result)
            runtime.shutdown()

    def test_stale_revision_and_forged_destination_fail_without_filesystem_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            config.write_text("{}", encoding="utf-8")
            _private_key, public_key = support_keys()
            runtime = ApplicationRuntime.open(
                config,
                support_recipient_public_key=public_key,
                support_key_id="support-test-2026",
            )
            destination = root / "stale.zip"
            token = runtime.register_support_destination(destination)

            stale = runtime.execute(
                AppCommand("support.create", expected_revision=1, payload={"destinationId": token})
            )
            self.assertEqual("stale_revision", stale.code)
            self.assertFalse(destination.exists())

            success = runtime.execute(
                AppCommand("support.create", expected_revision=0, payload={"destinationId": token})
            )
            self.assertTrue(success.ok)
            forged = runtime.execute(
                AppCommand(
                    "support.create",
                    expected_revision=runtime.snapshot().revision,
                    payload={"destinationId": "x" * 43},
                )
            )
            self.assertEqual("support_destination_not_granted", forged.code)
            runtime.shutdown()

    def test_runtime_without_recipient_key_fails_closed_and_never_writes_v1(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            config.write_text("{}", encoding="utf-8")
            destination = root / "must-not-exist.zip"
            runtime = ApplicationRuntime.open(config)

            with self.assertRaises(SupportPackageError) as registration:
                runtime.register_support_destination(destination)
            self.assertEqual(
                "support_encryption_key_missing",
                registration.exception.code,
            )

            result = runtime.execute(
                AppCommand(
                    "support.create",
                    expected_revision=runtime.snapshot().revision,
                    payload={"destinationId": "x" * 43},
                )
            )

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("support_encryption_key_missing", result.code)
            self.assertFalse(destination.exists())
            runtime.shutdown()

    def test_running_support_operation_is_cooperatively_cancelled_and_cleans_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            config.write_text("{}", encoding="utf-8")
            destination = root / "engine-cancel.zip"
            service = SupportPackageService(config)
            token = service.register_destination(destination)
            engine = CommandEngine(
                store=None,
                support_package_service=service,
            )
            started = threading.Event()
            original = service._collect_entries

            def blocking_collect(options, state, redactor, cancellation):
                started.set()
                while not cancellation.cancelled:
                    time.sleep(0.005)
                service._check_cancelled(cancellation)
                return original(options, state, redactor, cancellation)

            service._collect_entries = blocking_collect
            command = AppCommand(
                "support.create",
                expected_revision=0,
                operation_id="support-cancel",
                payload={"destinationId": token},
            )
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(engine.execute, command)
                self.assertTrue(started.wait(5))
                self.assertTrue(engine.cancel(command.operation_id))
                result = future.result(timeout=5)

            self.assertEqual(OperationStatus.CANCELLED, result.status)
            self.assertEqual("support_package_cancelled", result.code)
            self.assertFalse(destination.exists())
            self.assertIsNone(engine.store.snapshot().active_operation)
            self.assertFalse(engine.cancel(command.operation_id))
            engine.shutdown()

    def test_safety_rejects_target_and_process_plan_for_local_support(self):
        policy = SafetyPolicy()
        targeted = AppCommand(
            "support.create",
            expected_revision=0,
            target_serial=SERIAL,
            payload={"destinationId": "x" * 43},
        )
        self.assertEqual("support_target_not_allowed", policy.evaluate(targeted, snapshot()).code)

        planned = AppCommand(
            "support.create",
            expected_revision=0,
            payload={"destinationId": "x" * 43},
            operation_plan=OperationPlan(request=ProcessRequest(("echo", "unsafe"))),
        )
        self.assertEqual("untrusted_operation_plan", policy.evaluate(planned, snapshot()).code)

    def test_bridge_and_factory_accept_only_opaque_destination_and_closed_options(self):
        with tempfile.TemporaryDirectory() as directory:
            factory = create_command_factory(lambda: snapshot())
            registry = SupportDestinationRegistry()
            factory.bind_support_destination_registrar(registry.grant)
            grant = factory.path_grants.issue_file(
                Path(directory) / "support.zip",
                purpose="support.create.destination",
                access=GrantAccess.WRITE,
            )
            parsed = request(
                {
                    "grant": grant.token,
                    "includeConfig": True,
                    "includeLogs": False,
                    "includeState": True,
                    "includeSystemInfo": True,
                }
            )
            command = factory(parsed)
            self.assertIsNone(command.target_serial)
            self.assertFalse(command.destructive)
            self.assertFalse(command.requires_confirmation)
            self.assertIn("destinationId", command.payload)
            self.assertNotIn("grant", command.payload)
            self.assertIn("support.create", SafetyPolicy().revisioned_kinds)

        for bad_payload in (
            {"destination": "C:/forged/support.zip"},
            {"destinationId": "A" * 43},
            {"grant": "short", "includeLogs": "yes"},
            {"grant": "A" * 43, "argv": ["zip"]},
        ):
            with self.subTest(bad_payload=bad_payload):
                with self.assertRaises(BridgeProtocolError) as rejected:
                    request(bad_payload)
                self.assertEqual("invalid_payload", rejected.exception.code)

        bypass = BridgeRequest(
            BRIDGE_VERSION,
            "factory-bypass",
            "support.create",
            {"destinationId": "A" * 43, "path": "C:/forged.zip"},
            0,
        )
        with self.assertRaises(BridgeProtocolError):
            create_command_factory(AppSnapshot)(bypass)


if __name__ == "__main__":
    unittest.main()
