import ast
import json
import unittest
from pathlib import Path
from types import SimpleNamespace

from build_artifact_policy import RETIRED_UI_DATA_DIRS, RETIRED_UI_MODULES
from pixelflasher_core import (
    ActiveOperation,
    AppSnapshot,
    BootInfo,
    BootloaderLockEvidence,
    FileArtifact,
    FirmwareInfo,
    FlashPlan,
    InteractionKind,
    InteractionRequest,
    OperationFinished,
    OperationPlan,
    OperationPreviewBatch,
    OperationResult,
    ProcessRequest,
    ProgressEvent,
    ProgressPhase,
    SnapshotChanged,
    ToolchainInfo,
)
from ui.bridge_contract import BRIDGE_VERSION, BridgeRequest, response_envelope
from ui.command_registry import ALLOWED_COMMANDS
from ui.pages.modern_webview_host import (
    ModernWebViewFrame,
    ReplayAction,
    _jsonable,
    _RequestReplayLedger,
)
from ui.public_bridge import (
    PUBLIC_RESULT_PROJECTORS,
    PublicProjectionError,
    project_operation_result,
    public_snapshot,
)

ROOT = Path(__file__).resolve().parents[1]
DESKTOP_SPECS = (
    ROOT / "build-on-win.spec",
    ROOT / "build-on-win-arm64.spec",
    ROOT / "build-on-linux.spec",
    ROOT / "build-on-mac.spec",
    ROOT / "build-on-mac-intel-only.spec",
)

HOST_PATH_SENTINELS = (
    r"C:\Users\Alice\PixelFlasher\private.zip",
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
)


def _module_candidates(module_name: str) -> tuple[Path, Path]:
    base = ROOT.joinpath(*module_name.split("."))
    return base.with_suffix(".py"), base / "__init__.py"


class ModernArtifactBoundaryTests(unittest.TestCase):
    def assert_route_free(self, value: object) -> None:
        def strings(item: object):
            if isinstance(item, str):
                yield item
            elif isinstance(item, dict):
                for key, nested in item.items():
                    yield str(key)
                    yield from strings(nested)
            elif isinstance(item, (list, tuple)):
                for nested in item:
                    yield from strings(nested)

        public_strings = tuple(strings(value))
        for sentinel in HOST_PATH_SENTINELS:
            with self.subTest(sentinel=sentinel):
                self.assertFalse(
                    any(sentinel in item for item in public_strings),
                    (sentinel, public_strings),
                )
        json.dumps(value)

    def test_retired_preview_and_widget_adapter_modules_are_absent(self):
        for module_name in RETIRED_UI_MODULES:
            if module_name == "Main":
                continue
            for candidate in _module_candidates(module_name):
                with self.subTest(module=module_name, candidate=candidate.name):
                    self.assertFalse(candidate.exists(), candidate)

    def test_retired_preview_assets_are_not_packaged_or_kept(self):
        for relative in RETIRED_UI_DATA_DIRS:
            directory = ROOT / relative
            with self.subTest(relative=relative):
                self.assertFalse(directory.exists() and any(directory.rglob("*")))
        for spec in DESKTOP_SPECS:
            source = spec.read_text(encoding="utf-8")
            with self.subTest(spec=spec.name):
                self.assertIn(
                    "from build_artifact_policy import RETIRED_UI_MODULES", source
                )
                self.assertIn("*RETIRED_UI_MODULES", source)
                for relative in RETIRED_UI_DATA_DIRS:
                    self.assertNotIn(relative, source)

    def test_legacy_main_cannot_enter_the_modern_artifact(self):
        self.assertIn("Main", RETIRED_UI_MODULES)
        entrypoint = (ROOT / "PixelFlasher.py").read_text(encoding="utf-8")
        self.assertNotIn("import Main", entrypoint)
        self.assertNotIn("from Main", entrypoint)

    def test_main_no_longer_exposes_preview_handlers_or_menu(self):
        source = (ROOT / "Main.py").read_text(encoding="utf-8")
        for retired in (
            "_on_modern_ui_preview",
            "_on_modern_patch_boot",
            "_modern_patch_boot_flavor",
            "_modern_ui_preview_frame",
            "ui.pages.dashboard_app",
            "Open the modern PixelFlasher workspace",
        ):
            with self.subTest(retired=retired):
                self.assertNotIn(retired, source)

    def test_modern_python_surface_has_no_named_legacy_delegates(self):
        violations: list[str] = []
        paths = [ROOT / "PixelFlasher.py", *sorted((ROOT / "ui").rglob("*.py"))]
        for path in paths:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if node.value.startswith("_on_"):
                        violations.append(f"{path.relative_to(ROOT)}:{node.lineno}:{node.value}")
                if isinstance(node, ast.Import):
                    imports = {alias.name.split(".", 1)[0] for alias in node.names}
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    imports = {node.module.split(".", 1)[0]}
                else:
                    continue
                for forbidden in imports & {"Main", "runtime", "pf_modules"}:
                    violations.append(
                        f"{path.relative_to(ROOT)}:{node.lineno}:import {forbidden}"
                    )
        self.assertEqual([], violations)

    def test_historical_action_contract_remains_evidence_not_executable_code(self):
        golden = json.loads(
            (ROOT / "tests" / "golden" / "modern_action_contracts.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(1, golden["schemaVersion"])
        self.assertEqual(32, len(golden["actions"]))
        self.assertTrue(any(action.get("delegate") for action in golden["actions"]))

    def test_snapshot_and_last_result_are_route_free_on_every_platform(self):
        digest = "a" * 64
        evidence = BootloaderLockEvidence(
            serial="SERIAL123456",
            device_codename="akita",
            firmware_hash=digest,
            firmware_build="AP4A.250205.002",
            flash_operation_id="flash-operation",
            flash_plan_fingerprint="b" * 64,
            snapshot_revision=8,
            required_partitions=("boot", "vbmeta"),
            flashed_partitions=("boot", "vbmeta"),
            slots=("a", "b"),
        )
        for route in HOST_PATH_SENTINELS:
            with self.subTest(route=route):
                result = OperationResult.success(
                    "operation",
                    message=f"completed [{route}]",
                    stdout=route,
                    stderr=route,
                    value={"path": route, "metadata": {"cwd": route}},
                )
                snapshot = AppSnapshot(
                    revision=8,
                    firmware=FirmwareInfo(
                        path=route,
                        type="factory",
                        build="AP4A.250205.002",
                        hash=digest,
                        verified=True,
                    ),
                    boot=BootInfo(
                        id="stock-boot",
                        path=route,
                        hash=digest,
                        flavor="boot",
                    ),
                    plan=FlashPlan(options={"images": {"boot": route}}),
                    toolchain=ToolchainInfo(
                        adb=f"{route}/adb",
                        fastboot=f"{route}/fastboot",
                        version="35.0.2",
                        ready=True,
                    ),
                    active_operation=ActiveOperation(
                        "operation",
                        "firmware.process",
                        f"Processing [{route}]",
                    ),
                    last_result=result,
                    bootloader_lock_evidence=(evidence,),
                )

                public = public_snapshot(snapshot)
                self.assert_route_free(public)
                self.assertNotIn("value", public["last_result"])
                self.assertNotIn("stdout", public["last_result"])
                self.assertNotIn("stderr", public["last_result"])
                self.assertEqual(
                    [{"serial": "SERIAL123456", "snapshot_revision": 8}],
                    public["bootloader_lock_evidence"],
                )

    def test_plan_preview_response_keeps_logical_argv_but_no_host_routes(self):
        digest = "c" * 64
        for route in HOST_PATH_SENTINELS:
            with self.subTest(route=route):
                artifact_path = f"{route}/firmware.zip"
                artifact = FileArtifact(artifact_path, digest, "firmware")
                plan = OperationPlan(
                    ProcessRequest(
                        (f"{route}/platform-tools/adb", artifact_path),
                        cwd=route,
                        env=(("PRIVATE_ROOT", route),),
                    ),
                    label=f"Flash [{route}]",
                    artifacts=(artifact,),
                    dry_run=True,
                )
                result = OperationResult.success(
                    "preview",
                    message=f"Preview [{route}]",
                    stdout=route,
                    stderr=route,
                    value={
                        "revision": 9,
                        "canonical_plan": FlashPlan().to_dict(),
                        "plan": FlashPlan().to_dict(),
                        "selected_serials": ["SERIAL123456"],
                        "firmware": FirmwareInfo(
                            path=route,
                            type="factory",
                            build="AP4A.250205.002",
                            hash=digest,
                        ).to_dict(),
                        "compiled": {
                            "ok": True,
                            "code": "ok",
                            "message": route,
                            "destructive": False,
                            "requires_confirmation": False,
                            "plan": plan.to_dict(),
                            "confirmation": None,
                        },
                    },
                )

                public = project_operation_result("flash.plan.preview", result)
                self.assert_route_free(public)
                compiled = public["value"]["compiled"]
                request = compiled["plan"]["requests"][0]
                self.assertNotIn("cwd", request)
                self.assertNotIn("env", request)
                self.assertEqual(
                    f"@artifact/firmware/{digest[:12]}",
                    request["argv"][1],
                )

    def test_dry_run_batch_projection_is_closed_and_route_free(self):
        route = HOST_PATH_SENTINELS[0]
        digest = "d" * 64
        artifact = FileArtifact(f"{route}/boot.img", digest, "partition:boot")
        plans = tuple(
            OperationPlan(
                ProcessRequest((f"{route}/fastboot", "-s", serial, "flash", "boot", artifact.path)),
                target_serial=serial,
                artifacts=(artifact,),
                dry_run=True,
                created=100.0,
                expires=400.0,
            )
            for serial in ("SERIAL-A", "SERIAL-B")
        )
        preview = OperationPreviewBatch(plans, created=100.0, expires=400.0)
        preview_result = OperationResult.success(
            "preview-batch",
            value={
                "revision": 9,
                "canonical_plan": FlashPlan(dry_run=True).to_dict(),
                "plan": FlashPlan(dry_run=True).to_dict(),
                "selected_serials": ["SERIAL-A", "SERIAL-B"],
                "firmware": FirmwareInfo(hash=digest).to_dict(),
                "compiled": {
                    "ok": True,
                    "code": "ok",
                    "message": "",
                    "destructive": False,
                    "requires_confirmation": False,
                    "preview": preview.to_dict(),
                    "confirmation": None,
                },
                "batch": True,
            },
        )
        execute_result = OperationResult.success(
            "execute-batch",
            code="dry_run_batch_succeeded",
            value={"preview": preview.to_dict()},
        )

        public_preview = project_operation_result("flash.plan.preview", preview_result)
        public_execute = project_operation_result("flash.execute", execute_result)

        self.assert_route_free(public_preview)
        self.assert_route_free(public_execute)
        batch = public_preview["value"]["compiled"]["batch"]
        self.assertEqual(["SERIAL-A", "SERIAL-B"], batch["targetSerials"])
        self.assertTrue(batch["dry_run"])

    def test_every_exposed_command_has_a_fail_closed_result_projector(self):
        self.assertEqual(ALLOWED_COMMANDS, frozenset(PUBLIC_RESULT_PROJECTORS))
        for command in sorted(ALLOWED_COMMANDS):
            for route in HOST_PATH_SENTINELS:
                with self.subTest(command=command, route=route):
                    result = OperationResult.success(
                        "operation",
                        message=f"Result [{route}]",
                        stdout=route,
                        stderr=route,
                        value={
                            "path": route,
                            "cwd": route,
                            "env": {"PRIVATE": route},
                            "metadata": {"source": route},
                            "outputDirectory": route,
                        },
                    )
                    if command in {
                        "apps.action",
                        "backups.create",
                        "backups.delete",
                        "backups.list",
                        "backups.magisk.delete",
                        "backups.magisk.import",
                        "backups.magisk.list",
                        "backups.restore",
                        "boot.delete",
                        "device.inspect",
                        "device.openUrl",
                        "firmware.catalog.refresh",
                        "firmware.download",
                        "firmware.process",
                        "firmware.select",
                        "root.apps.catalog.refresh",
                        "root.apps.download",
                        "root.dataAdb.backup",
                        "root.dataAdb.clear",
                        "root.dataAdb.restore",
                        "root.modules.list",
                        "root.pif.document",
                        "root.pif.inventory",
                        "tools.logcat",
                        "tools.logcat.clear",
                        "tools.piAnalysis",
                        "tools.pif",
                        "tools.pushFiles",
                        "tools.avb",
                        "tools.keybox",
                        "tools.shizuku",
                        "tools.sos",
                        "tools.xml",
                        "tools.scrcpy.setup",
                        "tools.wifi.discover",
                    }:
                        with self.assertRaises(PublicProjectionError):
                            project_operation_result(command, result)
                    else:
                        self.assert_route_free(project_operation_result(command, result))

    def test_boot_delete_result_is_closed_and_contains_storage_evidence(self):
        value = {
            "bootId": "a" * 32,
            "sha256": "b" * 64,
            "objectRetained": True,
            "cleanupDeferred": False,
            "revision": 8,
        }
        public = project_operation_result(
            "boot.delete",
            OperationResult.success("delete-boot", value=value),
        )
        self.assertEqual(value, public["value"])

        for hostile in (
            {**value, "path": r"C:\private\boot.img"},
            {**value, "bootId": "A" * 32},
            {**value, "cleanupDeferred": "false"},
        ):
            with self.subTest(hostile=hostile), self.assertRaises(PublicProjectionError):
                project_operation_result(
                    "boot.delete",
                    OperationResult.success("delete-boot", value=hostile),
                )

    def test_ota_diagnostic_results_have_closed_bounded_public_dtos(self):
        status = {
            "action": "status",
            "state": "idle",
            "progress": 0.0,
            "idle": True,
            "lastAttemptError": "ErrorCode::kSuccess",
            "bounded": True,
        }
        certificates = {
            "action": "certificates",
            "archivePresent": True,
            "count": 2,
            "entries": [
                "META-INF/com/android/otacert.x509.pem",
                "releasekey.x509.pem",
            ],
            "bounded": True,
        }
        logs = {
            "action": "logs",
            "lineCount": 2,
            "lines": [
                "update_engine: payload verified",
                "update_engine_client: status=UPDATED_NEED_REBOOT",
            ],
            "redactedCount": 1,
            "bounded": True,
        }

        for command, value in (
            ("device.ota.status", status),
            ("device.ota.certificates", certificates),
            ("device.ota.logs", logs),
        ):
            with self.subTest(command=command):
                public = project_operation_result(
                    command,
                    OperationResult.success("ota-diagnostic", value=value),
                )
                self.assertEqual(value, public["value"])
                self.assert_route_free(public)

        invalid_certificates = (
            {**certificates, "signed": True},
            {key: item for key, item in certificates.items() if key != "archivePresent"},
            {**certificates, "action": "certificatePaths"},
            {**certificates, "archivePresent": False},
            {**certificates, "count": 1},
            {**certificates, "count": True},
            {**certificates, "entries": tuple(certificates["entries"])},
            {**certificates, "count": 1_025, "entries": ["cert.pem"] * 1_025},
            {**certificates, "count": 1, "entries": [f"{'x' * 257}.pem"]},
            {**certificates, "count": 1, "entries": ["é" * 129]},
        )
        invalid_logs = (
            {**logs, "path": "update_engine.log"},
            {**logs, "action": "logcat"},
            {**logs, "bounded": False},
            {**logs, "lineCount": 1},
            {**logs, "redactedCount": True},
            {**logs, "lines": tuple(logs["lines"])},
            {**logs, "lineCount": 5_001, "lines": ["update_engine"] * 5_001},
            {**logs, "lineCount": 1, "lines": ["x" * 4_097]},
            {
                **logs,
                "lineCount": 1,
                "lines": [f"update_engine: {'😀' * 1_022}"],
            },
            {**logs, "lineCount": 1, "lines": ["ordinary log line"]},
            {**logs, "lineCount": 1, "lines": ["update_engine:\x07 bell"]},
        )
        invalid_status = (
            {**status, "path": "/data/update_engine"},
            {**status, "state": "unknown"},
            {**status, "progress": -0.1},
            {**status, "progress": float("nan")},
            {**status, "idle": False},
            {**status, "lastAttemptError": "bad value"},
        )
        for command, invalid_values in (
            ("device.ota.status", invalid_status),
            ("device.ota.certificates", invalid_certificates),
            ("device.ota.logs", invalid_logs),
        ):
            for value in invalid_values:
                with self.subTest(command=command, value=value):
                    public = project_operation_result(
                        command,
                        OperationResult.success("ota-diagnostic", value=value),
                    )
                    self.assertNotIn("value", public)
                    self.assert_route_free(public)

        for route in HOST_PATH_SENTINELS:
            unsafe_certificates = {
                **certificates,
                "count": 1,
                "entries": [route],
            }
            unsafe_logs = {**logs, "lineCount": 1, "lines": [route]}
            for command, value in (
                ("device.ota.certificates", unsafe_certificates),
                ("device.ota.logs", unsafe_logs),
            ):
                with self.subTest(command=command, route=route):
                    public = project_operation_result(
                        command,
                        OperationResult.success("ota-diagnostic", value=value),
                    )
                    self.assertNotIn("value", public)
                    self.assert_route_free(public)

    def test_firmware_catalog_and_download_results_are_closed_and_route_free(self):
        entry = {
            "artifactId": "a" * 32,
            "device": "akita",
            "channel": "stable",
            "kind": "factory",
            "version": "AP4A.260719.001",
            "sha256": "b" * 64,
            "size": 2_000_000_000,
            "license": "Google Terms",
            "provenance": "Google Pixel official images",
        }
        catalog = {
            "count": 1,
            "entries": [entry],
            "device": "akita",
            "channel": "stable",
            "revision": 7,
        }
        inspection = {
            "type": "factory",
            "sha256": "b" * 64,
            "build": "AP4A.260719.001",
            "device": "akita",
            "code": "ok",
            "ok": True,
            "provenance": "official",
            "detectedDevices": ["akita"],
            "expectedDevices": ["akita"],
            "compatibility": "matched",
            "evidence": [
                "sha256_computed",
                "archive_paths_validated",
                "archive_members_verified",
                "factory_flash_script",
                "factory_image_archive",
            ],
        }
        download = {
            "artifact": entry,
            "cacheHit": False,
            "resumed": True,
            "revision": 8,
            "inspection": inspection,
        }
        for command, value in (
            ("firmware.catalog.refresh", catalog),
            ("firmware.download", download),
        ):
            public = project_operation_result(
                command,
                OperationResult.success("firmware", value=value),
            )
            self.assertEqual(value, public["value"])
            self.assert_route_free(public)

        hostile = {**entry, "url": "https://downloads.example/private.zip"}
        with self.assertRaises(PublicProjectionError):
            project_operation_result(
                "firmware.catalog.refresh",
                OperationResult.success(
                    "firmware",
                    value={**catalog, "entries": [hostile]},
                ),
            )

        open_download = {
            **download,
            "inspection": {**inspection, "path": HOST_PATH_SENTINELS[0]},
        }
        with self.assertRaises(PublicProjectionError):
            project_operation_result(
                "firmware.download",
                OperationResult.success("firmware", value=open_download),
            )

    def test_platform_tools_result_exposes_closed_installation_receipt_without_routes(self):
        digest = "d" * 64
        receipt = {
            "source": "official",
            "ready": True,
            "version": "36.0.0",
            "installation": {
                "installed": True,
                "adbAvailable": True,
                "fastbootAvailable": True,
                "archiveSha256": digest.upper(),
                "archiveSize": 12_345,
                "version": "36.0.0",
            },
            "revision": 12,
        }
        public = project_operation_result(
            "platformTools.setup",
            OperationResult.success("platform-tools", value=receipt),
        )

        self.assert_route_free(public)
        self.assertEqual(
            {
                **receipt,
                "installation": {
                    **receipt["installation"],
                    "archiveSha256": digest,
                },
            },
            public["value"],
        )

        directory_receipt = {
            "source": "directory",
            "ready": True,
            "version": "35.0.2",
            "installation": None,
            "revision": 13,
        }
        directory_public = project_operation_result(
            "platformTools.setup",
            OperationResult.success("platform-tools-directory", value=directory_receipt),
        )
        self.assertEqual(directory_receipt, directory_public["value"])

        for route in HOST_PATH_SENTINELS:
            with self.subTest(route=route):
                unsafe_values = (
                    {**receipt, "path": route},
                    {**receipt, "version": route},
                    {
                        **receipt,
                        "installation": {**receipt["installation"], "root": route},
                    },
                )
                for unsafe in unsafe_values:
                    projected = project_operation_result(
                        "platformTools.setup",
                        OperationResult.success("platform-tools", value=unsafe),
                    )
                    self.assert_route_free(projected)
                    self.assertNotIn("value", projected)

    def test_snapshot_progress_interaction_and_finished_events_are_route_free(self):
        for route in HOST_PATH_SENTINELS:
            with self.subTest(route=route):
                snapshot = AppSnapshot(
                    revision=3,
                    last_result=OperationResult.failed(
                        "operation",
                        code="failed",
                        message=f"Failed [{route}]",
                        stderr=route,
                    ),
                )
                events = (
                    SnapshotChanged(snapshot),
                    ProgressEvent(
                        "operation",
                        ProgressPhase.RUNNING,
                        f"Working [{route}]",
                        50,
                    ),
                    InteractionRequest(
                        "operation",
                        InteractionKind.CONFIRM,
                        f"Confirm [{route}]",
                        f"Continue [{route}]",
                        3,
                    ),
                    OperationFinished(
                        OperationResult.success(
                            "operation",
                            message=f"Finished [{route}]",
                            stdout=route,
                            value={"path": route},
                        )
                    ),
                )
                for event in events:
                    self.assert_route_free(_jsonable(event))

    def test_response_replay_stores_only_the_sanitized_projection(self):
        route = r"C:\Users\Alice\private\firmware.zip"
        request = BridgeRequest.from_json(
            json.dumps(
                {
                    "version": BRIDGE_VERSION,
                    "requestId": "privacy-replay",
                    "command": "tools.pushFiles",
                    "payload": {
                        "serial": "SERIAL123456",
                        "grants": ["g" * 32],
                        "destination": "/sdcard/Download/",
                    },
                    "expectedRevision": 4,
                }
            )
        )
        ledger = _RequestReplayLedger(maximum_completed=4)
        emitted: list[dict[str, object]] = []
        host = SimpleNamespace(_replay_ledger=ledger, _emit=emitted.append)
        self.assertIs(ReplayAction.EXECUTE, ledger.begin(request).action)
        result = project_operation_result(
            request.command,
            OperationResult.success(
                "push",
                message=f"Pushed [{route}]",
                stdout=route,
                value={
                    "targetSerial": "SERIAL123456",
                    "count": 1,
                    "files": [
                        {
                            "displayName": "file.zip",
                            "destination": "/sdcard/Download/file.zip",
                            "sha256": "a" * 64,
                            "sizeBytes": 42,
                            "verified": True,
                        }
                    ],
                },
            ),
        )
        ModernWebViewFrame._complete_request(
            host,
            request,
            response_envelope(request.request_id, ok=True, result=result),
        )
        replay = ledger.begin(request)
        self.assertIs(ReplayAction.REPLAY, replay.action)
        self.assertIsNotNone(replay.message)
        self.assert_route_free(emitted[0])
        self.assert_route_free(replay.message)
        projected_files = result["value"]["files"]
        self.assertNotIn("source", projected_files[0])
        self.assertEqual("a" * 64, projected_files[0]["sha256"])

    def test_successful_push_receipts_fail_closed_when_malformed(self):
        valid_file = {
            "displayName": "payload.zip",
            "destination": "/sdcard/Download/payload.zip",
            "sha256": "b" * 64,
            "sizeBytes": 7,
            "verified": True,
        }
        malformed_values = (
            None,
            {"count": 1, "files": []},
            {"targetSerial": "", "count": 1, "files": [valid_file]},
            {"targetSerial": r"C:\\private", "count": 1, "files": [valid_file]},
            {"targetSerial": "SERIAL", "count": 1, "files": [{**valid_file, "source": r"C:\\private.zip"}]},
            {"targetSerial": "SERIAL", "count": 1, "files": [{**valid_file, "verified": False}]},
            {"targetSerial": "SERIAL", "count": 1, "files": [{**valid_file, "sha256": "B" * 64}]},
            {
                "targetSerial": "SERIAL",
                "count": 1,
                "files": [{**valid_file, "destination": "/data/local/tmp/other.zip"}],
            },
        )
        for value in malformed_values:
            with self.subTest(value=value), self.assertRaises(PublicProjectionError):
                project_operation_result(
                    "tools.pushFiles",
                    OperationResult.success("push", value=value),
                )

    def test_avb_downgrade_receipt_is_closed_verified_and_route_free(self):
        value = {
            "artifact": {"sha256": "a" * 64, "role": "downgrade:boot"},
            "currentSecurityPatch": "2025-03-05",
            "targetSecurityPatch": "2025-02-05",
            "verified": True,
        }
        projected = project_operation_result(
            "tools.avb",
            OperationResult.success("avb", value=value),
        )
        self.assertEqual(value, projected["value"])
        self.assert_route_free(projected)

        hostile_values = (
            {**value, "path": r"C:\\private\\downgrade.img"},
            {**value, "artifact": {**value["artifact"], "path": "/private/output.img"}},
            {**value, "artifact": {**value["artifact"], "sha256": "A" * 64}},
            {**value, "artifact": {**value["artifact"], "role": "partition:boot"}},
            {**value, "verified": False},
            {**value, "currentSecurityPatch": "2025-02-05"},
            {**value, "currentSecurityPatch": "2025-02-30"},
        )
        for hostile in hostile_values:
            with self.subTest(hostile=hostile), self.assertRaises(PublicProjectionError):
                project_operation_result(
                    "tools.avb",
                    OperationResult.success("avb", value=hostile),
                )

    def test_binary_xml_receipt_is_bounded_closed_and_route_free(self):
        value = {
            "format": "android-binary-xml",
            "xml": '<?xml version="1.0" encoding="utf-8"?>\n<manifest>\n</manifest>\n',
            "sha256": "b" * 64,
            "sizeBytes": 128,
            "elementCount": 1,
            "attributeCount": 0,
            "bounded": True,
        }
        projected = project_operation_result(
            "tools.xml",
            OperationResult.success("xml", value=value),
        )
        self.assertEqual(value, projected["value"])
        self.assert_route_free(projected)

        hostile_values = (
            {**value, "path": r"C:\\private\\manifest.axml"},
            {**value, "xml": '<?xml version="1.0" encoding="utf-8"?>\nC:\\private\n'},
            {**value, "sha256": "B" * 64},
            {**value, "format": "text/xml"},
            {**value, "bounded": False},
            {**value, "elementCount": 0},
            {**value, "attributeCount": -1},
        )
        for hostile in hostile_values:
            with self.subTest(hostile=hostile), self.assertRaises(PublicProjectionError):
                project_operation_result(
                    "tools.xml",
                    OperationResult.success("xml", value=hostile),
                )

    def test_keybox_receipt_is_bounded_closed_and_secret_free(self):
        report = {
            "displayName": "attestation.xml",
            "sha256": "c" * 64,
            "sizeBytes": 128,
            "status": "unverified",
            "structureValid": True,
            "cryptographicValid": True,
            "keyboxCount": 1,
            "algorithms": ["ecdsa", "rsa"],
            "certificateCount": 4,
            "expired": False,
            "expiringSoon": False,
            "softwareAttestation": False,
            "revocationStatus": "unverified",
            "issues": ["revocation_evidence_unavailable"],
        }
        value = {
            "reports": [report],
            "count": 1,
            "summary": {
                "valid": 0,
                "unverified": 1,
                "revoked": 0,
                "expired": 0,
                "softwareAttestation": 0,
                "invalid": 0,
            },
            "revocationEvidence": None,
            "bounded": True,
        }
        projected = project_operation_result(
            "tools.keybox",
            OperationResult.success("keybox", value=value),
        )
        self.assertEqual(value, projected["value"])
        self.assert_route_free(projected)

        hostile_values = (
            {**value, "path": r"C:\\private\\keybox.xml"},
            {**value, "reports": [{**report, "privateKey": "SECRET"}]},
            {**value, "reports": [{**report, "certificate": "SECRET"}]},
            {**value, "reports": [{**report, "displayName": "/private/keybox.xml"}]},
            {**value, "reports": [{**report, "status": "valid"}]},
            {**value, "count": 2},
        )
        for hostile in hostile_values:
            with self.subTest(hostile=hostile), self.assertRaises(PublicProjectionError):
                project_operation_result(
                    "tools.keybox",
                    OperationResult.success("keybox", value=hostile),
                )

    def test_generic_host_serializer_rejects_python_paths_and_host_path_strings(self):
        with self.assertRaises(PublicProjectionError):
            _jsonable({"path": Path("private.zip")})
        for route in HOST_PATH_SENTINELS:
            with self.subTest(route=route), self.assertRaises(PublicProjectionError):
                _jsonable({"message": route})

        # Deliberate device paths remain part of typed device reports.
        self.assertEqual(
            {"apk_path": "/system/app/example/base.apk"},
            _jsonable({"apk_path": "/system/app/example/base.apk"}),
        )


if __name__ == "__main__":
    unittest.main()
