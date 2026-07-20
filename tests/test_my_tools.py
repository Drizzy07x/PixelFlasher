import json
import os
import tempfile
import unittest
from pathlib import Path

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    AppStateStore,
    BoundReadFile,
    CancellationToken,
    CommandExecutor,
    FakeProcessTransport,
    ModernPreferences,
    MyToolsError,
    MyToolsRepository,
    MyToolsService,
    OperationResult,
    PathGrantStore,
)
from pixelflasher_core.executor import TransportOutcome
from tests.command_engine_factory import make_test_command_engine
from ui.bridge_contract import BRIDGE_VERSION, BridgeProtocolError, BridgeRequest
from ui.core_command_factory import create_command_factory
from ui.public_bridge import PublicProjectionError, project_operation_result


def _executable(root: Path, name: str = "personal.exe") -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    path = root / (name if name.endswith(suffix) else f"{name}{suffix}")
    path.write_bytes(b"safe personal tool\n")
    if os.name != "nt":
        path.chmod(0o700)
    return path


def _bound(path: Path) -> BoundReadFile:
    grants = PathGrantStore()
    issued = grants.issue_file(path, purpose="tools.myTools.executable")
    return grants.resolve_bound_file(issued.token, purpose="tools.myTools.executable")


def _bridge(
    payload: dict[str, object],
    command_name: str = "tools.myTools",
) -> BridgeRequest:
    return BridgeRequest.from_json(
        json.dumps(
            {
                "version": BRIDGE_VERSION,
                "requestId": "my-tools-test",
                "command": command_name,
                "payload": payload,
                "expectedRevision": 7,
            }
        )
    )


class MyToolsRepositoryTests(unittest.TestCase):
    def test_saves_without_exposing_path_and_reloads_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = _executable(root)
            repository = MyToolsRepository(root / "my-tools-v1.json")

            saved = repository.save(
                title="Diagnostics",
                executable=_bound(executable),
                arguments=("--mode", "safe value"),
                enabled=True,
            )

            public = saved.to_public_dict()
            self.assertNotIn(str(root), json.dumps(public))
            self.assertEqual(["--mode", "safe value"], public["arguments"])
            reloaded = MyToolsRepository(root / "my-tools-v1.json")
            self.assertEqual(saved, reloaded.get(saved.tool_id))
            self.assertFalse(list(root.glob(".my-tools-v1.json.*")))

    def test_imports_legacy_commands_with_exact_preview_but_no_permission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy = root / "mytools.json"
            legacy.write_text(
                json.dumps(
                    {
                        "count": 2,
                        "tools": {
                            "1": {
                                "title": "Unsafe old command",
                                "command": "cmd.exe",
                                "arguments": "/c erase everything",
                                "enabled": True,
                            },
                            "2": {"title": "---", "enabled": True},
                        },
                    }
                ),
                encoding="iso-8859-1",
            )

            repository = MyToolsRepository(root / "my-tools-v1.json", legacy_path=legacy)

            inventory = repository.inventory()
            self.assertEqual([], inventory["tools"])
            self.assertEqual(1, len(inventory["legacyRaw"]))
            migrated = inventory["legacyRaw"][0]
            self.assertEqual("legacyRaw", migrated["mode"])
            self.assertFalse(migrated["permissionGranted"])
            self.assertEqual('"cmd.exe" /c erase everything', migrated["commandPreview"])
            self.assertEqual("legacy_raw_permission_required", migrated["blockedReason"])
            self.assertRegex(migrated["fingerprint"], r"^[0-9a-f]{64}$")

    def test_legacy_migration_skips_only_invalid_entries_and_rehydrates_schema_one(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy = root / "mytools.json"
            legacy.write_text(
                json.dumps(
                    {
                        "tools": {
                            "bad": {"title": "\n", "command": "echo", "enabled": True},
                            "good": {
                                "title": "Recovered",
                                "command": "echo",
                                "arguments": "restored",
                                "enabled": True,
                            },
                        }
                    }
                ),
                encoding="iso-8859-1",
            )
            store = root / "store.json"
            store.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "tools": [],
                        "legacyRaw": [
                            {"id": "legacy:good", "title": "Recovered", "enabled": True}
                        ],
                    }
                ),
                encoding="utf-8",
            )

            repository = MyToolsRepository(store, legacy_path=legacy)

            inventory = repository.inventory()
            self.assertEqual(2, inventory["schemaVersion"])
            self.assertEqual(1, len(inventory["legacyRaw"]))
            self.assertEqual('"echo" restored', inventory["legacyRaw"][0]["commandPreview"])
            self.assertEqual(2, json.loads(store.read_text(encoding="utf-8"))["schemaVersion"])

    def test_rejects_executable_that_changed_after_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = _executable(root)
            repository = MyToolsRepository(root / "my-tools-v1.json")
            saved = repository.save(
                title="Pinned",
                executable=_bound(executable),
                arguments=(),
                enabled=True,
            )
            executable.write_bytes(b"changed binary\n")

            with self.assertRaisesRegex(MyToolsError, "must be selected again") as raised:
                repository.revalidate(saved.tool_id)
            self.assertEqual("my_tool_executable_changed", raised.exception.code)

    def test_service_executes_exact_argv_and_propagates_nonzero_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = _executable(root)
            repository = MyToolsRepository(root / "my-tools-v1.json")
            saved = repository.save(
                title="Argv only",
                executable=_bound(executable),
                arguments=("--literal", "a && b"),
                enabled=True,
            )
            transport = FakeProcessTransport(
                [TransportOutcome(0, stdout="ok"), TransportOutcome(9, stderr="failed")]
            )
            service = MyToolsService(repository, CommandExecutor(transport))
            command = AppCommand(
                "tools.myTools",
                expected_revision=7,
                payload={"action": "run", "toolId": saved.tool_id},
                operation_id="run-safe-tool",
            )

            succeeded = service.run(command, saved.tool_id, CancellationToken())
            failed = service.run(command, saved.tool_id, CancellationToken())

            self.assertTrue(succeeded.ok)
            self.assertFalse(failed.ok)
            self.assertEqual((str(executable), "--literal", "a && b"), transport.calls[0].argv)
            self.assertIsNone(transport.calls[0].cwd)
            self.assertIsNone(transport.calls[0].env)
            self.assertEqual(4 * 1024 * 1024, transport.calls[0].output_limit_bytes)

    def test_legacy_raw_requires_persistent_permission_and_per_run_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy = root / "mytools.json"
            legacy.write_text(
                json.dumps(
                    {
                        "tools": {
                            "1": {
                                "title": "Legacy echo",
                                "command": "echo",
                                "arguments": "literal && value",
                                "directory": str(root),
                                "enabled": True,
                            }
                        }
                    }
                ),
                encoding="iso-8859-1",
            )
            repository = MyToolsRepository(root / "my-tools-v2.json", legacy_path=legacy)
            transport = FakeProcessTransport([TransportOutcome(0, stdout="ok")])
            service = MyToolsService(
                repository,
                CommandExecutor(transport),
                allowed_legacy_cwd_roots=(root,),
            )
            spec = repository.get_legacy("legacy:1")
            with self.assertRaises(MyToolsError):
                service.set_legacy_permission(
                    spec.legacy_id,
                    granted=True,
                    confirmation_text="ALLOW RAW WRONG",
                )
            allowed = service.set_legacy_permission(
                spec.legacy_id,
                granted=True,
                confirmation_text=service.legacy_permission_confirmation(spec),
            )
            self.assertTrue(allowed.permission_granted)
            self.assertTrue(
                MyToolsRepository(root / "my-tools-v2.json", legacy_path=legacy)
                .get_legacy(spec.legacy_id)
                .permission_granted
            )
            command = AppCommand(
                "tools.myTools.legacyRun",
                expected_revision=7,
                payload={"toolId": spec.legacy_id},
            )
            with self.assertRaises(MyToolsError):
                service.run_legacy(command, spec.legacy_id, "RUN RAW WRONG", CancellationToken())
            result = service.run_legacy(
                command,
                spec.legacy_id,
                service.legacy_run_confirmation(spec),
                CancellationToken(),
            )

            self.assertTrue(result.ok)
            request = transport.calls[0]
            self.assertEqual(str(root.resolve()), request.cwd)
            if os.name == "nt":
                self.assertEqual(("/d", "/s", "/c"), request.argv[1:4])
                self.assertEqual("%PIXELFLASHER_LEGACY_RAW_COMMAND%", request.argv[-1])
                self.assertEqual(
                    (("PIXELFLASHER_LEGACY_RAW_COMMAND", '"echo" literal && value'),),
                    request.env,
                )
            else:
                self.assertIsNone(request.env)
                self.assertEqual('"echo" literal && value', request.argv[-1])
                self.assertEqual("-c", request.argv[-2])

            stored = json.loads((root / "my-tools-v2.json").read_text(encoding="utf-8"))
            stored["legacyRaw"][0]["arguments"] = "changed after permission"
            (root / "my-tools-v2.json").write_text(json.dumps(stored), encoding="utf-8")
            rebound = MyToolsRepository(root / "my-tools-v2.json", legacy_path=legacy)
            self.assertFalse(rebound.get_legacy(spec.legacy_id).permission_granted)
            self.assertEqual(
                "legacy_raw_permission_required",
                rebound.get_legacy(spec.legacy_id).to_public_dict()["blockedReason"],
            )

    def test_legacy_raw_rejects_redirection_elevation_and_unapproved_cwd(self):
        cases = (
            ("echo", "safe > output.txt", "", "legacy_raw_redirection_blocked"),
            ("sudo", "whoami", "", "legacy_raw_elevation_blocked"),
            ("echo", "safe", str(Path.home()), "legacy_raw_cwd_not_allowed"),
        )
        for command_text, arguments, cwd, code in cases:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                legacy = root / "mytools.json"
                legacy.write_text(
                    json.dumps(
                        {
                            "tools": {
                                "1": {
                                    "title": "Restricted",
                                    "command": command_text,
                                    "arguments": arguments,
                                    "directory": cwd,
                                    "enabled": True,
                                }
                            }
                        }
                    ),
                    encoding="iso-8859-1",
                )
                repository = MyToolsRepository(root / "store.json", legacy_path=legacy)
                service = MyToolsService(
                    repository,
                    CommandExecutor(FakeProcessTransport()),
                    allowed_legacy_cwd_roots=(root,),
                )
                spec = repository.get_legacy("legacy:1")
                with self.assertRaises(MyToolsError) as raised:
                    service.set_legacy_permission(
                        spec.legacy_id,
                        granted=True,
                        confirmation_text=service.legacy_permission_confirmation(spec),
                    )
                self.assertEqual(code, raised.exception.code)

    def test_command_engine_enforces_expert_mode_and_exact_legacy_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy = root / "mytools.json"
            legacy.write_text(
                json.dumps(
                    {
                        "tools": {
                            "1": {
                                "title": "Engine legacy",
                                "command": "echo",
                                "arguments": "engine",
                                "enabled": True,
                            }
                        }
                    }
                ),
                encoding="iso-8859-1",
            )
            repository = MyToolsRepository(root / "store.json", legacy_path=legacy)
            transport = FakeProcessTransport([TransportOutcome(0, stdout="ok")])
            service = MyToolsService(
                repository,
                CommandExecutor(transport),
                allowed_legacy_cwd_roots=(root,),
            )
            spec = repository.get_legacy("legacy:1")
            store = AppStateStore(
                AppSnapshot(
                    revision=7,
                    preferences=ModernPreferences(expert_mode=True),
                )
            )
            engine = make_test_command_engine(
                store=store,
                executor=service.executor,
                my_tools_service=service,
            )

            granted = engine.execute(
                AppCommand(
                    "tools.myTools.legacyPermission",
                    expected_revision=7,
                    payload={
                        "toolId": spec.legacy_id,
                        "granted": True,
                        "confirmationText": service.legacy_permission_confirmation(spec),
                    },
                )
            )
            completed = engine.execute(
                AppCommand(
                    "tools.myTools.legacyRun",
                    expected_revision=7,
                    payload={
                        "toolId": spec.legacy_id,
                        "confirmationText": service.legacy_run_confirmation(spec),
                    },
                )
            )

            self.assertTrue(granted.ok)
            self.assertEqual("legacy_raw_permission_updated", granted.code)
            self.assertTrue(completed.ok)
            self.assertEqual("legacy_raw_completed", completed.code)
            self.assertEqual(1, len(transport.calls))
            store.update(
                expected_revision=7,
                preferences=ModernPreferences(expert_mode=False),
            )
            denied = engine.execute(
                AppCommand(
                    "tools.myTools.legacyRun",
                    expected_revision=8,
                    payload={
                        "toolId": spec.legacy_id,
                        "confirmationText": service.legacy_run_confirmation(spec),
                    },
                )
            )
            self.assertEqual("expert_mode_required", denied.code)
            self.assertEqual(1, len(transport.calls))


class MyToolsBridgeTests(unittest.TestCase):
    def test_closed_actions_reject_ambiguous_or_raw_shell_payloads(self):
        _bridge({"action": "list"})
        _bridge({"action": "run", "toolId": "a" * 32})
        _bridge(
            {
                "action": "save",
                "title": "Safe",
                "grant": "g" * 64,
                "arguments": ["--one", "two"],
                "enabled": True,
            }
        )
        for payload in (
            {"action": "list", "toolId": "a" * 32},
            {"action": "run", "toolId": "a" * 32, "arguments": ["/c"]},
            {"action": "save", "title": "Raw", "command": "cmd /c whoami"},
            {"action": "save", "title": "No grant", "arguments": [], "enabled": True},
        ):
            with self.subTest(payload=payload), self.assertRaises(BridgeProtocolError):
                _bridge(payload)

    def test_factory_resolves_executable_grant_to_bound_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = _executable(root)
            factory = create_command_factory(lambda: AppSnapshot(revision=7))
            grant = factory.path_grants.issue_file(
                executable, purpose="tools.myTools.executable"
            )
            command = factory(
                _bridge(
                    {
                        "action": "save",
                        "title": "Safe",
                        "grant": grant.token,
                        "arguments": [],
                        "enabled": True,
                    }
                )
            )

            self.assertIsInstance(command.payload["grant"], BoundReadFile)
            self.assertNotIn(str(executable), repr(command))

    def test_public_projection_is_closed_and_never_accepts_a_host_path(self):
        tool = {
            "id": "a" * 32,
            "title": "Safe",
            "mode": "safeArgv",
            "displayName": "safe.exe",
            "sha256": "b" * 64,
            "arguments": ["--literal"],
            "enabled": True,
        }
        projected = project_operation_result(
            "tools.myTools",
            OperationResult.success(
                "public-my-tools",
                value={"schemaVersion": 2, "tools": [tool], "legacyRaw": [], "revision": 7},
            ),
        )
        self.assertNotIn("executable", json.dumps(projected))
        hostile = {**tool, "path": "C:/Users/private/tool.exe"}
        with self.assertRaises(PublicProjectionError):
            project_operation_result(
                "tools.myTools",
                OperationResult.success(
                    "hostile-my-tools",
                    value={"tool": hostile, "revision": 7},
                ),
            )

    def test_legacy_raw_bridge_and_public_receipt_are_exact_and_closed(self):
        _bridge(
            {
                "toolId": "legacy:1",
                "granted": True,
                "confirmationText": "ALLOW RAW 01234567",
            },
            "tools.myTools.legacyPermission",
        )
        _bridge(
            {
                "toolId": "legacy:1",
                "confirmationText": "RUN RAW 01234567",
            },
            "tools.myTools.legacyRun",
        )
        legacy = {
            "id": "legacy:1",
            "title": "Legacy",
            "mode": "legacyRaw",
            "displayName": "Legacy 9.x",
            "sha256": "",
            "arguments": [],
            "enabled": True,
            "permissionGranted": True,
            "blockedReason": "",
            "commandPreview": '"tool.exe" --literal',
            "fingerprint": "a" * 64,
            "workingDirectory": "default",
        }
        projected = project_operation_result(
            "tools.myTools.legacyRun",
            OperationResult.success(
                "legacy-public",
                value={"tool": legacy, "revision": 7},
            ),
        )
        self.assertEqual('"tool.exe" --literal', projected["value"]["tool"]["commandPreview"])
        self.assertNotIn("cwd", json.dumps(projected))
        with self.assertRaises(BridgeProtocolError):
            _bridge(
                {
                    "toolId": "legacy:1",
                    "confirmationText": "RUN RAW 01234567",
                    "command": "whoami",
                },
                "tools.myTools.legacyRun",
            )


if __name__ == "__main__":
    unittest.main()
