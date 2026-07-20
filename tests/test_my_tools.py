import json
import os
import tempfile
import unittest
from pathlib import Path

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    BoundReadFile,
    CancellationToken,
    CommandExecutor,
    FakeProcessTransport,
    MyToolsError,
    MyToolsRepository,
    MyToolsService,
    OperationResult,
    PathGrantStore,
)
from pixelflasher_core.executor import TransportOutcome
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


def _bridge(payload: dict[str, object]) -> BridgeRequest:
    return BridgeRequest.from_json(
        json.dumps(
            {
                "version": BRIDGE_VERSION,
                "requestId": "my-tools-test",
                "command": "tools.myTools",
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

    def test_imports_legacy_commands_as_blocked_metadata_only(self):
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
            self.assertNotIn("cmd.exe", json.dumps(inventory))
            self.assertNotIn("erase everything", json.dumps(inventory))

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
                value={"schemaVersion": 1, "tools": [tool], "legacyRaw": [], "revision": 7},
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


if __name__ == "__main__":
    unittest.main()
