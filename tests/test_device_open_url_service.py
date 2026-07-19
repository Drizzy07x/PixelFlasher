import hashlib
import json
import shlex
import threading
import unittest
from dataclasses import replace

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    AppStateStore,
    CommandExecutor,
    DeviceInfo,
    FakeProcessTransport,
    FakeTransportStep,
    InteractionDecision,
    OperationPostcondition,
    OperationResult,
    OperationRisk,
    OperationStatus,
    ToolchainInfo,
    TransportOutcome,
)
from pixelflasher_core.device_tools import DeviceToolPlanningError, DeviceToolsService
from tests.command_engine_factory import make_test_command_engine
from ui.public_bridge import PublicProjectionError, project_operation_result

REMOTE_PREFIX = (
    "am start -W --user current "
    "-a android.intent.action.VIEW "
    "-c android.intent.category.BROWSABLE -d "
)


def snapshot() -> AppSnapshot:
    return AppSnapshot(
        revision=7,
        devices=(DeviceInfo("SERIAL", codename="akita", mode="adb", online=True),),
        selected_serial="SERIAL",
        toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
    )


def command(url: object, **extra: object) -> AppCommand:
    return AppCommand(
        "device.openUrl",
        expected_revision=7,
        target_serial="SERIAL",
        payload={"url": url, **extra},
    )


class DeviceOpenUrlServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = DeviceToolsService()
        self.snapshot = snapshot()

    def compile(self, url: object, **extra: object):
        return self.service.compile(command(url, **extra), self.snapshot)

    def test_compiles_one_posix_quoted_remote_script_with_mutating_evidence(self) -> None:
        supplied = "HTTPS://BÜCHER.example:444/a'b?q=1&next=$HOME;tick=`id`#frag"
        canonical = "https://xn--bcher-kva.example:444/a'b?q=1&next=$HOME;tick=`id`#frag"

        compilation = self.compile(supplied)
        request = compilation.plan.request
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        self.assertEqual(
            (
                "ADB",
                "-s",
                "SERIAL",
                "shell",
                f"{REMOTE_PREFIX}{shlex.quote(canonical)}",
            ),
            request.argv,
        )
        self.assertEqual(5, len(request.argv))
        self.assertIsNone(request.cwd)
        self.assertIsNone(request.env)
        self.assertEqual(30.0, request.timeout_seconds)
        self.assertEqual(64 * 1024, request.output_limit_bytes)
        self.assertFalse(hasattr(request, "shell"))
        self.assertIs(OperationRisk.MUTATING, compilation.plan.risk)
        self.assertTrue(compilation.device_write)
        self.assertTrue(compilation.requires_confirmation)
        self.assertFalse(compilation.destructive)
        self.assertEqual("device_view_intent", compilation.plan.data_behavior)
        self.assertEqual("SERIAL", compilation.plan.target_serial)
        self.assertEqual("akita", compilation.plan.expected_codename)
        self.assertEqual("adb", compilation.plan.expected_device_state)
        self.assertEqual(1, len(compilation.plan.postconditions))
        postcondition = compilation.plan.postconditions[0]
        self.assertEqual("view_intent_accepted", postcondition.kind)
        self.assertEqual(
            {
                "targetSerial": "SERIAL",
                "scheme": "https",
                "host": "xn--bcher-kva.example",
                "urlSha256": digest,
            },
            dict(postcondition.expected),
        )
        self.assertNotIn(canonical, compilation.plan.label)
        self.assertNotIn(canonical, json.dumps(postcondition.to_dict()))

    def test_accepts_the_closed_boundary_and_canonicalizes_idna_ipv4_and_ipv6(self) -> None:
        prefix = "https://example.com/"
        maximum = prefix + "x" * (2_048 - len(prefix.encode("utf-8")))
        cases = (
            (maximum, "https", "example.com"),
            ("http://127.0.0.1:8080/path", "http", "127.0.0.1"),
            ("https://[2001:0DB8::1]/path", "https", "2001:db8::1"),
            ("https://BÜCHER.example/über?q=%E2%9C%93", "https", "xn--bcher-kva.example"),
        )
        for url, scheme, host in cases:
            with self.subTest(url=url[:80]):
                compilation = self.compile(url)
                evidence = compilation.plan.postconditions[0].expected
                self.assertEqual(scheme, evidence["scheme"])
                self.assertEqual(host, evidence["host"])

    def test_rejects_non_http_ambiguous_or_oversized_urls_before_execution(self) -> None:
        prefix = "https://example.com/"
        invalid = (
            None,
            42,
            "",
            "ftp://example.com/file",
            "javascript:alert(1)",
            "intent://example.com/#Intent;end",
            "file:///data/local/tmp/private",
            "https://",
            "https://user@example.com/",
            "https://user:pass@example.com/",
            "https://example.com\\evil",
            "https://example.com/a b",
            "https://example.com/a\nnext",
            "https://example.com/\u200bhidden",
            "https://example.com/%",
            "https://example.com/%0",
            "https://example.com/%GG",
            "https://example.com:0/",
            "https://example.com:65536/",
            "https://example.com:not-a-port/",
            "https://bad_host.example/",
            "https://example.com./",
            "https://999.999.999.999/",
            "https://[fe80::1%25eth0]/",
            prefix + "x" * (2_049 - len(prefix.encode("utf-8"))),
        )
        for url in invalid:
            with self.subTest(url=repr(url)[:100]), self.assertRaises(DeviceToolPlanningError) as raised:
                self.compile(url)
            self.assertEqual("device_open_url_invalid", raised.exception.code)

        with self.assertRaises(DeviceToolPlanningError) as unknown:
            self.compile("https://example.com/", command="id")
        self.assertEqual("invalid_device_tool_payload", unknown.exception.code)

    def test_finalizer_requires_bounded_status_and_complete_and_returns_an_exact_receipt(self) -> None:
        url = "https://example.com/private/path?token=do-not-return"
        compilation = self.compile(url)
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
        provisional = OperationResult.success(
            "open-url",
            stdout=(
                "Starting: Intent { act=android.intent.action.VIEW }\n"
                "Status: ok\n"
                "LaunchState: COLD\n"
                "Activity: com.android.chrome/.Main\n"
                "TotalTime: 42\n"
                "Complete\n"
            ),
        )

        result = self.service.finalize_open_url(compilation, provisional)

        self.assertTrue(result.ok)
        self.assertEqual("device_open_url_succeeded", result.code)
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)
        self.assertEqual(
            {
                "action": "openUrl",
                "targetSerial": "SERIAL",
                "scheme": "https",
                "host": "example.com",
                "urlSha256": digest,
                "intentAccepted": True,
            },
            result.value,
        )
        serialized = json.dumps(result.to_dict())
        self.assertNotIn("private/path", serialized)
        self.assertNotIn("do-not-return", serialized)

    def test_exit_zero_without_exact_completion_evidence_fails_closed(self) -> None:
        compilation = self.compile("https://example.com/private")
        invalid_outputs = (
            "Starting: Intent {}\nComplete\n",
            "Status: ok\n",
            "Complete\nStatus: ok\n",
            "Status: ok\nStatus: ok\nComplete\n",
            "Status: ok\nComplete\nComplete\n",
            "Status: ok\nError: unable to resolve Intent\nComplete\n",
            "Status: ok\nError type 3\nComplete\n",
            "Status: timeout\nStatus: ok\nComplete\n",
            f"Status: ok\n{'x' * (4 * 1024 + 1)}\nComplete\n",
            f"Status: ok\n{'x' * (64 * 1024)}\nComplete\n",
            "Status: ok\x00\nComplete\n",
        )
        for output in invalid_outputs:
            with self.subTest(output=output[:80]):
                result = self.service.finalize_open_url(
                    compilation,
                    OperationResult.success("open-url", stdout=output),
                )
                self.assertIs(OperationStatus.FAILED, result.status)
                self.assertEqual("device_open_url_evidence_invalid", result.code)
                self.assertEqual("", result.stdout)
                self.assertEqual("", result.stderr)

        stderr_result = self.service.finalize_open_url(
            compilation,
            OperationResult.success(
                "open-url",
                stdout="Status: ok\nComplete\n",
                stderr="unexpected diagnostic",
            ),
        )
        self.assertEqual("device_open_url_evidence_invalid", stderr_result.code)

    def test_failures_and_cancellation_discard_raw_url_output(self) -> None:
        url = "https://example.com/private?token=hunter2"
        compilation = self.compile(url)
        cases = (
            OperationResult.failed(
                "failed",
                code="process_failed",
                exit_code=1,
                stdout=f"Starting: {url}",
                stderr=f"Could not open {url}",
            ),
            OperationResult.failed(
                "unknown",
                code="outcome_unknown",
                stdout=f"Possibly opened {url}",
            ),
            OperationResult.cancelled(
                "cancelled",
                stdout=f"Starting: {url}",
                stderr=url,
            ),
        )
        expected = (
            (OperationStatus.FAILED, "device_open_url_failed"),
            (OperationStatus.FAILED, "outcome_unknown"),
            (OperationStatus.CANCELLED, "cancelled"),
        )
        for provisional, (status, code) in zip(cases, expected, strict=True):
            with self.subTest(code=code):
                result = self.service.finalize_open_url(compilation, provisional)
                self.assertIs(status, result.status)
                self.assertEqual(code, result.code)
                self.assertEqual("", result.stdout)
                self.assertEqual("", result.stderr)
                self.assertNotIn(url, json.dumps(result.to_dict()))

    def test_finalizer_rejects_a_plan_without_exact_evidence_metadata(self) -> None:
        compilation = self.compile("https://example.com/")
        invalid_plan = replace(
            compilation.plan,
            postconditions=(OperationPostcondition("wrong_evidence"),),
        )
        invalid_compilation = replace(compilation, plan=invalid_plan)

        result = self.service.finalize_open_url(
            invalid_compilation,
            OperationResult.success("open-url", stdout="Status: ok\nComplete\n"),
        )

        self.assertIs(OperationStatus.FAILED, result.status)
        self.assertEqual("device_open_url_compilation_invalid", result.code)

        unsafe_evidence = OperationPostcondition(
            "view_intent_accepted",
            {
                "targetSerial": "SERIAL",
                "scheme": "https",
                "host": "example.com\nforged",
                "urlSha256": "a" * 64,
            },
        )
        unsafe_plan = replace(compilation.plan, postconditions=(unsafe_evidence,))
        unsafe = self.service.finalize_open_url(
            replace(compilation, plan=unsafe_plan),
            OperationResult.success("open-url", stdout="Status: ok\nComplete\n"),
        )
        self.assertEqual("device_open_url_compilation_invalid", unsafe.code)

    def test_public_projection_accepts_only_the_closed_route_free_receipt(self) -> None:
        value = {
            "action": "openUrl",
            "targetSerial": "SERIAL",
            "scheme": "https",
            "host": "xn--bcher-kva.example",
            "urlSha256": "a" * 64,
            "intentAccepted": True,
        }
        public = project_operation_result(
            "device.openUrl",
            OperationResult.success("open-url", value=value),
        )
        self.assertEqual(value, public["value"])
        self.assertNotIn("https://", json.dumps(public).casefold())
        self.assertNotIn("private", json.dumps(public).casefold())

        for invalid in (
            {**value, "url": "https://example.com/private"},
            {**value, "targetSerial": "bad serial"},
            {**value, "scheme": "file"},
            {**value, "host": "example.com/path"},
            {**value, "urlSha256": "A" * 64},
            {**value, "intentAccepted": False},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(PublicProjectionError):
                project_operation_result(
                    "device.openUrl",
                    OperationResult.success("open-url", value=invalid),
                )

    def test_command_engine_revalidates_confirms_and_verifies_the_intent_receipt(self) -> None:
        interactions = []
        transport = FakeProcessTransport(
            [TransportOutcome(0, "Status: ok\nActivity: browser/.Main\nComplete\n")]
        )
        engine = make_test_command_engine(
            store=AppStateStore(self.snapshot),
            executor=CommandExecutor(transport),
            interaction_handler=lambda request: (
                interactions.append(request) or InteractionDecision.ACCEPTED
            ),
        )

        result = engine.execute(command("https://example.com/path"))

        self.assertTrue(result.ok)
        self.assertEqual("device_open_url_succeeded", result.code)
        self.assertEqual(
            {
                "action": "openUrl",
                "targetSerial": "SERIAL",
                "scheme": "https",
                "host": "example.com",
                "urlSha256": hashlib.sha256(
                    b"https://example.com/path"
                ).hexdigest(),
                "intentAccepted": True,
            },
            result.value,
        )
        self.assertEqual(1, len(interactions))
        self.assertEqual("Confirm device operation", interactions[0].title)
        self.assertFalse(interactions[0].destructive)
        self.assertEqual("SERIAL", interactions[0].target_serial)
        self.assertEqual(1, len(transport.calls))
        self.assertEqual(result, engine.store.snapshot().last_result)
        serialized = json.dumps(result.to_dict())
        self.assertNotIn("https://example.com/path", serialized)

    def test_command_engine_decline_and_late_cancel_never_claim_success(self) -> None:
        declined_transport = FakeProcessTransport(
            [TransportOutcome(0, "Status: ok\nComplete\n")]
        )
        declined_engine = make_test_command_engine(
            store=AppStateStore(self.snapshot),
            executor=CommandExecutor(declined_transport),
            interaction_handler=lambda _request: InteractionDecision.CANCELLED,
        )
        declined = declined_engine.execute(command("https://example.com/declined"))
        self.assertIs(OperationStatus.CANCELLED, declined.status)
        self.assertEqual([], declined_transport.calls)

        started = threading.Event()
        release = threading.Event()
        transport = FakeProcessTransport(
            [
                FakeTransportStep(
                    TransportOutcome(0, "Status: ok\nComplete\n"),
                    started_event=started,
                    release_event=release,
                )
            ]
        )
        engine = make_test_command_engine(
            store=AppStateStore(self.snapshot),
            executor=CommandExecutor(transport),
            interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
            postcondition_observer=lambda *_args: True,
        )
        late_command = AppCommand(
            "device.openUrl",
            expected_revision=7,
            target_serial="SERIAL",
            payload={"url": "https://example.com/private"},
            operation_id="open-url-late-cancel",
        )
        results: list[OperationResult] = []
        worker = threading.Thread(target=lambda: results.append(engine.execute(late_command)))
        worker.start()
        self.assertTrue(started.wait(2))
        self.assertTrue(engine.cancel(late_command.operation_id))
        worker.join(3)
        release.set()

        self.assertFalse(worker.is_alive())
        self.assertEqual(1, len(results))
        self.assertIs(OperationStatus.FAILED, results[0].status)
        self.assertEqual("outcome_unknown", results[0].code)
        self.assertNotIn("https://example.com/private", json.dumps(results[0].to_dict()))


if __name__ == "__main__":
    unittest.main()
