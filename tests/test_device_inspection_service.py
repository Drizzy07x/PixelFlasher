import json
import threading
import unittest
from typing import cast

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    AppStateStore,
    CommandExecutor,
    DeviceInfo,
    FakeProcessTransport,
    FakeTransportStep,
    OperationResult,
    OperationRisk,
    OperationStatus,
    ToolchainInfo,
    TransportOutcome,
)
from pixelflasher_core.device_tools import (
    DeviceInspectionParseError,
    DeviceToolPlanningError,
    DeviceToolsService,
    parse_bounded_fastboot_variables,
    parse_bounded_getprop,
    parse_bounded_screen_xml,
)
from tests.command_engine_factory import make_test_command_engine
from ui.bridge_contract import BRIDGE_VERSION, BridgeProtocolError, BridgeRequest

GETPROP_OUTPUT = """\
[ro.boot.slot_suffix]: [_a]
[ro.bootloader]: [akita-15.2-12345678]
[ro.build.fingerprint]: [google/akita/akita:16/BP2A.260101.001/1234567:user/release-keys]
[ro.build.id]: [BP2A.260101.001]
[ro.build.tags]: [release-keys]
[ro.build.type]: [user]
[ro.build.version.incremental]: [1234567]
[ro.build.version.release]: [16]
[ro.build.version.security_patch]: [2026-01-05]
[ro.product.brand]: [google]
[ro.product.device]: [akita]
[ro.product.first_api_level]: [34]
[ro.product.manufacturer]: [Google]
[ro.product.model]: [Pixel 8a]
[ro.product.name]: [akita]
[ro.serialno]: [PRIVATE-SERIAL]
"""


def snapshot() -> AppSnapshot:
    return AppSnapshot(
        revision=7,
        devices=(DeviceInfo("SERIAL", codename="akita", mode="adb", online=True),),
        selected_serial="SERIAL",
        toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
    )


def command(action: str) -> AppCommand:
    return AppCommand(
        "device.inspect",
        expected_revision=7,
        target_serial="SERIAL",
        payload={"action": action},
    )


class DeviceInspectionServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = DeviceToolsService(
            bootloader_prefixes={"akita": "akita"},
        )
        self.snapshot = snapshot()

    def compile(self, action: str):
        return self.service.compile(command(action), self.snapshot)

    def test_each_action_compiles_one_exact_serial_revision_and_codename_bound_argv(self):
        expected = {
            "properties": (("ADB", "-s", "SERIAL", "shell", "getprop"),),
            "bootloaderVersions": (
                ("ADB", "-s", "SERIAL", "shell", "getprop"),
                ("ADB", "-s", "SERIAL", "shell", "su", "0", "id", "-u"),
                (
                    "ADB",
                    "-s",
                    "SERIAL",
                    "exec-out",
                    "su",
                    "0",
                    "toybox",
                    "cat",
                    "/dev/block/by-name/abl_a",
                ),
                (
                    "ADB",
                    "-s",
                    "SERIAL",
                    "exec-out",
                    "su",
                    "0",
                    "toybox",
                    "cat",
                    "/dev/block/by-name/abl_b",
                ),
            ),
            "pifPrint": (("ADB", "-s", "SERIAL", "shell", "getprop"),),
            "screenXml": ((
                "ADB", "-s", "SERIAL", "exec-out", "uiautomator", "dump", "/dev/tty",
            ),),
        }
        for action, requests in expected.items():
            with self.subTest(action=action):
                compilation = self.compile(action)
                self.assertEqual(requests, tuple(item.argv for item in compilation.plan.requests))
                self.assertEqual("SERIAL", compilation.plan.target_serial)
                self.assertEqual(7, compilation.plan.snapshot_revision)
                self.assertEqual("akita", compilation.plan.expected_codename)
                self.assertEqual("adb", compilation.plan.expected_device_state)
                self.assertIs(OperationRisk.READ_ONLY, compilation.plan.risk)
                self.assertEqual((), compilation.plan.postconditions)
                self.assertFalse(compilation.device_write)
                self.assertFalse(compilation.destructive)
                self.assertFalse(compilation.requires_confirmation)
                if action == "bootloaderVersions":
                    self.assertEqual(("abl_a", "abl_b"), compilation.plan.partitions)
                    self.assertEqual(("a", "b"), compilation.plan.slots)
                    self.assertEqual("bootloader-slot-stream", compilation.execution)

    def test_action_and_payload_injection_fail_before_execution(self):
        for action in (
            "properties;rm",
            "Properties",
            "screenXml /data/local/tmp/out",
            "",
        ):
            with self.subTest(action=action), self.assertRaises(DeviceToolPlanningError) as raised:
                self.compile(action)
            self.assertEqual("device_inspection_action_invalid", raised.exception.code)

        with self.assertRaises(DeviceToolPlanningError) as unknown:
            self.service.compile(
                AppCommand(
                    "device.inspect",
                    expected_revision=7,
                    target_serial="SERIAL",
                    payload={"action": "properties", "command": "id"},
                ),
                self.snapshot,
            )
        self.assertEqual("invalid_device_tool_payload", unknown.exception.code)

    def test_getprop_parser_is_strict_bounded_and_rejects_duplicates(self):
        parsed = parse_bounded_getprop("[ro.product.device]: [akita]\r\n")
        self.assertEqual({"ro.product.device": "akita"}, parsed)

        invalid_cases = (
            ("ro.product.device=akita\n", "getprop_format_invalid"),
            (
                "[ro.product.device]: [akita]\n[ro.product.device]: [other]\n",
                "getprop_property_duplicate",
            ),
            ("[ro.product.device]: [bad\tvalue]\n", "getprop_value_invalid"),
            (
                f"[ro.product.device]: [{'x' * (1024 * 1024)}]\n",
                "getprop_output_too_large",
            ),
        )
        for output, code in invalid_cases:
            with self.subTest(code=code), self.assertRaises(DeviceInspectionParseError) as raised:
                parse_bounded_getprop(output)
            self.assertEqual(code, raised.exception.code)

    def test_properties_report_redacts_identifiers_and_discards_raw_output(self):
        compilation = self.compile("properties")
        result = self.service.finalize_inspection(
            compilation,
            OperationResult.success(
                "inspect-properties",
                stdout=GETPROP_OUTPUT,
            ),
        )

        self.assertTrue(result.ok)
        self.assertEqual("device_inspection_properties_succeeded", result.code)
        self.assertEqual("[REDACTED]", result.value["properties"]["ro.serialno"])
        self.assertEqual(["ro.serialno"], result.value["redactedKeys"])
        self.assertEqual("Pixel 8a", result.value["summary"]["model"])
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)
        self.assertNotIn("PRIVATE-SERIAL", json.dumps(result.to_dict()))

    def test_pif_report_is_typed_and_fail_closed_when_incomplete(self):
        pif = self.service.finalize_inspection(
            self.compile("pifPrint"),
            OperationResult.success("pif", stdout=GETPROP_OUTPUT),
        )
        self.assertTrue(pif.ok)
        self.assertEqual("playintegrityfork-v5-compatible", pif.value["format"])
        self.assertEqual("32", pif.value["profile"]["DEVICE_INITIAL_SDK_INT"])
        self.assertEqual("akita", pif.value["profile"]["DEVICE"])
        self.assertNotIn("PRIVATE-SERIAL", pif.value["json"])

        wrong_boundary = self.service.finalize_inspection(
            self.compile("bootloaderVersions"),
            OperationResult.success(
                "missing-bootloader",
                stdout="[ro.product.device]: [akita]\n",
            ),
        )
        self.assertIs(OperationStatus.FAILED, wrong_boundary.status)
        self.assertEqual("device_inspection_compilation_invalid", wrong_boundary.code)
        self.assertEqual("", wrong_boundary.stdout)

    def test_screen_xml_parser_validates_structure_limits_and_redacts_password_nodes(self):
        report = parse_bounded_screen_xml(
            "<?xml version='1.0' encoding='UTF-8'?>"
            "<hierarchy rotation='0'><node text='secret' content-desc='pin' "
            "password='true'/><node text='public'/></hierarchy>\n"
            "UI hierchary dumped to: /dev/tty\n"
        )
        self.assertEqual(3, report["nodeCount"])
        self.assertEqual(2, report["redactedFields"])
        xml = cast(str, report["xml"])
        digest = cast(str, report["sha256"])
        self.assertIn("[REDACTED]", xml)
        self.assertNotIn("secret", xml)
        self.assertNotIn("pin", xml)
        self.assertEqual(64, len(digest))

        invalid_cases = (
            ("not xml", "screen_xml_missing"),
            ("<root/>", "screen_xml_missing"),
            (
                "<!DOCTYPE hierarchy [<!ENTITY x 'bad'>]><hierarchy>&x;</hierarchy>",
                "screen_xml_declaration_forbidden",
            ),
            (
                "unexpected\n<hierarchy></hierarchy>",
                "screen_xml_wrapper_invalid",
            ),
        )
        for output, code in invalid_cases:
            with self.subTest(code=code), self.assertRaises(DeviceInspectionParseError) as raised:
                parse_bounded_screen_xml(output)
            self.assertEqual(code, raised.exception.code)

    def test_cancel_and_process_failure_are_explicit_and_redacted(self):
        compilation = self.compile("properties")
        cancelled = self.service.finalize_inspection(
            compilation,
            OperationResult.cancelled(
                "cancelled",
                stdout="[ro.serialno]: [PRIVATE-SERIAL]",
            ),
        )
        failed = self.service.finalize_inspection(
            compilation,
            OperationResult.failed(
                "failed",
                code="process_failed",
                stdout="[ro.serialno]: [PRIVATE-SERIAL]",
                stderr="private diagnostic",
            ),
        )
        self.assertIs(OperationStatus.CANCELLED, cancelled.status)
        self.assertEqual("", cancelled.stdout)
        self.assertIs(OperationStatus.FAILED, failed.status)
        self.assertEqual("process_failed", failed.code)
        self.assertEqual("", failed.stdout)
        self.assertEqual("", failed.stderr)

    def test_command_engine_routes_through_operation_runner_and_typed_finalizer(self):
        transport = FakeProcessTransport([TransportOutcome(0, GETPROP_OUTPUT)])
        engine = make_test_command_engine(
            store=AppStateStore(self.snapshot),
            executor=CommandExecutor(transport),
        )

        result = engine.execute(command("properties"))

        self.assertTrue(result.ok)
        self.assertEqual("device_inspection_properties_succeeded", result.code)
        self.assertEqual(
            [("ADB", "-s", "SERIAL", "shell", "getprop")],
            [request.argv for request in transport.calls],
        )
        self.assertEqual(result, engine.store.snapshot().last_result)
        self.assertNotIn("PRIVATE-SERIAL", json.dumps(result.to_dict()))

    def test_command_engine_cancellation_remains_cancelled_and_redacted(self):
        started = threading.Event()
        release = threading.Event()
        transport = FakeProcessTransport(
            [
                FakeTransportStep(
                    TransportOutcome(0, GETPROP_OUTPUT),
                    started_event=started,
                    release_event=release,
                )
            ]
        )
        engine = make_test_command_engine(
            store=AppStateStore(self.snapshot),
            executor=CommandExecutor(transport),
        )
        inspection = AppCommand(
            "device.inspect",
            expected_revision=7,
            target_serial="SERIAL",
            payload={"action": "properties"},
            operation_id="inspect-cancel",
        )
        result_holder: list[OperationResult] = []
        worker = threading.Thread(
            target=lambda: result_holder.append(engine.execute(inspection)),
        )

        worker.start()
        self.assertTrue(started.wait(2))
        self.assertTrue(engine.cancel("inspect-cancel"))
        worker.join(2)
        release.set()

        self.assertFalse(worker.is_alive())
        self.assertEqual(1, len(result_holder))
        self.assertIs(OperationStatus.CANCELLED, result_holder[0].status)
        self.assertEqual("", result_holder[0].stdout)
        self.assertNotIn("PRIVATE-SERIAL", json.dumps(result_holder[0].to_dict()))

    def test_command_engine_process_failure_does_not_leak_partial_report(self):
        transport = FakeProcessTransport(
            [
                TransportOutcome(
                    17,
                    "[ro.serialno]: [PRIVATE-SERIAL]\n",
                    "transport diagnostic",
                )
            ]
        )
        engine = make_test_command_engine(
            store=AppStateStore(self.snapshot),
            executor=CommandExecutor(transport),
        )

        result = engine.execute(command("properties"))

        self.assertIs(OperationStatus.FAILED, result.status)
        self.assertEqual("process_failed", result.code)
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)
        self.assertNotIn("PRIVATE-SERIAL", json.dumps(result.to_dict()))

    def test_bridge_rejects_unknown_inspection_action_before_command_factory(self):
        encoded = json.dumps(
            {
                "version": BRIDGE_VERSION,
                "requestId": "inspect-bridge",
                "command": "device.inspect",
                "payload": {"action": "properties;id"},
                "expectedRevision": 7,
            }
        )
        with self.assertRaises(BridgeProtocolError) as raised:
            BridgeRequest.from_json(encoded)
        self.assertEqual("invalid_payload", raised.exception.code)


class FastbootVariableInspectionTests(unittest.TestCase):
    """9.x served Device Info in fastboot mode through ``getvar all``.

    The four adb inspection actions cannot answer in fastboot, so the bootloader
    variable dump is its own command with its own device states.
    """

    def setUp(self) -> None:
        self.service = DeviceToolsService(bootloader_prefixes={"akita": "akita"})
        self.snapshot = AppSnapshot(
            revision=7,
            devices=(DeviceInfo("SERIAL", codename="akita", mode="fastboot", online=True),),
            selected_serial="SERIAL",
            toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
        )

    def command(self) -> AppCommand:
        return AppCommand(
            "device.fastbootVariables",
            expected_revision=7,
            target_serial="SERIAL",
            payload={},
        )

    def compile(self):
        return self.service.compile(self.command(), self.snapshot)

    def test_one_exact_serial_bound_argv_is_compiled_read_only(self):
        compilation = self.compile()

        self.assertEqual(
            (("FASTBOOT", "-s", "SERIAL", "getvar", "all"),),
            tuple(item.argv for item in compilation.plan.requests),
        )
        self.assertEqual("fastbootVariables", compilation.action)
        self.assertEqual("SERIAL", compilation.plan.target_serial)
        self.assertEqual(7, compilation.plan.snapshot_revision)
        self.assertIs(OperationRisk.READ_ONLY, compilation.plan.risk)
        self.assertFalse(compilation.device_write)
        self.assertFalse(compilation.destructive)
        self.assertFalse(compilation.requires_confirmation)

    def test_planning_fails_closed_without_a_validated_fastboot(self):
        self.snapshot = AppSnapshot(
            revision=7,
            devices=(DeviceInfo("SERIAL", codename="akita", mode="fastboot", online=True),),
            selected_serial="SERIAL",
            toolchain=ToolchainInfo("ADB", "", "36.0.0", False),
        )
        with self.assertRaises(DeviceToolPlanningError) as raised:
            self.compile()
        self.assertEqual("toolchain_not_ready", raised.exception.code)

    def test_variables_arrive_on_the_diagnostic_stream_and_identifiers_are_redacted(self):
        compilation = self.compile()
        result = self.service.finalize_fastboot_variables(
            compilation,
            OperationResult.success(
                "variables",
                stdout="",
                stderr=(
                    "(bootloader) version-bootloader: akita-15.2-12345678\n"
                    "(bootloader) version-baseband: g5300-000000\n"
                    "(bootloader) product: akita\n"
                    "(bootloader) current-slot: a\n"
                    "(bootloader) unlocked: yes\n"
                    "(bootloader) secure: no\n"
                    "(bootloader) serialno: PRIVATE-SERIAL\n"
                    "all: \n"
                    "Finished. Total time: 0.031s\n"
                ),
            ),
        )

        self.assertIs(OperationStatus.SUCCESS, result.status)
        value = cast(dict, result.value)
        self.assertEqual("fastbootVariables", value["action"])
        self.assertEqual("akita", value["summary"]["product"])
        self.assertEqual("akita-15.2-12345678", value["summary"]["bootloaderVersion"])
        self.assertEqual("a", value["summary"]["currentSlot"])
        self.assertEqual(7, value["variableCount"])
        self.assertEqual(["serialno"], value["redactedKeys"])
        self.assertEqual("[REDACTED]", value["variables"]["serialno"])
        self.assertNotIn("PRIVATE-SERIAL", json.dumps(result.to_dict()))

    def test_hostile_and_empty_variable_output_fails_closed(self):
        cases = {
            "fastboot_variable_format_invalid": "(bootloader) not-a-variable line\n",
            "fastboot_variable_output_empty": "all: \nFinished. Total time: 0.001s\n",
            "fastboot_variable_duplicate": (
                "(bootloader) product: akita\n(bootloader) product: husky\n"
            ),
            "fastboot_variable_value_invalid": f"(bootloader) product: {'a' * 600}\n",
        }
        for code, stderr in cases.items():
            with self.subTest(code=code):
                with self.assertRaises(DeviceInspectionParseError) as raised:
                    parse_bounded_fastboot_variables(stderr)
                self.assertEqual(code, raised.exception.code)

    def test_cancellation_and_process_failure_stay_explicit(self):
        compilation = self.compile()

        cancelled = self.service.finalize_fastboot_variables(
            compilation,
            OperationResult.cancelled("variables", code="operation_cancelled", message="stopped"),
        )
        failed = self.service.finalize_fastboot_variables(
            compilation,
            OperationResult.failed("variables", code="process_failed", message="boom"),
        )

        self.assertIs(OperationStatus.CANCELLED, cancelled.status)
        self.assertIs(OperationStatus.FAILED, failed.status)
        self.assertIsNone(failed.value)


if __name__ == "__main__":
    unittest.main()
