from __future__ import annotations

import sys
import time
import unittest

from pixelflasher_core.contracts import (
    AppCommand,
    OperationPlan,
    OperationStatus,
    ProcessRequest,
    ProgressEvent,
)
from pixelflasher_core.executor import (
    CancellationToken,
    CommandExecutor,
    FakeProcessTransport,
    FakeTransportStep,
    SubprocessTransport,
    TransportOutcome,
)


class OtaSideloadProgressTests(unittest.TestCase):
    def test_streamed_adb_percentages_are_fragment_safe_monotonic_and_redacted(self) -> None:
        events: list[ProgressEvent] = []
        transport = FakeProcessTransport(
            [
                FakeTransportStep(
                    TransportOutcome(
                        0,
                        stderr="serving: 'C:/private/ota.zip' (~100%)\n",
                    ),
                    output_chunks=(
                        ("stderr", "serving: 'C:/private/ota.zip' (~4"),
                        ("stderr", "7%)\r"),
                        ("stderr", "noise 12%\rserving: 'C:/private/(~99%).zip' (~80%)\r"),
                        ("stderr", "serving: 'C:/private/ota.zip' (~101%)\rserving: 'C:/private/ota.zip' (~100%)\n"),
                    ),
                ),
                TransportOutcome(0),
            ]
        )
        plan = OperationPlan(
            requests=(
                ProcessRequest(("ADB", "-s", "SERIAL-A", "sideload", "C:/private/ota.zip")),
                ProcessRequest(("ADB", "-s", "SERIAL-A", "reboot")),
            )
        )
        result = CommandExecutor(transport, events.append).execute(
            AppCommand("flash.execute", operation_id="ota-progress"),
            plan,
        )

        self.assertIs(OperationStatus.SUCCESS, result.status)
        percentages = [event.percent for event in events if event.percent is not None]
        self.assertEqual(sorted(percentages), percentages)
        self.assertEqual([0, 10, 47, 74, 90, 90, 100], percentages)
        transfer_messages = [
            event.message for event in events if event.message.startswith("OTA sideload transfer:")
        ]
        self.assertEqual(
            [
                "OTA sideload transfer: 47%",
                "OTA sideload transfer: 80%",
                "OTA sideload transfer: 100%",
            ],
            transfer_messages,
        )
        self.assertNotIn("private", "\n".join(transfer_messages).casefold())
        self.assertNotIn("ota.zip", "\n".join(transfer_messages).casefold())

    def test_percentage_output_is_ignored_for_non_sideload_commands(self) -> None:
        events: list[ProgressEvent] = []
        transport = FakeProcessTransport([TransportOutcome(0, stderr="upload 99%")])
        result = CommandExecutor(transport, events.append).execute(
            AppCommand("device.inspect", operation_id="not-ota"),
            OperationPlan(
                requests=(
                    ProcessRequest(("ADB", "-s", "SERIAL-A", "shell", "getprop")),
                )
            ),
        )

        self.assertIs(OperationStatus.SUCCESS, result.status)
        self.assertFalse(
            any(event.message.startswith("OTA sideload transfer:") for event in events)
        )

    def test_subprocess_streaming_delivers_output_before_process_completion(self) -> None:
        token = CancellationToken()
        observed: list[tuple[str, str]] = []
        request = ProcessRequest(
            (
                sys.executable,
                "-c",
                (
                    "import sys,time; "
                    "sys.stderr.write('serving (~37%)\\n'); "
                    "sys.stderr.flush(); time.sleep(5)"
                ),
            ),
            timeout_seconds=10,
        )

        started = time.monotonic()

        def observe(stream_name: str, value: str) -> None:
            observed.append((stream_name, value))
            token.cancel()

        outcome = SubprocessTransport().run_streaming(request, token, observe)

        self.assertTrue(outcome.cancelled)
        self.assertFalse(outcome.timed_out)
        self.assertLess(time.monotonic() - started, 3)
        self.assertTrue(any(stream == "stderr" and "37%" in value for stream, value in observed))


if __name__ == "__main__":
    unittest.main()
