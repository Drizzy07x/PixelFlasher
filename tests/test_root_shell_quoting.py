"""A root script has to reach `su` whole, not split at its first separator.

`adb shell` concatenates its remaining arguments without re-quoting them, so a
script handed over as its own argv element is parsed by the device shell before
`su` ever sees it. Only the first statement runs as root and everything after it
runs as the unprivileged shell, which for an enumeration means empty output and
a reported success.

Measured on a Pixel 9 Pro XL running KernelSU-Next, adb 37.0.0:

    adb shell su -c 'id -u; id -u'                     -> 0 then 2000
    adb shell su -c 'id -u; sha256sum -- /data/adb/ksud'
                                       -> 0 then "Permission denied", exit 1
    adb shell "su -c 'id -u; sha256sum -- /data/adb/ksud'"
                                       -> 0 then the digest, exit 0

`root.modules.list` reported {"count": 0} with code
root_modules_list_succeeded on a device carrying a valid running module.
"""

from __future__ import annotations

import shlex
import unittest

from pixelflasher_core.contracts import (
    AppCommand,
    AppSnapshot,
    DeviceInfo,
    ToolchainInfo,
    root_shell_argv,
)
from pixelflasher_core.rooting import RootingService

SNAPSHOT = AppSnapshot(
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


def command(kind: str, payload: dict) -> AppCommand:
    return AppCommand(
        kind,
        expected_revision=9,
        target_serial="SERIAL",
        payload=dict(payload),
    )


class RootShellArgvTests(unittest.TestCase):
    def test_the_script_becomes_one_argument_after_shell(self) -> None:
        argv = root_shell_argv("ADB", "SERIAL", "id -u; id -u")
        self.assertEqual(("ADB", "-s", "SERIAL", "shell"), argv[:4])
        self.assertEqual(5, len(argv), "everything after shell must be one token")

    def test_the_quoted_token_reconstructs_the_script_exactly(self) -> None:
        for script in (
            "id -u; id -u",
            "count=0; for dir in /data/adb/modules/*; do count=$((count+1)); done",
            "echo 'single' \"double\" $notavar && sha256sum -- /data/adb/ksud",
            "printf '%s\\n' \"a b\"",
        ):
            with self.subTest(script=script):
                argv = root_shell_argv("ADB", "SERIAL", script)
                parsed = shlex.split(argv[4])
                self.assertEqual(["su", "-c", script], parsed)

    def test_a_script_is_never_left_as_a_bare_element(self) -> None:
        argv = root_shell_argv("ADB", "SERIAL", "a; b")
        self.assertNotIn("-c", argv[4:][1:], "a bare -c element means adb will split the script")
        self.assertNotEqual("su", argv[4])


class CompiledRootRequestTests(unittest.TestCase):
    """The compiled plans must not hand a split script to the device shell."""

    def assert_root_script_is_whole(self, argv: tuple[str, ...]) -> None:
        if "su" not in argv:
            return
        index = argv.index("su")
        if index + 1 < len(argv) and argv[index + 1] == "0":
            # `su 0 <argv...>` passes separate elements with no shell parsing.
            return
        self.fail(f"the script is split across argv elements: {argv!r}")

    def test_module_list_sends_its_enumeration_as_one_root_script(self) -> None:
        compilation = RootingService().compile(
            command("root.modules.list", {"serial": "SERIAL"}),
            SNAPSHOT,
        )
        request = compilation.plan.requests[0]
        self.assert_root_script_is_whole(request.argv)
        self.assertEqual(5, len(request.argv))
        parsed = shlex.split(request.argv[4])
        self.assertEqual("su", parsed[0])
        self.assertEqual("-c", parsed[1])
        self.assertIn("/data/adb/modules/", parsed[2])
        self.assertIn("for dir in", parsed[2])


if __name__ == "__main__":
    unittest.main()
