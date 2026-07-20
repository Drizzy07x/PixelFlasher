import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from pty_smoke_contract import (
    PTY_SMOKE_MAXIMUM_OUTPUT_BYTES,
    PtySmokeError,
    create_pty_smoke_receipt,
    execute_pty_probe,
    load_pty_smoke_receipt,
    validate_pty_smoke_receipt,
    write_pty_smoke_receipt,
)
from scripts.verify_pty_smoke import main as verify_main


class FakeProcess:
    def __init__(self) -> None:
        self.terminated = False

    def write(self, _data: bytes) -> None:
        pass

    def resize(self, *, columns: int, rows: int) -> None:
        del columns, rows

    def terminate(self) -> None:
        self.terminated = True


class FakeBackend:
    def __init__(self, *, output: bytes = b"identity\r\n", exit_code: int | None = 0) -> None:
        self.output = output
        self.exit_code = exit_code
        self.process = FakeProcess()
        self.calls = []

    def start(self, argv, *, columns, rows, on_output, on_exit):
        self.calls.append((argv, columns, rows))
        if self.output:
            on_output(self.output)
        on_exit(self.exit_code)
        return self.process


class HangingBackend(FakeBackend):
    def start(self, argv, *, columns, rows, on_output, on_exit):
        del on_output, on_exit
        self.calls.append((argv, columns, rows))
        return self.process


class HangingStartBackend(FakeBackend):
    def __init__(self) -> None:
        super().__init__()
        self.release = threading.Event()

    def start(self, argv, *, columns, rows, on_output, on_exit):
        del argv, columns, rows, on_output, on_exit
        self.release.wait()
        return self.process


class CleanupFailureProcess(FakeProcess):
    def terminate(self) -> None:
        raise OSError("cleanup failed")


class CleanupFailureBackend(FakeBackend):
    def __init__(self) -> None:
        super().__init__()
        self.process = CleanupFailureProcess()


class PtySmokeContractTests(unittest.TestCase):
    def test_probe_executes_one_fixed_argv_and_requires_output_and_zero_exit(self):
        backend = FakeBackend()

        output, exit_code = execute_pty_probe(
            backend,
            (sys.executable,),
            timeout_seconds=1,
        )

        self.assertEqual(b"identity\r\n", output)
        self.assertEqual(0, exit_code)
        self.assertEqual([((sys.executable,), 80, 24)], backend.calls)
        self.assertTrue(backend.process.terminated)

        for failing in (
            FakeBackend(output=b""),
            FakeBackend(exit_code=7),
            FakeBackend(output=b"x" * (PTY_SMOKE_MAXIMUM_OUTPUT_BYTES + 1)),
        ):
            with self.subTest(output=len(failing.output), exit_code=failing.exit_code), self.assertRaises(PtySmokeError):
                execute_pty_probe(failing, (sys.executable,), timeout_seconds=1)

    def test_probe_timeout_terminates_the_process(self):
        backend = HangingBackend()

        with self.assertRaisesRegex(PtySmokeError, "timed out"):
            execute_pty_probe(backend, (sys.executable,), timeout_seconds=1)

        self.assertTrue(backend.process.terminated)

    def test_probe_start_is_also_bounded(self):
        backend = HangingStartBackend()

        with self.assertRaisesRegex(PtySmokeError, "start timed out"):
            execute_pty_probe(backend, (sys.executable,), timeout_seconds=1)

        backend.release.set()

    def test_probe_cannot_claim_success_when_cleanup_fails(self):
        with self.assertRaisesRegex(PtySmokeError, "cleanup failed"):
            execute_pty_probe(CleanupFailureBackend(), (sys.executable,), timeout_seconds=1)

    def test_receipt_is_closed_platform_bound_and_atomic(self):
        backend = "conpty" if sys.platform.startswith("win") else "posix-pty"
        executable = "whoami.exe" if sys.platform.startswith("win") else "id"
        receipt = create_pty_smoke_receipt(
            backend=backend,
            probe_executable=executable,
            output=b"identity\r\n",
            exit_code=0,
        )

        validated = validate_pty_smoke_receipt(receipt)
        self.assertEqual(backend, validated["backend"])
        self.assertNotIn("identity", json.dumps(validated))

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pty.json"
            write_pty_smoke_receipt(path, receipt)
            self.assertEqual(receipt, load_pty_smoke_receipt(path))
            leftovers = list(path.parent.glob(f".{path.name}.*.tmp"))
            self.assertEqual([], leftovers)

    def test_verifier_rejects_unknown_fields_platform_mismatch_and_bad_digest(self):
        backend = "conpty" if sys.platform.startswith("win") else "posix-pty"
        executable = "whoami.exe" if sys.platform.startswith("win") else "id"
        receipt = create_pty_smoke_receipt(
            backend=backend,
            probe_executable=executable,
            output=b"identity\n",
            exit_code=0,
        )
        hostile = dict(receipt, path="C:/secret")
        with self.assertRaisesRegex(PtySmokeError, "closed schema"):
            validate_pty_smoke_receipt(hostile)
        bad_digest = dict(receipt, outputSha256="g" * 64)
        with self.assertRaisesRegex(PtySmokeError, "output evidence"):
            validate_pty_smoke_receipt(bad_digest)
        with self.assertRaisesRegex(PtySmokeError, "expected platform"):
            validate_pty_smoke_receipt(
                receipt,
                expected_platform="linux" if sys.platform.startswith("win") else "windows",
            )

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pty.json"
            path.write_text(json.dumps(receipt), encoding="utf-8")
            wrong_platform = "linux" if sys.platform.startswith("win") else "windows"
            with patch("sys.stderr"):
                self.assertEqual(
                    1,
                    verify_main(
                        [
                            "--report",
                            str(path),
                            "--expect-platform",
                            wrong_platform,
                            "--expect-architecture",
                            str(receipt["architecture"]),
                        ]
                    ),
                )


if __name__ == "__main__":
    unittest.main()
