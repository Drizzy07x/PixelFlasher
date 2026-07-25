from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_binary_architecture.py"


def pe_binary(machine: int) -> bytes:
    content = bytearray(256)
    content[:2] = b"MZ"
    content[60:64] = (128).to_bytes(4, "little")
    content[128:132] = b"PE\x00\x00"
    content[132:134] = machine.to_bytes(2, "little")
    return bytes(content)


class VerifyBinaryArchitectureTests(unittest.TestCase):
    def run_verifier(self, binary: Path, architecture: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            (
                sys.executable,
                str(SCRIPT),
                "--binary",
                str(binary),
                "--platform",
                "windows",
                "--architecture",
                architecture,
            ),
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_accepts_matching_arm64_pe_header(self):
        with tempfile.TemporaryDirectory(prefix="pf-pe-arch-") as directory:
            binary = Path(directory) / "PixelFlasher-arm64.exe"
            binary.write_bytes(pe_binary(0xAA64))

            result = self.run_verifier(binary, "arm64")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("Verified windows/arm64 binary", result.stdout)

    def test_rejects_a_different_or_invalid_machine(self):
        with tempfile.TemporaryDirectory(prefix="pf-pe-arch-") as directory:
            x64 = Path(directory) / "x64.exe"
            invalid = Path(directory) / "invalid.exe"
            x64.write_bytes(pe_binary(0x8664))
            invalid.write_bytes(b"not-a-pe")

            mismatch = self.run_verifier(x64, "arm64")
            malformed = self.run_verifier(invalid, "arm64")

        self.assertNotEqual(0, mismatch.returncode)
        self.assertIn("found x86_64", mismatch.stderr)
        self.assertNotEqual(0, malformed.returncode)
        self.assertIn("found unrecognized", malformed.stderr)


if __name__ == "__main__":
    unittest.main()
