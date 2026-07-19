import hashlib
import json
import sys
import tempfile
import time
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

from pixelflasher_core.bootloader_inspection import (
    BOOTLOADER_PARTITION_LIMIT,
    BootloaderInspectionError,
    BootloaderSlotEvidence,
    BootloaderVersionScanner,
    SubprocessBootloaderPartitionRunner,
    load_bootloader_prefix_catalog,
)
from pixelflasher_core.cancellation import CancellationToken
from pixelflasher_core.contracts import ProcessRequest


def stream_request(slot: str = "a") -> ProcessRequest:
    return ProcessRequest(
        (
            "ADB",
            "-s",
            "SERIAL",
            "exec-out",
            "su",
            "0",
            "toybox",
            "cat",
            f"/dev/block/by-name/abl_{slot}",
        ),
        timeout_seconds=90,
        output_limit_bytes=BOOTLOADER_PARTITION_LIMIT,
    )


def python_stream_request(
    script: Path,
    *,
    slot: str = "a",
    timeout_seconds: float = 5.0,
) -> ProcessRequest:
    return ProcessRequest(
        (
            sys.executable,
            "-s",
            str(script),
            "exec-out",
            "su",
            "0",
            "toybox",
            "cat",
            f"/dev/block/by-name/abl_{slot}",
        ),
        timeout_seconds=timeout_seconds,
        output_limit_bytes=BOOTLOADER_PARTITION_LIMIT,
    )


class BootloaderCatalogTests(unittest.TestCase):
    def write_bytes(self, root: Path, payload: bytes) -> Path:
        path = root / "android_devices.json"
        path.write_bytes(payload)
        return path

    def assert_catalog_error(self, payload: bytes, expected_code: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_bytes(Path(directory), payload)
            with self.assertRaises(BootloaderInspectionError) as raised:
                load_bootloader_prefix_catalog(path)
        self.assertEqual(expected_code, raised.exception.code)

    def test_loads_only_validated_prefixes_and_returns_an_immutable_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_bytes(
                Path(directory),
                json.dumps(
                    {
                        "akita": {
                            "device": "Pixel 8a",
                            "bootloader_codename": "akita",
                        },
                        "bluejay": {
                            "bootloader_codename": "bluejay",
                            "has_init_boot": False,
                        },
                    }
                ).encode("utf-8"),
            )
            catalog = load_bootloader_prefix_catalog(path)

        self.assertEqual({"akita": "akita", "bluejay": "bluejay"}, catalog)
        with self.assertRaises(TypeError):
            catalog["akita"] = "forged"  # type: ignore[index]

    def test_missing_unreadable_empty_and_oversized_catalogs_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.json"
            with self.assertRaises(BootloaderInspectionError) as raised:
                load_bootloader_prefix_catalog(missing)
            self.assertEqual("bootloader_catalog_unavailable", raised.exception.code)

            self.assert_catalog_error(b"", "bootloader_catalog_invalid")
            self.assert_catalog_error(b" " * (1024 * 1024 + 1), "bootloader_catalog_invalid")

    def test_rejects_duplicate_keys_at_every_object_level(self):
        self.assert_catalog_error(
            b'{"akita":{"bootloader_codename":"akita"},'
            b'"akita":{"bootloader_codename":"other"}}',
            "bootloader_catalog_invalid",
        )
        self.assert_catalog_error(
            b'{"akita":{"bootloader_codename":"akita",'
            b'"bootloader_codename":"other"}}',
            "bootloader_catalog_invalid",
        )

    def test_rejects_invalid_encoding_json_roots_and_entry_count(self):
        for payload in (
            b"\xff",
            b"{",
            b"[]",
            b"{}",
            json.dumps(
                {
                    f"device_{index}": {"bootloader_codename": "valid"}
                    for index in range(513)
                }
            ).encode("utf-8"),
        ):
            with self.subTest(payload_size=len(payload)):
                self.assert_catalog_error(payload, "bootloader_catalog_invalid")

    def test_rejects_invalid_codenames_records_and_prefixes(self):
        invalid_catalogs: tuple[dict[str, object], ...] = (
            {"Akita": {"bootloader_codename": "akita"}},
            {"akita/path": {"bootloader_codename": "akita"}},
            {"a" * 65: {"bootloader_codename": "akita"}},
            {"akita": None},
            {"akita": []},
            {"akita": {}},
            {"akita": {"bootloader_codename": None}},
            {"akita": {"bootloader_codename": "Akita"}},
            {"akita": {"bootloader_codename": "-akita"}},
            {"akita": {"bootloader_codename": "akita/path"}},
            {"akita": {"bootloader_codename": "a" * 65}},
        )
        for catalog in invalid_catalogs:
            with self.subTest(catalog=catalog):
                self.assert_catalog_error(
                    json.dumps(catalog).encode("utf-8"),
                    "bootloader_catalog_invalid",
                )


class BootloaderVersionScannerTests(unittest.TestCase):
    def assert_scanner_error(
        self,
        scanner: BootloaderVersionScanner,
        expected_code: str,
    ) -> None:
        with self.assertRaises(BootloaderInspectionError) as raised:
            scanner.finish()
        self.assertEqual(expected_code, raised.exception.code)

    def test_finds_a_version_when_marker_value_and_nul_span_chunks(self):
        scanner = BootloaderVersionScanner("akita")
        for chunk in (b"prefix\x00aki", b"ta-15.2-12", b"345678", b"\x00suffix"):
            scanner.feed(chunk)
        self.assertEqual("15.2-12345678", scanner.finish())

    def test_accepts_the_exact_ascii_limit_and_identical_repetitions(self):
        version = "v" + "1" * 126
        scanner = BootloaderVersionScanner("akita")
        marker = f"akita-{version}\x00".encode("ascii")
        scanner.feed(marker + b"padding" + marker)
        self.assertEqual(version, scanner.finish())

    def test_rejects_conflicting_versions_even_across_chunks(self):
        scanner = BootloaderVersionScanner("akita")
        scanner.feed(b"akita-15.1\x00")
        scanner.feed(b"paddingakita-15.2\x00")
        self.assert_scanner_error(scanner, "bootloader_version_ambiguous")

    def test_distinguishes_missing_marker_from_malformed_candidate(self):
        unavailable = BootloaderVersionScanner("akita")
        unavailable.feed(b"unrelated binary data\x00")
        self.assert_scanner_error(unavailable, "bootloader_version_unavailable")

        malformed_payloads = (
            b"akita-unterminated",
            b"akita-\x00",
            b"akita-bad value\x00",
            b"akita-\xff\x00",
            b"akita-" + b"x" * 128 + b"\x00",
        )
        for payload in malformed_payloads:
            with self.subTest(payload=payload[:32]):
                malformed = BootloaderVersionScanner("akita")
                malformed.feed(payload)
                self.assert_scanner_error(malformed, "bootloader_version_invalid")

    def test_incomplete_marker_at_eof_is_not_mistaken_for_a_second_version(self):
        scanner = BootloaderVersionScanner("akita")
        scanner.feed(b"akita-valid\x00paddingakita-incomplete")
        self.assertEqual("valid", scanner.finish())

    def test_prefix_and_chunk_types_are_strict(self):
        for prefix in ("", "Akita", "-akita", "akita/path", "a" * 65):
            with self.subTest(prefix=prefix), self.assertRaises(BootloaderInspectionError) as raised:
                BootloaderVersionScanner(prefix)
            self.assertEqual("bootloader_prefix_invalid", raised.exception.code)

        scanner = BootloaderVersionScanner("akita")
        with self.assertRaises(TypeError):
            scanner.feed(bytearray(b"akita-v1\x00"))  # type: ignore[arg-type]


class BootloaderEvidenceTests(unittest.TestCase):
    def evidence(self, **overrides: object) -> BootloaderSlotEvidence:
        values: dict[str, object] = {
            "slot": "a",
            "partition": "abl_a",
            "bootloader_codename": "akita",
            "version": "15.2-12345678",
            "sha256": hashlib.sha256(b"partition").hexdigest(),
            "size_bytes": 9,
        }
        values.update(overrides)
        return BootloaderSlotEvidence(**values)  # type: ignore[arg-type]

    def test_evidence_is_frozen_and_projects_only_closed_public_fields(self):
        evidence = self.evidence()
        self.assertEqual("akita-15.2-12345678", evidence.full_version)
        self.assertEqual(
            {
                "partition": "abl_a",
                "version": "15.2-12345678",
                "fullVersion": "akita-15.2-12345678",
                "sha256": hashlib.sha256(b"partition").hexdigest(),
                "sizeBytes": 9,
            },
            evidence.to_dict(),
        )
        with self.assertRaises(FrozenInstanceError):
            evidence.version = "forged"  # type: ignore[misc]

    def test_rejects_wrong_targets_prefixes_versions_digests_and_sizes(self):
        invalid_overrides = (
            {"slot": "c", "partition": "abl_c"},
            {"slot": "a", "partition": "abl_b"},
            {"bootloader_codename": "Akita"},
            {"version": ""},
            {"version": "bad value"},
            {"version": "\N{SNOWMAN}"},
            {"version": "v" + "1" * 127},
            {"sha256": "A" * 64},
            {"sha256": "0" * 63},
            {"size_bytes": True},
            {"size_bytes": 0},
            {"size_bytes": BOOTLOADER_PARTITION_LIMIT + 1},
        )
        for overrides in invalid_overrides:
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                self.evidence(**overrides)


class BootloaderPartitionRunnerRequestTests(unittest.TestCase):
    def assert_invalid_request(self, request: ProcessRequest, *, slot: str = "a") -> None:
        token = CancellationToken()
        token.cancel()
        with self.assertRaises(BootloaderInspectionError) as raised:
            SubprocessBootloaderPartitionRunner().run(
                request,
                token,
                slot=slot,
                bootloader_codename="akita",
            )
        self.assertEqual("bootloader_stream_request_invalid", raised.exception.code)

    def test_exact_request_is_accepted_but_pre_cancelled_without_spawning(self):
        token = CancellationToken()
        token.cancel()
        outcome = SubprocessBootloaderPartitionRunner().run(
            stream_request(),
            token,
            slot="a",
            bootloader_codename="akita",
        )
        self.assertTrue(outcome.cancelled)
        self.assertFalse(outcome.timed_out)
        self.assertIsNone(outcome.returncode)
        self.assertIsNone(outcome.evidence)

        deadline = CancellationToken()
        deadline.set_deadline_at(max(0.0, time.monotonic() - 0.001))
        timed_out = SubprocessBootloaderPartitionRunner().run(
            stream_request("b"),
            deadline,
            slot="b",
            bootloader_codename="akita",
        )
        self.assertFalse(timed_out.cancelled)
        self.assertTrue(timed_out.timed_out)

    def test_rejects_any_argv_or_process_boundary_deviation(self):
        valid = stream_request()
        invalid = (
            replace(valid, argv=("ADB",)),
            replace(valid, argv=("",) + valid.argv[1:]),
            replace(valid, argv=valid.argv[:2] + ("",) + valid.argv[3:]),
            replace(valid, argv=valid.argv[:3] + ("shell",) + valid.argv[4:]),
            replace(valid, argv=valid.argv[:4] + ("su", "-c") + valid.argv[6:]),
            replace(valid, argv=valid.argv[:-1] + ("/dev/block/by-name/abl_b",)),
            replace(valid, cwd="C:\\unsafe"),
            replace(valid, env=(("INJECT", "1"),)),
            replace(valid, stdin_secret_field="secret"),
            replace(valid, timeout_seconds=90.001),
            replace(valid, timeout_seconds=None),
            replace(valid, output_limit_bytes=BOOTLOADER_PARTITION_LIMIT - 1),
            replace(valid, output_limit_bytes=None),
        )
        for request in invalid:
            with self.subTest(request=request):
                self.assert_invalid_request(request)

        self.assert_invalid_request(valid, slot="c")


class BootloaderPartitionRunnerProcessTests(unittest.TestCase):
    def run_script(
        self,
        source: str,
        *,
        timeout_seconds: float = 5.0,
    ):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "stream.py"
            script.write_text(source, encoding="utf-8")
            return SubprocessBootloaderPartitionRunner().run(
                python_stream_request(
                    script,
                    timeout_seconds=timeout_seconds,
                ),
                CancellationToken(),
                slot="a",
                bootloader_codename="akita",
            )

    def test_real_binary_process_is_streamed_to_digest_and_typed_evidence(self):
        payload = b"header\x00akita-15.2-12345678\x00tail"
        outcome = self.run_script(
            "import os\n"
            f"os.write(1, {payload!r})\n"
        )

        self.assertEqual(0, outcome.returncode)
        self.assertEqual(0, outcome.stderr_bytes)
        self.assertIsNotNone(outcome.evidence)
        assert outcome.evidence is not None
        self.assertEqual("15.2-12345678", outcome.evidence.version)
        self.assertEqual(len(payload), outcome.evidence.size_bytes)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), outcome.evidence.sha256)

    def test_real_process_timeout_terminates_without_partial_evidence(self):
        outcome = self.run_script(
            "import time\n"
            "time.sleep(30)\n",
            timeout_seconds=0.05,
        )

        self.assertTrue(outcome.timed_out)
        self.assertFalse(outcome.cancelled)
        self.assertIsNone(outcome.evidence)

    def test_real_process_detects_byte_after_partition_limit(self):
        marker = b"akita-v1\x00"
        outcome = self.run_script(
            "import os\n"
            f"os.write(1, {marker!r})\n"
            f"remaining = {BOOTLOADER_PARTITION_LIMIT + 1 - len(marker)}\n"
            "chunk = b'x' * (1024 * 1024)\n"
            "while remaining:\n"
            "    payload = chunk[:min(len(chunk), remaining)]\n"
            "    os.write(1, payload)\n"
            "    remaining -= len(payload)\n",
            timeout_seconds=15.0,
        )

        self.assertTrue(outcome.output_limited)
        self.assertEqual("bootloader_partition_limit_exceeded", outcome.error_code)
        self.assertIsNone(outcome.evidence)

    def test_real_process_never_exposes_stderr_content(self):
        outcome = self.run_script(
            "import os\n"
            "os.write(1, b'akita-v1\\x00')\n"
            "os.write(2, b'private diagnostic')\n"
        )

        self.assertEqual(len(b"private diagnostic"), outcome.stderr_bytes)
        self.assertEqual("bootloader_partition_stderr_unexpected", outcome.error_code)
        self.assertIsNone(outcome.evidence)
        self.assertNotIn("private", repr(outcome))


if __name__ == "__main__":
    unittest.main()
