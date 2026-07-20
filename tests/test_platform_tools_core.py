from __future__ import annotations

import hashlib
import stat
import tempfile
import unittest
import zipfile
from dataclasses import dataclass
from pathlib import Path

from pixelflasher_core.platform_tools import (
    PlatformToolsInstallation,
    PlatformToolsInstaller,
    PlatformToolsStatus,
    probe_platform_tools,
)


@dataclass
class _Completed:
    returncode: int
    stdout: str
    stderr: str = ""


def _successful_probe(argv: tuple[str, ...], timeout: float) -> _Completed:
    del timeout
    if argv[-1] == "version":
        return _Completed(0, "Android Debug Bridge version 1.0.41\nVersion 36.0.0")
    return _Completed(0, "fastboot version 36.0.0")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _pe_binary(machine: int, marker: bytes) -> bytes:
    content = bytearray(128)
    content[:2] = b"MZ"
    content[60:64] = (64).to_bytes(4, "little")
    content[64:68] = b"PE\x00\x00"
    content[68:70] = machine.to_bytes(2, "little")
    content[80 : 80 + len(marker)] = marker
    return bytes(content)


def _elf_binary(machine: int) -> bytes:
    content = bytearray(64)
    content[:4] = b"\x7fELF"
    content[4] = 2
    content[5] = 1
    content[18:20] = machine.to_bytes(2, "little")
    return bytes(content)


def _universal_macho_binary(*cpu_types: int) -> bytes:
    content = bytearray(8 + len(cpu_types) * 20)
    content[:4] = b"\xca\xfe\xba\xbe"
    content[4:8] = len(cpu_types).to_bytes(4, "big")
    for index, cpu_type in enumerate(cpu_types):
        offset = 8 + index * 20
        content[offset : offset + 4] = cpu_type.to_bytes(4, "big")
    return bytes(content)


def _write_posix_tools_archive(path: Path, binary: bytes) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("platform-tools/", b"")
        archive.writestr("platform-tools/adb", binary)
        archive.writestr("platform-tools/fastboot", binary)


def _write_tools_archive(
    path: Path,
    *,
    machine: int = 0x8664,
    extra: tuple[tuple[str, bytes], ...] = (),
) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("platform-tools/", b"")
        archive.writestr("platform-tools/adb.exe", _pe_binary(machine, b"adb-binary"))
        archive.writestr("platform-tools/fastboot.exe", _pe_binary(machine, b"fastboot-binary"))
        for name, content in extra:
            archive.writestr(name, content)


class PlatformToolsInstallerTests(unittest.TestCase):
    def test_verified_archive_replaces_install_atomically_and_hides_paths_publicly(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-core-tools-") as temporary:
            root = Path(temporary)
            archive = root / "platform-tools.zip"
            install_root = root / "install"
            old = install_root / "platform-tools"
            old.mkdir(parents=True)
            (old / "adb.exe").write_bytes(b"old-adb")
            (old / "fastboot.exe").write_bytes(b"old-fastboot")
            _write_tools_archive(archive)

            result = PlatformToolsInstaller(probe_runner=_successful_probe).install_archive(
                archive,
                install_root=install_root,
                expected_sha256=_sha256(archive),
                expected_size=archive.stat().st_size,
                platform="windows",
                expected_arch="x86_64",
            )

            self.assertEqual(PlatformToolsStatus.SUCCESS, result.status)
            self.assertIsNotNone(result.installation)
            assert result.installation is not None
            self.assertEqual(
                _pe_binary(0x8664, b"adb-binary"),
                result.installation.adb_path.read_bytes(),
            )
            self.assertEqual(
                _pe_binary(0x8664, b"fastboot-binary"),
                result.installation.fastboot_path.read_bytes(),
            )
            self.assertFalse(any(install_root.glob(".platform-tools-*")))
            public = result.installation.to_public_dict()
            self.assertNotIn("root", public)
            self.assertNotIn("path", " ".join(public).casefold())

    def test_hash_mismatch_never_mutates_existing_install(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-core-tools-hash-") as temporary:
            root = Path(temporary)
            archive = root / "platform-tools.zip"
            install_root = root / "install"
            existing = install_root / "platform-tools"
            existing.mkdir(parents=True)
            marker = existing / "keep.txt"
            marker.write_text("unchanged", encoding="utf-8")
            _write_tools_archive(archive)

            result = PlatformToolsInstaller(probe_runner=_successful_probe).install_archive(
                archive,
                install_root=install_root,
                expected_sha256="0" * 64,
                platform="windows",
            )

            self.assertEqual(PlatformToolsStatus.FAILED, result.status)
            self.assertEqual("archive_hash_mismatch", result.code)
            self.assertEqual("unchanged", marker.read_text(encoding="utf-8"))

    def test_traversal_duplicates_and_symlinks_fail_closed(self) -> None:
        cases: list[tuple[str, object]] = []
        with tempfile.TemporaryDirectory(prefix="pf-core-tools-unsafe-") as temporary:
            root = Path(temporary)
            traversal = root / "traversal.zip"
            _write_tools_archive(traversal, extra=(("platform-tools/../outside", b"bad"),))
            cases.append(("archive_path_invalid", traversal))

            duplicate = root / "duplicate.zip"
            _write_tools_archive(duplicate, extra=(("platform-tools/ADB.EXE", b"spoof"),))
            cases.append(("archive_duplicate_entry", duplicate))

            symlink = root / "symlink.zip"
            with zipfile.ZipFile(symlink, "w") as archive:
                archive.writestr("platform-tools/adb.exe", b"adb")
                archive.writestr("platform-tools/fastboot.exe", b"fastboot")
                link = zipfile.ZipInfo("platform-tools/link")
                link.create_system = 3
                link.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(link, b"adb.exe")
            cases.append(("archive_special_file_forbidden", symlink))

            for expected_code, candidate in cases:
                with self.subTest(expected_code=expected_code):
                    assert isinstance(candidate, Path)
                    result = PlatformToolsInstaller(probe_runner=_successful_probe).install_archive(
                        candidate,
                        install_root=root / f"install-{expected_code}",
                        expected_sha256=_sha256(candidate),
                        platform="windows",
                    )
                    self.assertEqual(PlatformToolsStatus.FAILED, result.status)
                    self.assertEqual(expected_code, result.code)

    def test_cancellation_during_extraction_preserves_existing_install(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-core-tools-cancel-") as temporary:
            root = Path(temporary)
            archive = root / "platform-tools.zip"
            install_root = root / "install"
            existing = install_root / "platform-tools"
            existing.mkdir(parents=True)
            marker = existing / "keep.txt"
            marker.write_text("old", encoding="utf-8")
            _write_tools_archive(archive)
            calls = 0

            def cancelled() -> bool:
                nonlocal calls
                calls += 1
                return calls >= 2

            result = PlatformToolsInstaller(probe_runner=_successful_probe).install_archive(
                archive,
                install_root=install_root,
                expected_sha256=_sha256(archive),
                platform="windows",
                cancelled=cancelled,
            )

            self.assertEqual(PlatformToolsStatus.CANCELLED, result.status)
            self.assertEqual("cancelled_before_mutation", result.code)
            self.assertEqual("old", marker.read_text(encoding="utf-8"))
            self.assertFalse(any(install_root.glob(".platform-tools-*.staging")))

    def test_binary_architecture_mismatch_fails_before_activation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-core-tools-arch-") as temporary:
            root = Path(temporary)
            archive = root / "platform-tools.zip"
            install_root = root / "install"
            existing = install_root / "platform-tools"
            existing.mkdir(parents=True)
            marker = existing / "keep.txt"
            marker.write_text("old", encoding="utf-8")
            _write_tools_archive(archive, machine=0xAA64)

            result = PlatformToolsInstaller(probe_runner=_successful_probe).install_archive(
                archive,
                install_root=install_root,
                expected_sha256=_sha256(archive),
                platform="windows",
                expected_arch="x86_64",
            )

            self.assertEqual(PlatformToolsStatus.FAILED, result.status)
            self.assertEqual("toolchain_arch_mismatch", result.code)
            self.assertEqual("old", marker.read_text(encoding="utf-8"))

    def test_official_windows_x86_binaries_are_compatible_with_x64_and_arm64_hosts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-core-tools-windows-compat-") as temporary:
            root = Path(temporary)
            archive = root / "platform-tools.zip"
            _write_tools_archive(archive, machine=0x014C)

            for architecture in ("x86", "x86_64", "arm64"):
                with self.subTest(architecture=architecture):
                    result = PlatformToolsInstaller(
                        probe_runner=_successful_probe
                    ).install_archive(
                        archive,
                        install_root=root / f"install-{architecture}",
                        expected_sha256=_sha256(archive),
                        platform="windows",
                        expected_arch=architecture,
                    )

                    self.assertEqual(PlatformToolsStatus.SUCCESS, result.status)

    def test_windows_compatibility_does_not_admit_unrelated_binary_architectures(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-core-tools-windows-reject-") as temporary:
            root = Path(temporary)
            archive = root / "platform-tools.zip"
            _write_tools_archive(archive, machine=0x01C4)

            result = PlatformToolsInstaller(probe_runner=_successful_probe).install_archive(
                archive,
                install_root=root / "install",
                expected_sha256=_sha256(archive),
                platform="windows",
                expected_arch="arm64",
            )

            self.assertEqual(PlatformToolsStatus.FAILED, result.status)
            self.assertEqual("toolchain_arch_mismatch", result.code)

    def test_linux_and_universal_macos_headers_are_validated_without_execution(self) -> None:
        cases = (
            ("linux", "arm64", _elf_binary(183)),
            ("darwin", "x86_64", _universal_macho_binary(0x01000007, 0x0100000C)),
            ("darwin", "arm64", _universal_macho_binary(0x01000007, 0x0100000C)),
        )
        with tempfile.TemporaryDirectory(prefix="pf-core-tools-formats-") as temporary:
            root = Path(temporary)
            for index, (platform, architecture, binary) in enumerate(cases):
                with self.subTest(platform=platform, architecture=architecture):
                    archive = root / f"platform-tools-{index}.zip"
                    _write_posix_tools_archive(archive, binary)
                    result = PlatformToolsInstaller(
                        probe_runner=_successful_probe
                    ).install_archive(
                        archive,
                        install_root=root / f"install-{index}",
                        expected_sha256=_sha256(archive),
                        platform=platform,
                        expected_arch=architecture,
                    )

                    self.assertEqual(PlatformToolsStatus.SUCCESS, result.status)

    def test_failed_post_activation_probe_rolls_back_previous_install(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-core-tools-rollback-") as temporary:
            root = Path(temporary)
            archive = root / "platform-tools.zip"
            install_root = root / "install"
            existing = install_root / "platform-tools"
            existing.mkdir(parents=True)
            (existing / "adb.exe").write_bytes(b"old-adb")
            (existing / "fastboot.exe").write_bytes(b"old-fastboot")
            _write_tools_archive(archive)
            calls: list[tuple[str, ...]] = []

            def fail_after_activation(argv: tuple[str, ...], timeout: float) -> _Completed:
                del timeout
                calls.append(argv)
                if len(calls) == 3:
                    return _Completed(1, "", "failed")
                return _successful_probe(argv, 10.0)

            result = PlatformToolsInstaller(probe_runner=fail_after_activation).install_archive(
                archive,
                install_root=install_root,
                expected_sha256=_sha256(archive),
                platform="windows",
                expected_arch="x86_64",
            )

            self.assertEqual(PlatformToolsStatus.FAILED, result.status)
            self.assertEqual("adb_probe_failed", result.code)
            self.assertEqual(b"old-adb", (existing / "adb.exe").read_bytes())
            self.assertEqual(b"old-fastboot", (existing / "fastboot.exe").read_bytes())
            self.assertIn(str(existing / "adb.exe"), calls[2])
            self.assertFalse(any(install_root.glob(".platform-tools-*")))


class PlatformToolsProbeTests(unittest.TestCase):
    def test_probe_uses_typed_argv_and_requires_semantic_evidence(self) -> None:
        installation = PlatformToolsInstallation(
            root=Path("tools"),
            adb_path=Path("tools/adb"),
            fastboot_path=Path("tools/fastboot"),
            archive_sha256="a" * 64,
            archive_size=123,
        )
        calls: list[tuple[tuple[str, ...], float]] = []

        def runner(argv: tuple[str, ...], timeout: float) -> _Completed:
            calls.append((argv, timeout))
            if argv[-1] == "version":
                return _Completed(
                    0,
                    "Android Debug Bridge version 1.0.41\nVersion 36.0.0",
                )
            return _Completed(0, "fastboot version 36.0.0")

        result = probe_platform_tools(installation, runner=runner)

        self.assertEqual(PlatformToolsStatus.SUCCESS, result.status)
        self.assertEqual(
            [(('tools\\adb' if '\\' in str(installation.adb_path) else 'tools/adb', "version"), 10.0),
             (('tools\\fastboot' if '\\' in str(installation.fastboot_path) else 'tools/fastboot', "--version"), 10.0)],
            calls,
        )

    def test_exit_zero_without_version_evidence_is_failed(self) -> None:
        installation = PlatformToolsInstallation(
            root=Path("tools"),
            adb_path=Path("tools/adb"),
            fastboot_path=Path("tools/fastboot"),
            archive_sha256="a" * 64,
            archive_size=123,
        )

        result = probe_platform_tools(
            installation,
            runner=lambda _argv, _timeout: _Completed(0, "unexpected output"),
        )

        self.assertEqual(PlatformToolsStatus.FAILED, result.status)
        self.assertEqual("adb_version_unverified", result.code)

    def test_mixed_adb_and_fastboot_releases_are_rejected(self) -> None:
        installation = PlatformToolsInstallation(
            root=Path("tools"),
            adb_path=Path("tools/adb"),
            fastboot_path=Path("tools/fastboot"),
            archive_sha256="a" * 64,
            archive_size=123,
        )

        def runner(argv: tuple[str, ...], _timeout: float) -> _Completed:
            if argv[-1] == "version":
                return _Completed(
                    0,
                    "Android Debug Bridge version 1.0.41\nVersion 36.0.0",
                )
            return _Completed(0, "fastboot version 35.0.2")

        result = probe_platform_tools(installation, runner=runner)

        self.assertEqual(PlatformToolsStatus.FAILED, result.status)
        self.assertEqual("tool_version_mismatch", result.code)


if __name__ == "__main__":
    unittest.main()
