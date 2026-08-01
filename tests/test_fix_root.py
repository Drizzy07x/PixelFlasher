import base64
import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from pixelflasher_core.boot_patch import (
    BootPatchPlanningError,
    BootPatchService,
    PatchToolBundle,
)
from pixelflasher_core.contracts import (
    AppCommand,
    AppSnapshot,
    BootInfo,
    DeviceInfo,
    FileArtifact,
    ModernPreferences,
    ToolchainInfo,
)
from pixelflasher_core.rooting import (
    RootAppSource,
    RootingPlanningError,
    RootingService,
    parse_root_module_list,
)
from tests.apk_test_helpers import FakeVerifiedApkInspector


def sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def write_apk(path: Path, provider: str) -> bytes:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", provider.encode())
        archive.writestr("classes.dex", b"dex")
    return path.read_bytes()


def encode(value: bytes | str) -> str:
    raw = value.encode() if isinstance(value, str) else value
    return base64.b64encode(raw).decode()


def module_record(
    module_id: str,
    *,
    name: str = "Module",
    version: str = "1.0",
    version_code: str = "1",
    author: str = "author",
    description: bytes | str = "description",
    update_json: str = "",
) -> str:
    return "|".join(
        (
            "PF_RM",
            module_id,
            "enabled",
            encode(name),
            encode(version),
            version_code,
            encode(author),
            encode(description),
            encode(update_json),
        )
    )


class BootPatchFixture:
    """Shared minimal backend fixture for boot-patch planning."""

    def make_service(self, root: Path, flavor: str, provider: str):
        apk = root / f"{flavor}.apk"
        app_hash = sha256(write_apk(apk, provider))
        rooting = RootingService(
            (
                RootAppSource(
                    str(apk),
                    provider,
                    "stable",
                    "1.0",
                    "official",
                    app_hash,
                ),
            ),
            hash_chunk_size=2,
            apk_inspector=FakeVerifiedApkInspector(),
        )
        app = rooting.root_app_inventory()[0]
        runner = root / f"{flavor}-runner"
        runner.write_bytes(f"runner:{flavor}".encode())
        runner_artifact = FileArtifact(
            str(runner.resolve()),
            sha256(runner.read_bytes()),
            f"patch-runner:{flavor}",
        )
        return rooting, app, runner_artifact

    def make_snapshot(self, boot: Path) -> AppSnapshot:
        return AppSnapshot(
            revision=5,
            devices=(DeviceInfo("SERIAL", codename="akita", mode="adb", online=True),),
            selected_serial="SERIAL",
            boot=BootInfo("stock", str(boot), sha256(boot.read_bytes()), "boot", False),
            preferences=ModernPreferences(),
            toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
        )

    def command(self, flavor: str, app_id: str, destination: Path, operation_id: str):
        return AppCommand(
            "boot.patch",
            expected_revision=5,
            target_serial="SERIAL",
            payload={
                "flavor": flavor,
                "appId": app_id,
                "destination": str(destination),
            },
            operation_id=operation_id,
        )

    @staticmethod
    def staged(compilation, prefix: str) -> str:
        for request in compilation.plan.requests:
            for argument in request.argv:
                if argument.startswith(f"/data/local/tmp/{prefix}"):
                    return argument
        raise AssertionError(f"no staged {prefix} path in plan")


class BootPatchStagingTests(BootPatchFixture, unittest.TestCase):
    """BUG-26: a failed patch must not leave one more stock image per retry."""

    def test_retry_reuses_the_pushed_stock_image_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            boot = root / "boot.img"
            boot.write_bytes(b"stock boot image")
            rooting, app, runner_artifact = self.make_service(root, "magisk", "Magisk")
            service = BootPatchService(
                rooting,
                (PatchToolBundle("magisk", app.id, runner_artifact),),
                hash_chunk_size=2,
            )
            snapshot = self.make_snapshot(boot)

            first = service.compile(
                self.command("magisk", app.id, root / "patched.img", "patch-attempt-1"),
                snapshot,
            )
            second = service.compile(
                self.command("magisk", app.id, root / "patched.img", "patch-attempt-2"),
                snapshot,
            )

            # The failed attempt's stock image is overwritten by the retry
            # instead of accumulating in /data/local/tmp.
            self.assertEqual(
                self.staged(first, "pf-stock-"),
                self.staged(second, "pf-stock-"),
            )
            # The patched output stays operation scoped so a stale image from
            # an earlier attempt can never be pulled by this one.
            self.assertNotEqual(
                self.staged(first, "pf-patched-"),
                self.staged(second, "pf-patched-"),
            )
            self.assertIn(
                self.staged(first, "pf-stock-"),
                first.plan.requests[-1].argv,
            )

    def test_a_different_stock_image_still_gets_its_own_staging_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            boot = root / "boot.img"
            boot.write_bytes(b"stock boot image")
            other = root / "other.img"
            other.write_bytes(b"another stock boot image")
            rooting, app, runner_artifact = self.make_service(root, "magisk", "Magisk")
            service = BootPatchService(
                rooting,
                (PatchToolBundle("magisk", app.id, runner_artifact),),
                hash_chunk_size=2,
            )

            first = service.compile(
                self.command("magisk", app.id, root / "patched.img", "patch-attempt-1"),
                self.make_snapshot(boot),
            )
            second = service.compile(
                self.command("magisk", app.id, root / "patched.img", "patch-attempt-1"),
                self.make_snapshot(other),
            )

            self.assertNotEqual(
                self.staged(first, "pf-stock-"),
                self.staged(second, "pf-stock-"),
            )


class LegacyProviderPairingTests(BootPatchFixture, unittest.TestCase):
    """BUG-44: the catalog's "legacy" provider must reach the legacy flavor."""

    def test_catalog_legacy_provider_is_accepted_by_the_legacy_flavor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            boot = root / "boot.img"
            boot.write_bytes(b"stock boot image")
            rooting, app, runner_artifact = self.make_service(root, "legacy", "legacy")
            service = BootPatchService(
                rooting,
                (PatchToolBundle("legacy", app.id, runner_artifact),),
                hash_chunk_size=2,
            )

            compilation = service.compile(
                self.command("legacy", app.id, root / "patched.img", "patch-operation"),
                self.make_snapshot(boot),
            )

            self.assertEqual("legacy", compilation.flavor)

    def test_legacy_without_a_bundle_fails_closed_on_the_runner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            boot = root / "boot.img"
            boot.write_bytes(b"stock boot image")
            rooting, app, _runner = self.make_service(root, "legacy", "legacy")
            service = BootPatchService(rooting, (), hash_chunk_size=2)

            with self.assertRaises(BootPatchPlanningError) as raised:
                service.compile(
                    self.command("legacy", app.id, root / "patched.img", "patch-operation"),
                    self.make_snapshot(boot),
                )

            self.assertEqual("patch_runner_unavailable", raised.exception.code)

    def test_legacy_manager_is_never_paired_with_the_official_kernelsu_runner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            boot = root / "boot.img"
            boot.write_bytes(b"stock boot image")
            rooting, app, runner_artifact = self.make_service(root, "legacy", "legacy")
            service = BootPatchService(
                rooting,
                (PatchToolBundle("kernelsu", app.id, runner_artifact),),
                hash_chunk_size=2,
            )

            with self.assertRaises(BootPatchPlanningError) as raised:
                service.compile(
                    self.command("kernelsu", app.id, root / "patched.img", "patch-operation"),
                    self.make_snapshot(boot),
                )

            self.assertEqual("patch_app_provider_mismatch", raised.exception.code)


class ModuleListBoundsTests(unittest.TestCase):
    """BUG-34: one over-long property must not hide every installed module."""

    def test_over_long_description_is_clamped_and_keeps_the_other_modules(self):
        listing = "\n".join(
            (
                module_record("noisy", description="x" * 1500),
                module_record("quiet", name="Quiet", description="short"),
            )
        )

        modules = parse_root_module_list(listing)

        self.assertEqual(("noisy", "quiet"), tuple(item.id for item in modules))
        self.assertEqual("x" * 1024, modules[0].description)
        self.assertEqual("short", modules[1].description)

    def test_over_long_name_version_and_author_are_clamped(self):
        listing = module_record(
            "wordy",
            name="n" * 400,
            version="v" * 200,
            author="a" * 400,
        )

        modules = parse_root_module_list(listing)

        self.assertEqual("n" * 256, modules[0].name)
        self.assertEqual("v" * 128, modules[0].version)
        self.assertEqual("a" * 256, modules[0].author)

    def test_property_truncated_mid_utf8_character_still_parses(self):
        # ``head -c`` cuts on a byte boundary, so the last character can arrive
        # as an incomplete UTF-8 sequence.
        truncated = "café au lait ☕".encode()[:-2]
        listing = module_record("split", description=truncated)

        modules = parse_root_module_list(listing)

        self.assertEqual("café au lait", modules[0].description)

    def test_invalid_utf8_that_is_not_a_truncated_tail_still_fails(self):
        listing = module_record("broken", description=b"bad \xff byte here")

        with self.assertRaises(RootingPlanningError) as raised:
            parse_root_module_list(listing)

        self.assertEqual("root_module_list_malformed", raised.exception.code)

    def test_control_characters_and_record_forgery_are_still_rejected(self):
        for description in ("line\nbreak", "PF_RM|forged|enabled\x00"):
            with self.subTest(description=description):
                with self.assertRaises(RootingPlanningError) as raised:
                    parse_root_module_list(module_record("evil", description=description))
                self.assertEqual("root_module_list_malformed", raised.exception.code)

    def test_update_json_bounds_and_scheme_are_still_enforced(self):
        cases = (
            module_record("longurl", update_json="https://example.test/" + "a" * 2100),
            module_record("insecure", update_json="http://example.test/update.json"),
        )
        for listing in cases:
            with self.subTest(listing=listing[:32]):
                with self.assertRaises(RootingPlanningError) as raised:
                    parse_root_module_list(listing)
                self.assertEqual("root_module_list_malformed", raised.exception.code)

    def test_collector_truncates_to_the_parser_bounds(self):
        service = RootingService()
        snapshot = AppSnapshot(
            revision=3,
            devices=(
                DeviceInfo(
                    "SERIAL",
                    codename="akita",
                    mode="adb",
                    online=True,
                    root=True,
                ),
            ),
            selected_serial="SERIAL",
            toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
        )
        command = AppCommand(
            "root.modules.list",
            expected_revision=3,
            target_serial="SERIAL",
            payload={"serial": "SERIAL"},
            operation_id="modules-list",
        )

        compilation = service.compile(command, snapshot)
        script = compilation.plan.requests[0].argv[-1]

        for key, limit in (
            ("name", 256),
            ("version", 128),
            ("author", 256),
            ("description", 1024),
            ("updateJson", 2048),
        ):
            with self.subTest(key=key):
                self.assertIn(f"encode_prop {key} {limit})", script)


if __name__ == "__main__":
    unittest.main()
