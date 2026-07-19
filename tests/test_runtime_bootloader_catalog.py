from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pixelflasher_core.bootloader_inspection import BootloaderInspectionError
from pixelflasher_core.executor import FakeProcessTransport
from pixelflasher_core.runtime import ApplicationRuntime

ROOT = Path(__file__).resolve().parents[1]
DESKTOP_SPECS = (
    ROOT / "build-on-win.spec",
    ROOT / "build-on-win-arm64.spec",
    ROOT / "build-on-linux.spec",
    ROOT / "build-on-mac.spec",
    ROOT / "build-on-mac-intel-only.spec",
)


def versioned_config(path: Path) -> None:
    path.write_text(
        json.dumps({"_pixelflasher_core_schema": 1}),
        encoding="utf-8",
    )


class RuntimeBootloaderCatalogTests(unittest.TestCase):
    def test_runtime_injects_the_strict_catalog_and_shared_process_transport(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            catalog = root / "android_devices.json"
            versioned_config(config)
            catalog.write_text(
                json.dumps({"akita": {"bootloader_codename": "akita"}}),
                encoding="utf-8",
            )
            transport = FakeProcessTransport()

            runtime = ApplicationRuntime.open(
                config,
                transport=transport,
                android_device_catalog_path=catalog,
            )
            try:
                service = runtime.command_engine.device_tools_service
                self.assertEqual({"akita": "akita"}, dict(service.bootloader_prefixes))
                self.assertIs(transport, service.bootloader_process_transport)
                with self.assertRaises(TypeError):
                    service.bootloader_prefixes["other"] = "other"  # type: ignore[index]
            finally:
                runtime.shutdown()

    def test_missing_injected_catalog_fails_before_runtime_composition(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            versioned_config(config)

            with self.assertRaises(BootloaderInspectionError) as raised:
                ApplicationRuntime.open(
                    config,
                    android_device_catalog_path=root / "missing.json",
                )

            self.assertEqual("bootloader_catalog_unavailable", raised.exception.code)

    def test_default_source_path_and_every_desktop_bundle_include_the_catalog(self) -> None:
        expected = (ROOT / "android_devices.json").resolve()

        self.assertEqual(
            expected,
            ApplicationRuntime._packaged_android_device_catalog_path(),
        )
        self.assertTrue(expected.is_file())
        for spec in DESKTOP_SPECS:
            with self.subTest(spec=spec.name):
                source = spec.read_text(encoding="utf-8")
                self.assertIn("('android_devices.json', '.')", source)


if __name__ == "__main__":
    unittest.main()
