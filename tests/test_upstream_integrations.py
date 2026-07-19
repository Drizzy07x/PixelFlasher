import contextlib
import io
import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from config import Config
from pf_modules import _kernelsu_lkm_supports_magiskboot
from phone import Device


class KernelSuLkmCompatibilityTests(unittest.TestCase):
    def test_new_patcher_versions_drop_removed_magiskboot_argument(self):
        cases = (
            ('SukiSU_LKM', 40796),
            ('KernelSU_LKM', 32525),
            ('KernelSU-Next_LKM', 33214),
        )

        for flavor, removed_at in cases:
            with self.subTest(flavor=flavor, version=removed_at - 1):
                self.assertTrue(_kernelsu_lkm_supports_magiskboot(flavor, removed_at - 1))
            with self.subTest(flavor=flavor, version=removed_at):
                self.assertFalse(_kernelsu_lkm_supports_magiskboot(flavor, removed_at))

    def test_unaffected_patchers_keep_magiskboot_argument(self):
        self.assertTrue(_kernelsu_lkm_supports_magiskboot('Wild_KSU_LKM', 999999))
        self.assertTrue(_kernelsu_lkm_supports_magiskboot('KernelSU-Legacy_LKM', 999999))


class LsposedSchemaCompatibilityTests(unittest.TestCase):
    def _fetch_modules(self, schema_statements):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_db = root / 'source.db'
            config_dir = root / 'config'

            with sqlite3.connect(source_db) as connection:
                for statement, values in schema_statements:
                    connection.execute(statement, values)
                connection.commit()
            connection.close()

            device = Device('ABC123', 'adb', 'adb')
            device._rooted = True
            device.check_file = lambda *_args, **_kwargs: (1, None)

            def pull_file(_device_path, local_path, **_kwargs):
                shutil.copyfile(source_db, local_path)
                return 0

            device.pull_file = pull_file
            with (
                patch('phone.get_config_path', return_value=str(config_dir)),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                return device._fetch_lsposed_modules()

    def test_legacy_modules_table_keeps_enabled_and_auto_include(self):
        modules = self._fetch_modules(
            (
                ('CREATE TABLE modules (mid INTEGER, module_pkg_name TEXT, apk_path TEXT, enabled INTEGER, auto_include INTEGER)', ()),
                ('INSERT INTO modules VALUES (?, ?, ?, ?, ?)', (7, 'legacy.module', '/legacy.apk', 0, 1)),
            )
        )

        self.assertEqual(
            modules,
            [
                {
                    'id': '7',
                    'name': 'legacy.module',
                    'package_name': 'legacy.module',
                    'apk_path': '/legacy.apk',
                    'enabled': False,
                    'auto_include': True,
                }
            ],
        )

    def test_new_modules_state_schema_is_joined_without_dropping_modules(self):
        modules = self._fetch_modules(
            (
                ('CREATE TABLE modules (id INTEGER, module_pkg_name TEXT, apk_path TEXT)', ()),
                ('CREATE TABLE modules_state (module_pkg_name TEXT, is_enabled TEXT)', ()),
                ('INSERT INTO modules VALUES (?, ?, ?)', (11, 'disabled.module', '/disabled.apk')),
                ('INSERT INTO modules VALUES (?, ?, ?)', (12, 'default.module', '/default.apk')),
                ('INSERT INTO modules_state VALUES (?, ?)', ('disabled.module', 'false')),
            )
        )

        modules_by_id = {module['id']: module for module in modules}
        self.assertEqual(set(modules_by_id), {'11', '12'})
        self.assertFalse(modules_by_id['11']['enabled'])
        self.assertTrue(modules_by_id['12']['enabled'])


class RebootTimeoutIntegrationTests(unittest.TestCase):
    def test_timeout_round_trips_through_config(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / 'config.json'
            config = Config()
            config.reboot_to_system_timeout = 180
            config.save(path)

            with contextlib.redirect_stdout(io.StringIO()):
                loaded = Config.load(path)

            self.assertEqual(loaded.reboot_to_system_timeout, 180)
            self.assertEqual(json.loads(path.read_text(encoding='ISO-8859-1'))['reboot_to_system_timeout'], 180)

    def test_invalid_timeout_falls_back_to_default(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / 'config.json'
            path.write_text(json.dumps({'reboot_to_system_timeout': -5}), encoding='ISO-8859-1')

            with contextlib.redirect_stdout(io.StringIO()):
                loaded = Config.load(path)

            self.assertEqual(loaded.reboot_to_system_timeout, 90)


class MacBuildWorkflowTests(unittest.TestCase):
    def test_mac_build_uses_stable_runner_and_safe_brew_cleanup(self):
        workflow = Path('.github/workflows/mac.yml').read_text(encoding='utf-8')

        self.assertIn('- runner: macos-15', workflow)
        self.assertIn('- runner: macos-15-intel', workflow)
        self.assertIn('runs-on: ${{ matrix.runner }}', workflow)
        self.assertIn('brew uninstall --ignore-dependencies openssl@1.1 || true', workflow)
        self.assertNotIn('brew upgrade', workflow)


if __name__ == '__main__':
    unittest.main()
