# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

sys.path.insert(0, str(Path(SPECPATH)))
from build_artifact_policy import RETIRED_UI_MODULES

block_cipher = None

hidden_imports = ['_cffi_backend']
hidden_imports += collect_submodules('pkg_resources')
hidden_imports += collect_submodules('jaraco')
hidden_imports += collect_submodules('more_itertools')

a = Analysis(['PixelFlasher.py'],
             pathex=['.'],
             binaries=[('bin/7zzs', 'bin')],
             datas=[
                ("images/icon-64.png", "images"),
                ("images/icon-dark-64.png", "images"),
                ("images/icon-dark-256.png", "images"),
                ("images/icon-dark-256.ico", "images"),
                ("images/icon-dark-256.icns", "images"),
                ("windows-version-info.txt", "."),
                ('ui/web/dist', 'ui/web/dist'),
                ('resources/platform-tools', 'resources/platform-tools'),
                ('resources/boot-patch', 'resources/boot-patch'),
                ('resources/root-apps', 'resources/root-apps'),
                ('resources/ota-runner/runtime', 'resources/ota-runner/runtime'),
                ('bin/busybox_arm64-v8a', 'bin'),
                ('bin/busybox_armeabi-v7a', 'bin'),
                ('bin/busybox_x86', 'bin'),
                ('bin/busybox_x86_64', 'bin'),
                ('bin/aapt2_arm64-v8a', 'bin'),
                ('bin/aapt2_armeabi-v7a', 'bin'),
                ('bin/aapt2_x86', 'bin'),
                ('bin/aapt2_x86_64', 'bin'),
                ('bin/avbctl', 'bin'),
                ('android_versions.json', '.'),
                ('android_devices.json', '.'),
                ('testkey_rsa4096.pem', '.'),
                ('pixelflasher_core/payload_extractor.py', 'pixelflasher_core'),
                ('pixelflasher_core/payload_extractor.integrity.json', 'pixelflasher_core'),
                ('locale', 'locale')
             ],
             hiddenimports=hidden_imports,
             hookspath=[],
             runtime_hooks=['pyi_runtime_linux_gtk.py'],
             excludes=[
                *RETIRED_UI_MODULES,
                'bin/busybox_arm64-v8a',
                'bin/busybox_armeabi-v7a',
                'bin/busybox_x86',
                'bin/busybox_x86_64',
                'bin/aapt2_arm64-v8a',
                'bin/aapt2_armeabi-v7a',
                'bin/aapt2_x86',
                'bin/aapt2_x86_64',
                'bin/avbctl',
             ],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)

pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
        a.scripts,
        a.binaries,
        a.zipfiles,
        a.datas,
        name='PixelFlasher',
        debug=False,
        strip=False,
        upx=True,
        console=False,
        icon='images\\icon-dark-256.ico',
        bootloader_ignore_signals=False,
        disable_windowed_traceback=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None)
