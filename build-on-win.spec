# -*- mode: python -*-
from pathlib import Path

import wx
from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs

import sys

sys.path.insert(0, str(Path(SPECPATH)))
from build_artifact_policy import RETIRED_UI_MODULES

wx_dir = Path(wx.__file__).resolve().parent
winpty_binaries = collect_dynamic_libs('winpty')
winpty_datas = collect_data_files('winpty', includes=['*.exe'])

block_cipher = None
optional_runtime_datas = [
    (relative, relative)
    for relative in (
        "resources/firmware",
        "resources/keybox",
        "resources/scrcpy",
        "resources/support",
        "resources/updates",
    )
    if Path(relative).exists()
]

a = Analysis(['PixelFlasher.py'],
            pathex=['.'],
            binaries=[
                ('bin/7z.exe', 'bin'),
                ('bin/7z.dll', 'bin'),
                (str(wx_dir / 'WebView2Loader.dll'), 'wx'),
            ] + winpty_binaries,
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
            ] + optional_runtime_datas + winpty_datas,
            hiddenimports=[
                '_cffi_backend',
                'winpty',
                'winpty._winpty',
                'winpty.enums',
                'winpty.ptyprocess',
                'wx.html2',
            ],
            hookspath=[],
            runtime_hooks=[],
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
            cipher=block_cipher)

pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='PixelFlasher',
          version='windows-version-info.txt',
          debug=False,
          strip=False,
          upx=True,
          console=True,
          hide_console='hide-early',
          icon='images\\icon-dark-256.ico')
