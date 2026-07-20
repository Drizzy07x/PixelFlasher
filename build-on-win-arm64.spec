# -*- mode: python -*-

from build_artifact_policy import RETIRED_UI_MODULES
from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs

winpty_binaries = collect_dynamic_libs('winpty')
winpty_datas = collect_data_files('winpty', includes=['*.exe'])

block_cipher = None

a = Analysis(['PixelFlasher.py'],
            pathex=['.'],
            binaries=[('bin/7z.exe', 'bin'), ('bin/7z.dll', 'bin')] + winpty_binaries,
            datas=[
                ("images/icon-64.png", "images"),
                ("images/icon-dark-64.png", "images"),
                ('ui/web/dist', 'ui/web/dist'),
                ('bin/busybox_arm64-v8a', 'bin'),
                ('bin/busybox_armeabi-v7a', 'bin'),
                ('bin/busybox_x86', 'bin'),
                ('bin/busybox_x86_64', 'bin'),
                ('bin/aapt2_arm64-v8a', 'bin'),
                ('bin/aapt2_armeabi-v7a', 'bin'),
                ('bin/aapt2_x86', 'bin'),
                ('bin/aapt2_x86_64', 'bin'),
                ('bin/avbctl', 'bin'),
                ('bin/update_engine_client_r28', 'bin'),
                ('bin/update_engine_client_r72', 'bin'),
                ('android_versions.json', '.'),
                ('android_devices.json', '.'),
                ('testkey_rsa4096.pem', '.'),
                ('pixelflasher_core/payload_extractor.py', 'pixelflasher_core'),
                ('pixelflasher_core/payload_extractor.integrity.json', 'pixelflasher_core'),
                ('locale', 'locale')
            ] + winpty_datas,
            hiddenimports=[
                '_cffi_backend',
                'winpty',
                'winpty._winpty',
                'winpty.enums',
                'winpty.ptyprocess',
                'wx',
                'wx.adv',
                'wx.lib',
                'wx.lib.agw',
                'wx.lib.agw.aui',
                'wx.lib.inspection',
                'wx.lib.mixins',
                'wx.lib.mixins.inspection',
                'wx.lib.mixins.listctrl',
                'wx.lib.buttons',
                'wx.lib.wxpTag',
                'wx.stc',
                'wx.html',
                'wx.html2',
                'wx._core',
                'wx._adv',
                'wx._html',
                'wx._stc',
            ],
            hookspath=['pyi-hooks-arm64'],
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
                'bin/update_engine_client_r28',
                'bin/update_engine_client_r72'
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
          name='PixelFlasher-arm64',
          version='windows-version-info.txt',
          debug=False,
          strip=False,
          upx=True,
          target_arch='arm64',
          console=True,
          hide_console='hide-early',
          icon='images\\icon-dark-256.ico')
