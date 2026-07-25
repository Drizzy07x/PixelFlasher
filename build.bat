@echo off
setlocal
set "PYTHONPATH=%~dp0;%PYTHONPATH%"

python .\compile_po.py
if errorlevel 1 exit /b 1
if "%PIXELFLASHER_FRONTEND_PREBUILT%"=="1" (
    python .\scripts\build_frontend.py --check-only
) else (
    python .\scripts\build_frontend.py
)
if errorlevel 1 exit /b 1
set "CATALOG_OPTION=--allow-missing"
if "%PIXELFLASHER_REQUIRE_SIGNED_PLATFORM_TOOLS%"=="1" set "CATALOG_OPTION="
python .\scripts\verify_platform_tools_catalog.py --root .\resources\platform-tools\runtime %CATALOG_OPTION%
if errorlevel 1 exit /b 1
python .\scripts\verify_root_app_catalog.py --root .\resources\root-apps\runtime %CATALOG_OPTION%
if errorlevel 1 exit /b 1
python .\scripts\verify_firmware_catalog.py --root .\resources\firmware\runtime %CATALOG_OPTION%
if errorlevel 1 exit /b 1
python .\scripts\verify_scrcpy_catalog.py --root .\resources\scrcpy\runtime %CATALOG_OPTION%
if errorlevel 1 exit /b 1
python .\scripts\verify_update_manifest.py --path .\resources\updates\runtime\manifest.json %CATALOG_OPTION%
if errorlevel 1 exit /b 1
python .\scripts\verify_keybox_revocations.py --path .\resources\keybox\revocations.json %CATALOG_OPTION%
if errorlevel 1 exit /b 1
pyinstaller --log-level=DEBUG ^
			--clean ^
            --noconfirm ^
            build-on-win.spec
if errorlevel 1 exit /b 1
exit /b 0
