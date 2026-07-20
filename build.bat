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
if "%PIXELFLASHER_REQUIRE_SIGNED_PLATFORM_TOOLS%"=="1" (
    python .\scripts\verify_platform_tools_catalog.py --root .\resources\platform-tools\runtime
) else (
    python .\scripts\verify_platform_tools_catalog.py --root .\resources\platform-tools\runtime --allow-missing
)
if errorlevel 1 exit /b 1
pyinstaller --log-level=DEBUG ^
			--clean ^
            --noconfirm ^
            build-on-win.spec
if errorlevel 1 exit /b 1
exit /b 0
