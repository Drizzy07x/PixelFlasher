python .\compile_po.py
if "%PIXELFLASHER_FRONTEND_PREBUILT%"=="1" (
    python .\scripts\build_frontend.py --check-only
) else (
    python .\scripts\build_frontend.py
)
if errorlevel 1 exit /b %errorlevel%
pyinstaller --log-level=DEBUG ^
			--clean ^
            --noconfirm ^
            build-on-win.spec
