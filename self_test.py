#!/usr/bin/env python
"""PixelFlasher self-test helpers.

This module performs low-risk startup checks that are useful for beta builds and
CI. It deliberately avoids importing the main wxPython UI or talking to a real
phone unless an adb/fastboot executable is already discoverable.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from platform_utils import current_platform, repo_root, resolve_executable

try:
    from constants import APPNAME, CONFIG_FILE_NAME, VERSION
except Exception:  # pragma: no cover - defensive fallback for broken imports
    APPNAME = "PixelFlasher"
    CONFIG_FILE_NAME = "PixelFlasher.json"
    VERSION = "unknown"

try:
    from platformdirs import user_data_dir
except Exception:  # pragma: no cover - optional diagnostic fallback
    user_data_dir = None


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    message: str = ""
    required: bool = True

    @property
    def status(self) -> str:
        if self.ok:
            return "PASS"
        return "FAIL" if self.required else "WARN"


def _repo_root() -> Path:
    return repo_root()


def _is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def _is_executable(path: Path) -> bool:
    if sys.platform.startswith("win"):
        return path.is_file()
    return path.is_file() and os.access(path, os.X_OK)


def _find_binary(names: Iterable[str]) -> str | None:
    found = resolve_executable(names)
    return str(found) if found else None


def _find_configured_platform_tool(names: Iterable[str]) -> str | None:
    root = _configured_platform_tools_path()
    if root is None:
        return None
    for name in names:
        candidate = root / name
        if _is_executable(candidate):
            return str(candidate)
    return None


def _configured_platform_tools_path() -> Path | None:
    if user_data_dir is None:
        return None
    try:
        config_path = Path(user_data_dir(APPNAME, appauthor=False, roaming=True)) / CONFIG_FILE_NAME
        if not config_path.is_file():
            return None
        data = json.loads(config_path.read_text(encoding="utf-8"))
        configured = str(data.get("platform_tools_path") or "").strip()
        return Path(configured) if configured else None
    except Exception:
        return None


def _check_python_version() -> CheckResult:
    version = sys.version_info
    ok = version >= (3, 8)
    return CheckResult(
        "python_version",
        ok,
        f"Python {platform.python_version()} on {platform.system()} {platform.release()}",
    )


def _check_module(module: str, required: bool = True) -> CheckResult:
    spec = importlib.util.find_spec(module)
    return CheckResult(
        f"module:{module}",
        spec is not None,
        "available" if spec is not None else "not importable",
        required=required,
    )


def _check_json_file(path: Path) -> CheckResult:
    try:
        with path.open("r", encoding="utf-8") as fh:
            json.load(fh)
        return CheckResult(f"json:{path.name}", True, "valid JSON")
    except Exception as exc:
        return CheckResult(f"json:{path.name}", False, str(exc))


def _check_required_file(path: Path) -> CheckResult:
    return CheckResult(
        f"file:{path.name}",
        path.is_file(),
        str(path.relative_to(_repo_root())) if path.exists() else "missing",
    )


def _check_required_dir(path: Path) -> CheckResult:
    return CheckResult(
        f"dir:{path.name}",
        path.is_dir(),
        str(path.relative_to(_repo_root())) if path.exists() else "missing",
    )


def _check_source_layout(root: Path) -> list[CheckResult]:
    if _is_frozen():
        return [CheckResult("source_layout", True, "skipped for packaged binary")]
    return [
        _check_required_file(root / "PixelFlasher.py"),
        _check_required_file(root / "Main.py"),
        _check_required_file(root / "requirements.txt"),
    ]


def _check_config_writable() -> CheckResult:
    try:
        with tempfile.TemporaryDirectory(prefix="pf-self-test-") as tmp:
            test_file = Path(tmp) / "write-test.tmp"
            test_file.write_text("ok", encoding="utf-8")
            ok = test_file.read_text(encoding="utf-8") == "ok"
        return CheckResult("config_writable", ok, "temporary config write succeeded")
    except Exception as exc:
        return CheckResult("config_writable", False, str(exc))


def _check_platform_tools() -> list[CheckResult]:
    adb = _find_binary(["adb.exe", "adb"]) or _find_configured_platform_tool(["adb.exe", "adb"])
    fastboot = _find_binary(["fastboot.exe", "fastboot"]) or _find_configured_platform_tool(["fastboot.exe", "fastboot"])
    return [
        CheckResult("platform_tool:adb", adb is not None, adb or "not found in PATH or configured Platform Tools path", required=False),
        CheckResult("platform_tool:fastboot", fastboot is not None, fastboot or "not found in PATH or configured Platform Tools path", required=False),
    ]


def _packaged_bin_ok(path: Path) -> bool:
    if sys.platform.startswith("win") or path.name.endswith(".dll"):
        return path.is_file()
    return path.is_file() and (bool(path.stat().st_mode & stat.S_IXUSR) or _is_executable(path))


def _check_packaged_bins() -> list[CheckResult]:
    root = _repo_root()
    bin_dir = root / "bin"
    if sys.platform.startswith("win"):
        checks = [("7z.exe", True), ("7z.dll", True)]
    else:
        # Linux/macOS packages may include either 7zz or the smaller 7zzs build.
        candidates = [bin_dir / "7zz", bin_dir / "7zzs"]
        found = [path.name for path in candidates if _packaged_bin_ok(path)]
        return [CheckResult("packaged_bin:7zip", bool(found), "/".join(found) if found else "missing", required=False)]

    results: list[CheckResult] = []
    for name, required in checks:
        path = bin_dir / name
        results.append(CheckResult(f"packaged_bin:{name}", _packaged_bin_ok(path), "present" if path.exists() else "missing", required=required))
    return results


def _check_platform_layer() -> CheckResult:
    try:
        info = current_platform()
        return CheckResult("platform_layer", True, f"{info.system} {info.release} / {info.machine}")
    except Exception as exc:
        return CheckResult("platform_layer", False, str(exc))


def _check_ui_foundation() -> list[CheckResult]:
    results: list[CheckResult] = []
    try:
        from ui.theme import get_theme
        get_theme("light")
        get_theme("dark")
        results.append(CheckResult("ui_theme_tokens", True, "light/dark themes load"))
    except Exception as exc:
        results.append(CheckResult("ui_theme_tokens", False, str(exc)))

    try:
        from ui.icons import ICON_REGISTRY, validate_icon_registry
        errors = validate_icon_registry()
        results.append(CheckResult("ui_icon_registry", not errors, f"{len(ICON_REGISTRY)} icons" if not errors else "; ".join(errors)))
    except Exception as exc:
        results.append(CheckResult("ui_icon_registry", False, str(exc)))
    return results


def _check_modern_entrypoints() -> list[CheckResult]:
    modules = (
        "ui.pages.dashboard_app",
        "ui.pages.flash_wizard_app",
        "ui.pages.modern_shell_app",
        "ui.pages.main_integration",
    )
    if importlib.util.find_spec("wx") is None:
        return [
            CheckResult(
                f"entrypoint:{module.rsplit('.', 1)[-1]}",
                True,
                "skipped; wx not importable in this environment",
            )
            for module in modules
        ]

    results: list[CheckResult] = []
    for module in modules:
        try:
            __import__(module, fromlist=["*"])
            results.append(CheckResult(f"entrypoint:{module.rsplit('.', 1)[-1]}", True, "importable"))
        except Exception as exc:
            results.append(CheckResult(f"entrypoint:{module.rsplit('.', 1)[-1]}", False, str(exc)))
    return results


def run_checks() -> list[CheckResult]:
    root = _repo_root()
    checks: list[CheckResult] = [
        CheckResult("app", True, f"{APPNAME} {VERSION}"),
        _check_python_version(),
    ]
    checks.extend(_check_source_layout(root))
    checks.extend([
        _check_platform_layer(),
        _check_required_dir(root / "images"),
        _check_required_dir(root / "bin"),
        _check_json_file(root / "android_devices.json"),
        _check_json_file(root / "android_versions.json"),
        _check_config_writable(),
        _check_module("wx", required=False),
        _check_module("requests", required=False),
        _check_module("psutil", required=False),
        _check_module("darkdetect", required=True),
        _check_module("json5", required=True),
    ])
    checks.extend(_check_platform_tools())
    checks.extend(_check_ui_foundation())
    checks.extend(_check_modern_entrypoints())
    checks.extend(_check_packaged_bins())
    return checks


def format_results(results: list[CheckResult]) -> str:
    lines = [f"{APPNAME} self-test"]
    pass_marker, fail_marker = _result_markers()
    for result in results:
        marker = pass_marker if result.ok else (fail_marker if result.required else "!")
        lines.append(f"{marker} {result.status:<4} {result.name:<28} {result.message}")
    required_failures = [r for r in results if r.required and not r.ok]
    warnings = [r for r in results if not r.required and not r.ok]
    lines.append("")
    lines.append(f"Required failures: {len(required_failures)}")
    lines.append(f"Warnings: {len(warnings)}")
    return "\n".join(lines)


def _result_markers() -> tuple[str, str]:
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        "✓✗".encode(encoding)
        return "✓", "✗"
    except Exception:
        return "+", "x"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run PixelFlasher startup self-test checks.")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON output")
    args = parser.parse_args(argv)

    results = run_checks()
    if args.json:
        print(json.dumps([result.__dict__ | {"status": result.status} for result in results], indent=2))
    else:
        print(format_results(results))

    return 1 if any(result.required and not result.ok for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
