#!/usr/bin/env python
"""PixelFlasher self-test helpers.

This module performs low-risk startup checks that are useful for release builds
and CI. It deliberately avoids importing the main wxPython UI or talking to a
real phone unless an adb/fastboot executable is already discoverable.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import stat
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from platform_utils import current_platform, repo_root, resolve_executable

try:
    from constants import (
        APPNAME as imported_appname,
    )
    from constants import (
        CONFIG_FILE_NAME as imported_config_file_name,
    )
    from constants import (
        VERSION as imported_version,
    )
except Exception:  # pragma: no cover - defensive fallback for broken imports
    imported_appname = "PixelFlasher"
    imported_config_file_name = "PixelFlasher.json"
    imported_version = "unknown"

APPNAME = imported_appname
CONFIG_FILE_NAME = imported_config_file_name
VERSION = imported_version

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
        _check_required_file(root / "pixelflasher_core" / "__init__.py"),
        _check_required_file(root / "ui" / "web" / "package.json"),
        _check_required_file(root / "requirements.txt"),
    ]


def _check_release_metadata(root: Path) -> list[CheckResult]:
    version_is_stable = "beta" not in VERSION.lower()
    icon_paths = (
        root / "images" / "icon-dark-256.png",
        root / "images" / "icon-dark-256.ico",
        root / "images" / "icon-dark-256.icns",
        root / "windows-version-info.txt",
    )
    return [
        CheckResult("release_version", version_is_stable, VERSION if version_is_stable else f"pre-release version: {VERSION}"),
        *(_check_required_file(path) for path in icon_paths),
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
    """Validate the product UI source without importing retired wx previews."""

    if _is_frozen():
        return [
            CheckResult("ui_theme_tokens", True, "covered by the bundled frontend contract"),
            CheckResult("ui_asset_registry", True, "covered by the bundled frontend contract"),
        ]

    web_root = _repo_root() / "ui" / "web" / "src"
    styles = web_root / "styles.css"
    assets = web_root / "assets.ts"
    results: list[CheckResult] = []

    try:
        source = styles.read_text(encoding="utf-8")
        required_tokens = (
            ":root",
            'data-theme="light"',
            "forced-colors: active",
            "prefers-reduced-motion: reduce",
            ":focus-visible",
        )
        missing = [token for token in required_tokens if token not in source]
        results.append(
            CheckResult(
                "ui_theme_tokens",
                not missing,
                "dark/light/contrast/motion/focus tokens present"
                if not missing
                else "missing: " + ", ".join(missing),
            )
        )
    except Exception as exc:
        results.append(CheckResult("ui_theme_tokens", False, str(exc)))

    try:
        source = assets.read_text(encoding="utf-8")
        required_assets = ("appLogo", "phoneRender", "dashboard", "warningPng")
        missing = [asset for asset in required_assets if asset not in source]
        results.append(
            CheckResult(
                "ui_asset_registry",
                not missing,
                "React image/icon assets registered"
                if not missing
                else "missing: " + ", ".join(missing),
            )
        )
    except Exception as exc:
        results.append(CheckResult("ui_asset_registry", False, str(exc)))
    return results


def _check_modern_entrypoints() -> list[CheckResult]:
    headless_modules = ("pixelflasher_core", "ui.bridge_contract")
    modules = ("ui.pages.modern_webview_host", "ui.pages.modern_primary_app")
    results: list[CheckResult] = []
    for module in headless_modules:
        try:
            __import__(module, fromlist=["*"])
            results.append(CheckResult(f"entrypoint:{module.rsplit('.', 1)[-1]}", True, "importable"))
        except Exception as exc:
            results.append(CheckResult(f"entrypoint:{module.rsplit('.', 1)[-1]}", False, str(exc)))

    if importlib.util.find_spec("wx") is None:
        results.extend(
            CheckResult(
                f"entrypoint:{module.rsplit('.', 1)[-1]}",
                True,
                "skipped; wx not importable in this environment",
            )
            for module in modules
        )
        return results

    for module in modules:
        try:
            __import__(module, fromlist=["*"])
            results.append(CheckResult(f"entrypoint:{module.rsplit('.', 1)[-1]}", True, "importable"))
        except Exception as exc:
            results.append(CheckResult(f"entrypoint:{module.rsplit('.', 1)[-1]}", False, str(exc)))
    return results


def _check_frontend_assets() -> list[CheckResult]:
    dist = _repo_root() / "ui" / "web" / "dist"
    index = dist / "index.html"
    assets = dist / "assets"
    results = [
        CheckResult("frontend:index", index.is_file(), str(index) if index.exists() else "missing bundled React index"),
        CheckResult("frontend:assets", assets.is_dir(), str(assets) if assets.exists() else "missing bundled React assets"),
    ]
    if index.is_file():
        try:
            source = index.read_text(encoding="utf-8")
            classic = (
                "<script src=" in source
                and 'type="module"' not in source
                and "http://" not in source
                and "https://" not in source
            )
            results.append(
                CheckResult(
                    "frontend:webview_bundle",
                    classic,
                    "classic local bundle" if classic else "module or remote runtime dependency detected",
                )
            )
        except Exception as exc:
            results.append(CheckResult("frontend:webview_bundle", False, str(exc)))
    return results


def _check_patch_resources() -> CheckResult:
    try:
        from pixelflasher_core.patch_resources import (
            load_optional_packaged_patch_resource_registry,
        )

        registry = load_optional_packaged_patch_resource_registry(_repo_root())
        if registry is None:
            return CheckResult(
                "boot_patch:runner_distribution",
                False,
                "packaged runner distribution is missing",
            )
        expected = {"magisk", "apatch", "kernelsu", "kernelsu-next", "sukisu", "wild-ksu"}
        missing = expected - registry.ready_flavors
        return CheckResult(
            "boot_patch:runner_distribution",
            not missing,
            (
                f"{len(registry.tool_bundles)} verified ABI runner bindings"
                if not missing
                else "missing flavors: " + ", ".join(sorted(missing))
            ),
        )
    except Exception as exc:
        return CheckResult("boot_patch:runner_distribution", False, str(exc))


def run_checks() -> list[CheckResult]:
    root = _repo_root()
    checks: list[CheckResult] = [
        CheckResult("app", True, f"{APPNAME} {VERSION}"),
        _check_python_version(),
    ]
    checks.extend(_check_source_layout(root))
    checks.extend(_check_release_metadata(root))
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
    ])
    checks.extend(_check_platform_tools())
    checks.append(_check_patch_resources())
    checks.extend(_check_ui_foundation())
    checks.extend(_check_modern_entrypoints())
    checks.extend(_check_frontend_assets())
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


def _write_frozen_self_test_log(output: str) -> None:
    if not _is_frozen():
        return
    try:
        path = Path(tempfile.gettempdir()) / "PixelFlasher-self-test.log"
        path.write_text(output + "\n", encoding="utf-8", errors="replace")
    except Exception:
        pass


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
        output = json.dumps([result.__dict__ | {"status": result.status} for result in results], indent=2)
    else:
        output = format_results(results)

    print(output)
    _write_frozen_self_test_log(output)

    return 1 if any(result.required and not result.ok for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
