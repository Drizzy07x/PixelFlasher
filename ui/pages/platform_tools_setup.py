"""Install and validate Android Platform Tools for PixelFlasher."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from constants import APPNAME
from platformdirs import user_data_dir


PLATFORM_TOOLS_URLS = {
    "win32": "https://dl.google.com/android/repository/platform-tools-latest-windows.zip",
    "darwin": "https://dl.google.com/android/repository/platform-tools-latest-darwin.zip",
    "linux": "https://dl.google.com/android/repository/platform-tools-latest-linux.zip",
}


class PlatformToolsSetupError(RuntimeError):
    """Raised when Platform Tools cannot be installed or validated."""


@dataclass(frozen=True)
class PlatformToolsSetupResult:
    platform_tools_path: str
    adb_path: str
    fastboot_path: str


def platform_tools_binary_names(platform: str | None = None) -> tuple[str, str]:
    if (platform or sys.platform) == "win32":
        return "adb.exe", "fastboot.exe"
    return "adb", "fastboot"


def platform_tools_download_url(platform: str | None = None) -> str:
    key = platform or sys.platform
    if key.startswith("linux"):
        key = "linux"
    try:
        return PLATFORM_TOOLS_URLS[key]
    except KeyError as exc:
        raise PlatformToolsSetupError(f"Unsupported platform: {platform or sys.platform}") from exc


def default_platform_tools_install_root() -> Path:
    return Path(user_data_dir(APPNAME, appauthor=False)) / "android-sdk"


def validate_platform_tools_path(path: str | os.PathLike[str], platform: str | None = None) -> PlatformToolsSetupResult:
    root = Path(path)
    adb_name, fastboot_name = platform_tools_binary_names(platform)
    adb_path = root / adb_name
    fastboot_path = root / fastboot_name
    if not adb_path.is_file() or not fastboot_path.is_file():
        raise PlatformToolsSetupError("The selected folder does not contain adb and fastboot.")
    return PlatformToolsSetupResult(str(root), str(adb_path), str(fastboot_path))


def install_platform_tools(
    install_root: str | os.PathLike[str] | None = None,
    download_url: str | None = None,
) -> PlatformToolsSetupResult:
    """Download and install Android Platform Tools into a user-writable folder."""

    url = download_url or platform_tools_download_url()
    root = Path(install_root) if install_root else default_platform_tools_install_root()
    root.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="pf-platform-tools-") as tmp_name:
        tmp_root = Path(tmp_name)
        archive_path = tmp_root / "platform-tools.zip"
        extract_root = tmp_root / "extract"
        urllib.request.urlretrieve(url, archive_path)

        with zipfile.ZipFile(archive_path) as archive:
            _safe_extract(archive, extract_root)

        extracted_tools = extract_root / "platform-tools"
        validate_platform_tools_path(extracted_tools)

        target = root / "platform-tools"
        staging = root / ".platform-tools-installing"
        backup = root / f"platform-tools.backup-{datetime.now():%Y%m%d-%H%M%S}"

        if staging.exists():
            shutil.rmtree(staging)
        shutil.copytree(extracted_tools, staging)
        if target.exists():
            target.rename(backup)
        staging.rename(target)

    return validate_platform_tools_path(root / "platform-tools")


def _safe_extract(archive: zipfile.ZipFile, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    destination_root = destination.resolve()
    for member in archive.infolist():
        member_path = (destination / member.filename).resolve()
        if member_path != destination_root and destination_root not in member_path.parents:
            raise PlatformToolsSetupError("Platform Tools archive contains an unsafe path.")
    archive.extractall(destination)
