"""Audit pinned official root-app release APKs without retaining downloads."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import urllib.request
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path

APPLICATION_ROOT = Path(__file__).resolve().parents[1]
if str(APPLICATION_ROOT) not in sys.path:
    sys.path.insert(0, str(APPLICATION_ROOT))

from pixelflasher_core.apk_inspection import inspect_apk  # noqa: E402

MAXIMUM_APK_BYTES = 64 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024
KNOWN_ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")


@dataclass(frozen=True, slots=True)
class ReleaseAsset:
    provider: str
    repository: str
    tag: str
    asset: str
    version: str
    sha256: str
    size: int
    package_name: str

    @property
    def url(self) -> str:
        return f"https://github.com/{self.repository}/releases/download/{self.tag}/{self.asset}"


RELEASES = (
    ReleaseAsset("Magisk", "topjohnwu/Magisk", "v30.7", "Magisk-v30.7.apk", "30.7", "e0d32d2123532860f97123d927b1bb86c4e08e6fd8a48bfc6b5bee0afae9ebd5", 11613864, "com.topjohnwu.magisk"),
    ReleaseAsset("APatch", "bmax121/APatch", "11142", "APatch_11142_166daa0_on_HEAD-release-signed.apk", "11142", "1695a51f5741c602fab50f389949e0d356a639708fc97663b0fc8a2a2d47ee81", 5850198, "me.bmax.apatch"),
    ReleaseAsset("KernelSU", "tiann/KernelSU", "v3.2.5", "KernelSU_v3.2.5_32525-release.apk", "3.2.5", "1417081413bf7ab1de8e440ecbcb62685037c8f28f048f0f8b79e305b31ab916", 9083665, "me.weishu.kernelsu"),
    ReleaseAsset("KernelSU-Next", "KernelSU-Next/KernelSU-Next", "v3.3.0", "KernelSU_Next_v3.3.0_33214-release.apk", "3.3.0", "fd0b12385c98fe9d5f4f1257b5f184e55c74c1376637507df0718305f5d7a924", 10209942, "com.rifsxd.ksunext"),
    ReleaseAsset("SukiSU", "SukiSU-Ultra/SukiSU-Ultra", "v4.1.3", "SukiSU_v4.1.3_40796-release.apk", "4.1.3", "1b1e837c0a5b6aa34554882fad67cef6db6ca1a84d43e07dd904cf54f8d261ae", 12148312, "com.sukisu.ultra"),
    ReleaseAsset("Wild_KSU", "WildKernels/Wild_KSU", "v3.1.2", "Wild_KSU_v3.1.2_33208-release.apk", "3.1.2", "c3709257dea869eb7ce5464037c93bd49619cb9aca5246b1a32b4441dc451dde", 10952665, "com.twj.wksu"),
    ReleaseAsset("KernelSU-Legacy", "rsuntk/KernelSU", "v3.2.2-10-legacy", "KernelSU_v3.2.2-10-legacy-42-g915b4872_32490-release.apk", "3.2.2-10-legacy", "78fe80980e65d30ced2a5f560680f8d6343d4443baee4c3bf1c82cbd6847147d", 7572584, "wffxxf.nclgit.cawxcw"),
)


def _download(asset: ReleaseAsset, destination: Path) -> None:
    request = urllib.request.Request(
        asset.url,
        headers={"User-Agent": "PixelFlasher-release-audit"},
    )
    digest = hashlib.sha256()
    total = 0
    with urllib.request.urlopen(request, timeout=60) as response, destination.open("wb") as stream:
        while True:
            chunk = response.read(CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            if total > MAXIMUM_APK_BYTES or total > asset.size:
                raise ValueError(f"{asset.provider} APK exceeds its pinned size")
            digest.update(chunk)
            stream.write(chunk)
    if total != asset.size:
        raise ValueError(f"{asset.provider} APK size changed")
    if digest.hexdigest() != asset.sha256:
        raise ValueError(f"{asset.provider} APK SHA-256 changed")


def _architectures(path: Path) -> list[str]:
    found: set[str] = set()
    with zipfile.ZipFile(path, "r") as archive:
        for name in archive.namelist():
            parts = name.split("/")
            if len(parts) >= 3 and parts[0] == "lib" and parts[1] in KNOWN_ABIS:
                found.add(parts[1])
    return [architecture for architecture in KNOWN_ABIS if architecture in found]


def audit() -> dict[str, object]:
    results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="pf-root-app-audit-") as directory:
        root = Path(directory)
        for index, asset in enumerate(RELEASES):
            path = root / f"{index:02d}.apk"
            _download(asset, path)
            identity = inspect_apk(path)
            if identity.package_name != asset.package_name:
                raise ValueError(
                    f"{asset.provider} package changed: {identity.package_name}"
                )
            results.append(
                {
                    **asdict(asset),
                    "url": asset.url,
                    "signerSha256": list(identity.signer_sha256),
                    "schemes": list(identity.schemes),
                    "architectures": _architectures(path),
                }
            )
    return {"schemaVersion": 1, "assets": results}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    print(
        json.dumps(
            audit(),
            indent=2 if args.pretty else None,
            sort_keys=True,
            separators=None if args.pretty else (",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
