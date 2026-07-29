#!/usr/bin/env python3
"""Build the real executable and run every packaged smoke against it.

The seven-target matrix in `main.yml` is the only place this ever ran, and it no
longer executes on a branch push. This reproduces the Windows x64 job locally:
build, assert the shipped archive, run the five packaged smokes, verify each
receipt with its own verifier, and record the receipts in the evidence store so
a gate can cite something that still exists tomorrow.
"""

from __future__ import annotations

import argparse
import os
import platform
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts.evidence_store import record  # noqa: E402

# Every smoke that the packaged binary can run without an Android device.
SMOKES: tuple[tuple[str, str, str], ...] = (
    ("pty", "--pty-smoke-report", "verify_pty_smoke.py"),
    ("legacy-raw", "--legacy-raw-smoke-report", "verify_legacy_raw_smoke.py"),
    ("firmware", "--firmware-smoke-report", "verify_firmware_smoke.py"),
    ("support", "--support-smoke-report", "verify_support_smoke.py"),
    ("ui", "--ui-smoke-report", "verify_ui_smoke.py"),
)

REQUIRED_ARCHIVE_ENTRIES = (
    "ui/web/dist/index.html",
    "ui/web/dist/assets/adb-terminal.js",
    "ui/web/dist/assets/adb-terminal.css",
    "ui/web/dist/i18n/manifest.json",
)


class PackagedGateError(RuntimeError):
    """The packaged gate cannot continue."""


@dataclass(frozen=True, slots=True)
class Target:
    platform: str
    architecture: str

    @classmethod
    def detect(cls) -> Target:
        system = {"windows": "windows", "darwin": "macos", "linux": "linux"}.get(
            platform.system().casefold()
        )
        machine = {
            "amd64": "x86_64",
            "x86_64": "x86_64",
            "arm64": "arm64",
            "aarch64": "arm64",
        }.get(platform.machine().casefold())
        if system is None or machine is None:
            raise PackagedGateError(
                f"unsupported host: {platform.system()} {platform.machine()}"
            )
        return cls(system, machine)


def _run(argv: Sequence[str], *, cwd: Path, env: dict[str, str] | None = None) -> None:
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        list(argv),
        cwd=cwd,
        env=env,
        check=False,
    )
    if completed.returncode != 0:
        raise PackagedGateError(f"{argv[0]} exited with {completed.returncode}")


def executable_path(target: Target) -> Path:
    suffix = ".exe" if target.platform == "windows" else ""
    return REPOSITORY_ROOT / "dist" / f"PixelFlasher{suffix}"


def build(target: Target) -> Path:
    """Run the same build entrypoint the packaged workflow runs."""

    env = dict(os.environ)
    env["PYTHONPATH"] = f"{REPOSITORY_ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}"
    # build.bat and build.sh call a bare `python`, so the interpreter running
    # this gate has to be the one they find.
    env["PATH"] = f"{Path(sys.executable).parent}{os.pathsep}{env['PATH']}"
    env["PIXELFLASHER_FRONTEND_PREBUILT"] = env.get("PIXELFLASHER_FRONTEND_PREBUILT", "1")
    script = "build.bat" if target.platform == "windows" else "build.sh"
    _run([str(REPOSITORY_ROOT / script)], cwd=REPOSITORY_ROOT, env=env)
    binary = executable_path(target)
    if not binary.is_file():
        raise PackagedGateError(f"the build produced no executable at {binary}")
    return binary


def assert_archive_contents(binary: Path, forbidden: Sequence[str]) -> None:
    """Confirm the shipped archive carries the assets and no 9.x modules.

    Nothing else inspects the built artifact: the existing workflow step only
    asserts that the React assets are present, never that the legacy
    application is absent.
    """

    viewer = Path(sys.executable).parent / (
        "pyi-archive_viewer.exe" if os.name == "nt" else "pyi-archive_viewer"
    )
    if not viewer.is_file():
        raise PackagedGateError(f"pyi-archive_viewer is unavailable at {viewer}")
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [str(viewer), "-b", "-l", str(binary)],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        raise PackagedGateError("pyi-archive_viewer could not list the archive")
    entries = {
        line.strip().replace("\\", "/")
        for line in completed.stdout.splitlines()
        if line.strip()
    }
    missing = [entry for entry in REQUIRED_ARCHIVE_ENTRIES if entry not in entries]
    if missing:
        raise PackagedGateError(f"the archive is missing required assets: {missing}")

    # A bundled Python module is a bare dotted name; anything carrying a path
    # separator is a data file and cannot be a 9.x module import.
    modules = {entry.split(".", 1)[0] for entry in entries if "/" not in entry}
    leaked = sorted(modules & set(forbidden))
    if leaked:
        raise PackagedGateError(f"the archive still bundles 9.x modules: {leaked}")
    print(f"    {len(entries)} archive entries, no 9.x module among them", flush=True)


def run_smokes(binary: Path, target: Target, *, keep: bool) -> list[Path]:
    receipts: list[Path] = []
    holder = Path(tempfile.mkdtemp(prefix="pixelflasher-packaged-gate-"))
    for name, flag, verifier in SMOKES:
        report = holder / f"pixelflasher-{name}-smoke-{target.platform}.json"
        argv = [str(binary), flag, str(report)]
        if name == "pty":
            argv.append("--pty-smoke-timeout=10")
        if name == "ui":
            config = holder / "ui-smoke-config" / "PixelFlasher.json"
            config.parent.mkdir(parents=True, exist_ok=True)
            argv += ["--ui-smoke-timeout", "30", "--config", str(config)]
        print(f"==> smoke:{name}", flush=True)
        _run(argv, cwd=REPOSITORY_ROOT)
        print(f"==> verify:{name}", flush=True)
        _run(
            [
                sys.executable,
                str(REPOSITORY_ROOT / "scripts" / verifier),
                "--report",
                str(report),
                "--expect-platform",
                target.platform,
                "--expect-architecture",
                target.architecture,
            ],
            cwd=REPOSITORY_ROOT,
        )
        receipts.append(report)
    if not keep:
        print(f"receipts staged in {holder}", flush=True)
    return receipts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="reuse the executable already in dist/ instead of rebuilding",
    )
    parser.add_argument(
        "--skip-evidence",
        action="store_true",
        help="run the smokes without recording their receipts",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        from tests.legacy_boundary import legacy_root_modules

        target = Target.detect()
        binary = executable_path(target) if args.skip_build else build(target)
        if not binary.is_file():
            raise PackagedGateError(f"no executable at {binary}; drop --skip-build")
        print(f"==> archive contents of {binary.name}", flush=True)
        assert_archive_contents(binary, sorted(legacy_root_modules(REPOSITORY_ROOT)))
        receipts = run_smokes(binary, target, keep=args.skip_evidence)
        if not args.skip_evidence:
            for report in receipts:
                name = report.stem.replace("pixelflasher-", "").replace(
                    f"-smoke-{target.platform}", ""
                )
                entry = record(
                    report,
                    record_id=f"{target.platform}-{target.architecture}/{name}-smoke",
                    kind="packaged-smoke",
                    attributes={
                        "platform": target.platform,
                        "architecture": target.architecture,
                    },
                )
                print(f"recorded {entry['id']} ({entry['sha256'][:12]})", flush=True)
    except PackagedGateError as error:
        print(f"error: {error}")
        return 1
    print(f"packaged gate passed for {target.platform}-{target.architecture}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
