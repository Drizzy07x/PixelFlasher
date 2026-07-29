#!/usr/bin/env python3
"""Run the per-commit source gate locally when hosted CI is unavailable.

The hosted workflows are the only thing that ever executed the complete suite:
`ubuntu-smoke.yml` skips four modules because its runtime omits wxPython, and the
workflows that do run them are `workflow_call` targets reached solely from a tag
or a pull request. This gate reproduces every check that a Windows workstation
can run, and it never skips the legacy-boundary modules.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent

COMPILED_MODULES = (
    "PixelFlasher.py",
    "self_test.py",
    "diagnostics.py",
    "platform_utils.py",
    "config.py",
    "ui/bridge_contract.py",
    "ui/core_command_factory.py",
    "ui/pages/modern_primary_app.py",
    "ui/pages/modern_webview_host.py",
    "tools/create_beta_bundle.py",
)

COVERAGE_FLOOR = 80.0


class GateError(RuntimeError):
    """A stage failed and the gate must stop."""


@dataclass(frozen=True, slots=True)
class Stage:
    name: str
    argv: tuple[str, ...]
    cwd: Path
    optional: bool = False


@dataclass(frozen=True, slots=True)
class StageResult:
    name: str
    ok: bool
    seconds: float
    detail: str


def _python() -> str:
    return sys.executable


def _package_manager() -> tuple[str, ...]:
    """Resolve pnpm the same way the workflows do, preferring corepack."""

    corepack = shutil.which("corepack")
    if corepack is not None:
        return (corepack, "pnpm")
    pnpm = shutil.which("pnpm")
    if pnpm is None:
        raise GateError("neither corepack nor pnpm is available on PATH")
    return (pnpm,)


def _frontend_stages(web: Path) -> tuple[Stage, ...]:
    manager = _package_manager()
    return (
        Stage("frontend.build", (*manager, "build"), web),
        Stage("frontend.tests", (*manager, "test:coverage"), web),
    )


def _source_stages() -> tuple[Stage, ...]:
    python = _python()
    return (
        Stage(
            "bridge.contracts",
            (python, "scripts/generate_bridge_contracts.py", "--check"),
            REPOSITORY_ROOT,
        ),
        Stage(
            "bridge.react",
            (python, "scripts/verify_react_bridge_commands.py"),
            REPOSITORY_ROOT,
        ),
        Stage(
            "i18n.export",
            (python, "scripts/export_gettext_json.py", "--output-dir", "build/react-i18n"),
            REPOSITORY_ROOT,
        ),
        Stage(
            "i18n.check",
            (
                python,
                "scripts/export_gettext_json.py",
                "--output-dir",
                "build/react-i18n",
                "--check",
            ),
            REPOSITORY_ROOT,
        ),
        Stage("compile.modules", (python, "-m", "py_compile", *COMPILED_MODULES), REPOSITORY_ROOT),
        Stage("compile.core", (python, "-m", "compileall", "-q", "pixelflasher_core"), REPOSITORY_ROOT),
        Stage("selftest", (python, "PixelFlasher.py", "--self-test"), REPOSITORY_ROOT),
        Stage(
            "lint.ruff",
            (python, "-m", "ruff", "check", "pixelflasher_core", "ui", "scripts", "tests"),
            REPOSITORY_ROOT,
        ),
        Stage(
            "types.pyright",
            (
                python,
                "-m",
                "pyright",
                "--pythonpath",
                python,
                "--pythonplatform",
                "Windows" if os.name == "nt" else "Linux",
                "pixelflasher_core",
            ),
            REPOSITORY_ROOT,
        ),
        Stage(
            "tests.python",
            (
                python,
                "-m",
                "pytest",
                "-q",
                "--cov=pixelflasher_core",
                "--cov=ui.command_registry",
                "--cov-branch",
                "--cov-report=term-missing:skip-covered",
                "--cov-report=json:build/coverage-local.json",
                "--junitxml=build/pytest-local.xml",
                f"--cov-fail-under={COVERAGE_FLOOR:g}",
            ),
            REPOSITORY_ROOT,
        ),
    )


def _ota_runner_stage() -> Stage:
    return Stage(
        "ota.runner",
        (_python(), "scripts/build_ota_runner.py", "--check"),
        REPOSITORY_ROOT,
        optional=True,
    )


def _run(stage: Stage, *, echo: bool) -> StageResult:
    started = time.monotonic()
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        stage.argv,
        cwd=stage.cwd,
        capture_output=not echo,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    elapsed = time.monotonic() - started
    if completed.returncode == 0:
        return StageResult(stage.name, True, elapsed, "")
    detail = ""
    if not echo:
        tail = "\n".join(
            line
            for line in ((completed.stdout or "") + (completed.stderr or "")).splitlines()
            if line.strip()
        )
        detail = "\n".join(tail.splitlines()[-25:])
    return StageResult(stage.name, False, elapsed, detail or f"exit code {completed.returncode}")


def run_gate(
    *,
    stages: Sequence[Stage],
    echo: bool = False,
    keep_going: bool = False,
) -> tuple[StageResult, ...]:
    results: list[StageResult] = []
    for stage in stages:
        print(f"==> {stage.name}", flush=True)
        result = _run(stage, echo=echo)
        results.append(result)
        status = "ok" if result.ok else "FAILED"
        print(f"    {status} in {result.seconds:.1f}s", flush=True)
        if not result.ok:
            if result.detail:
                print(result.detail, flush=True)
            if not keep_going:
                break
    return tuple(results)


def select_stages(*, skip: frozenset[str], with_ota_runner: bool) -> tuple[Stage, ...]:
    web = REPOSITORY_ROOT / "ui" / "web"
    stages: list[Stage] = [*_frontend_stages(web), *_source_stages()]
    if with_ota_runner:
        stages.append(_ota_runner_stage())
    unknown = skip - {stage.name for stage in stages}
    if unknown:
        raise GateError(f"unknown stage(s) to skip: {', '.join(sorted(unknown))}")
    return tuple(stage for stage in stages if stage.name not in skip)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip",
        action="append",
        default=[],
        metavar="STAGE",
        help="skip a stage by name; may be repeated",
    )
    parser.add_argument(
        "--echo",
        action="store_true",
        help="stream stage output instead of retaining only a failing tail",
    )
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="run every stage even after one fails",
    )
    parser.add_argument(
        "--with-ota-runner",
        action="store_true",
        help="also rebuild and compare the packaged OTA runner DEX (needs a JDK and network)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        stages = select_stages(
            skip=frozenset(args.skip),
            with_ota_runner=args.with_ota_runner,
        )
    except GateError as error:
        print(f"error: {error}")
        return 1

    results = run_gate(stages=stages, echo=args.echo, keep_going=args.keep_going)
    failed = [result for result in results if not result.ok]
    total = sum(result.seconds for result in results)

    print()
    print(f"{len(results)}/{len(stages)} stage(s) run in {total:.1f}s")
    if failed:
        print("blocked by: " + ", ".join(result.name for result in failed))
        return 1
    if len(results) != len(stages):
        print("gate did not run every stage")
        return 1
    print("local gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
