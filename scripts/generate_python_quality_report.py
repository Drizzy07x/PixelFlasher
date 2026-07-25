from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

COMMIT = re.compile(r"[0-9a-f]{40}")
BRANCH_TARGETS = {
    "safetyPolicy": "pixelflasher_core/safety.py",
    "planner": "pixelflasher_core/planner.py",
    "postconditionObserver": "pixelflasher_core/observer.py",
    "commandRegistry": "ui/command_registry.py",
}


def _load_object(path: Path, label: str) -> Mapping[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read {label} at {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise RuntimeError(f"{label} must be a JSON object")
    return document


def _number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeError(f"{label} must be numeric")
    return float(value)


def _normalized_path(value: str) -> str:
    return value.replace("\\", "/")


def _branch_coverage(report: Mapping[str, Any], suffix: str) -> float:
    files = report.get("files")
    if not isinstance(files, dict):
        raise RuntimeError("coverage JSON must contain a files object")
    matches = [
        value
        for name, value in files.items()
        if isinstance(name, str) and _normalized_path(name).endswith(suffix)
    ]
    if len(matches) != 1 or not isinstance(matches[0], dict):
        raise RuntimeError(f"coverage JSON must contain exactly one {suffix}")
    summary = matches[0].get("summary")
    if not isinstance(summary, dict):
        raise RuntimeError(f"{suffix} must contain a coverage summary")
    branches = _number(summary.get("num_branches"), f"{suffix} num_branches")
    covered = _number(summary.get("covered_branches"), f"{suffix} covered_branches")
    if branches <= 0 or covered < 0 or covered > branches:
        raise RuntimeError(f"{suffix} has invalid branch totals")
    return round(covered * 100 / branches, 2)


def _pytest_summary(junit_path: Path) -> tuple[dict[str, int], int]:
    try:
        root = ET.parse(junit_path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise RuntimeError(f"cannot read pytest JUnit report at {junit_path}: {exc}") from exc
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    if not suites:
        raise RuntimeError("pytest JUnit report contains no testsuite")
    summary = {
        field: sum(int(suite.attrib.get(field, "0")) for suite in suites)
        for field in ("tests", "failures", "errors", "skipped")
    }
    posix_skips = 0
    for testcase in root.iter("testcase"):
        skipped = testcase.find("skipped")
        if skipped is None:
            continue
        identity = " ".join(
            (
                testcase.attrib.get("file", ""),
                testcase.attrib.get("classname", ""),
                testcase.attrib.get("name", ""),
                skipped.attrib.get("message", ""),
                skipped.text or "",
            )
        ).lower()
        if "test_resource_grants" in identity and "posix" in identity:
            posix_skips += 1
    return summary, posix_skips


def build_report(
    coverage_path: Path,
    junit_path: Path,
    candidate_commit: str,
) -> dict[str, Any]:
    if COMMIT.fullmatch(candidate_commit) is None:
        raise RuntimeError("candidate commit must be a full lowercase 40-character SHA")
    coverage = _load_object(coverage_path, "coverage JSON")
    totals = coverage.get("totals")
    if not isinstance(totals, dict):
        raise RuntimeError("coverage JSON must contain totals")
    total_percent = round(_number(totals.get("percent_covered"), "total coverage"), 2)
    if total_percent < 80:
        raise RuntimeError(f"total Python coverage is {total_percent}%, below 80%")
    branches = {
        name: _branch_coverage(coverage, suffix)
        for name, suffix in BRANCH_TARGETS.items()
    }
    incomplete = [name for name, percent in branches.items() if percent != 100]
    if incomplete:
        raise RuntimeError("branch coverage is below 100% for: " + ", ".join(incomplete))
    pytest_summary, posix_skips = _pytest_summary(junit_path)
    if pytest_summary["failures"] or pytest_summary["errors"]:
        raise RuntimeError("pytest JUnit report contains failures or errors")
    if posix_skips:
        raise RuntimeError(f"pytest skipped {posix_skips} POSIX contract tests")
    return {
        "schemaVersion": 1,
        "status": "passed",
        "candidateCommit": candidate_commit,
        "pythonCoveragePercent": total_percent,
        "posixContractSkips": posix_skips,
        "branchCoveragePercent": branches,
        "pytest": pytest_summary,
    }


def _write_atomic(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _head_commit(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate candidate-bound RC1 Python quality evidence")
    parser.add_argument("--coverage", type=Path, required=True)
    parser.add_argument("--junit", type=Path, required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    arguments = parser.parse_args(argv)

    root = arguments.root.resolve()
    if _head_commit(root) != arguments.candidate_commit:
        raise RuntimeError("candidate commit does not match the checked-out HEAD")
    report = build_report(
        arguments.coverage.resolve(),
        arguments.junit.resolve(),
        arguments.candidate_commit,
    )
    _write_atomic(arguments.output.resolve(), report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
