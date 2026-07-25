from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.generate_python_quality_report import BRANCH_TARGETS, build_report

COMMIT = "a" * 40


def _coverage(*, total: float = 81.67, missing_target: str | None = None) -> dict[str, object]:
    files = {}
    for target, path in BRANCH_TARGETS.items():
        files[path] = {
            "summary": {
                "num_branches": 10,
                "covered_branches": 9 if target == missing_target else 10,
            }
        }
    return {"totals": {"percent_covered": total}, "files": files}


def _junit(*, failures: int = 0, posix_skip: bool = False) -> str:
    skip = (
        '<skipped message="POSIX descriptor cleanup contract"/>'
        if posix_skip
        else ""
    )
    skipped = 1 if posix_skip else 0
    return (
        f'<testsuites tests="2" failures="{failures}" errors="0" skipped="{skipped}">'
        f'<testsuite tests="2" failures="{failures}" errors="0" skipped="{skipped}">'
        '<testcase classname="tests.test_core" name="test_core"/>'
        '<testcase classname="tests.test_resource_grants.ResourceGrantTests" '
        f'name="test_posix_contract">{skip}</testcase>'
        "</testsuite></testsuites>"
    )


class GeneratePythonQualityReportTests(unittest.TestCase):
    def _write_inputs(
        self,
        root: Path,
        *,
        coverage: dict[str, object] | None = None,
        junit: str | None = None,
    ) -> tuple[Path, Path]:
        coverage_path = root / "coverage.json"
        junit_path = root / "pytest.xml"
        coverage_path.write_text(
            json.dumps(coverage or _coverage()),
            encoding="utf-8",
        )
        junit_path.write_text(junit or _junit(), encoding="utf-8")
        return coverage_path, junit_path

    def test_builds_candidate_bound_report_from_measured_results(self):
        with tempfile.TemporaryDirectory() as directory:
            coverage_path, junit_path = self._write_inputs(Path(directory))

            report = build_report(coverage_path, junit_path, COMMIT)

        self.assertEqual(1, report["schemaVersion"])
        self.assertEqual("passed", report["status"])
        self.assertEqual(COMMIT, report["candidateCommit"])
        self.assertEqual(81.67, report["pythonCoveragePercent"])
        self.assertEqual(0, report["posixContractSkips"])
        self.assertEqual(
            {target: 100.0 for target in BRANCH_TARGETS},
            report["branchCoveragePercent"],
        )

    def test_rejects_coverage_below_global_threshold(self):
        with tempfile.TemporaryDirectory() as directory:
            coverage_path, junit_path = self._write_inputs(
                Path(directory),
                coverage=_coverage(total=79.99),
            )

            with self.assertRaisesRegex(RuntimeError, "below 80%"):
                build_report(coverage_path, junit_path, COMMIT)

    def test_rejects_incomplete_safety_branch_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            coverage_path, junit_path = self._write_inputs(
                Path(directory),
                coverage=_coverage(missing_target="safetyPolicy"),
            )

            with self.assertRaisesRegex(RuntimeError, "safetyPolicy"):
                build_report(coverage_path, junit_path, COMMIT)

    def test_rejects_skipped_posix_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            coverage_path, junit_path = self._write_inputs(
                Path(directory),
                junit=_junit(posix_skip=True),
            )

            with self.assertRaisesRegex(RuntimeError, "POSIX"):
                build_report(coverage_path, junit_path, COMMIT)

    def test_rejects_failed_pytest_report(self):
        with tempfile.TemporaryDirectory() as directory:
            coverage_path, junit_path = self._write_inputs(
                Path(directory),
                junit=_junit(failures=1),
            )

            with self.assertRaisesRegex(RuntimeError, "failures or errors"):
                build_report(coverage_path, junit_path, COMMIT)

    def test_rejects_noncanonical_candidate_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            coverage_path, junit_path = self._write_inputs(Path(directory))

            with self.assertRaisesRegex(RuntimeError, "full lowercase"):
                build_report(coverage_path, junit_path, "abc")
