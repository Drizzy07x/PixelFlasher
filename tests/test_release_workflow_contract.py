import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "main.yml"


class ReleaseWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text(encoding="utf-8")
        cls.workflow = yaml.safe_load(cls.source)

    def test_release_needs_every_same_run_platform_build(self):
        release = self.workflow["jobs"]["release"]
        self.assertEqual(
            {
                "windows-x64",
                "windows-arm64",
                "ubuntu-22",
                "ubuntu-24",
                "appimage-x64",
                "macos",
            },
            set(release["needs"]),
        )
        self.assertIn("success()", release["if"])
        self.assertIn("refs/tags/v10.", release["if"])
        self.assertNotIn("always()", self.source)

    def test_release_never_searches_or_reuses_prior_run_artifacts(self):
        forbidden = (
            "check_artifacts",
            "head_sha=",
            "workflow_runs",
            "gh run download $RUN_ID",
            "previous runs",
        )
        for marker in forbidden:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, self.source)
        self.assertIn(
            "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
            self.source,
        )
        self.assertIn('pattern: "* Artifacts"', self.source)

    def test_supply_chain_evidence_and_signing_are_mandatory(self):
        required = (
            "anchore/sbom-action",
            "actions/attest-build-provenance",
            "release-manifest.json",
            "SHA256SUMS.asc",
            "RELEASE_SIGNING_KEY is mandatory",
            "gpg --batch --verify",
            "environment: release",
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.source)

    def test_stable_release_cannot_be_created_by_workflow_dispatch(self):
        release_if = self.workflow["jobs"]["release"]["if"]
        self.assertNotIn("workflow_dispatch", release_if)
        self.assertIn("github.event_name == 'push'", release_if)


if __name__ == "__main__":
    unittest.main()
