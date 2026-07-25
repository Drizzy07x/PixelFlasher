from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from scripts.rc1_preflight import (
    REQUIRED_ASSETS,
    REQUIRED_EVIDENCE,
    check_parity_inventory,
    run_preflight,
)


def _run(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        arguments,
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def _write_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")


def _capability(index: int, *, status: str = "native", gated: bool = True) -> dict[str, object]:
    return {
        "id": f"gate.{index}",
        "modernStatus": status,
        "releaseGate": gated,
    }


class Rc1PreflightTests(unittest.TestCase):
    def make_repository(self, root: Path) -> str:
        _run(root, "git", "init", "-q")
        _run(root, "git", "config", "user.name", "PixelFlasher Tests")
        _run(root, "git", "config", "user.email", "tests@pixelflasher.invalid")
        parity = [_capability(index) for index in range(52)]
        parity.append(
            {
                "id": "flash.wipe_shortcut",
                "modernStatus": "policy_absent",
                "releaseGate": False,
            }
        )
        _write_json(root / "docs" / "modern-ui-parity.json", {"capabilities": parity})
        (root / ".gitignore").write_text("build/\n", encoding="utf-8")

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        for name, relative in REQUIRED_ASSETS.items():
            path = root.joinpath(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            if name == "supportRecipientPublicKey":
                path.write_bytes(public_key)
            elif name == "otaRunnerDex":
                path.write_bytes(b"reproducible-ota-runner")
            elif name == "otaRunnerChecksum":
                dex = root / REQUIRED_ASSETS["otaRunnerDex"]
                path.write_text(hashlib.sha256(dex.read_bytes()).hexdigest() + "\n", encoding="ascii")
            elif name == "kernelSuLegacyDecision":
                _write_json(
                    path,
                    {
                        "schemaVersion": 1,
                        "provider": "legacy",
                        "usablePatchInputs": [],
                        "decision": "fail_closed",
                    },
                )
            else:
                _write_json(path, {"schemaVersion": 1, "name": name})

        _run(root, "git", "add", ".")
        _run(root, "git", "commit", "-qm", "candidate")
        commit = _run(root, "git", "rev-parse", "HEAD")
        _run(root, "git", "tag", "v10.0.0-rc.1")
        assets = {}
        for name, relative in REQUIRED_ASSETS.items():
            contents = root.joinpath(*relative.split("/")).read_bytes()
            assets[name] = {
                "path": relative,
                "sha256": hashlib.sha256(contents).hexdigest(),
            }
        reports = {
            "pythonQuality": {
                "schemaVersion": 1,
                "status": "passed",
                "candidateCommit": commit,
                "pythonCoveragePercent": 80,
                "posixContractSkips": 0,
                "branchCoveragePercent": {
                    "safetyPolicy": 100,
                    "planner": 100,
                    "postconditionObserver": 100,
                    "commandRegistry": 100,
                },
            },
            "packagedMatrix": {
                "schemaVersion": 1,
                "status": "passed",
                "candidateCommit": commit,
                "targets": [
                    "windows-x64",
                    "windows-arm64",
                    "macos-intel",
                    "macos-arm64",
                    "ubuntu-22",
                    "ubuntu-24",
                    "appimage-x11",
                    "appimage-wayland",
                ],
                "realWebview": True,
                "fakeAdbFastboot": True,
            },
            "hardwareValidation": {
                "schemaVersion": 1,
                "status": "passed",
                "candidateCommit": commit,
                "profiles": [
                    "pixel-ab-legacy",
                    "pixel-tensor-init-boot",
                    "pixel-android-17",
                ],
                "scenarios": [
                    "factory",
                    "ota",
                    "custom",
                    "recovery-sideload",
                    "locked",
                    "unlocked",
                    "disconnect",
                ],
            },
            "accessibilityValidation": {
                "schemaVersion": 1,
                "status": "passed",
                "candidateCommit": commit,
                "assistiveTechnologies": ["NVDA", "VoiceOver", "Orca"],
                "localeCount": 6,
                "highContrast": True,
                "zoom200Percent": True,
                "visualRegression": "passed",
            },
            "defectAudit": {
                "schemaVersion": 1,
                "status": "passed",
                "candidateCommit": commit,
                "openP0": 0,
                "openP1": 0,
            },
            "upstreamFreezeAudit": {
                "schemaVersion": 1,
                "status": "passed",
                "candidateCommit": commit,
                "upstreamSha": "a" * 40,
            },
        }
        ota_digest = hashlib.sha256(
            (root / REQUIRED_ASSETS["otaRunnerDex"]).read_bytes()
        ).hexdigest()
        reports["otaRunnerReproducibility"] = {
            "schemaVersion": 1,
            "status": "passed",
            "candidateCommit": commit,
            "rebuiltSha256": ota_digest,
            "packagedSha256": ota_digest,
        }
        reports["releaseSigning"] = {
            "schemaVersion": 1,
            "status": "passed",
            "candidateCommit": commit,
            "authenticode": True,
            "appleCodeSign": True,
            "appleNotarization": True,
            "gpgSha256Sums": True,
            "sbom": True,
            "provenanceAttestations": True,
        }
        reports["releaseControls"] = {
            "schemaVersion": 1,
            "status": "passed",
            "candidateCommit": commit,
            "protectedV10Tags": True,
            "releaseEnvironment": True,
            "candidateMilestone": True,
        }
        evidence = {}
        for name, relative in REQUIRED_EVIDENCE.items():
            path = root.joinpath(*relative.split("/"))
            _write_json(path, reports[name])
            evidence[name] = {
                "path": relative,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        _write_json(
            root / "candidate.json",
            {
                "schemaVersion": 1,
                "candidate": {"tag": "v10.0.0-rc.1", "commit": commit},
                "assets": assets,
                "evidence": evidence,
            },
        )
        return commit

    def test_accepts_complete_candidate_with_52_native_gates_and_one_policy_absent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-rc1-ready-") as directory:
            root = Path(directory)
            commit = self.make_repository(root)
            evidence = root / "candidate.json"
            platform_verifier = Mock(return_value="verified signed Platform Tools matrix")
            root_app_verifier = Mock(return_value="verified signed root-app matrix")
            report = run_preflight(
                root,
                tag="v10.0.0-rc.1",
                expected_commit=commit,
                evidence_manifest=evidence,
                platform_verifier=platform_verifier,
                root_app_verifier=root_app_verifier,
                firmware_verifier=lambda _path: "verified signed firmware catalog",
                scrcpy_verifier=lambda _path: "verified signed Scrcpy catalog",
                update_verifier=lambda _path: "verified signed update manifest",
            )
            self.assertTrue(report.ok, report.render())
            self.assertIn("52/52 release gates are native", report.render())
            platform_verifier.assert_called_once_with(
                root / "resources" / "platform-tools" / "runtime"
            )
            root_app_verifier.assert_called_once_with(root / "resources" / "root-apps" / "runtime")

    def test_parity_fails_for_non_native_gate_or_extra_policy_absent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-rc1-parity-") as directory:
            root = Path(directory)
            capabilities = [_capability(index) for index in range(52)]
            capabilities[7]["modernStatus"] = "partial"
            capabilities.append(
                {"id": "policy.one", "modernStatus": "policy_absent", "releaseGate": False}
            )
            capabilities.append(
                {"id": "policy.two", "modernStatus": "policy_absent", "releaseGate": False}
            )
            _write_json(root / "docs" / "modern-ui-parity.json", {"capabilities": capabilities})
            with self.assertRaisesRegex(RuntimeError, "not native"):
                check_parity_inventory(root)
            capabilities[7]["modernStatus"] = "native"
            _write_json(root / "docs" / "modern-ui-parity.json", {"capabilities": capabilities})
            with self.assertRaisesRegex(RuntimeError, "exactly one non-gate"):
                check_parity_inventory(root)

    def test_reports_dirty_tree_invalid_tag_and_missing_evidence_without_short_circuiting(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-rc1-blocked-") as directory:
            root = Path(directory)
            _run(root, "git", "init", "-q")
            _run(root, "git", "config", "user.name", "PixelFlasher Tests")
            _run(root, "git", "config", "user.email", "tests@pixelflasher.invalid")
            (root / "dirty.txt").write_text("dirty", encoding="utf-8")
            report = run_preflight(root, tag="v10.0.0-beta.1")
            codes = {check.code for check in report.blockers}
            self.assertIn("git.clean", codes)
            self.assertIn("git.candidate", codes)
            self.assertIn("candidate.evidence", codes)
            self.assertIn("asset.platformToolsCatalog", codes)
            self.assertIn("working tree is not clean", report.render())
            self.assertIn("candidate tag must match v10.0.0-rc.N", report.render())

    def test_asset_digest_mismatch_is_a_named_blocker(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-rc1-digest-") as directory:
            root = Path(directory)
            commit = self.make_repository(root)
            evidence = root / "candidate.json"
            target = root / REQUIRED_ASSETS["firmwareCatalog"]
            target.write_text('{"tampered":true}', encoding="utf-8")
            with patch("scripts.rc1_preflight._git") as git:
                def fake_git(_root: Path, *arguments: str) -> str:
                    if arguments[0] == "status":
                        return ""
                    if arguments[0] == "rev-parse":
                        return commit
                    raise AssertionError(arguments)

                git.side_effect = fake_git
                report = run_preflight(
                    root,
                    tag="v10.0.0-rc.1",
                    evidence_manifest=evidence,
                    platform_verifier=lambda _path: "verified",
                    root_app_verifier=lambda _path: "verified",
                    firmware_verifier=lambda _path: "verified",
                    scrcpy_verifier=lambda _path: "verified",
                    update_verifier=lambda _path: "verified",
                )
            blocker = next(
                check for check in report.blockers if check.code == "asset.firmwareCatalog"
            )
            self.assertIn("digest mismatch", blocker.detail)

    def test_ota_runner_rejects_a_binary_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-rc1-ota-") as directory:
            root = Path(directory)
            commit = self.make_repository(root)
            evidence = root / "candidate.json"
            dex = root / REQUIRED_ASSETS["otaRunnerDex"]
            dex.write_bytes(b"tampered")
            manifest = json.loads(evidence.read_text(encoding="utf-8"))
            manifest["assets"]["otaRunnerDex"]["sha256"] = hashlib.sha256(
                dex.read_bytes()
            ).hexdigest()
            _write_json(evidence, manifest)
            with patch("scripts.rc1_preflight._git") as git:
                git.side_effect = lambda _root, *arguments: (
                    "" if arguments[0] == "status" else commit
                )
                report = run_preflight(
                    root,
                    tag="v10.0.0-rc.1",
                    evidence_manifest=evidence,
                    platform_verifier=lambda _path: "verified",
                    root_app_verifier=lambda _path: "verified",
                    firmware_verifier=lambda _path: "verified",
                    scrcpy_verifier=lambda _path: "verified",
                    update_verifier=lambda _path: "verified",
                )
            blocker = next(
                check for check in report.blockers if check.code == "asset.otaRunnerDex"
            )
            self.assertIn("does not match its pinned SHA-256", blocker.detail)


if __name__ == "__main__":
    unittest.main()
