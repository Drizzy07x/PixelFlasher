#!/usr/bin/env python3
"""Fail-closed local preflight for a PixelFlasher 10 RC candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from scripts.verify_firmware_catalog import verify as verify_firmware  # noqa: E402
from scripts.verify_keybox_revocations import verify as verify_keybox  # noqa: E402
from scripts.verify_platform_tools_catalog import verify as verify_platform_tools  # noqa: E402
from scripts.verify_root_app_catalog import verify as verify_root_apps  # noqa: E402
from scripts.verify_scrcpy_catalog import verify as verify_scrcpy  # noqa: E402
from scripts.verify_update_manifest import verify as verify_update  # noqa: E402

RC_TAG = re.compile(r"^v10\.0\.0-rc\.(?:[1-9][0-9]*)$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")

REQUIRED_ASSETS: Mapping[str, str] = {
    "platformToolsCatalog": "resources/platform-tools/runtime/catalog.json",
    "rootAppCatalog": "resources/root-apps/runtime/catalog.json",
    "firmwareCatalog": "resources/firmware/runtime/catalog.json",
    "firmwareTrustRoots": "resources/firmware/runtime/trust-roots.json",
    "firmwareValidationFixtures": "resources/firmware/runtime/validation-fixtures.json",
    "scrcpyCatalog": "resources/scrcpy/runtime/catalog.json",
    "updateManifest": "resources/updates/runtime/manifest.json",
    "otaRunnerDex": "resources/ota-runner/runtime/pf-ota-runner.dex",
    "otaRunnerChecksum": "resources/ota-runner/runtime/pf-ota-runner.sha256",
    "otaRunnerToolchainLock": "resources/ota-runner/toolchain-lock.json",
    "supportRecipientPublicKey": "resources/support/recipient-public-key.pem",
    "keyboxRevocationEvidence": "resources/keybox/revocations.json",
    "bootPatchManifest": "resources/boot-patch/runtime/patch-resources.json",
    "kernelSuLegacyDecision": "resources/boot-patch/kernelsu-legacy-assessment.json",
    "androidDeviceCatalog": "android_devices.json",
}

REQUIRED_EVIDENCE: Mapping[str, str] = {
    "pythonQuality": "build/rc1-evidence/python-quality.json",
    "packagedMatrix": "build/rc1-evidence/packaged-matrix.json",
    "hardwareValidation": "build/rc1-evidence/hardware-validation.json",
    "accessibilityValidation": "build/rc1-evidence/accessibility-validation.json",
    "defectAudit": "build/rc1-evidence/defect-audit.json",
    "upstreamFreezeAudit": "build/rc1-evidence/upstream-freeze-audit.json",
    "otaRunnerReproducibility": "build/rc1-evidence/ota-runner-reproducibility.json",
    "releaseSigning": "build/rc1-evidence/release-signing.json",
    "releaseControls": "build/rc1-evidence/release-controls.json",
}

PACKAGED_TARGETS = frozenset(
    {
        "windows-x64",
        "windows-arm64",
        "macos-intel",
        "macos-arm64",
        "ubuntu-22",
        "ubuntu-24",
        "appimage-x11",
        "appimage-wayland",
    }
)
HARDWARE_PROFILES = frozenset({"pixel-ab-legacy", "pixel-tensor-init-boot", "pixel-android-17"})
HARDWARE_SCENARIOS = frozenset(
    {
        "factory",
        "ota",
        "custom",
        "recovery-sideload",
        "locked",
        "unlocked",
        "disconnect",
    }
)
ACCESSIBILITY_TOOLS = frozenset({"NVDA", "VoiceOver", "Orca"})


@dataclass(frozen=True, slots=True)
class Check:
    code: str
    ok: bool
    detail: str


@dataclass(frozen=True, slots=True)
class PreflightReport:
    checks: tuple[Check, ...]

    @property
    def ok(self) -> bool:
        return all(check.ok for check in self.checks)

    @property
    def blockers(self) -> tuple[Check, ...]:
        return tuple(check for check in self.checks if not check.ok)

    def render(self) -> str:
        state = "READY" if self.ok else "BLOCKED"
        lines = [f"PixelFlasher 10 RC1 preflight: {state}"]
        for check in self.checks:
            marker = "PASS" if check.ok else "BLOCK"
            lines.append(f"[{marker}] {check.code}: {check.detail}")
        lines.append(
            "No RC1 blockers found."
            if self.ok
            else f"{len(self.blockers)} blocker(s) must be resolved before tagging RC1."
        )
        return "\n".join(lines)

    def as_json(self) -> dict[str, object]:
        return {
            "ready": self.ok,
            "blockerCount": len(self.blockers),
            "checks": [{"code": check.code, "ok": check.ok, "detail": check.detail} for check in self.checks],
        }


def _check(code: str, action: Callable[[], str]) -> Check:
    try:
        return Check(code, True, action())
    except Exception as exc:
        return Check(code, False, str(exc))


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"{label} is missing: {path}") from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{label} is unreadable or invalid JSON: {path}") from exc
    if not isinstance(raw, dict):
        raise RuntimeError(f"{label} must be a JSON object: {path}")
    return raw


def check_parity_inventory(root: Path) -> str:
    document = _load_object(root / "docs" / "modern-ui-parity.json", "parity inventory")
    capabilities = document.get("capabilities")
    if not isinstance(capabilities, list):
        raise RuntimeError("parity inventory capabilities must be an array")

    ids: set[str] = set()
    gated: list[dict[str, Any]] = []
    non_gated: list[dict[str, Any]] = []
    for index, raw in enumerate(capabilities):
        if not isinstance(raw, dict):
            raise RuntimeError(f"parity capability at index {index} must be an object")
        capability_id = raw.get("id")
        if not isinstance(capability_id, str) or not capability_id:
            raise RuntimeError(f"parity capability at index {index} has no valid id")
        if capability_id in ids:
            raise RuntimeError(f"parity inventory contains duplicate id {capability_id}")
        ids.add(capability_id)
        release_gate = raw.get("releaseGate")
        if type(release_gate) is not bool:
            raise RuntimeError(f"{capability_id} releaseGate must be a boolean")
        (gated if release_gate else non_gated).append(raw)

    if len(gated) != 52:
        raise RuntimeError(f"expected exactly 52 release gates, found {len(gated)}")
    incomplete = [
        f"{entry['id']}={entry.get('modernStatus')!r}" for entry in gated if entry.get("modernStatus") != "native"
    ]
    if incomplete:
        raise RuntimeError(f"{len(incomplete)} of 52 release gates are not native: " + ", ".join(incomplete))
    if len(non_gated) != 1:
        raise RuntimeError(f"expected exactly one non-gate, found {len(non_gated)}")
    policy = non_gated[0]
    if policy.get("modernStatus") != "policy_absent":
        raise RuntimeError(
            f"the sole non-gate {policy['id']} must be policy_absent, found {policy.get('modernStatus')!r}"
        )
    policy_absent = [entry["id"] for entry in capabilities if entry.get("modernStatus") == "policy_absent"]
    if policy_absent != [policy["id"]]:
        raise RuntimeError("policy_absent may be used only by the sole non-gate; found " + ", ".join(policy_absent))
    return f"52/52 release gates are native; sole non-gate {policy['id']} is policy_absent"


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ("git", *arguments),
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown git error"
        raise RuntimeError(f"git {' '.join(arguments)} failed: {detail}")
    return completed.stdout.rstrip("\r\n")


def resolve_candidate_tag(root: Path, supplied_tag: str | None) -> str:
    tag = supplied_tag or os.environ.get("GITHUB_REF_NAME")
    if not tag:
        candidates = [
            value for value in _git(root, "tag", "--points-at", "HEAD").splitlines() if RC_TAG.fullmatch(value)
        ]
        if len(candidates) != 1:
            raise RuntimeError("provide --tag or check out exactly one v10.0.0-rc.N tag at HEAD")
        tag = candidates[0]
    if RC_TAG.fullmatch(tag) is None:
        raise RuntimeError(f"candidate tag must match v10.0.0-rc.N, found {tag!r}")
    return tag


def check_git_candidate(
    root: Path,
    *,
    supplied_tag: str | None,
    expected_commit: str | None,
    evidence_manifest: Path,
) -> tuple[str, str, tuple[Check, ...]]:
    checks: list[Check] = []
    resolved: dict[str, str] = {}

    def clean_tree() -> str:
        status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
        if status:
            lines = status.splitlines()
            try:
                relative_evidence = evidence_manifest.resolve().relative_to(root).as_posix()
            except ValueError:
                relative_evidence = ""
            lines = [
                line
                for line in lines
                if not (line.startswith("?? ") and line[3:].replace("\\", "/") == relative_evidence)
            ]
            if not lines:
                return "working tree is clean; the exact untracked candidate evidence input is excluded"
            paths = [line[3:] if len(line) > 3 else line for line in lines]
            preview = ", ".join(paths[:12])
            suffix = f" (+{len(paths) - 12} more)" if len(paths) > 12 else ""
            raise RuntimeError(f"working tree is not clean: {preview}{suffix}")
        return "working tree is clean, including untracked files"

    checks.append(_check("git.clean", clean_tree))

    def candidate_ref() -> str:
        tag = resolve_candidate_tag(root, supplied_tag)
        head = _git(root, "rev-parse", "HEAD").lower()
        tagged = _git(root, "rev-parse", f"refs/tags/{tag}^{{commit}}").lower()
        if head != tagged:
            raise RuntimeError(f"{tag} resolves to {tagged}, but HEAD is {head}")
        requested = expected_commit or os.environ.get("GITHUB_SHA")
        if requested:
            requested = requested.strip().lower()
            if COMMIT.fullmatch(requested) is None:
                raise RuntimeError(f"expected commit must be a full 40-character SHA, found {requested!r}")
            if requested != head:
                raise RuntimeError(f"expected commit {requested} does not match HEAD {head}")
        resolved.update(tag=tag, commit=head)
        return f"{tag} resolves to candidate commit {head}"

    checks.append(_check("git.candidate", candidate_ref))
    return (
        resolved.get("tag", supplied_tag or ""),
        resolved.get("commit", ""),
        tuple(checks),
    )


def load_candidate_manifest(path: Path) -> dict[str, Any]:
    document = _load_object(path, "candidate evidence manifest")
    if set(document) != {"schemaVersion", "candidate", "assets", "evidence"}:
        raise RuntimeError(
            "candidate evidence manifest fields must be exactly schemaVersion, candidate, assets, evidence"
        )
    if document["schemaVersion"] != 1:
        raise RuntimeError("candidate evidence manifest schemaVersion must be 1")
    if (
        not isinstance(document["candidate"], dict)
        or not isinstance(document["assets"], dict)
        or not isinstance(document["evidence"], dict)
    ):
        raise RuntimeError("candidate, assets, and evidence must be JSON objects")
    return document


def check_candidate_metadata(document: Mapping[str, Any], tag: str, commit: str) -> str:
    candidate = document["candidate"]
    if set(candidate) != {"tag", "commit"}:
        raise RuntimeError("candidate metadata fields must be exactly tag and commit")
    if not tag or not commit:
        raise RuntimeError("candidate metadata cannot be checked until the Git candidate is valid")
    if candidate["tag"] != tag:
        raise RuntimeError(f"manifest tag {candidate['tag']!r} does not match {tag!r}")
    manifest_commit = candidate["commit"]
    if not isinstance(manifest_commit, str) or COMMIT.fullmatch(manifest_commit) is None:
        raise RuntimeError("manifest candidate commit must be a lowercase full SHA")
    if manifest_commit != commit:
        raise RuntimeError(f"manifest commit {manifest_commit} does not match HEAD {commit}")
    return f"candidate evidence is bound to {tag} at {commit}"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _asset_path(root: Path, expected: str) -> Path:
    relative = PurePosixPath(expected)
    if relative.is_absolute() or ".." in relative.parts:
        raise RuntimeError(f"invalid required asset path {expected!r}")
    return root.joinpath(*relative.parts)


def check_asset_binding(
    root: Path,
    document: Mapping[str, Any],
    name: str,
    expected_path: str,
    *,
    collection: str = "assets",
) -> Path:
    inventory = document[collection]
    descriptor = inventory.get(name)
    if not isinstance(descriptor, dict) or set(descriptor) != {"path", "sha256"}:
        raise RuntimeError(f"{name} must have exactly path and sha256 metadata")
    if descriptor["path"] != expected_path:
        raise RuntimeError(f"{name} must use {expected_path}, found {descriptor['path']!r}")
    digest = descriptor["sha256"]
    if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
        raise RuntimeError(f"{name} sha256 must be 64 lowercase hexadecimal characters")
    path = _asset_path(root, expected_path)
    if not path.is_file():
        raise RuntimeError(f"{name} is missing: {expected_path}")
    if path.stat().st_size <= 0:
        raise RuntimeError(f"{name} is empty: {expected_path}")
    actual = _sha256(path)
    if actual != digest:
        raise RuntimeError(f"{name} digest mismatch: expected {digest}, found {actual}")
    return path


def _validate_json_asset(path: Path, name: str) -> None:
    document = _load_object(path, name)
    if not document:
        raise RuntimeError(f"{name} must not be an empty JSON object")


def _validate_support_key(path: Path) -> None:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError("supportRecipientPublicKey is not a valid PEM public key") from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
        raise RuntimeError("supportRecipientPublicKey must be an RSA public key of at least 2048 bits")


def _validate_ota_runner(root: Path) -> None:
    dex = _asset_path(root, REQUIRED_ASSETS["otaRunnerDex"])
    checksum = _asset_path(root, REQUIRED_ASSETS["otaRunnerChecksum"])
    try:
        pinned = checksum.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise RuntimeError("OTA runner checksum is unreadable") from exc
    if SHA256.fullmatch(pinned) is None or not dex.is_file() or _sha256(dex) != pinned:
        raise RuntimeError("OTA runner DEX is missing or does not match its pinned SHA-256")


def _validate_kernel_su_legacy_decision(path: Path) -> None:
    document = _load_object(path, "kernelSuLegacyDecision")
    if document.get("schemaVersion") != 1 or document.get("provider") != "legacy":
        raise RuntimeError("kernelSuLegacyDecision has an invalid schema or provider")
    has_inputs = isinstance(document.get("usablePatchInputs"), list) and bool(document["usablePatchInputs"])
    if not has_inputs and document.get("decision") != "fail_closed":
        raise RuntimeError("KernelSU Legacy must provide reproducible patch inputs or remain formally fail_closed")


def check_asset(
    root: Path,
    document: Mapping[str, Any],
    name: str,
    expected_path: str,
    *,
    platform_verifier: Callable[[Path], str],
    root_app_verifier: Callable[[Path], str],
    firmware_verifier: Callable[[Path], str],
    scrcpy_verifier: Callable[[Path], str],
    update_verifier: Callable[[Path], str],
    keybox_verifier: Callable[[Path], str],
) -> str:
    path = check_asset_binding(root, document, name, expected_path)
    if name == "platformToolsCatalog":
        verification = platform_verifier(path.parent)
    elif name == "rootAppCatalog":
        verification = root_app_verifier(path.parent)
    elif name == "firmwareCatalog":
        verification = firmware_verifier(path.parent)
    elif name == "scrcpyCatalog":
        verification = scrcpy_verifier(path.parent)
    elif name == "updateManifest":
        verification = update_verifier(path)
    elif name == "keyboxRevocationEvidence":
        verification = keybox_verifier(path)
    elif name == "supportRecipientPublicKey":
        _validate_support_key(path)
        verification = "valid production RSA recipient public key"
    elif name in {"otaRunnerDex", "otaRunnerChecksum"}:
        _validate_ota_runner(root)
        verification = "OTA fallback runner DEX matches its pinned SHA-256"
    elif name == "otaRunnerToolchainLock":
        _validate_json_asset(path, name)
        verification = "non-empty OTA runner toolchain lock"
    elif name == "kernelSuLegacyDecision":
        _validate_kernel_su_legacy_decision(path)
        verification = "KernelSU Legacy input/exclusion decision is explicit"
    else:
        _validate_json_asset(path, name)
        verification = "non-empty JSON asset"
    return f"{expected_path} is SHA-256 bound; {verification}"


def check_evidence_report(
    root: Path,
    document: Mapping[str, Any],
    name: str,
    expected_path: str,
    candidate_commit: str,
) -> str:
    path = check_asset_binding(
        root,
        document,
        name,
        expected_path,
        collection="evidence",
    )
    report = _load_object(path, name)
    if report.get("schemaVersion") != 1 or report.get("status") != "passed":
        raise RuntimeError(f"{name} must use schemaVersion 1 and status 'passed'")
    if report.get("candidateCommit") != candidate_commit:
        raise RuntimeError(f"{name} is not bound to candidate commit {candidate_commit}")
    if name == "pythonQuality":
        coverage = report.get("pythonCoveragePercent")
        if isinstance(coverage, bool) or not isinstance(coverage, (int, float)) or coverage < 80:
            raise RuntimeError("pythonQuality must record at least 80% Python coverage")
        if report.get("posixContractSkips") != 0:
            raise RuntimeError("pythonQuality must record zero skipped POSIX contracts")
        branch_targets = report.get("branchCoveragePercent")
        required_modules = {
            "safetyPolicy",
            "planner",
            "postconditionObserver",
            "commandRegistry",
        }
        if not isinstance(branch_targets, dict) or any(
            branch_targets.get(module) != 100 for module in required_modules
        ):
            raise RuntimeError("pythonQuality must record 100% branch coverage for all four RC safety modules")
    elif name == "packagedMatrix":
        if set(report.get("targets", ())) != PACKAGED_TARGETS:
            raise RuntimeError("packagedMatrix does not cover every required release target/backend")
        if report.get("realWebview") is not True or report.get("fakeAdbFastboot") is not True:
            raise RuntimeError("packagedMatrix must pass real WebView and fake ADB/Fastboot journeys")
    elif name == "hardwareValidation":
        if set(report.get("profiles", ())) != HARDWARE_PROFILES:
            raise RuntimeError("hardwareValidation does not cover all three required Pixel profiles")
        if set(report.get("scenarios", ())) != HARDWARE_SCENARIOS:
            raise RuntimeError("hardwareValidation does not cover every required mutation/failure scenario")
    elif name == "accessibilityValidation":
        if set(report.get("assistiveTechnologies", ())) != ACCESSIBILITY_TOOLS:
            raise RuntimeError("accessibilityValidation must cover NVDA, VoiceOver, and Orca")
        if (
            report.get("localeCount") != 6
            or report.get("highContrast") is not True
            or report.get("zoom200Percent") is not True
            or report.get("visualRegression") != "passed"
        ):
            raise RuntimeError(
                "accessibilityValidation must cover six locales, high contrast, 200% zoom, and visual regression"
            )
    elif name == "defectAudit":
        if report.get("openP0") != 0 or report.get("openP1") != 0:
            raise RuntimeError("defectAudit must record zero open P0 and P1 defects")
    elif name == "upstreamFreezeAudit":
        upstream_sha = report.get("upstreamSha")
        if not isinstance(upstream_sha, str) or COMMIT.fullmatch(upstream_sha) is None:
            raise RuntimeError("upstreamFreezeAudit must record the full audited upstream/main SHA")
    elif name == "otaRunnerReproducibility":
        rebuilt = report.get("rebuiltSha256")
        packaged = report.get("packagedSha256")
        if (
            not isinstance(rebuilt, str)
            or SHA256.fullmatch(rebuilt) is None
            or rebuilt != packaged
            or rebuilt != _sha256(_asset_path(root, REQUIRED_ASSETS["otaRunnerDex"]))
        ):
            raise RuntimeError("otaRunnerReproducibility must prove a byte-identical rebuild of the packaged DEX")
    elif name == "releaseSigning":
        required = {
            "authenticode",
            "appleCodeSign",
            "appleNotarization",
            "gpgSha256Sums",
            "sbom",
            "provenanceAttestations",
        }
        if any(report.get(field) is not True for field in required):
            raise RuntimeError("releaseSigning must prove every signature and supply-chain artifact")
    elif name == "releaseControls":
        if (
            report.get("protectedV10Tags") is not True
            or report.get("releaseEnvironment") is not True
            or report.get("candidateMilestone") is not True
        ):
            raise RuntimeError(
                "releaseControls must prove protected v10 tags, release environment, and candidate milestone"
            )
    return f"{expected_path} passed and is SHA-256/candidate bound"


def run_preflight(
    root: Path,
    *,
    tag: str | None = None,
    expected_commit: str | None = None,
    evidence_manifest: Path | None = None,
    platform_verifier: Callable[[Path], str] = verify_platform_tools,
    root_app_verifier: Callable[[Path], str] = verify_root_apps,
    firmware_verifier: Callable[[Path], str] = verify_firmware,
    scrcpy_verifier: Callable[[Path], str] = verify_scrcpy,
    update_verifier: Callable[[Path], str] = verify_update,
    keybox_verifier: Callable[[Path], str] = verify_keybox,
) -> PreflightReport:
    root = root.resolve()
    manifest_path = evidence_manifest or root / "build" / "rc1-candidate.json"
    if not manifest_path.is_absolute():
        manifest_path = root / manifest_path
    checks: list[Check] = [_check("parity.inventory", lambda: check_parity_inventory(root))]
    resolved_tag, resolved_commit, git_checks = check_git_candidate(
        root,
        supplied_tag=tag,
        expected_commit=expected_commit,
        evidence_manifest=manifest_path,
    )
    checks.extend(git_checks)

    manifest: dict[str, Any] | None = None

    def evidence() -> str:
        nonlocal manifest
        manifest = load_candidate_manifest(manifest_path)
        try:
            display_path = manifest_path.relative_to(root)
        except ValueError:
            display_path = manifest_path
        return f"loaded schema 1 candidate evidence from {display_path}"

    checks.append(_check("candidate.evidence", evidence))
    if manifest is None:
        checks.append(
            Check(
                "candidate.metadata",
                False,
                "candidate metadata cannot be checked because the evidence manifest is invalid",
            )
        )
        for name, expected_path in REQUIRED_ASSETS.items():
            asset_path = _asset_path(root, expected_path)
            detail = "asset cannot be accepted without a valid candidate evidence manifest"
            if not asset_path.is_file():
                detail += f"; required production asset is also missing: {expected_path}"
            checks.append(
                Check(
                    f"asset.{name}",
                    False,
                    detail,
                )
            )
        for name, expected_path in REQUIRED_EVIDENCE.items():
            checks.append(
                Check(
                    f"evidence.{name}",
                    False,
                    "report cannot be accepted without a valid candidate evidence manifest"
                    + (
                        f"; required report is also missing: {expected_path}"
                        if not _asset_path(root, expected_path).is_file()
                        else ""
                    ),
                )
            )
        return PreflightReport(tuple(checks))

    checks.append(
        _check(
            "candidate.metadata",
            lambda: check_candidate_metadata(manifest, resolved_tag, resolved_commit),
        )
    )
    for name, expected_path in REQUIRED_ASSETS.items():
        checks.append(
            _check(
                f"asset.{name}",
                lambda name=name, expected_path=expected_path: check_asset(
                    root,
                    manifest,
                    name,
                    expected_path,
                    platform_verifier=platform_verifier,
                    root_app_verifier=root_app_verifier,
                    firmware_verifier=firmware_verifier,
                    scrcpy_verifier=scrcpy_verifier,
                    update_verifier=update_verifier,
                    keybox_verifier=keybox_verifier,
                ),
            )
        )
    extra_assets = sorted(set(manifest["assets"]) - set(REQUIRED_ASSETS))
    checks.append(
        Check(
            "asset.inventory",
            not extra_assets,
            (
                f"candidate evidence contains exactly the {len(REQUIRED_ASSETS)} required production assets"
                if not extra_assets
                else "unrecognized candidate assets: " + ", ".join(extra_assets)
            ),
        )
    )
    for name, expected_path in REQUIRED_EVIDENCE.items():
        checks.append(
            _check(
                f"evidence.{name}",
                lambda name=name, expected_path=expected_path: check_evidence_report(
                    root,
                    manifest,
                    name,
                    expected_path,
                    resolved_commit,
                ),
            )
        )
    extra_evidence = sorted(set(manifest["evidence"]) - set(REQUIRED_EVIDENCE))
    checks.append(
        Check(
            "evidence.inventory",
            not extra_evidence,
            (
                f"candidate evidence contains exactly the {len(REQUIRED_EVIDENCE)} required reports"
                if not extra_evidence
                else "unrecognized evidence reports: " + ", ".join(extra_evidence)
            ),
        )
    )
    return PreflightReport(tuple(checks))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--tag", help="candidate tag; defaults to GITHUB_REF_NAME or the tag at HEAD")
    parser.add_argument("--expected-commit", help="full candidate SHA; defaults to GITHUB_SHA when set")
    parser.add_argument(
        "--evidence-manifest",
        type=Path,
        help="defaults to build/rc1-candidate.json below --root",
    )
    parser.add_argument("--json", action="store_true", dest="json_output")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    report = run_preflight(
        arguments.root,
        tag=arguments.tag,
        expected_commit=arguments.expected_commit,
        evidence_manifest=arguments.evidence_manifest,
    )
    if arguments.json_output:
        print(json.dumps(report.as_json(), indent=2, sort_keys=True))
    else:
        print(report.render())
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
