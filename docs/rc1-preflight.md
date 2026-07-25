# RC1 preflight

`scripts/rc1_preflight.py` is the fail-closed decision boundary for a
PixelFlasher 10 release candidate. It is intended to run after the candidate
commit is clean and tagged, once production assets and candidate-bound reports
have been collected.

```text
python scripts/rc1_preflight.py \
  --tag v10.0.0-rc.1 \
  --expected-commit <full-40-character-sha> \
  --evidence-manifest build/rc1-candidate.json
```

Exit code `0` means every declared check passed. Exit code `1` means the
candidate is blocked. `--json` emits the same decision as structured output.

## Candidate manifest

The manifest uses schema version 1 and contains only four top-level fields:

```json
{
  "schemaVersion": 1,
  "candidate": {
    "tag": "v10.0.0-rc.1",
    "commit": "<full lowercase SHA>"
  },
  "assets": {
    "<asset name>": {
      "path": "<required repository-relative path>",
      "sha256": "<lowercase SHA-256>"
    }
  },
  "evidence": {
    "<report name>": {
      "path": "<required repository-relative path>",
      "sha256": "<lowercase SHA-256>"
    }
  }
}
```

The accepted asset and report names are deliberately closed in
`REQUIRED_ASSETS` and `REQUIRED_EVIDENCE`. Extra, missing, renamed or
path-substituted entries fail.

The current firmware, Scrcpy and update production catalogs are not yet
provisioned and do not yet have dedicated signature verifiers. Their default
preflight handlers deliberately fail closed even if a file is placed at the
expected path. Those catalog formats and their production verifiers must be
implemented together; a checksum-only placeholder is not accepted.

## Required report envelope

Every JSON report under `build/rc1-evidence/` must contain:

- `schemaVersion: 1`
- `status: "passed"`
- `candidateCommit` equal to the tagged commit
- the report-specific fields checked by `check_evidence_report`

The reports cover Python quality and POSIX contracts, the packaged desktop
matrix, Pixel hardware, accessibility/visual regression, P0/P1 defects,
upstream freeze, OTA runner reproducibility, release signing/supply chain and
remote release controls.

Reports are evidence, not switches. The preflight verifies their exact
SHA-256 binding and checks their required fields; it does not turn a failing
job or an incomplete manual run into a pass.

## Ordering

1. Provision, verify and commit the required production catalogs, trust roots
   and recipient keys.
2. Freeze the intended commit, complete the upstream audit and create the
   protected RC tag.
3. Build and sign the candidate artifacts, then run the complete local,
   packaged, hardware and accessibility matrices against that exact tag.
4. Retain the ignored `build/rc1-evidence/` reports with
   `candidateCommit` set to the tagged SHA.
5. Generate the ignored `build/rc1-candidate.json` binding those reports and
   the committed production assets by SHA-256.
6. Run the preflight against the tag and full commit.
7. Publish only if the preflight is ready and same-run release controls also
   pass.

The current development branch is expected to fail this command until all 52
release gates are native and the production/evidence inputs exist.
