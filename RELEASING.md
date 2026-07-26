# Releasing PixelFlasher 10

PixelFlasher 10 releases are built only by `.github/workflows/main.yml` from a
protected `v10.X.Y-rc.N` or `v10.X.Y` tag. Manual workflow runs never publish a
release, and artifacts from another run are never reused.

## Preconditions

- The modern parity inventory has no release-gated capability outside
  `native`; deliberately absent policy shortcuts use `policy_absent`.
- Python, frontend, accessibility, packaged WebView and fake ADB/Fastboot
  suites are green at their required coverage thresholds.
- Windows x64/ARM64, macOS Intel/Apple Silicon, Ubuntu 22/24 and AppImage jobs
  all launch the real packaged entrypoint and validate its closed
  `--ui-smoke-report` receipt after React bridge v2 readiness and clean shutdown.
- The release environment contains Windows signing, Apple Developer ID and
  notarization credentials plus `RELEASE_SIGNING_KEY`.
- There are no open P0/P1 defects and the hardware validation report is
  attached to the candidate milestone.
- `docs/upstream-audit.md` records a code-freeze audit of the exact
  `upstream/main` SHA and the decision for every commit since the preceding
  milestone.

## Running the platform matrix

An ordinary branch push runs only `Ubuntu Smoke Checks`, which builds no
installer. The seven-target matrix in `main.yml` runs on a `v10.*` tag, on a
pull request into `main`, or on demand:

```text
gh workflow run "Build and release all platforms" --ref <branch>
```

A full matrix run uploads roughly 1.4 GB of artifacts, so it is never attached
to every commit. Platform artifacts expire after seven days; published release
payloads live in the GitHub release, not in Actions storage. Collect the
packaged evidence required above from a dispatched run on the exact candidate
commit.

## Candidate sequence

1. Tag `v10.0.0-rc.1` and retain its evidence for at least 14 days.
2. Land only reviewed corrections found during RC1, then tag `v10.0.0-rc.2`.
3. Retain RC2 for at least seven days. Any source or dependency change requires
   another RC and a new soak.
4. Create `v10.0.0` on the exact approved source commit and lockfiles. Only
   tag-derived version metadata and signatures may differ.
5. Verify GitHub attestations, SBOMs, notarization, Authenticode and the signed
   `SHA256SUMS` before announcing the release.

Version constants and package metadata remain 9.2.2 until RC1. For protected
release tags, `scripts/release_version.py` derives all release metadata from
the tag; source files are not hand-edited to create a candidate.

## Emergency stop

Delete a bad unpublished tag before rerunning. Never overwrite a published tag
or replace its assets. For a published defect, follow `docs/ROLLBACK.md` and
issue a new signed release.
