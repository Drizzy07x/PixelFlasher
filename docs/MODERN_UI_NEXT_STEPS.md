# PixelFlasher Modern UI Next Steps

This document is the working plan for continuing the Modern UI rollout after `v9.2.0-beta.18`.

The purpose is to keep future work fast, safe, and reviewable without relying on chat history.

## Current baseline

Current baseline release: `v9.2.0-beta.18`.

Confirmed in this baseline:

- `main` includes the beta18 Modern UI safety polish.
- Linux, Windows, and macOS release assets were generated for the beta18 tag.
- Ubuntu source validation passed with `Required failures: 0` and `Warnings: 0`.
- Flash Wizard demo final step no longer shows a clickable-looking final flash action.
- Modern Shell Preview pages for Patch Boot, Devices, Tools, and Logs show explicit preview-only/read-only states.
- Real device operations remain in legacy PixelFlasher.

## Non-negotiable safety rules

Modern UI work must stay additive and guarded until promoted deliberately.

Do not add, wire, or execute these from Modern UI preview code:

- Real flash execution.
- Real boot/init_boot patch execution.
- ADB command execution.
- Fastboot command execution.
- Reboot behavior.
- Slot switching.
- Wipe/data behavior.
- Firmware extraction or parsing.
- File mutation outside explicit diagnostics or packaging paths.
- A new independent flash execution path.

Future real execution, if ever enabled, must delegate to existing guarded legacy logic first.

## Preferred workflow

Use small branches and small PRs.

Branch naming:

```text
modern-ui-<topic>
```

Examples:

```text
modern-ui-docs-beta18
modern-ui-readonly-state
modern-ui-dashboard-copy
modern-ui-wizard-safety-tests
```

Avoid branch names that expose tool/vendor names or implementation experiments.

## Standard local validation

For documentation-only PRs:

```bash
git diff --check
```

For Python or UI PRs:

```bash
python3 -m py_compile <changed-python-files>
python3 PixelFlasher.py --self-test
```

For Modern UI visual PRs:

```bash
python3 PixelFlasher.py --flash-wizard-demo
python3 PixelFlasher.py --modern-shell-preview
python3 PixelFlasher.py --modern-dashboard-preview
```

When validating release assets, always test the asset from the target release, not an older local binary.

## PR rules

Each PR should state:

- What changed.
- What did not change.
- Safety boundaries.
- Validation commands.
- Visual checks, if UI changed.

Do not merge UI changes without either local screenshots or a clear reason why visual validation is not required.

## Cleanup rules

After a PR is merged and the release/tag is validated:

- Delete temporary feature branches.
- Prune stale remote refs locally.
- Keep `main` and release tags.
- Keep validation docs.

Suggested cleanup:

```bash
git checkout main
git pull --ff-only
git fetch --prune
git branch --merged main
```

Delete only branches that are already merged and no longer needed.

## Assisted-coding tool policy

Use an assisted coding tool only when it saves meaningful time on mechanical work, broad refactors, or test generation.

Good use cases:

- Writing tests for existing behavior.
- Updating docs across multiple files.
- Refactoring read-only adapters.
- Fixing straightforward CI failures.

Do not use assisted coding tools for:

- Real device execution paths.
- Flash, patch, reboot, wipe, slot, ADB, or Fastboot wiring.
- Large changes to `Main.py`.
- Creating release tags.
- Merging PRs without human review.

If an assisted coding tool creates a noisy branch or PR, copy the resulting changes into a neutral branch, close the noisy PR, and continue from the clean branch.

## Near-term phases

### Phase 1: Documentation operating base

Status: in progress.

Tasks:

- Add this next-steps document.
- Add beta18 validation notes.
- Update beta roadmap to the beta18 baseline.
- Update beta testing guide to include beta18 visual checks.

Exit criteria:

- A future contributor can continue from docs without chat history.

### Phase 2: Safety tests

Goal: protect the beta18 safety behavior.

Tasks:

- Add tests that prove preview sessions remain non-flashable by default.
- Add tests for Flash Wizard final-step safety copy.
- Add lightweight tests for Modern Shell page dispatch, including Tools.

Exit criteria:

- CI protects the no-final-action preview behavior.

### Phase 3: Shared read-only state layer

Goal: stop duplicating read-only state logic across Dashboard, Wizard, and Modern Shell.

Tasks:

- Add a read-only Modern UI state object.
- Move safe frame/config reads into one adapter.
- Keep the adapter side-effect free.
- Add tests using fake frames/config objects.

Exit criteria:

- Dashboard, Wizard, and Shell can consume consistent read-only state.

### Phase 4: Modern Shell state usefulness

Goal: make Modern Shell reflect already-loaded legacy state while remaining preview-only.

Tasks:

- Devices page shows selected device and known connection state.
- Flash page shows selected firmware state.
- Patch Boot page shows known boot/init_boot availability if already loaded.
- Tools page shows tool availability as read-only status.
- Logs page remains static or reads only safe internal diagnostics.

Exit criteria:

- Modern Shell becomes useful for review without executing commands.

### Phase 5: Dashboard copy polish

Goal: make the compact dashboard clearer inside legacy PixelFlasher.

Tasks:

- Replace generic `Run` labels with safer text such as `Use legacy` or `Open legacy flow`.
- Keep all actions delegated to existing guarded legacy handlers.
- Avoid making Modern UI appear responsible for real execution.

Exit criteria:

- Testers understand that real operations remain legacy-owned.

### Phase 6: Cross-platform validation

Goal: validate Modern UI beta behavior on all release assets.

Tasks:

- Ubuntu asset smoke test.
- Windows asset smoke test.
- macOS asset smoke test.
- Record findings in validation docs.

Exit criteria:

- Release notes can state which platforms were visually checked.
