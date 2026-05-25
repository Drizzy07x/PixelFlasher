# PixelFlasher Modern UI Beta Roadmap

This document tracks the current beta state and the next safe implementation phases.

## Current beta status

Release candidate: `v9.2.0-beta.16` or newer.

Validated on Linux:

- `--self-test` returns `Required failures: 0`.
- `--modern-dashboard` opens inside the legacy UI.
- `--modern-shell-preview` opens the standalone full Modern Shell preview.
- `--flash-wizard-demo` opens and navigates through all preview steps.
- Flash Wizard remains read-only and does not execute flash, patch, ADB, or Fastboot commands.
- Modern Shell Preview remains UI-only and does not execute flash, patch, ADB, Fastboot, reboot, or file-processing operations.
- Linux GTK/GVFS terminal noise is filtered in packaged builds.

## Hard safety rules

Do not wire real flashing into the Wizard or Modern Shell until these are true:

1. Device detection is read from the same trusted source as the legacy UI.
2. Firmware compatibility checks are deterministic and tested.
3. Patch flow has explicit user confirmation and rollback behavior.
4. Final review screen shows every dangerous option clearly.
5. The final action delegates to existing guarded legacy flash logic, not a new independent flash path.
6. CI validates the Wizard model, state adapter, and preview entrypoints before packaging.

## Phase 1: Beta stabilization

Goal: keep the app stable while testers validate the modern overlay.

Tasks:

- Keep Dashboard behind `--modern-dashboard`.
- Keep Flash Wizard preview-only.
- Keep Modern Shell behind `--modern-shell-preview`.
- Collect Linux, Windows, and macOS screenshots.
- Fix only crashes, layout breakage, packaging failures, and confusing copy.
- Avoid large UI rewrites during beta feedback.

Exit criteria:

- Linux, Windows, and macOS builds are attached to a pre-release.
- Self-test passes on at least one Linux machine.
- Windows and macOS open without packaging regressions.
- No terminal/log spam that looks like a crash.

## Phase 2: Dashboard usefulness and shell preview

Goal: make the compact Dashboard useful while building the full Modern Shell safely beside the legacy UI.

Planned work:

- Add one-click refresh using existing legacy state.
- Show active slot, bootloader state, and firmware status when available.
- Show clearer empty states when no device or firmware is selected.
- Add a small “copy diagnostics” action for bug reports.
- Keep the Dashboard small enough to not crowd the legacy controls.
- Iterate on the standalone Modern Shell preview with UI-only pages.
- Keep Modern Shell actions disabled until adapters are validated.

## Phase 3: Wizard data integration

Goal: make the Wizard reflect real app state while still remaining read-only.

Planned work:

- Read selected device from legacy scan results.
- Read selected firmware path and detected package metadata.
- Read patch availability from existing boot/init_boot image data.
- Show blocking warnings with concise reasons.
- Add tests for every WizardSession state.

Exit criteria:

- Wizard accurately mirrors legacy selections.
- Wizard still cannot execute real flashing.
- Warnings match expected behavior in tests.

## Phase 4: Guarded execution planning

Goal: prepare real execution without adding risk.

Planned work:

- Add a final review contract object.
- Compare review contract against legacy flash parameters.
- Add dry-run validation path.
- Add explicit confirmation gates.
- Keep execution disabled by default.

Exit criteria:

- The Wizard can generate a validated plan.
- The plan can be compared against legacy flash inputs.
- No command execution happens without explicit guarded enablement.

## Phase 5: Optional full modern UI

Goal: only after the beta proves stable.

Planned work:

- Replace selected legacy panels gradually.
- Keep fallback to legacy UI.
- Preserve existing advanced tools.
- Avoid removing mature controls until replacements are tested.

## Recommended tester command set

Linux:

```bash
chmod +x PixelFlasher_Ubuntu_24_04
./PixelFlasher_Ubuntu_24_04 --self-test
./PixelFlasher_Ubuntu_24_04 --modern-dashboard
./PixelFlasher_Ubuntu_24_04 --modern-shell-preview
./PixelFlasher_Ubuntu_24_04 --flash-wizard-demo
```

Expected self-test result:

```text
Required failures: 0
Warnings: 0
```

Expected safety state:

```text
Modern Dashboard: preview overlay only
Modern Shell: standalone preview only
Flash Wizard: read-only / execution disabled
Real device operations: use legacy PixelFlasher controls
```
