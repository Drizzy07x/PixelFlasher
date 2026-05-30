# PixelFlasher Modern UI Beta Roadmap

This document tracks the current beta state and the next safe implementation phases.

## Current beta status

Current baseline: `v9.2.0-beta.18`.

Validated on Linux source checkout:

- `--self-test` returns `Required failures: 0` and `Warnings: 0`.
- `--modern-dashboard` opens inside the legacy UI when explicitly requested.
- `--modern-dashboard-preview` opens the standalone dashboard preview.
- `--modern-shell-preview` opens the standalone full Modern Shell preview.
- `--flash-wizard-demo` opens and navigates through all preview steps.
- Flash Wizard final step is blocked and no longer shows a clickable-looking final flash action.
- Flash Wizard remains read-only and does not execute flash, patch, ADB, or Fastboot commands.
- Modern Shell Preview remains UI-only and does not execute flash, patch, ADB, Fastboot, reboot, slot, wipe, or file-processing operations.
- Modern Shell Preview has explicit preview-only/read-only states for Patch Boot, Devices, Tools, and Logs.
- Linux, Windows, and macOS assets are attached to the beta18 pre-release.

## Hard safety rules

Do not wire real flashing into the Wizard or Modern Shell until these are true:

1. Device detection is read from the same trusted source as the legacy UI.
2. Firmware compatibility checks are deterministic and tested.
3. Patch flow has explicit user confirmation and rollback behavior.
4. Final review screen shows every dangerous option clearly.
5. The final action delegates to existing guarded legacy flash logic, not a new independent flash path.
6. CI validates the Wizard model, state adapter, and preview entrypoints before packaging.
7. Cross-platform visual validation has been completed on release assets.

## Phase 1: Beta stabilization

Status: mostly complete for beta18.

Goal: keep the app stable while testers validate the modern overlay.

Completed:

- Keep Dashboard behind `--modern-dashboard`.
- Keep Flash Wizard preview-only.
- Keep Modern Shell behind `--modern-shell-preview`.
- Fix confusing Flash Wizard final action copy.
- Add explicit Modern Shell preview-only states for Patch Boot, Devices, Tools, and Logs.
- Package Linux, Windows, and macOS assets for beta18.

Remaining:

- Validate Windows and macOS assets visually.
- Record beta18 asset validation results.
- Fix only crashes, layout breakage, packaging failures, and confusing copy.
- Avoid large UI rewrites during beta feedback.

Exit criteria:

- Linux, Windows, and macOS builds are attached to a pre-release.
- Self-test passes on at least one Linux machine.
- Windows and macOS open without packaging regressions.
- No terminal/log spam that looks like a crash.
- Preview-only behavior is clear on every Modern UI surface.

## Phase 2: Safety tests and documentation base

Goal: protect beta18 behavior and make future work faster.

Planned work:

- Keep `docs/MODERN_UI_NEXT_STEPS.md` current.
- Keep beta validation docs current.
- Add tests that protect Flash Wizard preview-only final action behavior.
- Add tests for WizardSession blocking logic around `flash_connected=False`.
- Add lightweight tests for Modern Shell page dispatch, including Tools.
- Keep CI useful on systems where wxPython is unavailable.

Exit criteria:

- The beta18 safety behavior is covered by tests.
- Future contributors can continue from docs without chat history.

## Phase 3: Shared read-only state layer

Goal: stop duplicating read-only state logic across Dashboard, Wizard, and Modern Shell.

Planned work:

- Add a shared read-only Modern UI state object.
- Move safe frame/config reads into one adapter.
- Keep the adapter side-effect free.
- Use fake frames/config objects in tests.
- Make Dashboard, Wizard, and Shell consume consistent state labels.

Non-goals:

- No live ADB scan.
- No live Fastboot scan.
- No firmware extraction/parsing.
- No patch detection that mutates files.
- No flash planning execution.

Exit criteria:

- Dashboard, Wizard, and Modern Shell display consistent read-only state.
- Tests prove the adapter does not require wxPython or device commands.

## Phase 4: Modern Shell state usefulness

Goal: make Modern Shell reflect already-loaded legacy state while remaining preview-only.

Planned work:

- Devices page shows selected device and known connection state.
- Flash page shows selected firmware state.
- Patch Boot page shows known boot/init_boot availability if already loaded.
- Tools page shows platform-tool availability as read-only status.
- Logs page remains static or reads only safe internal diagnostics.

Exit criteria:

- Modern Shell becomes useful for review without executing commands.
- Every action-looking surface remains disabled or explicitly legacy-owned.

## Phase 5: Dashboard copy polish

Goal: make the compact dashboard clearer inside legacy PixelFlasher.

Planned work:

- Replace generic `Run` labels with safer copy such as `Use legacy` or `Open legacy flow`.
- Keep all actions delegated to existing guarded legacy handlers.
- Avoid making Modern UI appear responsible for real execution.
- Keep Dashboard compact enough to not crowd legacy controls.

Exit criteria:

- Testers understand that real operations remain legacy-owned.

## Phase 6: Guarded execution planning

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

## Phase 7: Optional full modern UI

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
./PixelFlasher_Ubuntu_24_04 --modern-dashboard-preview
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
