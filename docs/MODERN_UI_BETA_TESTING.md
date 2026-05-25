# PixelFlasher Modern UI Beta Testing

This document explains how to test the modern UI rollout safely.

Current baseline: `v9.2.0-beta.18`.

The modern UI work is additive and guarded. The legacy PixelFlasher UI and existing flash flows remain intact.

## Current safety status

The modern Dashboard, Modern Shell Preview, and Flash Wizard are beta UI layers.

The Flash Wizard is read-only and preview-focused at this stage:

- It does not run ADB commands.
- It does not run Fastboot commands.
- It does not patch boot or init_boot images.
- It does not parse firmware packages.
- It does not flash devices.
- It does not replace the existing guarded legacy flash flow.
- Its final Flash step remains blocked and shows no clickable-looking final flash action.

The Modern Shell Preview is also read-only:

- Patch Boot execution is disabled.
- Device scan/refresh is disabled.
- Tool execution is disabled.
- Live log capture is disabled.
- Real operations remain in legacy PixelFlasher.

Use the legacy PixelFlasher controls for real device operations until Modern UI behavior is explicitly promoted out of preview mode.

## Commands

### Launch normal legacy app

```bash
python PixelFlasher.py
```

Expected result:

- PixelFlasher opens normally.
- No modern dashboard is injected.
- Existing workflows should behave as before.

### Launch legacy app with compact modern dashboard

```bash
python PixelFlasher.py --modern-dashboard
```

Expected result:

- PixelFlasher opens normally.
- A compact Modern Dashboard appears above the legacy UI.
- The legacy UI remains below it.
- Dashboard controls are available:
  - `Wizard`
  - `Refresh`
  - `Copy Diag`
  - `Hide` / `Show`

### Launch standalone dashboard preview

```bash
python PixelFlasher.py --modern-dashboard-preview
```

Expected result:

- A standalone dashboard preview window opens.
- This is useful for visual review without launching the full legacy app.

### Launch standalone Modern Shell preview

```bash
python PixelFlasher.py --modern-shell-preview
```

Expected result:

- A standalone Modern Shell preview window opens.
- It shows Dashboard, Flash, Patch Boot, Devices, Tools, Logs, and Settings pages.
- Header clearly shows `Preview Only` and `No Flash Execution`.
- No page performs real device operations.

### Launch standalone Flash Wizard preview

```bash
python PixelFlasher.py --flash-wizard-preview
```

Expected result:

- A standalone Flash Wizard window opens.
- It shows preview/read-only state.
- The final flash step remains blocked.
- No final action appears clickable.

### Launch standalone Flash Wizard demo

```bash
python PixelFlasher.py --flash-wizard-demo
```

Expected result:

- A standalone Flash Wizard window opens with fake demo data.
- Example state includes a Pixel device, verified firmware, safe options, and Flash disabled.
- This is for UI review and screenshots only.

### Run self-test

```bash
python PixelFlasher.py --self-test
```

Expected result:

- Required checks should pass.
- Optional warnings are allowed on systems without wxPython, adb, or fastboot.
- On a fully configured Linux test machine, expected result is:

```text
Required failures: 0
Warnings: 0
```

### Create diagnostics bundle

```bash
python PixelFlasher.py --diagnostics --output PixelFlasher-diagnostics.zip
```

Expected result:

- A redacted diagnostics ZIP is created.
- Do not manually attach private logs without reviewing them first.

## What to test

### Legacy app safety

Run:

```bash
python PixelFlasher.py
```

Verify:

- App opens normally.
- No modern UI appears unless requested.
- Existing menus and controls still render.
- App closes normally.

### Compact modern dashboard

Run:

```bash
python PixelFlasher.py --modern-dashboard
```

Verify:

- Dashboard appears above the legacy UI.
- Legacy UI remains usable.
- `Refresh` does not crash.
- `Copy Diag` copies redacted Modern UI diagnostics.
- `Hide` hides the dashboard.
- `Show` restores the dashboard.
- `Wizard` opens a separate Flash Wizard preview window.
- Closing the Wizard does not close the main app.

### Wizard from dashboard

In the app launched with:

```bash
python PixelFlasher.py --modern-dashboard
```

Click:

```text
Wizard
```

Verify:

- Wizard opens in a separate window.
- It reads available state from the current UI/config.
- It shows Device, Firmware, Patch Boot, Options, Review, and Flash steps.
- Back/Next navigation works.
- Flash remains disabled.
- Main PixelFlasher window remains stable.

### Flash Wizard preview

Run:

```bash
python PixelFlasher.py --flash-wizard-preview
```

Verify:

- Wizard opens.
- Steps render correctly.
- Summary panel shows read-only state.
- Warnings are visible.
- Final Flash step remains blocked.
- Final Flash step does not show a clickable-looking flash action.

### Flash Wizard demo

Run:

```bash
python PixelFlasher.py --flash-wizard-demo
```

Verify:

- Demo data appears.
- Device step shows a fake Pixel device.
- Firmware step shows fake verified firmware.
- Options step shows safe defaults.
- Review step shows generated session lines.
- Flash step remains blocked.
- On the final Flash step, only `Back` remains visible in the footer.
- No dark `Flash disabled` button appears on the final Flash step.

### Modern Shell preview

Run:

```bash
python PixelFlasher.py --modern-shell-preview
```

Verify each page:

- Dashboard shows preview-only quick actions.
- Flash shows `Flash Now disabled` and `Dry Run preview` as non-executing preview rows.
- Patch Boot shows `Preview only · patch execution disabled`.
- Devices shows `Preview only · scan/refresh disabled`.
- Tools shows `Preview only · tool execution disabled` and does not fall back to a generic placeholder.
- Logs shows `Preview only · live log capture disabled` and static preview log text.
- Settings remains visual-only.

## What not to test yet

Do not expect these to work from the modern Dashboard, Wizard, or Shell yet:

- Real device scanning.
- Real firmware parsing.
- Real boot/init_boot patching.
- Real flash execution.
- Real slot switching.
- Real wipe/keep-data execution.
- Real command generation from the wizard.
- Live device log capture.

Use the existing legacy PixelFlasher controls for real operations.

## Release asset validation

When validating a release, test the downloaded asset from that release tag. Do not validate an older local binary.

Linux asset checklist:

```bash
chmod +x PixelFlasher_Ubuntu_24_04
sha256sum -c PixelFlasher_Ubuntu_24_04.sha256
./PixelFlasher_Ubuntu_24_04 --self-test
./PixelFlasher_Ubuntu_24_04 --flash-wizard-demo
./PixelFlasher_Ubuntu_24_04 --modern-shell-preview
```

Expected:

- SHA-256 check passes.
- Self-test has no required failures.
- Flash Wizard final step remains blocked with no final flash action button.
- Modern Shell pages remain preview-only/read-only.

## Reporting bugs

Useful beta reports include:

- Operating system and version.
- Source checkout or release asset used.
- Release tag or commit SHA.
- How the app was launched.
- Exact command used.
- Screenshot if the issue is visual.
- Whether the issue happens in legacy mode too.
- Diagnostics ZIP if relevant.

Example report:

```text
OS: Ubuntu 24.04
Build: v9.2.0-beta.18 release asset
Command: ./PixelFlasher_Ubuntu_24_04 --modern-shell-preview
Issue: Tools page renders, but preview-only banner is clipped at 125% scaling.
Legacy mode affected: no
Diagnostics: attached
```

## Known limitations

- The modern Dashboard is currently an overlay, not a full replacement.
- The standalone Modern Shell is a preview, not the production app shell.
- The Flash Wizard is preview/read-only.
- The Wizard final action remains disabled by design.
- The Dashboard, Wizard, and Shell use wxPython controls, so visual appearance can differ slightly across Windows, Linux, and macOS.
- The state adapter only reads already-loaded UI/config values. It does not perform live checks.

## Promotion criteria before enabling more behavior

Before connecting real actions to the Wizard or Modern Shell, these must be true:

- CI stays green on Windows, macOS, and Ubuntu.
- Wizard model tests cover the target behavior.
- Adapter tests cover legacy state mapping.
- Preview-only final action behavior is protected by tests.
- Pre-flight checks are explicit and visible.
- Dangerous options require confirmation.
- The final command plan is visible before execution.
- Real flash action delegates to the existing guarded legacy flow first, not a new untested implementation.
