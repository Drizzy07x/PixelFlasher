# PixelFlasher React UI — Design QA

Date: 2026-07-18

Scope: the production React shell and the current critical Device, Firmware, Flash, Root, Tools, and Settings journeys. This pass does not claim complete PixelFlasher 10 feature parity; the remaining product gaps are recorded in the parity inventory.

## Grounding and comparison

- Reference dashboard: `pixelflasher-modernization-audit/01-dashboard.png`.
- Final implementation capture: `docs/qa/final-dashboard.png`.
- Combined comparison: `docs/qa/dashboard-comparison.png`.
- The reference and implementation were compared side by side at the same 1536 × 960 viewport and dashboard state.
- Device and Tools interaction passes were also run at 1536 × 960 in the dark theme with the English locale.
- The React shell preserves the established dark navy workspace, compact task rail, blue/violet accents, bordered cards, device summary, readiness banner, quick actions, and bottom status strip. It also uses the repository's existing product imagery and icons.
- Intentional differences are limited to the requested nine task areas, native wx window chrome, and realistic development-only data that makes the main journeys testable without attached hardware.

## Visual checks

| Check | Evidence | Result |
| --- | --- | --- |
| Dashboard composition | 1536 × 960 combined comparison | Pass |
| Production reload | Dashboard restored at `#/dashboard`, dark theme, English, 100% zoom | Pass |
| Root workspace | Seven patch methods, verified app inventory, module controls, guarded confirmation | Pass |
| Firmware workspace | Native package selection contract, process action, verified Ready state | Pass |
| Flash review | Five-step wizard, explicit target, immutable review, destructive confirmation | Pass |
| Device workspace | Fastboot device operations, boot image actions, slot mutation and bootloader controls; reinforced challenge receives initial focus | Pass |
| Tools workspace — ADB | Standard and Expert states covering scrcpy, wireless ADB, bounded logcat, file push and support export | Pass |
| Tools workspace — fastboot | Partition manager list, selection, read/write/erase controls and result presentation | Pass |
| Responsive shell | 1024 × 768 collapsed task rail and no body overflow | Pass |
| Zoom and scrolling | 200% at 1536 × 960 initially exposed 29 px of internal overflow; container reflow removed it (`rootOverflow=0`, `mainOverflow=0`) and the sidebar remains vertically scrollable | Pass after fix |
| Theme variants | Dark, light, and high-contrast states inspected with visible borders and focus | Pass |

## Interaction and accessibility checks

- Nine task buttons, URL hash routing, Alt+1…9 navigation, skip link, and focus transfer to each page heading work.
- Theme, locale, high contrast, reduced motion, and 80–200% zoom controls work. Settings persist through the host preferences contract.
- At 200% zoom, QA detected 29 px of internal horizontal overflow. The container reflow fix was rechecked with `rootOverflow=0` and `mainOverflow=0`; the sidebar owns its vertical overflow, so Settings and Expert Mode remain reachable.
- Keyboard focus uses a visible 3 px focus ring. Confirmation dialogs initially focus Cancel and use the neutral Continue label outside the flash-specific flow.
- In the fastboot Device flow, reinforced operations open the challenge UI with initial focus on the reinforced challenge rather than leaving focus behind the dialog.
- Firmware processing emits only `firmware.process` with an empty payload and does not render Ready until the canonical snapshot promotes a verified processed artifact.
- Root patching stays disabled until a compatible verified app inventory is loaded. Its exact request contains only serial, flavor, opaque app ID, and destination. Module actions are gated on one selected rooted ADB device.
- The five-step flash wizard preserves state across canonical snapshots and performs plan update, plan preview, exact confirmation, and execution against the returned revision.
- Tools was exercised in both one-device ADB/Expert state and fastboot state. The bounded logcat viewer, native multi-file push picker, wireless controls, support destination grant and partition workspace all preserve the selected serial and typed bridge boundary.
- Axe reports zero automated violations on the primary dashboard and the bounded Tools/Wireless ADB workspace with its jsdom-incompatible color-contrast rule excluded; rendered contrast was inspected in the browser in dark, light, and high-contrast modes.
- The final in-app browser pass reported no console warnings or errors.

## Host-integrity and regression checks

- Real WebView mode starts from an empty snapshot and never exposes HTTP-preview firmware, app, backup, device, or root inventories.
- Development data remains behind `window.pixelflasher.__mock`; production bridge requests use the canonical Python allow-list and revision contract.
- Protocol acknowledgements without a terminal result are never presented as successful operations.
- Frontend regression: 23/23 Vitest tests passed, including dashboard and Tools axe smokes, exact bridge payloads, Device, Tools, Root, Firmware, and Flash journeys.
- Production build: TypeScript, 283 gettext message IDs and 267 web contexts across all six locales, Vite output, and the static `file://` WebView contract passed.
- Backend regression is 466/466, including serial-bound fastboot getvars, fastbootd classification, cancellation and identity-history tests. The post-command observer half of P1 remains open.
- This scoped design QA has no remaining visual overflow defect; it does not close the remaining postcondition work or any release-level parity gate.

## Open product gaps outside this QA pass

- Verified third-party APKs and native patch runners are not yet packaged, so real boot patch execution remains fail-closed.
- APatch secret transport and KMI/architecture-bound kernel selection still need production implementations.
- Tools is not complete: runtime scrcpy packaging/discovery, wireless discovery and disconnected-device handoff, logcat streaming/export/redaction, per-file push progress/retry, partition postconditions, and legacy support-package data remain tracked as partial.
- Full parity for advanced Apps, Backups, PIF, support, update, and the remaining expert surfaces remains tracked in the parity inventory.
- Fastboot inventory state is now enriched safely, but the P1 observer that must prove reboot, slot and bootloader postconditions after a zero exit code remains open.

final result: passed
