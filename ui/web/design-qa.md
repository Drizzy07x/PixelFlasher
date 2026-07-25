# PixelFlasher React UI — RC design and quality audit

Date: 2026-07-24

Scope: the production React/WebView shell and the release evidence required for
PixelFlasher 10 RC1. The machine-readable parity inventory remains the source
of truth for capability status.

## Current result

RC1 is blocked. The current inventory contains 52 release gates: 20 are
`native` and 32 remain `partial`. A partial row is not promoted merely because
its React and backend implementation exists; every capability-specific
packaged, hardware or accessibility exit criterion must also be demonstrated.

The historical dashboard captures under `docs/qa/` remain useful visual
references, but they are not candidate-bound RC evidence. Candidate evidence
must be generated for one clean, tagged commit and retained through
`scripts/rc1_preflight.py`.

## Automated UI evidence

| Check | Current local evidence | RC disposition |
| --- | --- | --- |
| Python quality | 1,618 tests passed, 5 POSIX-only contracts skipped on Windows; 80.17% combined line/branch coverage; Ruff clean; Pyright 0 errors | Pass locally; the 80% gate is active in Ubuntu CI |
| React tests | 33 files, 216 tests passed | Pass locally |
| React coverage | 82.27% statements, 80.62% branches, 86.04% functions, 87.68% lines | Pass locally |
| TypeScript and Vite | Application and terminal bundles built; static WebView contract passed | Pass locally |
| Gettext | 922 message IDs exported and checked across six locales | Pass locally |
| Packaged self-test | Required failures 0; the bundled OTA DEX hash is verified; four expected environment/provisioning warnings remain | Pass on the rebuilt local Windows x64 package |
| UI smoke schema v2 | One real WebView document visits all nine routes with `Alt+1…9`, verifies active route and heading focus, then shuts down cleanly | Pass on the rebuilt local Windows x64 package |
| Packaged functional smokes | ConPTY, Legacy Raw, firmware, Support v2 and UI receipts validated | Pass on the rebuilt local Windows x64 package |

The local receipts prove the rebuilt executable, not the remote target matrix.
Windows ARM64, macOS Intel/ARM, Ubuntu 22/24 and AppImage X11/Wayland results
must come from the exact candidate SHA and be retained as candidate-bound
evidence.

## Interaction and accessibility

- URL-hash routing, nine task buttons, `Alt+1…9`, the skip link and page-heading
  focus are covered by the persistent-document smoke.
- Theme, locale, high contrast, reduced motion and 80–200% zoom controls remain
  in the production settings contract.
- Keyboard focus and dialog focus behavior are covered by React tests, including
  reinforced confirmations.
- Automated axe coverage remains useful but is not equivalent to the required
  NVDA, VoiceOver and Orca runs.
- The prior 1536×960 and 1024×768 captures are historical checks. Fresh
  candidate-bound visual regression evidence is still required.

## Implementation changes since the prior audit

- Productive postcondition observation now covers reboot, slot, bootloader,
  package, partition, OTA and related mutation outcomes; the previous note that
  the observer was wholly open is obsolete.
- Scrcpy setup, wireless ADB, bounded Logcat, file push, partitions and Support
  have native React/backend chains. Their remaining gaps are production
  catalogs, packaged evidence or hardware evidence rather than absent panels.
- OTA cancel/reset now has an owned architecture-neutral DEX fallback built
  reproducibly from source with a hash-locked Google R8/D8 toolchain. The
  runtime verifies it locally, stages it privately, verifies the pushed hash
  on-device and uses it for status preflight, cancel, reset and idle
  observation. Rooted real-device Binder/SELinux validation remains open.

## Remaining RC evidence

- Production signing/key custody and final catalogs for Platform Tools, root
  apps, firmware, Scrcpy and updates.
- Dedicated production signature verifiers for the still-unprovisioned
  firmware, Scrcpy and update catalog formats; the RC1 preflight fails closed
  until those formats and verifiers exist.
- Candidate-bound packaged smoke results for every supported desktop target.
- The defined Pixel hardware matrix, including destructive and disconnect
  scenarios.
- NVDA, VoiceOver and Orca passes plus fresh visual regression captures.
- A clean RC tag, release signing/notarization evidence and repository release
  controls.
- Closure of all P0/P1 defects and a passing fail-closed RC1 preflight.

Final result: **blocked for RC1; local UI implementation and Windows x64 smoke
are green, release evidence is incomplete.**
