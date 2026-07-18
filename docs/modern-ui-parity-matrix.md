# Modern UI parity matrix

Baseline: 2026-07-18 · schema version 1

This is the release contract for replacing the wxPython interface. The
machine-readable source of truth is
[`modern-ui-parity.json`](modern-ui-parity.json). It inventories the public
README features, primary controls, top-level and context menus, their current
handlers, the historical modern-preview action (when one existed), the live
versioned bridge command, current parity and a testable exit contract.

Dynamic firmware versions, connected-device entries and user-defined My Tools
commands are represented by their generating handler. They are not expanded
into unstable rows per runtime value.

The default executable now starts `ApplicationRuntime` and one wx/WebView
window that loads the packaged React document. It does not construct or import
`Main.PixelFlasher`. This architectural milestone is real, but it does not make
an individual capability complete: rows remain `partial` when only the backend
contract or only the React surface exists.

## Status meanings

| Status | Meaning |
|---|---|
| `native` | Implemented without opening or delegating to legacy UI handlers. |
| `read_only` | State is visible, but the complete native mutation flow is absent. |
| `delegated` | Modern UI reaches the behavior through a legacy handler/frame. |
| `partial` | Only a documented subset exists. |
| `blocked` | Explicitly disabled until its safe native contract exists. |
| `missing` | No equivalent modern flow exists. |

`delegated` is not completion. A capability reaches parity only when its exit
contract passes with the legacy frame unavailable.

## Primary journeys

| Capability | Current modern state | Risk | Release gap |
|---|---:|---:|---|
| Default React/WebView host and dashboard | native | none | Continue packaged cross-platform smoke coverage; no hidden legacy frame is used by this path. |
| Device, flash, safety and about navigation | native | none | Keep focus, keyboard and state continuity covered as feature flows expand. |
| Backup, settings and tools workspaces | partial | none | Tools now has native flows for scrcpy, wireless ADB, bounded logcat, file push, partitions and support export; advanced utilities and the documented postconditions remain open. |
| Firmware downloads workspace | read-only | none | Add download progress, cancellation, integrity and selection. |
| Scan/select devices | native | device read | Typed adb/fastboot discovery now reads serial-bound `current-slot`, `unlocked` and `is-userspace`, distinguishes fastbootd, preserves stable identity without reusing stale operational state, and retains cancellation/partial-source behavior. |
| Platform Tools setup | partial | host write | Local pair/version validation is native; checksum-verified atomic download/install is explicitly unsupported. |
| Select/process factory, OTA and custom ROM packages | partial | host read/write | The React flow uses a native picker and typed `firmware.select`/`firmware.process` commands. Factory archives, OTA packages and direct-image custom ROMs are processed fail-closed into hash-bound planner artifacts; official downloads, custom `payload.bin` processing and complete diagnostics remain open. |
| Firmware downloads | delegated | host write | Native progress, cancellation and SHA-256 verification. |
| Keep-data, wipe, dry-run and OTA planning | partial | device write/destructive | React intent, verified factory/direct-image artifacts and backend enforcement exist; recovery/fastbootd transition orchestration and remaining mode coverage remain open. |
| Review and execute flash | partial | destructive | Browser preview and execute use the trusted backend planner and registered firmware artifacts; multi-device batch execution, runtime transition orchestration and complete packaged-platform validation remain open. |
| Patch boot images | partial | device write | React, bridge and backend contracts cover Magisk, APatch, KernelSU, KernelSU-Next, SukiSU, Wild_KSU and Legacy with a hash-pinned resource registry. No real provider APKs or compatible runners are packaged yet; APatch secret handling and KMI/architecture-based kernel selection remain open. |
| Flash/live-boot images | partial | device write/destructive | React controls and exact-argv, serial/hash-bound backend plans exist with unlocked-fastboot guards; post-command device/slot/boot-state verification remains open. |
| Raw boot-chain backup/restore | partial | device write | Safe backend create/restore and React path/partition/slot inputs exist; persisted inventory, provenance display and Magisk import/delete remain open. |
| Application packages and APK install | partial | device write/destructive | PackageService and React canonical refresh cover listing plus enable/disable; APK install and the remaining package actions are not exposed yet. |
| Partition manager | partial | destructive | React list/read/write/erase controls, native pickers and the allow-listed guarded backend exist; device-side verification after write/erase and richer progress/retry remain open. |
| Logcat and file push | partial | device read/write | Logcat has a timeout/line-bounded viewer, while file push has a native multi-file picker, closed destinations and typed results; export/stream redaction, per-file progress/retry and device-side hash verification remain open. |
| Reboot and slot switch | partial | device write | React controls and serial-bound exact plans cover system/recovery/bootloader/fastbootd and slot switching; remaining destinations and post-transition verification remain open. |
| Scrcpy and wireless ADB | partial | device write | React and typed backend contracts bind the selected serial, securely pass pairing codes and verify responses; runtime scrcpy packaging/discovery, wireless discovery and disconnected-device handoff remain open. |
| Sanitized support package | partial | host write | Native destination grants, mandatory redaction, atomic ZIP output and an inclusion/omission manifest are tested; the legacy database, recursive file listing and encrypted wrapper are intentionally not migrated yet. |
| Modern presentation preferences | partial | host write | Five visible fields are host-backed end to end and Expert Mode controls advanced disclosure; broader 9.x settings and host persistence for Expert Mode remain open. |
| Standalone wipe | blocked | destructive | Must never bypass the reviewed flash plan. |

## Current implementation boundary

The primary host is native in the architectural sense: `PixelFlasher.py` calls
`ui/pages/modern_primary_app.py`, which opens one persistent local React
document through `ui/pages/modern_webview_host.py`. The core package has no wx,
UI or `Main` dependency. Commands enter through the single versioned
`pixelflasher` bridge and return explicit `SUCCESS`, `CANCELLED` or `FAILED`
results.

Flash now follows the trusted planner path. The React wizard submits semantic
options through `flash.plan.update`, requests
`flash.plan.preview`, renders the backend plan and exact argv, then calls
`flash.execute` without supplying argv or an `OperationPlan`. `OperationPlanner`
constructs that immutable plan, binds reinforced confirmations when needed,
and the engine revalidates revision, selected serial, device mode, canonical
plan fingerprint and every artifact hash immediately before the executor. A
dry-run starts zero subprocesses. `FirmwareArtifactService` now extracts and
registers verified factory and direct-image custom artifacts, registers the
verified OTA source, and atomically promotes the canonical firmware and stock
boot state. This row remains `partial` because custom `payload.bin` processing,
runtime recovery/fastbootd transitions and multi-device batch execution remain
open.

Nine bounded service groups now use reviewed planner/policy/executor or local
atomic-operation boundaries:

- `PackageService` lists package scopes and compiles enable, disable,
  uninstall, clear-data, force-stop, launch, permissions and APK install.
- `PartitionService` lists, fetches, flashes and erases only allow-listed
  fastboot partitions; erase uses reinforced confirmation.
- `DeviceToolsService` supports managed scrcpy launch, secret-safe wireless ADB
  pairing/connectivity, bounded logcat snapshots and fixed-destination file
  push. Arbitrary ADB shell is explicitly rejected without execution.
- `BackupService` creates and restores bounded boot-chain partition images,
  finalizing created files into verified artifacts and confirming restore.
- `RootingService` inventories backend-owned verified rooting APKs, installs by
  opaque identifier and manages validated Magisk modules with action-specific
  confirmation metadata.
- `FirmwareArtifactService` validates complete archives without running their
  scripts, extracts only allow-listed images to backend-chosen paths, hashes and
  registers them in the planner repository, and persists only verified cache
  metadata for rehydration.
- `BootPatchService` compiles serial-, revision-, app-, runner- and hash-bound
  plans for all seven supported patch flavors. `PatchResourceRegistry` accepts
  only a backend-pinned manifest and confined, hash-verified resources; the
  shipped registry remains intentionally empty until real compatible APKs and
  runners are supplied.
- `SupportPackageService` consumes a short-lived native destination grant,
  redacts allow-listed text sources, verifies an atomic ZIP and records every
  included or intentionally omitted source in its manifest.
- `BootloaderLockPolicy` fails closed unless canonical, revision-bound evidence
  proves a complete compatible stock factory flash across both slots. No
  producer is trusted yet, so the real host keeps lock disabled by default.

These are backend-native contracts, not claims of complete UI parity. The Apps
page refreshes canonical rows through `apps.list` but currently exposes only
enable/disable. The Tools page now owns the bounded logcat viewer, scrcpy,
wireless ADB, file-push, partition and support-package flows, but each row stays
partial until its documented packaging, postcondition, progress or legacy-data
gap is closed. Backups collects path, partition and slot but does not maintain a
persisted inventory/result view.

`ModernPreferences` and `ApplicationRuntime` implement strict
`settings.get`/`settings.update` contracts for theme, locale, high contrast,
reduced motion and zoom. They migrate recognized 9.x keys and rely on
`ConfigStore` for atomic writes and backup. The real React host loads those
values and serializes updates through the bridge; only the isolated mock
preview uses local storage. Settings remains `partial` because the broader 9.x
application settings and host-backed expert-mode preference are not yet represented.

Destructive confirmation is end to end: `SafetyPolicy` produces an
`InteractionRequest`, `InteractionBroker` publishes it through the host, the
accessible React modal answers with `interaction.respond`, and the engine
rechecks safety and plan validity after the user response. Cancellation never
becomes implicit success.

## Legacy-only capability groups

| Area | Missing or partial behaviors |
|---|---|
| Device connection | Wireless discovery/disconnected-device handoff, hotplug tuning, complete reboot destinations and post-transition verification. |
| Applications | React APK install, download, denylist, SU controls and the remaining package actions. |
| Device tools | Explicit expert ADB shell decision, packaged scrcpy discovery/lifecycle, reports, props/XML/PIF, logcat streaming/export/redaction and OTA diagnostics. |
| Boot and flash | Boot-record mutation, device/slot postcondition checks, trusted stock-flash evidence production before bootloader lock, downgrade artifact production, custom `payload.bin`, runtime recovery/fastbootd transitions, real patch APK/runner resources, APatch secret handling and KMI/architecture-based kernel selection. |
| Support | Safe migration of the legacy database plus an explicit decision for the recursive listing and encrypted support wrapper. |
| Backups | Persisted raw-backup inventory/results and complete Magisk list/import/delete behavior. |
| Root and integrity | `/data/adb` backup/restore/clear, PIF/TargetedFix, PI analysis, Shizuku and SOS. |
| Developer/personal tools | Keybox, binary XML, AVB tools and arbitrary My Tools commands. |
| Application shell | Remaining 9.x/expert preferences, toolbar customization, folders, update/link actions and console controls. |

The JSON inventory maps each individual menu/context-menu and primary-control
handler into one of these capability groups, including selection-only actions
such as check-all and copy-to-clipboard. The former 32 preview actions remain
frozen in `tests/golden/modern_action_contracts.json` as migration evidence;
they are no longer the live contract. Tests reject an unknown capability,
duplicate ownership, any untracked command in `ui.bridge_contract.ALLOWED_COMMANDS`,
or a change to the characterized primary-control handler set. React declares
only the subset it emits in `ui/web/src/commands.ts`; a repository-level parser
rejects any value outside the Python allow-list and any runtime literal that
bypasses those constants, so the frontend does not maintain a divergent copy of
the complete host contract.

## Release gates

A row changes to `native` only when all of the following are true:

1. It runs with no hidden `Main.PixelFlasher` frame and no call to a legacy
   event handler.
2. Success, cancellation, timeout, partial failure and retry results have typed
   behavioral tests.
3. Device mutations execute only from an immutable plan bound to serial,
   connection state, firmware/image hash, partition and slot.
4. Destructive actions are rejected by the operation layer unless the exact
   reviewed plan was freshly confirmed; UI confirmation alone is insufficient.
5. The flow is keyboard accessible and passes the packaged Windows, macOS and
   Linux smoke matrix.

## Updating the baseline

Update both files in the same change. Add a capability before adding a public
feature, menu handler, primary control or bridge command. Do not silently mark a
delegated action as native: include the behavioral test that proves the legacy
frame can be absent. Run:

```bash
python -m unittest tests.test_modern_parity_inventory -v
```
