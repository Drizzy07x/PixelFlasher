# Modern UI parity matrix

Baseline: 2026-07-18 · schema version 2

This is the release contract for replacing the wxPython interface. The
machine-readable source of truth is
[`modern-ui-parity.json`](modern-ui-parity.json). It inventories the public
README features, primary controls, top-level and context menus, their current
handlers, the historical modern-preview action (when one existed), the live
versioned bridge command, current parity and testable exit criteria. Schema v2
separates evidence of what exists today from the remaining gap and the criteria
for closing it.

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
| `blocked` | A parity capability is unavailable because a named prerequisite or product decision prevents a safe native contract. |
| `missing` | No equivalent modern flow exists. |
| `policy_absent` | Intentionally excluded by safety or product policy; it is not a parity deficit. |

`delegated` is not completion. A capability reaches parity only when its exit
criteria pass with the legacy frame unavailable. `native` records implementation
parity; it does not by itself waive the packaged-platform, accessibility or RC
release gates.

## Schema v2 contract

Every capability has exactly one functional `owner`. `currentEvidence` and
`tests` point to what is present now; `gap` contains only unfinished parity
work; `exitCriteria` describes the independently testable target. `dependsOn`
is an acyclic list of other capability IDs. `risk` and `platforms` state the
safety class and target applicability. `blockReason` names a concrete
impediment when one exists. `releaseGate: true` means the capability is required
for the stable 10.0 release; `false` is reserved for a deliberate
`policy_absent` behavior.

Navigation shells do not own the operations shown inside them. In particular,
`navigation.flash` owns only routing, state continuity and focus; operational
parity belongs to `flash.execute`. Downloads has one owner,
`firmware.downloads`, which also owns both historical download action IDs.

## Primary journeys

| Capability | Current modern state | Risk | Release gap |
|---|---:|---:|---|
| Default React/WebView host and dashboard | native | none | Continue packaged cross-platform smoke coverage; no hidden legacy frame is used by this path. |
| Device, Flash and Safety navigation shells | native | none | Navigation is native; operational Flash parity is tracked independently by `flash.execute`. |
| About/help surface | missing | none | Add a live React surface for packaged version, license, updates, support and project information. |
| Backup, settings and tools workspaces | partial | none | Tools now has native flows for scrcpy, wireless ADB, bounded logcat, file push, partitions and support export; advanced utilities and the documented postconditions remain open. |
| Scan/select/manage devices | native | device read/host write | Typed adb/fastboot discovery reads serial-bound `current-slot`, `unlocked` and `is-userspace`, distinguishes fastbootd and preserves stable identity without reusing stale operational state. A versioned manager persists aliases and enabled state, pauses/resumes hotplug, switches between enabled/all scope, repairs selection and migrates the bounded 9.x roster with an automatic backup. |
| Platform Tools setup | partial | host write | Signed official downloads and opaque-grant directories now use pinned manifests, versioned atomic installation, binary/version probes and transactional activation. Production key/catalog provisioning and packaged cross-platform smokes remain. |
| Select/process factory, OTA and custom ROM packages | partial | host read/write | The React flow uses a native picker and typed `firmware.select`/`firmware.process` commands. Factory archives, OTA packages and direct-image custom ROMs are processed fail-closed into hash-bound planner artifacts; official downloads, custom `payload.bin` processing and complete diagnostics remain open. |
| Firmware downloads | missing | host write | There is no separate live Downloads route or native catalog implementation; the retired wx delegate is no longer shipped. Add one firmware-owned React flow providing progress, cancellation, SHA-256 verification and final selection. |
| Keep-data, wipe, dry-run and OTA planning | partial | device write/destructive | React intent, verified factory/direct-image artifacts and backend enforcement exist; recovery/fastbootd transition orchestration and remaining mode coverage remain open. |
| Review and execute flash | partial | destructive | Browser preview and execute use the trusted backend planner and registered firmware artifacts; multi-device batch execution, runtime transition orchestration and complete packaged-platform validation remain open. |
| Patch boot images | partial | device write | React, bridge and backend contracts cover Magisk, APatch, KernelSU, KernelSU-Next, SukiSU, Wild_KSU and Legacy with a hash-pinned resource registry. APatch delivers its opaque one-use superkey only through the runner's stdin and redacts reflected output. Real provider APKs/runners and KMI/architecture-based kernel selection remain open. |
| Flash/live-boot images | partial | device write/destructive | React controls and exact-argv, serial/hash-bound backend plans exist with unlocked-fastboot guards; post-command device/slot/boot-state verification remains open. |
| Raw boot-chain backup/restore | partial | device write | Safe backend create/restore and React path/partition/slot inputs exist; persisted inventory, provenance display and Magisk import/delete remain open. |
| Application packages and APK install | partial | device write/destructive | PackageService and React now cover canonical listing, enable/disable and APK installation through an opaque native grant, all six admitted install flags, explicit terminal states and a success-gated inventory refresh. Play Store ownership and the remaining package actions stay open. |
| Partition manager | partial | destructive | React list/read/write/erase controls, native pickers and the allow-listed guarded backend exist; device-side verification after write/erase and richer progress/retry remain open. |
| Logcat and file push | native | destructive device write and host write | Logcat provides bounded snapshot and incremental stream modes, serial/revision binding, cancellation, all legacy format verbs/modifiers, typed tag/priority plus Expert regex/UID filters, configurable redaction and atomic export through a one-use native grant. Remote clearing is serialized and success-gated: backend command completion is combined with a differential sentinel in the main buffer, without claiming that every buffer remains empty. File push uses opaque superseding grants, private verified staging, closed destinations, bounded per-file progress, explicit cancellation/manual retry and batched remote SHA-256 verification with a bounded `toybox` fallback. |
| Reboot and slot switch | native | device write | Reboot to system, bootloader, fastbootd, recovery, safe mode and sideload uses serial/revision-bound plans and observed mode, boot-completion or safe-mode postconditions. Vendor download mode is explicitly policy-absent and fails closed as `reboot_download_unverifiable` without starting a process. Slot switching verifies `fastboot getvar current-slot` after reconnection. |
| Scrcpy and wireless ADB | partial | device write | React and typed backend contracts bind the selected serial, securely pass pairing codes and verify responses; runtime scrcpy packaging/discovery, wireless discovery and disconnected-device handoff remain open. |
| Sanitized support package | partial | host write | Native destination grants, strict allow-listed collection, mandatory redaction, a sanitized SQLite copy, an inclusion/omission manifest and atomic AES-256-GCM output with RSA-OAEP key wrapping are tested. Production recipient-key injection and packaged interoperability validation remain open. |
| Modern presentation preferences | partial | host write | Five visible fields are host-backed end to end and Expert Mode controls advanced disclosure; broader 9.x settings and host persistence for Expert Mode remain open. |
| Standalone wipe | `policy_absent` | destructive | This is intentionally not a parity target: wipe is allowed only inside a reviewed immutable flash plan. |

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

Ten bounded service groups now use reviewed planner/policy/executor or local
atomic-operation boundaries:

- Device management uses a strict versioned codec and transactional runtime
  boundary for scan policy, aliases, enable/disable and removal. Discovery
  filters disabled serials before property enrichment, preserves one stable
  identity across ADB/fastboot transitions, and persists hotplug updates without
  promoting state if the atomic configuration write fails. The accessible React
  panel exposes the same closed bridge contract and never receives host paths.
- `PackageService` lists package scopes and compiles enable, disable,
  uninstall, clear-data, force-stop, launch, permissions and APK install.
- `PartitionService` lists, fetches, flashes and erases only allow-listed
  fastboot partitions; erase uses reinforced confirmation.
- `DeviceToolsService` supports managed scrcpy launch, secret-safe wireless ADB
  pairing/connectivity, bounded logcat snapshots and fixed-destination file
  push. File-push success requires a device-observed SHA-256 match for every
  source through fixed `sha256sum` or `toybox sha256sum` argv. Its typed
  `device.inspect` command now returns redacted properties and
  device summary, a bounded PIF profile, validated/sanitized screen XML, or the
  independently streamed A/B bootloader versions from fixed, root-proven ABL
  reads. Each slot is capped at 64 MiB, hashed incrementally and reconciled
  against the fresh Android-reported active slot/version; binary bytes and
  stderr never enter the result or snapshot. React presents those reports
  through serial-bound, typed views and copies only the sanitized value.
  The separate `device.openUrl` mutation accepts only canonical HTTP(S) URLs,
  quotes the Android remote shell boundary, requires confirmation and reports
  success only from bounded `am start -W` completion evidence without returning
  the URL itself.
  Arbitrary ADB shell is explicitly rejected without execution.
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
- `SupportPackageV2Service` consumes a short-lived native destination grant,
  rebuilds a bounded sanitized SQLite copy, redacts every allow-listed source,
  verifies hashes and writes only an encrypted v2 container. The reader keeps
  10.x compatibility with v1 packages; production fails closed until a pinned
  recipient public key and key ID are injected.
- `BootloaderLockPolicy` fails closed unless canonical, revision-bound evidence
  proves a complete compatible stock factory flash across both slots. No
  producer is trusted yet, so the real host keeps lock disabled by default.

These are backend-native contracts, not claims of complete UI parity. The Apps
page refreshes canonical rows through `apps.list`, exposes enable/disable and
installs verified APKs without revealing host paths; Play Store ownership and
the remaining manager actions stay open. The Tools page now owns the bounded logcat viewer, scrcpy,
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
| Device connection | Bounded mDNS discovery is native without a selected device, and versioned scan/hotplug management is complete. Pair/connect without a selected ADB target and disconnected-device handoff remain. Portable reboot destinations are verified; vendor download mode is policy-absent because it has no portable backend postcondition. |
| Applications | React APK install, download, denylist, SU controls and the remaining package actions. |
| Device tools | The explicit expert ADB shell decision, packaged scrcpy discovery/lifecycle and OTA cancel/reset. Safe HTTP(S) URL opening, independently verified per-slot bootloader inspection, read-only otacerts inspection, bounded Logcat snapshot/stream/export/redaction, typed legacy-compatible filters, verified remote buffer clearing and the filtered update_engine snapshot are now native. |
| Boot and flash | Boot-record mutation, complete device/slot postcondition coverage, trusted stock-flash evidence production before bootloader lock, downgrade artifact production, custom `payload.bin`, runtime recovery/fastbootd transitions, real patch APK/runner resources and KMI/architecture-based kernel selection. |
| Support | Production recipient-key provisioning, packaged v1-read/v2-write interoperability and complete console/log redaction validation. |
| Backups | Persisted raw-backup inventory/results and complete Magisk list/import/delete behavior. |
| Root and integrity | `/data/adb` backup/restore/clear, PIF/TargetedFix, PI analysis, Shizuku and SOS. |
| Developer/personal tools | Keybox, binary XML, AVB tools and arbitrary My Tools commands. |
| Application shell | About/help, remaining 9.x/expert preferences, toolbar customization, folders, update/link actions and console controls. |

The JSON inventory maps each individual menu/context-menu and primary-control
handler into one of these capability groups, including selection-only actions
such as check-all and copy-to-clipboard. The former 32 preview actions remain
frozen in `tests/golden/modern_action_contracts.json` as migration evidence;
they are no longer the live contract. Tests reject unknown fields or enum
values, missing evidence/gap/exit metadata, invalid or cyclic dependencies,
duplicate action/command ownership, any untracked command in
`ui.bridge_contract.ALLOWED_COMMANDS`, or a change to the characterized
primary-control handler set. Dedicated invariants keep Downloads under one
firmware owner, keep the Flash navigation shell separate from execution, and
keep standalone wipe `policy_absent`. React declares only the subset it emits
in `ui/web/src/commands.ts`; a repository-level parser rejects any value
outside the Python allow-list and any runtime literal that bypasses those
constants, so the frontend does not maintain a divergent copy of the complete
host contract.

## Release gates

A row changes to `native` only when all of the following implementation
conditions are true:

1. It runs with no hidden `Main.PixelFlasher` frame and no call to a legacy
   event handler.
2. Its scoped success, cancellation and failure behavior has typed behavioral
   tests; timeout, partial failure and retry are included wherever applicable.
3. Device mutations execute only from an immutable plan bound to serial,
   connection state, firmware/image hash, partition and slot.
4. Destructive actions are rejected by the operation layer unless the exact
   reviewed plan was freshly confirmed; UI confirmation alone is insufficient.

`releaseGate` is independent of that implementation label. A stable 10.0
candidate additionally requires every `releaseGate: true` row to be `native`,
the complete keyboard/accessibility suite, and the packaged Windows, macOS and
Linux smoke matrix. A native row therefore cannot be used as evidence that the
global delivery gate has already passed.

## Updating the baseline

Update both files in the same change. Add a capability before adding a public
feature, menu handler, primary control or bridge command. Do not silently mark a
delegated action as native: include the behavioral test that proves the legacy
frame can be absent. Run:

```bash
python -m unittest tests.test_modern_parity_inventory -v
```
