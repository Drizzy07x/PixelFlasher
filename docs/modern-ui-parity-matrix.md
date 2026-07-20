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
| About/help surface | partial | none | The accessible React surface and native allow-listed links are live; signed update status and packaged dev/RC version derivation remain open. |
| Backup, settings and tools workspaces | partial | none | Tools now has native flows for scrcpy, wireless ADB, bounded logcat, file push, partitions and support export; advanced utilities and the documented postconditions remain open. |
| Scan/select/manage devices | native | device read/host write | Typed adb/fastboot discovery reads serial-bound `current-slot`, `unlocked` and `is-userspace`, distinguishes fastbootd and preserves stable identity without reusing stale operational state. A versioned manager persists aliases and enabled state, pauses/resumes hotplug, switches between enabled/all scope, repairs selection and migrates the bounded 9.x roster with an automatic backup. |
| Platform Tools setup | partial | host write | Signed official downloads and opaque-grant directories use pinned manifests, versioned atomic installation, binary/version probes and transactional activation. The audited stable 37.0.0 source lock covers five host targets with exact upstream/local hashes and real binary architectures; an offline signer, strict runtime loader and v10 fail-closed release gate are delivered. Production Ed25519 key custody, final signed catalog generation and packaged remote smokes remain. |
| Select/process factory, OTA and custom ROM packages | partial | host read/write | React exposes separate factory/OTA and custom-ROM native-grant controls; `expectedKind` is validated by bridge and backend so the wrong package class fails before persistence. A streaming AOSP whole-file verifier rejects malformed or tampered OTA signatures, official artifacts remain bound to the signed Ed25519 catalog, trusted OTA signers can pass directly and every other local package requires one hash-bound reinforced confirmation. React shows the closed trust receipt. Direct images and custom/OTA `payload.bin` use the bounded parser and packaged verified extractor. Stock boot images are promoted into BootRepository with firmware/device provenance; failed revisioned promotion rolls back firmware/boot rows, content-addressed objects, planner registrations and extracted output. Manual retry is explicit, never automatic, retains only an opaque artifact/firmware identity and invalidates a processing retry when selection changes. A deterministic, route-free CLI smoke now proves the packaged grant → trust → selection → processing → `init_boot` promotion cycle and is wired into all seven targets. Production signer roots, real fixtures and remote matrix results remain open. |
| List/import/select/delete boot images | native | host read/write | `BootRepository` owns content-addressed boot records and provenance. Import/select use opaque IDs or purpose-bound grants. `boot.delete` is revisioned, rejects the canonical selection and active operations, preserves shared objects, exposes a closed storage receipt and uses an accessible inline React confirmation. A bounded startup collector reclaims canonical unowned objects after deferred unlink failures while preserving live, linked and unknown files. |
| Rooting Apps catalog/download/install | partial | host/device write | Backend Ed25519 manifests cover stable/beta/canary entries for all seven providers. The official stable source lock now pins non-spoofed APKs with release URL, size, SHA-256, package, signer, schemes and ABIs; a reproducible network audit verified all seven real APKs, while an offline builder reinspects them and emits a strict 13-target signed runtime catalog. React receives opaque IDs and closed metadata only. Production key custody/catalog generation and packaged download/install smokes remain open. |
| Firmware downloads | partial | host write | A firmware-owned React catalog now refreshes signed backend manifests by device/channel and downloads by opaque artifact ID with cancellation, ETag/Range cache validation, SHA-256 inspection, official provenance and final selection. Production signed catalogs and packaged official-source smokes remain open. |
| Keep-data, wipe, dry-run and OTA planning | partial | device write/destructive | React intent, verified factory/direct-image artifacts and backend enforcement exist. Dry-run is complete for factory, OTA and custom ROM, including immutable process-free multi-device previews. Wipe is confined to its canonical flash mode with individual and fingerprint-bound batch confirmations; pre-mutation cancellation runs no process and post-boundary uncertainty fails as `outcome_unknown`. OTA owns ADB/recovery→sideload plus build/slot verification, while factory/custom plans split bootloader and dynamic partitions across fastboot/fastbootd with explicit waits. Firmware kinds cannot cross incompatible modes and temporary-root/no-reboot ambiguity is rejected. Downgrade artifact production and packaged coverage remain open. |
| Review and execute flash | partial | destructive | Browser preview and execute use the trusted backend planner and registered firmware artifacts. Multi-device flash executes sequentially, revalidates every target and stops at the first failure. OTA and dynamic-partition plans own their sideload/fastbootd transitions. A verified safe factory flash across both slots now emits revision-bound, one-use relock evidence; complete packaged-platform/WebView/hardware validation remains open. |
| Patch boot images | partial | device write | React, bridge and backend contracts cover all seven flavors. The packaged owned runner covers Magisk, APatch and KernelSU-family LKM patchers with ABI-bound BusyBox resources; the audited official APK inputs and strict signed-catalog loader are connected at startup. APatch delivers its one-use secret only through stdin. `create_boot_tar` now publishes a deterministic verified Odin archive atomically. The pinned KernelSU Legacy release has no usable kernel/module input, so Legacy remains explicitly fail-closed. Production catalog signing, a reproducible Legacy input and packaged/real-device smokes remain open. |
| Flash/live-boot images | partial | device write/destructive | React controls and exact-argv, serial/hash-bound backend plans exist with unlocked-fastboot guards. Flash success requires bounded readback and SHA-256 verification of the slot-qualified target partition; live boot requires an observed ADB reconnection and `boot_completed`. Mismatch and unavailable evidence fail explicitly. Packaged-platform and real-device validation remain open. |
| Raw boot-chain backup/restore | partial | device write | Safe backend create/restore and React path/partition/slot inputs exist; persisted inventory, provenance display and Magisk import/delete remain open. |
| Application packages and APK install | partial | device/host write and destructive | PackageService and React cover canonical listing, enable/disable, uninstall with keep-data, clear-data, force-stop, launch, bounded permissions, Magisk denylist, SU allow/deny/revoke, verified APK export and APK installation. Export resolves the device path below the UI, uses a write-once grant, validates APK identity/hash, publishes atomically and proves cleanup. Play Store ownership is a typed boolean that compiles to exact argv and is independently verified from Android's installer report. Root actions are root-gated and independently observed. Packaged cross-platform smokes remain open. |
| Partition manager | partial | destructive | React list/read/write/erase controls, native pickers and the allow-listed guarded backend exist; device-side verification after write/erase and richer progress/retry remain open. |
| Logcat and file push | native | destructive device write and host write | Logcat provides bounded snapshot and incremental stream modes, serial/revision binding, cancellation, all legacy format verbs/modifiers, typed tag/priority plus Expert regex/UID filters, configurable redaction and atomic export through a one-use native grant. Remote clearing is serialized and success-gated: backend command completion is combined with a differential sentinel in the main buffer, without claiming that every buffer remains empty. File push uses opaque superseding grants, private verified staging, closed destinations, bounded per-file progress, explicit cancellation/manual retry and batched remote SHA-256 verification with a bounded `toybox` fallback. |
| Reboot and slot switch | native | device write | Reboot to system, bootloader, fastbootd, recovery, safe mode and sideload uses serial/revision-bound plans and observed mode, boot-completion or safe-mode postconditions. Vendor download mode is explicitly policy-absent and fails closed as `reboot_download_unverifiable` without starting a process. Slot switching verifies `fastboot getvar current-slot` after reconnection. |
| Scrcpy and wireless ADB | partial | device write | Scrcpy now has typed React options, serial-bound argv, managed cancellation, a signed-manifest ZIP/TAR installer, confined extraction, architecture/version/hash verification, atomic activation and a route-free receipt. Production Ed25519 manifests plus packaged window/process smokes remain; wireless disconnected-device handoff is still open. |
| Interactive ADB shell | partial | destructive | Expert Mode opens a revision- and serial-bound xterm.js terminal through fixed `adb -s SERIAL shell` argv, explicitly selected ConPTY on Windows and PTY on macOS/Linux. Windows packages retain the required console subsystem but hide it at the earliest bootloader stage, so no classic window is visible. Input/output/resize are bounded, binary output crosses the bridge as base64, and state/toolchain/device changes close the session. A closed packaged-process smoke now opens the native PTY backend, observes output and clean exit, and is wired into Windows x64/ARM64, macOS Intel/ARM, Ubuntu 22/24 and AppImage CI; local Windows x64 PTY and WebView smokes pass without residual processes. Remote matrix results plus terminal-specific axe and NVDA/VoiceOver/Orca validation remain. |
| Sanitized support package | partial | host write | Native destination grants, strict allow-listed collection, mandatory redaction, a sanitized SQLite copy, an inclusion/omission manifest and atomic AES-256-GCM output with RSA-OAEP key wrapping are tested. Production recipient-key injection and packaged interoperability validation remain open. |
| Modern presentation preferences | native | host write | The immutable host-backed contract covers appearance, accessibility, Expert Mode, safety, maintenance, patch/processing, typography and toolbar layout. A closed registry classifies all 31 advanced 9.x settings as migrated, safely replaced or policy-enforced; no option is silently retired. Generative schema round-trips and strict invalid-type tests cover the full contract. Packaged visual/accessibility smokes remain release gates, not implementation gaps. |
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
dry-run starts zero subprocesses; multiple selected devices produce one
immutable, non-executable preview plan per device without exposing host paths.
`FirmwareArtifactService` now extracts and registers verified factory and direct-image custom artifacts, registers the
verified OTA source, and atomically promotes the canonical firmware and stock
boot state. This row remains `partial` because custom `payload.bin` processing,
runtime recovery/fastbootd transitions and multi-device batch execution remain
open.

Eleven bounded service groups now use reviewed planner/policy/executor or local
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
  Fastboot/Fastbootd partitions. Reads fetch into private staging and publish
  atomically through a one-use native grant; writes and erases require bounded
  device-side readback. React exposes typed receipts, progress, cancellation
  and manual-only retry; erase uses reinforced confirmation.
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
- `AdbTerminalService` is a separate expert-only lifecycle boundary. It passes
  open through `SafetyPolicy`, launches only fixed `adb -s SERIAL shell` argv
  without a host shell, bounds terminal dimensions and I/O chunks, and closes
  the PTY when revision, selected serial, device mode/connectivity or toolchain
  changes. React receives only versioned terminal events, never a host command.
- `BackupService` creates and restores bounded boot-chain partition images.
  `BackupRepository` atomically imports them into a persistent content-addressed
  SQLite inventory, exposes only opaque IDs and provenance, rehashes a managed
  object immediately before restore, and deletes metadata before best-effort
  object cleanup under an exact reinforced confirmation.
- `RootingService` inventories backend-owned verified rooting APKs, installs by
  opaque identifier and manages validated Magisk modules with action-specific
  confirmation metadata. Module updates are fetched only in the backend,
  confined to bounded public HTTPS code-hosting origins, inspected into a
  private content-addressed cache, addressed by a serial-bound opaque ID, and
  guarded by the source versionCode immediately before Magisk mutates the
  device. Identity, SHA-256, presence and resulting versionCode are verified.
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
- `MyToolsService` keeps safe profiles on pinned, revalidated executable argv.
  Imported Legacy Raw profiles remain backend-owned and are isolated behind
  Expert Mode, content-bound persistent permission, exact per-run confirmation,
  restricted working directories and bounded host-shell execution. React sees
  the exact reviewed preview but never sends a command, cwd or environment.

These are backend-native contracts, not claims of complete UI parity. The Apps
page refreshes canonical rows through `apps.list`, exposes enable/disable,
uninstall, clear-data, force-stop, launch, bounded permission reports, Magisk
denylist, verified SU policy controls and route-free verified APK export, and
installs verified APKs without revealing host paths, including typed Play Store
ownership with independent installer-source observation. Packaged smokes stay
open. The Tools page now owns the bounded logcat viewer, expert ADB terminal,
scrcpy, wireless ADB, file-push, partition and support-package flows, but each row stays
partial until its documented packaging, postcondition, progress or legacy-data
gap is closed. Backups now renders the canonical persisted raw-image inventory,
provenance and typed create/restore/delete results without exposing host paths;
the distinct on-device Magisk backup-manager semantics remain open.

`ModernPreferences` and `ApplicationRuntime` implement a strict revisioned
`settings.get`/`settings.update` contract for the complete supported settings
surface. `LEGACY_PREFERENCE_POLICIES` exhaustively classifies all 31 options
from `advanced_settings.py`; migrated values retain 9.x mirrors, incompatible
path/shell controls have explicit safe replacements, and security invariants
are enforced rather than user-disableable. `ConfigStore` supplies atomic
writes and backup. The real React host loads and serializes those values through
the bridge; only the isolated development mock uses local storage. Settings
remains `partial` solely for expanded property coverage and packaged
cross-platform visual/accessibility validation.

Destructive confirmation is end to end: `SafetyPolicy` produces an
`InteractionRequest`, `InteractionBroker` publishes it through the host, the
accessible React modal answers with `interaction.respond`, and the engine
rechecks safety and plan validity after the user response. Cancellation never
becomes implicit success.

## Legacy-only capability groups

| Area | Missing or partial behaviors |
|---|---|
| Device connection | Bounded mDNS discovery is native without a selected device, and versioned scan/hotplug management is complete. Pair/connect without a selected ADB target and disconnected-device handoff remain. Portable reboot destinations are verified; vendor download mode is policy-absent because it has no portable backend postcondition. |
| Applications | Packaged cross-platform smokes remain; listing, install with verified Play Store ownership, verified export, denylist, SU and the other package actions are connected to React. |
| Device tools | Confirm the packaged ADB PTY process receipts across the remote Windows/macOS/Linux matrix, provision production Scrcpy manifests/smokes and supply a reproducibly sourced OTA fallback runner. The expert terminal, packaged smoke, Scrcpy installer and managed lifecycle are implemented. Safe HTTP(S) URL opening, per-slot bootloader inspection, otacerts, bounded Logcat, filtered logs and closed update_engine status are native. Root-only OTA cancel/reset now has confirmation, an immediate non-mutating preflight, fixed host shell-free argv, independent idle observation and correct pre/post-mutation cancellation semantics. A hash-bound fallback is still required for devices without a compatible system client; opaque legacy binaries remain excluded. |
| Boot and flash | Boot-record mutation, complete device/slot postcondition coverage, custom `payload.bin`, remaining runtime recovery/fastbootd validation, real patch APK/runner resources and KMI/architecture-based kernel selection. Stock-flash relock evidence and a firmware-bound AVB downgrade flow now exist; their packaged/hardware validation remains. |
| Support | Production recipient-key provisioning, packaged v1-read/v2-write interoperability and complete console/log redaction validation. |
| Backups | Raw-backup inventory/results are persistent and route-free; complete the distinct Magisk list/import/delete behavior. |
| Root and integrity | `/data/adb` now rejects the complete hostile tar matrix and distinguishes verified pre-mutation staging failures from `outcome_unknown` cancellation/disconnection after the mutation-bearing request starts; packaged rooted-device smokes remain. PIF/TargetedFix, PI analysis, Shizuku and SOS still require their hardware/release validation. |
| Developer/personal tools | Production signed keybox revocation evidence and packaged validation of AVB downgrade, binary XML and local keybox remain. My Tools safe argv and the isolated Legacy Raw permission/confirmation flow are technically complete; their schema-v2 smoke proves grant/hash/reload/direct argv plus the restricted native-shell boundary in the Windows x64 package and is wired into the remaining release targets. |
| Application shell | Production signed update manifests and packaged dev/RC version derivation. The 31 advanced 9.x preferences have an explicit migration/replacement/enforcement policy. About/help and allow-listed native links are implemented. Backend-owned Configuration, Logs and Cache folders, safe revisioned exit, persistent top/right/bottom/left toolbar layout and a bounded redacted console with clear plus atomic one-use-grant export are implemented without exposing paths or opening classic dialogs. |

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
