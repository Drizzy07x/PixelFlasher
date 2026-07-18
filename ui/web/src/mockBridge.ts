import { demoSnapshot } from './demoData';
import { commands } from './commands';
import { demoApps, demoFirmwares } from './demoData';
import type { ActiveOperation, BridgeRequest, BridgeResponse, HostSnapshot, Locale, ModernPreferences, Theme } from './types';

const copySnapshot = (): HostSnapshot => structuredClone(demoSnapshot);

const mockRootApps = [
  { id: 'a'.repeat(64), path: 'C:\\mock\\Magisk.apk', provider: 'Magisk', flavor: 'stable', version: '30.7', sha256: '1'.repeat(64), provenance: 'official' },
  { id: 'b'.repeat(64), path: 'C:\\mock\\KernelSU.apk', provider: 'KernelSU', flavor: 'stable', version: '1.0.2', sha256: '2'.repeat(64), provenance: 'verified-download' },
  { id: 'c'.repeat(64), path: 'C:\\mock\\APatch.apk', provider: 'APatch', flavor: 'stable', version: '11039', sha256: '3'.repeat(64), provenance: 'official' },
  { id: 'd'.repeat(64), path: 'C:\\mock\\SukiSU.apk', provider: 'SukiSU', flavor: 'stable', version: '2.0', sha256: '4'.repeat(64), provenance: 'verified-download' },
] as const;

const defaultPreferences: ModernPreferences = {
  schemaVersion: 1,
  theme: 'dark',
  locale: 'en',
  highContrast: false,
  reducedMotion: false,
  zoom: 100,
};

function storedValue<T>(key: string, fallback: T): T {
  try {
    const value = window.localStorage.getItem(key);
    return value === null ? fallback : JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

function mockPreferences(): ModernPreferences {
  const theme = storedValue<Theme>('pf.theme', defaultPreferences.theme);
  const locale = storedValue<Locale>('pf.locale', defaultPreferences.locale);
  const highContrast = storedValue('pf.highContrast', defaultPreferences.highContrast);
  const reducedMotion = storedValue('pf.reducedMotion', defaultPreferences.reducedMotion);
  const zoom = storedValue('pf.zoom', defaultPreferences.zoom);
  return {
    schemaVersion: 1,
    theme: theme === 'light' ? 'light' : 'dark',
    locale: ['en', 'es', 'fr', 'it', 'zh_CN', 'zh_TW'].includes(locale) ? locale : 'en',
    highContrast: typeof highContrast === 'boolean' ? highContrast : false,
    reducedMotion: typeof reducedMotion === 'boolean' ? reducedMotion : false,
    zoom: typeof zoom === 'number' && Number.isInteger(zoom) && zoom >= 80 && zoom <= 200 ? zoom : 100,
  };
}

function persistMockPreferences(preferences: ModernPreferences) {
  const entries: [string, unknown][] = [
    ['pf.theme', preferences.theme],
    ['pf.locale', preferences.locale],
    ['pf.highContrast', preferences.highContrast],
    ['pf.reducedMotion', preferences.reducedMotion],
    ['pf.zoom', preferences.zoom],
  ];
  try {
    entries.forEach(([key, value]) => window.localStorage.setItem(key, JSON.stringify(value)));
  } catch {
    // Runtime state remains usable when storage is unavailable in a preview.
  }
}

function updatedMockPreferences(payload: Record<string, unknown>): ModernPreferences | null {
  const allowed = new Set(['schemaVersion', 'theme', 'locale', 'highContrast', 'reducedMotion', 'zoom']);
  if (Object.keys(payload).some((key) => !allowed.has(key))) return null;
  const current = mockPreferences();
  const next = { ...current, ...payload } as Record<string, unknown>;
  if (
    next.schemaVersion !== 1 ||
    (next.theme !== 'dark' && next.theme !== 'light') ||
    typeof next.locale !== 'string' ||
    !['en', 'es', 'fr', 'it', 'zh_CN', 'zh_TW'].includes(next.locale) ||
    typeof next.highContrast !== 'boolean' ||
    typeof next.reducedMotion !== 'boolean' ||
    typeof next.zoom !== 'number' ||
    !Number.isInteger(next.zoom) ||
    next.zoom < 80 ||
    next.zoom > 200
  ) return null;
  return next as unknown as ModernPreferences;
}

function emit(detail: unknown) {
  window.dispatchEvent(new CustomEvent('pixelflasher:message', { detail }));
}

function errorMessage(message: string, request: BridgeRequest): BridgeResponse {
  return {
    version: 1,
    type: 'response',
    requestId: request.requestId,
    ok: false,
    error: { code: 'MOCK_COMMAND_ERROR', message },
  };
}

export function installDevelopmentBridge() {
  if (typeof window === 'undefined' || window.pixelflasher) return;

  let snapshot = copySnapshot();
  let pendingFlash: { request: BridgeRequest; operation: ActiveOperation } | null = null;
  let pendingGuarded: { request: BridgeRequest; operationId: string; complete: () => void } | null = null;
  let mockRootModules = ['play_integrity_fix', 'zygisk_next'];

  const publishSnapshot = () => {
    emit({ version: 1, type: 'snapshot', payload: structuredClone(snapshot), revision: snapshot.revision });
  };

  const respondTo = (request: BridgeRequest, result: unknown = null) => {
    emit({
      version: 1,
      type: 'response',
      requestId: request.requestId,
      ok: true,
      result,
      revision: snapshot.revision,
    } satisfies BridgeResponse);
  };
  const respond = respondTo;

  const success = (message: string, value: Record<string, unknown> = {}) => ({
    status: 'SUCCESS',
    code: 'mock_success',
    message,
    value,
  });

  const finishOperation = (request: BridgeRequest, operation: ActiveOperation) => {
    snapshot = {
      ...snapshot,
      revision: snapshot.revision + 1,
      activeOperation: operation,
      active_operation: operation,
    };
    emit({ version: 1, type: 'progress', operation, revision: snapshot.revision });
    publishSnapshot();
    respond(request, success('Flash operation started.', { operationId: operation.id }));

    const checkpoints = [
      { progress: 18, detail: 'Checking device state' },
      { progress: 44, detail: 'Preparing partitions' },
      { progress: 76, detail: 'Writing selected images' },
      { progress: 100, detail: 'Verifying flash result' },
    ];

    checkpoints.forEach((checkpoint, index) => {
      window.setTimeout(() => {
        const status = checkpoint.progress === 100 ? 'success' : 'running';
        const next: ActiveOperation = { ...operation, ...checkpoint, status };
        snapshot = {
          ...snapshot,
          revision: snapshot.revision + 1,
          activeOperation: next,
          active_operation: next,
        };
        emit({ version: 1, type: 'progress', operation: next, revision: snapshot.revision });
        publishSnapshot();
      }, 320 * (index + 1));
    });
  };

  const finishGuarded = (request: BridgeRequest, result: Record<string, unknown>) => {
    snapshot = { ...snapshot, revision: snapshot.revision + 1 };
    respond(request, result);
    publishSnapshot();
  };

  const requestGuardedConfirmation = (
    request: BridgeRequest,
    message: string,
    destructive: boolean,
    complete: () => void,
    reinforced = false,
  ) => {
    if (pendingFlash || pendingGuarded) {
      emit(errorMessage('Another confirmation is already pending.', request));
      return;
    }
    const operationId = `guarded-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    pendingGuarded = { request, operationId, complete };
    const serial = typeof request.payload.serial === 'string' ? request.payload.serial : snapshot.selectedSerial ?? '';
    emit({
      version: 1,
      type: 'interaction',
      revision: snapshot.revision,
      payload: {
        event_type: 'interaction',
        operation_id: operationId,
        kind: 'confirm',
        title: destructive ? 'Confirm destructive operation' : 'Confirm operation',
        message,
        expected_revision: snapshot.revision,
        target_serial: serial,
        destructive,
        reinforced,
      },
    });
  };

  const requireConfirmationText = (request: BridgeRequest, requiredText: string) => {
    emit({
      version: 1,
      type: 'response',
      requestId: request.requestId,
      ok: false,
      result: {
        status: 'FAILED',
        code: 'confirmation_text_required',
        message: 'Exact confirmation text is required.',
        value: { confirmation: { required_text: requiredText, nonce: 'mock-reinforced' } },
      },
      error: { code: 'confirmation_text_required', message: 'Exact confirmation text is required.' },
      revision: snapshot.revision,
    } satisfies BridgeResponse);
  };

  window.pixelflasher = {
    __mock: true,
    __reset() {
      snapshot = copySnapshot();
      pendingFlash = null;
      pendingGuarded = null;
      mockRootModules = ['play_integrity_fix', 'zygisk_next'];
    },
    postMessage(rawMessage: string) {
      window.setTimeout(() => {
        let request: BridgeRequest;
        try {
          request = JSON.parse(rawMessage) as BridgeRequest;
        } catch {
          return;
        }

        if (request.version !== 1 || !request.requestId || !request.command) {
          emit(errorMessage('Invalid bridge request.', request));
          return;
        }

        if (
          request.expectedRevision !== null &&
          request.expectedRevision !== snapshot.revision &&
          request.command !== commands.snapshotGet
        ) {
          emit(errorMessage('The host state changed. Refresh and try again.', request));
          return;
        }

        switch (request.command) {
          case 'snapshot.get':
            respond(request, { status: 'SUCCESS', snapshot: structuredClone(snapshot) });
            publishSnapshot();
            break;
          case 'settings.get':
            respond(request, {
              status: 'SUCCESS',
              code: 'settings_loaded',
              message: 'Preferences loaded.',
              value: { preferences: mockPreferences() },
            });
            break;
          case 'settings.update': {
            const preferences = updatedMockPreferences(request.payload);
            if (!preferences) {
              emit(errorMessage('Invalid preferences.', request));
              break;
            }
            persistMockPreferences(preferences);
            respond(request, {
              status: 'SUCCESS',
              code: 'settings_updated',
              message: 'Preferences saved.',
              value: { preferences },
            });
            break;
          }
          case 'device.scan':
            snapshot = { ...snapshot, revision: snapshot.revision + 1 };
            respond(request, success(`Found ${snapshot.devices.length} devices.`, { count: snapshot.devices.length }));
            publishSnapshot();
            break;
          case 'device.select': {
            const serials = Array.isArray(request.payload.serials)
              ? request.payload.serials.filter((serial): serial is string => typeof serial === 'string')
              : [];
            snapshot = {
              ...snapshot,
              revision: snapshot.revision + 1,
              selectedSerials: serials,
              selected_serials: serials,
              selectedSerial: serials[0] ?? null,
              selected_serial: serials[0] ?? null,
            };
            respond(request, success('Device selection updated.', { serials }));
            publishSnapshot();
            break;
          }
          case 'native.pickFile': {
            const filters = Array.isArray(request.payload.filters) ? request.payload.filters : [];
            const modulePicker = filters.some((filter) => {
              const extensions = filter && typeof filter === 'object' && Array.isArray((filter as Record<string, unknown>).extensions)
                ? (filter as Record<string, unknown>).extensions as unknown[]
                : [];
              return extensions.length === 1 && extensions[0] === 'zip';
            });
            const imagePicker = filters.some((filter) => {
              const extensions = filter && typeof filter === 'object' && Array.isArray((filter as Record<string, unknown>).extensions)
                ? (filter as Record<string, unknown>).extensions as unknown[]
                : [];
              return extensions.includes('img');
            });
            respond(request, {
              status: 'SUCCESS',
              message: 'File selected.',
              data: { path: modulePicker ? 'C:\\mock\\magisk-module.zip' : imagePicker ? 'C:\\mock\\partition-image.img' : demoFirmwares[0].path },
            });
            break;
          }
          case 'native.pickFiles':
            respond(request, {
              status: 'SUCCESS',
              message: 'Files selected.',
              data: { paths: ['C:\\mock\\alpha.zip', 'C:\\mock\\beta.txt'] },
            });
            break;
          case 'native.saveFile': {
            const defaultName = typeof request.payload.defaultName === 'string' ? request.payload.defaultName : '';
            if (request.payload.purpose === 'support') {
              respond(request, {
                status: 'SUCCESS',
                message: 'Support destination selected.',
                data: { destinationId: 's'.repeat(64), displayName: defaultName || 'PixelFlasher-support.zip' },
              });
              break;
            }
            respond(request, {
              status: 'SUCCESS',
              message: 'File selected.',
              data: { path: defaultName.startsWith('patched-') ? `C:\\mock\\${defaultName}` : 'C:\\mock\\partition-backup.img' },
            });
            break;
          }
          case 'native.pickDirectory':
            respond(request, { status: 'SUCCESS', message: 'Folder selected.', data: { path: 'C:\\mock\\platform-tools' } });
            break;
          case 'firmware.select': {
            const path = typeof request.payload.path === 'string' ? request.payload.path : '';
            const firmware = demoFirmwares.find((entry) => entry.path === path);
            snapshot = {
              ...snapshot,
              revision: snapshot.revision + 1,
              firmware: firmware ?? snapshot.firmware,
              boot: null,
            };
            respond(request, success('Firmware selected.', { snapshot: structuredClone(snapshot) }));
            publishSnapshot();
            break;
          }
          case 'firmware.process': {
            if (Object.keys(request.payload).length || !snapshot.firmware) {
              emit(errorMessage('Select one canonical firmware package before processing.', request));
              break;
            }
            const firmwareHash = '8'.repeat(64);
            const bootHash = '9'.repeat(64);
            const firmware = { ...snapshot.firmware, verified: true, processed: true, hash: firmwareHash };
            const boot = firmware.kind === 'ota' ? null : {
              id: `stock:init_boot:${bootHash}`,
              path: 'C:\\mock\\firmware-cache\\init_boot.img',
              hash: bootHash,
              flavor: 'init_boot',
              patched: false,
            };
            snapshot = {
              ...snapshot,
              revision: snapshot.revision + 2,
              firmware,
              boot,
            };
            respond(request, {
              status: 'SUCCESS',
              code: 'firmware_processed',
              message: `${firmware.kind} firmware processed successfully`,
              value: { firmware: structuredClone(firmware), boot: structuredClone(boot) },
            });
            publishSnapshot();
            break;
          }
          case 'flash.plan.update':
            snapshot = {
              ...snapshot,
              revision: snapshot.revision + 1,
              plan: {
                mode: request.payload.mode,
                options: request.payload.options,
                revision: Number((snapshot.plan as Record<string, unknown> | null)?.revision ?? 0) + 1,
                fingerprint: `mock-${Date.now()}`,
              },
            };
            respond(request, success('Flash plan updated.', { snapshot: structuredClone(snapshot) }));
            publishSnapshot();
            break;
          case 'flash.plan.preview': {
            const mode = String((snapshot.plan as Record<string, unknown> | null)?.mode ?? '').toLowerCase();
            const serial = typeof request.payload.serial === 'string' ? request.payload.serial : snapshot.selectedSerial ?? '';
            const target = snapshot.devices.find((device) => device.serial === serial);
            if (!target || (mode === 'ota' ? target.mode !== 'sideload' : target.mode !== 'fastboot')) {
              emit(errorMessage(mode === 'ota' ? 'OTA requires sideload mode.' : 'Image flashing requires Fastboot mode.', request));
              break;
            }
            if (snapshot.firmware?.device && snapshot.firmware.device !== target.codename) {
              emit(errorMessage('The selected firmware does not match the target device.', request));
              break;
            }
            if ((mode === 'ota') !== (snapshot.firmware?.kind === 'ota')) {
              emit(errorMessage(mode === 'ota' ? 'Select an OTA package.' : 'OTA packages require OTA sideload mode.', request));
              break;
            }
            const destructive = true;
            const requiredText = mode === 'wipe' || mode === 'wipedata' ? `WIPE ${serial} ${target?.codename ?? 'unknown'}` : '';
            respond(request, success('Flash plan previewed.', {
              compiled: {
                ok: true,
                destructive,
                requires_confirmation: destructive,
                confirmation: requiredText ? { required_text: requiredText, nonce: 'mock-confirmation' } : null,
                plan: {
                  label: `Flash ${target?.name ?? serial}`,
                  target_serial: serial,
                  expected_device_state: target?.mode ?? '',
                  data_behavior: mode === 'wipe' ? 'wipe' : 'preserve',
                  partitions: mode === 'ota' ? ['ota-package'] : ['boot', 'system', 'vendor'],
                  slots: mode === 'ota' ? [] : ['a'],
                  requests: mode === 'ota'
                    ? [{ argv: ['adb.exe', '-s', serial, 'sideload', snapshot.firmware?.path ?? 'firmware.zip'] }]
                    : [
                        { argv: ['adb.exe', '-s', serial, 'reboot', 'bootloader'] },
                        { argv: ['fastboot.exe', '-s', serial, 'update', snapshot.firmware?.path ?? 'firmware.zip', ...(mode === 'wipe' ? ['-w'] : [])] },
                      ],
                },
              },
            }));
            break;
          }
          case 'flash.execute': {
            const operation: ActiveOperation = {
              id: `flash-${Date.now()}`,
              label: 'Flash devices',
              status: 'running',
              progress: 4,
              detail: 'Validating flash plan',
            };
            if (pendingFlash || pendingGuarded) {
              emit(errorMessage('Another confirmation is already pending.', request));
              break;
            }
            pendingFlash = { request, operation };
            const serial = typeof request.payload.serial === 'string' ? request.payload.serial : snapshot.selectedSerial ?? '';
            const target = snapshot.devices.find((device) => device.serial === serial);
            emit({
              version: 1,
              type: 'interaction',
              revision: snapshot.revision,
              payload: {
                event_type: 'interaction',
                operation_id: operation.id,
                kind: 'confirm',
                title: 'Confirm destructive operation',
                message: `Run the verified flash plan on device ${serial}?`,
                expected_revision: snapshot.revision,
                target_serial: serial,
                destructive: true,
                reinforced: String((snapshot.plan as Record<string, unknown> | null)?.mode ?? '').toLowerCase() === 'wipe',
                codename: target?.codename ?? '',
              },
            });
            break;
          }
          case 'root.apps.list':
            respond(request, {
              status: 'SUCCESS',
              code: 'root_apps_list_succeeded',
              message: `found ${mockRootApps.length} local root app(s)`,
              value: { count: mockRootApps.length, apps: structuredClone(mockRootApps) },
            });
            break;
          case 'root.apps.install': {
            const serial = typeof request.payload.serial === 'string' ? request.payload.serial : snapshot.selectedSerial ?? '';
            const target = snapshot.devices.find((device) => device.serial === serial);
            const app = mockRootApps.find((candidate) => candidate.id === request.payload.appId);
            if (!target || target.mode !== 'adb' || !app) {
              emit(errorMessage(!app ? 'Rooting app is no longer available.' : 'Rooting app install requires one ADB device.', request));
              break;
            }
            requestGuardedConfirmation(
              request,
              `Install ${app.provider} ${app.flavor} on device ${serial}?`,
              false,
              () => finishGuarded(request, {
                status: 'SUCCESS',
                code: 'root_app_installed',
                message: `installed ${app.provider} ${app.flavor}`,
                value: { action: 'install', targetSerial: serial, app: structuredClone(app) },
              }),
            );
            break;
          }
          case 'root.modules.list': {
            const serial = typeof request.payload.serial === 'string' ? request.payload.serial : snapshot.selectedSerial ?? '';
            const target = snapshot.devices.find((device) => device.serial === serial);
            if (!target || target.mode !== 'adb' || !target.rooted) {
              emit(errorMessage('Magisk modules require one rooted ADB device.', request));
              break;
            }
            respond(request, {
              status: 'SUCCESS',
              code: 'root_modules_list_succeeded',
              message: `found ${mockRootModules.length} Magisk module(s)`,
              value: { count: mockRootModules.length, modules: mockRootModules.map((id) => ({ id })) },
            });
            break;
          }
          case 'root.modules.action': {
            const serial = typeof request.payload.serial === 'string' ? request.payload.serial : snapshot.selectedSerial ?? '';
            const target = snapshot.devices.find((device) => device.serial === serial);
            const action = request.payload.action;
            if (!target || target.mode !== 'adb' || !target.rooted || !['install', 'enable', 'disable', 'remove'].includes(String(action))) {
              emit(errorMessage('Invalid Magisk module action.', request));
              break;
            }
            const moduleId = action === 'install' ? 'mock_module' : request.payload.moduleId;
            if (typeof moduleId !== 'string' || !/^[A-Za-z][A-Za-z0-9._-]{0,63}$/.test(moduleId)) {
              emit(errorMessage('Invalid Magisk module identifier.', request));
              break;
            }
            if (action === 'install' && typeof request.payload.path !== 'string') {
              emit(errorMessage('A module ZIP is required.', request));
              break;
            }
            const destructive = action === 'install' || action === 'remove';
            requestGuardedConfirmation(
              request,
              `${String(action)} Magisk module ${moduleId} on device ${serial}?`,
              destructive,
              () => {
                if (action === 'install' && !mockRootModules.includes(moduleId)) mockRootModules = [...mockRootModules, moduleId];
                if (action === 'remove') mockRootModules = mockRootModules.filter((id) => id !== moduleId);
                finishGuarded(request, {
                  status: 'SUCCESS',
                  code: `root_module_${action === 'install' ? 'installed' : action === 'enable' ? 'enabled' : action === 'disable' ? 'disabled' : 'removed'}`,
                  message: `${String(action)} Magisk module ${moduleId}`,
                  value: {
                    action,
                    targetSerial: serial,
                    moduleId,
                    artifact: action === 'install'
                      ? { path: request.payload.path, sha256: '5'.repeat(64), role: `root-module-zip:${moduleId}` }
                      : null,
                  },
                });
              },
            );
            break;
          }
          case 'boot.patch': {
            const serial = typeof request.payload.serial === 'string' ? request.payload.serial : snapshot.selectedSerial ?? '';
            const target = snapshot.devices.find((device) => device.serial === serial);
            const flavor = typeof request.payload.flavor === 'string' ? request.payload.flavor : '';
            const destination = typeof request.payload.destination === 'string' ? request.payload.destination : '';
            const app = mockRootApps.find((candidate) => candidate.id === request.payload.appId);
            if (!target || target.mode !== 'adb' || !flavor || !destination.endsWith('.img') || !app) {
              emit(errorMessage('Boot patch payload is incomplete or no verified app is available.', request));
              break;
            }
            requestGuardedConfirmation(
              request,
              `Patch the selected boot image with ${flavor} on device ${serial}?`,
              false,
              () => {
                const hash = '6'.repeat(64);
                snapshot = { ...snapshot, boot: { id: hash.slice(0, 16), path: destination, hash, flavor: 'boot', patched: true } };
                finishGuarded(request, {
                  status: 'SUCCESS',
                  code: 'boot_patched',
                  message: `patched boot with ${flavor}`,
                  value: {
                    patchedBoot: { artifact: { path: destination, sha256: hash, role: `patched-boot:${flavor}` }, sourceSha256: '7'.repeat(64), flavor, partition: 'boot' },
                    boot: snapshot.boot,
                  },
                });
              },
            );
            break;
          }
          case 'interaction.respond': {
            const operationId = request.payload.operationId;
            const decision = request.payload.decision;
            if (decision !== 'accepted' && decision !== 'cancelled') {
              emit(errorMessage('Interaction is no longer pending.', request));
              break;
            }
            if (pendingFlash && operationId === pendingFlash.operation.id) {
              const pending = pendingFlash;
              pendingFlash = null;
              respond(request, success('Decision recorded.'));
              if (decision === 'accepted') finishOperation(pending.request, pending.operation);
              else emit({
                version: 1,
                type: 'response',
                requestId: pending.request.requestId,
                ok: false,
                error: { code: 'operation_cancelled', message: 'Operation was cancelled.' },
                revision: snapshot.revision,
              } satisfies BridgeResponse);
              break;
            }
            if (pendingGuarded && operationId === pendingGuarded.operationId) {
              const pending = pendingGuarded;
              pendingGuarded = null;
              respond(request, success('Decision recorded.'));
              if (decision === 'accepted') pending.complete();
              else emit({
                version: 1,
                type: 'response',
                requestId: pending.request.requestId,
                ok: false,
                error: { code: 'operation_cancelled', message: 'Operation was cancelled.' },
                revision: snapshot.revision,
              } satisfies BridgeResponse);
              break;
            }
            emit(errorMessage('Interaction is no longer pending.', request));
            break;
          }
          case 'device.reboot': {
            const serial = typeof request.payload.serial === 'string' ? request.payload.serial : snapshot.selectedSerial ?? '';
            const mode = typeof request.payload.mode === 'string' ? request.payload.mode : 'system';
            const target = snapshot.devices.find((device) => device.serial === serial);
            if (!target || !['system', 'recovery', 'bootloader', 'fastbootd'].includes(mode)) {
              emit(errorMessage('Reboot target is unavailable.', request));
              break;
            }
            const nextMode = mode === 'system' ? 'adb' : mode === 'bootloader' ? 'fastboot' : mode === 'fastbootd' ? 'fastbootd' : 'recovery';
            snapshot = {
              ...snapshot,
              revision: snapshot.revision + 1,
              devices: snapshot.devices.map((device) => device.serial === serial ? { ...device, mode: nextMode } : device),
            };
            respond(request, success(`Rebooted ${serial} to ${mode}.`));
            publishSnapshot();
            break;
          }
          case 'device.switchSlot': {
            const serial = typeof request.payload.serial === 'string' ? request.payload.serial : snapshot.selectedSerial ?? '';
            const slot = request.payload.slot === 'a' || request.payload.slot === 'b' ? request.payload.slot : '';
            const target = snapshot.devices.find((device) => device.serial === serial);
            if (!target || target.mode !== 'fastboot' || !slot) {
              emit(errorMessage('Slot switching requires one Fastboot device.', request));
              break;
            }
            const requiredText = `SWITCH ${serial} TO SLOT ${slot}`;
            if (request.payload.confirmationText !== requiredText) {
              requireConfirmationText(request, requiredText);
              break;
            }
            requestGuardedConfirmation(
              request,
              `Switch ${serial} to slot ${slot}?`,
              true,
              () => {
                snapshot = {
                  ...snapshot,
                  devices: snapshot.devices.map((device) => device.serial === serial ? { ...device, slot } : device),
                };
                finishGuarded(request, success(`Switched ${serial} to slot ${slot}.`));
              },
              true,
            );
            break;
          }
          case 'device.bootloader.lock':
          case 'device.bootloader.unlock': {
            const serial = typeof request.payload.serial === 'string' ? request.payload.serial : snapshot.selectedSerial ?? '';
            const target = snapshot.devices.find((device) => device.serial === serial);
            const action = request.command.endsWith('unlock') ? 'UNLOCK' : 'LOCK';
            if (!target || target.mode !== 'fastboot') {
              emit(errorMessage('Bootloader management requires one Fastboot device.', request));
              break;
            }
            if (action === 'LOCK' && !snapshot.bootloaderLockEvidence?.some((evidence) => evidence.serial === serial)) {
              emit(errorMessage('Locking requires verified complete stock factory flash evidence.', request));
              break;
            }
            const requiredText = `${action} ${serial} ${target.codename || 'unknown'}`;
            if (request.payload.confirmationText !== requiredText) {
              requireConfirmationText(request, requiredText);
              break;
            }
            requestGuardedConfirmation(
              request,
              `${action === 'LOCK' ? 'Lock' : 'Unlock'} the bootloader on ${serial}? This wipes user data.`,
              true,
              () => {
                const bootloader = action === 'LOCK' ? 'locked' : 'unlocked';
                snapshot = {
                  ...snapshot,
                  devices: snapshot.devices.map((device) => device.serial === serial ? { ...device, bootloader } : device),
                };
                finishGuarded(request, success(`${action === 'LOCK' ? 'Locked' : 'Unlocked'} bootloader on ${serial}.`));
              },
              true,
            );
            break;
          }
          case 'boot.live':
          case 'boot.flash': {
            const serial = typeof request.payload.serial === 'string' ? request.payload.serial : snapshot.selectedSerial ?? '';
            const target = snapshot.devices.find((device) => device.serial === serial);
            const live = request.command === 'boot.live';
            if (!target || target.mode !== 'fastboot' || target.bootloader !== 'unlocked' || !snapshot.boot?.path || !snapshot.boot.hash) {
              emit(errorMessage('A verified boot image and one unlocked Fastboot device are required.', request));
              break;
            }
            if (live && snapshot.boot.flavor !== 'boot') {
              emit(errorMessage('Live boot supports only a boot image.', request));
              break;
            }
            requestGuardedConfirmation(
              request,
              live ? `Live boot the verified image on ${serial}?` : `Flash the verified ${snapshot.boot.flavor || 'boot'} image on ${serial}?`,
              !live,
              () => finishGuarded(request, success(live ? `Live boot started on ${serial}.` : `Flashed boot image on ${serial}.`)),
            );
            break;
          }
          case 'partitions.list':
            respond(request, success('Partitions listed.', {
              partitions: [
                { name: 'boot_a', size_bytes: 67108864, partition_type: 'raw' },
                { name: 'init_boot_a', size_bytes: 8388608, partition_type: 'raw' },
                { name: 'userdata', size_bytes: 128849018880, partition_type: 'ext4' },
              ],
            }));
            break;
          case 'partitions.read':
            respond(request, success(`Read ${String(request.payload.partition)} image.`));
            break;
          case 'partitions.write':
            requestGuardedConfirmation(
              request,
              `Write ${String(request.payload.partition)} on ${String(request.payload.serial)}?`,
              true,
              () => finishGuarded(request, success(`Wrote ${String(request.payload.partition)} image.`)),
            );
            break;
          case 'partitions.erase': {
            const serial = typeof request.payload.serial === 'string' ? request.payload.serial : snapshot.selectedSerial ?? '';
            const selectedPartition = typeof request.payload.partition === 'string' ? request.payload.partition : '';
            const requiredText = `ERASE ${serial} ${selectedPartition}`;
            if (!selectedPartition || request.payload.confirmationText !== requiredText) {
              requireConfirmationText(request, requiredText);
              break;
            }
            requestGuardedConfirmation(
              request,
              `Erase ${selectedPartition} on ${serial}?`,
              true,
              () => finishGuarded(request, success(`Erased ${selectedPartition}.`)),
              true,
            );
            break;
          }
          case 'tools.logcat':
            respond(request, success('Collected 3 log lines.', {
              lineCount: 3,
              lines: [
                '07-18 17:12:01.100 I/ActivityManager: PixelFlasher test ready',
                '07-18 17:12:01.220 D/PackageManager: package scan complete',
                '07-18 17:12:01.440 W/DeviceIdle: mock preview only',
              ],
            }));
            break;
          case 'tools.scrcpy':
            respond(request, success('scrcpy launched for the selected device', { pid: 4242 }));
            break;
          case 'tools.wifi': {
            const action = typeof request.payload.action === 'string' ? request.payload.action : '';
            respond(request, success(`ADB Wi-Fi ${action} succeeded`, {
              action,
              ...(action === 'status' ? { state: 'device' } : { endpoint: `${String(request.payload.host)}:${String(request.payload.port)}` }),
            }));
            break;
          }
          case 'tools.pushFiles':
            requestGuardedConfirmation(
              request,
              `Push selected files to ${String(request.payload.destination)}?`,
              false,
              () => finishGuarded(request, success('Pushed 2 files.', { count: 2 })),
            );
            break;
          case 'support.create':
            respond(request, success('Created redacted support package.', {
              displayName: 'PixelFlasher-support.zip',
              includedCount: 4,
            }));
            break;
          case 'platformTools.setup':
          case 'backups.create':
          case 'backups.restore':
          case 'apps.action':
          case 'tools.adbShell':
          case 'tools.avb':
            respond(request, success('Command accepted.'));
            break;
          case 'apps.list':
            respond(request, success('Packages listed.', {
              packages: demoApps.map((app) => ({
                package: app.id,
                apk_path: app.scope === 'System' ? `/system/app/${app.id}.apk` : `/data/app/${app.id}.apk`,
              })),
            }));
            break;
          default:
            respond(request, success('Command accepted.', { command: request.command }));
        }
      }, 45);
    },
  };
}
