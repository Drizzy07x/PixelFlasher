import { demoSnapshot } from './demoData';
import { commands } from './commands';
import { demoApps, demoFirmwares } from './demoData';
import type { ActiveOperation, BridgeRequest, BridgeResponse, HostSnapshot, Locale, ModernPreferences, Theme } from './types';

const copySnapshot = (): HostSnapshot => structuredClone(demoSnapshot);
const validFontFace = (value: unknown): value is string => typeof value === 'string'
  && value.length >= 1
  && value.length <= 96
  && value === value.trim()
  && !/[\u0000-\u001f\u007f"'\\,;{}()]/u.test(value);

const mockRootApps = [
  { id: 'a'.repeat(64), provider: 'Magisk', flavor: 'stable', version: '30.7', sha256: '1'.repeat(64), provenance: 'official', packageName: 'com.topjohnwu.magisk', signerSha256: ['9'.repeat(64)], schemes: ['v2', 'v3'], architecture: 'universal' },
  { id: 'b'.repeat(64), provider: 'KernelSU', flavor: 'stable', version: '1.0.2', sha256: '2'.repeat(64), provenance: 'verified-download', packageName: 'me.weishu.kernelsu', signerSha256: ['8'.repeat(64)], schemes: ['v2'], architecture: 'arm64-v8a' },
  { id: 'c'.repeat(64), provider: 'APatch', flavor: 'stable', version: '11039', sha256: '3'.repeat(64), provenance: 'official', packageName: 'me.bmax.apatch', signerSha256: ['7'.repeat(64)], schemes: ['v2'], architecture: 'arm64-v8a' },
  { id: 'd'.repeat(64), provider: 'SukiSU', flavor: 'stable', version: '2.0', sha256: '4'.repeat(64), provenance: 'verified-download', packageName: 'com.sukisu.ultra', signerSha256: ['6'.repeat(64)], schemes: ['v2'], architecture: 'arm64-v8a' },
] as const;

const mockRootAppCatalog = [{
  artifactId: 'e'.repeat(32),
  provider: 'Wild_KSU',
  channel: 'stable',
  flavor: 'stable',
  version: '1.0.0',
  architecture: 'arm64-v8a',
  packageName: 'com.wild.ksu',
  signerSha256: ['5'.repeat(64)],
  sha256: 'f'.repeat(64),
  size: 12_345_678,
  license: 'GPL-3.0',
  provenance: 'official release',
}] as const;

const mockDownloadedRootApp = {
  id: 'e'.repeat(64),
  provider: 'Wild_KSU',
  flavor: 'stable',
  version: '1.0.0',
  sha256: 'f'.repeat(64),
  provenance: 'verified-download',
  packageName: 'com.wild.ksu',
  signerSha256: ['5'.repeat(64)],
  schemes: ['v2'],
  architecture: 'arm64-v8a',
} as const;

type MockBackupRecord = {
  id: string;
  sha256: string;
  sizeBytes: number;
  createdAt: number;
  targetSerial: string;
  deviceCodename: string;
  partition: string;
  slot: 'a' | 'b';
  targetPartition: string;
  provenance: 'created' | 'user_supplied';
  available: boolean;
  integrity: 'stored' | 'missing';
};

const defaultPreferences: ModernPreferences = {
  schemaVersion: 1,
  theme: 'dark',
  locale: 'en',
  highContrast: false,
  reducedMotion: false,
  zoom: 100,
  expertMode: false,
  automaticUpdateCheck: false,
  checkDiskSpace: true,
  checkBootloaderUnlocked: true,
  checkFirmwareHash: true,
  checkModuleUpdates: false,
  showNotifications: false,
  rebootTimeoutSeconds: 90,
  offerPatchMethods: false,
  showRecoveryPatching: false,
  keepPatchTemporaryFiles: false,
  useBusyboxShell: false,
  lowMemoryMode: false,
  extraImageExtracts: false,
  showCustomRomOptions: false,
  keyboxIndex: false,
  customizeFont: false,
  fontFace: 'Courier',
  fontSize: 12,
  toolbarPosition: 'top',
  toolbarShowDevice: true,
  toolbarShowTheme: true,
  toolbarShowLanguage: true,
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
  const expertMode = storedValue('pf.expertMode', defaultPreferences.expertMode);
  const automaticUpdateCheck = storedValue('pf.automaticUpdateCheck', defaultPreferences.automaticUpdateCheck);
  const checkDiskSpace = storedValue('pf.checkDiskSpace', defaultPreferences.checkDiskSpace);
  const checkBootloaderUnlocked = storedValue('pf.checkBootloaderUnlocked', defaultPreferences.checkBootloaderUnlocked);
  const checkFirmwareHash = storedValue('pf.checkFirmwareHash', defaultPreferences.checkFirmwareHash);
  const checkModuleUpdates = storedValue('pf.checkModuleUpdates', defaultPreferences.checkModuleUpdates);
  const showNotifications = storedValue('pf.showNotifications', defaultPreferences.showNotifications);
  const rebootTimeoutSeconds = storedValue('pf.rebootTimeoutSeconds', defaultPreferences.rebootTimeoutSeconds);
  const offerPatchMethods = storedValue('pf.offerPatchMethods', false);
  const showRecoveryPatching = storedValue('pf.showRecoveryPatching', false);
  const keepPatchTemporaryFiles = storedValue('pf.keepPatchTemporaryFiles', false);
  const useBusyboxShell = storedValue('pf.useBusyboxShell', false);
  const lowMemoryMode = storedValue('pf.lowMemoryMode', false);
  const extraImageExtracts = storedValue('pf.extraImageExtracts', false);
  const showCustomRomOptions = storedValue('pf.showCustomRomOptions', false);
  const keyboxIndex = storedValue('pf.keyboxIndex', false);
  const customizeFont = storedValue('pf.customizeFont', false);
  const fontFace = storedValue('pf.fontFace', 'Courier');
  const fontSize = storedValue('pf.fontSize', 12);
  const toolbarPosition = storedValue('pf.toolbarPosition', 'top');
  const toolbarShowDevice = storedValue('pf.toolbarShowDevice', true);
  const toolbarShowTheme = storedValue('pf.toolbarShowTheme', true);
  const toolbarShowLanguage = storedValue('pf.toolbarShowLanguage', true);
  return {
    schemaVersion: 1,
    theme: theme === 'light' ? 'light' : 'dark',
    locale: ['en', 'es', 'fr', 'it', 'zh_CN', 'zh_TW'].includes(locale) ? locale : 'en',
    highContrast: typeof highContrast === 'boolean' ? highContrast : false,
    reducedMotion: typeof reducedMotion === 'boolean' ? reducedMotion : false,
    zoom: typeof zoom === 'number' && Number.isInteger(zoom) && zoom >= 80 && zoom <= 200 ? zoom : 100,
    expertMode: typeof expertMode === 'boolean' ? expertMode : false,
    automaticUpdateCheck: typeof automaticUpdateCheck === 'boolean' ? automaticUpdateCheck : false,
    checkDiskSpace: typeof checkDiskSpace === 'boolean' ? checkDiskSpace : true,
    checkBootloaderUnlocked: typeof checkBootloaderUnlocked === 'boolean' ? checkBootloaderUnlocked : true,
    checkFirmwareHash: typeof checkFirmwareHash === 'boolean' ? checkFirmwareHash : true,
    checkModuleUpdates: typeof checkModuleUpdates === 'boolean' ? checkModuleUpdates : false,
    showNotifications: typeof showNotifications === 'boolean' ? showNotifications : false,
    rebootTimeoutSeconds: typeof rebootTimeoutSeconds === 'number' && Number.isInteger(rebootTimeoutSeconds)
      && rebootTimeoutSeconds >= 1 && rebootTimeoutSeconds <= 3600 ? rebootTimeoutSeconds : 90,
    offerPatchMethods: typeof offerPatchMethods === 'boolean' ? offerPatchMethods : false,
    showRecoveryPatching: typeof showRecoveryPatching === 'boolean' ? showRecoveryPatching : false,
    keepPatchTemporaryFiles: typeof keepPatchTemporaryFiles === 'boolean' ? keepPatchTemporaryFiles : false,
    useBusyboxShell: typeof useBusyboxShell === 'boolean' ? useBusyboxShell : false,
    lowMemoryMode: typeof lowMemoryMode === 'boolean' ? lowMemoryMode : false,
    extraImageExtracts: typeof extraImageExtracts === 'boolean' ? extraImageExtracts : false,
    showCustomRomOptions: typeof showCustomRomOptions === 'boolean' ? showCustomRomOptions : false,
    keyboxIndex: typeof keyboxIndex === 'boolean' ? keyboxIndex : false,
    customizeFont: typeof customizeFont === 'boolean' ? customizeFont : false,
    fontFace: validFontFace(fontFace) ? fontFace : 'Courier',
    fontSize: typeof fontSize === 'number' && Number.isInteger(fontSize) && fontSize >= 6 && fontSize <= 50 ? fontSize : 12,
    toolbarPosition: typeof toolbarPosition === 'string' && ['top', 'right', 'bottom', 'left'].includes(toolbarPosition)
      ? toolbarPosition as ModernPreferences['toolbarPosition'] : 'top',
    toolbarShowDevice: typeof toolbarShowDevice === 'boolean' ? toolbarShowDevice : true,
    toolbarShowTheme: typeof toolbarShowTheme === 'boolean' ? toolbarShowTheme : true,
    toolbarShowLanguage: typeof toolbarShowLanguage === 'boolean' ? toolbarShowLanguage : true,
  };
}

function persistMockPreferences(preferences: ModernPreferences) {
  const entries: [string, unknown][] = [
    ['pf.theme', preferences.theme],
    ['pf.locale', preferences.locale],
    ['pf.highContrast', preferences.highContrast],
    ['pf.reducedMotion', preferences.reducedMotion],
    ['pf.zoom', preferences.zoom],
    ['pf.expertMode', preferences.expertMode],
    ['pf.automaticUpdateCheck', preferences.automaticUpdateCheck],
    ['pf.checkDiskSpace', preferences.checkDiskSpace],
    ['pf.checkBootloaderUnlocked', preferences.checkBootloaderUnlocked],
    ['pf.checkFirmwareHash', preferences.checkFirmwareHash],
    ['pf.checkModuleUpdates', preferences.checkModuleUpdates],
    ['pf.showNotifications', preferences.showNotifications],
    ['pf.rebootTimeoutSeconds', preferences.rebootTimeoutSeconds],
    ['pf.offerPatchMethods', preferences.offerPatchMethods],
    ['pf.showRecoveryPatching', preferences.showRecoveryPatching],
    ['pf.keepPatchTemporaryFiles', preferences.keepPatchTemporaryFiles],
    ['pf.useBusyboxShell', preferences.useBusyboxShell],
    ['pf.lowMemoryMode', preferences.lowMemoryMode],
    ['pf.extraImageExtracts', preferences.extraImageExtracts],
    ['pf.showCustomRomOptions', preferences.showCustomRomOptions],
    ['pf.keyboxIndex', preferences.keyboxIndex],
    ['pf.customizeFont', preferences.customizeFont],
    ['pf.fontFace', preferences.fontFace],
    ['pf.fontSize', preferences.fontSize],
    ['pf.toolbarPosition', preferences.toolbarPosition],
    ['pf.toolbarShowDevice', preferences.toolbarShowDevice],
    ['pf.toolbarShowTheme', preferences.toolbarShowTheme],
    ['pf.toolbarShowLanguage', preferences.toolbarShowLanguage],
  ];
  try {
    entries.forEach(([key, value]) => window.localStorage.setItem(key, JSON.stringify(value)));
  } catch {
    // Runtime state remains usable when storage is unavailable in a preview.
  }
}

function updatedMockPreferences(payload: Record<string, unknown>): ModernPreferences | null {
  const allowed = new Set([
    'schemaVersion', 'theme', 'locale', 'highContrast', 'reducedMotion', 'zoom', 'expertMode',
    'automaticUpdateCheck', 'checkDiskSpace', 'checkBootloaderUnlocked', 'checkFirmwareHash',
    'checkModuleUpdates', 'showNotifications', 'rebootTimeoutSeconds',
    'offerPatchMethods', 'showRecoveryPatching', 'keepPatchTemporaryFiles', 'useBusyboxShell',
    'lowMemoryMode', 'extraImageExtracts', 'showCustomRomOptions', 'keyboxIndex',
    'customizeFont', 'fontFace', 'fontSize', 'toolbarPosition', 'toolbarShowDevice',
    'toolbarShowTheme', 'toolbarShowLanguage',
  ]);
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
    || typeof next.expertMode !== 'boolean'
    || typeof next.automaticUpdateCheck !== 'boolean'
    || typeof next.checkDiskSpace !== 'boolean'
    || typeof next.checkBootloaderUnlocked !== 'boolean'
    || typeof next.checkFirmwareHash !== 'boolean'
    || typeof next.checkModuleUpdates !== 'boolean'
    || typeof next.showNotifications !== 'boolean'
    || typeof next.rebootTimeoutSeconds !== 'number'
    || !Number.isInteger(next.rebootTimeoutSeconds)
    || next.rebootTimeoutSeconds < 1
    || next.rebootTimeoutSeconds > 3600
    || typeof next.offerPatchMethods !== 'boolean'
    || typeof next.showRecoveryPatching !== 'boolean'
    || typeof next.keepPatchTemporaryFiles !== 'boolean'
    || typeof next.useBusyboxShell !== 'boolean'
    || typeof next.lowMemoryMode !== 'boolean'
    || typeof next.extraImageExtracts !== 'boolean'
    || typeof next.showCustomRomOptions !== 'boolean'
    || typeof next.keyboxIndex !== 'boolean'
    || typeof next.customizeFont !== 'boolean'
    || !validFontFace(next.fontFace)
    || typeof next.fontSize !== 'number'
    || !Number.isInteger(next.fontSize)
    || next.fontSize < 6
    || next.fontSize > 50
    || (next.toolbarPosition !== 'top' && next.toolbarPosition !== 'right'
      && next.toolbarPosition !== 'bottom' && next.toolbarPosition !== 'left')
    || typeof next.toolbarShowDevice !== 'boolean'
    || typeof next.toolbarShowTheme !== 'boolean'
    || typeof next.toolbarShowLanguage !== 'boolean'
  ) return null;
  return next as unknown as ModernPreferences;
}

function emit(detail: unknown) {
  window.dispatchEvent(new CustomEvent('pixelflasher:message', { detail }));
}

function errorMessage(message: string, request: BridgeRequest): BridgeResponse {
  return {
    version: 2,
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
  let mockDisabledRootModules = new Set<string>();
  let mockPifFavoriteRevision = 0;
  let mockPifFavorites: Array<{
    favoriteId: string; label: string; createdAt: string; sha256: string; size: number; content: string;
  }> = [];
  let mockBootImages: Array<{
    bootId: string;
    sha256: string;
    size: number;
    provenance: string;
    createdAt: number;
    partition: 'boot' | 'init_boot' | 'vendor_boot' | 'vendor_kernel_boot';
    deviceCodenames: string[];
    patcher: string;
    patcherVersion: string;
    signature: string;
    sourceHash: string;
    patched: boolean;
    verified: boolean;
  }> = [];
  let backupSequence = 1;
  let mockMagiskBackups = [{
    sha1: '1'.repeat(40),
    sizeBytes: 64 * 1024 * 1024,
    createdAt: 1_752_816_600,
    integrity: 'verified' as const,
  }];
  let mockBackups: MockBackupRecord[] = snapshot.devices.slice(0, 2).map((device, index) => {
    const partition = index ? 'init_boot' : 'boot';
    const slot = device.slot === 'b' ? 'b' : 'a';
    return {
      id: String(index + 1).repeat(32),
      sha256: String(index + 3).repeat(64),
      sizeBytes: 64 * 1024 * 1024,
      createdAt: 1_752_816_600 - index * 86_400,
      targetSerial: device.serial,
      deviceCodename: device.codename,
      partition,
      slot,
      targetPartition: `${partition}_${slot}`,
      provenance: index ? 'user_supplied' : 'created',
      available: true,
      integrity: 'stored',
    };
  });

  const publishSnapshot = () => {
    emit({ version: 2, event: 'snapshot', revision: snapshot.revision, payload: structuredClone(snapshot) });
  };

  const respondTo = (request: BridgeRequest, result: Record<string, unknown>) => {
    emit({
      version: 2,
      requestId: request.requestId,
      ok: true,
      result: { ...result, revision: snapshot.revision },
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
    emit({
      version: 2,
      event: 'progress',
      payload: {
        event_type: 'progress',
        operation_id: operation.id,
        phase: 'execute',
        message: operation.detail ?? operation.label,
        percent: operation.progress ?? 0,
      },
      revision: snapshot.revision,
    });
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
        emit({
          version: 2,
          event: 'progress',
          payload: {
            event_type: 'progress',
            operation_id: next.id,
            phase: status === 'success' ? 'finished' : 'execute',
            message: next.detail ?? next.label,
            percent: next.progress ?? 0,
          },
          revision: snapshot.revision,
        });
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
      version: 2,
      event: 'interaction',
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
      version: 2,
      requestId: request.requestId,
      ok: false,
      error: {
        code: 'confirmation_text_required',
        message: 'Exact confirmation text is required.',
        details: {
          status: 'FAILED',
          code: 'confirmation_text_required',
          message: 'Exact confirmation text is required.',
          value: { confirmation: { required_text: requiredText, nonce: 'mock-reinforced' } },
        },
      },
    } satisfies BridgeResponse);
  };

  window.pixelflasher = {
    __mock: true,
    __reset() {
      snapshot = copySnapshot();
      pendingFlash = null;
      pendingGuarded = null;
      mockRootModules = ['play_integrity_fix', 'zygisk_next'];
      mockDisabledRootModules = new Set<string>();
      mockBootImages = [];
    },
    postMessage(rawMessage: string) {
      window.setTimeout(() => {
        let request: BridgeRequest;
        try {
          request = JSON.parse(rawMessage) as BridgeRequest;
        } catch {
          return;
        }

        if (request.version !== 2 || !request.requestId || !request.command) {
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
          case 'app.console.export':
            respond(request, { status: 'SUCCESS', code: 'console_exported', message: 'Redacted console exported.' });
            return;
          case 'app.openFolder': {
            const target = request.payload.target;
            if (!['configuration', 'logs', 'cache'].includes(String(target))) {
              emit(errorMessage('The requested application folder is unavailable.', request));
              return;
            }
            respond(request, { status: 'SUCCESS', code: 'application_directory_opened', message: 'Application folder opened.', target });
            return;
          }
          case 'app.exit':
            respond(request, { status: 'SUCCESS', code: 'exit_requested', message: 'PixelFlasher is closing.' });
            return;
          case 'snapshot.get':
            respond(request, structuredClone(snapshot) as unknown as Record<string, unknown>);
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
          case 'device.ota.status':
            respond(request, {
              status: 'SUCCESS',
              code: 'ota_update_engine_status_inspected',
              message: 'update_engine state is idle',
              value: {
                action: 'status',
                state: 'idle',
                progress: 0,
                idle: true,
                lastAttemptError: 'ErrorCode::kSuccess',
                bounded: true,
              },
            });
            break;
          case 'device.inspect': {
            const serial = typeof request.payload.serial === 'string' ? request.payload.serial : '';
            const action = typeof request.payload.action === 'string' ? request.payload.action : '';
            const target = snapshot.devices.find((device) => device.serial === serial);
            if (!target || target.mode !== 'adb') {
              emit(errorMessage('Device inspection requires one ADB device.', request));
              break;
            }
            const properties = {
              'ro.boot.slot_suffix': `_${target.slot}`,
              'ro.bootloader': 'akita-mock-1.0',
              'ro.build.display.id': target.build,
              'ro.build.version.release': target.androidVersion,
              'ro.build.version.security_patch': target.securityPatch,
              'ro.product.device': target.codename,
              'ro.product.manufacturer': 'Google',
              'ro.product.model': target.model,
              'ro.serialno': '[REDACTED]',
            };
            const values: Record<string, Record<string, unknown>> = {
              properties: {
                action,
                targetSerial: serial,
                count: Object.keys(properties).length,
                properties,
                redactedKeys: ['ro.serialno'],
                summary: {
                  manufacturer: 'Google',
                  model: target.model,
                  codename: target.codename,
                  androidVersion: target.androidVersion,
                  build: target.build,
                  securityPatch: target.securityPatch,
                  bootloader: 'akita-mock-1.0',
                },
              },
              screenXml: {
                action,
                targetSerial: serial,
                xml: '<?xml version="1.0" encoding="UTF-8"?>\n<hierarchy rotation="0"><node text="PixelFlasher demo" /></hierarchy>',
                sha256: 'a'.repeat(64),
                nodeCount: 2,
                redactedFields: 0,
              },
              bootloaderVersions: {
                action,
                targetSerial: serial,
                source: 'abl_slots',
                current: 'akita-mock-1.0',
                activeSlot: target.slot === 'b' ? 'b' : 'a',
                bootloaderCodename: 'akita',
                slots: {
                  a: {
                    partition: 'abl_a',
                    version: 'mock-1.0',
                    fullVersion: 'akita-mock-1.0',
                    sha256: 'a'.repeat(64),
                    sizeBytes: 64 * 1024 * 1024,
                  },
                  b: {
                    partition: 'abl_b',
                    version: 'mock-1.0',
                    fullVersion: 'akita-mock-1.0',
                    sha256: 'b'.repeat(64),
                    sizeBytes: 64 * 1024 * 1024,
                  },
                },
                activeMatchesReported: true,
              },
              pifPrint: {
                action,
                targetSerial: serial,
                format: 'playintegrityfork-v5-compatible',
                profile: {
                  MANUFACTURER: 'Google',
                  MODEL: target.model,
                  FINGERPRINT: `google/${target.codename}/${target.codename}:demo/${target.build}:user/release-keys`,
                  PRODUCT: target.codename,
                  DEVICE: target.codename,
                  SECURITY_PATCH: target.securityPatch,
                  DEVICE_INITIAL_SDK_INT: '32',
                },
              },
            };
            const value = values[action];
            if (!value) {
              emit(errorMessage('Unknown device inspection action.', request));
              break;
            }
            respond(request, {
              status: 'SUCCESS',
              code: `device_inspection_${action}_succeeded`,
              message: 'Device inspection completed.',
              value,
            });
            break;
          }
          case 'device.openUrl': {
            const serial = typeof request.payload.serial === 'string' ? request.payload.serial : '';
            const rawUrl = typeof request.payload.url === 'string' ? request.payload.url : '';
            const target = snapshot.devices.find((device) => device.serial === serial);
            let parsed: URL;
            try {
              parsed = new URL(rawUrl);
            } catch {
              emit(errorMessage('The URL is invalid.', request));
              break;
            }
            if (!target || target.mode !== 'adb' || !['http:', 'https:'].includes(parsed.protocol)) {
              emit(errorMessage('Opening a URL requires one ADB device and an HTTP(S) address.', request));
              break;
            }
            respond(request, {
              status: 'SUCCESS',
              code: 'device_open_url_succeeded',
              message: 'The device accepted the browser intent.',
              value: {
                action: 'openUrl',
                targetSerial: serial,
                scheme: parsed.protocol.slice(0, -1),
                host: parsed.hostname,
                urlSha256: 'd'.repeat(64),
                intentAccepted: true,
              },
            });
            break;
          }
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
          case 'secret.issue': {
            const purpose = String(request.payload.purpose);
            respond(request, {
              status: 'SUCCESS',
              message: 'Native secret approved.',
              data: {
                grant: 's'.repeat(64),
                purpose,
                consumeOnce: true,
                expiresInSeconds: 60,
              },
            });
            break;
          }
          case 'native.pickFile': {
            const purpose = String(request.payload.purpose);
            respond(request, {
              status: 'SUCCESS',
              message: 'File selected.',
              data: {
                grant: 'g'.repeat(64),
                purpose,
                target: 'file',
                access: 'read',
                consumeOnce: false,
                expiresInSeconds: null,
                displayName: purpose === 'root.modules.install' ? 'magisk-module.zip' : 'selected-file.img',
              },
            });
            break;
          }
          case 'native.pickFiles': {
            const purpose = String(request.payload.purpose);
            respond(request, {
              status: 'SUCCESS',
              message: 'Files selected.',
              data: {
                purpose,
                grants: ['g', 'h'].map((prefix, index) => ({
                  grant: prefix.repeat(64),
                  purpose,
                  target: 'file',
                  access: 'read',
                  consumeOnce: false,
                  expiresInSeconds: null,
                  displayName: index ? 'beta.txt' : 'alpha.zip',
                })),
              },
            });
            break;
          }
          case 'native.saveFile': {
            const defaultName = typeof request.payload.defaultName === 'string' ? request.payload.defaultName : '';
            const purpose = String(request.payload.purpose);
            respond(request, {
              status: 'SUCCESS',
              message: 'File selected.',
              data: {
                grant: 'w'.repeat(64),
                purpose,
                target: 'file',
                access: 'write',
                consumeOnce: true,
                expiresInSeconds: 300,
                displayName: defaultName || 'selected-output.bin',
              },
            });
            break;
          }
          case 'native.pickDirectory': {
            const purpose = String(request.payload.purpose);
            respond(request, {
              status: 'SUCCESS',
              message: 'Folder selected.',
              data: {
                grant: 'd'.repeat(64),
                purpose,
                target: 'directory',
                access: 'read',
                consumeOnce: false,
                expiresInSeconds: null,
                displayName: 'platform-tools',
              },
            });
            break;
          }
          case 'firmware.catalog.refresh': {
            const device = String(request.payload.device);
            const channel = String(request.payload.channel ?? 'stable');
            const entry = {
              artifactId: 'a'.repeat(32),
              device,
              channel,
              kind: 'factory',
              version: 'AP4A.260719.001',
              sha256: 'b'.repeat(64),
              size: 2_000_000_000,
              license: 'Google Terms',
              provenance: 'Google Pixel official images',
            };
            respond(request, success('Official catalog refreshed.', {
              count: 1, entries: [entry], device, channel, revision: snapshot.revision,
            }));
            break;
          }
          case 'firmware.download': {
            const artifactId = String(request.payload.artifactId);
            const entry = {
              artifactId,
              device: snapshot.devices[0]?.codename ?? 'akita',
              channel: 'stable',
              kind: 'factory',
              version: 'AP4A.260719.001',
              sha256: 'b'.repeat(64),
              size: 2_000_000_000,
              license: 'Google Terms',
              provenance: 'Google Pixel official images',
            };
            snapshot = {
              ...snapshot,
              revision: snapshot.revision + 1,
              firmware: {
                id: entry.sha256,
                name: entry.version,
                device: entry.device,
                build: entry.version,
                version: entry.version,
                securityPatch: '2026-07-05',
                kind: 'factory',
                channel: 'stable',
                size: '1.86 GiB',
                hash: entry.sha256,
                verified: true,
                processed: false,
              },
              boot: null,
            };
            respond(request, success('Firmware downloaded and selected.', {
              artifact: entry, cacheHit: false, resumed: false, revision: snapshot.revision,
            }));
            publishSnapshot();
            break;
          }
          case 'firmware.select': {
            const firmwareId = typeof request.payload.firmwareId === 'string' ? request.payload.firmwareId : '';
            const selected = demoFirmwares.find((firmware) => firmware.id === firmwareId) ?? demoFirmwares[0];
            snapshot = {
              ...snapshot,
              revision: snapshot.revision + 1,
              firmware: selected,
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
            const selectedSerials = snapshot.selectedSerials
              ?? (snapshot.selectedSerial ? [snapshot.selectedSerial] : []);
            const serials = typeof request.payload.serial === 'string'
              ? [request.payload.serial]
              : selectedSerials;
            const targets = serials.map((serial) => snapshot.devices.find((device) => device.serial === serial));
            const target = targets[0];
            const otaModes = new Set(['adb', 'recovery', 'sideload']);
            const imageModes = new Set(['fastboot', 'fastbootd']);
            if (!target || targets.some((item) => !item || (mode === 'ota' ? !otaModes.has(item.mode) : !imageModes.has(item.mode)))) {
              emit(errorMessage(mode === 'ota' ? 'OTA requires ADB, recovery or sideload mode.' : 'Image flashing requires Fastboot mode.', request));
              break;
            }
            if (snapshot.firmware?.device && targets.some((item) => item?.codename !== snapshot.firmware?.device)) {
              emit(errorMessage('The selected firmware does not match the target device.', request));
              break;
            }
            if ((mode === 'ota') !== (snapshot.firmware?.kind === 'ota')) {
              emit(errorMessage(mode === 'ota' ? 'Select an OTA package.' : 'OTA packages require OTA sideload mode.', request));
              break;
            }
            const dryRun = (snapshot.plan as Record<string, unknown> | null)?.options
              && ((snapshot.plan as Record<string, unknown>).options as Record<string, unknown>).dryRun === true;
            const destructive = !dryRun;
            const requiredText = destructive && (mode === 'wipe' || mode === 'wipedata') ? `WIPE ${serials[0]} ${target?.codename ?? 'unknown'}` : '';
            const plans = targets.map((item, index) => ({
              label: `Flash ${item?.name ?? serials[index]}`,
              target_serial: serials[index],
              expected_device_state: item?.mode ?? '',
              data_behavior: mode === 'wipe' ? 'wipe' : 'preserve',
              partitions: mode === 'ota' ? ['ota-package'] : ['boot', 'system', 'vendor'],
              slots: mode === 'ota' ? [] : ['a'],
              requests: mode === 'ota'
                ? [
                    ...(item?.mode === 'sideload' ? [] : [
                      { argv: ['adb.exe', '-s', serials[index], 'reboot', 'sideload'] },
                      { argv: ['adb.exe', '-s', serials[index], 'wait-for-sideload'] },
                    ]),
                    { argv: ['adb.exe', '-s', serials[index], 'sideload', snapshot.firmware?.name ?? 'selected-firmware'] },
                  ]
                : [
                    { argv: ['adb.exe', '-s', serials[index], 'reboot', 'bootloader'] },
                    { argv: ['fastboot.exe', '-s', serials[index], 'update', snapshot.firmware?.name ?? 'selected-firmware', ...(mode === 'wipe' ? ['-w'] : [])] },
                  ],
            }));
            respond(request, success('Flash plan previewed.', {
              compiled: {
                ok: true,
                destructive,
                requires_confirmation: destructive,
                confirmation: requiredText ? { required_text: requiredText, nonce: 'mock-confirmation' } : null,
                plan: plans.length === 1 ? plans[0] : null,
                ...(plans.length > 1 ? { batch: { plans, targetSerials: serials } } : {}),
              },
            }));
            break;
          }
          case 'flash.execute': {
            const dryRun = (snapshot.plan as Record<string, unknown> | null)?.options
              && ((snapshot.plan as Record<string, unknown>).options as Record<string, unknown>).dryRun === true;
            const selectedSerials = snapshot.selectedSerials ?? [];
            if (dryRun && typeof request.payload.serial !== 'string' && selectedSerials.length > 1) {
              respond(request, success(`Planned ${selectedSerials.length} devices without launching a subprocess.`));
              break;
            }
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
              version: 2,
              event: 'interaction',
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
          case 'boot.inventory':
            respond(request, {
              status: 'SUCCESS',
              code: 'boot_inventory_listed',
              message: `found ${mockBootImages.length} boot image(s)`,
              value: {
                boots: structuredClone(mockBootImages),
                selectedBootId: snapshot.boot?.id ?? null,
                revision: snapshot.revision,
              },
            });
            break;
          case 'boot.select': {
            let selected = mockBootImages.find((entry) => entry.bootId === request.payload.bootId);
            if (typeof request.payload.grant === 'string') {
              const partition = request.payload.partition;
              if (!['boot', 'init_boot', 'vendor_boot', 'vendor_kernel_boot'].includes(String(partition))) {
                emit(errorMessage('A supported boot partition is required.', request));
                break;
              }
              selected = {
                bootId: 'e'.repeat(32),
                sha256: '7'.repeat(64),
                size: 67_108_864,
                provenance: 'user_supplied',
                createdAt: Math.floor(Date.now() / 1000),
                partition: partition as 'boot' | 'init_boot' | 'vendor_boot' | 'vendor_kernel_boot',
                deviceCodenames: [],
                patcher: '',
                patcherVersion: '',
                signature: '',
                sourceHash: '',
                patched: false,
                verified: true,
              };
              mockBootImages = [selected, ...mockBootImages.filter((entry) => entry.bootId !== selected?.bootId)];
            }
            if (!selected?.verified) {
              emit(errorMessage('The requested verified boot image is unavailable.', request));
              break;
            }
            snapshot = {
              ...snapshot,
              revision: snapshot.revision + 1,
              boot: {
                id: selected.bootId,
                image: `${selected.partition}.img`,
                hash: selected.sha256,
                flavor: selected.partition,
                patched: selected.patched,
                verified: true,
              },
            };
            respond(request, {
              status: 'SUCCESS',
              code: typeof request.payload.grant === 'string' ? 'boot_imported' : 'boot_selected',
              message: 'Verified boot image selected.',
              value: { selected: structuredClone(selected), revision: snapshot.revision },
            });
            publishSnapshot();
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
          case 'root.apps.catalog.refresh':
            respond(request, {
              status: 'SUCCESS',
              code: 'root_app_catalog_refreshed',
              message: `Loaded ${mockRootAppCatalog.length} verified root application(s).`,
              value: {
                count: mockRootAppCatalog.length,
                entries: structuredClone(mockRootAppCatalog),
                channel: request.payload.channel ?? 'stable',
                revision: snapshot.revision,
              },
            });
            break;
          case 'root.apps.download':
            snapshot = { ...snapshot, revision: snapshot.revision + 1 };
            respond(request, {
              status: 'SUCCESS',
              code: 'root_app_download_registered',
              message: 'Root application was downloaded, verified, and registered.',
              value: {
                artifact: structuredClone(mockRootAppCatalog[0]),
                app: structuredClone(mockDownloadedRootApp),
                cacheHit: false,
                resumed: false,
                revision: snapshot.revision,
              },
            });
            publishSnapshot();
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
              value: {
                count: mockRootModules.length,
                modules: mockRootModules.map((id) => ({
                  id,
                  name: id === 'play_integrity_fix' ? 'Play Integrity Fix' : id === 'zygisk_next' ? 'Zygisk Next' : id,
                  version: '1.0.0',
                  versionCode: 100,
                  author: 'PixelFlasher demo',
                  description: 'Verified demo module metadata.',
                  state: mockDisabledRootModules.has(id) ? 'disabled' : 'enabled',
                  updateMetadata: 'absent',
                })),
              },
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
            if (action === 'install' && typeof request.payload.grant !== 'string') {
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
                if (action === 'remove') {
                  mockRootModules = mockRootModules.filter((id) => id !== moduleId);
                  mockDisabledRootModules.delete(moduleId);
                }
                if (action === 'enable') mockDisabledRootModules.delete(moduleId);
                if (action === 'disable') mockDisabledRootModules.add(moduleId);
                finishGuarded(request, {
                  status: 'SUCCESS',
                  code: `root_module_${action === 'install' ? 'installed' : action === 'enable' ? 'enabled' : action === 'disable' ? 'disabled' : 'removed'}`,
                  message: `${String(action)} Magisk module ${moduleId}`,
                  value: {
                    action,
                    targetSerial: serial,
                    moduleId,
                    artifact: action === 'install'
                      ? { path: 'C:\\mock\\magisk-module.zip', sha256: '5'.repeat(64), role: `root-module-zip:${moduleId}` }
                      : null,
                  },
                });
              },
            );
            break;
          }
          case 'tools.shizuku': {
            const serial = typeof request.payload.serial === 'string' ? request.payload.serial : snapshot.selectedSerial ?? '';
            const target = snapshot.devices.find((device) => device.serial === serial);
            if (!target || target.mode !== 'adb' || request.payload.action !== 'start') {
              emit(errorMessage('Shizuku requires one ADB device.', request));
              break;
            }
            requestGuardedConfirmation(
              request,
              `Start Shizuku on device ${serial}?`,
              false,
              () => finishGuarded(request, {
                status: 'SUCCESS',
                code: 'shizuku_started',
                message: 'Shizuku is running',
                value: { action: 'startShizuku', targetSerial: serial, verified: true },
              }),
            );
            break;
          }
          case 'tools.piAnalysis': {
            const serial = typeof request.payload.serial === 'string' ? request.payload.serial : snapshot.selectedSerial ?? '';
            const target = snapshot.devices.find((device) => device.serial === serial);
            if (!target || target.mode !== 'adb' || !target.rooted || request.payload.action !== 'analyze') {
              emit(errorMessage('Play Integrity analysis requires one rooted ADB device.', request));
              break;
            }
            const kinds = [
              'pif_custom_json', 'pif_custom_prop', 'pif_module_json', 'pif_legacy_json',
              'pif_app_replace', 'pif_scripts_only', 'tricky_spoof', 'tricky_target',
              'tricky_security_patch', 'tricky_tee', 'targeted_targets', 'keybox',
            ];
            respond(request, {
              status: 'SUCCESS',
              code: 'pi_analysis_completed',
              message: 'redacted Play Integrity analysis completed',
              value: {
                schemaVersion: 1,
                redacted: true,
                complete: true,
                device: {
                  codename: target.codename || 'unknown',
                  build: 'AP4A.260101.001',
                  rootAccess: 'verified',
                  testKeys: false,
                  overlayVisible: false,
                },
                packages: [
                  { id: 'gms', installed: true, version: '25.20.33', versionCode: 252033000 },
                  { id: 'play_store', installed: true, version: '46.2.39', versionCode: 84623900 },
                ],
                modules: mockRootModules.slice().sort().map((id) => ({
                  id,
                  state: mockDisabledRootModules.has(id) ? 'disabled' : 'enabled',
                })),
                configs: kinds.map((kind) => ({
                  kind,
                  present: kind === 'pif_custom_json' || kind === 'keybox',
                  size: kind === 'pif_custom_json' ? 512 : kind === 'keybox' ? 2048 : 0,
                  sha256: kind === 'pif_custom_json' ? 'a'.repeat(64) : null,
                })),
                signals: { targetedFixTargetCount: 2, magiskDenylistCount: 3, droidGuardVmCount: 1 },
                withheld: ['android_ids', 'device_serial', 'keybox_material', 'raw_config_contents', 'raw_logs', 'target_package_names'],
              },
            });
            break;
          }
          case 'root.pif.inventory': {
            const serial = typeof request.payload.serial === 'string' ? request.payload.serial : snapshot.selectedSerial ?? '';
            const target = snapshot.devices.find((device) => device.serial === serial);
            if (!target || target.mode !== 'adb' || !target.rooted) {
              emit(errorMessage('PIF inventory requires one rooted ADB device.', request));
              break;
            }
            const specs = [
              ['pif.custom_json', 'playintegrityfix', 'json'],
              ['pif.custom_prop', 'playintegrityfix', 'prop'],
              ['pif.module_json', 'playintegrityfix', 'json'],
              ['pif.legacy_json', 'playintegrityfix', 'json'],
              ['pif.app_replace', 'playintegrityfix', 'list'],
              ['pif.scripts_only', 'playintegrityfix', 'marker'],
              ['tricky.spoof', 'tricky_store', 'prop'],
              ['tricky.target', 'tricky_store', 'list'],
              ['tricky.security_patch', 'tricky_store', 'text'],
              ['tricky.tee', 'tricky_store', 'text'],
              ['targeted.targets', 'targetedfix', 'list'],
            ];
            const profiles = specs.map(([id, module, format], index) => ({
              id, module, format, present: index === 0, size: index === 0 ? 512 : 0,
              sha256: index === 0 ? 'a'.repeat(64) : null,
            }));
            respond(request, {
              status: 'SUCCESS',
              code: 'pif_inventory_listed',
              message: 'verified PIF and TargetedFix inventory completed',
              value: {
                schemaVersion: 1,
                rootAccess: 'verified',
                bounded: true,
                count: profiles.length,
                profiles,
                targetCount: 1,
                targets: [{
                  packageName: 'com.google.android.gms', format: 'json', present: true,
                  size: 64, sha256: 'b'.repeat(64),
                }],
              },
            });
            break;
          }
          case 'root.pif.transform': {
            const source = typeof request.payload.content === 'string' ? request.payload.content : '';
            try {
              const values = request.payload.inputFormat === 'json'
                ? JSON.parse(source) as Record<string, unknown>
                : Object.fromEntries(source.split(/\r?\n/).filter((line) => line.trim() && !line.trim().startsWith('#')).map((line) => {
                  const separator = line.indexOf('=');
                  if (separator < 1) throw new Error('invalid property');
                  return [line.slice(0, separator).trim(), line.slice(separator + 1).trim()];
                }));
              if (request.payload.firstApi !== undefined) values.FIRST_API_LEVEL = String(request.payload.firstApi);
              const entries = Object.entries(values);
              if (request.payload.sortKeys === true) entries.sort(([left], [right]) => left.localeCompare(right));
              const outputFormat = String(request.payload.outputFormat);
              const content = outputFormat === 'json'
                ? `${JSON.stringify(Object.fromEntries(entries), null, 2)}\n`
                : outputFormat === 'prop'
                  ? `${entries.map(([key, value]) => `${key}=${String(value)}`).join('\n')}\n`
                  : `// PixelFlasher FrameworkPatcher profile\n${['MANUFACTURER', 'MODEL', 'FINGERPRINT', 'BRAND', 'PRODUCT', 'DEVICE', 'RELEASE', 'ID', 'INCREMENTAL', 'TYPE', 'TAGS', 'SECURITY_PATCH'].map((key) => `map.put("${key}", "${String(values[key] ?? '')}");`).join('\n')}\n`;
              const sha256 = content.length.toString(16).padStart(64, '0').slice(-64);
              respond(request, success('PIF profile transformed.', {
                schemaVersion: 1, format: outputFormat, content, sha256,
                size: new TextEncoder().encode(content).length, fieldCount: entries.length,
                bounded: true,
              }));
            } catch {
              emit(errorMessage('PIF transformation is invalid.', request));
            }
            break;
          }
          case 'root.pif.favorites.list': {
            respond(request, success('PIF favorites loaded.', {
              schemaVersion: 1, revision: mockPifFavoriteRevision,
              count: mockPifFavorites.length,
              favorites: mockPifFavorites.map(({ content: _content, ...item }) => item),
              bounded: true,
            }));
            break;
          }
          case 'root.pif.favorites.get': {
            const favorite = mockPifFavorites.find((item) => item.favoriteId === request.payload.favoriteId);
            if (!favorite) {
              emit(errorMessage('PIF favorite was not found.', request));
              break;
            }
            respond(request, success('PIF favorite loaded.', {
              schemaVersion: 1, revision: mockPifFavoriteRevision,
              favorite, bounded: true,
            }));
            break;
          }
          case 'root.pif.favorites.save': {
            const content = typeof request.payload.content === 'string' ? request.payload.content : '';
            const label = typeof request.payload.label === 'string' ? request.payload.label : '';
            const favoriteId = content.length.toString(16).padStart(64, '0').slice(-64);
            const favorite = {
              favoriteId, label, createdAt: new Date().toISOString(), sha256: favoriteId,
              size: new TextEncoder().encode(content).length, content,
            };
            mockPifFavorites = [...mockPifFavorites.filter((item) => item.favoriteId !== favoriteId), favorite];
            mockPifFavoriteRevision += 1;
            snapshot = { ...snapshot, revision: snapshot.revision + 1 };
            respond(request, success('PIF favorite saved.', {
              schemaVersion: 1, action: 'saved', revision: mockPifFavoriteRevision,
              snapshotRevision: snapshot.revision,
              favorite: (({ content: _content, ...item }) => item)(favorite), bounded: true,
            }));
            publishSnapshot();
            break;
          }
          case 'root.pif.favorites.delete': {
            const index = mockPifFavorites.findIndex((item) => item.favoriteId === request.payload.favoriteId);
            if (index < 0) {
              emit(errorMessage('PIF favorite was not found.', request));
              break;
            }
            const [favorite] = mockPifFavorites.splice(index, 1);
            mockPifFavoriteRevision += 1;
            snapshot = { ...snapshot, revision: snapshot.revision + 1 };
            respond(request, success('PIF favorite deleted.', {
              schemaVersion: 1, action: 'deleted', revision: mockPifFavoriteRevision,
              snapshotRevision: snapshot.revision,
              favorite: (({ content: _content, ...item }) => item)(favorite), bounded: true,
            }));
            publishSnapshot();
            break;
          }
          case 'root.pif.document': {
            const serial = typeof request.payload.serial === 'string' ? request.payload.serial : snapshot.selectedSerial ?? '';
            const target = snapshot.devices.find((device) => device.serial === serial);
            const profileId = typeof request.payload.profileId === 'string' ? request.payload.profileId : '';
            const formats: Record<string, 'json' | 'prop' | 'list' | 'text'> = {
              'pif.custom_json': 'json', 'pif.custom_prop': 'prop', 'pif.module_json': 'json', 'pif.legacy_json': 'json',
              'pif.app_replace': 'list', 'tricky.spoof': 'prop', 'tricky.target': 'list', 'tricky.security_patch': 'text',
            };
            const format = formats[profileId];
            if (!target || target.mode !== 'adb' || !target.rooted || !format) {
              emit(errorMessage('PIF editor request is invalid.', request));
              break;
            }
            const content = format === 'json'
              ? '{\n  "PRODUCT": "akita",\n  "DEVICE": "akita"\n}\n'
              : format === 'prop'
                ? 'PRODUCT=akita\nDEVICE=akita\n'
                : format === 'list'
                  ? 'com.google.android.gms\n'
                  : '2026-07-05\n';
            respond(request, {
              status: 'SUCCESS', code: 'pif_document_loaded',
              value: {
                schemaVersion: 1, profileId, format, present: true, content,
                size: new TextEncoder().encode(content).length, sha256: 'a'.repeat(64),
                editable: true, bounded: true,
              },
            });
            break;
          }
          case 'tools.pif': {
            const serial = typeof request.payload.serial === 'string' ? request.payload.serial : snapshot.selectedSerial ?? '';
            const target = snapshot.devices.find((device) => device.serial === serial);
            const profileId = typeof request.payload.profileId === 'string' ? request.payload.profileId : '';
            const action = String(request.payload.action);
            const importing = action === 'importProfile';
            const targetAction = action === 'addTarget' || action === 'deleteTarget' || action === 'importTargetProfile';
            const cleaningDroidGuard = action === 'cleanupDroidGuard';
            const launchingIntegrityCheck = action === 'launchIntegrityCheck';
            const updatingProfile = action === 'updateProfile';
            const checker = typeof request.payload.checker === 'string' ? request.payload.checker : '';
            const content = typeof request.payload.content === 'string' ? request.payload.content : '';
            const targetPackage = typeof request.payload.targetPackage === 'string' ? request.payload.targetPackage : '';
            const targetFormat = request.payload.targetFormat === 'prop' ? 'prop' : 'json';
            const required = updatingProfile
              ? `SAVE PIF ${profileId} ${serial.slice(-6).toUpperCase()}`
              : launchingIntegrityCheck
              ? `OPEN PI ${checker} ${serial.slice(-6).toUpperCase()}`
              : cleaningDroidGuard
              ? `CLEANUP DG ${serial.slice(-6).toUpperCase()}`
              : targetAction
              ? action === 'importTargetProfile'
                ? `IMPORT TARGET ${targetPackage} ${targetFormat.toUpperCase()} ${serial.slice(-6).toUpperCase()}`
                : `${action === 'addTarget' ? 'ADD' : 'DELETE'} TARGET ${targetPackage} ${serial.slice(-6).toUpperCase()}`
              : `${importing ? 'IMPORT' : 'DELETE'} PIF ${profileId} ${serial.slice(-6).toUpperCase()}`;
            if (
              !target || target.mode !== 'adb' || !target.rooted
              || !['deleteProfile', 'importProfile', 'updateProfile', 'addTarget', 'deleteTarget', 'importTargetProfile', 'cleanupDroidGuard', 'launchIntegrityCheck'].includes(action)
              || (launchingIntegrityCheck && !['piac', 'spic', 'aic', 'playStore'].includes(checker))
              || (updatingProfile && (!content || !['absent', 'a'.repeat(64)].includes(String(request.payload.baseSha256))))
              || request.payload.confirmationText !== required
            ) {
              emit(errorMessage('PIF or TargetedFix request is invalid.', request));
              break;
            }
            requestGuardedConfirmation(
              request,
              updatingProfile
                ? `Save PIF profile ${profileId} on ${serial}?`
                : launchingIntegrityCheck
                ? `Open integrity checker ${checker} on ${serial}?`
                : cleaningDroidGuard
                ? `Clean DroidGuard cache on ${serial}?`
                : targetAction
                ? `${action === 'addTarget' ? 'Add' : action === 'deleteTarget' ? 'Delete' : 'Import'} TargetedFix target ${targetPackage} on ${serial}?`
                : `${importing ? 'Import' : 'Delete'} PIF profile ${profileId} on ${serial}?`,
              true,
              () => finishGuarded(request, {
                status: 'SUCCESS',
                code: updatingProfile
                  ? 'pif_profile_updated'
                  : launchingIntegrityCheck
                  ? 'integrity_checker_opened'
                  : cleaningDroidGuard
                  ? 'droidguard_cache_cleaned'
                  : targetAction
                  ? action === 'addTarget'
                    ? 'targeted_fix_target_added'
                    : action === 'deleteTarget'
                      ? 'targeted_fix_target_deleted'
                      : 'targeted_fix_profile_imported'
                  : importing ? 'pif_profile_imported' : 'pif_profile_deleted',
                message: updatingProfile
                  ? `PIF profile ${profileId} update hash was independently verified`
                  : launchingIntegrityCheck
                  ? `Integrity checker ${checker} was opened and its process was independently verified`
                  : cleaningDroidGuard
                  ? 'DroidGuard cache absence was independently verified'
                  : targetAction
                  ? 'TargetedFix target state was independently verified'
                  : `PIF profile ${importing ? 'import hash' : 'deletion'} was independently verified`,
                value: updatingProfile
                  ? { action, profileId, sha256: 'e'.repeat(64), size: new TextEncoder().encode(content).length }
                  : launchingIntegrityCheck
                  ? { action, checker, verified: true }
                  : cleaningDroidGuard
                  ? { action, verified: true }
                  : targetAction
                  ? action === 'importTargetProfile'
                    ? { action, targetPackage, targetFormat, sha256: 'd'.repeat(64), size: 512 }
                    : { action, targetPackage }
                  : importing
                    ? { action: 'importProfile', profileId, sha256: 'c'.repeat(64), size: 512 }
                    : { action: 'deleteProfile', profileId },
              }),
            );
            break;
          }
          case 'tools.sos': {
            const serial = typeof request.payload.serial === 'string' ? request.payload.serial : snapshot.selectedSerial ?? '';
            const target = snapshot.devices.find((device) => device.serial === serial);
            const confirmation = `SOS ${serial.slice(-6).toUpperCase()}`;
            if (
              !target || target.mode !== 'adb' || !target.rooted
              || request.payload.action !== 'disableModules'
              || request.payload.confirmationText !== confirmation
            ) {
              emit(errorMessage('SOS confirmation or rooted ADB target is invalid.', request));
              break;
            }
            requestGuardedConfirmation(
              request,
              `Disable every Magisk module on device ${serial}?`,
              false,
              () => {
                mockDisabledRootModules = new Set(mockRootModules);
                finishGuarded(request, {
                  status: 'SUCCESS',
                  code: 'sos_modules_disabled',
                  message: 'every Magisk module is disabled',
                  value: { action: 'disableModules', targetSerial: serial, verified: true },
                });
              },
            );
            break;
          }
          case 'boot.patch': {
            const serial = typeof request.payload.serial === 'string' ? request.payload.serial : snapshot.selectedSerial ?? '';
            const target = snapshot.devices.find((device) => device.serial === serial);
            const flavor = typeof request.payload.flavor === 'string' ? request.payload.flavor : '';
            const destination = `C:\\mock\\patched-${flavor}.img`;
            const app = mockRootApps.find((candidate) => candidate.id === request.payload.appId);
            const secretReady = flavor !== 'apatch' || request.payload.secretGrant === 's'.repeat(64);
            if (!target || target.mode !== 'adb' || !flavor || typeof request.payload.grant !== 'string' || !app || !secretReady) {
              emit(errorMessage('Boot patch payload is incomplete or no verified app is available.', request));
              break;
            }
            requestGuardedConfirmation(
              request,
              `Patch the selected boot image with ${flavor} on device ${serial}?`,
              false,
              () => {
                const hash = '6'.repeat(64);
                snapshot = { ...snapshot, boot: { id: hash.slice(0, 16), image: 'boot.img', hash, flavor: 'boot', patched: true, verified: true } };
                finishGuarded(request, {
                  status: 'SUCCESS',
                  code: 'boot_patched',
                  message: `patched boot with ${flavor}`,
                  value: {
                    patchedBoot: { artifact: { sha256: hash, role: `patched-boot:${flavor}`, displayName: `@artifact/patched-boot/${hash.slice(0, 12)}` }, sourceSha256: '7'.repeat(64), flavor, partition: 'boot' },
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
                version: 2,
                requestId: pending.request.requestId,
                ok: false,
                error: { code: 'operation_cancelled', message: 'Operation was cancelled.' },
              } satisfies BridgeResponse);
              break;
            }
            if (pendingGuarded && operationId === pendingGuarded.operationId) {
              const pending = pendingGuarded;
              pendingGuarded = null;
              respond(request, success('Decision recorded.'));
              if (decision === 'accepted') pending.complete();
              else emit({
                version: 2,
                requestId: pending.request.requestId,
                ok: false,
                error: { code: 'operation_cancelled', message: 'Operation was cancelled.' },
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
            if (!target || target.mode !== 'fastboot' || target.bootloader !== 'unlocked' || !snapshot.boot?.id || !snapshot.boot.hash) {
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
          case 'tools.logcat': {
            const lines = [
              '07-18 17:12:01.100 I/ActivityManager: PixelFlasher test ready',
              '07-18 17:12:01.220 D/PackageManager: package scan complete',
              '07-18 17:12:01.440 W/DeviceIdle: mock preview only',
            ];
            const targetSerial = typeof request.payload.serial === 'string'
              ? request.payload.serial
              : snapshot.selectedSerial ?? '';
            const safeSerial = targetSerial.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 96) || 'device';
            respond(request, success('Collected 3 log lines.', {
              targetSerial,
              mode: request.payload.mode === 'stream' ? 'stream' : 'snapshot',
              lineCount: lines.length,
              lines,
              text: lines.join('\n'),
              redaction: ['strict', 'standard', 'none'].includes(String(request.payload.redaction))
                ? request.payload.redaction
                : 'strict',
              redactedCount: 1,
              bounded: true,
              truncated: false,
              ...(typeof request.payload.grant === 'string' ? {
                export: {
                  fileName: `PixelFlasher-logcat-${safeSerial}.txt`,
                  sha256: '0a23f3916c7cc8c5bd40fd0a2b7304f1672daf8e3906d8af0000b2a912007ec3',
                  size: lines.join('\n').length,
                },
              } : {}),
            }));
            break;
          }
          case 'tools.scrcpy.setup':
            respond(request, success('Official Scrcpy was verified and installed.', {
              ready: true,
              installation: {
                installed: true,
                version: '3.3.3',
                platform: 'windows',
                architecture: 'x86_64',
                license: 'Apache-2.0',
                provenance: 'Genymobile scrcpy GitHub release',
                archiveSha256: '7'.repeat(64),
                archiveSize: 42_000_000,
              },
            }));
            break;
          case 'tools.scrcpy':
            respond(request, success('scrcpy launched for the selected device', { pid: 4242 }));
            break;
          case 'tools.wifi.discover':
            respond(request, success('Discovered 3 wireless ADB services', {
              action: 'discover',
              count: 3,
              services: [
                { id: 'e40c684b4676d421a07f620444fb00fee6c7462bffe725333a6b864a61c90f67', instance: 'adb-pairing-pixel', serviceType: 'pairing', host: '192.168.1.42', port: 37123, endpoint: '192.168.1.42:37123', addressFamily: 'ipv4' },
                { id: '76fc9d880ef5da0afe9bce466dba343198a8e4e7d667f2993e27c681b2ccf4bd', instance: 'adb-connect-pixel', serviceType: 'connect', host: '192.168.1.42', port: 38301, endpoint: '192.168.1.42:38301', addressFamily: 'ipv4' },
                { id: 'ca21b390981df20dae7ee60f526bbb74f07ba2ec953c8576ab0d689e28a7f264', instance: 'legacy-adb', serviceType: 'legacy', host: '192.168.1.77', port: 5555, endpoint: '192.168.1.77:5555', addressFamily: 'ipv4' },
              ],
              discardedCount: 0,
              bounded: true,
            }));
            break;
          case 'tools.wifi': {
            const action = typeof request.payload.action === 'string' ? request.payload.action : '';
            respond(request, success(`ADB Wi-Fi ${action} succeeded`, {
              action,
              endpoint: `${String(request.payload.host)}:${String(request.payload.port)}`,
            }));
            break;
          }
          case 'tools.wifi.status':
            respond(request, success('ADB Wi-Fi status succeeded', {
              action: 'status',
              state: 'device',
              targetSerial: request.payload.serial,
            }));
            break;
          case 'tools.pushFiles':
            requestGuardedConfirmation(
              request,
              `Push selected files to ${String(request.payload.destination)}?`,
              false,
              () => finishGuarded(request, success('Pushed 2 files.', {
                targetSerial: request.payload.serial,
                count: 2,
                files: [
                  {
                    displayName: 'alpha.bin',
                    destination: `${String(request.payload.destination)}alpha.bin`,
                    sha256: 'a'.repeat(64),
                    sizeBytes: 5,
                    verified: true,
                  },
                  {
                    displayName: 'beta.zip',
                    destination: `${String(request.payload.destination)}beta.zip`,
                    sha256: 'b'.repeat(64),
                    sizeBytes: 2048,
                    verified: true,
                  },
                ],
              })),
            );
            break;
          case 'tools.avb':
            respond(request, {
              status: 'SUCCESS',
              code: 'downgrade_artifact_registered',
              message: 'Verified downgrade artifact created.',
              value: {
                artifact: {
                  role: 'downgrade:boot',
                  sha256: 'a'.repeat(64),
                  securityPatch: typeof request.payload.currentSecurityPatch === 'string'
                    ? request.payload.currentSecurityPatch
                    : '2025-02-05',
                  verified: true,
                },
              },
            });
            break;
          case 'tools.xml':
            respond(request, {
              status: 'SUCCESS',
              code: 'binary_xml_decoded',
              message: 'Android binary XML decoded successfully.',
              value: {
                format: 'android-binary-xml',
                xml: '<?xml version="1.0" encoding="utf-8"?>\n<manifest package="com.example.preview">\n</manifest>\n',
                sha256: 'b'.repeat(64),
                sizeBytes: 256,
                elementCount: 1,
                attributeCount: 1,
                bounded: true,
              },
            });
            break;
          case 'tools.keybox':
            respond(request, {
              status: 'SUCCESS',
              code: 'keybox_analyzed',
              message: 'Keybox analysis completed.',
              value: {
                reports: [{
                  displayName: 'attestation.xml',
                  sha256: 'c'.repeat(64),
                  sizeBytes: 4096,
                  status: 'unverified',
                  structureValid: true,
                  cryptographicValid: true,
                  keyboxCount: 1,
                  algorithms: ['ecdsa', 'rsa'],
                  certificateCount: 4,
                  expired: false,
                  expiringSoon: false,
                  softwareAttestation: false,
                  revocationStatus: 'unverified',
                  issues: ['revocation_evidence_unavailable'],
                }],
                count: 1,
                summary: {
                  valid: 0,
                  unverified: 1,
                  revoked: 0,
                  expired: 0,
                  softwareAttestation: 0,
                  invalid: 0,
                },
                revocationEvidence: null,
                bounded: true,
              },
            });
            break;
          case 'support.create':
            respond(request, success('Created redacted support package.', {
              displayName: 'PixelFlasher-support.zip',
              includedCount: 4,
            }));
            break;
          case 'platformTools.setup':
            respond(request, success('Command accepted.'));
            break;
          case 'backups.list': {
            const serial = typeof request.payload.serial === 'string' ? request.payload.serial : '';
            const backups = mockBackups.filter((backup) => !serial || backup.targetSerial === serial);
            respond(request, success('Managed backups listed.', {
              backups,
              count: backups.length,
              totalCount: backups.length,
              filteredSerial: serial || null,
              revision: snapshot.revision,
              bounded: true,
              truncated: false,
            }));
            break;
          }
          case 'backups.magisk.list':
            respond(request, success('Magisk backups listed.', {
              action: 'list',
              targetSerial: String(request.payload.serial ?? ''),
              count: mockMagiskBackups.length,
              backups: mockMagiskBackups,
              bounded: true,
            }));
            break;
          case 'backups.magisk.import': {
            const sha1 = '2'.repeat(40);
            if (!mockMagiskBackups.some((backup) => backup.sha1 === sha1)) {
              mockMagiskBackups = [{
                sha1,
                sizeBytes: 64 * 1024 * 1024,
                createdAt: Math.floor(Date.now() / 1000),
                integrity: 'verified',
              }, ...mockMagiskBackups];
            }
            respond(request, success('Magisk backup imported.', {
              action: 'import', targetSerial: String(request.payload.serial ?? ''), sha1, verified: true,
            }));
            break;
          }
          case 'backups.magisk.delete': {
            const sha1 = String(request.payload.sha1 ?? '');
            mockMagiskBackups = mockMagiskBackups.filter((backup) => backup.sha1 !== sha1);
            respond(request, success('Magisk backup deleted.', {
              action: 'delete', targetSerial: String(request.payload.serial ?? ''), sha1, verified: true,
            }));
            break;
          }
          case 'root.dataAdb.backup':
            respond(request, success('/data/adb backup created.', {
              action: 'backup',
              targetSerial: String(request.payload.serial ?? ''),
              fileName: 'data-adb-mock.pfdataadb',
              sha256: 'a'.repeat(64),
              sizeBytes: 1024,
              payloadSha256: 'b'.repeat(64),
              entryCount: 4,
              contentFingerprint: 'c'.repeat(64),
              deviceCodename: 'komodo',
              verified: true,
              remoteCleaned: true,
            }));
            break;
          case 'root.dataAdb.restore':
            respond(request, success('/data/adb restore completed.', {
              action: 'restore',
              targetSerial: String(request.payload.serial ?? ''),
              payloadSha256: 'b'.repeat(64),
              entryCount: 4,
              contentFingerprint: 'c'.repeat(64),
              deviceCodename: 'komodo',
              verified: true,
              remoteCleaned: true,
            }));
            break;
          case 'root.dataAdb.clear':
            respond(request, success('/data/adb cleared.', {
              action: 'clear',
              targetSerial: String(request.payload.serial ?? ''),
              empty: true,
              verified: true,
            }));
            break;
          case 'backups.create': {
            const serial = String(request.payload.serial ?? snapshot.selectedSerial ?? 'MOCK-SERIAL');
            const partition = String(request.payload.partition ?? 'boot');
            const slot = request.payload.slot === 'b' ? 'b' : 'a';
            const device = snapshot.devices.find((candidate) => candidate.serial === serial);
            const id = (backupSequence++).toString(16).padStart(32, 'a').slice(-32);
            const backup: MockBackupRecord = {
              id,
              sha256: id.padEnd(64, 'b'),
              sizeBytes: 64 * 1024 * 1024,
              createdAt: Math.floor(Date.now() / 1000),
              targetSerial: serial,
              deviceCodename: device?.codename ?? 'mock',
              partition,
              slot,
              targetPartition: `${partition}_${slot}`,
              provenance: 'created',
              available: true,
              integrity: 'stored',
            };
            mockBackups = [backup, ...mockBackups];
            respond(request, success('Backup created.', {
              action: 'create', targetSerial: serial, partition: backup.targetPartition,
              slot, backup, inventoryRegistered: true,
            }));
            break;
          }
          case 'backups.restore': {
            const existing = typeof request.payload.backupId === 'string'
              ? mockBackups.find((backup) => backup.id === request.payload.backupId)
              : undefined;
            respond(request, success('Backup restored.', {
              action: 'restore',
              targetSerial: String(request.payload.serial ?? ''),
              partition: `${String(request.payload.partition ?? 'boot')}_${request.payload.slot === 'b' ? 'b' : 'a'}`,
              slot: request.payload.slot === 'b' ? 'b' : 'a',
              backup: existing ?? null,
              inventoryRegistered: Boolean(existing),
              inventoryIssue: existing ? null : 'backup_import_failed',
            }));
            break;
          }
          case 'backups.delete': {
            const backupId = String(request.payload.backupId ?? '');
            mockBackups = mockBackups.filter((backup) => backup.id !== backupId);
            respond(request, success('Managed backup deleted.', {
              backupId,
              deleted: true,
              objectRemoved: true,
              sharedObjectRetained: false,
              objectMissing: false,
              cleanupDeferred: false,
              revision: snapshot.revision,
            }));
            break;
          }
          case 'apps.action': {
            if (request.payload.action === 'install') {
              respond(request, success('APK installed.', {
                action: 'install',
                apkIdentity: {
                  packageName: 'com.example.selected',
                  sha256: '9'.repeat(64),
                  signerSha256: ['8'.repeat(64)],
                  schemes: ['v2', 'v3'],
                  verified: true,
                },
              }));
            } else if (request.payload.action === 'permissions') {
              const packages = Array.isArray(request.payload.packages) ? request.payload.packages : [];
              const packageName = typeof packages[0] === 'string' ? packages[0] : 'com.example.selected';
              respond(request, success('Permissions inspected.', {
                action: 'permissions',
                report: {
                  package: packageName,
                  requested: ['android.permission.POST_NOTIFICATIONS'],
                  runtimeGranted: ['android.permission.POST_NOTIFICATIONS'],
                  runtimeDenied: [],
                  requestedCount: 1,
                  runtimeCount: 1,
                  bounded: true,
                },
              }));
            } else if (request.payload.action === 'export') {
              const packageName = typeof request.payload.package === 'string' ? request.payload.package : 'com.example.selected';
              respond(request, success('APK exported.', {
                action: 'export',
                export: {
                  package: packageName,
                  fileName: `${packageName}.apk`,
                  sha256: '7'.repeat(64),
                  size: 1024,
                  verified: true,
                  remoteCleaned: true,
                },
              }));
            } else {
              respond(request, success('Command accepted.', { action: request.payload.action }));
            }
            break;
          }
          case 'apps.list':
            respond(request, success('Packages listed.', {
              packages: demoApps.map((app, index) => ({
                package: app.id,
                apk_path: app.scope === 'System' ? `/system/app/${app.id}.apk` : `/data/app/${app.id}.apk`,
                uid: 10000 + index,
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
