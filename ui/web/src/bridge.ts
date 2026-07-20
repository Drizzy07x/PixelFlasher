import {
  bridgeVersion,
  commandTimeoutByName,
  commands,
  revisionOptionalCommands,
  type BridgeCommand,
} from './commands';
import type {
  ActiveOperation,
  BootArtifact,
  BridgeEvent,
  BridgeMessage,
  BridgeRequest,
  BridgeResponse,
  BridgeFailureResponse,
  Device,
  DeviceManagementState,
  Firmware,
  HostSnapshot,
  InteractionRequest,
  ModernPreferences,
  OperationStatus,
} from './types';
import { MAX_MANAGED_DEVICE_TIMESTAMP } from './types';

type Listener = (message: BridgeEvent) => void;

interface PendingRequest {
  resolve: (response: BridgeResponse) => void;
  reject: (error: Error) => void;
  timeout: number;
}

export class BridgeError extends Error {
  constructor(message: string, public readonly response?: BridgeFailureResponse) {
    super(message);
    this.name = 'BridgeError';
  }
}

const supportedLocales = new Set(['en', 'es', 'fr', 'it', 'zh_CN', 'zh_TW']);
const validFontFace = (value: unknown): value is string => typeof value === 'string'
  && value.length >= 1
  && value.length <= 96
  && value === value.trim()
  && !/[\u0000-\u001f\u007f"'\\,;{}()]/u.test(value);
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

export function commandTimeoutMs(command: BridgeCommand) {
  return commandTimeoutByName[command];
}

export function normalizePreferences(input: unknown): ModernPreferences {
  if (!input || typeof input !== 'object') {
    throw new BridgeError('Host returned invalid preferences.');
  }
  const raw = input as Record<string, unknown>;
  if (
    raw.schemaVersion !== 1 ||
    (raw.theme !== 'dark' && raw.theme !== 'light') ||
    typeof raw.locale !== 'string' ||
    !supportedLocales.has(raw.locale) ||
    typeof raw.highContrast !== 'boolean' ||
    typeof raw.reducedMotion !== 'boolean' ||
    typeof raw.zoom !== 'number' ||
    !Number.isInteger(raw.zoom) ||
    raw.zoom < 80 ||
    raw.zoom > 200
    || typeof raw.expertMode !== 'boolean'
    || typeof raw.automaticUpdateCheck !== 'boolean'
    || typeof raw.checkDiskSpace !== 'boolean'
    || typeof raw.checkBootloaderUnlocked !== 'boolean'
    || typeof raw.checkFirmwareHash !== 'boolean'
    || typeof raw.checkModuleUpdates !== 'boolean'
    || typeof raw.showNotifications !== 'boolean'
    || typeof raw.rebootTimeoutSeconds !== 'number'
    || !Number.isInteger(raw.rebootTimeoutSeconds)
    || raw.rebootTimeoutSeconds < 1
    || raw.rebootTimeoutSeconds > 3600
    || typeof raw.offerPatchMethods !== 'boolean'
    || typeof raw.showRecoveryPatching !== 'boolean'
    || typeof raw.keepPatchTemporaryFiles !== 'boolean'
    || typeof raw.useBusyboxShell !== 'boolean'
    || typeof raw.lowMemoryMode !== 'boolean'
    || typeof raw.extraImageExtracts !== 'boolean'
    || typeof raw.showCustomRomOptions !== 'boolean'
    || typeof raw.keyboxIndex !== 'boolean'
    || typeof raw.customizeFont !== 'boolean'
    || !validFontFace(raw.fontFace)
    || typeof raw.fontSize !== 'number'
    || !Number.isInteger(raw.fontSize)
    || raw.fontSize < 6
    || raw.fontSize > 50
    || (raw.toolbarPosition !== 'top' && raw.toolbarPosition !== 'right'
      && raw.toolbarPosition !== 'bottom' && raw.toolbarPosition !== 'left')
    || typeof raw.toolbarShowDevice !== 'boolean'
    || typeof raw.toolbarShowTheme !== 'boolean'
    || typeof raw.toolbarShowLanguage !== 'boolean'
  ) {
    throw new BridgeError('Host returned invalid preferences.');
  }
  return {
    schemaVersion: 1,
    theme: raw.theme,
    locale: raw.locale as ModernPreferences['locale'],
    highContrast: raw.highContrast,
    reducedMotion: raw.reducedMotion,
    zoom: raw.zoom,
    expertMode: raw.expertMode,
    automaticUpdateCheck: raw.automaticUpdateCheck,
    checkDiskSpace: raw.checkDiskSpace,
    checkBootloaderUnlocked: raw.checkBootloaderUnlocked,
    checkFirmwareHash: raw.checkFirmwareHash,
    checkModuleUpdates: raw.checkModuleUpdates,
    showNotifications: raw.showNotifications,
    rebootTimeoutSeconds: raw.rebootTimeoutSeconds,
    offerPatchMethods: raw.offerPatchMethods,
    showRecoveryPatching: raw.showRecoveryPatching,
    keepPatchTemporaryFiles: raw.keepPatchTemporaryFiles,
    useBusyboxShell: raw.useBusyboxShell,
    lowMemoryMode: raw.lowMemoryMode,
    extraImageExtracts: raw.extraImageExtracts,
    showCustomRomOptions: raw.showCustomRomOptions,
    keyboxIndex: raw.keyboxIndex,
    customizeFont: raw.customizeFont,
    fontFace: raw.fontFace,
    fontSize: raw.fontSize,
    toolbarPosition: raw.toolbarPosition,
    toolbarShowDevice: raw.toolbarShowDevice,
    toolbarShowTheme: raw.toolbarShowTheme,
    toolbarShowLanguage: raw.toolbarShowLanguage,
  };
}

function preferencesResult(input: unknown): { preferences: ModernPreferences; message: string } {
  if (!input || typeof input !== 'object') {
    throw new BridgeError('Host returned an invalid preferences result.');
  }
  const result = input as Record<string, unknown>;
  if (normalizeOperationStatus(result.status) !== 'success') {
    throw new BridgeError(typeof result.message === 'string' && result.message
      ? result.message
      : 'The PixelFlasher host did not save preferences.');
  }
  const value = result.value;
  if (!value || typeof value !== 'object' || !('preferences' in value)) {
    throw new BridgeError('Host returned an invalid preferences result.');
  }
  return {
    preferences: normalizePreferences((value as Record<string, unknown>).preferences),
    message: typeof result.message === 'string' ? result.message : '',
  };
}

function requestId() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `pf-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function hasExactFields(value: Record<string, unknown>, fields: readonly string[]) {
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  return actual.length === expected.length && actual.every((field, index) => field === expected[index]);
}

function validRevision(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0;
}

export function validTargetSerial(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  if (/^[A-Za-z0-9._:-]{1,128}$/.test(value)) return true;
  const endpoint = /^\[([0-9A-Fa-f:]{2,64}(?:%[A-Za-z0-9._-]{1,32})?)\]:([0-9]{1,5})$/.exec(value);
  if (!endpoint || !validIpv6Host(endpoint[1] ?? '')) return false;
  const port = Number(endpoint[2]);
  return Number.isInteger(port) && port >= 1 && port <= 65_535;
}

function validIpv6Host(scopedHost: string) {
  const host = scopedHost.split('%', 1)[0] ?? '';
  const compressed = host.split('::');
  if (!host || compressed.length > 2) return false;
  const groups = compressed.flatMap((side) => side ? side.split(':') : []);
  if (groups.some((group) => !/^[0-9A-Fa-f]{1,4}$/.test(group))) return false;
  return compressed.length === 2 ? groups.length < 8 : groups.length === 8;
}

function validError(value: unknown): value is BridgeFailureResponse['error'] {
  if (!isRecord(value)) return false;
  const validFields = hasExactFields(value, ['code', 'message'])
    || hasExactFields(value, ['code', 'message', 'details']);
  return validFields
    && typeof value.code === 'string'
    && typeof value.message === 'string'
    && (!('details' in value) || isRecord(value.details));
}

export function parseBridgeMessage(detail: unknown): BridgeMessage | null {
  try {
    const parsed = typeof detail === 'string' ? JSON.parse(detail) : detail;
    if (!isRecord(parsed) || parsed.version !== bridgeVersion) return null;
    if ('requestId' in parsed || 'ok' in parsed) {
      if (typeof parsed.requestId !== 'string' || parsed.requestId.length > 128) return null;
      if (parsed.ok === true) {
        if (!hasExactFields(parsed, ['version', 'requestId', 'ok', 'result']) || !isRecord(parsed.result)) return null;
      } else if (parsed.ok === false) {
        if (!hasExactFields(parsed, ['version', 'requestId', 'ok', 'error']) || !validError(parsed.error)) return null;
      } else {
        return null;
      }
      return parsed as unknown as BridgeResponse;
    }
    if (typeof parsed.event !== 'string' || !['snapshot', 'progress', 'interaction', 'runtime', 'terminal'].includes(parsed.event)) return null;
    if (!hasExactFields(parsed, ['version', 'event', 'revision', 'payload'])) return null;
    if (!isRecord(parsed.payload) || !validRevision(parsed.revision)) return null;
    return parsed as unknown as BridgeEvent;
  } catch {
    return null;
  }
}

export function normalizeOperationStatus(status: unknown): OperationStatus {
  const value = typeof status === 'string' ? status.trim().toLowerCase() : '';
  if (value === 'success' || value === 'succeeded' || value === 'complete' || value === 'completed') return 'success';
  if (value === 'cancelled' || value === 'canceled') return 'cancelled';
  if (value === 'failed' || value === 'failure' || value === 'error') return 'failed';
  if (value === 'pending' || value === 'queued') return 'pending';
  if (value === 'running' || value === 'active' || value === 'in_progress') return 'running';
  return 'idle';
}

const deviceModes = new Set<Device['mode']>([
  'adb',
  'fastboot',
  'fastbootd',
  'recovery',
  'sideload',
  'offline',
  'unauthorized',
]);

function fallbackDeviceManagement(devices: Device[]): DeviceManagementState {
  return {
    schemaVersion: 1,
    scanEnabled: true,
    scanScope: 'enabled',
    devices: devices.map((device) => ({
      serial: device.serial,
      label: '',
      enabled: true,
      model: device.model,
      codename: device.codename,
      connected: !['offline', 'unauthorized'].includes(device.mode),
      mode: device.mode,
      firstSeen: 0,
      lastSeen: 0,
    })),
  };
}

function normalizeDeviceManagement(input: unknown, devices: Device[]): DeviceManagementState {
  if (!isRecord(input)
    || input.schemaVersion !== 1
    || typeof input.scanEnabled !== 'boolean'
    || (input.scanScope !== 'enabled' && input.scanScope !== 'all')
    || !Array.isArray(input.devices)
    || input.devices.length > 256) {
    return fallbackDeviceManagement(devices);
  }
  const serials = new Set<string>();
  const managed = input.devices.flatMap((entry) => {
    if (!isRecord(entry)
      || typeof entry.serial !== 'string'
      || !entry.serial
      || entry.serial !== entry.serial.trim()
      || entry.serial.length > 256
      || typeof entry.label !== 'string'
      || entry.label.length > 120
      || typeof entry.enabled !== 'boolean'
      || typeof entry.model !== 'string'
      || entry.model.length > 256
      || typeof entry.codename !== 'string'
      || entry.codename.length > 128
      || typeof entry.connected !== 'boolean'
      || typeof entry.mode !== 'string'
      || !deviceModes.has(entry.mode as Device['mode'])
      || typeof entry.firstSeen !== 'number'
      || !Number.isSafeInteger(entry.firstSeen)
      || entry.firstSeen < 0
      || entry.firstSeen > MAX_MANAGED_DEVICE_TIMESTAMP
      || typeof entry.lastSeen !== 'number'
      || !Number.isSafeInteger(entry.lastSeen)
      || entry.lastSeen < 0
      || entry.lastSeen > MAX_MANAGED_DEVICE_TIMESTAMP
      || (entry.firstSeen > 0 && entry.lastSeen > 0 && entry.lastSeen < entry.firstSeen)
      || serials.has(entry.serial)) {
      return [];
    }
    serials.add(entry.serial);
    return [{
      serial: entry.serial,
      label: entry.label,
      enabled: entry.enabled,
      model: entry.model,
      codename: entry.codename,
      connected: entry.connected,
      mode: entry.mode as Device['mode'],
      firstSeen: entry.firstSeen,
      lastSeen: entry.lastSeen,
    }];
  });
  return {
    schemaVersion: 1,
    scanEnabled: input.scanEnabled,
    scanScope: input.scanScope,
    devices: managed,
  };
}

export function normalizeSnapshot(input: HostSnapshot): HostSnapshot {
  const sourceSerials = input.selectedSerials ?? input.selected_serials;
  const selected = input.selectedSerial ?? input.selected_serial ?? sourceSerials?.[0] ?? null;
  const serials = sourceSerials?.length ? sourceSerials : selected ? [selected] : [];
  const rawOperation = (input.activeOperation ?? input.active_operation) as
    | (Partial<ActiveOperation> & { operation_id?: unknown })
    | null
    | undefined;
  const operationId = typeof rawOperation?.id === 'string' && rawOperation.id
    ? rawOperation.id
    : typeof rawOperation?.operation_id === 'string' ? rawOperation.operation_id : '';
  const operationTarget = validTargetSerial(rawOperation?.targetSerial)
    ? rawOperation.targetSerial
    : validTargetSerial(rawOperation?.target_serial) ? rawOperation.target_serial : '';
  const activeOperation = rawOperation && operationId
    ? {
        id: operationId,
        ...(typeof rawOperation.kind === 'string' && rawOperation.kind
          ? { kind: rawOperation.kind }
          : {}),
        label: typeof rawOperation.label === 'string' && rawOperation.label
          ? rawOperation.label
          : 'Operation in progress',
        status: normalizeOperationStatus(rawOperation.status ?? 'running'),
        ...(typeof rawOperation.progress === 'number' ? { progress: rawOperation.progress } : {}),
        ...(typeof rawOperation.detail === 'string' ? { detail: rawOperation.detail } : {}),
        ...(operationTarget ? { targetSerial: operationTarget, target_serial: operationTarget } : {}),
      }
    : null;
  const devices = (Array.isArray(input.devices) ? input.devices : []).map((raw) => {
    const device = raw as Device & Record<string, unknown>;
    const mode = typeof device.mode === 'string' ? device.mode : 'offline';
    const model = typeof device.model === 'string' && device.model ? device.model : String(device.codename || device.serial);
    return {
      serial: typeof device.serial === 'string' ? device.serial : '',
      name: typeof device.name === 'string' && device.name ? device.name : model,
      model,
      codename: typeof device.codename === 'string' ? device.codename : '',
      mode,
      androidVersion: typeof device.androidVersion === 'string'
        ? device.androidVersion
        : typeof device.android_version === 'string' ? device.android_version : '—',
      build: typeof device.build === 'string' ? device.build : '—',
      securityPatch: typeof device.securityPatch === 'string'
        ? device.securityPatch
        : typeof device.security_patch === 'string' ? device.security_patch : '—',
      bootloader: device.bootloader === 'locked' || device.bootloader === 'unlocked' ? device.bootloader : 'unknown',
      slot: device.slot === 'a' || device.slot === 'b' ? device.slot : 'unknown',
      battery: typeof device.battery === 'number' ? device.battery : 0,
      connection: device.connection === 'Wi-Fi' ? 'Wi-Fi' : 'USB',
      architecture: typeof device.architecture === 'string' ? device.architecture : '',
      kernelRelease: typeof device.kernelRelease === 'string'
        ? device.kernelRelease
        : typeof device.kernel_release === 'string' ? device.kernel_release : '',
      kmi: typeof device.kmi === 'string' ? device.kmi : '',
      rooted: typeof device.rooted === 'boolean' ? device.rooted : Boolean(device.root),
      online: typeof device.online === 'boolean' ? device.online : true,
    } as Device;
  });
  const rawFirmware = input.firmware as (Firmware & Record<string, unknown>) | null | undefined;
  const hasFirmware = rawFirmware && typeof rawFirmware === 'object' && [
    rawFirmware.id,
    rawFirmware.name,
    rawFirmware.hash,
    rawFirmware.build,
  ].some((value) => typeof value === 'string' && value.trim());
  const firmware = hasFirmware ? {
    id: typeof rawFirmware.id === 'string' && rawFirmware.id
      ? rawFirmware.id
      : String(rawFirmware.hash || rawFirmware.build || 'selected-firmware'),
    name: typeof rawFirmware.name === 'string' && rawFirmware.name
      ? rawFirmware.name
      : String(rawFirmware.build || 'Selected firmware'),
    version: typeof rawFirmware.version === 'string' ? rawFirmware.version : '',
    build: typeof rawFirmware.build === 'string' ? rawFirmware.build : '—',
    device: typeof rawFirmware.device === 'string' ? rawFirmware.device : '',
    kind: rawFirmware.kind === 'factory' || rawFirmware.kind === 'ota' || rawFirmware.kind === 'custom'
      ? rawFirmware.kind
      : rawFirmware.type === 'ota' ? 'ota' : rawFirmware.type === 'custom_rom' ? 'custom' : 'factory',
    channel: rawFirmware.channel === 'beta' ? 'beta' : 'stable',
    size: typeof rawFirmware.size === 'string' ? rawFirmware.size : '—',
    securityPatch: typeof rawFirmware.securityPatch === 'string' ? rawFirmware.securityPatch : '—',
    verified: rawFirmware.verified === true,
    processed: rawFirmware.processed === true,
    hash: typeof rawFirmware.hash === 'string' ? rawFirmware.hash : '',
  } as Firmware : null;
  const rawBoot = input.boot as (BootArtifact & Record<string, unknown>) | null | undefined;
  const hasBoot = rawBoot && typeof rawBoot === 'object'
    && [rawBoot.id, rawBoot.hash].some((value) => typeof value === 'string' && value.trim());
  const boot = hasBoot ? {
    id: typeof rawBoot.id === 'string' ? rawBoot.id : '',
    image: typeof rawBoot.image === 'string' ? rawBoot.image : 'boot.img',
    hash: typeof rawBoot.hash === 'string' ? rawBoot.hash : '',
    flavor: typeof rawBoot.flavor === 'string' ? rawBoot.flavor : 'boot',
    patched: rawBoot.patched === true,
    verified: rawBoot.verified === true,
  } satisfies BootArtifact : null;
  const rawLockEvidence = input.bootloaderLockEvidence ?? input.bootloader_lock_evidence;
  const bootloaderLockEvidence = (Array.isArray(rawLockEvidence) ? rawLockEvidence : []).flatMap((entry) => (
    entry
    && typeof entry === 'object'
    && typeof entry.serial === 'string'
    && typeof entry.snapshot_revision === 'number'
    && Number.isInteger(entry.snapshot_revision)
    && entry.snapshot_revision >= 0
      ? [{ serial: entry.serial, snapshot_revision: entry.snapshot_revision }]
      : []
  ));
  const rawToolchain: Record<string, unknown> = isRecord(input.toolchain) ? input.toolchain : {};
  const toolchain = {
    adb: rawToolchain.adb === true,
    fastboot: rawToolchain.fastboot === true,
    ready: rawToolchain.ready === true,
    version: typeof rawToolchain.version === 'string' ? rawToolchain.version : '',
  };
  const rawLastResult = input.lastResult ?? input.last_result;
  const lastResult = isRecord(rawLastResult) ? {
    event_type: typeof rawLastResult.event_type === 'string' ? rawLastResult.event_type : 'runtime',
    operation_id: typeof rawLastResult.operation_id === 'string' ? rawLastResult.operation_id : '',
    status: typeof rawLastResult.status === 'string' ? rawLastResult.status : 'failed',
    code: typeof rawLastResult.code === 'string' ? rawLastResult.code : 'operation_failed',
    message: typeof rawLastResult.message === 'string' ? rawLastResult.message : '',
    exit_code: typeof rawLastResult.exit_code === 'number' ? rawLastResult.exit_code : null,
  } : null;
  const deviceManagement = normalizeDeviceManagement(
    input.deviceManagement ?? input.device_management,
    devices,
  );
  return {
    revision: Number.isFinite(input.revision) ? input.revision : 0,
    preferences: normalizePreferences(input.preferences ?? defaultPreferences),
    deviceManagement,
    device_management: deviceManagement,
    devices,
    selectedSerial: selected,
    selected_serial: selected,
    selectedSerials: serials,
    selected_serials: serials,
    firmware,
    boot,
    plan: isRecord(input.plan) ? input.plan : null,
    toolchain,
    activeOperation,
    active_operation: activeOperation,
    lastResult,
    last_result: lastResult,
    bootloaderLockEvidence,
    bootloader_lock_evidence: bootloaderLockEvidence,
  };
}

function errorText(response: BridgeResponse) {
  return response.ok ? 'The PixelFlasher host rejected the request.' : response.error.message;
}

class PixelFlasherClient {
  private pending = new Map<string, PendingRequest>();
  private listeners = new Set<Listener>();

  constructor() {
    window.addEventListener('pixelflasher:message', this.handleMessage as EventListener);
  }

  private handleMessage = (event: CustomEvent<unknown>) => {
    const message = parseBridgeMessage(event.detail);
    if (!message) return;

    if ('ok' in message) {
      const pending = this.pending.get(message.requestId);
      if (!pending) return;
      window.clearTimeout(pending.timeout);
      this.pending.delete(message.requestId);
      if (message.ok) pending.resolve(message);
      else pending.reject(new BridgeError(errorText(message), message));
      return;
    }

    this.listeners.forEach((listener) => listener(message));
  };

  subscribe(listener: Listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  async command<T = unknown>(
    command: BridgeCommand,
    payload: Record<string, unknown> = {},
    expectedRevision?: number,
    onRequestAccepted?: (requestId: string) => void,
  ): Promise<{ result: T; revision?: number }> {
    const bridge = window.pixelflasher;
    if (!bridge) throw new BridgeError('PixelFlasher host bridge is unavailable.');
    if (expectedRevision === undefined && !revisionOptionalCommands.has(command)) {
      throw new BridgeError(`A current revision is required for ${command}.`);
    }

    const id = requestId();
    const request: BridgeRequest = {
      version: bridgeVersion,
      requestId: id,
      command,
      payload,
      expectedRevision: expectedRevision ?? null,
    };
    onRequestAccepted?.(id);

    const response = await new Promise<BridgeResponse>((resolve, reject) => {
      const timeout = window.setTimeout(() => {
        this.pending.delete(id);
        reject(new BridgeError(`Timed out waiting for ${command}.`));
      }, commandTimeoutMs(command));
      this.pending.set(id, { resolve, reject, timeout });
      bridge.postMessage(JSON.stringify(request));
    });

    if (!response.ok) throw new BridgeError(errorText(response), response);
    const revision = response.result.revision;
    return {
      result: response.result as T,
      revision: validRevision(revision) ? revision : undefined,
    };
  }

  async getSnapshot() {
    const { result } = await this.command<HostSnapshot>(commands.snapshotGet);
    if (!result || typeof result !== 'object') throw new BridgeError('Host returned an invalid snapshot.');
    return normalizeSnapshot(result);
  }

  async getPreferences() {
    const { result } = await this.command<unknown>(commands.settingsGet);
    return preferencesResult(result).preferences;
  }

  async updatePreferences(
    patch: Partial<Omit<ModernPreferences, 'schemaVersion'>>,
    expectedRevision: number,
  ) {
    const { result, revision } = await this.command<unknown>(commands.settingsUpdate, patch, expectedRevision);
    return { ...preferencesResult(result), revision };
  }
}

export const bridge = new PixelFlasherClient();

export function snapshotFromEvent(event: BridgeEvent): HostSnapshot | null {
  if (event.event !== 'snapshot') return null;
  return normalizeSnapshot(event.payload as unknown as HostSnapshot);
}

export function operationFromEvent(
  event: BridgeEvent,
  previous: ActiveOperation | null = null,
): ActiveOperation | null {
  if (event.event !== 'progress') return null;
  const operationId = event.payload.operation_id;
  if (typeof operationId !== 'string' || !operationId) return null;
  const phase = typeof event.payload.phase === 'string' ? event.payload.phase : 'running';
  const status = phase === 'completed' || phase === 'finished'
    ? 'success'
    : phase === 'cancelled'
      ? 'cancelled'
      : phase === 'failed'
        ? 'failed'
        : phase === 'queued'
          ? 'pending'
          : 'running';
  const kind = typeof event.payload.kind === 'string' && event.payload.kind
    ? event.payload.kind
    : previous?.id === operationId ? previous.kind : undefined;
  const targetSerial = validTargetSerial(event.payload.target_serial)
    ? event.payload.target_serial
    : previous?.id === operationId ? previous.targetSerial ?? previous.target_serial : undefined;
  const current = event.payload.current;
  const total = event.payload.total;
  const validPosition = typeof current === 'number'
    && Number.isInteger(current)
    && typeof total === 'number'
    && Number.isInteger(total)
    && current >= 1
    && current <= total
    && total <= 10_000;
  const item = validPosition
    && typeof event.payload.item === 'string'
    && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(event.payload.item)
    ? event.payload.item
    : undefined;
  const progress = typeof event.payload.percent === 'number'
    && Number.isInteger(event.payload.percent)
    && event.payload.percent >= 0
    && event.payload.percent <= 100
    ? event.payload.percent
    : undefined;
  return {
    id: operationId,
    ...(kind ? { kind } : {}),
    label: typeof event.payload.message === 'string' && event.payload.message
      ? event.payload.message
      : phase,
    status,
    progress,
    detail: typeof event.payload.message === 'string' ? event.payload.message : undefined,
    ...(validPosition ? { current, total } : {}),
    ...(item ? { item } : {}),
    ...(targetSerial ? { targetSerial, target_serial: targetSerial } : {}),
  };
}

export function interactionFromEvent(event: BridgeEvent): InteractionRequest | null {
  if (event.event !== 'interaction') return null;
  const raw = event.payload;
  const operationId = raw.operation_id;
  const expectedRevision = raw.expected_revision;
  if (typeof operationId !== 'string' || !operationId || typeof expectedRevision !== 'number') return null;
  return {
    operationId,
    kind: typeof raw.kind === 'string' ? raw.kind : 'confirm',
    title: typeof raw.title === 'string' ? raw.title : '',
    message: typeof raw.message === 'string' ? raw.message : '',
    expectedRevision,
    targetSerial: typeof raw.target_serial === 'string' ? raw.target_serial : null,
    destructive: raw.destructive === true,
    reinforced: raw.reinforced === true,
  };
}
