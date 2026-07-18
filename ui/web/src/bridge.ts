import { installDevelopmentBridge } from './mockBridge';
import { commands, type BridgeCommand } from './commands';
import type {
  ActiveOperation,
  BridgeEvent,
  BridgeMessage,
  BridgeRequest,
  BridgeResponse,
  Device,
  Firmware,
  HostSnapshot,
  InteractionRequest,
  ModernPreferences,
  OperationStatus,
} from './types';

installDevelopmentBridge();

type Listener = (message: BridgeEvent) => void;

interface PendingRequest {
  resolve: (response: BridgeResponse) => void;
  reject: (error: Error) => void;
  timeout: number;
}

export class BridgeError extends Error {
  constructor(message: string, public readonly response?: BridgeResponse) {
    super(message);
    this.name = 'BridgeError';
  }
}

const supportedLocales = new Set(['en', 'es', 'fr', 'it', 'zh_CN', 'zh_TW']);

export function commandTimeoutMs(command: BridgeCommand) {
  if (command === commands.flashExecute || command === commands.firmwareProcess) {
    return 30 * 60_000;
  }
  if (command === commands.bootFlash) return 10 * 60_000;
  if (command === commands.bootLive) return 5 * 60_000;
  if (command === commands.partitionsRead || command === commands.partitionsWrite) return 20 * 60_000;
  if (command === commands.partitionsErase || command === commands.toolsPushFiles || command === commands.supportCreate) return 10 * 60_000;
  if (command === commands.toolsLogcat) return 3 * 60_000;
  return command === commands.firmwareSelect ? 3 * 60_000 : 60_000;
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

function parseMessage(detail: unknown): BridgeMessage | null {
  try {
    const parsed = typeof detail === 'string' ? JSON.parse(detail) : detail;
    if (!parsed || typeof parsed !== 'object' || !('type' in parsed)) return null;
    return parsed as BridgeMessage;
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

export function normalizeSnapshot(input: HostSnapshot): HostSnapshot {
  const sourceSerials = input.selectedSerials ?? input.selected_serials;
  const selected = input.selectedSerial ?? input.selected_serial ?? sourceSerials?.[0] ?? null;
  const serials = sourceSerials?.length ? sourceSerials : selected ? [selected] : [];
  const rawOperation = input.activeOperation ?? input.active_operation;
  const activeOperation = rawOperation
    ? { ...rawOperation, status: normalizeOperationStatus(rawOperation.status) }
    : null;
  const devices = (Array.isArray(input.devices) ? input.devices : []).map((raw) => {
    const device = raw as Device & Record<string, unknown>;
    const mode = typeof device.mode === 'string' ? device.mode : 'offline';
    const model = typeof device.model === 'string' && device.model ? device.model : String(device.codename || device.serial);
    return {
      ...device,
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
      rooted: typeof device.rooted === 'boolean' ? device.rooted : Boolean(device.root),
    } as Device;
  });
  const rawFirmware = input.firmware as (Firmware & Record<string, unknown>) | null | undefined;
  const hasFirmware = rawFirmware && typeof rawFirmware === 'object' && [
    rawFirmware.id,
    rawFirmware.name,
    rawFirmware.path,
    rawFirmware.hash,
    rawFirmware.build,
  ].some((value) => typeof value === 'string' && value.trim());
  const firmware = hasFirmware ? {
    ...rawFirmware,
    id: typeof rawFirmware.id === 'string' && rawFirmware.id
      ? rawFirmware.id
      : String(rawFirmware.hash || rawFirmware.path || rawFirmware.build || 'selected-firmware'),
    name: typeof rawFirmware.name === 'string' && rawFirmware.name
      ? rawFirmware.name
      : String(rawFirmware.path || rawFirmware.build || 'Selected firmware'),
    version: typeof rawFirmware.version === 'string' ? rawFirmware.version : '',
    build: typeof rawFirmware.build === 'string' ? rawFirmware.build : '—',
    device: typeof rawFirmware.device === 'string' ? rawFirmware.device : '',
    kind: rawFirmware.kind === 'factory' || rawFirmware.kind === 'ota' || rawFirmware.kind === 'custom'
      ? rawFirmware.kind
      : rawFirmware.type === 'ota' ? 'ota' : rawFirmware.type === 'custom_rom' ? 'custom' : 'factory',
    channel: rawFirmware.channel === 'beta' ? 'beta' : 'stable',
    size: typeof rawFirmware.size === 'string' ? rawFirmware.size : '—',
    securityPatch: typeof rawFirmware.securityPatch === 'string' ? rawFirmware.securityPatch : '—',
  } as Firmware : null;
  const rawLockEvidence = input.bootloaderLockEvidence ?? input.bootloader_lock_evidence;
  const bootloaderLockEvidence = (Array.isArray(rawLockEvidence) ? rawLockEvidence : []).filter((entry) => (
    entry
    && typeof entry === 'object'
    && typeof entry.serial === 'string'
    && typeof entry.device_codename === 'string'
    && typeof entry.firmware_hash === 'string'
    && typeof entry.firmware_build === 'string'
    && typeof entry.flash_operation_id === 'string'
    && typeof entry.flash_plan_fingerprint === 'string'
    && typeof entry.snapshot_revision === 'number'
    && Array.isArray(entry.required_partitions)
    && Array.isArray(entry.flashed_partitions)
    && Array.isArray(entry.slots)
  ));
  return {
    ...input,
    revision: Number.isFinite(input.revision) ? input.revision : 0,
    devices,
    selectedSerial: selected,
    selected_serial: selected,
    selectedSerials: serials,
    selected_serials: serials,
    firmware,
    activeOperation,
    active_operation: activeOperation,
    lastResult: input.lastResult ?? input.last_result ?? null,
    last_result: input.lastResult ?? input.last_result ?? null,
    bootloaderLockEvidence,
    bootloader_lock_evidence: bootloaderLockEvidence,
  };
}

function errorText(response: BridgeResponse) {
  if (typeof response.error === 'string') return response.error;
  return response.error?.message ?? 'The PixelFlasher host rejected the request.';
}

class PixelFlasherClient {
  private pending = new Map<string, PendingRequest>();
  private listeners = new Set<Listener>();

  constructor() {
    window.addEventListener('pixelflasher:message', this.handleMessage as EventListener);
  }

  private handleMessage = (event: CustomEvent<unknown>) => {
    const message = parseMessage(event.detail);
    if (!message) return;

    if (message.type === 'response') {
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
  ): Promise<{ result: T; revision?: number }> {
    const bridge = window.pixelflasher;
    if (!bridge) throw new BridgeError('PixelFlasher host bridge is unavailable.');

    const id = requestId();
    const request: BridgeRequest = {
      version: 1,
      requestId: id,
      command,
      payload,
      expectedRevision: expectedRevision ?? null,
    };

    const response = await new Promise<BridgeResponse>((resolve, reject) => {
      const timeout = window.setTimeout(() => {
        this.pending.delete(id);
        reject(new BridgeError(`Timed out waiting for ${command}.`));
      }, commandTimeoutMs(command));
      this.pending.set(id, { resolve, reject, timeout });
      bridge.postMessage(JSON.stringify(request));
    });

    return { result: response.result as T, revision: response.revision };
  }

  async getSnapshot() {
    const { result } = await this.command<HostSnapshot | { snapshot: HostSnapshot }>(commands.snapshotGet);
    const snapshot = result && typeof result === 'object' && 'snapshot' in result ? result.snapshot : result;
    if (!snapshot || typeof snapshot !== 'object') throw new BridgeError('Host returned an invalid snapshot.');
    return normalizeSnapshot(snapshot);
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
  if (event.type !== 'snapshot') return null;
  const direct = event.snapshot;
  const nested = event.payload?.snapshot;
  const payloadSnapshot = nested && typeof nested === 'object'
    ? nested as HostSnapshot
    : event.payload && typeof event.payload === 'object'
      ? event.payload as unknown as HostSnapshot
      : null;
  const snapshot = direct ?? payloadSnapshot;
  return snapshot ? normalizeSnapshot(snapshot) : null;
}

export function operationFromEvent(event: BridgeEvent): ActiveOperation | null {
  if (event.type !== 'progress') return null;
  const operation = event.operation ?? event.payload?.operation;
  if (!operation || typeof operation !== 'object') return null;
  const typed = operation as unknown as ActiveOperation;
  return { ...typed, status: normalizeOperationStatus(typed.status) };
}

export function interactionFromEvent(event: BridgeEvent): InteractionRequest | null {
  if (event.type !== 'interaction' || !event.payload || typeof event.payload !== 'object') return null;
  const raw = event.payload;
  const operationId = raw.operationId ?? raw.operation_id;
  const expectedRevision = raw.expectedRevision ?? raw.expected_revision;
  if (typeof operationId !== 'string' || !operationId || typeof expectedRevision !== 'number') return null;
  return {
    operationId,
    kind: typeof raw.kind === 'string' ? raw.kind : 'confirm',
    title: typeof raw.title === 'string' ? raw.title : '',
    message: typeof raw.message === 'string' ? raw.message : '',
    expectedRevision,
    targetSerial: typeof (raw.targetSerial ?? raw.target_serial) === 'string' ? String(raw.targetSerial ?? raw.target_serial) : null,
    destructive: raw.destructive === true,
    reinforced: raw.reinforced === true,
  };
}
