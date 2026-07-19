export type Locale = 'en' | 'es' | 'fr' | 'it' | 'zh_CN' | 'zh_TW';
export type Theme = 'dark' | 'light';

export interface ModernPreferences {
  schemaVersion: 1;
  theme: Theme;
  locale: Locale;
  highContrast: boolean;
  reducedMotion: boolean;
  zoom: number;
}
export type RouteId =
  | 'dashboard'
  | 'device'
  | 'flash'
  | 'firmware'
  | 'root'
  | 'apps'
  | 'backups'
  | 'tools'
  | 'settings';

export type DeviceMode = 'adb' | 'fastboot' | 'fastbootd' | 'recovery' | 'sideload' | 'offline' | 'unauthorized';

export interface Device {
  serial: string;
  name: string;
  model: string;
  codename: string;
  mode: DeviceMode;
  androidVersion: string;
  build: string;
  securityPatch: string;
  bootloader: 'locked' | 'unlocked' | 'unknown';
  slot: 'a' | 'b' | 'unknown';
  battery: number;
  connection: 'USB' | 'Wi-Fi';
  rooted: boolean;
}

export interface Firmware {
  id: string;
  name: string;
  version: string;
  build: string;
  device: string;
  kind: 'factory' | 'ota' | 'custom';
  channel: 'stable' | 'beta';
  size: string;
  securityPatch: string;
  verified?: boolean;
  processed?: boolean;
  hash?: string;
}

export interface BootArtifact {
  id?: string;
  image?: string;
  hash?: string;
  flavor?: string;
  patched?: boolean;
  patcher?: string;
  verified?: boolean;
}

export type OperationStatus =
  | 'idle'
  | 'pending'
  | 'running'
  | 'success'
  | 'cancelled'
  | 'failed';

export interface ActiveOperation {
  id: string;
  label: string;
  status: OperationStatus | string;
  progress?: number;
  detail?: string;
}

export interface InteractionRequest {
  operationId: string;
  kind: string;
  title: string;
  message: string;
  expectedRevision: number;
  targetSerial?: string | null;
  destructive: boolean;
  reinforced: boolean;
}

export interface BootloaderLockEvidence {
  serial: string;
  snapshot_revision: number;
}

export interface HostSnapshot {
  revision: number;
  preferences: ModernPreferences;
  devices: Device[];
  selectedSerial?: string | null;
  selected_serial?: string | null;
  selectedSerials?: string[];
  selected_serials?: string[];
  firmware?: Firmware | null;
  boot?: BootArtifact | null;
  plan?: Record<string, unknown> | null;
  toolchain?: {
    adb: boolean;
    fastboot: boolean;
    ready?: boolean;
    version?: string;
  };
  activeOperation?: ActiveOperation | null;
  active_operation?: ActiveOperation | null;
  lastResult?: Record<string, unknown> | null;
  last_result?: Record<string, unknown> | null;
  bootloaderLockEvidence?: BootloaderLockEvidence[];
  bootloader_lock_evidence?: BootloaderLockEvidence[];
}

export interface BridgeRequest {
  version: 2;
  requestId: string;
  command: import('./commands').BridgeCommand;
  payload: Record<string, unknown>;
  expectedRevision: number | null;
}

export interface BridgeSuccessResponse {
  version: 2;
  requestId: string;
  ok: true;
  result: Record<string, unknown>;
}

export interface BridgeFailureResponse {
  version: 2;
  requestId: string;
  ok: false;
  error: { code: string; message: string; details?: Record<string, unknown> };
}

export type BridgeResponse = BridgeSuccessResponse | BridgeFailureResponse;

export interface BridgeEvent {
  version: 2;
  event: 'snapshot' | 'progress' | 'interaction' | 'runtime';
  revision: number;
  payload: Record<string, unknown>;
}

export interface NativeGrant {
  grant: string;
  purpose: string;
  target: 'file' | 'directory';
  access: 'read' | 'write';
  consumeOnce: boolean;
  expiresInSeconds: number | null;
  displayName: string;
}

export type BridgeMessage = BridgeResponse | BridgeEvent;

declare global {
  interface Window {
    pixelflasher?: {
      postMessage(message: string): void;
      __mock?: boolean;
      __reset?: () => void;
    };
  }
}
