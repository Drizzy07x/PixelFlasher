import { lazy, Suspense, useEffect, useRef, useState, type Dispatch, type SetStateAction } from 'react';
import type { AssetName } from '../../assets';
import { normalizeOperationStatus, validTargetSerial } from '../../bridge';
import { commands, type BridgeCommand } from '../../commands';
import { useI18n } from '../../i18n';
import type { ActiveOperation } from '../../types';
import { Badge, Button, Card, CardTitle, EmptyState, Icon, PageHeader } from '../../components/ui';
import { isToolchainReady, record, selectedGrant, selectedGrants, type CommandRunOptions, type SharedPageProps } from '../shared';
import {
  LogcatPanel,
  MAX_LOGCAT_PREVIEW_LINES,
  appendLogcatProgressBatch,
  hasUnredactedLogcatState,
  initialLogcatUiState,
  purgeUnredactedLogcatState,
  useLogcatExpertGuard,
  type LogcatUiState,
} from './LogcatPanel';

const AdbShellPanel = lazy(async () => {
  const module = await import('./AdbShellPanel');
  return { default: module.AdbShellPanel };
});

type ToolPanel = 'scrcpy' | 'wifi' | 'shell' | 'logcat' | 'partitions' | 'push' | 'avb' | 'xml' | 'keybox' | 'mytools' | null;
type PartitionRow = { name: string; sizeBytes: number | null; partitionType: string };
type PartitionAction = 'read' | 'write' | 'erase';
type PartitionReceipt = {
  action: PartitionAction;
  targetSerial: string;
  partition: string;
  fileName?: string;
  sha256?: string;
  sizeBytes?: number;
};
type PartitionOutcome = {
  status: 'idle' | 'running' | 'cancelling' | 'success' | 'cancelled' | 'failed' | 'unknown';
  action: PartitionAction | null;
  targetSerial: string | null;
  message: string;
  receipt: PartitionReceipt | null;
};
type WifiService = {
  id: string;
  instance: string;
  serviceType: 'pairing' | 'connect' | 'legacy';
  host: string;
  port: number;
  endpoint: string;
};
type MyToolRow = {
  id: string;
  title: string;
  mode: 'safeArgv' | 'legacyRaw';
  displayName: string;
  sha256: string;
  arguments: string[];
  enabled: boolean;
  blockedReason?: string;
  permissionGranted?: boolean;
  commandPreview?: string;
  fingerprint?: string;
  workingDirectory?: 'default' | 'approved';
};
const SAFE_MY_TOOL_FIELDS = ['arguments', 'displayName', 'enabled', 'id', 'mode', 'sha256', 'title'] as const;
const LEGACY_MY_TOOL_FIELDS = [
  'arguments',
  'blockedReason',
  'commandPreview',
  'displayName',
  'enabled',
  'fingerprint',
  'id',
  'mode',
  'permissionGranted',
  'sha256',
  'title',
  'workingDirectory',
] as const;
export type PushDestination = '/data/local/tmp/' | '/sdcard/Download/';
export type PushPayload = { serial: string; grants: string[]; destination: PushDestination };
export type PushReceipt = {
  displayName: string;
  destination: string;
  sha256: string;
  sizeBytes: number;
  verified: true;
};
export type PushOutcome = {
  status: 'idle' | 'running' | 'cancelling' | 'success' | 'cancelled' | 'failed' | 'unknown';
  targetSerial: string | null;
  message: string;
  receipts: PushReceipt[];
};
export type PushUiState = {
  destination: PushDestination;
  retry: PushPayload | null;
  outcome: PushOutcome;
  operationId: string | null;
  contextSerial: string | null;
  contextMode: string | null;
};

export const initialPushUiState: PushUiState = {
  destination: '/sdcard/Download/',
  retry: null,
  outcome: { status: 'idle', targetSerial: null, message: '', receipts: [] },
  operationId: null,
  contextSerial: null,
  contextMode: null,
};

export {
  initialLogcatUiState,
  MAX_LOGCAT_PREVIEW_LINES,
  appendLogcatProgressBatch,
  hasUnredactedLogcatState,
  purgeUnredactedLogcatState,
  useLogcatExpertGuard,
  type LogcatUiState,
};

const WIFI_DISCOVERY_FIELDS = ['action', 'bounded', 'count', 'discardedCount', 'services'] as const;
const WIFI_SERVICE_FIELDS = ['addressFamily', 'endpoint', 'host', 'id', 'instance', 'port', 'serviceType'] as const;

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]) {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

function isLocalIpv4(host: string) {
  const segments = host.split('.');
  if (segments.length !== 4 || segments.some((segment) => !/^(?:0|[1-9][0-9]{0,2})$/.test(segment))) return false;
  const octets = segments.map(Number);
  if (octets.some((octet) => octet < 0 || octet > 255)) return false;
  const [first, second] = octets;
  return first === 10
    || (first === 100 && second >= 64 && second <= 127)
    || (first === 169 && second === 254)
    || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && second === 168);
}

async function wifiServiceId(serviceType: WifiService['serviceType'], endpoint: string) {
  try {
    const bytes = new TextEncoder().encode(`${serviceType}\0${endpoint}`);
    const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest), (value) => value.toString(16).padStart(2, '0')).join('');
  } catch {
    return null;
  }
}

async function parseWifiDiscovery(value: unknown): Promise<WifiService[] | null> {
  const source = record(value);
  if (
    !hasExactKeys(source, WIFI_DISCOVERY_FIELDS)
    || source.action !== 'discover'
    || source.bounded !== true
    || typeof source.count !== 'number'
    || !Number.isInteger(source.count)
    || source.count < 0
    || typeof source.discardedCount !== 'number'
    || !Number.isInteger(source.discardedCount)
    || source.discardedCount < 0
    || !Array.isArray(source.services)
    || source.services.length > 256
    || source.count !== source.services.length
    || source.count + source.discardedCount > 256
  ) return null;

  const parsed: WifiService[] = [];
  const identities = new Set<string>();
  for (const raw of source.services) {
    const item = record(raw);
    const serviceType = item.serviceType;
    if (
      !hasExactKeys(item, WIFI_SERVICE_FIELDS)
      || typeof item.id !== 'string'
      || !/^[0-9a-f]{64}$/.test(item.id)
      || typeof item.instance !== 'string'
      || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/.test(item.instance)
      || (serviceType !== 'pairing' && serviceType !== 'connect' && serviceType !== 'legacy')
      || typeof item.host !== 'string'
      || !isLocalIpv4(item.host)
      || typeof item.port !== 'number'
      || !Number.isInteger(item.port)
      || item.port < 1
      || item.port > 65535
      || typeof item.endpoint !== 'string'
      || item.endpoint !== `${item.host}:${item.port}`
      || item.addressFamily !== 'ipv4'
    ) return null;
    const identity = `${serviceType}\0${item.endpoint}`;
    const expectedId = await wifiServiceId(serviceType, item.endpoint);
    if (!expectedId || item.id !== expectedId || identities.has(identity)) return null;
    identities.add(identity);
    parsed.push({
      id: item.id,
      instance: item.instance,
      serviceType,
      host: item.host,
      port: item.port,
      endpoint: item.endpoint,
    });
  }
  return parsed;
}

function parsePushReceipts(value: unknown, expectedSerial: string): PushReceipt[] | null {
  const source = record(value);
  if (!hasExactKeys(source, ['count', 'files', 'targetSerial'])
    || typeof source.targetSerial !== 'string'
    || !validTargetSerial(source.targetSerial)
    || source.targetSerial !== expectedSerial
    || typeof source.count !== 'number'
    || !Number.isInteger(source.count)
    || source.count < 1
    || source.count > 32
    || !Array.isArray(source.files)
    || source.files.length !== source.count) return null;
  const destinations = new Set<string>();
  const displayNames = new Set<string>();
  const receipts: PushReceipt[] = [];
  for (const raw of source.files) {
    const item = record(raw);
    if (!hasExactKeys(item, ['destination', 'displayName', 'sha256', 'sizeBytes', 'verified'])
      || typeof item.displayName !== 'string'
      || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(item.displayName)
      || typeof item.destination !== 'string'
      || ![`/data/local/tmp/${item.displayName}`, `/sdcard/Download/${item.displayName}`].includes(item.destination)
      || destinations.has(item.destination)
      || displayNames.has(item.displayName.toLowerCase())
      || typeof item.sha256 !== 'string'
      || !/^[0-9a-f]{64}$/.test(item.sha256)
      || typeof item.sizeBytes !== 'number'
      || !Number.isSafeInteger(item.sizeBytes)
      || item.sizeBytes < 0
      || item.verified !== true) return null;
    destinations.add(item.destination);
    displayNames.add(item.displayName.toLowerCase());
    receipts.push({
      displayName: item.displayName,
      destination: item.destination,
      sha256: item.sha256,
      sizeBytes: item.sizeBytes,
      verified: true,
    });
  }
  return receipts;
}

function parsePartitionReceipt(
  value: unknown,
  action: PartitionAction,
  expectedSerial: string,
  expectedPartition: string,
): PartitionReceipt | null {
  const source = record(value);
  const common = source.action === action
    && source.targetSerial === expectedSerial
    && validTargetSerial(expectedSerial)
    && source.partition === expectedPartition
    && typeof source.partition === 'string'
    && /^[a-z0-9][a-z0-9_.-]{0,63}$/.test(source.partition)
    && source.verified === true;
  if (!common) return null;
  if (action === 'read') {
    if (!hasExactKeys(source, ['action', 'fileName', 'partition', 'sha256', 'sizeBytes', 'targetSerial', 'verified'])
      || typeof source.fileName !== 'string'
      || !/^[A-Za-z0-9][A-Za-z0-9._ +@=-]{0,191}$/.test(source.fileName)
      || typeof source.sha256 !== 'string'
      || !/^[0-9a-f]{64}$/.test(source.sha256)
      || typeof source.sizeBytes !== 'number'
      || !Number.isSafeInteger(source.sizeBytes)
      || source.sizeBytes < 1
      || source.sizeBytes > 16 * 1024 * 1024 * 1024) return null;
    return {
      action,
      targetSerial: expectedSerial,
      partition: expectedPartition,
      fileName: source.fileName,
      sha256: source.sha256,
      sizeBytes: source.sizeBytes,
    };
  }
  if (action === 'write') {
    if (!hasExactKeys(source, ['action', 'partition', 'sha256', 'targetSerial', 'verified'])
      || typeof source.sha256 !== 'string'
      || !/^[0-9a-f]{64}$/.test(source.sha256)) return null;
    return {
      action,
      targetSerial: expectedSerial,
      partition: expectedPartition,
      sha256: source.sha256,
    };
  }
  if (!hasExactKeys(source, ['action', 'erased', 'partition', 'targetSerial', 'verified'])
    || source.erased !== true) return null;
  return { action, targetSerial: expectedSerial, partition: expectedPartition };
}

function formatBytes(sizeBytes: number) {
  if (sizeBytes < 1024) return `${sizeBytes} B`;
  if (sizeBytes < 1024 * 1024) return `${(sizeBytes / 1024).toFixed(1)} KiB`;
  return `${(sizeBytes / 1024 / 1024).toFixed(1)} MiB`;
}

export function ToolsPage({
  snapshot,
  selectedSerials,
  onCommand,
  expertMode,
  pushUiState,
  onPushUiStateChange,
  logcatUiState,
  logcatProgressBatch,
  onLogcatUiStateChange,
}: SharedPageProps & {
  expertMode: boolean;
  pushUiState?: PushUiState;
  onPushUiStateChange?: Dispatch<SetStateAction<PushUiState>>;
  logcatUiState?: LogcatUiState;
  logcatProgressBatch?: readonly ActiveOperation[];
  onLogcatUiStateChange?: Dispatch<SetStateAction<LogcatUiState>>;
}) {
  const { t } = useI18n();
  const primary = selectedSerials.length === 1
    ? snapshot.devices.find((device) => device.serial === selectedSerials[0])
    : undefined;
  const adbReady = primary?.mode === 'adb' && isToolchainReady(snapshot);
  const fastbootReady = ['fastboot', 'fastbootd'].includes(primary?.mode ?? '') && isToolchainReady(snapshot);
  const toolchainReady = isToolchainReady(snapshot);
  const [panel, setPanel] = useState<ToolPanel>(() => (
    pushUiState?.outcome.status !== 'idle'
    || snapshot.activeOperation?.kind === commands.toolsPushFiles
      ? 'push'
      : null
  ));
  const [busy, setBusy] = useState('');
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [partitions, setPartitions] = useState<PartitionRow[]>([]);
  const [partition, setPartition] = useState('');
  const [partitionOutcome, setPartitionOutcome] = useState<PartitionOutcome>({
    status: 'idle',
    action: null,
    targetSerial: null,
    message: '',
    receipt: null,
  });
  const [partitionRetry, setPartitionRetry] = useState<PartitionAction | null>(null);
  const [partitionOperationId, setPartitionOperationId] = useState<string | null>(null);
  const [scrcpyMaxSize, setScrcpyMaxSize] = useState(1920);
  const [scrcpyMaxFps, setScrcpyMaxFps] = useState(60);
  const [scrcpyVideoBitRate, setScrcpyVideoBitRate] = useState(12);
  const [scrcpyFullscreen, setScrcpyFullscreen] = useState(false);
  const [scrcpyAlwaysOnTop, setScrcpyAlwaysOnTop] = useState(false);
  const [scrcpyStayAwake, setScrcpyStayAwake] = useState(true);
  const [scrcpyTurnScreenOff, setScrcpyTurnScreenOff] = useState(false);
  const [scrcpyShowTouches, setScrcpyShowTouches] = useState(false);
  const [scrcpyNoAudio, setScrcpyNoAudio] = useState(false);
  const [avbSource, setAvbSource] = useState<'image' | 'manual'>('image');
  const [avbSecurityPatch, setAvbSecurityPatch] = useState('');
  const [avbPatchFingerprint, setAvbPatchFingerprint] = useState(true);
  const [wifiAction, setWifiAction] = useState<'pair' | 'connect' | 'disconnect' | 'status'>('status');
  const [wifiHost, setWifiHost] = useState('192.168.1.42');
  const [wifiPort, setWifiPort] = useState(5555);
  const [wifiServices, setWifiServices] = useState<WifiService[]>([]);
  const [wifiDiscoveryRan, setWifiDiscoveryRan] = useState(false);
  const [selectedWifiServiceId, setSelectedWifiServiceId] = useState('');
  const [myTools, setMyTools] = useState<MyToolRow[]>([]);
  const [legacyMyTools, setLegacyMyTools] = useState<MyToolRow[]>([]);
  const [myToolId, setMyToolId] = useState('');
  const [myToolTitle, setMyToolTitle] = useState('');
  const [myToolArguments, setMyToolArguments] = useState('');
  const [myToolEnabled, setMyToolEnabled] = useState(true);
  const [myToolGrant, setMyToolGrant] = useState('');
  const [myToolGrantRevision, setMyToolGrantRevision] = useState<number | undefined>();
  const [myToolExecutableName, setMyToolExecutableName] = useState('');
  const [legacyRawPending, setLegacyRawPending] = useState<{ tool: MyToolRow; action: 'allow' | 'run' } | null>(null);
  const [legacyRawConfirmation, setLegacyRawConfirmation] = useState('');
  const [secretPromptOpen, setSecretPromptOpen] = useState(false);
  const [secretValue, setSecretValue] = useState('');
  const secretResolverRef = useRef<((value: string | null) => void) | null>(null);
  const secretDialogRef = useRef<HTMLElement>(null);
  const secretInputRef = useRef<HTMLInputElement>(null);
  const [localPushUiState, setLocalPushUiState] = useState<PushUiState>(initialPushUiState);
  useEffect(() => {
    if (expertMode) return;
    setLegacyRawPending(null);
    setLegacyRawConfirmation('');
    if (panel === 'mytools') setPanel(null);
  }, [expertMode, panel]);
  const currentPushUiState = pushUiState ?? localPushUiState;
  const setPushUiState = onPushUiStateChange ?? setLocalPushUiState;
  const pushDestination = currentPushUiState.destination;
  const pushRetry = currentPushUiState.retry;
  const pushOutcome = currentPushUiState.outcome;
  const queuedPushOperationId = currentPushUiState.operationId;
  const setPushRetry = (retry: PushPayload | null) => {
    setPushUiState((current) => ({ ...current, retry }));
  };
  const setPushOutcome = (next: SetStateAction<PushOutcome>) => {
    setPushUiState((current) => ({
      ...current,
      outcome: typeof next === 'function' ? next(current.outcome) : next,
    }));
  };
  const pushContextRef = useRef({ serial: primary?.serial ?? null, mode: primary?.mode ?? null });
  pushContextRef.current = { serial: primary?.serial ?? null, mode: primary?.mode ?? null };
  const activePushCandidate = snapshot.activeOperation?.kind === commands.toolsPushFiles
    && ['pending', 'running'].includes(normalizeOperationStatus(snapshot.activeOperation.status))
    ? snapshot.activeOperation
    : null;
  const activePush = activePushCandidate
    && primary?.mode === 'adb'
    && (activePushCandidate.targetSerial ?? activePushCandidate.target_serial) === primary.serial
    ? activePushCandidate
    : null;
  const activePartitionCandidate = snapshot.activeOperation
    && [commands.partitionsRead, commands.partitionsWrite, commands.partitionsErase]
      .includes(snapshot.activeOperation.kind as typeof commands.partitionsRead)
    && ['pending', 'running'].includes(normalizeOperationStatus(snapshot.activeOperation.status))
      ? snapshot.activeOperation
      : null;
  const activePartition = activePartitionCandidate
    && primary
    && ['fastboot', 'fastbootd'].includes(primary.mode)
    && (activePartitionCandidate.targetSerial ?? activePartitionCandidate.target_serial) === primary.serial
      ? activePartitionCandidate
      : null;

  useEffect(() => {
    if (!secretPromptOpen) return;
    window.requestAnimationFrame(() => secretInputRef.current?.focus());
  }, [secretPromptOpen]);

  useEffect(() => () => {
    secretResolverRef.current?.(null);
    secretResolverRef.current = null;
  }, []);

  useEffect(() => {
    setPushUiState((current) => (
      current.contextSerial === (primary?.serial ?? null)
      && current.contextMode === (primary?.mode ?? null)
        ? current
        : {
            ...current,
            retry: null,
            outcome: { status: 'idle', targetSerial: null, message: '', receipts: [] },
            operationId: null,
            contextSerial: primary?.serial ?? null,
            contextMode: primary?.mode ?? null,
          }
    ));
  }, [primary?.mode, primary?.serial]);

  useEffect(() => {
    setPartitionOutcome({
      status: 'idle',
      action: null,
      targetSerial: null,
      message: '',
      receipt: null,
    });
    setPartitionRetry(null);
    setPartitionOperationId(null);
  }, [primary?.mode, primary?.serial]);

  const requestPairingCode = () => new Promise<string | null>((resolve) => {
    secretResolverRef.current = resolve;
    setSecretValue('');
    setSecretPromptOpen(true);
  });

  const finishSecretPrompt = (value: string | null) => {
    const resolve = secretResolverRef.current;
    secretResolverRef.current = null;
    setSecretValue('');
    setSecretPromptOpen(false);
    resolve?.(value);
  };

  const runTool = async (
    command: BridgeCommand,
    payload: Record<string, unknown>,
    options?: CommandRunOptions,
  ) => {
    if (busy) return null;
    setBusy(command);
    setResult(null);
    try {
      const response = await (options
        ? onCommand(command, payload, options)
        : onCommand(command, payload));
      if (response) setResult(record(response.result));
      return response;
    } finally {
      setBusy('');
    }
  };

  const listPartitions = async () => {
    if (!primary || !fastbootReady) return;
    const response = await runTool(commands.partitionsList, { serial: primary.serial });
    const value = record(record(response?.result).value);
    const parsed = (Array.isArray(value.partitions) ? value.partitions : []).flatMap((entry) => {
      const item = record(entry);
      if (typeof item.name !== 'string' || !item.name) return [];
      return [{
        name: item.name,
        sizeBytes: typeof item.size_bytes === 'number' ? item.size_bytes : null,
        partitionType: typeof item.partition_type === 'string' ? item.partition_type : '',
      }];
    });
    setPartitions(parsed);
    setPartition((current) => parsed.some((entry) => entry.name === current) ? current : parsed[0]?.name ?? '');
  };

  const runPartition = async (
    action: PartitionAction,
    payload: Record<string, unknown>,
    expectedRevision?: number,
  ) => {
    if (!primary || !fastbootReady || busy) return;
    const expectedPartition = partition;
    const expectedSerial = primary.serial;
    setPartitionRetry(action);
    setPartitionOutcome({
      status: 'running',
      action,
      targetSerial: expectedSerial,
      message: t('tools.partitionRunning'),
      receipt: null,
    });
    const response = await runTool(
      action === 'read'
        ? commands.partitionsRead
        : action === 'write'
          ? commands.partitionsWrite
          : commands.partitionsErase,
      payload,
      {
        returnCancelled: true,
        returnFailed: true,
        suppressNotice: true,
        onOperationAccepted: setPartitionOperationId,
        ...(expectedRevision === undefined ? {} : { expectedRevision }),
      },
    );
    setPartitionOperationId(null);
    if (!response) {
      setPartitionOutcome({
        status: 'failed',
        action,
        targetSerial: expectedSerial,
        message: t('tools.partitionFailed'),
        receipt: null,
      });
      return;
    }
    const operation = record(response.result);
    const status = normalizeOperationStatus(operation.status);
    if (status === 'success') {
      const receipt = parsePartitionReceipt(
        operation.value,
        action,
        expectedSerial,
        expectedPartition,
      );
      if (receipt === null) {
        setPartitionOutcome({
          status: 'failed',
          action,
          targetSerial: expectedSerial,
          message: t('tools.partitionInvalidReceipt'),
          receipt: null,
        });
        return;
      }
      setPartitionRetry(null);
      setPartitionOutcome({
        status: 'success',
        action,
        targetSerial: expectedSerial,
        message: t('tools.partitionVerified'),
        receipt,
      });
      return;
    }
    if (status === 'cancelled') {
      setPartitionOutcome({
        status: 'cancelled',
        action,
        targetSerial: expectedSerial,
        message: t('tools.partitionCancelled'),
        receipt: null,
      });
      return;
    }
    setPartitionOutcome({
      status: operation.code === 'outcome_unknown' ? 'unknown' : 'failed',
      action,
      targetSerial: expectedSerial,
      message: operation.code === 'outcome_unknown'
        ? t('tools.partitionUnknown')
        : t('tools.partitionFailed'),
      receipt: null,
    });
  };

  const readPartition = async () => {
    if (!primary || !fastbootReady || !partition || busy) return;
    setBusy('partition-read-picker');
    try {
      const picked = await onCommand(commands.nativeSaveFile, {
        purpose: 'partitions.read.destination',
        title: t('tools.partitionRead'),
        defaultName: `${partition}.img`,
        filters: [{ label: t('tools.partition'), extensions: ['img'] }],
      });
      const grant = selectedGrant(picked);
      if (!grant) return;
      setBusy('');
      await runPartition(
        'read',
        { serial: primary.serial, partition, grant, overwrite: true },
        picked?.revision,
      );
    } finally {
      setBusy('');
    }
  };

  const writePartition = async () => {
    if (!primary || !fastbootReady || !partition || busy) return;
    setBusy('partition-write-picker');
    try {
      const picked = await onCommand(commands.nativePickFile, {
        purpose: 'partitions.write.source',
        title: t('tools.partitionWrite'),
        filters: [{ label: t('tools.partition'), extensions: ['img'] }],
      });
      const grant = selectedGrant(picked);
      if (!grant) return;
      setBusy('');
      await runPartition(
        'write',
        { serial: primary.serial, partition, grant },
        picked?.revision,
      );
    } finally {
      setBusy('');
    }
  };

  const erasePartition = async () => {
    if (!primary || !fastbootReady || !partition || busy) return;
    await runPartition('erase', { serial: primary.serial, partition });
  };

  const cancelPartition = async () => {
    const operationId = activePartition?.id ?? partitionOperationId;
    if (!operationId || partitionOutcome.status === 'cancelling') return;
    setPartitionOutcome((current) => ({
      ...current,
      status: 'cancelling',
      message: t('tools.partitionCancelling'),
    }));
    const response = await onCommand(commands.operationCancel, { operationId });
    if (!response) {
      setPartitionOutcome((current) => ({
        ...current,
        status: 'running',
        message: t('tools.partitionRunning'),
      }));
    }
  };

  const retryPartition = async () => {
    if (!partitionRetry || busy || !fastbootReady) return;
    if (partitionRetry === 'read') await readPartition();
    else if (partitionRetry === 'write') await writePartition();
    else await erasePartition();
  };

  const runPush = async (payload: PushPayload, expectedRevision?: number) => {
    setPushUiState((current) => ({
      ...current,
      retry: payload,
      operationId: null,
      outcome: {
        status: 'running',
        targetSerial: payload.serial,
        message: t('tools.pushPreparing'),
        receipts: [],
      },
    }));
    const response = await runTool(
      commands.toolsPushFiles,
      payload,
      {
        returnCancelled: true,
        returnFailed: true,
        suppressNotice: true,
        onOperationAccepted: (operationId) => {
          setPushUiState((current) => ({ ...current, operationId }));
        },
        ...(expectedRevision === undefined ? {} : { expectedRevision }),
      },
    );
    const contextStillMatches = pushContextRef.current.serial === payload.serial
      && pushContextRef.current.mode === 'adb';
    if (!contextStillMatches) return;
    setPushUiState((current) => ({ ...current, operationId: null }));
    if (!response) {
      setPushOutcome({ status: 'failed', targetSerial: payload.serial, message: t('tools.pushFailed'), receipts: [] });
      return;
    }
    const operation = record(response.result);
    const status = normalizeOperationStatus(operation.status);
    if (status === 'success') {
      const receipts = parsePushReceipts(operation.value, payload.serial);
      if (receipts === null) {
        setPushOutcome({ status: 'failed', targetSerial: payload.serial, message: t('tools.pushInvalidReceipt'), receipts: [] });
        return;
      }
      setPushRetry(null);
      setPushOutcome({ status: 'success', targetSerial: payload.serial, message: t('tools.pushReceipts'), receipts });
      return;
    }
    if (status === 'cancelled') {
      setPushOutcome({ status: 'cancelled', targetSerial: payload.serial, message: t('tools.pushCancelled'), receipts: [] });
      return;
    }
    setPushOutcome({
      status: operation.code === 'outcome_unknown' ? 'unknown' : 'failed',
      targetSerial: payload.serial,
      message: operation.code === 'outcome_unknown' ? t('tools.pushUnknown') : t('tools.pushFailed'),
      receipts: [],
    });
  };

  const pushFiles = async () => {
    if (!primary || !adbReady || busy) return;
    setBusy('push-picker');
    try {
      const picked = await onCommand(commands.nativePickFiles, {
        purpose: 'tools.pushFiles.sources',
        title: t('tools.chooseFiles'),
      });
      const grants = selectedGrants(picked);
      if (!grants.length) return;
      setBusy('');
      await runPush(
        { serial: primary.serial, grants, destination: pushDestination },
        picked?.revision,
      );
    } finally {
      setBusy('');
    }
  };

  const cancelPush = async () => {
    const operationId = activePush?.id ?? queuedPushOperationId;
    if (!operationId || pushOutcome.status === 'cancelling') return;
    setPushOutcome((current) => ({ ...current, status: 'cancelling', message: t('tools.pushCancelling') }));
    try {
      const response = await onCommand(commands.operationCancel, { operationId });
      const acknowledgement = record(response?.result);
      const status = normalizeOperationStatus(acknowledgement.status);
      if (!response || status !== 'success' || acknowledgement.code !== 'cancellation_requested') {
        setPushOutcome((current) => current.status === 'cancelling'
          ? { ...current, status: 'running', message: t('tools.pushRunning') }
          : current);
      }
    } catch {
      setPushOutcome((current) => current.status === 'cancelling'
        ? { ...current, status: 'running', message: t('tools.pushRunning') }
        : current);
    }
  };

  const retryPush = async () => {
    if (!pushRetry || !primary || !adbReady || busy || primary.serial !== pushRetry.serial) return;
    await runPush(pushRetry);
  };

  const changePushDestination = (destination: PushDestination) => {
    setPushUiState((current) => ({ ...current, destination, retry: null }));
  };

  const runWifi = async () => {
    if (!toolchainReady || busy) return;
    if (wifiAction === 'status') {
      if (!primary || !adbReady) return;
      await runTool(commands.toolsWifiStatus, { serial: primary.serial });
      return;
    }
    const payload: Record<string, unknown> = {
      action: wifiAction,
      host: wifiHost,
      port: wifiPort,
    };
    let operationRevision: number | undefined;
    if (wifiAction === 'pair') {
      let secret = await requestPairingCode();
      if (!secret) return;
      let approved;
      try {
        approved = await onCommand(commands.secretIssue, {
          purpose: 'wifi.pairingCode',
          secret,
        });
      } finally {
        secret = '';
      }
      const secretGrant = selectedGrant(approved);
      const issuedRevision = approved?.revision;
      if (!secretGrant || typeof issuedRevision !== 'number' || !Number.isInteger(issuedRevision) || issuedRevision < 0) return;
      payload.secretGrant = secretGrant;
      operationRevision = issuedRevision;
    }
    const response = await runTool(
      commands.toolsWifi,
      payload,
      operationRevision === undefined ? undefined : { expectedRevision: operationRevision },
    );
    const status = record(response?.result).status;
    const nextRevision = response?.revision;
    if (
      status === 'SUCCESS'
      && (wifiAction === 'connect' || wifiAction === 'disconnect')
      && typeof nextRevision === 'number'
      && Number.isInteger(nextRevision)
      && nextRevision >= 0
    ) {
      await onCommand(commands.deviceScan, {}, { expectedRevision: nextRevision });
    }
  };

  const discoverWifi = async () => {
    if (!toolchainReady || busy) return;
    const response = await runTool(commands.toolsWifiDiscover, {});
    const resultValue = record(response?.result);
    if (resultValue.status !== 'SUCCESS') return;
    const parsed = await parseWifiDiscovery(resultValue.value);
    if (parsed === null) {
      setResult(null);
      return;
    }
    setWifiServices(parsed);
    setWifiDiscoveryRan(true);
    setSelectedWifiServiceId('');
  };

  const useWifiService = (service: WifiService) => {
    setSelectedWifiServiceId(service.id);
    setWifiHost(service.host);
    setWifiPort(service.port);
    setWifiAction(service.serviceType === 'pairing' ? 'pair' : 'connect');
  };

  const createSupportPackage = async () => {
    if (busy) return;
    setBusy('support-picker');
    try {
      const picked = await onCommand(commands.nativeSaveFile, {
        title: t('tools.support'),
        purpose: 'support.create.destination',
        defaultName: 'PixelFlasher-support.zip',
        filters: [{ label: t('tools.support'), extensions: ['zip'] }],
      });
      const grant = selectedGrant(picked);
      if (!grant) return;
      setBusy('');
      await runTool(commands.supportCreate, {
        grant,
        includeConfig: true,
        includeLogs: true,
        includeState: true,
        includeSystemInfo: true,
      });
    } finally {
      setBusy('');
    }
  };

  const avbFirmwareReady = snapshot.firmware?.kind === 'factory'
    && snapshot.firmware.verified === true
    && snapshot.firmware.processed === true
    && typeof snapshot.firmware.hash === 'string'
    && /^[a-f0-9]{64}$/i.test(snapshot.firmware.hash);
  const prepareAvbDowngrade = async () => {
    if (!avbFirmwareReady || busy) return;
    if (avbSource === 'manual') {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(avbSecurityPatch)) return;
      await runTool(commands.toolsAvb, {
        action: 'prepareDowngrade',
        currentSecurityPatch: avbSecurityPatch,
        patchFingerprint: false,
      }, { returnCancelled: true, returnFailed: true });
      return;
    }
    setBusy('avb-current-boot-picker');
    try {
      const picked = await onCommand(commands.nativePickFile, {
        purpose: 'tools.avb.currentBoot',
        title: t('tools.avbChooseBoot'),
        filters: [{ label: t('tools.avbCurrentBoot'), extensions: ['img'] }],
      });
      const grant = selectedGrant(picked);
      if (!grant) return;
      setBusy('');
      await runTool(commands.toolsAvb, {
        action: 'prepareDowngrade',
        grant,
        patchFingerprint: avbPatchFingerprint,
      }, {
        expectedRevision: picked?.revision,
        returnCancelled: true,
        returnFailed: true,
      });
    } finally {
      setBusy('');
    }
  };
  const decodeBinaryXml = async () => {
    if (busy) return;
    setBusy('binary-xml-picker');
    try {
      const picked = await onCommand(commands.nativePickFile, {
        purpose: 'tools.xml.source',
        title: t('tools.xmlChoose'),
        filters: [{ label: t('tools.xmlFiles'), extensions: ['xml', 'axml'] }],
      });
      const grant = selectedGrant(picked);
      if (!grant) return;
      setBusy('');
      await runTool(commands.toolsXml, {
        action: 'decodeBinary',
        grant,
      }, {
        expectedRevision: picked?.revision,
        returnCancelled: true,
        returnFailed: true,
      });
    } finally {
      setBusy('');
    }
  };
  const analyzeKeyboxes = async () => {
    if (busy) return;
    setBusy('keybox-picker');
    try {
      const picked = await onCommand(commands.nativePickFiles, {
        purpose: 'tools.keybox.sources',
        title: t('tools.keyboxChoose'),
        filters: [{ label: t('tools.keyboxFiles'), extensions: ['xml'] }],
      });
      const grants = selectedGrants(picked);
      if (!grants.length) return;
      setBusy('');
      await runTool(commands.toolsKeybox, {
        action: 'analyze',
        grants,
      }, {
        expectedRevision: picked?.revision,
        returnCancelled: true,
        returnFailed: true,
      });
    } finally {
      setBusy('');
    }
  };

  const parseMyTool = (value: unknown, mode: MyToolRow['mode']): MyToolRow | null => {
    const item = record(value);
    if (
      !hasExactKeys(item, mode === 'legacyRaw' ? LEGACY_MY_TOOL_FIELDS : SAFE_MY_TOOL_FIELDS)
      ||
      typeof item.id !== 'string'
      || typeof item.title !== 'string'
      || item.mode !== mode
      || typeof item.displayName !== 'string'
      || typeof item.sha256 !== 'string'
      || !Array.isArray(item.arguments)
      || item.arguments.some((argument) => typeof argument !== 'string')
      || typeof item.enabled !== 'boolean'
    ) return null;
    if (mode === 'legacyRaw' && (
      !/^legacy:[A-Za-z0-9._-]{1,64}$/.test(item.id)
      || item.sha256 !== ''
      || item.arguments.length !== 0
      || typeof item.permissionGranted !== 'boolean'
      || typeof item.blockedReason !== 'string'
      || typeof item.commandPreview !== 'string'
      || typeof item.fingerprint !== 'string' || !/^[0-9a-f]{64}$/.test(item.fingerprint)
      || !['default', 'approved'].includes(String(item.workingDirectory))
    )) return null;
    return {
      id: item.id,
      title: item.title,
      mode,
      displayName: item.displayName,
      sha256: item.sha256,
      arguments: item.arguments as string[],
      enabled: item.enabled,
      ...(typeof item.blockedReason === 'string' ? { blockedReason: item.blockedReason } : {}),
      ...(typeof item.permissionGranted === 'boolean' ? { permissionGranted: item.permissionGranted } : {}),
      ...(typeof item.commandPreview === 'string' ? { commandPreview: item.commandPreview } : {}),
      ...(typeof item.fingerprint === 'string' ? { fingerprint: item.fingerprint } : {}),
      ...(item.workingDirectory === 'default' || item.workingDirectory === 'approved'
        ? { workingDirectory: item.workingDirectory }
        : {}),
    };
  };
  const loadMyTools = async () => {
    const response = await runTool(commands.toolsMyTools, { action: 'list' }, { returnFailed: true });
    const value = record(record(response?.result).value);
    if (
      !hasExactKeys(value, ['legacyRaw', 'revision', 'schemaVersion', 'tools'])
      || value.schemaVersion !== 2
      || !Array.isArray(value.tools)
      || !Array.isArray(value.legacyRaw)
      || value.tools.length > 128
      || value.legacyRaw.length > 128
    ) {
      setMyTools([]);
      setLegacyMyTools([]);
      return;
    }
    const safe = value.tools.flatMap((item) => { const parsed = parseMyTool(item, 'safeArgv'); return parsed ? [parsed] : []; });
    const legacy = value.legacyRaw.flatMap((item) => { const parsed = parseMyTool(item, 'legacyRaw'); return parsed ? [parsed] : []; });
    if (safe.length !== value.tools.length || legacy.length !== value.legacyRaw.length) {
      setMyTools([]);
      setLegacyMyTools([]);
      return;
    }
    setMyTools(safe);
    setLegacyMyTools(legacy);
  };
  const resetMyToolEditor = () => {
    setMyToolId('');
    setMyToolTitle('');
    setMyToolArguments('');
    setMyToolEnabled(true);
    setMyToolGrant('');
    setMyToolGrantRevision(undefined);
    setMyToolExecutableName('');
  };
  const editMyTool = (tool: MyToolRow) => {
    setMyToolId(tool.id);
    setMyToolTitle(tool.title);
    setMyToolArguments(tool.arguments.join('\n'));
    setMyToolEnabled(tool.enabled);
    setMyToolGrant('');
    setMyToolGrantRevision(undefined);
    setMyToolExecutableName(tool.displayName);
  };
  const chooseMyToolExecutable = async () => {
    if (busy) return;
    setBusy('my-tool-picker');
    try {
      const picked = await onCommand(commands.nativePickFile, {
        purpose: 'tools.myTools.executable',
        title: t('tools.myToolsChoose'),
      });
      const grant = selectedGrant(picked);
      const resultValue = record(record(picked?.result).value);
      const data = record(record(resultValue.data).grant ? resultValue.data : record(picked?.result).data);
      if (!grant) return;
      setMyToolGrant(grant);
      setMyToolGrantRevision(picked?.revision);
      setMyToolExecutableName(typeof data.displayName === 'string' ? data.displayName : t('tools.myToolsSelected'));
    } finally {
      setBusy('');
    }
  };
  const saveMyTool = async () => {
    if (busy || !myToolTitle.trim() || (!myToolId && !myToolGrant)) return;
    const payload: Record<string, unknown> = {
      action: 'save',
      title: myToolTitle.trim(),
      arguments: myToolArguments.split(/\r?\n/).filter((argument) => argument.length > 0),
      enabled: myToolEnabled,
      ...(myToolId ? { toolId: myToolId } : {}),
      ...(myToolGrant ? { grant: myToolGrant } : {}),
    };
    const response = await runTool(
      commands.toolsMyTools,
      payload,
      { expectedRevision: myToolGrantRevision, returnFailed: true },
    );
    if (normalizeOperationStatus(record(response?.result).status) !== 'success') return;
    resetMyToolEditor();
    await loadMyTools();
  };
  const runMyTool = async (toolId: string) => {
    await runTool(commands.toolsMyTools, { action: 'run', toolId }, { returnCancelled: true, returnFailed: true });
  };
  const deleteMyTool = async (toolId: string) => {
    const response = await runTool(commands.toolsMyTools, { action: 'delete', toolId }, { returnFailed: true });
    if (normalizeOperationStatus(record(response?.result).status) !== 'success') return;
    if (myToolId === toolId) resetMyToolEditor();
    await loadMyTools();
  };
  const legacyRawRequired = legacyRawPending?.tool.fingerprint
    ? `${legacyRawPending.action === 'allow' ? 'ALLOW' : 'RUN'} RAW ${legacyRawPending.tool.fingerprint.slice(0, 8).toUpperCase()}`
    : '';
  const updateLegacyPermission = async (tool: MyToolRow, granted: boolean) => {
    if (busy) return;
    const response = await runTool(commands.toolsMyToolsLegacyPermission, {
      toolId: tool.id,
      granted,
      ...(granted ? { confirmationText: legacyRawConfirmation } : {}),
    }, { returnFailed: true });
    if (normalizeOperationStatus(record(response?.result).status) !== 'success') return;
    setLegacyRawPending(null);
    setLegacyRawConfirmation('');
    await loadMyTools();
  };
  const runLegacyRaw = async () => {
    if (!legacyRawPending || legacyRawPending.action !== 'run' || busy) return;
    const response = await runTool(commands.toolsMyToolsLegacyRun, {
      toolId: legacyRawPending.tool.id,
      confirmationText: legacyRawConfirmation,
    }, { returnCancelled: true, returnFailed: true });
    if (normalizeOperationStatus(record(response?.result).status) !== 'success') return;
    setLegacyRawPending(null);
    setLegacyRawConfirmation('');
  };
  const openMyTools = () => {
    openPanel('mytools');
    void loadMyTools();
  };

  const openPanel = (next: ToolPanel) => {
    setPanel(next);
    setResult(null);
  };
  const runScrcpy = async () => {
    if (!primary || !adbReady || busy) return;
    await runTool(commands.toolsScrcpy, {
      serial: primary.serial,
      maxSize: scrcpyMaxSize,
      maxFps: scrcpyMaxFps,
      videoBitRateMbps: scrcpyVideoBitRate,
      fullscreen: scrcpyFullscreen,
      alwaysOnTop: scrcpyAlwaysOnTop,
      stayAwake: scrcpyStayAwake,
      turnScreenOff: scrcpyTurnScreenOff,
      showTouches: scrcpyShowTouches,
      noAudio: scrcpyNoAudio,
    });
  };
  type ToolCard = { id: string; icon: AssetName; title: string; detail: string; disabled: boolean; run: () => void };
  const cards: ToolCard[] = [
    {
      id: 'recovery', icon: 'reboot', title: t('tools.recovery'), detail: t('tools.recoveryDetail'),
      disabled: !primary || !isToolchainReady(snapshot), run: () => { if (primary) void runTool(commands.deviceReboot, { serial: primary.serial, mode: 'recovery' }); },
    },
    {
      id: 'scrcpy', icon: 'devices', title: t('tools.scrcpy'), detail: t('tools.scrcpyDetail'),
      disabled: !adbReady, run: () => openPanel('scrcpy'),
    },
    {
      id: 'wifi', icon: 'adb', title: t('tools.wifi'), detail: t('tools.wifiDetail'),
      disabled: !toolchainReady, run: () => openPanel('wifi'),
    },
    {
      id: 'push', icon: 'folder', title: t('tools.push'), detail: t('tools.pushDetail'),
      disabled: !adbReady, run: () => openPanel('push'),
    },
    {
      id: 'support', icon: 'shield', title: t('tools.support'), detail: t('tools.supportDetail'),
      disabled: false, run: () => void createSupportPackage(),
    },
    ...(expertMode ? [
      { id: 'shell', icon: 'shell', title: t('tools.shell'), detail: t('tools.shellDetail'), disabled: !adbReady, run: () => openPanel('shell') },
      { id: 'logcat', icon: 'logs', title: t('tools.logs'), detail: t('tools.logcatDetail'), disabled: !adbReady, run: () => openPanel('logcat') },
      { id: 'partition', icon: 'slot', title: t('tools.partition'), detail: t('tools.partitionDetail'), disabled: !fastbootReady, run: () => openPanel('partitions') },
      { id: 'bootloader', icon: 'bootloader', title: t('tools.bootloader'), detail: t('tools.bootloaderDetail'), disabled: !primary || !isToolchainReady(snapshot), run: () => { if (primary) void runTool(commands.deviceReboot, { serial: primary.serial, mode: 'bootloader' }); } },
      { id: 'avb', icon: 'shield', title: t('tools.avbDowngrade'), detail: t('tools.avbDowngradeDetail'), disabled: !avbFirmwareReady, run: () => openPanel('avb') },
      { id: 'xml', icon: 'processFile', title: t('tools.xmlDecode'), detail: t('tools.xmlDecodeDetail'), disabled: false, run: () => openPanel('xml') },
      { id: 'keybox', icon: 'shield', title: t('tools.keyboxValidate'), detail: t('tools.keyboxValidateDetail'), disabled: false, run: () => openPanel('keybox') },
      { id: 'mytools', icon: 'wrench', title: t('tools.myTools'), detail: t('tools.myToolsDetail'), disabled: false, run: openMyTools },
    ] satisfies ToolCard[] : []),
  ];
  const pushProgress = typeof activePush?.progress === 'number' && Number.isFinite(activePush.progress)
    ? Math.max(0, Math.min(100, activePush.progress))
    : null;
  const partitionProgress = typeof activePartition?.progress === 'number'
    && Number.isFinite(activePartition.progress)
      ? Math.max(0, Math.min(100, activePartition.progress))
      : null;
  const partitionPending = Boolean(
    activePartition
    || (
      partitionOperationId
      && primary
      && ['fastboot', 'fastbootd'].includes(primary.mode)
      && partitionOutcome.targetSerial === primary.serial
      && ['running', 'cancelling'].includes(partitionOutcome.status)
    ),
  );
  const canRetryPartition = Boolean(
    partitionRetry && fastbootReady && !busy && !partitionPending,
  );
  const pushPending = Boolean(
    activePush
    || (
      queuedPushOperationId
      && primary?.mode === 'adb'
      && pushOutcome.targetSerial === primary.serial
      && ['running', 'cancelling'].includes(pushOutcome.status)
    ),
  );
  const canRetryPush = Boolean(
    pushRetry
    && primary
    && adbReady
    && primary.serial === pushRetry.serial
    && !busy
    && !pushPending,
  );
  const toolResultStatus = normalizeOperationStatus(result?.status);
  const toolResultSucceeded = toolResultStatus === 'success';
  const toolResultFailed = toolResultStatus === 'failed';

  return (
    <>
      <PageHeader title={t('tools.title')} subtitle={t('tools.subtitle')} />
      {!primary ? <div className="inline-alert inline-alert--warning"><Icon name="warningPng" size={18} /><span>{t('device.singleActionGuard')}</span></div> : null}
      <div className="tool-grid">
        {cards.map((tool) => (
          <button type="button" className={`tool-card ${panel === tool.id ? 'is-active' : ''}`} key={tool.id} onClick={tool.run} disabled={Boolean(busy) || tool.disabled}>
            <span className="tool-card__icon"><Icon name={tool.icon} size={28} /></span>
            <span><strong>{tool.title}</strong><small>{tool.detail}</small></span>
            {tool.disabled ? <Badge tone="neutral">{t('common.disabled')}</Badge> : null}
            <Icon name="right" size={18} />
          </button>
        ))}
      </div>

      {panel ? (
        <Card className="tool-workspace" aria-busy={Boolean(busy)}>
          <CardTitle icon={panel === 'scrcpy' ? 'devices' : panel === 'shell' ? 'shell' : panel === 'logcat' ? 'logs' : panel === 'partitions' ? 'slot' : panel === 'push' ? 'folder' : panel === 'avb' || panel === 'keybox' ? 'shield' : panel === 'xml' ? 'processFile' : panel === 'mytools' ? 'wrench' : 'adb'} after={<Button variant="ghost" onClick={() => setPanel(null)}>{t('common.close')}</Button>}>
            {panel === 'scrcpy' ? t('tools.scrcpy') : panel === 'shell' ? t('tools.shell') : panel === 'logcat' ? t('tools.logs') : panel === 'partitions' ? t('tools.partition') : panel === 'push' ? t('tools.push') : panel === 'avb' ? t('tools.avbDowngrade') : panel === 'xml' ? t('tools.xmlDecode') : panel === 'keybox' ? t('tools.keyboxValidate') : panel === 'mytools' ? t('tools.myTools') : t('tools.wifi')}
          </CardTitle>
          {panel === 'scrcpy' ? (
            <div className="tool-panel-body scrcpy-panel">
              <p className="tool-help">{t('tools.scrcpyOptionsDetail')}</p>
              <div className="wifi-discovery-toolbar">
                <div><strong>{t('tools.scrcpyInstall')}</strong><p>{t('tools.scrcpyInstallDetail')}</p></div>
                <Button icon="download" onClick={() => void runTool(commands.toolsScrcpySetup, { source: 'official' })} disabled={Boolean(busy)}>{t('tools.scrcpyInstall')}</Button>
              </div>
              <div className="tool-form-grid scrcpy-options-grid">
                <label><span>{t('tools.scrcpyMaxSize')}</span><input type="number" min="0" max="8192" value={scrcpyMaxSize} onChange={(event) => setScrcpyMaxSize(Number(event.currentTarget.value))} disabled={Boolean(busy)} /></label>
                <label><span>{t('tools.scrcpyMaxFps')}</span><input type="number" min="1" max="240" value={scrcpyMaxFps} onChange={(event) => setScrcpyMaxFps(Number(event.currentTarget.value))} disabled={Boolean(busy)} /></label>
                <label><span>{t('tools.scrcpyBitRate')}</span><input type="number" min="1" max="200" value={scrcpyVideoBitRate} onChange={(event) => setScrcpyVideoBitRate(Number(event.currentTarget.value))} disabled={Boolean(busy)} /></label>
              </div>
              <fieldset className="scrcpy-toggle-grid">
                <legend>{t('tools.scrcpyWindowOptions')}</legend>
                <label><input type="checkbox" checked={scrcpyFullscreen} onChange={(event) => setScrcpyFullscreen(event.currentTarget.checked)} disabled={Boolean(busy)} />{t('tools.scrcpyFullscreen')}</label>
                <label><input type="checkbox" checked={scrcpyAlwaysOnTop} onChange={(event) => setScrcpyAlwaysOnTop(event.currentTarget.checked)} disabled={Boolean(busy)} />{t('tools.scrcpyAlwaysOnTop')}</label>
                <label><input type="checkbox" checked={scrcpyStayAwake} onChange={(event) => setScrcpyStayAwake(event.currentTarget.checked)} disabled={Boolean(busy)} />{t('tools.scrcpyStayAwake')}</label>
                <label><input type="checkbox" checked={scrcpyTurnScreenOff} onChange={(event) => setScrcpyTurnScreenOff(event.currentTarget.checked)} disabled={Boolean(busy)} />{t('tools.scrcpyTurnScreenOff')}</label>
                <label><input type="checkbox" checked={scrcpyShowTouches} onChange={(event) => setScrcpyShowTouches(event.currentTarget.checked)} disabled={Boolean(busy)} />{t('tools.scrcpyShowTouches')}</label>
                <label><input type="checkbox" checked={scrcpyNoAudio} onChange={(event) => setScrcpyNoAudio(event.currentTarget.checked)} disabled={Boolean(busy)} />{t('tools.scrcpyNoAudio')}</label>
              </fieldset>
              <Button variant="primary" icon="devices" onClick={() => void runScrcpy()} disabled={Boolean(busy) || !adbReady || scrcpyMaxSize < 0 || scrcpyMaxSize > 8192 || scrcpyMaxFps < 1 || scrcpyMaxFps > 240 || scrcpyVideoBitRate < 1 || scrcpyVideoBitRate > 200}>{t('tools.scrcpyLaunch')}</Button>
            </div>
          ) : null}
          {panel === 'wifi' ? (
            <div className="tool-panel-body">
              <div className="wifi-discovery-toolbar">
                <div><strong>{t('tools.wifiDiscover')}</strong><p>{t('tools.wifiDiscoverDetail')}</p></div>
                <Button icon="scan" onClick={() => void discoverWifi()} disabled={Boolean(busy) || !toolchainReady}>{t('tools.wifiDiscoverAction')}</Button>
              </div>
              {wifiServices.length ? (
                <ul className="wifi-discovery-results" aria-label={t('tools.wifiDiscovered')}>
                  {wifiServices.map((service) => (
                    <li key={service.id}>
                      <button type="button" aria-pressed={selectedWifiServiceId === service.id} onClick={() => useWifiService(service)} disabled={Boolean(busy)}>
                        <span><strong>{service.instance}</strong><small>{service.serviceType === 'pairing' ? t('tools.pair') : t('tools.connect')}</small></span>
                        <code>{service.endpoint}</code>
                      </button>
                    </li>
                  ))}
                </ul>
              ) : wifiDiscoveryRan ? <EmptyState icon="scan" title={t('common.none')} detail={t('tools.wifiNone')} /> : null}
              <p className="tool-help">{t('tools.wifiUntrusted')}</p>
              {wifiAction === 'status' && !adbReady ? <div className="inline-alert inline-alert--warning"><Icon name="warningPng" size={18} /><span>{t('tools.wifiConnectGuard')}</span></div> : null}
              <div className="tool-form-grid">
                <label><span>{t('tools.action')}</span><select value={wifiAction} onChange={(event) => setWifiAction(event.currentTarget.value as typeof wifiAction)} disabled={Boolean(busy)}><option value="status">{t('tools.status')}</option><option value="pair">{t('tools.pair')}</option><option value="connect">{t('tools.connect')}</option><option value="disconnect">{t('tools.disconnect')}</option></select></label>
                {wifiAction !== 'status' ? <label><span>{t('tools.host')}</span><input value={wifiHost} onChange={(event) => setWifiHost(event.currentTarget.value)} inputMode="decimal" autoComplete="off" /></label> : null}
                {wifiAction !== 'status' ? <label><span>{t('tools.port')}</span><input type="number" min="1" max="65535" value={wifiPort} onChange={(event) => setWifiPort(Number(event.currentTarget.value))} /></label> : null}
                {wifiAction === 'pair' ? <p className="tool-help">{t('tools.pairingCode')}</p> : null}
                <Button variant="primary" icon="adb" onClick={() => void runWifi()} disabled={Boolean(busy) || !toolchainReady || (wifiAction === 'status' ? !adbReady : (!wifiHost || wifiPort < 1 || wifiPort > 65535))}>{t('common.apply')}</Button>
              </div>
            </div>
          ) : null}
          {panel === 'shell' && expertMode && primary ? (
            <Suspense fallback={<p className="tool-help" role="status">{t('tools.shellOpening')}</p>}>
              <AdbShellPanel serial={primary.serial} revision={snapshot.revision} />
            </Suspense>
          ) : null}
          {panel === 'logcat' ? (
            <LogcatPanel
              device={primary}
              operation={snapshot.activeOperation}
              progressBatch={logcatProgressBatch}
              adbReady={adbReady}
              hostBusy={Boolean(busy)}
              expertMode={expertMode}
              onCommand={onCommand}
              uiState={logcatUiState}
              onUiStateChange={onLogcatUiStateChange}
            />
          ) : null}
          {panel === 'partitions' ? (
            <div className="tool-panel-body">
              <div className="tool-form-grid tool-form-grid--partition"><label><span>{t('tools.selectPartition')}</span><select value={partition} onChange={(event) => setPartition(event.currentTarget.value)} disabled={!partitions.length || Boolean(busy) || partitionPending}><option value="">—</option>{partitions.map((entry) => <option value={entry.name} key={entry.name}>{entry.name}</option>)}</select></label><Button icon="scan" onClick={() => void listPartitions()} disabled={Boolean(busy) || partitionPending || !fastbootReady}>{t('common.refresh')}</Button><Button icon="download" onClick={() => void readPartition()} disabled={Boolean(busy) || partitionPending || !partition}>{t('tools.partitionRead')}</Button><Button variant="primary" icon="flash" onClick={() => void writePartition()} disabled={Boolean(busy) || partitionPending || !partition}>{t('tools.partitionWrite')}</Button><Button variant="danger" icon="warningPng" onClick={() => void erasePartition()} disabled={Boolean(busy) || partitionPending || !partition}>{t('tools.partitionErase')}</Button></div>
              {partitionPending ? (
                <div className="push-progress">
                  <div className="push-progress__copy" role="status" aria-live="polite">
                    <strong>{partitionOutcome.status === 'cancelling' ? t('tools.partitionCancelling') : t('tools.partitionRunning')}</strong>
                    <span>{activePartition?.detail || partitionOutcome.message}</span>
                  </div>
                  {partitionProgress !== null ? <progress aria-label={t('tools.partitionProgress')} max={100} value={partitionProgress} /> : null}
                  <Button variant="ghost" onClick={() => void cancelPartition()} disabled={partitionOutcome.status === 'cancelling'}>{t('common.cancel')}</Button>
                </div>
              ) : null}
              {!partitionPending && partitionOutcome.status !== 'idle' ? (
                <div className={`push-outcome push-outcome--${partitionOutcome.status}`}>
                  <Icon name={partitionOutcome.status === 'success' ? 'check' : 'warningPng'} size={18} />
                  <span role={partitionOutcome.status === 'failed' || partitionOutcome.status === 'unknown' ? 'alert' : 'status'} aria-live={partitionOutcome.status === 'failed' || partitionOutcome.status === 'unknown' ? 'assertive' : 'polite'}>
                    <strong>{partitionOutcome.status === 'success' ? t('tools.partitionVerified') : partitionOutcome.status === 'unknown' ? t('tools.partitionUnknownTitle') : t('tools.results')}</strong>
                    <small>{partitionOutcome.message}</small>
                  </span>
                  {partitionRetry ? <Button variant="ghost" onClick={() => void retryPartition()} disabled={!canRetryPartition}>{t('tools.partitionRetry')}</Button> : null}
                </div>
              ) : null}
              {partitionOutcome.receipt ? (
                <div className="artifact-hash" aria-label={t('tools.partitionVerified')}>
                  <Badge tone="success">{partitionOutcome.receipt.action === 'read' ? t('tools.partitionRead') : partitionOutcome.receipt.action === 'write' ? t('tools.partitionWrite') : t('tools.partitionErase')}</Badge>
                  <span>{partitionOutcome.receipt.fileName ? `${partitionOutcome.receipt.fileName} · ` : ''}{partitionOutcome.receipt.sizeBytes ? formatBytes(partitionOutcome.receipt.sizeBytes) : partitionOutcome.receipt.partition}</span>
                  {partitionOutcome.receipt.sha256 ? <code title={partitionOutcome.receipt.sha256}>{partitionOutcome.receipt.sha256}</code> : null}
                </div>
              ) : null}
              {partitions.length ? <div className="partition-results" aria-label={t('tools.partition')}>{partitions.map((entry) => <button type="button" className={partition === entry.name ? 'is-selected' : ''} onClick={() => setPartition(entry.name)} key={entry.name}><strong>{entry.name}</strong><span>{entry.partitionType || '—'}</span><span>{entry.sizeBytes === null ? '—' : `${Math.ceil(entry.sizeBytes / 1024 / 1024)} MiB`}</span></button>)}</div> : <EmptyState icon="slot" title={t('common.none')} detail={t('tools.partitionDetail')} />}
            </div>
          ) : null}
          {panel === 'push' ? (
            <div className="tool-panel-body push-files-panel">
              <div className="tool-form-grid">
                <label>
                  <span>{t('tools.destination')}</span>
                  <select
                    value={pushDestination}
                    onChange={(event) => changePushDestination(event.currentTarget.value as PushDestination)}
                    disabled={Boolean(busy) || pushPending}
                  >
                    <option value="/sdcard/Download/">/sdcard/Download/</option>
                    <option value="/data/local/tmp/">/data/local/tmp/</option>
                  </select>
                </label>
                <Button variant="primary" icon="folderPng" onClick={() => void pushFiles()} disabled={Boolean(busy) || pushPending || !adbReady}>{t('tools.chooseFiles')}</Button>
              </div>
              {pushPending ? (
                <div className="push-progress">
                  <div className="push-progress__copy" role="status" aria-live="polite">
                    <strong>{pushOutcome.status === 'cancelling' ? t('tools.pushCancelling') : t('tools.pushRunning')}</strong>
                    <span>
                      {activePush?.current && activePush.total
                        ? `${t('tools.pushFile')} ${activePush.current}/${activePush.total}${activePush.item ? ` · ${activePush.item}` : ''}`
                        : activePush?.detail || pushOutcome.message || t('tools.pushPreparing')}
                    </span>
                  </div>
                  {pushProgress !== null ? <progress aria-label={t('tools.pushProgress')} max={100} value={pushProgress} /> : null}
                  <Button variant="ghost" onClick={() => void cancelPush()} disabled={pushOutcome.status === 'cancelling'}>{t('tools.pushCancel')}</Button>
                </div>
              ) : null}
              {!pushPending && pushOutcome.status !== 'idle' ? (
                <div className={`push-outcome push-outcome--${pushOutcome.status}`}>
                  <Icon name={pushOutcome.status === 'success' ? 'check' : 'warningPng'} size={18} />
                  <span
                    role={pushOutcome.status === 'failed' || pushOutcome.status === 'unknown' ? 'alert' : 'status'}
                    aria-live={pushOutcome.status === 'failed' || pushOutcome.status === 'unknown' ? 'assertive' : 'polite'}
                  ><strong>{pushOutcome.status === 'success' ? t('tools.pushVerified') : pushOutcome.status === 'unknown' ? t('tools.pushUnknownTitle') : t('tools.results')}</strong><small>{pushOutcome.message}</small></span>
                  {pushRetry ? <Button variant="ghost" onClick={() => void retryPush()} disabled={!canRetryPush}>{t('tools.pushRetry')}</Button> : null}
                </div>
              ) : null}
              {pushOutcome.receipts.length ? (
                <ul className="push-receipts" aria-label={t('tools.pushReceipts')}>
                  {pushOutcome.receipts.map((receipt) => (
                    <li key={receipt.destination}>
                      <div><strong>{receipt.displayName}</strong><small>{receipt.destination} · {formatBytes(receipt.sizeBytes)}</small></div>
                      <code title={receipt.sha256}>{receipt.sha256}</code>
                      <Badge tone="success">{t('tools.pushVerified')}</Badge>
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
          ) : null}
          {panel === 'avb' ? (
            <div className="tool-panel-body avb-downgrade-panel">
              {!avbFirmwareReady ? (
                <div className="inline-alert inline-alert--warning">
                  <Icon name="warningPng" size={18} />
                  <span>{t('tools.avbFactoryRequired')}</span>
                </div>
              ) : null}
              <p className="tool-help">{t('tools.avbDowngradeDetail')}</p>
              <fieldset className="scrcpy-toggle-grid">
                <legend>{t('tools.avbCurrentSource')}</legend>
                <label>
                  <input
                    type="radio"
                    name="avb-source"
                    value="image"
                    checked={avbSource === 'image'}
                    onChange={() => setAvbSource('image')}
                    disabled={Boolean(busy)}
                  />
                  {t('tools.avbCurrentBoot')}
                </label>
                <label>
                  <input
                    type="radio"
                    name="avb-source"
                    value="manual"
                    checked={avbSource === 'manual'}
                    onChange={() => setAvbSource('manual')}
                    disabled={Boolean(busy)}
                  />
                  {t('tools.avbManualSpl')}
                </label>
              </fieldset>
              {avbSource === 'manual' ? (
                <div className="tool-form-grid">
                  <label>
                    <span>{t('tools.avbManualSpl')}</span>
                    <input
                      type="date"
                      value={avbSecurityPatch}
                      onChange={(event) => setAvbSecurityPatch(event.currentTarget.value)}
                      disabled={Boolean(busy)}
                    />
                  </label>
                  <p className="tool-help">{t('tools.avbManualHelp')}</p>
                </div>
              ) : (
                <label className="tool-checkbox-row">
                  <input
                    type="checkbox"
                    checked={avbPatchFingerprint}
                    onChange={(event) => setAvbPatchFingerprint(event.currentTarget.checked)}
                    disabled={Boolean(busy)}
                  />
                  <span>{t('tools.avbPatchFingerprint')}</span>
                </label>
              )}
              <Button
                variant="primary"
                icon="shield"
                onClick={() => void prepareAvbDowngrade()}
                disabled={Boolean(busy) || !avbFirmwareReady || (avbSource === 'manual' && !/^\d{4}-\d{2}-\d{2}$/.test(avbSecurityPatch))}
              >
                {avbSource === 'image' ? t('tools.avbChooseBoot') : t('tools.avbPrepare')}
              </Button>
              {typeof record(record(result?.value).artifact).sha256 === 'string' ? (
                <div className="artifact-hash">
                  <Badge tone="success">{t('tools.avbVerified')}</Badge>
                  <code>{String(record(record(result?.value).artifact).sha256)}</code>
                </div>
              ) : null}
            </div>
          ) : null}
          {panel === 'xml' ? (
            <div className="tool-panel-body binary-xml-panel">
              <div className="wifi-discovery-toolbar">
                <div>
                  <strong>{t('tools.xmlDecode')}</strong>
                  <p>{t('tools.xmlDecodeDetail')}</p>
                </div>
                <Button variant="primary" icon="processFile" onClick={() => void decodeBinaryXml()} disabled={Boolean(busy)}>
                  {t('tools.xmlChoose')}
                </Button>
              </div>
              {typeof record(result?.value).xml === 'string' ? (
                <>
                  <dl className="device-inspection-meta">
                    <div><dt>{t('tools.xmlInputDigest')}</dt><dd><code>{String(record(result?.value).sha256)}</code></dd></div>
                    <div><dt>{t('tools.xmlElements')}</dt><dd>{String(record(result?.value).elementCount)}</dd></div>
                    <div><dt>{t('tools.xmlAttributes')}</dt><dd>{String(record(result?.value).attributeCount)}</dd></div>
                  </dl>
                  <pre className="tool-log-viewer" aria-label={t('tools.xmlDecodedOutput')} tabIndex={0}>{String(record(result?.value).xml)}</pre>
                </>
              ) : <EmptyState icon="processFile" title={t('tools.xmlDecodedOutput')} detail={t('tools.xmlDecodeDetail')} />}
            </div>
          ) : null}
          {panel === 'keybox' ? (
            <div className="tool-panel-body keybox-panel">
              <div className="wifi-discovery-toolbar">
                <div>
                  <strong>{t('tools.keyboxValidate')}</strong>
                  <p>{t('tools.keyboxValidateDetail')}</p>
                </div>
                <Button variant="primary" icon="shield" onClick={() => void analyzeKeyboxes()} disabled={Boolean(busy)}>
                  {t('tools.keyboxChoose')}
                </Button>
              </div>
              {Array.isArray(record(result?.value).reports) ? (
                <>
                  {record(result?.value).revocationEvidence === null ? (
                    <div className="inline-alert inline-alert--warning" role="status">
                      <Icon name="warningPng" size={18} />
                      <span>{t('tools.keyboxRevocationUnavailable')}</span>
                    </div>
                  ) : (
                    <div className="inline-alert inline-alert--success" role="status">
                      <Icon name="check" size={18} />
                      <span>{t('tools.keyboxRevocationAuthenticated')}</span>
                    </div>
                  )}
                  <dl className="device-inspection-meta">
                    <div><dt>{t('tools.keyboxValid')}</dt><dd>{String(record(record(result?.value).summary).valid ?? 0)}</dd></div>
                    <div><dt>{t('tools.keyboxUnverified')}</dt><dd>{String(record(record(result?.value).summary).unverified ?? 0)}</dd></div>
                    <div><dt>{t('tools.keyboxRevoked')}</dt><dd>{String(record(record(result?.value).summary).revoked ?? 0)}</dd></div>
                    <div><dt>{t('tools.keyboxExpired')}</dt><dd>{String(record(record(result?.value).summary).expired ?? 0)}</dd></div>
                    <div><dt>{t('tools.keyboxSoftware')}</dt><dd>{String(record(record(result?.value).summary).softwareAttestation ?? 0)}</dd></div>
                    <div><dt>{t('tools.keyboxInvalid')}</dt><dd>{String(record(record(result?.value).summary).invalid ?? 0)}</dd></div>
                  </dl>
                  <ul className="keybox-report-list" aria-label={t('tools.keyboxReports')}>
                    {(record(result?.value).reports as unknown[]).map((entry) => {
                      const report = record(entry);
                      const status = String(report.status);
                      const tone = status === 'valid' ? 'success' : status === 'unverified' || status === 'expired' ? 'warning' : 'danger';
                      const label = status === 'valid' ? t('tools.keyboxValid') : status === 'unverified' ? t('tools.keyboxUnverified') : status === 'revoked' ? t('tools.keyboxRevoked') : status === 'expired' ? t('tools.keyboxExpired') : status === 'software_attestation' ? t('tools.keyboxSoftware') : t('tools.keyboxInvalid');
                      return <li key={`${String(report.sha256)}-${String(report.displayName)}`}><strong>{String(report.displayName)}</strong><Badge tone={tone}>{label}</Badge><code>{String(report.sha256)}</code></li>;
                    })}
                  </ul>
                </>
              ) : <EmptyState icon="shield" title={t('tools.keyboxReports')} detail={t('tools.keyboxValidateDetail')} />}
            </div>
          ) : null}
          {panel === 'mytools' ? (
            <div className="tool-panel-body my-tools-panel">
              <div className="inline-alert inline-alert--warning" role="status">
                <Icon name="shield" size={18} />
                <span>{t('tools.myToolsSafety')}</span>
              </div>
              <div className="my-tools-layout">
                <section className="my-tools-list" aria-label={t('tools.myToolsSaved')}>
                  <div className="wifi-discovery-toolbar">
                    <div><strong>{t('tools.myToolsSaved')}</strong><p>{t('tools.myToolsSavedDetail')}</p></div>
                    <Button icon="scan" onClick={() => void loadMyTools()} disabled={Boolean(busy)}>{t('common.refresh')}</Button>
                  </div>
                  {myTools.length ? <ul>
                    {myTools.map((tool) => <li key={tool.id}>
                      <button type="button" className="my-tool-summary" onClick={() => editMyTool(tool)} disabled={Boolean(busy)}>
                        <span><strong>{tool.title}</strong><small>{tool.displayName}</small></span>
                        <Badge tone={tool.enabled ? 'success' : 'neutral'}>{tool.enabled ? t('common.enabled') : t('common.disabled')}</Badge>
                      </button>
                      <div className="my-tool-actions">
                        <Button variant="ghost" onClick={() => void runMyTool(tool.id)} disabled={Boolean(busy) || !tool.enabled}>{t('tools.myToolsRun')}</Button>
                        <Button variant="danger" onClick={() => void deleteMyTool(tool.id)} disabled={Boolean(busy)}>{t('tools.myToolsDelete')}</Button>
                      </div>
                    </li>)}
                  </ul> : <EmptyState icon="wrench" title={t('common.none')} detail={t('tools.myToolsEmpty')} />}
                  {legacyMyTools.length ? <div className="legacy-tools">
                    <strong>{t('tools.myToolsLegacy')}</strong>
                    <p>{t('tools.myToolsLegacyDetail')}</p>
                    <ul>{legacyMyTools.map((tool) => <li key={tool.id}>
                      <span>
                        <strong>{tool.title}</strong>
                        {tool.commandPreview ? <code>{tool.commandPreview}</code> : null}
                        <small>{t('tools.myToolsLegacyCwd', { mode: tool.workingDirectory ?? 'default' })}</small>
                      </span>
                      <span className="button-row">
                        {tool.blockedReason && tool.blockedReason !== 'legacy_raw_permission_required'
                          ? <Badge tone="warning">{t('tools.myToolsBlocked')}</Badge>
                          : tool.permissionGranted
                            ? <>
                                <Badge tone="danger">{t('tools.myToolsLegacyAllowed')}</Badge>
                                <Button variant="danger" onClick={() => { setLegacyRawPending({ tool, action: 'run' }); setLegacyRawConfirmation(''); }} disabled={Boolean(busy) || !tool.enabled}>{t('tools.myToolsRun')}</Button>
                                <Button variant="ghost" onClick={() => void updateLegacyPermission(tool, false)} disabled={Boolean(busy)}>{t('tools.myToolsLegacyRevoke')}</Button>
                              </>
                            : <Button variant="secondary" onClick={() => { setLegacyRawPending({ tool, action: 'allow' }); setLegacyRawConfirmation(''); }} disabled={Boolean(busy) || !tool.enabled}>{t('tools.myToolsLegacyAllow')}</Button>}
                      </span>
                    </li>)}</ul>
                    {legacyRawPending ? <div className="root-footer root-footer--wrap">
                      <p className="root-manager__guard"><Icon name="warningPng" size={16} />{t('tools.myToolsLegacyWarning')}</p>
                      <code>{legacyRawPending.tool.commandPreview}</code>
                      <label><span>{t('tools.myToolsLegacyConfirm')}</span><input value={legacyRawConfirmation} onChange={(event) => setLegacyRawConfirmation(event.currentTarget.value.slice(0, 128))} placeholder={legacyRawRequired} autoComplete="off" spellCheck={false} disabled={Boolean(busy)} /></label>
                      <Button variant="danger" onClick={() => void (legacyRawPending.action === 'allow' ? updateLegacyPermission(legacyRawPending.tool, true) : runLegacyRaw())} disabled={Boolean(busy) || legacyRawConfirmation !== legacyRawRequired}>{legacyRawPending.action === 'allow' ? t('tools.myToolsLegacyAllow') : t('tools.myToolsRun')}</Button>
                      <Button variant="ghost" onClick={() => { setLegacyRawPending(null); setLegacyRawConfirmation(''); }} disabled={Boolean(busy)}>{t('common.cancel')}</Button>
                    </div> : null}
                  </div> : null}
                </section>
                <section className="my-tools-editor" aria-label={t('tools.myToolsEditor')}>
                  <div className="wifi-discovery-toolbar">
                    <div><strong>{myToolId ? t('tools.myToolsEdit') : t('tools.myToolsAdd')}</strong><p>{t('tools.myToolsArgumentsDetail')}</p></div>
                    {myToolId ? <Button variant="ghost" onClick={resetMyToolEditor}>{t('tools.myToolsNew')}</Button> : null}
                  </div>
                  <div className="tool-form-grid my-tools-form">
                    <label><span>{t('tools.myToolsTitle')}</span><input value={myToolTitle} maxLength={96} onChange={(event) => setMyToolTitle(event.currentTarget.value)} disabled={Boolean(busy)} /></label>
                    <label><span>{t('tools.myToolsExecutable')}</span><input value={myToolExecutableName} readOnly placeholder={t('tools.myToolsNoExecutable')} /></label>
                    <Button icon="folderPng" onClick={() => void chooseMyToolExecutable()} disabled={Boolean(busy)}>{t('tools.myToolsChoose')}</Button>
                    <label className="my-tools-arguments"><span>{t('tools.myToolsArguments')}</span><textarea value={myToolArguments} onChange={(event) => setMyToolArguments(event.currentTarget.value)} rows={7} disabled={Boolean(busy)} /></label>
                    <label className="tool-checkbox-row"><input type="checkbox" checked={myToolEnabled} onChange={(event) => setMyToolEnabled(event.currentTarget.checked)} disabled={Boolean(busy)} /><span>{t('common.enabled')}</span></label>
                    <Button variant="primary" icon="wrench" onClick={() => void saveMyTool()} disabled={Boolean(busy) || !myToolTitle.trim() || (!myToolId && !myToolGrant)}>{t('tools.myToolsSave')}</Button>
                  </div>
                </section>
              </div>
            </div>
          ) : null}
          {result && panel !== 'push' ? <div className={`tool-result tool-result--${toolResultStatus}`} role={toolResultFailed ? 'alert' : 'status'}><Icon name={toolResultSucceeded ? 'check' : 'warningPng'} size={18} /><span><strong>{t('tools.results')}</strong><small>{typeof result.message === 'string' ? result.message : t('status.ready')}</small></span></div> : null}
        </Card>
      ) : null}
      {secretPromptOpen ? (
        <div className="interaction-backdrop">
          <section
            ref={secretDialogRef}
            className="interaction-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="wifi-secret-title"
            aria-describedby="wifi-secret-message"
            onKeyDown={(event) => {
              if (event.key === 'Escape') {
                event.preventDefault();
                finishSecretPrompt(null);
                return;
              }
              if (event.key !== 'Tab') return;
              const controls = Array.from(secretDialogRef.current?.querySelectorAll<HTMLElement>('input:not(:disabled), button:not(:disabled)') ?? []);
              if (!controls.length) return;
              const currentIndex = controls.indexOf(document.activeElement as HTMLElement);
              const nextIndex = event.shiftKey
                ? (currentIndex <= 0 ? controls.length - 1 : currentIndex - 1)
                : (currentIndex >= controls.length - 1 ? 0 : currentIndex + 1);
              event.preventDefault();
              controls[nextIndex].focus();
            }}
          >
            <span className="interaction-dialog__icon"><Icon name="adb" size={26} /></span>
            <div className="interaction-dialog__copy">
              <h2 id="wifi-secret-title">{t('tools.pairingCode')}</h2>
              <p id="wifi-secret-message">{t('tools.wifiDetail')}</p>
              <label className="reinforced-confirmation-field">
                <span>{t('tools.pairingCode')}</span>
                <input
                  ref={secretInputRef}
                  type="password"
                  value={secretValue}
                  onChange={(event) => setSecretValue(event.currentTarget.value.replace(/\D/g, '').slice(0, 6))}
                  inputMode="numeric"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  autoComplete="one-time-code"
                />
              </label>
            </div>
            <div className="interaction-dialog__actions">
              <button type="button" className="button button--ghost" onClick={() => finishSecretPrompt(null)}>{t('common.cancel')}</button>
              <button type="button" className="button button--primary" onClick={() => finishSecretPrompt(secretValue)} disabled={!/^\d{6}$/.test(secretValue)}>{t('common.continue')}</button>
            </div>
          </section>
        </div>
      ) : null}
    </>
  );
}
