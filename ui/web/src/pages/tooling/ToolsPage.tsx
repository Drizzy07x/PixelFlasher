import { useEffect, useRef, useState, type Dispatch, type SetStateAction } from 'react';
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

type ToolPanel = 'scrcpy' | 'wifi' | 'logcat' | 'partitions' | 'push' | null;
type PartitionRow = { name: string; sizeBytes: number | null; partitionType: string };
type WifiService = {
  id: string;
  instance: string;
  serviceType: 'pairing' | 'connect' | 'legacy';
  host: string;
  port: number;
  endpoint: string;
};
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
  const fastbootReady = primary?.mode === 'fastboot' && isToolchainReady(snapshot);
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
  const [scrcpyMaxSize, setScrcpyMaxSize] = useState(1920);
  const [scrcpyMaxFps, setScrcpyMaxFps] = useState(60);
  const [scrcpyVideoBitRate, setScrcpyVideoBitRate] = useState(12);
  const [scrcpyFullscreen, setScrcpyFullscreen] = useState(false);
  const [scrcpyAlwaysOnTop, setScrcpyAlwaysOnTop] = useState(false);
  const [scrcpyStayAwake, setScrcpyStayAwake] = useState(true);
  const [scrcpyTurnScreenOff, setScrcpyTurnScreenOff] = useState(false);
  const [scrcpyShowTouches, setScrcpyShowTouches] = useState(false);
  const [scrcpyNoAudio, setScrcpyNoAudio] = useState(false);
  const [wifiAction, setWifiAction] = useState<'pair' | 'connect' | 'disconnect' | 'status'>('status');
  const [wifiHost, setWifiHost] = useState('192.168.1.42');
  const [wifiPort, setWifiPort] = useState(5555);
  const [wifiServices, setWifiServices] = useState<WifiService[]>([]);
  const [wifiDiscoveryRan, setWifiDiscoveryRan] = useState(false);
  const [selectedWifiServiceId, setSelectedWifiServiceId] = useState('');
  const [secretPromptOpen, setSecretPromptOpen] = useState(false);
  const [secretValue, setSecretValue] = useState('');
  const secretResolverRef = useRef<((value: string | null) => void) | null>(null);
  const secretDialogRef = useRef<HTMLElement>(null);
  const secretInputRef = useRef<HTMLInputElement>(null);
  const [localPushUiState, setLocalPushUiState] = useState<PushUiState>(initialPushUiState);
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
      await runTool(commands.partitionsRead, { serial: primary.serial, partition, grant, overwrite: true });
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
      await runTool(commands.partitionsWrite, { serial: primary.serial, partition, grant });
    } finally {
      setBusy('');
    }
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
      { id: 'shell', icon: 'shell', title: t('tools.shell'), detail: t('tools.shellBlocked'), disabled: true, run: () => {} },
      { id: 'logcat', icon: 'logs', title: t('tools.logs'), detail: t('tools.logcatDetail'), disabled: !adbReady, run: () => openPanel('logcat') },
      { id: 'partition', icon: 'slot', title: t('tools.partition'), detail: t('tools.partitionDetail'), disabled: !fastbootReady, run: () => openPanel('partitions') },
      { id: 'bootloader', icon: 'bootloader', title: t('tools.bootloader'), detail: t('tools.bootloaderDetail'), disabled: !primary || !isToolchainReady(snapshot), run: () => { if (primary) void runTool(commands.deviceReboot, { serial: primary.serial, mode: 'bootloader' }); } },
      { id: 'integrity', icon: 'shield', title: t('tools.integrity'), detail: t('tools.integrityBlocked'), disabled: true, run: () => {} },
    ] satisfies ToolCard[] : []),
  ];
  const pushProgress = typeof activePush?.progress === 'number' && Number.isFinite(activePush.progress)
    ? Math.max(0, Math.min(100, activePush.progress))
    : null;
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
          <CardTitle icon={panel === 'scrcpy' ? 'devices' : panel === 'logcat' ? 'logs' : panel === 'partitions' ? 'slot' : panel === 'push' ? 'folder' : 'adb'} after={<Button variant="ghost" onClick={() => setPanel(null)}>{t('common.close')}</Button>}>
            {panel === 'scrcpy' ? t('tools.scrcpy') : panel === 'logcat' ? t('tools.logs') : panel === 'partitions' ? t('tools.partition') : panel === 'push' ? t('tools.push') : t('tools.wifi')}
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
              <div className="tool-form-grid tool-form-grid--partition"><label><span>{t('tools.selectPartition')}</span><select value={partition} onChange={(event) => setPartition(event.currentTarget.value)} disabled={!partitions.length || Boolean(busy)}><option value="">—</option>{partitions.map((entry) => <option value={entry.name} key={entry.name}>{entry.name}</option>)}</select></label><Button icon="scan" onClick={() => void listPartitions()} disabled={Boolean(busy) || !fastbootReady}>{t('common.refresh')}</Button><Button icon="download" onClick={() => void readPartition()} disabled={Boolean(busy) || !partition}>{t('tools.partitionRead')}</Button><Button variant="primary" icon="flash" onClick={() => void writePartition()} disabled={Boolean(busy) || !partition}>{t('tools.partitionWrite')}</Button><Button variant="danger" icon="warningPng" onClick={() => primary && void runTool(commands.partitionsErase, { serial: primary.serial, partition })} disabled={Boolean(busy) || !partition}>{t('tools.partitionErase')}</Button></div>
              {partitions.length ? <div className="partition-results" role="table" aria-label={t('tools.partition')}>{partitions.map((entry) => <button type="button" role="row" className={partition === entry.name ? 'is-selected' : ''} onClick={() => setPartition(entry.name)} key={entry.name}><strong role="cell">{entry.name}</strong><span role="cell">{entry.partitionType || '—'}</span><span role="cell">{entry.sizeBytes === null ? '—' : `${Math.ceil(entry.sizeBytes / 1024 / 1024)} MiB`}</span></button>)}</div> : <EmptyState icon="slot" title={t('common.none')} detail={t('tools.partitionDetail')} />}
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
          {result && panel !== 'push' ? <div className="tool-result" role="status"><Icon name="check" size={18} /><span><strong>{t('tools.results')}</strong><small>{typeof result.message === 'string' ? result.message : t('status.ready')}</small></span></div> : null}
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
