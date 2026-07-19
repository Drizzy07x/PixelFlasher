import { useEffect, useRef, useState } from 'react';
import type { AssetName } from '../../assets';
import { commands, type BridgeCommand } from '../../commands';
import { useI18n } from '../../i18n';
import { Badge, Button, Card, CardTitle, EmptyState, Icon, PageHeader } from '../../components/ui';
import { isToolchainReady, record, selectedGrant, selectedGrants, type CommandRunOptions, type SharedPageProps } from '../shared';

type ToolPanel = 'wifi' | 'logcat' | 'partitions' | 'push' | null;
type PartitionRow = { name: string; sizeBytes: number | null; partitionType: string };
type WifiService = {
  id: string;
  instance: string;
  serviceType: 'pairing' | 'connect' | 'legacy';
  host: string;
  port: number;
  endpoint: string;
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

export function ToolsPage({ snapshot, selectedSerials, onCommand, expertMode }: SharedPageProps & { expertMode: boolean }) {
  const { t } = useI18n();
  const primary = selectedSerials.length === 1
    ? snapshot.devices.find((device) => device.serial === selectedSerials[0])
    : undefined;
  const adbReady = primary?.mode === 'adb' && isToolchainReady(snapshot);
  const fastbootReady = primary?.mode === 'fastboot' && isToolchainReady(snapshot);
  const toolchainReady = isToolchainReady(snapshot);
  const [panel, setPanel] = useState<ToolPanel>(null);
  const [busy, setBusy] = useState('');
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [logLines, setLogLines] = useState<string[]>([]);
  const [maxLines, setMaxLines] = useState(500);
  const [partitions, setPartitions] = useState<PartitionRow[]>([]);
  const [partition, setPartition] = useState('');
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
  const [pushDestination, setPushDestination] = useState<'/data/local/tmp/' | '/sdcard/Download/'>('/sdcard/Download/');

  useEffect(() => {
    if (!secretPromptOpen) return;
    window.requestAnimationFrame(() => secretInputRef.current?.focus());
  }, [secretPromptOpen]);

  useEffect(() => () => {
    secretResolverRef.current?.(null);
    secretResolverRef.current = null;
  }, []);

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

  const collectLogcat = async () => {
    if (!primary || !adbReady) return;
    const response = await runTool(commands.toolsLogcat, {
      serial: primary.serial,
      buffers: ['main'],
      format: 'threadtime',
      maxLines,
      timeoutSeconds: 30,
    });
    const value = record(record(response?.result).value);
    setLogLines(Array.isArray(value.lines) ? value.lines.filter((line): line is string => typeof line === 'string') : []);
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
      await runTool(commands.toolsPushFiles, { serial: primary.serial, grants, destination: pushDestination });
    } finally {
      setBusy('');
    }
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
  type ToolCard = { id: string; icon: AssetName; title: string; detail: string; disabled: boolean; run: () => void };
  const cards: ToolCard[] = [
    {
      id: 'recovery', icon: 'reboot', title: t('tools.recovery'), detail: t('tools.recoveryDetail'),
      disabled: !primary || !isToolchainReady(snapshot), run: () => { if (primary) void runTool(commands.deviceReboot, { serial: primary.serial, mode: 'recovery' }); },
    },
    {
      id: 'scrcpy', icon: 'devices', title: t('tools.scrcpy'), detail: t('tools.scrcpyDetail'),
      disabled: !adbReady, run: () => { if (primary) void runTool(commands.toolsScrcpy, { serial: primary.serial }); },
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
          <CardTitle icon={panel === 'logcat' ? 'logs' : panel === 'partitions' ? 'slot' : panel === 'push' ? 'folder' : 'adb'} after={<Button variant="ghost" onClick={() => setPanel(null)}>{t('common.close')}</Button>}>
            {panel === 'logcat' ? t('tools.logs') : panel === 'partitions' ? t('tools.partition') : panel === 'push' ? t('tools.push') : t('tools.wifi')}
          </CardTitle>
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
            <div className="tool-panel-body">
              <div className="tool-form-grid tool-form-grid--compact"><label><span>{t('tools.maxLines')}</span><input type="number" min="1" max="10000" value={maxLines} onChange={(event) => setMaxLines(Math.max(1, Math.min(10000, Number(event.currentTarget.value))))} /></label><Button variant="primary" icon="logs" onClick={() => void collectLogcat()} disabled={Boolean(busy) || !adbReady}>{t('tools.collectLogs')}</Button></div>
              {logLines.length ? <pre className="tool-log-viewer" aria-label={t('tools.logs')}>{logLines.join('\n')}</pre> : <EmptyState icon="logs" title={t('common.none')} detail={t('tools.logcatDetail')} />}
            </div>
          ) : null}
          {panel === 'partitions' ? (
            <div className="tool-panel-body">
              <div className="tool-form-grid tool-form-grid--partition"><label><span>{t('tools.selectPartition')}</span><select value={partition} onChange={(event) => setPartition(event.currentTarget.value)} disabled={!partitions.length || Boolean(busy)}><option value="">—</option>{partitions.map((entry) => <option value={entry.name} key={entry.name}>{entry.name}</option>)}</select></label><Button icon="scan" onClick={() => void listPartitions()} disabled={Boolean(busy) || !fastbootReady}>{t('common.refresh')}</Button><Button icon="download" onClick={() => void readPartition()} disabled={Boolean(busy) || !partition}>{t('tools.partitionRead')}</Button><Button variant="primary" icon="flash" onClick={() => void writePartition()} disabled={Boolean(busy) || !partition}>{t('tools.partitionWrite')}</Button><Button variant="danger" icon="warningPng" onClick={() => primary && void runTool(commands.partitionsErase, { serial: primary.serial, partition })} disabled={Boolean(busy) || !partition}>{t('tools.partitionErase')}</Button></div>
              {partitions.length ? <div className="partition-results" role="table" aria-label={t('tools.partition')}>{partitions.map((entry) => <button type="button" role="row" className={partition === entry.name ? 'is-selected' : ''} onClick={() => setPartition(entry.name)} key={entry.name}><strong role="cell">{entry.name}</strong><span role="cell">{entry.partitionType || '—'}</span><span role="cell">{entry.sizeBytes === null ? '—' : `${Math.ceil(entry.sizeBytes / 1024 / 1024)} MiB`}</span></button>)}</div> : <EmptyState icon="slot" title={t('common.none')} detail={t('tools.partitionDetail')} />}
            </div>
          ) : null}
          {panel === 'push' ? (
            <div className="tool-form-grid"><label><span>{t('tools.destination')}</span><select value={pushDestination} onChange={(event) => setPushDestination(event.currentTarget.value as typeof pushDestination)}><option value="/sdcard/Download/">/sdcard/Download/</option><option value="/data/local/tmp/">/data/local/tmp/</option></select></label><Button variant="primary" icon="folderPng" onClick={() => void pushFiles()} disabled={Boolean(busy) || !adbReady}>{t('tools.chooseFiles')}</Button></div>
          ) : null}
          {result ? <div className="tool-result" role="status"><Icon name="check" size={18} /><span><strong>{t('tools.results')}</strong><small>{typeof result.message === 'string' ? result.message : t('status.ready')}</small></span></div> : null}
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
