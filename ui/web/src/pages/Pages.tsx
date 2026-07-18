import { useMemo, useState } from 'react';
import { assets, type AssetName } from '../assets';
import { commands, type BridgeCommand } from '../commands';
import { demoApps, demoBackups, demoFirmwares } from '../demoData';
import { localeOptions, useI18n } from '../i18n';
import type { BootArtifact, Device, Firmware, HostSnapshot, Locale, Theme } from '../types';
import { DeviceSelector } from '../components/DeviceSelector';
import { Badge, Button, Card, CardTitle, EmptyState, Icon, Meter, PageHeader, Toggle } from '../components/ui';

interface SharedPageProps {
  snapshot: HostSnapshot;
  selectedSerials: string[];
  onSelectionChange: (serials: string[]) => void | Promise<void>;
  onCommand: (command: BridgeCommand, payload?: Record<string, unknown>) => Promise<{
    result: Record<string, unknown>;
    revision?: number;
  } | null>;
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? value as Record<string, unknown> : {};
}

interface RootAppEntry {
  id: string;
  provider: string;
  flavor: string;
  version: string;
  sha256: string;
  provenance: string;
}

interface RootModuleEntry {
  id: string;
}

function selectedPath(response: Awaited<ReturnType<SharedPageProps['onCommand']>>) {
  if (!response) return '';
  const result = record(response.result);
  const value = record(result.value);
  const data = record(result.data ?? value.data);
  return typeof data.path === 'string' ? data.path : '';
}

function selectedPaths(response: Awaited<ReturnType<SharedPageProps['onCommand']>>) {
  if (!response) return [];
  const result = record(response.result);
  const value = record(result.value);
  const data = record(result.data ?? value.data);
  return Array.isArray(data.paths)
    ? data.paths.filter((path): path is string => typeof path === 'string' && Boolean(path))
    : [];
}

function providerKey(provider: string) {
  const normalized = provider.trim().toLowerCase().replaceAll(' ', '-');
  if (normalized === 'wild-ksu') return 'wild_ksu';
  if (normalized === 'kernelsu-legacy') return 'kernelsu';
  return normalized;
}

function patchProvider(method: string) {
  const providers: Record<string, string> = {
    magisk: 'magisk',
    apatch: 'apatch',
    kernelsu: 'kernelsu',
    'kernelsu-next': 'kernelsu-next',
    sukisu: 'sukisu',
    'wild-ksu': 'wild_ksu',
    legacy: 'kernelsu',
  };
  return providers[method] ?? '';
}

function methodForProvider(provider: string) {
  const providerName = provider.trim().toLowerCase().replaceAll(' ', '-');
  if (providerName === 'kernelsu-legacy') return 'legacy';
  const normalized = providerKey(provider);
  if (normalized === 'wild_ksu') return 'wild-ksu';
  return ['magisk', 'apatch', 'kernelsu', 'kernelsu-next', 'sukisu'].includes(normalized)
    ? normalized
    : '';
}

function isToolchainReady(snapshot: HostSnapshot) {
  return snapshot.toolchain?.ready ?? Boolean(snapshot.toolchain?.adb && snapshot.toolchain?.fastboot);
}

export function DashboardPage({ snapshot, selectedSerials, onCommand }: SharedPageProps) {
  const { t } = useI18n();
  const primary = snapshot.devices.find((device) => selectedSerials.includes(device.serial)) ?? snapshot.devices[0];
  const firmware = snapshot.firmware ?? (window.pixelflasher?.__mock ? demoFirmwares[0] : null);
  const toolchainReady = isToolchainReady(snapshot);

  const setupPlatformTools = async () => {
    const picked = await onCommand(commands.nativePickDirectory, { title: t('dashboard.toolsSetup') });
    if (!picked) return;
    const result = record(picked.result);
    const nested = record(result.value);
    const data = record(result.data ?? nested.data);
    if (typeof data.path === 'string' && data.path) {
      await onCommand(commands.platformToolsSetup, { path: data.path });
    }
  };

  const quickActions = [
    { icon: 'scan', title: t('dashboard.scan'), detail: t('dashboard.scanDetail'), command: commands.deviceScan, payload: {}, disabled: !toolchainReady },
    { icon: 'rebootPng', title: t('dashboard.reboot'), detail: t('dashboard.rebootDetail'), command: commands.deviceReboot, payload: { serial: primary?.serial, mode: 'system' }, disabled: !primary },
    { icon: 'switchSlot', title: t('dashboard.slot'), detail: t('dashboard.slotDetail'), command: commands.deviceSwitchSlot, payload: { serial: primary?.serial, slot: primary?.slot === 'a' ? 'b' : 'a' }, disabled: !primary || primary.mode !== 'fastboot' || primary.slot === 'unknown' },
  ] as const;

  return (
    <>
      <PageHeader title={t('dashboard.title')} subtitle={t('dashboard.subtitle')} />

      <div className={`platform-banner ${toolchainReady ? '' : 'platform-banner--warning'}`} role={toolchainReady ? 'status' : 'alert'}>
        <span className="platform-banner__icon"><Icon name={toolchainReady ? 'check' : 'warningPng'} size={19} /></span>
        <span><strong>{t(toolchainReady ? 'dashboard.toolsReady' : 'dashboard.toolsNeeded')}</strong><small>{t(toolchainReady ? 'dashboard.toolsDetail' : 'dashboard.toolsNeededDetail')}</small></span>
        {toolchainReady ? (
          <Badge tone="accent">ADB {snapshot.toolchain?.version ?? ''}</Badge>
        ) : (
          <Button icon="tools" onClick={() => void setupPlatformTools()}>{t('dashboard.toolsSetup')}</Button>
        )}
      </div>

      <div className="dashboard-grid">
        <Card className="device-hero">
          <CardTitle icon="devices" after={<Badge tone={primary?.mode.startsWith('fastboot') ? 'warning' : 'success'}>{primary?.mode.toUpperCase() ?? 'OFFLINE'}</Badge>}>
            {t('dashboard.connected')}
          </CardTitle>
          {primary ? (
            <div className="device-hero__content">
              <img className="device-hero__render" src={assets.phoneRender} alt="" aria-hidden="true" />
              <div className="device-hero__details">
                <span className="eyebrow">{primary.model}</span>
                <h2>{primary.name}</h2>
                <code>{primary.serial}</code>
                <dl className="spec-grid">
                  <div><dt>Android</dt><dd>{primary.androidVersion}</dd></div>
                  <div><dt>{t('common.build')}</dt><dd>{primary.build}</dd></div>
                  <div><dt>{t('flash.review.slot')}</dt><dd>{primary.slot.toUpperCase()}</dd></div>
                  <div><dt>{t('device.bootloader')}</dt><dd>{primary.bootloader}</dd></div>
                </dl>
                <Meter value={primary.battery} label={t('device.battery')} />
              </div>
            </div>
          ) : null}
        </Card>

        <Card className="quick-card">
          <CardTitle icon="flash">{t('dashboard.quick')}</CardTitle>
          <div className="quick-list">
            {quickActions.map((action) => (
              <button type="button" className="quick-action" key={action.command} onClick={() => void onCommand(action.command, action.payload)} disabled={action.disabled}>
                <span className="quick-action__icon"><Icon name={action.icon} size={22} /></span>
                <span><strong>{action.title}</strong><small>{action.detail}</small></span>
                <Icon name="right" size={17} />
              </button>
            ))}
          </div>
        </Card>
      </div>

      <div className="summary-grid">
        <Card className="summary-card">
          <span className="summary-card__icon"><Icon name="firmware" size={23} /></span>
          <span><small>{t('dashboard.firmware')}</small><strong>{firmware?.build ?? '—'}</strong><em>{firmware?.name ?? t('common.none')}</em></span>
        </Card>
        <Card className="summary-card">
          <span className="summary-card__icon"><Icon name="shield" size={23} /></span>
          <span><small>{t('dashboard.security')}</small><strong>{primary?.securityPatch ?? '—'}</strong><em>{primary ? `Verified Boot ${primary.bootloader === 'unlocked' ? 'unlocked' : primary.bootloader === 'locked' ? 'active' : 'unknown'}` : t('common.none')}</em></span>
        </Card>
        <Card className="summary-card">
          <span className="summary-card__icon"><Icon name="adb" size={23} /></span>
          <span><small>{t('dashboard.deviceMode')}</small><strong>{primary?.mode.toUpperCase() ?? 'OFFLINE'}</strong><em>{primary?.connection ?? 'No connection'}</em></span>
        </Card>
      </div>
    </>
  );
}

export function DevicePage({ snapshot, selectedSerials, onSelectionChange, onCommand, expertMode }: SharedPageProps & { expertMode: boolean }) {
  const { t } = useI18n();
  const primary = snapshot.devices.find((device) => selectedSerials.includes(device.serial)) ?? snapshot.devices[0];
  const operationTarget = selectedSerials.length === 1
    ? snapshot.devices.find((device) => device.serial === selectedSerials[0])
    : undefined;

  return (
    <>
      <PageHeader
        title={t('device.title')}
        subtitle={t('device.subtitle')}
        actions={<Button icon="scan" onClick={() => void onCommand(commands.deviceScan)} disabled={!isToolchainReady(snapshot)}>{t('common.refresh')}</Button>}
      />
      <div className="two-column-layout two-column-layout--wide-left">
        <Card>
          <CardTitle icon="devices" after={<Badge tone="accent">{t('device.multi', { count: selectedSerials.length })}</Badge>}>
            {t('device.choose')}
          </CardTitle>
          <DeviceSelector devices={snapshot.devices} selected={selectedSerials} onChange={onSelectionChange} ariaLabel={t('device.choose')} />
        </Card>
        <Card className="device-inspector">
          <CardTitle icon="adb">{t('device.details')}</CardTitle>
          {primary ? <DeviceDetails device={primary} /> : null}
        </Card>
        <DeviceOperations
          device={operationTarget}
          boot={snapshot.boot ?? null}
          lockEvidence={snapshot.bootloaderLockEvidence?.find((evidence) => (
            evidence.serial === operationTarget?.serial
            && evidence.snapshot_revision === snapshot.revision
          ))}
          toolchainReady={isToolchainReady(snapshot)}
          expertMode={expertMode}
          onCommand={onCommand}
        />
      </div>
    </>
  );
}

function DeviceDetails({ device }: { device: Device }) {
  const { t } = useI18n();
  return (
    <div className="device-details">
      <div className="device-details__heading">
        <span className="device-details__glyph"><Icon name="devices" size={34} /></span>
        <span><strong>{device.name}</strong><code>{device.serial}</code></span>
        <Badge tone={device.mode.startsWith('fastboot') ? 'warning' : 'success'}>{device.mode.toUpperCase()}</Badge>
      </div>
      <dl className="detail-list">
        <div><dt>{t('device.model')}</dt><dd>{device.model}</dd></div>
        <div><dt>{t('device.codename')}</dt><dd>{device.codename}</dd></div>
        <div><dt>Android / {t('common.build')}</dt><dd>{device.androidVersion} · {device.build}</dd></div>
        <div><dt>{t('device.connection')}</dt><dd>{device.connection}</dd></div>
        <div><dt>{t('device.bootloader')}</dt><dd><Badge tone={device.bootloader === 'unlocked' ? 'warning' : 'success'}>{device.bootloader}</Badge></dd></div>
        <div><dt>{t('device.root')}</dt><dd>{device.rooted ? t('device.rooted') : t('device.stock')}</dd></div>
      </dl>
      <Meter value={device.battery} label={t('device.battery')} />
    </div>
  );
}

function DeviceOperations({
  device,
  boot,
  lockEvidence,
  toolchainReady,
  expertMode,
  onCommand,
}: {
  device?: Device;
  boot: BootArtifact | null;
  lockEvidence?: NonNullable<HostSnapshot['bootloaderLockEvidence']>[number];
  toolchainReady: boolean;
  expertMode: boolean;
  onCommand: SharedPageProps['onCommand'];
}) {
  const { t } = useI18n();
  const [rebootMode, setRebootMode] = useState<'system' | 'recovery' | 'bootloader' | 'fastbootd'>('system');
  const suggestedPartition = boot?.flavor && ['boot', 'init_boot', 'vendor_boot', 'vendor_kernel_boot', 'recovery'].includes(boot.flavor)
    ? boot.flavor
    : 'boot';
  const [slot, setSlot] = useState<'' | 'a' | 'b'>('');
  const [busy, setBusy] = useState<BridgeCommand | ''>('');

  const online = Boolean(device && !['offline', 'unauthorized'].includes(device.mode));
  const fastboot = online && device?.mode === 'fastboot';
  const unlockedFastboot = fastboot && device?.bootloader === 'unlocked';
  const bootReady = Boolean(boot?.path && boot?.hash && /^[0-9a-f]{64}$/i.test(boot.hash));
  const nextSlot = device?.slot === 'a' ? 'b' : device?.slot === 'b' ? 'a' : null;
  const lockEvidenceCurrent = Boolean(
    lockEvidence
    && lockEvidence.snapshot_revision >= 0
    && lockEvidence.serial === device?.serial,
  );
  const lockBlockedMessage = t('device.lockRequiresStockEvidence');
  const lockBlockedId = device ? `lock-blocked-${device.serial.replace(/[^A-Za-z0-9_-]/g, '-')}` : undefined;
  const bootName = boot?.path?.split(/[\\/]/).pop() ?? boot?.image ?? '';

  const execute = async (command: BridgeCommand, payload: Record<string, unknown>) => {
    if (!device || busy) return;
    setBusy(command);
    try {
      await onCommand(command, payload);
    } finally {
      setBusy('');
    }
  };

  return (
    <Card className="device-operations-card" aria-busy={Boolean(busy)}>
      <CardTitle icon="tools" after={device ? <Badge tone={device.mode.startsWith('fastboot') ? 'warning' : 'success'}>{device.serial}</Badge> : null}>
        {t('device.actions')}
      </CardTitle>
      {!device ? (
        <div className="inline-alert inline-alert--warning device-operations-guard" role="status">
          <Icon name="warningPng" size={18} />
          <span>{t('device.singleActionGuard')}</span>
        </div>
      ) : null}
      <div className="device-operation-grid">
        <section className="device-operation-group">
          <span className="device-operation-group__icon"><Icon name="rebootPng" size={23} /></span>
          <div className="device-operation-group__copy">
            <strong>{t('dashboard.reboot')}</strong>
            <label className="select-field select-field--compact">
              <span>{t('device.rebootTarget')}</span>
              <select value={rebootMode} onChange={(event) => setRebootMode(event.currentTarget.value as typeof rebootMode)} disabled={!device || Boolean(busy)}>
                <option value="system">{t('device.rebootSystem')}</option>
                <option value="recovery">{t('device.rebootRecovery')}</option>
                <option value="bootloader">{t('device.rebootBootloader')}</option>
                <option value="fastbootd">{t('device.rebootFastbootd')}</option>
              </select>
            </label>
            <Button icon="rebootPng" onClick={() => void execute(commands.deviceReboot, { serial: device?.serial, mode: rebootMode })} disabled={!device || !online || !toolchainReady || Boolean(busy)}>
              {t('device.rebootNow')}
            </Button>
          </div>
        </section>

        <section className="device-operation-group">
          <span className="device-operation-group__icon"><Icon name="slot" size={23} /></span>
          <div className="device-operation-group__copy">
            <strong>{t('device.slotBootloader')}</strong>
            <span className="device-operation-meta">
              <Badge tone="accent">{t('flash.review.slot')} {device?.slot?.toUpperCase() ?? '—'}</Badge>
              <Badge tone={device?.bootloader === 'unlocked' ? 'warning' : 'success'}>{device?.bootloader ?? '—'}</Badge>
            </span>
            <div className="button-row button-row--wrap">
              <Button icon="switchSlot" onClick={() => nextSlot && void execute(commands.deviceSwitchSlot, { serial: device?.serial, slot: nextSlot })} disabled={!device || !fastboot || !nextSlot || !toolchainReady || Boolean(busy)}>
                {t('device.switchToSlot', { slot: nextSlot?.toUpperCase() ?? '—' })}
              </Button>
              {expertMode && device?.bootloader === 'unlocked' ? (
                <Button variant="danger" icon="lock" onClick={() => void execute(commands.deviceBootloaderLock, { serial: device.serial })} disabled={!fastboot || !toolchainReady || !lockEvidenceCurrent || Boolean(busy)} aria-describedby={!lockEvidenceCurrent ? lockBlockedId : undefined}>
                  {t('device.lockBootloader')}
                </Button>
              ) : expertMode && device?.bootloader === 'locked' ? (
                <Button variant="danger" icon="unlock" onClick={() => void execute(commands.deviceBootloaderUnlock, { serial: device.serial })} disabled={!fastboot || !toolchainReady || Boolean(busy)}>
                  {t('device.unlockBootloader')}
                </Button>
              ) : null}
            </div>
            {expertMode && device?.bootloader === 'unlocked' && !lockEvidenceCurrent ? (
              <small id={lockBlockedId} className="device-operation-warning" role="status">{lockBlockedMessage}</small>
            ) : null}
          </div>
        </section>

        <section className="device-operation-group">
          <span className="device-operation-group__icon"><Icon name="boot" size={23} /></span>
          <div className="device-operation-group__copy">
            <strong>{t('device.bootImage')}</strong>
            {bootReady ? (
              <span className="device-operation-boot"><code>{bootName}</code><small>{boot?.patched ? t('root.patch') : boot?.flavor ?? 'boot'}</small></span>
            ) : (
              <small className="device-operation-warning">{t('device.noBootImage')}</small>
            )}
            <div className="device-operation-fields">
              <label>
                <span>{t('device.partition')}</span>
                <output>{suggestedPartition}</output>
              </label>
              <label>
                <span>{t('flash.review.slot')}</span>
                <select value={slot} onChange={(event) => setSlot(event.currentTarget.value as typeof slot)} disabled={!bootReady || Boolean(busy)}>
                  <option value="">{t('device.defaultSlot')}</option>
                  <option value="a">A</option>
                  <option value="b">B</option>
                </select>
              </label>
            </div>
            <div className="button-row button-row--wrap">
              <Button icon="boot" onClick={() => void execute(commands.bootLive, { serial: device?.serial })} disabled={!device || !unlockedFastboot || !bootReady || suggestedPartition !== 'boot' || !toolchainReady || Boolean(busy)}>
                {t('device.liveBoot')}
              </Button>
              <Button variant="primary" icon="flash" onClick={() => void execute(commands.bootFlash, { serial: device?.serial, partition: suggestedPartition, ...(slot ? { slot } : {}) })} disabled={!device || !unlockedFastboot || !bootReady || !toolchainReady || Boolean(busy)}>
                {t('device.flashBoot')}
              </Button>
            </div>
          </div>
        </section>
      </div>
    </Card>
  );
}

export function FirmwarePage({ snapshot, onCommand }: SharedPageProps) {
  const { t } = useI18n();
  const [busy, setBusy] = useState(false);
  const active = snapshot.firmware?.id ?? null;
  const available = window.pixelflasher?.__mock
    ? demoFirmwares.map((entry) => entry.id === active && snapshot.firmware
      ? { ...entry, ...snapshot.firmware }
      : entry)
    : snapshot.firmware ? [snapshot.firmware] : [];

  const pickFirmware = async () => {
    if (busy) return;
    setBusy(true);
    try {
      const picked = await onCommand(commands.nativePickFile, {
        title: t('firmware.import'),
        filters: [{ label: t('firmware.title'), extensions: ['zip', 'tgz', 'tar'] }],
      });
      if (!picked) return;
      const result = record(picked.result);
      const nested = record(result.value);
      const data = record(result.data ?? nested.data);
      if (typeof data.path === 'string' && data.path) {
        await onCommand(commands.firmwareSelect, { path: data.path });
      }
    } finally {
      setBusy(false);
    }
  };

  const processFirmware = async () => {
    if (!snapshot.firmware || snapshot.firmware.processed || busy) return;
    setBusy(true);
    try {
      await onCommand(commands.firmwareProcess);
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <PageHeader title={t('firmware.title')} subtitle={t('firmware.subtitle')} actions={<Button variant="primary" icon="folderPng" onClick={() => void pickFirmware()} disabled={busy}>{t('firmware.import')}</Button>} />
      <Card aria-busy={busy}>
        <CardTitle icon="firmware" after={<Badge tone="accent">{available.length}</Badge>}>{t('firmware.available')}</CardTitle>
        <div className="firmware-table" role="list">
          {available.map((entry) => {
            const isActive = entry.id === active;
            return (
              <div className={`firmware-row ${isActive ? 'is-active' : ''}`} role="listitem" key={entry.id}>
                <span className="firmware-row__icon"><Icon name={entry.kind === 'ota' ? 'download' : 'firmware'} size={25} /></span>
                <span className="firmware-row__name"><strong>{entry.name}</strong><small>{entry.device} · {entry.kind.toUpperCase()}</small></span>
                <span><small>{t('common.build')}</small><strong>{entry.build}</strong></span>
                <span><small>{t('dashboard.security')}</small><strong>{entry.securityPatch}</strong></span>
                <span><small>{t('common.size')}</small><strong>{entry.size}</strong></span>
                <Badge tone={entry.channel === 'stable' ? 'success' : 'warning'}>{entry.channel}</Badge>
                {isActive && entry.processed ? (
                  <Badge tone="success">{t('status.ready')}</Badge>
                ) : (
                  <Button
                    variant={isActive ? 'primary' : 'secondary'}
                    icon={isActive ? 'firmware' : 'right'}
                    onClick={() => isActive ? void processFirmware() : entry.path && void onCommand(commands.firmwareSelect, { path: entry.path })}
                    disabled={busy || !entry.path}
                  >
                    {isActive ? t('firmware.process') : t('firmware.use')}
                  </Button>
                )}
              </div>
            );
          })}
          {!available.length ? <EmptyState icon="firmware" title={t('common.none')} detail={t('firmware.import')} /> : null}
        </div>
      </Card>
    </>
  );
}

export function RootPage({ snapshot, selectedSerials, onCommand }: SharedPageProps) {
  const { t } = useI18n();
  type RootMethod = { id: string; name: string; version: string; icon: 'magisk' | 'kernelSu' | 'apatch' | 'sukiSu' | 'wildKsu'; detail: string };
  const methodCatalog: RootMethod[] = [
    { id: 'magisk', name: 'Magisk', version: '28.1', icon: 'magisk', detail: t('root.magiskDetail') },
    { id: 'kernelsu', name: 'KernelSU', version: '1.0.2', icon: 'kernelSu', detail: t('root.kernelSuDetail') },
    { id: 'kernelsu-next', name: 'KernelSU Next', version: '—', icon: 'kernelSu', detail: t('root.kernelSuDetail') },
    { id: 'apatch', name: 'APatch', version: '11039', icon: 'apatch', detail: t('root.apatchDetail') },
    { id: 'sukisu', name: 'SukiSU Ultra', version: '2.0', icon: 'sukiSu', detail: t('root.sukisuDetail') },
    { id: 'wild-ksu', name: 'Wild_KSU', version: '—', icon: 'wildKsu', detail: t('root.kernelSuDetail') },
    { id: 'legacy', name: 'KernelSU Legacy', version: '—', icon: 'kernelSu', detail: t('root.kernelSuDetail') },
  ];
  const [rootApps, setRootApps] = useState<RootAppEntry[]>([]);
  const [appsLoaded, setAppsLoaded] = useState(false);
  const [modules, setModules] = useState<RootModuleEntry[]>([]);
  const [modulesLoaded, setModulesLoaded] = useState(false);
  const [busy, setBusy] = useState('');
  const inventoryMethods = rootApps.flatMap((app) => {
    const id = methodForProvider(app.provider);
    const definition = methodCatalog.find((entry) => entry.id === id);
    return definition ? [{ ...definition, version: app.version }] : [];
  }).filter((entry, index, entries) => entries.findIndex((candidate) => candidate.id === entry.id) === index);
  const methods: readonly RootMethod[] = window.pixelflasher?.__mock
    ? methodCatalog
    : inventoryMethods;
  const [method, setMethod] = useState<string>(() => window.pixelflasher?.__mock ? 'magisk' : '');
  const primary = selectedSerials.length === 1
    ? snapshot.devices.find((device) => device.serial === selectedSerials[0])
    : undefined;
  const singleAdb = selectedSerials.length === 1 && primary?.mode === 'adb';
  const rootedAdb = singleAdb && primary?.rooted === true;
  const compatibleApps = rootApps.filter((app) => providerKey(app.provider) === patchProvider(method));
  const compatibleApp = compatibleApps.find((app) => methodForProvider(app.provider) === method) ?? compatibleApps[0];

  const refreshRootApps = async () => {
    if (busy) return;
    setBusy('apps-list');
    try {
      const response = await onCommand(commands.rootAppsList);
      if (!response) return;
      const value = record(record(response.result).value);
      const parsed = (Array.isArray(value.apps) ? value.apps : []).flatMap((entry) => {
        const app = record(entry);
        if (
          typeof app.id !== 'string' || !/^[0-9a-f]{64}$/i.test(app.id) ||
          typeof app.provider !== 'string' || !app.provider ||
          typeof app.flavor !== 'string' ||
          typeof app.version !== 'string' ||
          typeof app.sha256 !== 'string' || !/^[0-9a-f]{64}$/i.test(app.sha256) ||
          typeof app.provenance !== 'string'
        ) return [];
        return [{
          id: app.id,
          provider: app.provider,
          flavor: app.flavor,
          version: app.version,
          sha256: app.sha256,
          provenance: app.provenance,
        }];
      });
      setRootApps(parsed);
      setAppsLoaded(true);
      setMethod((current) => {
        const availableMethods = parsed.map((app) => methodForProvider(app.provider)).filter(Boolean);
        if (current && availableMethods.includes(current)) return current;
        return availableMethods[0] ?? '';
      });
    } finally {
      setBusy('');
    }
  };

  const installRootApp = async (appId: string) => {
    if (!singleAdb || !primary || busy) return;
    setBusy(`app:${appId}`);
    try {
      await onCommand(commands.rootAppsInstall, { serial: primary.serial, appId });
    } finally {
      setBusy('');
    }
  };

  const refreshModules = async () => {
    if (!rootedAdb || !primary || busy) return;
    setBusy('modules-list');
    try {
      const response = await onCommand(commands.rootModulesList, { serial: primary.serial });
      if (!response) return;
      const value = record(record(response.result).value);
      const parsed = (Array.isArray(value.modules) ? value.modules : []).flatMap((entry) => {
        const module = record(entry);
        return typeof module.id === 'string' && /^[A-Za-z][A-Za-z0-9._-]{0,63}$/.test(module.id)
          ? [{ id: module.id }]
          : [];
      });
      setModules(parsed);
      setModulesLoaded(true);
    } finally {
      setBusy('');
    }
  };

  const runModuleAction = async (action: 'enable' | 'disable' | 'remove', moduleId: string) => {
    if (!rootedAdb || !primary || busy) return;
    setBusy(`module:${action}:${moduleId}`);
    try {
      const response = await onCommand(commands.rootModulesAction, { serial: primary.serial, action, moduleId });
      if (response && action === 'remove') {
        setModules((current) => current.filter((module) => module.id !== moduleId));
      }
    } finally {
      setBusy('');
    }
  };

  const installModule = async () => {
    if (!rootedAdb || !primary || busy) return;
    setBusy('module:install');
    try {
      const picked = await onCommand(commands.nativePickFile, {
        title: t('root.moduleInstall'),
        filters: [{ label: t('root.modulesTitle'), extensions: ['zip'] }],
      });
      const path = selectedPath(picked);
      if (!path) return;
      const response = await onCommand(commands.rootModulesAction, { serial: primary.serial, action: 'install', path });
      if (!response) return;
      const value = record(record(response.result).value);
      if (typeof value.moduleId === 'string' && /^[A-Za-z][A-Za-z0-9._-]{0,63}$/.test(value.moduleId)) {
        setModules((current) => current.some((module) => module.id === value.moduleId)
          ? current
          : [...current, { id: value.moduleId as string }]);
        setModulesLoaded(true);
      }
    } finally {
      setBusy('');
    }
  };

  const patchBoot = async () => {
    if (!singleAdb || !primary || !method || !compatibleApp || !snapshot.boot || busy) return;
    setBusy('boot-patch');
    try {
      const picked = await onCommand(commands.nativeSaveFile, {
        title: t('root.patch'),
        defaultName: `patched-${method}.img`,
        filters: [{ label: t('root.patch'), extensions: ['img'] }],
      });
      const destination = selectedPath(picked);
      if (!destination) return;
      await onCommand(commands.bootPatch, {
        serial: primary.serial,
        flavor: method,
        appId: compatibleApp.id,
        destination,
      });
    } finally {
      setBusy('');
    }
  };

  return (
    <>
      <PageHeader title={t('root.title')} subtitle={t('root.subtitle')} />
      <div className="inline-alert inline-alert--warning root-warning">
        <Icon name="warningPng" size={20} />
        <span>{t('root.warning')}</span>
      </div>
      <Card>
        <CardTitle icon="root">{t('root.choose')}</CardTitle>
        <div className="root-methods" role="radiogroup" aria-label={t('root.choose')}>
          {methods.map((entry) => (
            <label className={`root-method ${method === entry.id ? 'is-selected' : ''}`} key={entry.id}>
              <input type="radio" name="root-method" checked={method === entry.id} onChange={() => setMethod(entry.id)} />
              <img src={assets[entry.icon]} width={48} height={48} alt="" aria-hidden="true" />
              <span><strong>{entry.name}</strong><Badge tone="neutral">{entry.version}</Badge><small>{entry.detail}</small></span>
            </label>
          ))}
          {!methods.length ? <EmptyState icon="root" title={t('common.none')} detail={t('root.subtitle')} /> : null}
        </div>
        <div className="root-footer">
          <span>{compatibleApp ? `${compatibleApp.provider} ${compatibleApp.version}` : t('root.patchAppsRequired')}</span>
          <Button variant="primary" icon="patch" onClick={() => void patchBoot()} disabled={Boolean(busy) || !singleAdb || !snapshot.boot || !method || !compatibleApp}>
            {t('root.patch')}
          </Button>
        </div>
      </Card>

      <div className="root-management-grid">
        <Card className="root-manager" aria-busy={busy.startsWith('app') || busy === 'apps-list'}>
          <CardTitle icon="android" after={(
            <Button icon="scan" onClick={() => void refreshRootApps()} disabled={Boolean(busy)}>{t('common.refresh')}</Button>
          )}>{t('root.appsTitle')}</CardTitle>
          <p className="root-manager__detail">{t('root.appsDetail')}</p>
          {!singleAdb ? <p className="root-manager__guard"><Icon name="warningPng" size={16} />{t('root.appDeviceRequired')}</p> : null}
          <div className="root-inventory" role="list" aria-label={t('root.appsTitle')}>
            {rootApps.map((app) => (
              <article className="root-inventory__row" role="listitem" key={app.id}>
                <span className="root-inventory__icon"><Icon name="androidPng" size={24} /></span>
                <span className="root-inventory__copy">
                  <strong>{app.provider}</strong>
                  <span><Badge tone="accent">{app.flavor || '—'}</Badge><Badge tone="neutral">{app.provenance || '—'}</Badge></span>
                  <small>{app.version || '—'} · <code title={app.sha256}>{app.sha256.slice(0, 12)}…</code></small>
                </span>
                <Button icon="download" onClick={() => void installRootApp(app.id)} disabled={Boolean(busy) || !singleAdb}>{t('root.appInstall')}</Button>
              </article>
            ))}
            {!rootApps.length ? <EmptyState icon="android" title={t('common.none')} detail={appsLoaded ? t('common.none') : t('root.appsEmpty')} /> : null}
          </div>
        </Card>

        <Card className="root-manager" aria-busy={busy.startsWith('module')}>
          <CardTitle icon="packages" after={(
            <div className="button-row">
              <Button icon="scan" onClick={() => void refreshModules()} disabled={Boolean(busy) || !rootedAdb}>{t('common.refresh')}</Button>
              <Button variant="primary" icon="folderPng" onClick={() => void installModule()} disabled={Boolean(busy) || !rootedAdb}>{t('root.moduleInstall')}</Button>
            </div>
          )}>{t('root.modulesTitle')}</CardTitle>
          <p className="root-manager__detail">{t('root.modulesDetail')}</p>
          {!rootedAdb ? <p className="root-manager__guard"><Icon name="warningPng" size={16} />{t('root.moduleDeviceRequired')}</p> : null}
          <div className="root-inventory" role="list" aria-label={t('root.modulesTitle')}>
            {modules.map((module) => (
              <article className="root-inventory__row root-inventory__row--module" role="listitem" key={module.id}>
                <span className="root-inventory__icon"><Icon name="packages" size={24} /></span>
                <span className="root-inventory__copy"><strong>{module.id}</strong><small>Magisk</small></span>
                <span className="root-inventory__actions">
                  <Button variant="ghost" onClick={() => void runModuleAction('enable', module.id)} disabled={Boolean(busy)}>{t('root.moduleEnable')}</Button>
                  <Button variant="ghost" onClick={() => void runModuleAction('disable', module.id)} disabled={Boolean(busy)}>{t('root.moduleDisable')}</Button>
                  <Button variant="danger" onClick={() => void runModuleAction('remove', module.id)} disabled={Boolean(busy)}>{t('root.moduleRemove')}</Button>
                </span>
              </article>
            ))}
            {!modules.length ? <EmptyState icon="packages" title={t('common.none')} detail={rootedAdb && !modulesLoaded ? t('root.modulesEmpty') : rootedAdb ? t('common.none') : t('root.moduleDeviceRequired')} /> : null}
          </div>
        </Card>
      </div>
    </>
  );
}

export function AppsPage({ snapshot, selectedSerials, onCommand }: SharedPageProps) {
  const { t } = useI18n();
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<string[]>([]);
  const [action, setAction] = useState<'enable' | 'disable'>('disable');
  const [listedApps, setListedApps] = useState<typeof demoApps>([]);
  const [busy, setBusy] = useState(false);
  const snapshotApps = (snapshot as HostSnapshot & { apps?: typeof demoApps }).apps;
  const available = window.pixelflasher?.__mock ? demoApps : listedApps.length ? listedApps : Array.isArray(snapshotApps) ? snapshotApps : [];
  const filtered = useMemo(() => available.filter((app) => `${app.name} ${app.id}`.toLowerCase().includes(query.toLowerCase())), [available, query]);

  const refreshPackages = async () => {
    const serial = selectedSerials[0];
    if (!serial || busy) return;
    setBusy(true);
    try {
      const response = await onCommand(commands.appsList, { serial, scope: 'all' });
      if (!response) return;
      const result = record(response.result);
      const value = record(result.value);
      const rawPackages = Array.isArray(value.packages) ? value.packages : [];
      setListedApps(rawPackages.flatMap((entry) => {
        const item = record(entry);
        if (typeof item.package !== 'string' || !item.package) return [];
        return [{
          id: item.package,
          name: item.package,
          version: '—',
          scope: String(item.apk_path ?? '').startsWith('/system') ? 'System' : 'User',
          enabled: true,
        }];
      }));
      setSelected([]);
    } finally {
      setBusy(false);
    }
  };

  const applyAction = async () => {
    const serial = selectedSerials[0];
    if (!serial || !selected.length || busy) return;
    setBusy(true);
    try {
      const response = await onCommand(commands.appsAction, { serial, packages: selected, action });
      if (!response) return;
      setListedApps((apps) => apps.map((app) => selected.includes(app.id) ? { ...app, enabled: action === 'enable' } : app));
      setSelected([]);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeader
        title={t('apps.title')}
        subtitle={t('apps.subtitle')}
        actions={(
          <div className="page-header__controls">
            <Button icon="scan" onClick={() => void refreshPackages()} disabled={!selectedSerials.length || busy}>{t('common.refresh')}</Button>
            <label className="toolbar-locale">
              <span className="sr-only">{t('common.apply')}</span>
              <select value={action} onChange={(event) => setAction(event.currentTarget.value as 'enable' | 'disable')}>
                <option value="disable">{t('common.disabled')}</option>
                <option value="enable">{t('common.enabled')}</option>
              </select>
            </label>
            <Button variant="primary" icon="check" onClick={() => void applyAction()} disabled={busy || !selected.length || !selectedSerials.length || !available.length}>{t('common.apply')}</Button>
          </div>
        )}
      />
      <Card>
        <div className="table-toolbar">
          <CardTitle icon="android">{t('apps.title')}</CardTitle>
          <label className="search-field">
            <Icon name="scan" size={18} />
            <span className="sr-only">{t('apps.filter')}</span>
            <input type="search" value={query} onChange={(event) => setQuery(event.currentTarget.value)} placeholder={t('apps.filter')} />
          </label>
        </div>
        <div className="data-table" role="table" aria-label={t('apps.title')}>
          <div className="data-table__head" role="row">
            <span role="columnheader" aria-label={t('common.selected')} />
            <span role="columnheader">{t('apps.package')}</span>
            <span role="columnheader">{t('apps.version')}</span>
            <span role="columnheader">{t('apps.scope')}</span>
            <span role="columnheader">{t('apps.state')}</span>
          </div>
          {filtered.map((app) => (
            <label className="data-table__row" role="row" key={app.id}>
              <span role="cell"><input type="checkbox" checked={selected.includes(app.id)} onChange={() => setSelected((value) => value.includes(app.id) ? value.filter((id) => id !== app.id) : [...value, app.id])} aria-label={`${t('apps.package')}: ${app.name}`} /></span>
              <span role="cell"><strong>{app.name}</strong><small>{app.id}</small></span>
              <span role="cell">{app.version}</span>
              <span role="cell">{t(app.scope === 'System' ? 'common.system' : 'common.user')}</span>
              <span role="cell"><Badge tone={app.enabled ? 'success' : 'neutral'}>{t(app.enabled ? 'common.enabled' : 'common.disabled')}</Badge></span>
            </label>
          ))}
          {!available.length ? <EmptyState icon="android" title={t('common.none')} detail={t('apps.subtitle')} /> : null}
        </div>
      </Card>
    </>
  );
}

export function BackupsPage({ snapshot, selectedSerials, onCommand }: SharedPageProps) {
  const { t } = useI18n();
  const primary = snapshot.devices.find((device) => selectedSerials.includes(device.serial));
  const [partition, setPartition] = useState('boot');
  const [slot, setSlot] = useState<'a' | 'b'>(primary?.slot === 'b' ? 'b' : 'a');
  const [busy, setBusy] = useState(false);
  const snapshotBackups = (snapshot as HostSnapshot & { backups?: typeof demoBackups }).backups;
  const available = window.pixelflasher?.__mock ? demoBackups : Array.isArray(snapshotBackups) ? snapshotBackups : [];

  const pickedPath = (response: Awaited<ReturnType<typeof onCommand>>) => {
    if (!response) return '';
    const result = record(response.result);
    const value = record(result.value);
    const data = record(result.data ?? value.data);
    return typeof data.path === 'string' ? data.path : '';
  };

  const createBackup = async () => {
    const serial = selectedSerials[0];
    if (!serial || busy) return;
    setBusy(true);
    try {
      const picked = await onCommand(commands.nativeSaveFile, {
        title: t('backups.create'),
        defaultName: `${partition}_${slot}.img`,
        filters: [{ label: t('backups.title'), extensions: ['img'] }],
      });
      const destination = pickedPath(picked);
      if (!destination) return;
      await onCommand(commands.backupsCreate, { serial, partition, slot, destination });
    } finally {
      setBusy(false);
    }
  };

  const restoreBackup = async () => {
    const serial = selectedSerials[0];
    if (!serial || busy) return;
    setBusy(true);
    try {
      const picked = await onCommand(commands.nativePickFile, {
        title: t('backups.restore'),
        filters: [{ label: t('backups.title'), extensions: ['img'] }],
      });
      const path = pickedPath(picked);
      if (!path) return;
      await onCommand(commands.backupsRestore, { serial, partition, slot, path });
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeader title={t('backups.title')} subtitle={t('backups.subtitle')} actions={(
        <div className="page-header__controls">
          <label className="toolbar-locale">
            <span className="sr-only">{t('tools.partition')}</span>
            <select value={partition} onChange={(event) => setPartition(event.currentTarget.value)}>
              {['boot', 'init_boot', 'vendor_boot', 'dtbo', 'vbmeta'].map((value) => <option value={value} key={value}>{value}</option>)}
            </select>
          </label>
          <label className="toolbar-locale">
            <span className="sr-only">{t('flash.review.slot')}</span>
            <select value={slot} onChange={(event) => setSlot(event.currentTarget.value as 'a' | 'b')}>
              <option value="a">A</option>
              <option value="b">B</option>
            </select>
          </label>
          <Button icon="restore" onClick={() => void restoreBackup()} disabled={busy || !selectedSerials.length || primary?.mode !== 'fastboot'}>{t('backups.restore')}</Button>
          <Button variant="primary" icon="backupPng" onClick={() => void createBackup()} disabled={busy || !selectedSerials.length || (primary?.mode !== 'fastboot' && !(primary?.mode === 'adb' && primary.rooted))}>{t('backups.create')}</Button>
        </div>
      )} />
      <div className="backup-grid">
        {available.map((backup) => (
          <Card className="backup-card" key={backup.id}>
            <div className="backup-card__header">
              <span className="backup-card__icon"><Icon name="backup" size={25} /></span>
              <span><strong>{backup.device}</strong><code>{backup.serial}</code></span>
              <Badge tone="accent">{backup.size}</Badge>
            </div>
            <dl>
              <div><dt>{t('common.date')}</dt><dd>{backup.date}</dd></div>
              <div><dt>{t('backups.contents')}</dt><dd>{backup.contents}</dd></div>
            </dl>
            <Button icon="restore" onClick={() => void restoreBackup()} disabled={busy || !selectedSerials.length || primary?.mode !== 'fastboot'}>{t('backups.restore')}</Button>
          </Card>
        ))}
        {!available.length ? <Card><EmptyState icon="backup" title={t('common.none')} detail={t('backups.subtitle')} /></Card> : null}
      </div>
    </>
  );
}

export function ToolsPage({ snapshot, selectedSerials, onCommand, expertMode }: SharedPageProps & { expertMode: boolean }) {
  const { t } = useI18n();
  type ToolPanel = 'wifi' | 'logcat' | 'partitions' | 'push' | null;
  type PartitionRow = { name: string; sizeBytes: number | null; partitionType: string };
  const primary = selectedSerials.length === 1
    ? snapshot.devices.find((device) => device.serial === selectedSerials[0])
    : undefined;
  const adbReady = primary?.mode === 'adb' && isToolchainReady(snapshot);
  const fastbootReady = primary?.mode === 'fastboot' && isToolchainReady(snapshot);
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
  const [pairingCode, setPairingCode] = useState('');
  const [pushDestination, setPushDestination] = useState<'/data/local/tmp/' | '/sdcard/Download/'>('/sdcard/Download/');

  const runTool = async (command: BridgeCommand, payload: Record<string, unknown>) => {
    if (busy) return null;
    setBusy(command);
    setResult(null);
    try {
      const response = await onCommand(command, payload);
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
        title: t('tools.partitionRead'),
        defaultName: `${partition}.img`,
        filters: [{ label: t('tools.partition'), extensions: ['img'] }],
      });
      const destination = selectedPath(picked);
      if (!destination) return;
      setBusy('');
      await runTool(commands.partitionsRead, { serial: primary.serial, partition, destination, overwrite: true });
    } finally {
      setBusy('');
    }
  };

  const writePartition = async () => {
    if (!primary || !fastbootReady || !partition || busy) return;
    setBusy('partition-write-picker');
    try {
      const picked = await onCommand(commands.nativePickFile, {
        title: t('tools.partitionWrite'),
        filters: [{ label: t('tools.partition'), extensions: ['img'] }],
      });
      const path = selectedPath(picked);
      if (!path) return;
      setBusy('');
      await runTool(commands.partitionsWrite, { serial: primary.serial, partition, path });
    } finally {
      setBusy('');
    }
  };

  const pushFiles = async () => {
    if (!primary || !adbReady || busy) return;
    setBusy('push-picker');
    try {
      const picked = await onCommand(commands.nativePickFiles, { title: t('tools.chooseFiles') });
      const paths = selectedPaths(picked);
      if (!paths.length) return;
      setBusy('');
      await runTool(commands.toolsPushFiles, { serial: primary.serial, paths, destination: pushDestination });
    } finally {
      setBusy('');
    }
  };

  const runWifi = async () => {
    if (!primary || !adbReady || busy) return;
    const payload: Record<string, unknown> = { serial: primary.serial, action: wifiAction };
    if (wifiAction !== 'status') {
      payload.host = wifiHost;
      payload.port = wifiPort;
    }
    if (wifiAction === 'pair') payload.pairingCode = pairingCode;
    try {
      const response = await runTool(commands.toolsWifi, payload);
      if (response && (wifiAction === 'connect' || wifiAction === 'disconnect')) {
        await onCommand(commands.deviceScan);
      }
    } finally {
      setPairingCode('');
    }
  };

  const createSupportPackage = async () => {
    if (busy) return;
    setBusy('support-picker');
    try {
      const picked = await onCommand(commands.nativeSaveFile, {
        title: t('tools.support'),
        purpose: 'support',
        defaultName: 'PixelFlasher-support.zip',
        filters: [{ label: t('tools.support'), extensions: ['zip'] }],
      });
      const data = record(record(picked?.result).data ?? record(record(picked?.result).value).data);
      const destinationId = typeof data.destinationId === 'string' ? data.destinationId : '';
      if (!destinationId) return;
      setBusy('');
      await runTool(commands.supportCreate, {
        destinationId,
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
      disabled: !adbReady, run: () => openPanel('wifi'),
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
            <div className="tool-form-grid">
              <label><span>{t('tools.action')}</span><select value={wifiAction} onChange={(event) => setWifiAction(event.currentTarget.value as typeof wifiAction)} disabled={Boolean(busy)}><option value="status">{t('tools.status')}</option><option value="pair">{t('tools.pair')}</option><option value="connect">{t('tools.connect')}</option><option value="disconnect">{t('tools.disconnect')}</option></select></label>
              {wifiAction !== 'status' ? <label><span>{t('tools.host')}</span><input value={wifiHost} onChange={(event) => setWifiHost(event.currentTarget.value)} inputMode="decimal" autoComplete="off" /></label> : null}
              {wifiAction !== 'status' ? <label><span>{t('tools.port')}</span><input type="number" min="1" max="65535" value={wifiPort} onChange={(event) => setWifiPort(Number(event.currentTarget.value))} /></label> : null}
              {wifiAction === 'pair' ? <label><span>{t('tools.pairingCode')}</span><input type="password" value={pairingCode} onChange={(event) => setPairingCode(event.currentTarget.value.replace(/\D/g, '').slice(0, 6))} inputMode="numeric" pattern="[0-9]{6}" maxLength={6} autoComplete="one-time-code" /></label> : null}
              <Button variant="primary" icon="adb" onClick={() => void runWifi()} disabled={Boolean(busy) || (wifiAction !== 'status' && (!wifiHost || wifiPort < 1 || wifiPort > 65535)) || (wifiAction === 'pair' && !/^\d{6}$/.test(pairingCode))}>{t('common.apply')}</Button>
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
    </>
  );
}

export function SettingsPage({
  theme,
  onThemeChange,
  locale,
  onLocaleChange,
  highContrast,
  onHighContrastChange,
  reducedMotion,
  onReducedMotionChange,
  zoom,
  onZoomChange,
}: {
  theme: Theme;
  onThemeChange: (theme: Theme) => void;
  locale: Locale;
  onLocaleChange: (locale: Locale) => void;
  highContrast: boolean;
  onHighContrastChange: (value: boolean) => void;
  reducedMotion: boolean;
  onReducedMotionChange: (value: boolean) => void;
  zoom: number;
  onZoomChange: (value: number) => void;
}) {
  const { t } = useI18n();
  return (
    <>
      <PageHeader title={t('settings.title')} subtitle={t('settings.subtitle')} />
      <div className="inline-alert" role="status">
        <Icon name="shield" size={18} />
        <span>{t('settings.localPersistence')}</span>
      </div>
      <div className="settings-grid">
        <Card>
          <CardTitle icon="settings">{t('settings.appearance')}</CardTitle>
          <div className="settings-section">
            <label className="field-label" id="theme-label">{t('settings.theme')}</label>
            <div className="segmented" role="group" aria-labelledby="theme-label">
              <button type="button" className={theme === 'dark' ? 'is-active' : ''} aria-pressed={theme === 'dark'} onClick={() => onThemeChange('dark')}>{t('settings.dark')}</button>
              <button type="button" className={theme === 'light' ? 'is-active' : ''} aria-pressed={theme === 'light'} onClick={() => onThemeChange('light')}>{t('settings.light')}</button>
            </div>
          </div>
          <label className="select-field">
            <span>{t('settings.language')}</span>
            <select value={locale} onChange={(event) => onLocaleChange(event.currentTarget.value as Locale)}>
              {localeOptions.map((option) => <option value={option.value} key={option.value}>{option.label}</option>)}
            </select>
          </label>
          <div className="settings-section">
            <div className="zoom-row">
              <span><strong>{t('settings.zoom')}</strong><small>{zoom}%</small></span>
              <div className="zoom-controls">
                <Button variant="ghost" onClick={() => onZoomChange(Math.max(80, zoom - 10))} aria-label={t('settings.zoomOut')}>−</Button>
                <Button variant="ghost" onClick={() => onZoomChange(100)} aria-label={t('settings.zoomReset')}>100%</Button>
                <Button variant="ghost" onClick={() => onZoomChange(Math.min(200, zoom + 10))} aria-label={t('settings.zoomIn')}>+</Button>
              </div>
            </div>
          </div>
        </Card>
        <Card>
          <CardTitle icon="shield">{t('settings.accessibility')}</CardTitle>
          <div className="toggle-stack">
            <Toggle checked={highContrast} onChange={onHighContrastChange} label={t('settings.contrast')} description={t('settings.contrastDetail')} />
            <Toggle checked={reducedMotion} onChange={onReducedMotionChange} label={t('settings.motion')} description={t('settings.motionDetail')} />
          </div>
        </Card>
        <Card className="settings-shortcuts">
          <CardTitle icon="tools">{t('settings.shortcuts')}</CardTitle>
          <ul>
            <li><kbd>Alt</kbd><kbd>1…9</kbd><span>{t('settings.shortcutNav')}</span></li>
            <li><kbd>Ctrl</kbd><kbd>+</kbd><kbd>−</kbd><kbd>0</kbd><span>{t('settings.shortcutZoom')}</span></li>
            <li><kbd>Tab</kbd><kbd>Enter</kbd><span>{t('settings.shortcutFocus')}</span></li>
          </ul>
        </Card>
      </div>
    </>
  );
}
