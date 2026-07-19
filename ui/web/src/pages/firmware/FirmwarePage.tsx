import { useMemo, useState } from 'react';
import { commands } from '../../commands';
import { demoFirmwares } from '../../demoData';
import { useI18n } from '../../i18n';
import { Badge, Button, Card, CardTitle, EmptyState, Icon, PageHeader } from '../../components/ui';
import { selectedGrant, type SharedPageProps } from '../shared';

type CatalogEntry = {
  artifactId: string;
  device: string;
  channel: 'stable' | 'beta' | 'canary';
  kind: 'factory' | 'ota';
  version: string;
  sha256: string;
  size: number;
  license: string;
  provenance: string;
};

const ARTIFACT_ID = /^[0-9a-f]{32}$/;
const SHA256 = /^[0-9a-f]{64}$/;

function catalogEntries(value: unknown): CatalogEntry[] | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const source = value as Record<string, unknown>;
  if (!Array.isArray(source.entries) || source.entries.length > 512 || source.count !== source.entries.length) return null;
  const entries: CatalogEntry[] = [];
  for (const raw of source.entries) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
    const entry = raw as Record<string, unknown>;
    if (
      Object.keys(entry).length !== 9
      || typeof entry.artifactId !== 'string' || !ARTIFACT_ID.test(entry.artifactId)
      || typeof entry.device !== 'string'
      || !['stable', 'beta', 'canary'].includes(String(entry.channel))
      || !['factory', 'ota'].includes(String(entry.kind))
      || typeof entry.version !== 'string' || !entry.version || entry.version.length > 128
      || typeof entry.sha256 !== 'string' || !SHA256.test(entry.sha256)
      || typeof entry.size !== 'number' || !Number.isSafeInteger(entry.size) || entry.size <= 0
      || typeof entry.license !== 'string' || !entry.license
      || typeof entry.provenance !== 'string' || !entry.provenance
    ) return null;
    entries.push(entry as CatalogEntry);
  }
  return entries;
}

function formatBytes(value: number) {
  const gib = value / (1024 ** 3);
  return `${gib.toFixed(gib >= 10 ? 1 : 2)} GiB`;
}

export function FirmwarePage({ snapshot, onCommand }: SharedPageProps) {
  const { t } = useI18n();
  const [busy, setBusy] = useState(false);
  const [channel, setChannel] = useState<'stable' | 'beta' | 'canary'>('stable');
  const [catalog, setCatalog] = useState<CatalogEntry[]>([]);
  const [catalogError, setCatalogError] = useState(false);
  const active = snapshot.firmware?.id ?? null;
  const available = window.pixelflasher?.__mock
    ? demoFirmwares.map((entry) => entry.id === active && snapshot.firmware
      ? { ...entry, ...snapshot.firmware }
      : entry)
    : snapshot.firmware ? [snapshot.firmware] : [];
  const selectedDevice = useMemo(
    () => snapshot.devices.find((device) => (snapshot.selectedSerials ?? []).includes(device.serial)),
    [snapshot.devices, snapshot.selectedSerials],
  );

  const refreshCatalog = async () => {
    if (busy || !selectedDevice?.codename) return;
    setBusy(true);
    setCatalogError(false);
    try {
      const response = await onCommand(commands.firmwareCatalogRefresh, {
        device: selectedDevice.codename.toLowerCase(),
        channel,
      });
      const result = response?.result as Record<string, unknown> | undefined;
      const parsed = catalogEntries(result?.value);
      if (!parsed) {
        setCatalogError(true);
        setCatalog([]);
        return;
      }
      setCatalog(parsed);
    } catch {
      setCatalogError(true);
      setCatalog([]);
    } finally {
      setBusy(false);
    }
  };

  const downloadFirmware = async (artifactId: string) => {
    if (busy) return;
    setBusy(true);
    setCatalogError(false);
    try {
      const response = await onCommand(commands.firmwareDownload, { artifactId });
      const status = (response?.result as Record<string, unknown> | undefined)?.status;
      if (typeof status !== 'string' || status.toLowerCase() !== 'success') setCatalogError(true);
    } catch {
      setCatalogError(true);
    } finally {
      setBusy(false);
    }
  };

  const pickFirmware = async () => {
    if (busy) return;
    setBusy(true);
    try {
      const picked = await onCommand(commands.nativePickFile, {
        purpose: 'firmware.select',
        title: t('firmware.import'),
        filters: [{ label: t('firmware.title'), extensions: ['zip', 'tgz', 'tar'] }],
      });
      if (!picked) return;
      const grant = selectedGrant(picked);
      if (grant) await onCommand(commands.firmwareSelect, { grant });
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
        <CardTitle icon="download" after={<Badge tone="accent">{catalog.length}</Badge>}>{t('firmware.officialCatalog')}</CardTitle>
        <div className="firmware-catalog-toolbar">
          <label>
            <span>{t('firmware.channel')}</span>
            <select value={channel} onChange={(event) => setChannel(event.target.value as typeof channel)} disabled={busy}>
              <option value="stable">{t('common.stable')}</option>
              <option value="beta">{t('common.beta')}</option>
              <option value="canary">{t('firmware.canary')}</option>
            </select>
          </label>
          <Button variant="secondary" icon="download" onClick={() => void refreshCatalog()} disabled={busy || !selectedDevice?.codename}>
            {t('firmware.refreshCatalog')}
          </Button>
          {!selectedDevice?.codename ? <small>{t('firmware.catalogDeviceRequired')}</small> : null}
        </div>
        {catalogError ? <div className="inline-alert inline-alert--warning" role="alert">{t('firmware.catalogFailed')}</div> : null}
        <div className="firmware-table" role="list">
          {catalog.map((entry) => (
            <div className="firmware-row" role="listitem" key={entry.artifactId}>
              <span className="firmware-row__icon"><Icon name={entry.kind === 'ota' ? 'download' : 'firmware'} size={25} /></span>
              <span className="firmware-row__name"><strong>{entry.version}</strong><small>{entry.device} · {entry.kind.toUpperCase()}</small></span>
              <span><small>{t('common.size')}</small><strong>{formatBytes(entry.size)}</strong></span>
              <span><small>{t('firmware.provenance')}</small><strong>{entry.provenance}</strong></span>
              <Badge tone={entry.channel === 'stable' ? 'success' : 'warning'}>{entry.channel}</Badge>
              <Button variant="primary" icon="download" onClick={() => void downloadFirmware(entry.artifactId)} disabled={busy}>
                {t('firmware.downloadSelect')}
              </Button>
            </div>
          ))}
          {!catalog.length && !catalogError ? <EmptyState icon="download" title={t('firmware.catalogEmpty')} detail={t('firmware.refreshCatalog')} /> : null}
        </div>
      </Card>
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
                    onClick={() => { if (isActive) void processFirmware(); }}
                    disabled={busy || !isActive}
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
