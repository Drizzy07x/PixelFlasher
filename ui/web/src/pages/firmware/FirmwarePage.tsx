import { useState } from 'react';
import { commands } from '../../commands';
import { demoFirmwares } from '../../demoData';
import { useI18n } from '../../i18n';
import { Badge, Button, Card, CardTitle, EmptyState, Icon, PageHeader } from '../../components/ui';
import { selectedGrant, type SharedPageProps } from '../shared';

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
