import { useState } from 'react';
import { commands } from '../../commands';
import { demoBackups } from '../../demoData';
import { useI18n } from '../../i18n';
import type { HostSnapshot } from '../../types';
import { Badge, Button, Card, EmptyState, Icon, PageHeader } from '../../components/ui';
import { selectedGrant, type SharedPageProps } from '../shared';

export function BackupsPage({ snapshot, selectedSerials, onCommand }: SharedPageProps) {
  const { t } = useI18n();
  const primary = snapshot.devices.find((device) => selectedSerials.includes(device.serial));
  const [partition, setPartition] = useState('boot');
  const [slot, setSlot] = useState<'a' | 'b'>(primary?.slot === 'b' ? 'b' : 'a');
  const [busy, setBusy] = useState(false);
  const snapshotBackups = (snapshot as HostSnapshot & { backups?: typeof demoBackups }).backups;
  const available = window.pixelflasher?.__mock ? demoBackups : Array.isArray(snapshotBackups) ? snapshotBackups : [];

  const createBackup = async () => {
    const serial = selectedSerials[0];
    if (!serial || busy) return;
    setBusy(true);
    try {
      const picked = await onCommand(commands.nativeSaveFile, {
        purpose: 'backups.create.destination',
        title: t('backups.create'),
        defaultName: `${partition}_${slot}.img`,
        filters: [{ label: t('backups.title'), extensions: ['img'] }],
      });
      const grant = selectedGrant(picked);
      if (!grant) return;
      await onCommand(commands.backupsCreate, { serial, partition, slot, grant });
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
        purpose: 'backups.restore.source',
        title: t('backups.restore'),
        filters: [{ label: t('backups.title'), extensions: ['img'] }],
      });
      const grant = selectedGrant(picked);
      if (!grant) return;
      await onCommand(commands.backupsRestore, { serial, partition, slot, grant });
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
