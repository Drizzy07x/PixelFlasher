import { useCallback, useEffect, useState } from 'react';
import { commands } from '../../commands';
import { useI18n } from '../../i18n';
import { Badge, Button, Card, EmptyState, Icon, PageHeader } from '../../components/ui';
import { record, selectedGrant, type SharedPageProps } from '../shared';

type BackupRecord = {
  id: string;
  sha256: string;
  sizeBytes: number;
  createdAt: number;
  targetSerial: string;
  deviceCodename: string;
  partition: string;
  slot: 'a' | 'b';
  targetPartition: string;
  provenance: 'created' | 'user_supplied';
  available: boolean;
  integrity: 'stored' | 'missing';
};

type MagiskBackupRecord = {
  sha1: string;
  sizeBytes: number;
  createdAt: number;
  integrity: 'verified' | 'corrupt';
};

const BACKUP_ID = /^[0-9a-f]{32}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const SHA1 = /^[0-9a-f]{40}$/;

function operationSucceeded(result: Record<string, unknown>) {
  return typeof result.status === 'string' && result.status.toLowerCase() === 'success';
}

function inventoryRows(result: Record<string, unknown>): BackupRecord[] | null {
  if (!operationSucceeded(result)) return null;
  const value = record(result.value);
  if (value.bounded !== true || !Array.isArray(value.backups) || value.backups.length > 1000) return null;
  const rows = value.backups.flatMap((entry) => {
    const item = record(entry);
    if (
      typeof item.id !== 'string' || !BACKUP_ID.test(item.id)
      || typeof item.sha256 !== 'string' || !SHA256.test(item.sha256)
      || typeof item.sizeBytes !== 'number' || !Number.isSafeInteger(item.sizeBytes) || item.sizeBytes <= 0
      || typeof item.createdAt !== 'number' || !Number.isSafeInteger(item.createdAt) || item.createdAt < 0
      || typeof item.targetSerial !== 'string' || !item.targetSerial
      || typeof item.deviceCodename !== 'string' || !item.deviceCodename
      || typeof item.partition !== 'string' || !item.partition
      || (item.slot !== 'a' && item.slot !== 'b')
      || item.targetPartition !== `${item.partition}_${item.slot}`
      || (item.provenance !== 'created' && item.provenance !== 'user_supplied')
      || typeof item.available !== 'boolean'
      || item.integrity !== (item.available ? 'stored' : 'missing')
    ) return [];
    return [item as BackupRecord];
  });
  return rows.length === value.backups.length ? rows : null;
}

function magiskInventoryRows(result: Record<string, unknown>): MagiskBackupRecord[] | null {
  if (!operationSucceeded(result)) return null;
  const value = record(result.value);
  if (value.action !== 'list' || value.bounded !== true || !Array.isArray(value.backups) || value.backups.length > 256) return null;
  const rows = value.backups.flatMap((entry) => {
    const item = record(entry);
    if (
      typeof item.sha1 !== 'string' || !SHA1.test(item.sha1)
      || typeof item.sizeBytes !== 'number' || !Number.isSafeInteger(item.sizeBytes) || item.sizeBytes < 0
      || typeof item.createdAt !== 'number' || !Number.isSafeInteger(item.createdAt) || item.createdAt < 0
      || (item.integrity !== 'verified' && item.integrity !== 'corrupt')
    ) return [];
    return [item as MagiskBackupRecord];
  });
  return rows.length === value.backups.length ? rows : null;
}

function formatSize(bytes: number) {
  const mib = bytes / (1024 * 1024);
  return `${mib >= 10 ? mib.toFixed(0) : mib.toFixed(1)} MiB`;
}

export function BackupsPage({ snapshot, selectedSerials, onCommand }: SharedPageProps) {
  const { locale, t } = useI18n();
  const serial = selectedSerials.length === 1 ? selectedSerials[0] : '';
  const primary = snapshot.devices.find((device) => device.serial === serial);
  const [partition, setPartition] = useState('boot');
  const [slot, setSlot] = useState<'a' | 'b'>(primary?.slot === 'b' ? 'b' : 'a');
  const [backups, setBackups] = useState<BackupRecord[]>([]);
  const [busy, setBusy] = useState('');
  const [inventoryState, setInventoryState] = useState<'idle' | 'loading' | 'ready' | 'error'>('idle');
  const [confirmDelete, setConfirmDelete] = useState('');
  const [confirmationText, setConfirmationText] = useState('');
  const [magiskBackups, setMagiskBackups] = useState<MagiskBackupRecord[]>([]);
  const [magiskState, setMagiskState] = useState<'idle' | 'loading' | 'ready' | 'error'>('idle');
  const [confirmMagiskDelete, setConfirmMagiskDelete] = useState('');
  const [magiskConfirmationText, setMagiskConfirmationText] = useState('');
  const [dataAdbAction, setDataAdbAction] = useState<'restore' | 'clear' | ''>('');
  const [dataAdbConfirmation, setDataAdbConfirmation] = useState('');
  const [dataAdbNotice, setDataAdbNotice] = useState('');

  const refreshInventory = useCallback(async (expectedRevision?: number) => {
    if (!serial) {
      setBackups([]);
      setInventoryState('ready');
      return false;
    }
    setInventoryState('loading');
    try {
      const response = await onCommand(
        commands.backupsList,
        { serial },
        expectedRevision === undefined ? undefined : { expectedRevision },
      );
      const rows = response ? inventoryRows(record(response.result)) : null;
      if (!rows) {
        setInventoryState('error');
        return false;
      }
      setBackups(rows);
      setInventoryState('ready');
      return true;
    } catch {
      setInventoryState('error');
      return false;
    }
  }, [onCommand, serial]);

  const magiskReady = Boolean(serial && primary?.mode === 'adb' && primary.rooted);
  const refreshMagisk = useCallback(async (expectedRevision?: number) => {
    if (!magiskReady) {
      setMagiskBackups([]);
      setMagiskState('ready');
      return false;
    }
    setMagiskState('loading');
    try {
      const response = await onCommand(
        commands.backupsMagiskList,
        { serial },
        expectedRevision === undefined ? undefined : { expectedRevision },
      );
      const rows = response ? magiskInventoryRows(record(response.result)) : null;
      if (!rows) {
        setMagiskState('error');
        return false;
      }
      setMagiskBackups(rows);
      setMagiskState('ready');
      return true;
    } catch {
      setMagiskState('error');
      return false;
    }
  }, [magiskReady, onCommand, serial]);

  useEffect(() => {
    setConfirmDelete('');
    setConfirmationText('');
    setConfirmMagiskDelete('');
    setMagiskConfirmationText('');
    setDataAdbAction('');
    setDataAdbConfirmation('');
    setDataAdbNotice('');
    void refreshInventory();
    void refreshMagisk();
  }, [refreshInventory, refreshMagisk]);

  const importMagiskBackup = async () => {
    if (!magiskReady || busy) return;
    setBusy('magisk-import');
    try {
      const picked = await onCommand(commands.nativePickFile, {
        purpose: 'backups.magisk.import.source',
        title: t('backups.magiskImport'),
        filters: [{ label: t('backups.magiskImageFiles'), extensions: ['img'] }],
      }, { returnCancelled: true });
      const grant = selectedGrant(picked);
      if (!grant) return;
      const response = await onCommand(
        commands.backupsMagiskImport,
        { serial, grant },
        { returnCancelled: true },
      );
      if (response && operationSucceeded(record(response.result))) {
        await refreshMagisk(response.revision);
      }
    } finally {
      setBusy('');
    }
  };

  const deleteMagiskBackup = async (backup: MagiskBackupRecord) => {
    const required = `DELETE MAGISK ${backup.sha1.slice(-8).toUpperCase()} ${serial.slice(-6).toUpperCase()}`;
    if (!magiskReady || busy || magiskConfirmationText !== required) return;
    setBusy(`magisk-delete:${backup.sha1}`);
    try {
      const response = await onCommand(commands.backupsMagiskDelete, {
        serial,
        sha1: backup.sha1,
        confirmationText: magiskConfirmationText,
      });
      if (response && operationSucceeded(record(response.result))) {
        setConfirmMagiskDelete('');
        setMagiskConfirmationText('');
        await refreshMagisk(response.revision);
      }
    } finally {
      setBusy('');
    }
  };

  const createBackup = async () => {
    if (!serial || busy) return;
    setBusy('create');
    try {
      const picked = await onCommand(commands.nativeSaveFile, {
        purpose: 'backups.create.destination',
        title: t('backups.create'),
        defaultName: `${partition}_${slot}.img`,
        filters: [{ label: t('backups.title'), extensions: ['img'] }],
      });
      const grant = selectedGrant(picked);
      if (!grant) return;
      const response = await onCommand(commands.backupsCreate, { serial, partition, slot, grant });
      if (response && operationSucceeded(record(response.result))) {
        await refreshInventory(response.revision);
      }
    } finally {
      setBusy('');
    }
  };

  const dataAdbReady = Boolean(serial && primary?.mode === 'adb' && primary.rooted);
  const dataAdbRequired = dataAdbAction === 'restore'
    ? `RESTORE DATAADB ${serial.slice(-6).toUpperCase()}`
    : `CLEAR DATAADB ${serial.slice(-6).toUpperCase()}`;

  const backupDataAdb = async () => {
    if (!dataAdbReady || busy) return;
    setBusy('data-adb-backup');
    setDataAdbNotice('');
    try {
      const picked = await onCommand(commands.nativeSaveFile, {
        purpose: 'root.dataAdb.backup.destination',
        title: t('backups.dataAdbBackup'),
        defaultName: `data-adb-${serial.slice(-6).toLowerCase()}.pfdataadb`,
        filters: [{ label: t('backups.dataAdbFiles'), extensions: ['pfdataadb'] }],
      }, { returnCancelled: true });
      const grant = selectedGrant(picked);
      if (!grant) return;
      const response = await onCommand(
        commands.rootDataAdbBackup,
        { serial, grant },
        { returnCancelled: true },
      );
      const result = record(response?.result);
      const value = record(result.value);
      if (operationSucceeded(result) && value.action === 'backup' && value.verified === true && value.remoteCleaned === true) {
        setDataAdbNotice(t('backups.dataAdbBackupSuccess', { file: String(value.fileName ?? '') }));
      }
    } finally {
      setBusy('');
    }
  };

  const restoreDataAdb = async () => {
    if (!dataAdbReady || busy || dataAdbConfirmation !== dataAdbRequired) return;
    setBusy('data-adb-restore');
    setDataAdbNotice('');
    try {
      const picked = await onCommand(commands.nativePickFile, {
        purpose: 'root.dataAdb.restore.source',
        title: t('backups.dataAdbRestore'),
        filters: [{ label: t('backups.dataAdbFiles'), extensions: ['pfdataadb'] }],
      }, { returnCancelled: true });
      const grant = selectedGrant(picked);
      if (!grant) return;
      const response = await onCommand(commands.rootDataAdbRestore, {
        serial,
        grant,
        confirmationText: dataAdbConfirmation,
      }, { returnCancelled: true });
      const result = record(response?.result);
      const value = record(result.value);
      if (operationSucceeded(result) && value.action === 'restore' && value.verified === true && value.remoteCleaned === true) {
        setDataAdbNotice(t('backups.dataAdbRestoreSuccess', { count: String(value.entryCount ?? 0) }));
        setDataAdbAction('');
        setDataAdbConfirmation('');
      }
    } finally {
      setBusy('');
    }
  };

  const clearDataAdb = async () => {
    if (!dataAdbReady || busy || dataAdbConfirmation !== dataAdbRequired) return;
    setBusy('data-adb-clear');
    setDataAdbNotice('');
    try {
      const response = await onCommand(commands.rootDataAdbClear, {
        serial,
        confirmationText: dataAdbConfirmation,
      }, { returnCancelled: true });
      const result = record(response?.result);
      const value = record(result.value);
      if (operationSucceeded(result) && value.action === 'clear' && value.empty === true && value.verified === true) {
        setDataAdbNotice(t('backups.dataAdbClearSuccess'));
        setDataAdbAction('');
        setDataAdbConfirmation('');
      }
    } finally {
      setBusy('');
    }
  };

  const restoreExternalBackup = async () => {
    if (!serial || busy) return;
    setBusy('restore-external');
    try {
      const picked = await onCommand(commands.nativePickFile, {
        purpose: 'backups.restore.source',
        title: t('backups.externalRestore'),
        filters: [{ label: t('backups.title'), extensions: ['img'] }],
      });
      const grant = selectedGrant(picked);
      if (!grant) return;
      const response = await onCommand(commands.backupsRestore, { serial, partition, slot, grant });
      if (response && operationSucceeded(record(response.result))) {
        await refreshInventory(response.revision);
      }
    } finally {
      setBusy('');
    }
  };

  const restoreManagedBackup = async (backup: BackupRecord) => {
    if (!serial || busy || !backup.available) return;
    setBusy(`restore:${backup.id}`);
    try {
      await onCommand(commands.backupsRestore, {
        serial,
        partition: backup.partition,
        slot: backup.slot,
        backupId: backup.id,
      });
    } finally {
      setBusy('');
    }
  };

  const deleteManagedBackup = async (backup: BackupRecord) => {
    const required = `DELETE ${backup.id.slice(-8).toUpperCase()}`;
    if (busy || confirmationText !== required) return;
    setBusy(`delete:${backup.id}`);
    try {
      const response = await onCommand(commands.backupsDelete, {
        backupId: backup.id,
        confirmationText,
      });
      if (response && operationSucceeded(record(response.result))) {
        setConfirmDelete('');
        setConfirmationText('');
        await refreshInventory(response.revision);
      }
    } finally {
      setBusy('');
    }
  };

  const fastbootReady = Boolean(serial && primary?.mode === 'fastboot');
  const createReady = Boolean(serial && (primary?.mode === 'fastboot' || (primary?.mode === 'adb' && primary.rooted)));

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
          <Button icon="restore" onClick={() => void restoreExternalBackup()} disabled={Boolean(busy) || !fastbootReady}>{t('backups.externalRestore')}</Button>
          <Button variant="primary" icon="backupPng" onClick={() => void createBackup()} disabled={Boolean(busy) || !createReady}>{t('backups.create')}</Button>
        </div>
      )} />
      <section aria-labelledby="data-adb-backups-title">
        <Card>
          <div className="card-title backup-inventory__title">
            <span className="card-title__label"><Icon name="backup" size={20} /><span id="data-adb-backups-title">{t('backups.dataAdbTitle')}</span></span>
            <div className="page-header__controls">
              <Button variant="primary" icon="backupPng" onClick={() => void backupDataAdb()} disabled={Boolean(busy) || !dataAdbReady}>{t('backups.dataAdbBackup')}</Button>
              <Button icon="restore" onClick={() => { setDataAdbAction('restore'); setDataAdbConfirmation(''); }} disabled={Boolean(busy) || !dataAdbReady}>{t('backups.dataAdbRestore')}</Button>
              <Button variant="danger" onClick={() => { setDataAdbAction('clear'); setDataAdbConfirmation(''); }} disabled={Boolean(busy) || !dataAdbReady}>{t('backups.dataAdbClear')}</Button>
            </div>
          </div>
          <p>{t('backups.dataAdbDetail')}</p>
          {!dataAdbReady ? <p role="status">{t('backups.dataAdbGuard')}</p> : null}
          {dataAdbNotice ? <p role="status">{dataAdbNotice}</p> : null}
          {dataAdbAction ? (
            <div className="backup-delete-confirm" role="group" aria-label={t(`backups.dataAdb${dataAdbAction === 'restore' ? 'Restore' : 'Clear'}`)}>
              <label>
                <span>{t('backups.dataAdbConfirmPrompt', { confirmation: dataAdbRequired })}</span>
                <input value={dataAdbConfirmation} onChange={(event) => setDataAdbConfirmation(event.currentTarget.value)} aria-label={t('backups.confirmationLabel')} autoComplete="off" />
              </label>
              <div className="page-header__controls">
                <Button variant="danger" onClick={() => void (dataAdbAction === 'restore' ? restoreDataAdb() : clearDataAdb())} disabled={Boolean(busy) || dataAdbConfirmation !== dataAdbRequired}>{t('common.continue')}</Button>
                <Button variant="ghost" onClick={() => { setDataAdbAction(''); setDataAdbConfirmation(''); }} disabled={Boolean(busy)}>{t('common.cancel')}</Button>
              </div>
            </div>
          ) : null}
        </Card>
      </section>
      <section aria-labelledby="magisk-backups-title">
        <div className="card-title backup-inventory__title">
          <span className="card-title__label"><Icon name="root" size={20} /><span id="magisk-backups-title">{t('backups.magiskTitle')}</span></span>
          <div className="page-header__controls">
            <Button icon="scan" onClick={() => void refreshMagisk()} disabled={Boolean(busy) || magiskState === 'loading' || !magiskReady}>{t('common.refresh')}</Button>
            <Button variant="primary" icon="download" onClick={() => void importMagiskBackup()} disabled={Boolean(busy) || !magiskReady}>{t('backups.magiskImport')}</Button>
          </div>
        </div>
        <p>{t('backups.magiskDetail')}</p>
        {!magiskReady ? <p role="status">{t('backups.magiskGuard')}</p> : null}
        {magiskState === 'error' ? <p role="alert">{t('backups.magiskLoadFailed')}</p> : null}
        {magiskState === 'loading' ? <p role="status">{t('backups.loading')}</p> : null}
        <div className="backup-grid">
          {magiskBackups.map((backup) => {
            const required = `DELETE MAGISK ${backup.sha1.slice(-8).toUpperCase()} ${serial.slice(-6).toUpperCase()}`;
            return (
              <Card className="backup-card" key={backup.sha1}>
                <div className="backup-card__header">
                  <span className="backup-card__icon"><Icon name="root" size={25} /></span>
                  <span><strong>{t('backups.magiskStockBoot')}</strong><code>{backup.sha1}</code></span>
                  <Badge tone={backup.integrity === 'verified' ? 'success' : 'danger'}>{t(`backups.magiskIntegrity.${backup.integrity}`)}</Badge>
                </div>
                <dl>
                  <div><dt>{t('common.date')}</dt><dd>{backup.createdAt ? new Intl.DateTimeFormat(locale.replace('_', '-'), { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(backup.createdAt * 1000)) : '—'}</dd></div>
                  <div><dt>{t('common.size')}</dt><dd>{backup.sizeBytes ? formatSize(backup.sizeBytes) : '—'}</dd></div>
                  <div><dt>{t('backups.sha1')}</dt><dd><code>{backup.sha1.slice(0, 12)}</code></dd></div>
                </dl>
                <Button variant="danger" onClick={() => { setConfirmMagiskDelete(backup.sha1); setMagiskConfirmationText(''); }} disabled={Boolean(busy)}>{t('backups.delete')}</Button>
                {confirmMagiskDelete === backup.sha1 ? (
                  <div className="backup-delete-confirm" role="group" aria-label={t('backups.magiskDelete')}>
                    <label>
                      <span>{t('backups.magiskDeletePrompt', { confirmation: required })}</span>
                      <input value={magiskConfirmationText} onChange={(event) => setMagiskConfirmationText(event.currentTarget.value)} aria-label={t('backups.confirmationLabel')} autoComplete="off" />
                    </label>
                    <div className="page-header__controls">
                      <Button variant="danger" onClick={() => void deleteMagiskBackup(backup)} disabled={Boolean(busy) || magiskConfirmationText !== required}>{t('backups.confirmDelete')}</Button>
                      <Button variant="ghost" onClick={() => { setConfirmMagiskDelete(''); setMagiskConfirmationText(''); }} disabled={Boolean(busy)}>{t('common.cancel')}</Button>
                    </div>
                  </div>
                ) : null}
              </Card>
            );
          })}
          {magiskState === 'ready' && magiskReady && !magiskBackups.length ? <Card><EmptyState icon="root" title={t('common.none')} detail={t('backups.magiskEmpty')} /></Card> : null}
        </div>
      </section>
      <section aria-labelledby="managed-backups-title">
        <div className="card-title backup-inventory__title">
          <span className="card-title__label"><Icon name="backup" size={20} /><span id="managed-backups-title">{t('backups.managedTitle')}</span></span>
          <Button icon="scan" onClick={() => void refreshInventory()} disabled={Boolean(busy) || inventoryState === 'loading' || !serial}>{t('common.refresh')}</Button>
        </div>
        <p>{t('backups.managedDetail')}</p>
        {inventoryState === 'error' ? <p role="alert">{t('backups.loadFailed')}</p> : null}
        {inventoryState === 'loading' ? <p role="status">{t('backups.loading')}</p> : null}
        <div className="backup-grid">
          {backups.map((backup) => {
            const required = `DELETE ${backup.id.slice(-8).toUpperCase()}`;
            return (
              <Card className="backup-card" key={backup.id}>
                <div className="backup-card__header">
                  <span className="backup-card__icon"><Icon name="backup" size={25} /></span>
                  <span><strong>{backup.deviceCodename}</strong><code>{backup.targetSerial}</code></span>
                  <Badge tone={backup.available ? 'success' : 'danger'}>{backup.available ? t('backups.available') : t('backups.missing')}</Badge>
                </div>
                <dl>
                  <div><dt>{t('common.date')}</dt><dd>{new Intl.DateTimeFormat(locale.replace('_', '-'), { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(backup.createdAt * 1000))}</dd></div>
                  <div><dt>{t('backups.contents')}</dt><dd>{backup.targetPartition}</dd></div>
                  <div><dt>{t('common.size')}</dt><dd>{formatSize(backup.sizeBytes)}</dd></div>
                  <div><dt>{t('backups.provenance')}</dt><dd>{t(`backups.provenance.${backup.provenance}`)}</dd></div>
                  <div><dt>{t('backups.hash')}</dt><dd><code>{backup.sha256.slice(0, 12)}</code></dd></div>
                </dl>
                <div className="page-header__controls">
                  <Button icon="restore" onClick={() => void restoreManagedBackup(backup)} disabled={Boolean(busy) || !fastbootReady || !backup.available}>{t('backups.restore')}</Button>
                  <Button variant="danger" onClick={() => { setConfirmDelete(backup.id); setConfirmationText(''); }} disabled={Boolean(busy)}>{t('backups.delete')}</Button>
                </div>
                {confirmDelete === backup.id ? (
                  <div className="backup-delete-confirm" role="group" aria-label={t('backups.delete')}>
                    <label>
                      <span>{t('backups.deletePrompt', { confirmation: required })}</span>
                      <input value={confirmationText} onChange={(event) => setConfirmationText(event.currentTarget.value)} aria-label={t('backups.confirmationLabel')} autoComplete="off" />
                    </label>
                    <div className="page-header__controls">
                      <Button variant="danger" onClick={() => void deleteManagedBackup(backup)} disabled={Boolean(busy) || confirmationText !== required}>{t('backups.confirmDelete')}</Button>
                      <Button variant="ghost" onClick={() => { setConfirmDelete(''); setConfirmationText(''); }} disabled={Boolean(busy)}>{t('common.cancel')}</Button>
                    </div>
                  </div>
                ) : null}
              </Card>
            );
          })}
          {inventoryState === 'ready' && !backups.length ? <Card><EmptyState icon="backup" title={t('common.none')} detail={t('backups.empty')} /></Card> : null}
        </div>
      </section>
    </>
  );
}
