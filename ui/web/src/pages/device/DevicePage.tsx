import { useState } from 'react';
import { commands, type BridgeCommand } from '../../commands';
import { useI18n } from '../../i18n';
import type { BootArtifact, Device, HostSnapshot } from '../../types';
import { DeviceSelector } from '../../components/DeviceSelector';
import { Badge, Button, Card, CardTitle, Icon, Meter, PageHeader } from '../../components/ui';
import { isToolchainReady, type SharedPageProps } from '../shared';
import { DeviceInspectionPanel } from './DeviceInspectionPanel';

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
        <DeviceInspectionPanel
          device={operationTarget}
          toolchainReady={isToolchainReady(snapshot)}
          activeOperation={snapshot.activeOperation ?? snapshot.active_operation}
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
  const bootReady = Boolean(boot?.id && boot?.hash && /^[0-9a-f]{64}$/i.test(boot.hash));
  const nextSlot = device?.slot === 'a' ? 'b' : device?.slot === 'b' ? 'a' : null;
  const lockEvidenceCurrent = Boolean(
    lockEvidence
    && lockEvidence.snapshot_revision >= 0
    && lockEvidence.serial === device?.serial,
  );
  const lockBlockedMessage = t('device.lockRequiresStockEvidence');
  const lockBlockedId = device ? `lock-blocked-${device.serial.replace(/[^A-Za-z0-9_-]/g, '-')}` : undefined;
  const bootName = boot?.image ?? '';

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
