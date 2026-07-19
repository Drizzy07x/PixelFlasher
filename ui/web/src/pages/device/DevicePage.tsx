import { useEffect, useRef, useState } from 'react';
import { commands, type BridgeCommand } from '../../commands';
import { useI18n } from '../../i18n';
import type { ActiveOperation, BootArtifact, Device, HostSnapshot } from '../../types';
import { DeviceSelector } from '../../components/DeviceSelector';
import { Badge, Button, Card, CardTitle, Icon, Meter, PageHeader } from '../../components/ui';
import { isToolchainReady, record, type SharedPageProps } from '../shared';
import { DeviceInspectionPanel } from './DeviceInspectionPanel';

type RebootMode = 'system' | 'recovery' | 'bootloader' | 'fastbootd' | 'sideload' | 'safemode';

type TransitionState =
  | { phase: 'idle' }
  | { phase: 'running' | 'cancelling' | 'success' | 'cancelled'; mode: RebootMode }
  | { phase: 'error'; mode: RebootMode; code?: string };

const SAFE_CODE = /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/;
const REBOOT_LABEL_KEYS = {
  system: 'device.rebootSystem',
  recovery: 'device.rebootRecovery',
  bootloader: 'device.rebootBootloader',
  fastbootd: 'device.rebootFastbootd',
  sideload: 'device.rebootSideload',
  safemode: 'device.rebootSafeMode',
} as const;

function operationStatus(result: Record<string, unknown>) {
  return typeof result.status === 'string' ? result.status.toLowerCase() : '';
}

function resultCode(result: Record<string, unknown>) {
  return typeof result.code === 'string' && SAFE_CODE.test(result.code) ? result.code : undefined;
}

export function DevicePage({ snapshot, selectedSerials, onSelectionChange, onCommand, expertMode }: SharedPageProps & { expertMode: boolean }) {
  const { t } = useI18n();
  const primary = snapshot.devices.find((device) => selectedSerials.includes(device.serial)) ?? snapshot.devices[0];
  const operationTarget = selectedSerials.length === 1
    ? snapshot.devices.find((device) => device.serial === selectedSerials[0])
    : undefined;
  const operationSerial = selectedSerials.length === 1 ? selectedSerials[0] : '';
  const activeOperation = snapshot.activeOperation ?? snapshot.active_operation;

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
          operationSerial={operationSerial}
          activeOperation={activeOperation}
          onCommand={onCommand}
        />
        <DeviceInspectionPanel
          device={operationTarget}
          toolchainReady={isToolchainReady(snapshot)}
          activeOperation={activeOperation}
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
  operationSerial,
  activeOperation,
  onCommand,
}: {
  device?: Device;
  boot: BootArtifact | null;
  lockEvidence?: NonNullable<HostSnapshot['bootloaderLockEvidence']>[number];
  toolchainReady: boolean;
  expertMode: boolean;
  operationSerial: string;
  activeOperation?: ActiveOperation | null;
  onCommand: SharedPageProps['onCommand'];
}) {
  const { t } = useI18n();
  const [rebootMode, setRebootMode] = useState<RebootMode>('system');
  const [transitionState, setTransitionState] = useState<TransitionState>({ phase: 'idle' });
  const transitionEpoch = useRef(0);
  const feedbackRef = useRef<HTMLElement>(null);
  const suggestedPartition = boot?.flavor && ['boot', 'init_boot', 'vendor_boot', 'vendor_kernel_boot', 'recovery'].includes(boot.flavor)
    ? boot.flavor
    : 'boot';
  const [slot, setSlot] = useState<'' | 'a' | 'b'>('');
  const [busy, setBusy] = useState<BridgeCommand | ''>('');

  const online = Boolean(device && !['offline', 'unauthorized'].includes(device.mode));
  const sideloadEligible = device?.mode === 'adb' || device?.mode === 'recovery';
  const safeModeEligible = device?.mode === 'adb' && device.rooted;
  const rebootEligible = rebootMode === 'sideload'
    ? sideloadEligible
    : rebootMode === 'safemode'
      ? safeModeEligible
      : online;
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
  const transitionBusy = transitionState.phase === 'running' || transitionState.phase === 'cancelling';
  const operationRunning = Boolean(
    activeOperation && ['pending', 'running'].includes(activeOperation.status.toLowerCase()),
  );
  const cancellableOperation = transitionBusy && operationRunning ? activeOperation : null;
  const anotherOperationRunning = operationRunning && !transitionBusy;
  const actionsBusy = Boolean(busy) || transitionBusy || anotherOperationRunning;
  const rawProgress = cancellableOperation?.progress;
  const transitionProgress = typeof rawProgress === 'number' && Number.isFinite(rawProgress)
    ? Math.min(100, Math.max(0, rawProgress))
    : null;

  useEffect(() => {
    transitionEpoch.current += 1;
    setTransitionState({ phase: 'idle' });
  }, [operationSerial]);

  useEffect(() => () => { transitionEpoch.current += 1; }, []);

  useEffect(() => {
    if (['success', 'cancelled', 'error'].includes(transitionState.phase)) {
      window.requestAnimationFrame(() => feedbackRef.current?.focus());
    }
  }, [transitionState.phase]);

  const execute = async (command: BridgeCommand, payload: Record<string, unknown>) => {
    if (!device || actionsBusy) return;
    setBusy(command);
    try {
      await onCommand(command, payload);
    } finally {
      setBusy('');
    }
  };

  const reboot = async () => {
    if (!device || actionsBusy || !rebootEligible || !toolchainReady) return;
    const epoch = transitionEpoch.current + 1;
    transitionEpoch.current = epoch;
    setBusy(commands.deviceReboot);
    setTransitionState({ phase: 'running', mode: rebootMode });
    try {
      const response = await onCommand(
        commands.deviceReboot,
        { serial: device.serial, mode: rebootMode },
        { returnCancelled: true },
      );
      if (transitionEpoch.current !== epoch) return;
      const result = record(response?.result);
      const status = operationStatus(result);
      if (status === 'success') {
        setTransitionState({ phase: 'success', mode: rebootMode });
      } else if (status === 'cancelled') {
        setTransitionState({ phase: 'cancelled', mode: rebootMode });
      } else {
        setTransitionState({ phase: 'error', mode: rebootMode, code: resultCode(result) });
      }
    } catch {
      if (transitionEpoch.current === epoch) {
        setTransitionState({ phase: 'error', mode: rebootMode });
      }
    } finally {
      if (transitionEpoch.current === epoch) setBusy('');
    }
  };

  const cancelTransition = async () => {
    if (!cancellableOperation || transitionState.phase !== 'running') return;
    setTransitionState({ phase: 'cancelling', mode: transitionState.mode });
    try {
      const response = await onCommand(commands.operationCancel, {
        operationId: cancellableOperation.id,
      });
      const result = record(response?.result);
      if (!response || operationStatus(result) !== 'success') {
        setTransitionState((current) => current.phase === 'cancelling'
          ? { phase: 'running', mode: current.mode }
          : current);
      }
    } catch {
      setTransitionState((current) => current.phase === 'cancelling'
        ? { phase: 'running', mode: current.mode }
        : current);
    }
  };

  const rebootTargetLabel = (mode: RebootMode) => t(REBOOT_LABEL_KEYS[mode]);

  return (
    <Card className="device-operations-card" aria-busy={actionsBusy}>
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
              <select value={rebootMode} onChange={(event) => setRebootMode(event.currentTarget.value as RebootMode)} disabled={!device || actionsBusy}>
                <option value="system">{t('device.rebootSystem')}</option>
                <option value="recovery">{t('device.rebootRecovery')}</option>
                <option value="bootloader">{t('device.rebootBootloader')}</option>
                <option value="fastbootd">{t('device.rebootFastbootd')}</option>
                <option value="sideload" disabled={!sideloadEligible}>{t('device.rebootSideload')}</option>
                <option value="safemode" disabled={!safeModeEligible}>{t('device.rebootSafeMode')}</option>
              </select>
            </label>
            <Button icon="rebootPng" onClick={() => void reboot()} disabled={!device || !rebootEligible || !toolchainReady || actionsBusy}>
              {t('device.rebootNow')}
            </Button>
            {transitionBusy ? (
              <div className="device-transition-feedback" role="status" aria-live="polite">
                <span className="status-dot" aria-hidden="true" />
                <span>{t(transitionState.phase === 'cancelling' ? 'device.rebootCancelling' : 'device.rebootRunning', { target: rebootTargetLabel(transitionState.mode) })}</span>
                {transitionProgress !== null ? <progress aria-label={t('device.rebootProgress')} max={100} value={transitionProgress} /> : null}
                {cancellableOperation && transitionState.phase === 'running' ? (
                  <Button variant="danger" onClick={() => void cancelTransition()}>{t('device.rebootCancel')}</Button>
                ) : null}
              </div>
            ) : null}
            {transitionState.phase === 'success' ? (
              <section className="device-transition-feedback device-transition-feedback--success" ref={feedbackRef} tabIndex={-1} role="status">
                <Icon name="check" size={18} />
                <span>{t('device.rebootSucceeded', { target: rebootTargetLabel(transitionState.mode) })}</span>
              </section>
            ) : null}
            {transitionState.phase === 'cancelled' ? (
              <section className="device-transition-feedback" ref={feedbackRef} tabIndex={-1} role="status">
                <Icon name="warningPng" size={18} />
                <span>{t('device.rebootCancelled')}</span>
              </section>
            ) : null}
            {transitionState.phase === 'error' ? (
              <section className="device-transition-feedback device-transition-feedback--error" ref={feedbackRef} tabIndex={-1} role="alert">
                <Icon name="warningPng" size={18} />
                <span>{t('device.rebootFailed')}{transitionState.code ? <code>{transitionState.code}</code> : null}</span>
              </section>
            ) : null}
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
              <Button icon="switchSlot" onClick={() => nextSlot && void execute(commands.deviceSwitchSlot, { serial: device?.serial, slot: nextSlot })} disabled={!device || !fastboot || !nextSlot || !toolchainReady || actionsBusy}>
                {t('device.switchToSlot', { slot: nextSlot?.toUpperCase() ?? '—' })}
              </Button>
              {expertMode && device?.bootloader === 'unlocked' ? (
                <Button variant="danger" icon="lock" onClick={() => void execute(commands.deviceBootloaderLock, { serial: device.serial })} disabled={!fastboot || !toolchainReady || !lockEvidenceCurrent || actionsBusy} aria-describedby={!lockEvidenceCurrent ? lockBlockedId : undefined}>
                  {t('device.lockBootloader')}
                </Button>
              ) : expertMode && device?.bootloader === 'locked' ? (
                <Button variant="danger" icon="unlock" onClick={() => void execute(commands.deviceBootloaderUnlock, { serial: device.serial })} disabled={!fastboot || !toolchainReady || actionsBusy}>
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
                <select value={slot} onChange={(event) => setSlot(event.currentTarget.value as typeof slot)} disabled={!bootReady || actionsBusy}>
                  <option value="">{t('device.defaultSlot')}</option>
                  <option value="a">A</option>
                  <option value="b">B</option>
                </select>
              </label>
            </div>
            <div className="button-row button-row--wrap">
              <Button icon="boot" onClick={() => void execute(commands.bootLive, { serial: device?.serial })} disabled={!device || !unlockedFastboot || !bootReady || suggestedPartition !== 'boot' || !toolchainReady || actionsBusy}>
                {t('device.liveBoot')}
              </Button>
              <Button variant="primary" icon="flash" onClick={() => void execute(commands.bootFlash, { serial: device?.serial, partition: suggestedPartition, ...(slot ? { slot } : {}) })} disabled={!device || !unlockedFastboot || !bootReady || !toolchainReady || actionsBusy}>
                {t('device.flashBoot')}
              </Button>
            </div>
          </div>
        </section>
      </div>
    </Card>
  );
}
