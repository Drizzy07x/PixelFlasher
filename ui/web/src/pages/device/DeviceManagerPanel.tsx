import { useEffect, useId, useRef, useState, type FormEvent } from 'react';
import { commands, type BridgeCommand } from '../../commands';
import { Badge, Button, Card, CardTitle, Icon } from '../../components/ui';
import { useI18n } from '../../i18n';
import { MAX_MANAGED_DEVICE_TIMESTAMP, type DeviceManagementState, type ManagedDevice } from '../../types';
import type { SharedPageProps } from '../shared';

type BusyAction = BridgeCommand | '';

export function DeviceManagerPanel({
  management,
  onCommand,
}: {
  management: DeviceManagementState;
  onCommand: SharedPageProps['onCommand'];
}) {
  const { t } = useI18n();
  const [busy, setBusy] = useState<BusyAction>('');
  const managerFocusRef = useRef<HTMLDivElement>(null);
  const actionsBusy = Boolean(busy);

  const execute = async (command: BridgeCommand, payload: Record<string, unknown>) => {
    if (actionsBusy) return;
    setBusy(command);
    try {
      await onCommand(command, payload);
    } finally {
      setBusy('');
    }
  };

  return (
    <Card className="device-manager-card" aria-busy={actionsBusy}>
      <CardTitle
        icon="settings"
        after={<Badge tone={management.scanEnabled ? 'success' : 'warning'}>{t(management.scanEnabled ? 'device.managerRunning' : 'device.managerPaused')}</Badge>}
      >
        {t('device.managerTitle')}
      </CardTitle>
      <div className="device-manager-policy">
        <div
          ref={managerFocusRef}
          className="device-manager-policy__copy"
          role="group"
          aria-label={t('device.managerTitle')}
          tabIndex={-1}
        >
          <strong>{t('device.managerScanning')}</strong>
          <span>{t(management.scanEnabled ? 'device.managerScanningDetail' : 'device.managerPausedDetail')}</span>
        </div>
        <Button
          icon={management.scanEnabled ? 'warningPng' : 'scan'}
          onClick={() => void execute(commands.deviceManagerPolicy, { scanEnabled: !management.scanEnabled })}
          disabled={actionsBusy}
        >
          {t(management.scanEnabled ? 'device.managerPause' : 'device.managerResume')}
        </Button>
        <fieldset className="device-manager-scope" disabled={actionsBusy}>
          <legend>{t('device.managerScope')}</legend>
          <label>
            <input
              type="radio"
              name="device-manager-scope"
              value="enabled"
              checked={management.scanScope === 'enabled'}
              onChange={() => void execute(commands.deviceManagerPolicy, { scanScope: 'enabled' })}
            />
            <span>{t('device.managerEnabledOnly')}</span>
          </label>
          <label>
            <input
              type="radio"
              name="device-manager-scope"
              value="all"
              checked={management.scanScope === 'all'}
              onChange={() => void execute(commands.deviceManagerPolicy, { scanScope: 'all' })}
            />
            <span>{t('device.managerAll')}</span>
          </label>
        </fieldset>
      </div>
      {management.devices.length ? (
        <ul className="managed-device-list" aria-label={t('device.managerRemembered')}>
          {management.devices.map((device) => (
            <ManagedDeviceRow
              key={device.serial}
              device={device}
              disabled={actionsBusy}
              onUpdate={(payload) => execute(commands.deviceManagerUpdate, { serial: device.serial, ...payload })}
              onRemove={() => {
                managerFocusRef.current?.focus();
                return execute(commands.deviceManagerRemove, { serial: device.serial });
              }}
            />
          ))}
        </ul>
      ) : (
        <div className="device-manager-empty" role="status">
          <Icon name="devices" size={30} />
          <span>{t('device.managerEmpty')}</span>
        </div>
      )}
    </Card>
  );
}

function ManagedDeviceRow({
  device,
  disabled,
  onUpdate,
  onRemove,
}: {
  device: ManagedDevice;
  disabled: boolean;
  onUpdate: (payload: { label?: string; enabled?: boolean }) => Promise<void>;
  onRemove: () => Promise<void>;
}) {
  const { locale, t } = useI18n();
  const inputId = useId();
  const confirmationId = useId();
  const removeButtonRef = useRef<HTMLButtonElement>(null);
  const confirmButtonRef = useRef<HTMLButtonElement>(null);
  const restoreRemovalFocus = useRef(false);
  const [label, setLabel] = useState(device.label);
  const [confirmingRemoval, setConfirmingRemoval] = useState(false);
  const normalizedLabel = label.trim();
  const lastSeen = formatLastSeen(device.lastSeen, locale);
  const connectionTone = !device.connected || device.mode === 'offline'
    ? 'neutral'
    : device.mode === 'unauthorized' || device.mode.startsWith('fastboot')
      ? 'warning'
      : 'success';

  useEffect(() => {
    setLabel(device.label);
  }, [device.label, device.serial]);

  useEffect(() => {
    setConfirmingRemoval(false);
  }, [device.serial]);

  useEffect(() => {
    if (confirmingRemoval) {
      restoreRemovalFocus.current = true;
      confirmButtonRef.current?.focus();
    } else if (restoreRemovalFocus.current) {
      restoreRemovalFocus.current = false;
      removeButtonRef.current?.focus();
    }
  }, [confirmingRemoval]);

  const saveLabel = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (disabled || normalizedLabel === device.label) return;
    await onUpdate({ label: normalizedLabel });
  };

  return (
    <li className={`managed-device ${device.enabled ? '' : 'is-disabled'}`}>
      <div className="managed-device__identity">
        <span className="managed-device__icon"><Icon name="devices" size={24} /></span>
        <span className="managed-device__copy">
          <span className="managed-device__heading">
            <strong>{device.label || device.model || device.codename || device.serial}</strong>
            <Badge tone={connectionTone}>
              {device.connected ? device.mode.toUpperCase() : t('device.managerRememberedState')}
            </Badge>
          </span>
          <code>{device.serial}</code>
          <small>{[device.model, device.codename].filter(Boolean).join(' · ') || t('common.none')}</small>
          <small className="managed-device__seen">{lastSeen ? t('device.managerLastSeen', { date: lastSeen }) : t('device.managerNeverSeen')}</small>
        </span>
      </div>
      <form className="managed-device__label" onSubmit={(event) => void saveLabel(event)}>
        <label htmlFor={inputId}>{t('device.managerAlias')}</label>
        <div>
          <input
            id={inputId}
            value={label}
            maxLength={120}
            autoComplete="off"
            aria-label={t('device.managerAliasFor', { serial: device.serial })}
            onChange={(event) => setLabel(event.currentTarget.value)}
            disabled={disabled}
          />
          <Button type="submit" disabled={disabled || normalizedLabel === device.label}>
            {t('device.managerSaveAlias')}
          </Button>
        </div>
      </form>
      <div className="managed-device__actions">
        <Button
          onClick={() => void onUpdate({ enabled: !device.enabled })}
          disabled={disabled}
        >
          {t(device.enabled ? 'device.managerDisable' : 'device.managerEnable')}
        </Button>
        {!confirmingRemoval ? (
          <Button
            ref={removeButtonRef}
            variant="danger"
            onClick={() => setConfirmingRemoval(true)}
            disabled={disabled}
          >
            {t('device.managerRemove')}
          </Button>
        ) : (
          <div id={confirmationId} className="managed-device__remove-confirm" role="group" aria-label={t('device.managerRemoveConfirm', { serial: device.serial })}>
            <span>{t('device.managerRemovePrompt')}</span>
            <Button ref={confirmButtonRef} variant="danger" onClick={() => void onRemove()} disabled={disabled}>{t('device.managerRemoveConfirmAction')}</Button>
            <Button variant="ghost" onClick={() => setConfirmingRemoval(false)} disabled={disabled}>{t('common.cancel')}</Button>
          </div>
        )}
      </div>
    </li>
  );
}

function formatLastSeen(timestamp: number, locale: string): string {
  if (!Number.isSafeInteger(timestamp)
    || timestamp <= 0
    || timestamp > MAX_MANAGED_DEVICE_TIMESTAMP) return '';
  const date = new Date(timestamp * 1000);
  if (!Number.isFinite(date.getTime())) return '';
  try {
    return new Intl.DateTimeFormat(locale.replace('_', '-'), {
      dateStyle: 'medium',
      timeStyle: 'short',
    }).format(date);
  } catch {
    return '';
  }
}
