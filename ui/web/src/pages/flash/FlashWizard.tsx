import { useEffect, useMemo, useState } from 'react';
import type { AssetName } from '../../assets';
import { demoFirmwares } from '../../demoData';
import { useI18n } from '../../i18n';
import type { Device, Firmware, OperationStatus } from '../../types';
import { DeviceSelector } from '../../components/DeviceSelector';
import { Badge, Button, Card, CardTitle, Icon, Meter, Toggle } from '../../components/ui';

const stepKeys = [
  'flash.step.devices',
  'flash.step.firmware',
  'flash.step.options',
  'flash.step.plan',
  'flash.step.review',
] as const;

type FlashMode = 'keep' | 'wipe' | 'ota';
type SlotTarget = 'default' | 'inactive' | 'both';

export interface FlashPlan {
  serials: string[];
  firmware: Firmware;
  mode: FlashMode;
  slotTarget: SlotTarget;
  verify: boolean;
  disableVerity: boolean;
  disableVerification: boolean;
  force: boolean;
  noReboot: boolean;
  downgrade: boolean;
  temporaryRoot: boolean;
  dryRun: boolean;
}
export interface FlashPreview {
  revision: number;
  destructive: boolean;
  requiredConfirmation: string;
  label: string;
  targetSerial: string;
  targetSerials: string[];
  expectedDeviceState: string;
  dataBehavior: string;
  partitions: string[];
  slots: string[];
  commands: string[][];
}

export function FlashWizard({
  devices,
  selectedSerials,
  onSelectionChange,
  activeFirmware,
  operation,
  expertMode = false,
  onFirmwareChange,
  onPrepare,
  onStart,
}: {
  devices: Device[];
  selectedSerials: string[];
  onSelectionChange: (serials: string[]) => void | Promise<void>;
  activeFirmware?: Firmware | null;
  operation?: { status: OperationStatus | string; progress?: number; detail?: string } | null;
  expertMode?: boolean;
  onFirmwareChange: (firmware: Firmware) => Promise<void>;
  onPrepare: (plan: FlashPlan) => Promise<FlashPreview>;
  onStart: (plan: FlashPlan, confirmation: string, preview: FlashPreview) => Promise<void>;
}) {
  const { t } = useI18n();
  const [step, setStep] = useState(0);
  const [firmwareId, setFirmwareId] = useState(activeFirmware?.id ?? (window.pixelflasher?.__mock ? demoFirmwares[0].id : ''));
  const [mode, setMode] = useState<FlashMode>('keep');
  const [slotTarget, setSlotTarget] = useState<SlotTarget>('default');
  const [verify, setVerify] = useState(true);
  const [disableVerity, setDisableVerity] = useState(false);
  const [disableVerification, setDisableVerification] = useState(false);
  const [force, setForce] = useState(false);
  const [noReboot, setNoReboot] = useState(false);
  const [downgrade, setDowngrade] = useState(false);
  const [temporaryRoot, setTemporaryRoot] = useState(false);
  const [dryRun, setDryRun] = useState(false);
  const [confirmation, setConfirmation] = useState('');
  const [preview, setPreview] = useState<FlashPreview | null>(null);
  const [busy, setBusy] = useState(false);
  const [selectionBusy, setSelectionBusy] = useState(false);
  const [localError, setLocalError] = useState('');

  const firmwareOptions = useMemo(() => {
    if (window.pixelflasher?.__mock) return demoFirmwares;
    return activeFirmware ? [activeFirmware] : [];
  }, [activeFirmware]);
  const firmware = firmwareOptions.find((entry) => entry.id === firmwareId) ?? firmwareOptions[0];
  const targetSerial = selectedSerials[0] ?? '';
  const targets = devices.filter((device) => selectedSerials.includes(device.serial));
  const operationStatus = String(operation?.status ?? 'idle').toLowerCase();
  const isRunning = operationStatus === 'running' || operationStatus === 'pending';
  const canContinue = !selectionBusy && (step === 0 ? Boolean(targetSerial) : step === 1 ? Boolean(firmware) : true);

  const selectTarget = (serials: string[]) => {
    setSelectionBusy(true);
    void Promise.resolve(onSelectionChange(serials)).finally(() => setSelectionBusy(false));
  };

  useEffect(() => {
    if (mode !== 'ota') return;
    setSlotTarget('default');
    setDisableVerity(false);
    setDisableVerification(false);
    setForce(false);
    setDowngrade(false);
    setTemporaryRoot(false);
  }, [mode]);

  useEffect(() => {
    if (expertMode) return;
    setSlotTarget('default');
    setDisableVerity(false);
    setDisableVerification(false);
    setForce(false);
    setNoReboot(false);
    setDowngrade(false);
    setTemporaryRoot(false);
  }, [expertMode]);

  useEffect(() => {
    if (activeFirmware?.id && !firmwareOptions.some((entry) => entry.id === firmwareId)) {
      setFirmwareId(activeFirmware.id);
    }
  }, [activeFirmware, firmwareId, firmwareOptions]);

  useEffect(() => {
    setPreview(null);
    setConfirmation('');
    setLocalError('');
  }, [firmwareId, mode, slotTarget, verify, disableVerity, disableVerification, force, noReboot, downgrade, temporaryRoot, dryRun, selectedSerials.join('\u0000')]);

  const steps = useMemo(() => [
    { title: t('flash.step.devices'), detail: t('flash.devicesDetail') },
    { title: t('flash.step.firmware'), detail: t('flash.firmwareDetail') },
    { title: t('flash.step.options'), detail: t('flash.mode.keepDetail') },
    { title: t('flash.step.plan'), detail: t('flash.planDetail') },
    { title: t('flash.step.review'), detail: t('flash.reviewDetail') },
  ], [t]);

  const plan: FlashPlan | null = firmware ? {
    serials: [...selectedSerials],
    firmware,
    mode,
    slotTarget,
    verify,
    disableVerity,
    disableVerification,
    force,
    noReboot,
    downgrade,
    temporaryRoot,
    dryRun,
  } : null;

  const riskOptions = [
    disableVerity ? t('flash.review.disableVerity') : null,
    disableVerification ? t('flash.review.disableVerification') : null,
    force ? t('flash.review.force') : null,
    downgrade ? t('flash.review.downgrade') : null,
    noReboot ? t('flash.review.noReboot') : null,
    temporaryRoot ? t('flash.review.temporaryRoot') : null,
    dryRun ? t('flash.review.dryRun') : null,
  ].filter((value): value is string => Boolean(value));

  const needsConfirmation = Boolean(preview?.requiredConfirmation);
  const confirmationToken = preview?.requiredConfirmation ?? '';
  const confirmationMatches = !needsConfirmation || confirmation === confirmationToken;

  const planRows: Array<[AssetName, string, string]> = [
    ['scan', t('flash.plan.validate'), t('flash.plan.validateDetail', { count: targets.length })],
    ['shield', t('flash.plan.verify'), verify ? t('flash.plan.verifyEnabled') : t('flash.plan.verifySkipped')],
    ['flashPng', dryRun ? t('flash.plan.simulate') : t('flash.plan.write'), firmware?.build ?? '—'],
    [
      'slot',
      slotTarget === 'both' ? t('flash.plan.slotBoth') : slotTarget === 'inactive' ? t('flash.plan.slotInactive') : t('flash.plan.slotDefault'),
      t(`flash.mode.${mode}`),
    ],
    ['rebootPng', t('flash.plan.finish'), noReboot ? t('flash.plan.noReboot') : t('flash.plan.reboot')],
  ];

  const next = async () => {
    if (!canContinue || !plan) return;
    setBusy(true);
    setLocalError('');
    try {
      if (step === 1) await onFirmwareChange(firmware);
      if (step === 3) setPreview(await onPrepare(plan));
      setStep((value) => Math.min(4, value + 1));
    } catch (error) {
      setLocalError(error instanceof Error ? error.message : t('notice.error'));
    } finally {
      setBusy(false);
    }
  };

  const start = async () => {
    if (!plan || !preview || !confirmationMatches) return;
    setBusy(true);
    setLocalError('');
    try {
      await onStart(plan, confirmation, preview);
    } catch (error) {
      setLocalError(error instanceof Error ? error.message : t('notice.error'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card className="wizard-card">
      <ol className="wizard-steps" aria-label={t('flash.title')}>
        {stepKeys.map((key, index) => (
          <li className={`${index === step ? 'is-current' : ''} ${index < step ? 'is-complete' : ''}`} key={key}>
            <button type="button" onClick={() => index <= step && setStep(index)} aria-current={index === step ? 'step' : undefined}>
              <span className="wizard-step__number">{index < step ? <Icon name="check" size={14} /> : index + 1}</span>
              <span>{t(key)}</span>
            </button>
          </li>
        ))}
      </ol>

      <div className="wizard-body">
        <div className="wizard-heading">
          <span className="wizard-heading__eyebrow">{String(step + 1).padStart(2, '0')} / 05</span>
          <h2>{steps[step].title}</h2>
          <p>{steps[step].detail}</p>
        </div>

        {step === 0 ? (
          <div className="wizard-panel">
            <CardTitle icon="devices">{t('flash.devicesTitle')}</CardTitle>
            <DeviceSelector
              devices={devices}
              selected={selectedSerials}
              onChange={selectTarget}
              selectionMode="multiple"
              ariaLabel={t('flash.devicesTitle')}
            />
            {!targetSerial ? (
              <div className="inline-alert inline-alert--warning" role="alert">
                <Icon name="warning" size={18} />
                <span>{t('flash.needDevice')}</span>
              </div>
            ) : null}
          </div>
        ) : null}

        {step === 1 ? (
          <div className="wizard-panel firmware-options" role="radiogroup" aria-label={t('flash.firmwareTitle')}>
            {firmwareOptions.map((entry) => (
              <label className={`select-card ${firmwareId === entry.id ? 'is-selected' : ''}`} key={entry.id}>
                <input type="radio" name="firmware" value={entry.id} checked={firmwareId === entry.id} onChange={() => setFirmwareId(entry.id)} />
                <span className="select-card__visual"><Icon name={entry.kind === 'ota' ? 'download' : 'firmware'} size={28} /></span>
                <span className="select-card__copy">
                  <span className="select-card__heading"><strong>{entry.name}</strong><Badge tone={entry.channel === 'stable' ? 'success' : 'warning'}>{t(`common.${entry.channel}`)}</Badge></span>
                  <span>{entry.build} · {entry.size}</span>
                  <small>{entry.kind.toUpperCase()} · {entry.device} · {entry.securityPatch}</small>
                </span>
              </label>
            ))}
            {!firmwareOptions.length ? (
              <div className="empty-state">
                <Icon name="firmware" size={38} />
                <strong>{t('flash.firmwareTitle')}</strong>
                <span>{t('firmware.import')}</span>
              </div>
            ) : null}
          </div>
        ) : null}

        {step === 2 ? (
          <div className="wizard-panel wizard-options">
            <fieldset className="mode-fieldset">
              <legend>{t('flash.optionsTitle')}</legend>
              {(['keep', 'wipe', 'ota'] as FlashMode[]).map((value) => (
                <label className={`mode-option ${mode === value ? 'is-selected' : ''}`} key={value}>
                  <input type="radio" name="flash-mode" value={value} checked={mode === value} onChange={() => setMode(value)} />
                  <Icon name={value === 'wipe' ? 'warningPng' : value === 'ota' ? 'download' : 'shield'} size={25} />
                  <span><strong>{t(`flash.mode.${value}`)}</strong><small>{t(`flash.mode.${value}Detail`)}</small></span>
                </label>
              ))}
            </fieldset>
            {expertMode ? (
              <fieldset className="mode-fieldset" disabled={mode === 'ota'}>
                <legend>{t('flash.slot.title')}</legend>
                {(['default', 'inactive', 'both'] as SlotTarget[]).map((value) => (
                  <label className={`mode-option ${slotTarget === value ? 'is-selected' : ''}`} key={value}>
                    <input type="radio" name="slot-target" value={value} checked={slotTarget === value} onChange={() => setSlotTarget(value)} />
                    <Icon name={value === 'both' ? 'switchSlot' : value === 'inactive' ? 'slotB' : 'slot'} size={25} />
                    <span><strong>{t(`flash.slot.${value}`)}</strong><small>{mode === 'ota' ? t('flash.option.otaDisabled') : t(`flash.slot.${value}Detail`)}</small></span>
                  </label>
                ))}
              </fieldset>
            ) : null}
            <div className="toggle-stack wizard-options__toggles">
              <Toggle checked={verify} onChange={setVerify} label={t('flash.option.verify')} />
              {expertMode ? (
                <>
                  <Toggle checked={disableVerity} onChange={setDisableVerity} label={t('flash.option.disableVerity')} description={mode === 'ota' ? t('flash.option.otaDisabled') : undefined} disabled={mode === 'ota'} />
                  <Toggle checked={disableVerification} onChange={setDisableVerification} label={t('flash.option.disableVerification')} description={mode === 'ota' ? t('flash.option.otaDisabled') : undefined} disabled={mode === 'ota'} />
                  <Toggle checked={force} onChange={setForce} label={t('flash.option.force')} description={mode === 'ota' ? t('flash.option.otaDisabled') : undefined} disabled={mode === 'ota'} />
                  <Toggle checked={noReboot} onChange={setNoReboot} label={t('flash.option.noReboot')} />
                  <Toggle checked={downgrade} onChange={setDowngrade} label={t('flash.option.downgrade')} description={mode === 'ota' ? t('flash.option.otaDisabled') : undefined} disabled={mode === 'ota'} />
                  <Toggle checked={temporaryRoot} onChange={setTemporaryRoot} label={t('flash.option.temporaryRoot')} description={mode === 'ota' ? t('flash.option.otaDisabled') : undefined} disabled={mode === 'ota'} />
                </>
              ) : null}
              <Toggle checked={dryRun} onChange={setDryRun} label={t('flash.option.dryRun')} />
            </div>
          </div>
        ) : null}

        {step === 3 ? (
          <div className="wizard-panel plan-panel">
            <div className="plan-list">
              {planRows.map(([icon, title, detail], index) => (
                <div className="plan-row" key={title}>
                  <span className="plan-row__index">{index + 1}</span>
                  <Icon name={icon} size={20} />
                  <span><strong>{title}</strong><small>{detail}</small></span>
                </div>
              ))}
            </div>
            <div className="inline-alert">
              <Icon name="shield" size={18} />
              <span>{dryRun ? t('flash.plan.dryNotice') : t('flash.plan.safeNotice')}</span>
            </div>
          </div>
        ) : null}

        {step === 4 ? (
          <div className="wizard-panel review-panel">
            <div className="review-summary">
              <div><span>{t('flash.review.targets')}</span><strong>{targets.map((device) => device.name).join(', ')}</strong><small>{targets.map((device) => device.serial).join(', ') || t('status.targets', { count: 0 })}</small></div>
              <div><span>{t('flash.review.firmware')}</span><strong>{firmware?.name ?? '—'}</strong><small>{firmware?.build ?? '—'}</small></div>
              <div><span>{t('flash.review.mode')}</span><strong>{t(`flash.mode.${mode}`)}</strong><small>{t(`flash.mode.${mode}Detail`)}</small></div>
              <div><span>{t('flash.review.slot')}</span><strong>{t(`flash.slot.${slotTarget}`)}</strong><small>{t(`flash.slot.${slotTarget}Detail`)}</small></div>
            </div>

            <div className="review-risks">
              <div>
                <span>{t('flash.review.safeguards')}</span>
                <Badge tone={verify ? 'success' : 'warning'}>{verify ? t('flash.review.checksums') : t('flash.plan.verifySkipped')}</Badge>
              </div>
              <div>
                <span>{t('flash.review.risks')}</span>
                <div className="risk-badges">
                  {riskOptions.length ? riskOptions.map((risk) => <Badge tone={dryRun && risk === t('flash.review.dryRun') ? 'accent' : 'warning'} key={risk}>{risk}</Badge>) : <Badge tone="success">{t('flash.review.noRisk')}</Badge>}
                </div>
              </div>
            </div>

            <section className="exact-plan" aria-labelledby="exact-plan-title">
              <div className="exact-plan__header">
                <span className="exact-plan__title">
                  <Icon name="shield" size={19} />
                  <span><strong id="exact-plan-title">{t('flash.exactPlan')}</strong><small>{preview?.label ?? '—'}</small></span>
                </span>
                <Badge tone={preview?.destructive ? 'warning' : 'success'}>{preview?.dataBehavior || '—'}</Badge>
              </div>
              <dl className="exact-plan__facts">
                <div><dt>{t('flash.review.targets')}</dt><dd><code>{preview?.targetSerials.join(', ') || preview?.targetSerial || '—'}</code></dd></div>
                <div><dt>{t('dashboard.deviceMode')}</dt><dd>{preview?.expectedDeviceState || '—'}</dd></div>
                <div><dt>{t('tools.partition')}</dt><dd>{preview?.partitions.length ? preview.partitions.join(', ') : '—'}</dd></div>
                <div><dt>{t('flash.review.slot')}</dt><dd>{preview?.slots.length ? preview.slots.join(', ') : '—'}</dd></div>
              </dl>
              <div className="exact-plan__commands">
                <strong>{t('flash.exactCommands')}</strong>
                <ol>
                  {(preview?.commands ?? []).map((argv, index) => (
                    <li key={`${index}-${argv.join('\u0000')}`}><code>{argv.join(' ')}</code></li>
                  ))}
                </ol>
              </div>
            </section>

            {needsConfirmation ? (
              <label className="confirmation-field">
                <span><strong>{t('flash.confirm.title')}</strong><small>{t('flash.confirm.detail', { confirmation: confirmationToken })}</small></span>
                <input
                  type="text"
                  value={confirmation}
                  onChange={(event) => setConfirmation(event.currentTarget.value)}
                  placeholder={confirmationToken}
                  autoComplete="off"
                  spellCheck={false}
                />
              </label>
            ) : null}

            {localError ? (
              <div className="inline-alert inline-alert--warning" role="alert">
                <Icon name="warningPng" size={18} />
                <span>{localError}</span>
              </div>
            ) : null}

            {operation && operationStatus !== 'idle' ? (
              <div className={`operation operation--${operationStatus}`} aria-live="polite">
                <div className="operation__title">
                  <Icon name={operationStatus === 'success' ? 'check' : operationStatus === 'failed' || operationStatus === 'cancelled' ? 'warningPng' : 'flashPng'} size={20} />
                  <strong>{operationStatus === 'success' ? t('flash.success') : operationStatus === 'failed' ? t('flash.failed') : operationStatus === 'cancelled' ? t('flash.cancelled') : t('flash.running')}</strong>
                </div>
                <Meter value={operation.progress ?? 0} label={operation.detail ?? t('flash.running')} />
              </div>
            ) : null}
            <Button variant="primary" icon="flashPng" onClick={() => void start()} disabled={busy || isRunning || !targetSerial || !preview || !confirmationMatches}>
              {dryRun ? t('flash.simulate') : t('flash.start')}
            </Button>
          </div>
        ) : null}
      </div>

      <div className="wizard-footer">
        <Button icon="left" onClick={() => setStep((value) => Math.max(0, value - 1))} disabled={step === 0 || isRunning || busy}>
          {t('common.back')}
        </Button>
        <span className="wizard-footer__selection">{selectedSerials.length} {t('common.selected').toLowerCase()}</span>
        {step < 4 ? (
          <Button variant="primary" icon="right" onClick={() => void next()} disabled={!canContinue || isRunning || busy}>
            {busy ? t('flash.preparing') : step === 3 ? t('flash.prepare') : t('common.continue')}
          </Button>
        ) : null}
      </div>
    </Card>
  );
}
