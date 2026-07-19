import { useEffect, useRef, useState } from 'react';
import { commands } from '../../commands';
import { useI18n } from '../../i18n';
import type { ActiveOperation, Device } from '../../types';
import { Badge, Button, Card, CardTitle, Icon } from '../../components/ui';
import { record, type SharedPageProps } from '../shared';

type OpenUrlReceipt = {
  action: 'openUrl';
  targetSerial: string;
  scheme: 'http' | 'https';
  host: string;
  urlSha256: string;
  intentAccepted: true;
};

type OpenUrlState =
  | { phase: 'idle' }
  | { phase: 'running' | 'cancelling' }
  | { phase: 'success'; receipt: OpenUrlReceipt }
  | { phase: 'cancelled' | 'error'; code?: string };

const SAFE_CODE = /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/;
const SAFE_HOST = /^[A-Za-z0-9.:-]{1,253}$/;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const SHA256 = /^[0-9a-f]{64}$/;

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]) {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function isCanonicalHost(value: string) {
  if (!SAFE_HOST.test(value) || value !== value.toLowerCase()) return false;
  if (!value.includes(':') && value.split('.').some((label) => !DNS_LABEL.test(label))) return false;
  try {
    const literal = value.includes(':') ? `[${value}]` : value;
    return new URL(`https://${literal}/`).hostname.replace(/^\[|\]$/g, '').toLowerCase() === value;
  } catch {
    return false;
  }
}

export function parseOpenUrlReceipt(value: unknown, serial: string): OpenUrlReceipt | null {
  const source = record(value);
  if (
    !hasExactKeys(source, ['action', 'targetSerial', 'scheme', 'host', 'urlSha256', 'intentAccepted'])
    || source.action !== 'openUrl'
    || source.targetSerial !== serial
    || !['http', 'https'].includes(String(source.scheme))
    || typeof source.host !== 'string'
    || !isCanonicalHost(source.host)
    || typeof source.urlSha256 !== 'string'
    || !SHA256.test(source.urlSha256)
    || source.intentAccepted !== true
  ) return null;
  return {
    action: 'openUrl',
    targetSerial: serial,
    scheme: source.scheme as 'http' | 'https',
    host: source.host,
    urlSha256: source.urlSha256.toLowerCase(),
    intentAccepted: true,
  };
}

export function DeviceOpenUrlPanel({
  device,
  toolchainReady,
  activeOperation,
  onCommand,
}: {
  device?: Device;
  toolchainReady: boolean;
  activeOperation?: ActiveOperation | null;
  onCommand: SharedPageProps['onCommand'];
}) {
  const { t } = useI18n();
  const [url, setUrl] = useState('https://');
  const [state, setState] = useState<OpenUrlState>({ phase: 'idle' });
  const requestEpoch = useRef(0);
  const inFlight = useRef(false);
  const cancelling = useRef(false);
  const feedbackRef = useRef<HTMLElement>(null);
  const serial = device?.serial ?? '';
  const ready = Boolean(device && device.mode === 'adb' && toolchainReady);
  const pending = state.phase === 'running' || state.phase === 'cancelling';
  const cancellableOperation = pending
    && activeOperation
    && activeOperation.kind === commands.deviceOpenUrl
    && (activeOperation.targetSerial ?? activeOperation.target_serial) === serial
    && ['pending', 'running'].includes(activeOperation.status.toLowerCase())
    ? activeOperation
    : null;

  useEffect(() => {
    requestEpoch.current += 1;
    inFlight.current = false;
    cancelling.current = false;
    setState({ phase: 'idle' });
    setUrl('https://');
    return () => { requestEpoch.current += 1; };
  }, [device?.mode, serial, toolchainReady]);

  useEffect(() => {
    if (['success', 'cancelled', 'error'].includes(state.phase)) {
      window.requestAnimationFrame(() => feedbackRef.current?.focus());
    }
  }, [state.phase]);

  const openUrl = async () => {
    if (!ready || !device || inFlight.current || !url.trim()) return;
    inFlight.current = true;
    const epoch = requestEpoch.current + 1;
    requestEpoch.current = epoch;
    setState({ phase: 'running' });
    try {
      const response = await onCommand(commands.deviceOpenUrl, {
        serial: device.serial,
        url: url.trim(),
      });
      if (requestEpoch.current !== epoch) return;
      const result = record(response?.result);
      const status = typeof result.status === 'string' ? result.status.toLowerCase() : '';
      const code = typeof result.code === 'string' && SAFE_CODE.test(result.code) ? result.code : undefined;
      if (status === 'cancelled') {
        setState({ phase: 'cancelled', code });
        return;
      }
      if (status !== 'success') {
        setState({ phase: 'error', code });
        return;
      }
      const receipt = parseOpenUrlReceipt(result.value, device.serial);
      if (!receipt) {
        setState({ phase: 'error', code: 'invalid_typed_receipt' });
        return;
      }
      setUrl('https://');
      setState({ phase: 'success', receipt });
    } catch {
      if (requestEpoch.current === epoch) setState({ phase: 'error' });
    } finally {
      if (requestEpoch.current === epoch) inFlight.current = false;
    }
  };

  const cancel = async () => {
    if (!cancellableOperation || state.phase !== 'running' || cancelling.current) return;
    cancelling.current = true;
    setState({ phase: 'cancelling' });
    try {
      const response = await onCommand(commands.operationCancel, {
        operationId: cancellableOperation.id,
      });
      const acknowledgement = record(response?.result);
      if (!response || acknowledgement.accepted === false) {
        setState((current) => current.phase === 'cancelling' ? { phase: 'running' } : current);
      }
    } finally {
      cancelling.current = false;
    }
  };

  return (
    <Card className="device-open-url-card" aria-busy={pending}>
      <CardTitle icon="androidPng" after={ready && device ? <Badge tone="success">ADB · {device.serial}</Badge> : null}>
        {t('device.openUrlTitle')}
      </CardTitle>
      <p className="device-inspection-card__detail">{t('device.openUrlDetail')}</p>
      {!ready ? (
        <div className="inline-alert inline-alert--warning device-inspection-guard" role="status">
          <Icon name="warningPng" size={18} />
          <span>{t('device.openUrlGuard')}</span>
        </div>
      ) : null}
      <div className="device-open-url-form">
        <label htmlFor="device-open-url-input">
          <span>{t('device.openUrlLabel')}</span>
          <input
            id="device-open-url-input"
            type="url"
            inputMode="url"
            autoCapitalize="none"
            autoCorrect="off"
            autoComplete="off"
            spellCheck={false}
            value={url}
            maxLength={2048}
            disabled={!ready || pending}
            onChange={(event) => setUrl(event.currentTarget.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') {
                event.preventDefault();
                void openUrl();
              }
            }}
          />
        </label>
        <Button
          variant="primary"
          icon="androidPng"
          disabled={!ready || pending || !url.trim()}
          onClick={() => void openUrl()}
        >
          {t('device.openUrlAction')}
        </Button>
      </div>
      {pending ? (
        <div className="device-inspection-progress" role="status" aria-live="polite">
          <span className="status-dot" aria-hidden="true" />
          <span>{t(state.phase === 'cancelling' ? 'device.openUrlCancelling' : 'device.openUrlRunning')}</span>
          {cancellableOperation && state.phase === 'running' ? (
            <Button variant="ghost" onClick={() => void cancel()}>{t('device.openUrlCancel')}</Button>
          ) : null}
        </div>
      ) : null}
      {state.phase === 'success' ? (
        <section className="device-open-url-receipt" ref={feedbackRef} tabIndex={-1} role="status">
          <Icon name="check" size={18} />
          <span>
            <strong>{t('device.openUrlSucceeded')}</strong>
            <small>{state.receipt.scheme} · {state.receipt.host}</small>
          </span>
          <code>{state.receipt.urlSha256}</code>
        </section>
      ) : null}
      {state.phase === 'cancelled' ? (
        <section className="device-inspection-feedback" ref={feedbackRef} tabIndex={-1} role="status">
          <Icon name="warningPng" size={18} />
          <span><strong>{t('device.openUrlCancelled')}</strong>{state.code ? <code>{state.code}</code> : null}</span>
        </section>
      ) : null}
      {state.phase === 'error' ? (
        <section className="device-inspection-feedback device-inspection-feedback--error" ref={feedbackRef} tabIndex={-1} role="alert">
          <Icon name="warningPng" size={18} />
          <span><strong>{t('device.openUrlFailed')}</strong>{state.code ? <code>{state.code}</code> : null}</span>
        </section>
      ) : null}
    </Card>
  );
}
