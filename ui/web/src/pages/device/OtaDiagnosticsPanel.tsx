import { useEffect, useRef, useState } from 'react';
import type { AssetName } from '../../assets';
import { commands } from '../../commands';
import { useI18n } from '../../i18n';
import type { ActiveOperation, Device } from '../../types';
import { Badge, Button, Card, CardTitle, Icon } from '../../components/ui';
import { record, type SharedPageProps } from '../shared';

export type OtaDiagnosticAction = 'status' | 'certificates' | 'logs' | 'reset';

type OtaStatusReport = {
  action: 'status';
  state: 'idle' | 'checking_for_update' | 'update_available' | 'downloading' | 'verifying'
    | 'finalizing' | 'updated_need_reboot' | 'reporting_error_event' | 'attempting_rollback' | 'disabled';
  progress: number;
  idle: boolean;
  lastAttemptError: string | null;
  bounded: true;
};

type OtaCertificatesReport = {
  action: 'certificates';
  archivePresent: true;
  count: number;
  entries: string[];
  bounded: true;
};

type OtaLogsReport = {
  action: 'logs';
  lineCount: number;
  lines: string[];
  redactedCount: number;
  bounded: true;
};

type OtaResetReport = {
  action: 'reset';
  idle: true;
  bounded: true;
};

export type OtaDiagnosticReport = OtaStatusReport | OtaCertificatesReport | OtaLogsReport | OtaResetReport;

type DiagnosticState =
  | { phase: 'idle' }
  | { phase: 'running' | 'cancelling'; action: OtaDiagnosticAction }
  | { phase: 'success'; action: OtaDiagnosticAction; report: OtaDiagnosticReport }
  | { phase: 'cancelled' | 'error'; action: OtaDiagnosticAction; code?: string };

const MAX_CERTIFICATE_ENTRIES = 1_024;
const MAX_CERTIFICATE_NAME_BYTES = 256;
const MAX_CERTIFICATE_OUTPUT_BYTES = 256 * 1_024;
const MAX_LOG_LINES = 5_000;
const REQUESTED_LOG_LINES = 1_000;
const MAX_LOG_LINE_BYTES = 4_096;
const SAFE_CODE = /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/;
const SAFE_STATUS_VALUE = /^[A-Za-z0-9_.:+-]{1,128}$/;
const UNSAFE_CERTIFICATE_CHARACTER = /[\p{C}\p{Zl}\p{Zp}]/u;
const UNSAFE_LOG_CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
const OTA_STATES = new Set([
  'idle', 'checking_for_update', 'update_available', 'downloading', 'verifying', 'finalizing',
  'updated_need_reboot', 'reporting_error_event', 'attempting_rollback', 'disabled',
]);

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]) {
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}

function boundedInteger(value: unknown, maximum: number) {
  return typeof value === 'number'
    && Number.isSafeInteger(value)
    && value >= 0
    && value <= maximum
    ? value
    : null;
}

function boundedText(value: unknown, maximumBytes: number) {
  return typeof value === 'string'
    && new TextEncoder().encode(value).length <= maximumBytes
    && !value.includes('\0')
    ? value
    : null;
}

function safeCertificateEntry(value: unknown) {
  const entry = boundedText(value, MAX_CERTIFICATE_NAME_BYTES);
  if (
    entry === null
    || !entry
    || entry.includes('\\')
    || entry.startsWith('/')
    || entry.split('/').some((part) => !part || part === '.' || part === '..')
  ) return null;
  return UNSAFE_CERTIFICATE_CHARACTER.test(entry) ? null : entry;
}

function parseCertificates(value: Record<string, unknown>): OtaCertificatesReport | null {
  if (
    !hasExactKeys(value, ['action', 'archivePresent', 'count', 'entries', 'bounded'])
    || value.action !== 'certificates'
    || value.archivePresent !== true
    || value.bounded !== true
    || !Array.isArray(value.entries)
    || value.entries.length > MAX_CERTIFICATE_ENTRIES
  ) return null;
  const entries = value.entries.flatMap((entry) => {
    const parsed = safeCertificateEntry(entry);
    return parsed === null ? [] : [parsed];
  });
  const count = boundedInteger(value.count, MAX_CERTIFICATE_ENTRIES);
  const outputBytes = new TextEncoder().encode(entries.join('\n')).length;
  if (
    !entries.length
    || entries.length !== value.entries.length
    || count !== entries.length
    || outputBytes > MAX_CERTIFICATE_OUTPUT_BYTES
  ) return null;
  return { action: 'certificates', archivePresent: true, count, entries, bounded: true };
}

function parseLogs(value: Record<string, unknown>): OtaLogsReport | null {
  if (
    !hasExactKeys(value, ['action', 'lineCount', 'lines', 'redactedCount', 'bounded'])
    || value.action !== 'logs'
    || value.bounded !== true
    || !Array.isArray(value.lines)
    || value.lines.length > MAX_LOG_LINES
  ) return null;
  const lines = value.lines.flatMap((line) => {
    const parsed = boundedText(line, MAX_LOG_LINE_BYTES);
    return parsed !== null
      && !UNSAFE_LOG_CONTROL.test(parsed)
      && parsed.toLowerCase().includes('update_engine')
      ? [parsed]
      : [];
  });
  const lineCount = boundedInteger(value.lineCount, MAX_LOG_LINES);
  const redactedCount = boundedInteger(value.redactedCount, MAX_LOG_LINES);
  if (lines.length !== value.lines.length || lineCount !== lines.length || redactedCount === null) return null;
  return { action: 'logs', lineCount, lines, redactedCount, bounded: true };
}

function parseStatus(value: Record<string, unknown>): OtaStatusReport | null {
  if (
    !hasExactKeys(value, ['action', 'state', 'progress', 'idle', 'lastAttemptError', 'bounded'])
    || value.action !== 'status'
    || value.bounded !== true
    || typeof value.state !== 'string'
    || !OTA_STATES.has(value.state)
    || typeof value.progress !== 'number'
    || !Number.isFinite(value.progress)
    || value.progress < 0
    || value.progress > 1
    || typeof value.idle !== 'boolean'
    || value.idle !== (value.state === 'idle')
    || (value.lastAttemptError !== null && (
      typeof value.lastAttemptError !== 'string' || !SAFE_STATUS_VALUE.test(value.lastAttemptError)
    ))
  ) return null;
  return value as OtaStatusReport;
}

function parseReset(value: Record<string, unknown>): OtaResetReport | null {
  return hasExactKeys(value, ['action', 'idle', 'bounded'])
    && value.action === 'reset'
    && value.idle === true
    && value.bounded === true
    ? { action: 'reset', idle: true, bounded: true }
    : null;
}

export function parseOtaDiagnosticReport(
  action: OtaDiagnosticAction,
  value: unknown,
): OtaDiagnosticReport | null {
  const source = record(value);
  if (source.action !== action) return null;
  if (action === 'status') return parseStatus(source);
  if (action === 'certificates') return parseCertificates(source);
  return action === 'logs' ? parseLogs(source) : parseReset(source);
}

function actionLabel(action: OtaDiagnosticAction) {
  if (action === 'status') return 'device.otaStatus';
  if (action === 'certificates') return 'device.otaCertificates';
  return action === 'logs' ? 'device.otaLogs' : 'device.otaReset';
}

function actionCommand(action: OtaDiagnosticAction) {
  if (action === 'status') return commands.deviceOtaStatus;
  if (action === 'certificates') return commands.deviceOtaCertificates;
  return action === 'logs' ? commands.deviceOtaLogs : commands.deviceOtaReset;
}

export function OtaDiagnosticsPanel({
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
  const [state, setState] = useState<DiagnosticState>({ phase: 'idle' });
  const requestEpoch = useRef(0);
  const feedbackRef = useRef<HTMLElement>(null);
  const serial = device?.serial ?? '';
  const ready = Boolean(device && device.mode === 'adb' && toolchainReady);
  const busy = state.phase === 'running' || state.phase === 'cancelling';
  const operationRunning = Boolean(
    activeOperation && ['pending', 'running'].includes(activeOperation.status.toLowerCase()),
  );
  const expectedOperationKind = state.phase === 'running' || state.phase === 'cancelling'
    ? actionCommand(state.action)
    : null;
  const cancellableOperation = busy
    && operationRunning
    && activeOperation?.kind === expectedOperationKind
    ? activeOperation
    : null;
  const anotherOperationRunning = operationRunning && !busy;
  const progress = typeof cancellableOperation?.progress === 'number'
    && Number.isFinite(cancellableOperation.progress)
    ? Math.min(100, Math.max(0, cancellableOperation.progress))
    : null;

  useEffect(() => {
    requestEpoch.current += 1;
    setState({ phase: 'idle' });
    return () => { requestEpoch.current += 1; };
  }, [device?.mode, serial, toolchainReady]);

  useEffect(() => {
    if (['success', 'cancelled', 'error'].includes(state.phase)) {
      window.requestAnimationFrame(() => feedbackRef.current?.focus());
    }
  }, [state.phase]);

  const run = async (action: OtaDiagnosticAction) => {
    if (!ready || !device || busy || anotherOperationRunning || (action === 'reset' && !device.rooted)) return;
    const epoch = requestEpoch.current + 1;
    requestEpoch.current = epoch;
    setState({ phase: 'running', action });
    try {
      const command = actionCommand(action);
      const payload = action === 'logs'
        ? { serial: device.serial, maxLines: REQUESTED_LOG_LINES }
        : { serial: device.serial };
      const response = await onCommand(command, payload, { returnCancelled: true });
      if (requestEpoch.current !== epoch) return;
      const result = record(response?.result);
      const status = typeof result.status === 'string' ? result.status.toLowerCase() : '';
      const code = typeof result.code === 'string' && SAFE_CODE.test(result.code) ? result.code : undefined;
      if (status === 'cancelled') {
        setState({ phase: 'cancelled', action, code });
        return;
      }
      if (!response || status !== 'success') {
        setState({ phase: 'error', action, code });
        return;
      }
      const report = parseOtaDiagnosticReport(action, result.value);
      setState(report
        ? { phase: 'success', action, report }
        : { phase: 'error', action, code: 'invalid_typed_report' });
    } catch {
      if (requestEpoch.current === epoch) setState({ phase: 'error', action });
    }
  };

  const cancel = async () => {
    if (!cancellableOperation || state.phase !== 'running') return;
    setState({ phase: 'cancelling', action: state.action });
    try {
      const response = await onCommand(commands.operationCancel, {
        operationId: cancellableOperation.id,
      });
      const result = record(response?.result);
      const status = typeof result.status === 'string' ? result.status.toLowerCase() : '';
      if (!response || result.accepted === false || status === 'failed') {
        setState((current) => current.phase === 'cancelling'
          ? { phase: 'running', action: current.action }
          : current);
      }
    } catch {
      setState((current) => current.phase === 'cancelling'
        ? { phase: 'running', action: current.action }
        : current);
    }
  };

  const actions: Array<{
    action: OtaDiagnosticAction;
    icon: AssetName;
    title: string;
    detail: string;
    requiresRoot?: boolean;
  }> = [
    {
      action: 'status',
      icon: 'check',
      title: t('device.otaStatus'),
      detail: t('device.otaStatusDetail'),
    },
    {
      action: 'certificates',
      icon: 'shield',
      title: t('device.otaCertificates'),
      detail: t('device.otaCertificatesDetail'),
    },
    {
      action: 'logs',
      icon: 'logs',
      title: t('device.otaLogs'),
      detail: t('device.otaLogsDetail'),
    },
    {
      action: 'reset',
      icon: 'reboot',
      title: t('device.otaReset'),
      detail: t('device.otaResetDetail'),
      requiresRoot: true,
    },
  ];

  return (
    <Card className="device-inspection-card ota-diagnostics-card" aria-busy={busy}>
      <CardTitle icon="firmware" after={ready && device ? <Badge tone="success">ADB · {device.serial}</Badge> : null}>
        {t('device.otaTitle')}
      </CardTitle>
      <p className="device-inspection-card__detail">{t('device.otaDetail')}</p>
      {!ready ? (
        <div className="inline-alert inline-alert--warning device-inspection-guard" role="status">
          <Icon name="warningPng" size={18} />
          <span>{t('device.otaGuard')}</span>
        </div>
      ) : null}
      {ready && device && !device.rooted ? (
        <div className="inline-alert inline-alert--warning device-inspection-guard" role="status">
          <Icon name="warningPng" size={18} />
          <span>{t('device.otaResetRootGuard')}</span>
        </div>
      ) : null}
      <div className="device-inspection-actions">
        {actions.map((item) => {
          const descriptionId = `ota-${item.action}-description`;
          return (
            <section className="device-inspection-action" key={item.action}>
              <span className="device-operation-group__icon"><Icon name={item.icon} size={23} /></span>
              <div>
                <Button
                  variant="ghost"
                  onClick={() => void run(item.action)}
                  disabled={!ready || busy || anotherOperationRunning || (item.requiresRoot && !device?.rooted)}
                  aria-describedby={descriptionId}
                >
                  {item.title}
                </Button>
                <small id={descriptionId}>{item.detail}</small>
              </div>
            </section>
          );
        })}
      </div>
      {busy ? (
        <div className="device-inspection-progress" role="status" aria-live="polite">
          <span className="status-dot" aria-hidden="true" />
          <span>{t(state.phase === 'cancelling' ? 'device.otaCancelling' : 'device.otaRunning')}</span>
          {progress !== null ? <progress aria-label={t('device.otaProgress')} max={100} value={progress} /> : null}
          {cancellableOperation && state.phase === 'running' ? (
            <Button variant="ghost" onClick={() => void cancel()}>{t('device.otaCancel')}</Button>
          ) : null}
        </div>
      ) : null}
      {state.phase === 'cancelled' ? (
        <section className="device-inspection-feedback" ref={feedbackRef} tabIndex={-1} role="status" aria-live="polite">
          <Icon name="warningPng" size={18} />
          <span><strong>{t('device.otaCancelled')}</strong>{state.code ? <code>{state.code}</code> : null}</span>
        </section>
      ) : null}
      {state.phase === 'error' ? (
        <section className="device-inspection-feedback device-inspection-feedback--error" ref={feedbackRef} tabIndex={-1} role="alert">
          <Icon name="warningPng" size={18} />
          <span><strong>{t('device.otaFailed')}</strong>{state.code ? <code>{state.code}</code> : null}</span>
        </section>
      ) : null}
      {state.phase === 'success' ? <OtaDiagnosticResult state={state} feedbackRef={feedbackRef} /> : null}
    </Card>
  );
}

function OtaDiagnosticResult({
  state,
  feedbackRef,
}: {
  state: Extract<DiagnosticState, { phase: 'success' }>;
  feedbackRef: React.RefObject<HTMLElement | null>;
}) {
  const { t } = useI18n();
  const headingId = `ota-result-${state.action}`;
  const report = state.report;
  return (
    <section className="device-inspection-result" ref={feedbackRef} tabIndex={-1} aria-labelledby={headingId} aria-live="polite">
      <header>
        <span>
          <Badge tone="success">{t('status.ready')}</Badge>
          <h2 id={headingId}>{t(actionLabel(state.action))}</h2>
        </span>
      </header>
      {report.action === 'status' ? (
        <dl className="device-inspection-summary device-inspection-summary--compact">
          <div><dt>{t('device.otaState')}</dt><dd><code>{report.state}</code></dd></div>
          <div><dt>{t('device.otaStatusProgress')}</dt><dd>{Math.round(report.progress * 100)}%</dd></div>
          <div><dt>{t('device.otaIdle')}</dt><dd>{report.idle ? t('device.otaIdleYes') : t('device.otaIdleNo')}</dd></div>
          <div><dt>{t('device.otaLastError')}</dt><dd><code>{report.lastAttemptError ?? t('common.none')}</code></dd></div>
        </dl>
      ) : report.action === 'certificates' ? (
        <>
          <dl className="device-inspection-summary device-inspection-summary--compact">
            <div><dt>{t('device.otaArchive')}</dt><dd>{t('device.otaPresent')}</dd></div>
            <div><dt>{t('device.otaCertificateCount')}</dt><dd>{report.count}</dd></div>
            <div><dt>{t('device.otaBound')}</dt><dd>{t('device.otaBounded')}</dd></div>
          </dl>
          <ul className="ota-certificate-list" aria-label={t('device.otaCertificates')}>
            {report.entries.map((entry, index) => <li key={`${index}-${entry}`}><code>{entry}</code></li>)}
          </ul>
        </>
      ) : report.action === 'logs' ? (
        <>
          <div className="device-inspection-meta">
            <Badge tone="accent">{t('device.otaLogLines', { count: report.lineCount })}</Badge>
            <Badge tone="neutral">{t('device.otaRedacted', { count: report.redactedCount })}</Badge>
            <Badge tone="neutral">{t('device.otaBounded')}</Badge>
          </div>
          {report.lines.length ? (
            <pre tabIndex={0} aria-label={t('device.otaLogs')}>{report.lines.join('\n')}</pre>
          ) : (
            <p className="ota-diagnostics-empty" role="status">{t('device.otaNoLogs')}</p>
          )}
        </>
      ) : (
        <div className="device-inspection-feedback" role="status">
          <Icon name="check" size={18} />
          <span>{t('device.otaResetSucceeded')}</span>
        </div>
      )}
    </section>
  );
}
