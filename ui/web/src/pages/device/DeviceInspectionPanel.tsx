import { useEffect, useRef, useState } from 'react';
import type { AssetName } from '../../assets';
import { commands } from '../../commands';
import { useI18n } from '../../i18n';
import type { ActiveOperation, Device } from '../../types';
import { Badge, Button, Card, CardTitle, Icon } from '../../components/ui';
import { record, type SharedPageProps } from '../shared';

export type DeviceInspectionAction = 'properties' | 'screenXml' | 'bootloaderVersions' | 'pifPrint';

type PropertySummary = {
  manufacturer: string;
  model: string;
  codename: string;
  androidVersion: string;
  build: string;
  securityPatch: string;
  bootloader: string;
};

type PropertiesReport = {
  action: 'properties';
  targetSerial: string;
  count: number;
  properties: Record<string, string>;
  redactedKeys: string[];
  summary: PropertySummary;
};

type ScreenXmlReport = {
  action: 'screenXml';
  targetSerial: string;
  xml: string;
  sha256: string;
  nodeCount: number;
  redactedFields: number;
};

type BootloaderVersionsReport = {
  action: 'bootloaderVersions';
  targetSerial: string;
  source: 'adb_getprop';
  current: string;
  slot: '' | 'a' | 'b';
  versions: Record<string, string>;
};

type PifProfileReport = {
  action: 'pifPrint';
  targetSerial: string;
  format: 'playintegrityfork-v5-compatible';
  profile: Record<string, string>;
};

export type DeviceInspectionReport =
  | PropertiesReport
  | ScreenXmlReport
  | BootloaderVersionsReport
  | PifProfileReport;

type InspectionState =
  | { phase: 'idle' }
  | { phase: 'running' | 'cancelling'; action: DeviceInspectionAction }
  | { phase: 'success'; action: DeviceInspectionAction; report: DeviceInspectionReport }
  | { phase: 'cancelled' | 'error'; action: DeviceInspectionAction; code?: string };

const PROPERTY_KEY = /^[A-Za-z0-9_.-]{1,128}$/;
const PIF_KEY = /^[A-Z][A-Z0-9_]{0,63}$/;
const SAFE_CODE = /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/;
const SHA256 = /^[0-9a-f]{64}$/i;
const MAX_PROPERTY_COUNT = 8192;
const MAX_PROPERTY_VALUE = 16 * 1024;
const MAX_SCREEN_XML = 2 * 1024 * 1024;
const MAX_SCREEN_NODES = 20_000;

function boundedText(value: unknown, maximum: number, multiline = false): string | null {
  if (
    typeof value !== 'string'
    || new TextEncoder().encode(value).length > maximum
    || value.includes('\0')
  ) return null;
  if (!multiline && /[\u0001-\u001f\u007f]/.test(value)) return null;
  return value;
}

function boundedInteger(value: unknown, maximum: number): number | null {
  return typeof value === 'number'
    && Number.isSafeInteger(value)
    && value >= 0
    && value <= maximum
    ? value
    : null;
}

function stringMap(
  value: unknown,
  keyPattern: RegExp,
  maximumEntries: number,
  maximumValue: number,
): Record<string, string> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const source = record(value);
  const entries = Object.entries(source);
  if (entries.length > maximumEntries) return null;
  const parsed: Record<string, string> = {};
  for (const [key, rawValue] of entries) {
    const text = boundedText(rawValue, maximumValue);
    if (!keyPattern.test(key) || text === null) return null;
    parsed[key] = text;
  }
  return parsed;
}

function exactStringList(value: unknown, maximum: number): string[] | null {
  if (!Array.isArray(value) || value.length > maximum) return null;
  const parsed = value.flatMap((entry) => {
    const text = boundedText(entry, 128);
    return text === null ? [] : [text];
  });
  return parsed.length === value.length && new Set(parsed).size === parsed.length ? parsed : null;
}

function targetMatches(value: Record<string, unknown>, expectedSerial: string) {
  return value.targetSerial === expectedSerial;
}

function parseProperties(value: Record<string, unknown>, serial: string): PropertiesReport | null {
  const properties = stringMap(value.properties, PROPERTY_KEY, MAX_PROPERTY_COUNT, MAX_PROPERTY_VALUE);
  const redactedKeys = exactStringList(value.redactedKeys, MAX_PROPERTY_COUNT);
  const count = boundedInteger(value.count, MAX_PROPERTY_COUNT);
  const sourceSummary = record(value.summary);
  const summaryKeys: Array<keyof PropertySummary> = [
    'manufacturer', 'model', 'codename', 'androidVersion', 'build', 'securityPatch', 'bootloader',
  ];
  const summary = Object.fromEntries(summaryKeys.map((key) => [key, boundedText(sourceSummary[key], 1024)])) as Record<keyof PropertySummary, string | null>;
  if (
    !targetMatches(value, serial)
    || properties === null
    || redactedKeys === null
    || count === null
    || count !== Object.keys(properties).length
    || summaryKeys.some((key) => summary[key] === null)
    || redactedKeys.some((key) => properties[key] !== '[REDACTED]')
  ) return null;
  return {
    action: 'properties',
    targetSerial: serial,
    count,
    properties,
    redactedKeys,
    summary: summary as PropertySummary,
  };
}

function parseScreenXml(value: Record<string, unknown>, serial: string): ScreenXmlReport | null {
  const xml = boundedText(value.xml, MAX_SCREEN_XML, true);
  const sha256 = boundedText(value.sha256, 64);
  const nodeCount = boundedInteger(value.nodeCount, MAX_SCREEN_NODES);
  const redactedFields = boundedInteger(value.redactedFields, MAX_SCREEN_NODES * 2);
  if (
    !targetMatches(value, serial)
    || xml === null
    || !xml.startsWith('<?xml version="1.0" encoding="UTF-8"?>\n<hierarchy')
    || sha256 === null
    || !SHA256.test(sha256)
    || nodeCount === null
    || nodeCount < 1
    || redactedFields === null
  ) return null;
  return { action: 'screenXml', targetSerial: serial, xml, sha256: sha256.toLowerCase(), nodeCount, redactedFields };
}

function parseBootloaderVersions(value: Record<string, unknown>, serial: string): BootloaderVersionsReport | null {
  const versions = stringMap(value.versions, PROPERTY_KEY, 16, 1024);
  const current = boundedText(value.current, 1024);
  const slot = value.slot;
  if (
    !targetMatches(value, serial)
    || value.source !== 'adb_getprop'
    || versions === null
    || !Object.keys(versions).length
    || current === null
    || !current
    || !Object.values(versions).includes(current)
    || !['', 'a', 'b'].includes(String(slot))
  ) return null;
  return {
    action: 'bootloaderVersions',
    targetSerial: serial,
    source: 'adb_getprop',
    current,
    slot: slot as '' | 'a' | 'b',
    versions,
  };
}

function parsePifProfile(value: Record<string, unknown>, serial: string): PifProfileReport | null {
  const profile = stringMap(value.profile, PIF_KEY, 32, 4096);
  const required = ['MANUFACTURER', 'MODEL', 'FINGERPRINT', 'PRODUCT', 'DEVICE', 'SECURITY_PATCH', 'DEVICE_INITIAL_SDK_INT'];
  if (
    !targetMatches(value, serial)
    || value.format !== 'playintegrityfork-v5-compatible'
    || profile === null
    || required.some((key) => !profile[key])
  ) return null;
  return {
    action: 'pifPrint',
    targetSerial: serial,
    format: 'playintegrityfork-v5-compatible',
    profile,
  };
}

export function parseDeviceInspectionReport(
  action: DeviceInspectionAction,
  value: unknown,
  serial: string,
): DeviceInspectionReport | null {
  const source = record(value);
  if (source.action !== action) return null;
  if (action === 'properties') return parseProperties(source, serial);
  if (action === 'screenXml') return parseScreenXml(source, serial);
  if (action === 'bootloaderVersions') return parseBootloaderVersions(source, serial);
  return parsePifProfile(source, serial);
}

function copyValue(report: DeviceInspectionReport) {
  if (report.action === 'screenXml') return report.xml;
  if (report.action === 'properties') {
    return JSON.stringify({
      action: report.action,
      targetSerial: report.targetSerial,
      summary: report.summary,
      count: report.count,
      redactedKeys: report.redactedKeys,
      properties: report.properties,
    }, null, 2);
  }
  if (report.action === 'bootloaderVersions') {
    return JSON.stringify({
      action: report.action,
      targetSerial: report.targetSerial,
      source: report.source,
      current: report.current,
      slot: report.slot,
      versions: report.versions,
    }, null, 2);
  }
  return JSON.stringify({
    action: report.action,
    targetSerial: report.targetSerial,
    format: report.format,
    profile: report.profile,
  }, null, 2);
}

function reportLabel(action: DeviceInspectionAction) {
  const labels = {
    properties: 'device.inspectProperties',
    screenXml: 'device.inspectScreenXml',
    bootloaderVersions: 'device.inspectBootloaderVersions',
    pifPrint: 'device.inspectPifProfile',
  } as const;
  return labels[action];
}

async function writeSanitizedClipboard(text: string) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      // Local-file WebViews may expose Clipboard API but deny it as a
      // non-secure context. The bounded text-only fallback remains local.
    }
  }
  const focused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.readOnly = true;
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  try {
    document.body.append(textarea);
    textarea.select();
    if (!document.execCommand('copy')) throw new Error('clipboard unavailable');
  } finally {
    textarea.remove();
    focused?.focus({ preventScroll: true });
  }
}

export function DeviceInspectionPanel({
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
  const [state, setState] = useState<InspectionState>({ phase: 'idle' });
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'error'>('idle');
  const requestEpoch = useRef(0);
  const feedbackRef = useRef<HTMLElement>(null);
  const serial = device?.serial ?? '';
  const ready = Boolean(device && device.mode === 'adb' && toolchainReady);
  const busy = state.phase === 'running' || state.phase === 'cancelling';
  const cancellableOperation = busy
    && activeOperation
    && ['pending', 'running'].includes(activeOperation.status.toLowerCase())
    ? activeOperation
    : null;

  useEffect(() => {
    requestEpoch.current += 1;
    setState({ phase: 'idle' });
    setCopyState('idle');
    return () => { requestEpoch.current += 1; };
  }, [device?.mode, serial, toolchainReady]);

  useEffect(() => {
    if (['success', 'cancelled', 'error'].includes(state.phase)) {
      window.requestAnimationFrame(() => feedbackRef.current?.focus());
    }
  }, [state.phase]);

  const inspect = async (action: DeviceInspectionAction) => {
    if (!ready || !device || busy) return;
    const epoch = requestEpoch.current + 1;
    requestEpoch.current = epoch;
    setCopyState('idle');
    setState({ phase: 'running', action });
    let response;
    try {
      response = await onCommand(commands.deviceInspect, { serial: device.serial, action });
    } catch {
      if (requestEpoch.current === epoch) setState({ phase: 'error', action });
      return;
    }
    if (requestEpoch.current !== epoch) return;
    if (!response) {
      setState({ phase: 'error', action });
      return;
    }
    const result = record(response.result);
    const status = typeof result.status === 'string' ? result.status.toLowerCase() : '';
    const code = typeof result.code === 'string' && SAFE_CODE.test(result.code) ? result.code : undefined;
    if (status === 'cancelled') {
      setState({ phase: 'cancelled', action, code });
      return;
    }
    if (status !== 'success') {
      setState({ phase: 'error', action, code });
      return;
    }
    const report = parseDeviceInspectionReport(action, result.value, device.serial);
    setState(report ? { phase: 'success', action, report } : { phase: 'error', action, code: 'invalid_typed_report' });
  };

  const cancel = async () => {
    if (!cancellableOperation || state.phase !== 'running') return;
    setState({ phase: 'cancelling', action: state.action });
    const response = await onCommand(commands.operationCancel, { operationId: cancellableOperation.id });
    const acknowledgement = record(response?.result);
    if (!response || acknowledgement.accepted === false) {
      setState((current) => current.phase === 'cancelling'
        ? { phase: 'running', action: current.action }
        : current);
    }
  };

  const copyReport = async (report: DeviceInspectionReport) => {
    setCopyState('idle');
    try {
      await writeSanitizedClipboard(copyValue(report));
      setCopyState('copied');
    } catch {
      setCopyState('error');
    }
  };

  const actions: Array<{ action: DeviceInspectionAction; icon: AssetName; title: string; detail: string }> = [
    { action: 'properties', icon: 'processFile', title: t('device.inspectProperties'), detail: t('device.inspectPropertiesDetail') },
    { action: 'screenXml', icon: 'shell', title: t('device.inspectScreenXml'), detail: t('device.inspectScreenXmlDetail') },
    { action: 'bootloaderVersions', icon: 'bootloader', title: t('device.inspectBootloaderVersions'), detail: t('device.inspectBootloaderVersionsDetail') },
    { action: 'pifPrint', icon: 'shield', title: t('device.inspectPifProfile'), detail: t('device.inspectPifProfileDetail') },
  ];

  return (
    <Card className="device-inspection-card" aria-busy={busy}>
      <CardTitle icon="scan" after={ready && device ? <Badge tone="success">ADB · {device.serial}</Badge> : null}>
        {t('device.inspectTitle')}
      </CardTitle>
      <p className="device-inspection-card__detail">{t('device.inspectDetail')}</p>
      {!ready ? (
        <div className="inline-alert inline-alert--warning device-inspection-guard" role="status">
          <Icon name="warningPng" size={18} />
          <span>{t('device.inspectGuard')}</span>
        </div>
      ) : null}
      <div className="device-inspection-actions">
        {actions.map((item) => {
          const descriptionId = `inspection-${item.action}-description`;
          return (
            <section className="device-inspection-action" key={item.action}>
              <span className="device-operation-group__icon"><Icon name={item.icon} size={23} /></span>
              <div>
                <Button
                  variant="ghost"
                  onClick={() => void inspect(item.action)}
                  disabled={!ready || busy}
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
          <span>{t(state.phase === 'cancelling' ? 'device.inspectCancelling' : 'device.inspectRunning')}</span>
          {cancellableOperation && state.phase === 'running' ? (
            <Button variant="ghost" onClick={() => void cancel()}>{t('device.inspectCancel')}</Button>
          ) : null}
        </div>
      ) : null}
      {state.phase === 'cancelled' ? (
        <section className="device-inspection-feedback" ref={feedbackRef} tabIndex={-1} role="status">
          <Icon name="warningPng" size={18} />
          <span><strong>{t('device.inspectCancelled')}</strong>{state.code ? <code>{state.code}</code> : null}</span>
        </section>
      ) : null}
      {state.phase === 'error' ? (
        <section className="device-inspection-feedback device-inspection-feedback--error" ref={feedbackRef} tabIndex={-1} role="alert">
          <Icon name="warningPng" size={18} />
          <span><strong>{t('device.inspectFailed')}</strong>{state.code ? <code>{state.code}</code> : null}</span>
        </section>
      ) : null}
      {state.phase === 'success' ? (
        <InspectionResult
          state={state}
          copyState={copyState}
          onCopy={() => void copyReport(state.report)}
          feedbackRef={feedbackRef}
        />
      ) : null}
    </Card>
  );
}

function InspectionResult({
  state,
  copyState,
  onCopy,
  feedbackRef,
}: {
  state: Extract<InspectionState, { phase: 'success' }>;
  copyState: 'idle' | 'copied' | 'error';
  onCopy: () => void;
  feedbackRef: React.RefObject<HTMLElement | null>;
}) {
  const { t } = useI18n();
  const headingId = `inspection-result-${state.action}`;
  return (
    <section className="device-inspection-result" ref={feedbackRef} tabIndex={-1} aria-labelledby={headingId}>
      <header>
        <span>
          <Badge tone="success">{t('status.ready')}</Badge>
          <h2 id={headingId}>{t(reportLabel(state.action))}</h2>
        </span>
        <Button icon="processFile" onClick={onCopy}>{t('device.inspectCopy')}</Button>
      </header>
      <ReportBody report={state.report} />
      <span className={copyState === 'error' ? 'device-inspection-copy-status is-error' : 'device-inspection-copy-status'} role={copyState === 'error' ? 'alert' : 'status'} aria-live="polite">
        {copyState === 'error' ? t('device.inspectCopyFailed') : copyState === 'copied' ? t('device.inspectCopied') : ''}
      </span>
    </section>
  );
}

function ReportBody({ report }: { report: DeviceInspectionReport }) {
  const { t } = useI18n();
  if (report.action === 'properties') {
    const summary = [
      [t('device.inspectManufacturer'), report.summary.manufacturer],
      [t('device.model'), report.summary.model],
      [t('device.codename'), report.summary.codename],
      [`Android / ${t('common.build')}`, `${report.summary.androidVersion} · ${report.summary.build}`],
      [t('device.inspectSecurityPatch'), report.summary.securityPatch],
      [t('device.bootloader'), report.summary.bootloader],
    ];
    return (
      <>
        <dl className="device-inspection-summary">
          {summary.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value || '—'}</dd></div>)}
        </dl>
        <div className="device-inspection-meta">
          <Badge tone="accent">{t('device.inspectEntries', { count: report.count })}</Badge>
          <Badge tone="neutral">{t('device.inspectRedacted', { count: report.redactedKeys.length })}</Badge>
        </div>
        <pre tabIndex={0} aria-label={t('device.inspectProperties')}>{JSON.stringify(report.properties, null, 2)}</pre>
      </>
    );
  }
  if (report.action === 'screenXml') {
    return (
      <>
        <dl className="device-inspection-summary device-inspection-summary--compact">
          <div><dt>{t('device.inspectNodes')}</dt><dd>{report.nodeCount}</dd></div>
          <div><dt>{t('device.inspectRedactedFields')}</dt><dd>{report.redactedFields}</dd></div>
          <div><dt>{t('device.inspectDigest')}</dt><dd><code>{report.sha256}</code></dd></div>
        </dl>
        <pre tabIndex={0} aria-label={t('device.inspectScreenXml')}>{report.xml}</pre>
      </>
    );
  }
  if (report.action === 'bootloaderVersions') {
    return (
      <>
        <dl className="device-inspection-summary device-inspection-summary--compact">
          <div><dt>{t('device.inspectCurrentVersion')}</dt><dd>{report.current}</dd></div>
          <div><dt>{t('device.inspectSource')}</dt><dd>{report.source}</dd></div>
          <div><dt>{t('device.inspectActiveSlot')}</dt><dd>{report.slot ? report.slot.toUpperCase() : '—'}</dd></div>
        </dl>
        <pre tabIndex={0} aria-label={t('device.inspectBootloaderVersions')}>{JSON.stringify(report.versions, null, 2)}</pre>
      </>
    );
  }
  return (
    <>
      <div className="device-inspection-meta"><Badge tone="accent">{report.format}</Badge></div>
      <dl className="device-inspection-profile">
        {Object.entries(report.profile).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{value}</dd></div>)}
      </dl>
    </>
  );
}
