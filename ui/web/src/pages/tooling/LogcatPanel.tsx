import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type Dispatch,
  type SetStateAction,
} from 'react';
import { normalizeOperationStatus, validTargetSerial } from '../../bridge';
import { commands } from '../../commands';
import { useI18n } from '../../i18n';
import type { ActiveOperation, Device } from '../../types';
import { Badge, Button, EmptyState, Icon } from '../../components/ui';
import { record, selectedGrant, type SharedPageProps } from '../shared';

export type LogcatMode = 'snapshot' | 'stream';
export type LogcatRedaction = 'strict' | 'standard' | 'none';
export type LogcatBuffer = 'main' | 'system' | 'radio' | 'events' | 'crash';

export type LogcatExportReceipt = {
  fileName: string;
  sha256: string;
  size: number;
};

export type LogcatReport = {
  targetSerial: string;
  mode: LogcatMode;
  lineCount: number;
  lines: string[];
  text: string;
  redaction: LogcatRedaction;
  redactedCount: number;
  bounded: true;
  truncated: boolean;
  export?: LogcatExportReceipt;
};

export type LogcatReportSummary = Omit<LogcatReport, 'lines' | 'text'>;

type LogcatPhase = 'idle' | 'picking' | 'running' | 'cancelling' | 'success' | 'cancelled' | 'failed';

export type LogcatUiState = {
  mode: LogcatMode;
  buffers: LogcatBuffer[];
  format: 'brief' | 'epoch' | 'threadtime';
  maxLines: number;
  timeoutSeconds: number;
  redaction: LogcatRedaction;
  requestedRedaction: LogcatRedaction | null;
  phase: LogcatPhase;
  operationId: string | null;
  targetSerial: string | null;
  lastProgressCurrent: number;
  lines: string[];
  report: LogcatReportSummary | null;
  code: string;
};

export const initialLogcatUiState: LogcatUiState = {
  mode: 'snapshot',
  buffers: ['main'],
  format: 'threadtime',
  maxLines: 500,
  timeoutSeconds: 30,
  redaction: 'strict',
  requestedRedaction: null,
  phase: 'idle',
  operationId: null,
  targetSerial: null,
  lastProgressCurrent: 0,
  lines: [],
  report: null,
  code: '',
};

const REPORT_FIELDS = [
  'bounded',
  'lineCount',
  'lines',
  'mode',
  'redactedCount',
  'redaction',
  'targetSerial',
  'text',
  'truncated',
] as const;
const MAX_LINE_LENGTH = 4_096;
const MAX_LOG_CONTENT_BYTES = 16 * 1_024 * 1_024;
const MAX_TEXT_LENGTH = MAX_LOG_CONTENT_BYTES + 10_000;
const MAX_LOG_LINES = 10_000;
export const MAX_LOGCAT_PREVIEW_LINES = 500;
export const MAX_LOGCAT_PREVIEW_BYTES = 256 * 1_024;
const UNSAFE_LOG_CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\r\n]/;
const buffers: LogcatBuffer[] = ['main', 'system', 'radio', 'events', 'crash'];

type PreviewEntry = { line: string; bytes: number };

type PreviewRing = {
  entries: Array<PreviewEntry | undefined>;
  start: number;
  length: number;
  bytes: number;
  lineLimit: number;
};

type RenderedProgress = {
  current: number | null;
  total: number | null;
  percent: number | null;
};

function createPreviewRing(maxLines = MAX_LOGCAT_PREVIEW_LINES): PreviewRing {
  const lineLimit = Math.max(1, Math.min(MAX_LOGCAT_PREVIEW_LINES, maxLines));
  return { entries: new Array(lineLimit), start: 0, length: 0, bytes: 0, lineLimit };
}

function removeOldestPreviewLine(ring: PreviewRing) {
  const entry = ring.entries[ring.start];
  if (entry) ring.bytes -= entry.bytes;
  ring.entries[ring.start] = undefined;
  ring.start = (ring.start + 1) % ring.lineLimit;
  ring.length -= 1;
  if (ring.length > 0) ring.bytes -= 1;
}

function appendPreviewLine(ring: PreviewRing, line: string) {
  const bytes = utf8Size(line);
  if (bytes > MAX_LOGCAT_PREVIEW_BYTES) return;
  while (
    ring.length > 0
    && (ring.length >= ring.lineLimit || ring.bytes + bytes + 1 > MAX_LOGCAT_PREVIEW_BYTES)
  ) removeOldestPreviewLine(ring);
  const index = (ring.start + ring.length) % ring.lineLimit;
  ring.entries[index] = { line, bytes };
  if (ring.length > 0) ring.bytes += 1;
  ring.length += 1;
  ring.bytes += bytes;
}

function previewLines(ring: PreviewRing) {
  const lines: string[] = [];
  for (let offset = 0; offset < ring.length; offset += 1) {
    const entry = ring.entries[(ring.start + offset) % ring.lineLimit];
    if (entry) lines.push(entry.line);
  }
  return lines;
}

export function boundedLogcatPreview(lines: readonly string[], maxLines: number) {
  const ring = createPreviewRing(maxLines);
  for (const line of lines) appendPreviewLine(ring, line);
  return previewLines(ring);
}

export function hasUnredactedLogcatState(current: LogcatUiState) {
  return current.redaction === 'none'
    || current.requestedRedaction === 'none'
    || current.report?.redaction === 'none';
}

export function hasUnredactedLogcatCapture(current: LogcatUiState) {
  return current.requestedRedaction === 'none'
    || current.report?.redaction === 'none'
    || (
      current.redaction === 'none'
      && current.lines.length > 0
      && current.requestedRedaction === null
      && current.report === null
    );
}

export function purgeUnredactedLogcatState(current: LogcatUiState): LogcatUiState {
  const activeUnredacted = current.requestedRedaction === 'none'
    && (current.phase === 'running' || current.phase === 'cancelling');
  const containsUnredactedData = hasUnredactedLogcatCapture(current);
  if (current.redaction !== 'none' && !containsUnredactedData) return current;
  if (activeUnredacted) {
    return {
      ...current,
      redaction: 'strict',
      phase: current.operationId ? 'cancelling' : 'running',
      lastProgressCurrent: 0,
      lines: [],
      report: null,
      code: '',
    };
  }
  return {
    ...current,
    redaction: 'strict',
    requestedRedaction: null,
    phase: containsUnredactedData ? 'idle' : current.phase,
    operationId: containsUnredactedData ? null : current.operationId,
    targetSerial: containsUnredactedData ? null : current.targetSerial,
    lastProgressCurrent: containsUnredactedData ? 0 : current.lastProgressCurrent,
    lines: containsUnredactedData ? [] : current.lines,
    report: containsUnredactedData ? null : current.report,
    code: containsUnredactedData ? '' : current.code,
  };
}

export function useLogcatExpertGuard({
  expertMode,
  state,
  setState,
  cancelOperation,
  clearBufferedProgress,
}: {
  expertMode: boolean;
  state: LogcatUiState;
  setState: Dispatch<SetStateAction<LogcatUiState>>;
  cancelOperation: (operationId: string) => void | Promise<unknown>;
  clearBufferedProgress?: () => void;
}) {
  const cancellationIdsRef = useRef(new Set<string>());
  useLayoutEffect(() => {
    if (expertMode || !hasUnredactedLogcatState(state)) return;
    const operationId = state.requestedRedaction === 'none' ? state.operationId : null;
    const shouldCancel = Boolean(operationId)
      && state.phase !== 'cancelling'
      && !cancellationIdsRef.current.has(operationId as string);
    if (hasUnredactedLogcatCapture(state)) clearBufferedProgress?.();
    setState(purgeUnredactedLogcatState);
    if (!operationId || !shouldCancel) return;
    cancellationIdsRef.current.add(operationId);
    void Promise.resolve(cancelOperation(operationId)).catch(() => undefined);
  }, [
    cancelOperation,
    clearBufferedProgress,
    expertMode,
    setState,
    state.lines.length,
    state.operationId,
    state.phase,
    state.redaction,
    state.report?.redaction,
    state.requestedRedaction,
  ]);
}

export function logcatDefaultFileName(serial: string) {
  const safeSerial = serial.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 96) || 'device';
  return `PixelFlasher-logcat-${safeSerial}.txt`;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]) {
  const keys = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return keys.length === sorted.length && keys.every((key, index) => key === sorted[index]);
}

function utf8Size(value: string) {
  return new TextEncoder().encode(value).byteLength;
}

function utf8LinesSize(values: unknown[]) {
  return values.reduce<number>((total, value) => total + (typeof value === 'string' ? utf8Size(value) : 0), 0);
}

function parseExportReceipt(value: unknown, expectedSize: number): LogcatExportReceipt | null {
  const source = record(value);
  if (
    !exactKeys(source, ['fileName', 'sha256', 'size'])
    || typeof source.fileName !== 'string'
    || source.fileName.length < 1
    || source.fileName.length > 255
    || /[\\/\u0000-\u001f\u007f]/.test(source.fileName)
    || typeof source.sha256 !== 'string'
    || !/^[0-9a-f]{64}$/.test(source.sha256)
    || typeof source.size !== 'number'
    || !Number.isSafeInteger(source.size)
    || source.size < 0
    || source.size > MAX_TEXT_LENGTH
    || source.size !== expectedSize
  ) return null;
  return { fileName: source.fileName, sha256: source.sha256, size: source.size };
}

export function parseLogcatReport(
  value: unknown,
  expectedSerial: string,
  expectedMode: LogcatMode,
  expectedRedaction: LogcatRedaction,
): LogcatReport | null {
  const source = record(value);
  const rawLines = source.lines;
  const expectedFields = 'export' in source ? [...REPORT_FIELDS, 'export'] : REPORT_FIELDS;
  if (
    !exactKeys(source, expectedFields)
    || typeof source.targetSerial !== 'string'
    || !validTargetSerial(source.targetSerial)
    || source.targetSerial !== expectedSerial
    || source.mode !== expectedMode
    || source.redaction !== expectedRedaction
    || source.bounded !== true
    || typeof source.truncated !== 'boolean'
    || typeof source.lineCount !== 'number'
    || !Number.isInteger(source.lineCount)
    || source.lineCount < 0
    || source.lineCount > MAX_LOG_LINES
    || !Array.isArray(rawLines)
    || rawLines.length !== source.lineCount
    || rawLines.some((line) => typeof line !== 'string' || utf8Size(line) > MAX_LINE_LENGTH || UNSAFE_LOG_CONTROL.test(line))
    || utf8LinesSize(rawLines) > MAX_LOG_CONTENT_BYTES
    || typeof source.text !== 'string'
    || utf8Size(source.text) > MAX_TEXT_LENGTH
    || source.text.includes('\0')
    || source.text !== rawLines.join('\n')
    || typeof source.redactedCount !== 'number'
    || !Number.isInteger(source.redactedCount)
    || source.redactedCount < 0
    || source.redactedCount > source.lineCount
  ) return null;
  const exportReceipt = 'export' in source ? parseExportReceipt(source.export, utf8Size(source.text)) : undefined;
  if ('export' in source && !exportReceipt) return null;
  return {
    targetSerial: source.targetSerial,
    mode: source.mode as LogcatMode,
    lineCount: source.lineCount,
    lines: [...rawLines] as string[],
    text: source.text,
    redaction: source.redaction as LogcatRedaction,
    redactedCount: source.redactedCount,
    bounded: true,
    truncated: source.truncated,
    ...(exportReceipt ? { export: exportReceipt } : {}),
  };
}

function summarizeLogcatReport(report: LogcatReport): LogcatReportSummary {
  return {
    targetSerial: report.targetSerial,
    mode: report.mode,
    lineCount: report.lineCount,
    redaction: report.redaction,
    redactedCount: report.redactedCount,
    bounded: true,
    truncated: report.truncated,
    ...(report.export ? { export: report.export } : {}),
  };
}

function formatBytes(size: number) {
  if (size < 1_024) return `${size} B`;
  if (size < 1_024 * 1_024) return `${(size / 1_024).toFixed(1)} KiB`;
  return `${(size / 1_024 / 1_024).toFixed(1)} MiB`;
}

function activeLogcatOperation(operation: ActiveOperation | null | undefined, device: Device | undefined) {
  if (!operation || !device || operation.kind !== commands.toolsLogcat) return null;
  const status = normalizeOperationStatus(operation.status);
  const targetSerial = operation.targetSerial ?? operation.target_serial;
  return ['pending', 'running'].includes(status) && targetSerial === device.serial ? operation : null;
}

export function appendLogcatProgressBatch(
  current: LogcatUiState,
  candidates: readonly ActiveOperation[],
): LogcatUiState {
  if (
    current.mode !== 'stream'
    || current.phase === 'cancelling'
    || !current.operationId
    || !current.targetSerial
  ) return current;
  const ring = createPreviewRing(current.maxLines);
  for (const retained of current.lines) appendPreviewLine(ring, retained);
  let lastProgressCurrent = current.lastProgressCurrent;
  let appended = false;
  for (const candidate of candidates) {
    const targetSerial = candidate.targetSerial ?? candidate.target_serial;
    const sequence = candidate.current;
    const total = candidate.total;
    const line = candidate.detail;
    if (
      candidate.id !== current.operationId
      || candidate.kind !== commands.toolsLogcat
      || !['pending', 'running'].includes(normalizeOperationStatus(candidate.status))
      || targetSerial !== current.targetSerial
      || typeof sequence !== 'number'
      || !Number.isInteger(sequence)
      || typeof total !== 'number'
      || !Number.isInteger(total)
      || sequence < 1
      || sequence > total
      || total > MAX_LOG_LINES
      || sequence <= lastProgressCurrent
      || typeof line !== 'string'
      || utf8Size(line) > MAX_LINE_LENGTH
      || UNSAFE_LOG_CONTROL.test(line)
    ) continue;
    appendPreviewLine(ring, line);
    lastProgressCurrent = sequence;
    appended = true;
  }
  return appended
    ? {
        ...current,
        lastProgressCurrent,
        lines: previewLines(ring),
      }
    : current;
}

export function LogcatPanel({
  device,
  operation,
  progressBatch,
  adbReady,
  hostBusy,
  expertMode,
  onCommand,
  uiState,
  onUiStateChange,
}: {
  device?: Device;
  operation?: ActiveOperation | null;
  progressBatch?: readonly ActiveOperation[];
  adbReady: boolean;
  hostBusy: boolean;
  expertMode: boolean;
  onCommand: SharedPageProps['onCommand'];
  uiState?: LogcatUiState;
  onUiStateChange?: Dispatch<SetStateAction<LogcatUiState>>;
}) {
  const { t } = useI18n();
  const [localState, setLocalState] = useState(initialLogcatUiState);
  const state = uiState ?? localState;
  const setState = onUiStateChange ?? setLocalState;
  const contextRef = useRef({ serial: device?.serial ?? null, mode: device?.mode ?? null });
  const expertModeRef = useRef(expertMode);
  const lastProgressRef = useRef(state.lastProgressCurrent);
  const previewRingRef = useRef(createPreviewRing());
  const previewOperationRef = useRef<string | null>(null);
  const previewFrameRef = useRef<number | null>(null);
  const queuedProgressRef = useRef<RenderedProgress>({ current: null, total: null, percent: null });
  const [renderedProgress, setRenderedProgress] = useState<RenderedProgress>({
    current: null,
    total: null,
    percent: null,
  });
  const outputRef = useRef<HTMLPreElement>(null);
  contextRef.current = { serial: device?.serial ?? null, mode: device?.mode ?? null };
  expertModeRef.current = expertMode;
  const candidateOperation = activeLogcatOperation(operation, device);
  const activeOperation = candidateOperation?.id === state.operationId ? candidateOperation : null;
  const redaction = !expertMode && state.redaction === 'none' ? 'strict' : state.redaction;
  const terminal = state.phase === 'success' || state.phase === 'cancelled' || state.phase === 'failed';
  const pending = state.phase === 'running' || state.phase === 'cancelling' || (!terminal && Boolean(activeOperation));
  const operationProgress = state.mode === 'stream' ? renderedProgress.percent : activeOperation?.progress;
  const operationCurrent = state.mode === 'stream' ? renderedProgress.current : activeOperation?.current;
  const operationTotal = state.mode === 'stream' ? renderedProgress.total : activeOperation?.total;
  const progress = typeof operationProgress === 'number' && Number.isFinite(operationProgress)
    ? Math.max(0, Math.min(100, operationProgress))
    : operationCurrent && operationTotal
      ? Math.max(0, Math.min(100, Math.round(operationCurrent / operationTotal * 100)))
      : null;
  const visibleForDevice = state.targetSerial === null || state.targetSerial === device?.serial;
  const unsafeOutsideExpert = !expertMode && hasUnredactedLogcatCapture(state);
  const visibleLines = visibleForDevice && !unsafeOutsideExpert ? state.lines : null;
  const visibleText = useMemo(() => visibleLines?.join('\n') ?? '', [visibleLines]);
  const visibleReport = visibleForDevice && !unsafeOutsideExpert ? state.report : null;
  const previewTotal = visibleReport?.lineCount
    ?? (state.mode === 'stream' && typeof operationCurrent === 'number' ? operationCurrent : null);

  const clearBufferedPreview = useCallback((maxLines = MAX_LOGCAT_PREVIEW_LINES) => {
    if (previewFrameRef.current !== null) {
      window.cancelAnimationFrame(previewFrameRef.current);
      previewFrameRef.current = null;
    }
    previewRingRef.current = createPreviewRing(maxLines);
    previewOperationRef.current = null;
    queuedProgressRef.current = { current: null, total: null, percent: null };
    lastProgressRef.current = 0;
    setRenderedProgress({ current: null, total: null, percent: null });
  }, []);

  useLayoutEffect(() => {
    if (expertMode || !hasUnredactedLogcatState(state)) return;
    if (hasUnredactedLogcatCapture(state)) clearBufferedPreview(state.maxLines);
    setState(purgeUnredactedLogcatState);
  }, [
    clearBufferedPreview,
    expertMode,
    setState,
    state.lines.length,
    state.maxLines,
    state.redaction,
    state.report?.redaction,
    state.requestedRedaction,
  ]);

  useEffect(() => {
    clearBufferedPreview(state.maxLines);
    setState((previous) => (
      previous.targetSerial === null
      || (previous.targetSerial === (device?.serial ?? null) && device?.mode === 'adb')
        ? previous
        : {
            ...previous,
            phase: 'idle',
            operationId: null,
            requestedRedaction: null,
            targetSerial: null,
            lastProgressCurrent: 0,
            lines: [],
            report: null,
            code: '',
          }
    ));
  }, [clearBufferedPreview, device?.mode, device?.serial, setState, state.maxLines]);

  useEffect(() => {
    if (
      state.mode !== 'stream'
      || state.phase === 'cancelling'
      || (!expertMode && state.requestedRedaction === 'none')
    ) return;
    const candidates = progressBatch === undefined
      ? (activeOperation ? [activeOperation] : [])
      : progressBatch;
    let acceptedOperationId: string | null = null;
    let appended = false;
    for (const candidate of candidates) {
      const correlated = activeLogcatOperation(candidate, device);
      if (!correlated || correlated.id !== state.operationId) continue;
      const current = correlated.current;
      const line = correlated.detail;
      if (
        typeof current !== 'number'
        || !Number.isInteger(current)
        || typeof line !== 'string'
        || utf8Size(line) > MAX_LINE_LENGTH
        || UNSAFE_LOG_CONTROL.test(line)
      ) continue;
      if (previewOperationRef.current !== correlated.id) {
        previewRingRef.current = createPreviewRing(state.maxLines);
        for (const retained of state.lines) appendPreviewLine(previewRingRef.current, retained);
        previewOperationRef.current = correlated.id;
        lastProgressRef.current = state.lastProgressCurrent;
      }
      if (current <= lastProgressRef.current) continue;
      lastProgressRef.current = current;
      appendPreviewLine(previewRingRef.current, line);
      queuedProgressRef.current = {
        current,
        total: typeof correlated.total === 'number' ? correlated.total : null,
        percent: typeof correlated.progress === 'number' ? correlated.progress : null,
      };
      acceptedOperationId = correlated.id;
      appended = true;
    }
    if (!appended || !acceptedOperationId || previewFrameRef.current !== null) return;
    const operationId = acceptedOperationId;
    previewFrameRef.current = window.requestAnimationFrame(() => {
      previewFrameRef.current = null;
      const nextLines = previewLines(previewRingRef.current);
      const nextProgress = queuedProgressRef.current;
      setState((previous) => {
        if (
          previous.operationId !== operationId
          || previous.phase === 'cancelling'
          || (!expertModeRef.current && previous.requestedRedaction === 'none')
        ) return previous;
        return {
          ...previous,
          targetSerial: device?.serial ?? previous.targetSerial,
          lastProgressCurrent: nextProgress.current ?? previous.lastProgressCurrent,
          lines: nextLines,
        };
      });
      setRenderedProgress(nextProgress);
    });
  }, [
    activeOperation?.current,
    activeOperation?.detail,
    activeOperation?.id,
    activeOperation?.progress,
    activeOperation?.total,
    device,
    expertMode,
    progressBatch,
    setState,
    state.lines,
    state.lastProgressCurrent,
    state.maxLines,
    state.mode,
    state.operationId,
    state.phase,
    state.requestedRedaction,
  ]);

  useEffect(() => {
    if (!outputRef.current || state.mode !== 'stream' || !pending) return;
    outputRef.current.scrollTop = outputRef.current.scrollHeight;
  }, [pending, state.lines.length, state.mode]);

  useEffect(() => () => {
    if (previewFrameRef.current !== null) window.cancelAnimationFrame(previewFrameRef.current);
  }, []);

  const patchState = (patch: Partial<LogcatUiState>) => {
    setState((previous) => ({ ...previous, ...patch }));
  };

  const toggleBuffer = (buffer: LogcatBuffer) => {
    setState((previous) => {
      const selected = previous.buffers.includes(buffer)
        ? previous.buffers.filter((candidate) => candidate !== buffer)
        : [...previous.buffers, buffer];
      return { ...previous, buffers: selected.length ? selected : previous.buffers };
    });
  };

  const runCapture = async (grant?: string, expectedRevision?: number) => {
    if (
      !device
      || !adbReady
      || pending
      || hostBusy
      || contextRef.current.serial !== device.serial
      || contextRef.current.mode !== 'adb'
    ) return;
    const requestedSerial = device.serial;
    const requestedMode = state.mode;
    const requestedRedaction = redaction;
    clearBufferedPreview(state.maxLines);
    patchState({
      phase: 'running',
      operationId: null,
      requestedRedaction,
      targetSerial: requestedSerial,
      lastProgressCurrent: 0,
      lines: [],
      report: null,
      code: '',
    });
    const payload = {
      serial: requestedSerial,
      mode: requestedMode,
      buffers: state.buffers,
      format: state.format,
      maxLines: state.maxLines,
      timeoutSeconds: requestedMode === 'stream' ? state.timeoutSeconds : 30,
      redaction: requestedRedaction,
      ...(grant ? { grant } : {}),
    };
    let response;
    try {
      response = await onCommand(commands.toolsLogcat, payload, {
        returnCancelled: true,
        returnFailed: true,
        suppressNotice: true,
        onOperationAccepted: (operationId) => patchState({ operationId }),
        ...(expectedRevision === undefined ? {} : { expectedRevision }),
      });
    } catch {
      if (contextRef.current.serial === requestedSerial && contextRef.current.mode === 'adb') {
        clearBufferedPreview(state.maxLines);
        patchState({
          phase: 'failed',
          operationId: null,
          requestedRedaction: null,
          code: 'logcat_request_failed',
        });
      }
      return;
    }
    if (contextRef.current.serial !== requestedSerial || contextRef.current.mode !== 'adb') return;
    if (!response) {
      clearBufferedPreview(state.maxLines);
      patchState({
        phase: 'failed',
        operationId: null,
        requestedRedaction: null,
        code: 'logcat_request_failed',
      });
      return;
    }
    const result = record(response.result);
    const status = normalizeOperationStatus(result.status);
    const code = typeof result.code === 'string' ? result.code : '';
    if (requestedRedaction === 'none' && !expertModeRef.current) {
      clearBufferedPreview(state.maxLines);
      patchState({
        redaction: 'strict',
        requestedRedaction: null,
        phase: 'cancelled',
        operationId: null,
        targetSerial: null,
        lastProgressCurrent: 0,
        lines: [],
        report: null,
        code: 'expert_mode_disabled',
      });
      return;
    }
    if (status === 'cancelled') {
      clearBufferedPreview(state.maxLines);
      patchState({ phase: 'cancelled', operationId: null, requestedRedaction: null, code, report: null });
      return;
    }
    if (status !== 'success') {
      clearBufferedPreview(state.maxLines);
      patchState({ phase: 'failed', operationId: null, requestedRedaction: null, code, report: null });
      return;
    }
    const report = parseLogcatReport(result.value, requestedSerial, requestedMode, requestedRedaction);
    if (!report) {
      clearBufferedPreview(state.maxLines);
      patchState({
        phase: 'failed',
        operationId: null,
        requestedRedaction: null,
        code: 'logcat_result_invalid',
        report: null,
        lastProgressCurrent: 0,
        lines: [],
      });
      return;
    }
    clearBufferedPreview(state.maxLines);
    patchState({
      phase: 'success',
      operationId: null,
      requestedRedaction: null,
      code,
      report: summarizeLogcatReport(report),
      lastProgressCurrent: report.lineCount,
      lines: boundedLogcatPreview(report.lines, state.maxLines),
    });
  };

  const exportCapture = async () => {
    if (!device || !adbReady || pending || hostBusy) return;
    patchState({ phase: 'picking', code: '' });
    let picked;
    try {
      picked = await onCommand(commands.nativeSaveFile, {
        purpose: 'tools.logcat.export',
        title: t('tools.logcatExport'),
        defaultName: logcatDefaultFileName(device.serial),
        filters: [{ label: t('tools.logcatTextFiles'), extensions: ['txt', 'log'] }],
      });
    } catch {
      patchState({ phase: 'failed', code: 'logcat_export_picker_failed' });
      return;
    }
    const grant = selectedGrant(picked);
    if (!grant) {
      patchState({ phase: state.report ? 'success' : 'idle' });
      return;
    }
    if (contextRef.current.serial !== device.serial || contextRef.current.mode !== 'adb') {
      patchState({ phase: 'idle' });
      return;
    }
    patchState({ phase: 'idle' });
    await runCapture(grant, picked?.revision);
  };

  const cancel = async () => {
    const operationId = activeOperation?.id ?? state.operationId;
    if (!operationId || state.phase === 'cancelling') return;
    patchState({ phase: 'cancelling' });
    try {
      const response = await onCommand(commands.operationCancel, { operationId });
      const acknowledgement = record(response?.result);
      if (
        !response
        || normalizeOperationStatus(acknowledgement.status) !== 'success'
        || acknowledgement.code !== 'cancellation_requested'
      ) patchState({ phase: 'running' });
    } catch {
      patchState({ phase: 'running' });
    }
  };

  const clear = () => {
    clearBufferedPreview(state.maxLines);
    patchState({
      phase: 'idle',
      operationId: null,
      requestedRedaction: null,
      lastProgressCurrent: 0,
      lines: [],
      report: null,
      code: '',
    });
  };

  return (
    <div className="tool-panel-body logcat-panel" aria-busy={pending || state.phase === 'picking'}>
      <div className="logcat-mode" role="group" aria-label={t('tools.logcatMode')}>
        <button type="button" aria-label={t('tools.logcatSnapshot')} aria-pressed={state.mode === 'snapshot'} onClick={() => patchState({ mode: 'snapshot' })} disabled={pending || state.phase === 'picking'}>
          <strong>{t('tools.logcatSnapshot')}</strong>
          <small>{t('tools.logcatSnapshotDetail')}</small>
        </button>
        <button type="button" aria-label={t('tools.logcatStream')} aria-pressed={state.mode === 'stream'} onClick={() => patchState({ mode: 'stream' })} disabled={pending || state.phase === 'picking'}>
          <strong>{t('tools.logcatStream')}</strong>
          <small>{t('tools.logcatStreamDetail')}</small>
        </button>
      </div>

      <div className="logcat-controls">
        <fieldset className="logcat-buffers" disabled={pending || state.phase === 'picking'}>
          <legend>{t('tools.logcatBuffers')}</legend>
          {buffers.map((buffer) => (
            <label key={buffer}>
              <input type="checkbox" checked={state.buffers.includes(buffer)} onChange={() => toggleBuffer(buffer)} />
              <span>{buffer}</span>
            </label>
          ))}
        </fieldset>
        <label>
          <span>{t('tools.logcatFormat')}</span>
          <select value={state.format} onChange={(event) => patchState({ format: event.currentTarget.value as LogcatUiState['format'] })} disabled={pending || state.phase === 'picking'}>
            <option value="threadtime">threadtime</option>
            <option value="brief">brief</option>
            <option value="epoch">epoch</option>
          </select>
        </label>
        <label>
          <span>{t('tools.maxLines')}</span>
          <input type="number" min="1" max={MAX_LOG_LINES} value={state.maxLines} onChange={(event) => patchState({ maxLines: Math.max(1, Math.min(MAX_LOG_LINES, Number(event.currentTarget.value) || 1)) })} disabled={pending || state.phase === 'picking'} />
        </label>
        {state.mode === 'stream' ? (
          <label>
            <span>{t('tools.logcatDuration')}</span>
            <input type="number" min="1" max="120" value={state.timeoutSeconds} onChange={(event) => patchState({ timeoutSeconds: Math.max(1, Math.min(120, Number(event.currentTarget.value) || 1)) })} disabled={pending || state.phase === 'picking'} />
          </label>
        ) : null}
        <label>
          <span>{t('tools.logcatRedaction')}</span>
          <select value={redaction} onChange={(event) => patchState({ redaction: event.currentTarget.value as LogcatRedaction })} disabled={pending || state.phase === 'picking'}>
            <option value="strict">{t('tools.logcatRedactionStrict')}</option>
            <option value="standard">{t('tools.logcatRedactionStandard')}</option>
            {expertMode ? <option value="none">{t('tools.logcatRedactionNone')}</option> : null}
          </select>
        </label>
      </div>

      <p className={`logcat-redaction-note ${redaction === 'none' ? 'is-warning' : ''}`}>
        <Icon name={redaction === 'none' ? 'warningPng' : 'shield'} size={18} />
        <span>{t(redaction === 'strict' ? 'tools.logcatRedactionStrictDetail' : redaction === 'standard' ? 'tools.logcatRedactionStandardDetail' : 'tools.logcatRedactionNoneDetail')}</span>
      </p>

      <div className="logcat-actions">
        {pending ? (
          <Button variant="danger" onClick={() => void cancel()} disabled={state.phase === 'cancelling'}>
            {t(state.phase === 'cancelling' ? 'tools.logcatCancelling' : 'tools.logcatCancel')}
          </Button>
        ) : (
          <Button variant="primary" icon="logs" onClick={() => void runCapture()} disabled={!adbReady || hostBusy || state.phase === 'picking'}>
            {t(state.mode === 'snapshot' ? 'tools.logcatCollectSnapshot' : 'tools.logcatStartStream')}
          </Button>
        )}
        <Button icon="download" onClick={() => void exportCapture()} disabled={!adbReady || hostBusy || pending || state.phase === 'picking'}>{t('tools.logcatExport')}</Button>
        {visibleLines?.length ? <Button variant="ghost" onClick={clear} disabled={pending}>{t('tools.logcatClear')}</Button> : null}
      </div>
      <p className="logcat-export-help">{t('tools.logcatExportDetail')}</p>

      {pending || state.phase === 'picking' ? (
        <div className="logcat-progress">
          <span className="sr-only" role="status">
            {t(state.phase === 'picking' ? 'tools.logcatChoosingExport' : state.phase === 'cancelling' ? 'tools.logcatCancelling' : state.mode === 'stream' ? 'tools.logcatStreaming' : 'tools.logcatCollecting')}
          </span>
          <span className="status-dot status-dot--active" />
          <div>
            <strong>{t(state.phase === 'picking' ? 'tools.logcatChoosingExport' : state.phase === 'cancelling' ? 'tools.logcatCancelling' : state.mode === 'stream' ? 'tools.logcatStreaming' : 'tools.logcatCollecting')}</strong>
            <small aria-hidden="true">{operationCurrent ? t('tools.logcatProgressLines', { count: operationCurrent }) : t('tools.logcatBoundedStatus', { count: state.maxLines })}</small>
          </div>
          {progress !== null ? <progress aria-label={t('tools.logcatProgress')} max={100} value={progress} /> : null}
        </div>
      ) : null}

      {state.phase === 'cancelled' ? <div className="inline-alert inline-alert--warning" role="status"><Icon name="warningPng" size={18} /><span>{t('tools.logcatCancelled')}</span></div> : null}
      {state.phase === 'failed' ? <div className="inline-alert inline-alert--danger" role="alert"><Icon name="warningPng" size={18} /><span>{t(state.code === 'logcat_result_invalid' ? 'tools.logcatInvalidResult' : 'tools.logcatFailed')}</span></div> : null}

      {visibleReport ? (
        <div className="logcat-summary" role="status" aria-live="polite" aria-label={t('tools.logcatSummary')}>
          <Badge tone="accent">{t('tools.logcatLineCount', { count: visibleReport.lineCount })}</Badge>
          <Badge tone="neutral">{t('tools.logcatRedactedCount', { count: visibleReport.redactedCount })}</Badge>
          <Badge tone="success">{t('tools.logcatBounded')}</Badge>
          {visibleReport.truncated ? <Badge tone="warning">{t('tools.logcatTruncated')}</Badge> : null}
        </div>
      ) : null}

      {visibleLines && previewTotal !== null && previewTotal > visibleLines.length ? (
        <p className="logcat-export-help" role="note">
          {t('tools.logcatPreviewLimited', {
            shown: visibleLines.length,
            total: previewTotal,
          })}
        </p>
      ) : null}

      {visibleReport?.export ? (
        <div className="logcat-export-receipt" role="status">
          <Icon name="check" size={18} />
          <span><strong>{t('tools.logcatExported', { name: visibleReport.export.fileName })}</strong><small>{formatBytes(visibleReport.export.size)} · SHA-256</small></span>
          <code title={visibleReport.export.sha256}>{visibleReport.export.sha256}</code>
        </div>
      ) : null}

      {visibleLines?.length ? (
        <pre ref={outputRef} className="tool-log-viewer" aria-label={t('tools.logcatOutput')} aria-live="off" tabIndex={0}>{visibleText}</pre>
      ) : (
        <EmptyState icon="logs" title={t('common.none')} detail={t('tools.logcatEmpty')} />
      )}
    </div>
  );
}
