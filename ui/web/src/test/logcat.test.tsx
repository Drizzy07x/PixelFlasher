import { useCallback, useState } from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import axe from 'axe-core';
import { describe, expect, it, vi } from 'vitest';
import App from '../App';
import { commands } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import {
  LogcatPanel,
  MAX_LOGCAT_PREVIEW_BYTES,
  MAX_LOGCAT_PREVIEW_LINES,
  initialLogcatUiState,
  logcatDefaultFileName,
  parseLogcatClearReceipt,
  parseLogcatReport,
  useLogcatExpertGuard,
  type LogcatUiState,
} from '../pages/tooling/LogcatPanel';
import type { SharedPageProps } from '../pages/shared';
import type { ActiveOperation, BridgeRequest, Device, HostSnapshot } from '../types';

const WRITE_GRANT = 'w'.repeat(64);
const DIGEST = 'e'.repeat(64);

function adbDevice() {
  const device = structuredClone(demoSnapshot.devices[0]) as Device;
  device.mode = 'adb';
  return device;
}

function report(serial: string, overrides: Record<string, unknown> = {}) {
  const lines = [
    '07-19 10:00:00.100 I/ActivityManager: ready',
    '07-19 10:00:00.200 W/Network: [REDACTED]',
  ];
  return {
    targetSerial: serial,
    mode: 'snapshot',
    lineCount: lines.length,
    lines,
    text: lines.join('\n'),
    redaction: 'strict',
    redactedCount: 1,
    bounded: true,
    truncated: false,
    ...overrides,
  };
}

function success(value: Record<string, unknown>, code = 'logcat_collected') {
  return { result: { status: 'SUCCESS', code, value } };
}

function clearReceipt(serial: string, overrides: Record<string, unknown> = {}) {
  return {
    targetSerial: serial,
    buffers: ['all'],
    clearCommandCompleted: true,
    controlCommandVerified: true,
    mainBufferSentinelVerified: true,
    verificationEntryRetained: true,
    ...overrides,
  };
}

function completedLogcatState(serial: string): LogcatUiState {
  const output = report(serial);
  return {
    ...initialLogcatUiState,
    phase: 'success',
    targetSerial: serial,
    lines: output.lines as string[],
    report: {
      targetSerial: serial,
      mode: 'snapshot',
      lineCount: output.lineCount,
      redaction: 'strict',
      redactedCount: output.redactedCount,
      bounded: true,
      truncated: false,
    },
  };
}

function renderPanel({
  onCommand,
  operation = null,
  expertMode = true,
}: {
  onCommand: SharedPageProps['onCommand'];
  operation?: ActiveOperation | null;
  expertMode?: boolean;
}) {
  const device = adbDevice();
  const view = render(
    <I18nProvider locale="en">
      <LogcatPanel
        device={device}
        operation={operation}
        adbReady
        hostBusy={false}
        expertMode={expertMode}
        onCommand={onCommand}
      />
    </I18nProvider>,
  );
  return {
    device,
    ...view,
    update(nextOperation: ActiveOperation | null, nextExpertMode = expertMode) {
      view.rerender(
        <I18nProvider locale="en">
          <LogcatPanel
            device={device}
            operation={nextOperation}
            adbReady
            hostBusy={false}
            expertMode={nextExpertMode}
            onCommand={onCommand}
          />
        </I18nProvider>,
      );
    },
  };
}

function RedactionHarness({ expertMode, onCommand }: { expertMode: boolean; onCommand: SharedPageProps['onCommand'] }) {
  const [uiState, setUiState] = useState<LogcatUiState>({ ...initialLogcatUiState, redaction: 'none' });
  return (
    <I18nProvider locale="en">
      <LogcatPanel
        device={adbDevice()}
        operation={null}
        adbReady
        hostBusy={false}
        expertMode={expertMode}
        onCommand={onCommand}
        uiState={uiState}
        onUiStateChange={setUiState}
      />
    </I18nProvider>
  );
}

function GuardedLogcatHarness({
  expertMode,
  initialState,
  operation = null,
  progressBatch,
  onCommand,
  clearBufferedProgress,
}: {
  expertMode: boolean;
  initialState: LogcatUiState;
  operation?: ActiveOperation | null;
  progressBatch?: readonly ActiveOperation[];
  onCommand: SharedPageProps['onCommand'];
  clearBufferedProgress?: () => void;
}) {
  const [uiState, setUiState] = useState(initialState);
  const cancelOperation = useCallback(
    (operationId: string) => onCommand(commands.operationCancel, { operationId }),
    [onCommand],
  );
  useLogcatExpertGuard({
    expertMode,
    state: uiState,
    setState: setUiState,
    cancelOperation,
    clearBufferedProgress,
  });
  return (
    <I18nProvider locale="en">
      <LogcatPanel
        device={adbDevice()}
        operation={operation}
        progressBatch={progressBatch}
        adbReady
        hostBusy={false}
        expertMode={expertMode}
        onCommand={onCommand}
        uiState={uiState}
        onUiStateChange={setUiState}
      />
      <output data-testid="logcat-state">
        {JSON.stringify({
          phase: uiState.phase,
          redaction: uiState.redaction,
          requestedRedaction: uiState.requestedRedaction,
          operationId: uiState.operationId,
          lineCount: uiState.lines.length,
          reportRedaction: uiState.report?.redaction ?? null,
        })}
      </output>
    </I18nProvider>
  );
}

function operationLine(
  operationId: string,
  serial: string,
  current: number,
  total: number,
  line = `line-${current}`,
): ActiveOperation {
  return {
    id: operationId,
    kind: commands.toolsLogcat,
    label: line,
    status: 'running',
    progress: Math.floor(current / total * 100),
    current,
    total,
    detail: line,
    targetSerial: serial,
  };
}

describe('bounded Logcat viewer', () => {
  it('creates a Windows-safe default export name for wireless serials', () => {
    expect(logcatDefaultFileName('192.168.1.42:37123')).toBe(
      'PixelFlasher-logcat-192.168.1.42_37123.txt',
    );
  });

  it('collects a strict snapshot, validates the typed result, and exposes an accessible summary', async () => {
    const user = userEvent.setup();
    const device = adbDevice();
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async () => success(report(device.serial)));
    const view = renderPanel({ onCommand });

    await user.click(screen.getByRole('button', { name: 'Collect snapshot' }));

    await waitFor(() => expect(onCommand).toHaveBeenCalledWith(
      commands.toolsLogcat,
      {
        serial: device.serial,
        mode: 'snapshot',
        buffers: ['main'],
        formatEnabled: true,
        formatVerb: 'long',
        formatModifiers: ['color', 'descriptive'],
        filters: [{ tag: '*', priority: 'D' }],
        maxLines: 500,
        timeoutSeconds: 30,
        redaction: 'strict',
      },
      {
        returnCancelled: true,
        returnFailed: true,
        suppressNotice: true,
        onOperationAccepted: expect.any(Function),
      },
    ));
    expect(await screen.findByText(/ActivityManager: ready/)).toBeVisible();
    expect(screen.getByText('2 lines')).toBeVisible();
    expect(screen.getByText('1 values redacted')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Clear viewer' })).toBeEnabled();
    const results = await axe.run(view.container, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations).toEqual([]);
  });

  it('sends the complete advanced payload with typed filters, UID ordering, and a regex timeout cap', async () => {
    const user = userEvent.setup();
    const device = adbDevice();
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async () => success(report(device.serial, {
      mode: 'stream',
      redaction: 'none',
    })));
    renderPanel({ onCommand, expertMode: true });

    await user.click(screen.getByRole('button', { name: 'Bounded stream' }));
    await user.click(screen.getByRole('checkbox', { name: 'system' }));
    await user.click(screen.getByRole('checkbox', { name: 'radio' }));
    await user.selectOptions(screen.getByRole('combobox', { name: 'Line format' }), 'threadtime');
    await user.click(screen.getByRole('checkbox', { name: 'descriptive' }));
    await user.click(screen.getByRole('checkbox', { name: 'uid' }));
    await user.click(screen.getByRole('checkbox', { name: 'usec' }));
    await user.clear(screen.getByRole('textbox', { name: 'Tag filter' }));
    await user.type(screen.getByRole('textbox', { name: 'Tag filter' }), 'ActivityManager');
    await user.selectOptions(screen.getByRole('combobox', { name: 'Minimum priority' }), 'E');
    await user.type(screen.getByRole('textbox', { name: 'Regex filter (Expert)' }), 'FATAL.*');
    await user.type(screen.getByRole('textbox', { name: 'UID filters (Expert)' }), '2000, 1000');
    fireEvent.change(screen.getByRole('spinbutton', { name: 'Maximum lines' }), {
      target: { value: '2048' },
    });
    fireEvent.change(screen.getByRole('spinbutton', { name: 'Duration in seconds' }), {
      target: { value: '90' },
    });
    await user.selectOptions(screen.getByRole('combobox', { name: 'Redaction policy' }), 'none');

    await user.click(screen.getByRole('button', { name: 'Start bounded stream' }));

    await waitFor(() => expect(onCommand).toHaveBeenCalledWith(
      commands.toolsLogcat,
      {
        serial: device.serial,
        mode: 'stream',
        buffers: ['main', 'system', 'radio'],
        formatEnabled: true,
        formatVerb: 'threadtime',
        formatModifiers: ['color', 'uid', 'usec'],
        filters: [{ tag: 'ActivityManager', priority: 'E' }],
        regex: 'FATAL.*',
        uids: [1000, 2000],
        maxLines: 2048,
        timeoutSeconds: 30,
        redaction: 'none',
      },
      {
        returnCancelled: true,
        returnFailed: true,
        suppressNotice: true,
        onOperationAccepted: expect.any(Function),
      },
    ));
  });

  it('ignores incompatible format modifiers when device formatting is disabled', async () => {
    const user = userEvent.setup();
    const device = adbDevice();
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async () => success(report(device.serial)));
    renderPanel({ onCommand, expertMode: true });

    await user.click(screen.getByRole('checkbox', { name: 'epoch' }));
    await user.click(screen.getByRole('checkbox', { name: 'monotonic' }));
    expect(screen.getByRole('button', { name: 'Collect snapshot' })).toBeDisabled();
    expect(screen.getByRole('alert')).toHaveTextContent(/Correct the tag, modifier, regex, or UID filter/);

    await user.click(screen.getByRole('checkbox', { name: 'Enable Logcat formatting' }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Collect snapshot' })).toBeEnabled());
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Collect snapshot' }));

    await waitFor(() => expect(onCommand).toHaveBeenCalledWith(
      commands.toolsLogcat,
      {
        serial: device.serial,
        mode: 'snapshot',
        buffers: ['main'],
        formatEnabled: false,
        filters: [{ tag: '*', priority: 'D' }],
        maxLines: 500,
        timeoutSeconds: 30,
        redaction: 'strict',
      },
      expect.objectContaining({ onOperationAccepted: expect.any(Function) }),
    ));
  });

  it('clears the remote buffers only after a verified SUCCESS receipt and then empties the viewer', async () => {
    const user = userEvent.setup();
    const device = adbDevice();
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async () => success(
      clearReceipt(device.serial),
      'logcat_buffers_cleared',
    ));
    render(
      <GuardedLogcatHarness
        expertMode={false}
        initialState={completedLogcatState(device.serial)}
        onCommand={onCommand}
      />,
    );

    expect(screen.getByText(/ActivityManager: ready/)).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Clear device buffers' }));

    await waitFor(() => expect(onCommand).toHaveBeenCalledWith(
      commands.toolsLogcatClear,
      { serial: device.serial },
      {
        returnCancelled: true,
        returnFailed: true,
        suppressNotice: true,
        onOperationAccepted: expect.any(Function),
      },
    ));
    expect(await screen.findByText(/all-buffer clear control completed/i)).toBeVisible();
    expect(screen.queryByText(/ActivityManager: ready/)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Clear viewer' })).not.toBeInTheDocument();
  });

  it.each(['logcat_clear_failed', 'outcome_unknown'])(
    'preserves the existing viewer when remote clearing returns FAILED/%s',
    async (code) => {
      const user = userEvent.setup();
      const device = adbDevice();
      const onCommand = vi.fn<SharedPageProps['onCommand']>(async () => ({
        result: { status: 'FAILED', code, value: {} },
      }));
      render(
        <GuardedLogcatHarness
          expertMode={false}
          initialState={completedLogcatState(device.serial)}
          onCommand={onCommand}
        />,
      );

      await user.click(screen.getByRole('button', { name: 'Clear device buffers' }));

      expect(await screen.findByText(/could not be cleared with a verified outcome/i)).toBeVisible();
      expect(screen.getByText(/ActivityManager: ready/)).toBeVisible();
      expect(screen.getByText('2 lines')).toBeVisible();
      expect(screen.getByRole('button', { name: 'Clear viewer' })).toBeEnabled();
    },
  );

  it('submits a rapid double click on remote clear at most once', async () => {
    const device = adbDevice();
    let finish: ((response: ReturnType<typeof success>) => void) | undefined;
    const onCommand = vi.fn<SharedPageProps['onCommand']>((command) => {
      if (command !== commands.toolsLogcatClear) return Promise.resolve(null);
      return new Promise((resolve) => { finish = resolve; });
    });
    render(
      <GuardedLogcatHarness
        expertMode={false}
        initialState={completedLogcatState(device.serial)}
        onCommand={onCommand}
      />,
    );

    const clearButton = screen.getByRole('button', { name: 'Clear device buffers' });
    fireEvent.click(clearButton);
    fireEvent.click(clearButton);

    expect(onCommand.mock.calls.filter(([command]) => command === commands.toolsLogcatClear)).toHaveLength(1);
    await act(async () => {
      finish?.(success(clearReceipt(device.serial), 'logcat_buffers_cleared'));
    });
    expect(await screen.findByText(/all-buffer clear control completed/i)).toBeVisible();
  });

  it('uses a one-use save grant for a new capture and renders only a verified export receipt', async () => {
    const user = userEvent.setup();
    const device = adbDevice();
    const output = report(device.serial);
    const byteSize = new TextEncoder().encode(output.text as string).byteLength;
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async (command) => {
      if (command === commands.nativeSaveFile) {
        return {
          result: { status: 'SUCCESS', data: { grant: WRITE_GRANT } },
          revision: 42,
        };
      }
      return success({
        ...output,
        export: { fileName: `PixelFlasher-logcat-${device.serial}.txt`, sha256: DIGEST, size: byteSize },
      });
    });
    renderPanel({ onCommand });

    await user.click(screen.getByRole('button', { name: 'Capture and export' }));

    expect(onCommand).toHaveBeenCalledWith(commands.nativeSaveFile, {
      purpose: 'tools.logcat.export',
      title: 'Capture and export',
      defaultName: `PixelFlasher-logcat-${device.serial}.txt`,
      filters: [{ label: 'Text log files', extensions: ['txt', 'log'] }],
    });
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith(
      commands.toolsLogcat,
      expect.objectContaining({ serial: device.serial, grant: WRITE_GRANT }),
      expect.objectContaining({ expectedRevision: 42, onOperationAccepted: expect.any(Function) }),
    ));
    expect(await screen.findByText(`Exported PixelFlasher-logcat-${device.serial}.txt`)).toBeVisible();
    expect(screen.getByText(DIGEST)).toBeVisible();
    expect(document.body.textContent).not.toMatch(/C:\\|\/Users\/|\/home\//);
    expect(screen.getByText(/Runs a new capture with the current settings/)).toBeVisible();
  });

  it('shows bounded stream progress, appends redacted lines by sequence, and cancels by operation ID', async () => {
    const user = userEvent.setup();
    let finish: ((response: ReturnType<typeof success>) => void) | undefined;
    const onCommand = vi.fn<SharedPageProps['onCommand']>((command, _payload, options) => {
      if (command === commands.operationCancel) {
        return Promise.resolve({ result: { status: 'SUCCESS', code: 'cancellation_requested' } });
      }
      options?.onOperationAccepted?.('log-stream-operation');
      return new Promise((resolve) => { finish = resolve; });
    });
    const view = renderPanel({ onCommand });
    await user.click(screen.getByRole('button', { name: 'Bounded stream' }));
    await user.click(screen.getByRole('button', { name: 'Start bounded stream' }));

    view.update({
      id: 'log-stream-operation',
      kind: commands.toolsLogcat,
      label: 'streaming',
      status: 'running',
      progress: 12,
      current: 1,
      total: 500,
      detail: '07-19 I/Test: [REDACTED]',
      targetSerial: view.device.serial,
    });
    expect(await screen.findByText('07-19 I/Test: [REDACTED]')).toBeVisible();
    expect(screen.getByRole('progressbar', { name: 'Log collection progress' })).toHaveAttribute('value', '12');

    await user.click(screen.getByRole('button', { name: 'Cancel log collection' }));
    expect(onCommand).toHaveBeenCalledWith(commands.operationCancel, { operationId: 'log-stream-operation' });
    expect(screen.getAllByText('Cancelling log collection…')).not.toHaveLength(0);

    await act(async () => {
      finish?.({ result: { status: 'CANCELLED', code: 'logcat_cancelled', value: {} } });
    });
    expect(await screen.findByText('Log collection cancelled.')).toBeVisible();
  });

  it('keeps unredacted capture restricted to Expert Mode and returns to strict when Expert is disabled', async () => {
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async () => null);
    const view = render(<RedactionHarness expertMode onCommand={onCommand} />);
    expect(screen.getByRole('option', { name: 'None (Expert)' })).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Redaction policy' })).toHaveValue('none');

    view.rerender(<RedactionHarness expertMode={false} onCommand={onCommand} />);
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Redaction policy' })).toHaveValue('strict'));
    expect(screen.queryByRole('option', { name: 'None (Expert)' })).not.toBeInTheDocument();
  });

  it('immediately hides and purges a completed unredacted capture when Expert Mode is disabled', async () => {
    const device = adbDevice();
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async () => null);
    const unsafeState: LogcatUiState = {
      ...initialLogcatUiState,
      redaction: 'none',
      phase: 'success',
      targetSerial: device.serial,
      lines: ['RAW account=user@example.test token=secret'],
      report: {
        targetSerial: device.serial,
        mode: 'snapshot',
        lineCount: 1,
        redaction: 'none',
        redactedCount: 0,
        bounded: true,
        truncated: false,
      },
    };
    const view = render(
      <GuardedLogcatHarness expertMode initialState={unsafeState} onCommand={onCommand} />,
    );
    expect(screen.getByText(/RAW account=/)).toBeVisible();

    view.rerender(
      <GuardedLogcatHarness expertMode={false} initialState={unsafeState} onCommand={onCommand} />,
    );

    expect(screen.queryByText(/RAW account=/)).not.toBeInTheDocument();
    await waitFor(() => expect(screen.getByTestId('logcat-state')).toHaveTextContent(
      '"redaction":"strict","requestedRedaction":null,"operationId":null,"lineCount":0,"reportRedaction":null',
    ));
    expect(onCommand).not.toHaveBeenCalledWith(commands.operationCancel, expect.anything());
  });

  it('cancels an active unredacted capture exactly once and never exposes its buffered lines', async () => {
    const device = adbDevice();
    const clearBufferedProgress = vi.fn();
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async () => ({
      result: { status: 'SUCCESS', code: 'cancellation_requested' },
    }));
    const unsafeState: LogcatUiState = {
      ...initialLogcatUiState,
      mode: 'stream',
      redaction: 'none',
      requestedRedaction: 'none',
      phase: 'running',
      operationId: 'unsafe-logcat-operation',
      targetSerial: device.serial,
      lines: ['RAW token=secret'],
    };
    const active: ActiveOperation = {
      id: 'unsafe-logcat-operation',
      kind: commands.toolsLogcat,
      label: 'Logcat stream',
      status: 'running',
      targetSerial: device.serial,
    };
    const view = render(
      <GuardedLogcatHarness
        expertMode
        initialState={unsafeState}
        operation={active}
        progressBatch={[]}
        onCommand={onCommand}
        clearBufferedProgress={clearBufferedProgress}
      />,
    );
    expect(await screen.findByText('RAW token=secret')).toBeVisible();

    view.rerender(
      <GuardedLogcatHarness
        expertMode={false}
        initialState={unsafeState}
        operation={active}
        progressBatch={[]}
        onCommand={onCommand}
        clearBufferedProgress={clearBufferedProgress}
      />,
    );
    expect(screen.queryByText('RAW token=secret')).not.toBeInTheDocument();
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith(
      commands.operationCancel,
      { operationId: 'unsafe-logcat-operation' },
    ));

    view.rerender(
      <GuardedLogcatHarness
        expertMode={false}
        initialState={unsafeState}
        operation={active}
        progressBatch={[]}
        onCommand={onCommand}
        clearBufferedProgress={clearBufferedProgress}
      />,
    );
    await waitFor(() => expect(screen.getByTestId('logcat-state')).toHaveTextContent(
      '"phase":"cancelling","redaction":"strict","requestedRedaction":"none","operationId":"unsafe-logcat-operation","lineCount":0',
    ));
    expect(onCommand.mock.calls.filter(([command]) => command === commands.operationCancel)).toHaveLength(1);
    expect(clearBufferedProgress).toHaveBeenCalled();
  });

  it('preserves a safe capture when Expert Mode is disabled', async () => {
    const device = adbDevice();
    const clearBufferedProgress = vi.fn();
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async () => null);
    const safeState: LogcatUiState = {
      ...initialLogcatUiState,
      mode: 'stream',
      redaction: 'standard',
      requestedRedaction: 'standard',
      phase: 'running',
      operationId: 'safe-logcat-operation',
      targetSerial: device.serial,
      lines: ['safe diagnostic line'],
    };
    const active: ActiveOperation = {
      id: 'safe-logcat-operation',
      kind: commands.toolsLogcat,
      label: 'Logcat stream',
      status: 'running',
      targetSerial: device.serial,
    };
    render(
      <GuardedLogcatHarness
        expertMode={false}
        initialState={safeState}
        operation={active}
        progressBatch={[]}
        onCommand={onCommand}
        clearBufferedProgress={clearBufferedProgress}
      />,
    );

    expect(await screen.findByText('safe diagnostic line')).toBeVisible();
    expect(screen.getByTestId('logcat-state')).toHaveTextContent('"redaction":"standard"');
    expect(clearBufferedProgress).not.toHaveBeenCalled();
    expect(onCommand).not.toHaveBeenCalled();
  });

  it('preserves a completed standard report when only the next-capture selection was unredacted', async () => {
    const device = adbDevice();
    const clearBufferedProgress = vi.fn();
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async () => null);
    const safeState: LogcatUiState = {
      ...initialLogcatUiState,
      redaction: 'none',
      phase: 'success',
      targetSerial: device.serial,
      lines: ['previously redacted diagnostic line'],
      report: {
        targetSerial: device.serial,
        mode: 'snapshot',
        lineCount: 1,
        redaction: 'standard',
        redactedCount: 1,
        bounded: true,
        truncated: false,
      },
    };
    render(
      <GuardedLogcatHarness
        expertMode={false}
        initialState={safeState}
        onCommand={onCommand}
        clearBufferedProgress={clearBufferedProgress}
      />,
    );

    expect(screen.getByText('previously redacted diagnostic line')).toBeVisible();
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Redaction policy' })).toHaveValue('strict'));
    expect(screen.getByTestId('logcat-state')).toHaveTextContent('"lineCount":1,"reportRedaction":"standard"');
    expect(clearBufferedProgress).not.toHaveBeenCalled();
    expect(onCommand).not.toHaveBeenCalled();
  });

  it('batches streamed lines into a byte-bounded 500-line DOM preview without a live region per line', async () => {
    const device = adbDevice();
    const operationId = 'batched-logcat-operation';
    const batch = Array.from(
      { length: 600 },
      (_, index) => operationLine(operationId, device.serial, index + 1, 600),
    );
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async () => null);
    const streamingState: LogcatUiState = {
      ...initialLogcatUiState,
      mode: 'stream',
      requestedRedaction: 'strict',
      phase: 'running',
      operationId,
      targetSerial: device.serial,
      maxLines: 10_000,
    };
    const view = render(
      <GuardedLogcatHarness
        expertMode
        initialState={streamingState}
        operation={batch.at(-1)}
        progressBatch={batch}
        onCommand={onCommand}
      />,
    );

    const output = await screen.findByLabelText('Logcat output');
    await waitFor(() => expect(output.textContent).toContain('line-600'));
    const renderedLines = output.textContent?.split('\n') ?? [];
    expect(renderedLines).toHaveLength(MAX_LOGCAT_PREVIEW_LINES);
    expect(renderedLines[0]).toBe('line-101');
    expect(renderedLines.at(-1)).toBe('line-600');
    expect(new TextEncoder().encode(output.textContent ?? '').byteLength).toBeLessThanOrEqual(
      MAX_LOGCAT_PREVIEW_BYTES,
    );
    const progressRegion = view.container.querySelector('.logcat-progress');
    expect(progressRegion).not.toHaveAttribute('role');
    expect(progressRegion).not.toHaveAttribute('aria-live');
    expect(progressRegion?.querySelector('small')).toHaveAttribute('aria-hidden', 'true');
    expect(output).toHaveAttribute('aria-live', 'off');
    expect(screen.getByRole('note')).toHaveTextContent('Showing the last 500 of 600 lines.');
  });

  it('enforces the preview byte cap on the rendered text, including newline separators', async () => {
    const device = adbDevice();
    const operationId = 'byte-bounded-logcat-operation';
    const batch = Array.from({ length: 100 }, (_, index) => {
      const current = index + 1;
      return operationLine(
        operationId,
        device.serial,
        current,
        100,
        `line-${current}-${'x'.repeat(4_080)}`,
      );
    });
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async () => null);
    const streamingState: LogcatUiState = {
      ...initialLogcatUiState,
      mode: 'stream',
      requestedRedaction: 'strict',
      phase: 'running',
      operationId,
      targetSerial: device.serial,
      maxLines: 10_000,
    };
    render(
      <GuardedLogcatHarness
        expertMode
        initialState={streamingState}
        operation={batch.at(-1)}
        progressBatch={batch}
        onCommand={onCommand}
      />,
    );

    const output = await screen.findByLabelText('Logcat output');
    await waitFor(() => expect(output.textContent).toContain('line-100-'));
    const text = output.textContent ?? '';
    expect(new TextEncoder().encode(text).byteLength).toBeLessThanOrEqual(MAX_LOGCAT_PREVIEW_BYTES);
    expect(text.split('\n').length).toBeLessThan(100);
    expect(text).not.toContain('line-1-');
    expect(screen.getByRole('note')).toHaveTextContent(/Showing the last \d+ of 100 lines\./);
  });

  it('does not duplicate an overlapping persisted batch when the panel remounts', async () => {
    const device = adbDevice();
    const operationId = 'remounted-logcat-operation';
    const persistedState: LogcatUiState = {
      ...initialLogcatUiState,
      mode: 'stream',
      requestedRedaction: 'strict',
      phase: 'running',
      operationId,
      targetSerial: device.serial,
      lastProgressCurrent: 3,
      lines: ['line-1', 'line-2', 'line-3'],
    };
    const staleBatch = [
      operationLine(operationId, device.serial, 2, 4),
      operationLine(operationId, device.serial, 3, 4),
    ];
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async () => null);

    render(
      <GuardedLogcatHarness
        expertMode
        initialState={persistedState}
        operation={staleBatch.at(-1)}
        progressBatch={staleBatch}
        onCommand={onCommand}
      />,
    );

    const output = await screen.findByLabelText('Logcat output');
    await waitFor(() => expect(output.textContent).toBe('line-1\nline-2\nline-3'));
  });

  it('announces a local preview cap separately from backend truncation', () => {
    const device = adbDevice();
    const lines = Array.from({ length: MAX_LOGCAT_PREVIEW_LINES }, (_, index) => `line-${index + 101}`);
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async () => null);
    const completedState: LogcatUiState = {
      ...initialLogcatUiState,
      phase: 'success',
      targetSerial: device.serial,
      lines,
      report: {
        targetSerial: device.serial,
        mode: 'snapshot',
        lineCount: 600,
        redaction: 'strict',
        redactedCount: 0,
        bounded: true,
        truncated: false,
      },
    };
    render(
      <GuardedLogcatHarness expertMode={false} initialState={completedState} onCommand={onCommand} />,
    );

    expect(screen.getByRole('note')).toHaveTextContent('Showing the last 500 of 600 lines.');
    expect(screen.queryByText('Limit reached')).not.toBeInTheDocument();
  });

  it('retains the final Logcat batch when a terminal snapshot arrives before its animation frame', async () => {
    const user = userEvent.setup();
    const hostSnapshot = structuredClone(demoSnapshot) as HostSnapshot;
    hostSnapshot.revision = 50;
    hostSnapshot.activeOperation = null;
    hostSnapshot.active_operation = null;
    const serial = hostSnapshot.selectedSerials?.[0] ?? hostSnapshot.selectedSerial ?? '';
    let logcatRequest: BridgeRequest | null = null;
    const respond = (request: BridgeRequest, result: Record<string, unknown>) => {
      window.dispatchEvent(new CustomEvent('pixelflasher:message', {
        detail: {
          version: 2,
          requestId: request.requestId,
          ok: true,
          result,
        },
      }));
    };
    window.pixelflasher = {
      postMessage(raw) {
        const request = JSON.parse(raw) as BridgeRequest;
        if (request.command === commands.snapshotGet) {
          queueMicrotask(() => respond(request, hostSnapshot as unknown as Record<string, unknown>));
          return;
        }
        if (request.command === commands.settingsGet) {
          queueMicrotask(() => respond(request, {
            status: 'SUCCESS',
            code: 'settings_loaded',
            value: { preferences: hostSnapshot.preferences },
            revision: hostSnapshot.revision,
          }));
          return;
        }
        if (request.command === commands.toolsLogcat) {
          logcatRequest = request;
          return;
        }
        queueMicrotask(() => respond(request, {
          status: 'SUCCESS',
          code: 'command_completed',
          value: {},
          revision: hostSnapshot.revision,
        }));
      },
    };

    render(<App />);
    const navigation = within(await screen.findByRole('navigation', { name: 'Tasks' }));
    await user.click(navigation.getByRole('button', { name: 'Tools' }));
    await user.click(screen.getByRole('checkbox', { name: /Expert Mode/i }));
    await user.click(await screen.findByRole('button', { name: /Logcat/i }));
    const workspace = document.querySelector('.tool-workspace') as HTMLElement;
    await user.click(within(workspace).getByRole('button', { name: 'Bounded stream' }));
    await user.click(within(workspace).getByRole('button', { name: 'Start bounded stream' }));
    await waitFor(() => expect(logcatRequest).not.toBeNull());
    const activeRequest = logcatRequest as BridgeRequest | null;
    if (!activeRequest) throw new Error('The host did not receive the Logcat request.');
    const operationId = activeRequest.requestId;
    let frameId = 0;
    const queuedFrames = new Map<number, FrameRequestCallback>();
    const requestFrame = vi.spyOn(window, 'requestAnimationFrame').mockImplementation((callback) => {
      frameId += 1;
      queuedFrames.set(frameId, callback);
      return frameId;
    });
    const cancelFrame = vi.spyOn(window, 'cancelAnimationFrame').mockImplementation((id) => {
      queuedFrames.delete(id);
    });
    try {
      act(() => {
        for (let current = 1; current <= 128; current += 1) {
          window.dispatchEvent(new CustomEvent('pixelflasher:message', {
            detail: {
              version: 2,
              event: 'progress',
              revision: hostSnapshot.revision + current,
              payload: {
                event_type: 'progress',
                operation_id: operationId,
                kind: commands.toolsLogcat,
                phase: 'execute',
                message: `host-batch-line-${current}`,
                percent: Math.floor(current / 128 * 100),
                current,
                total: 128,
                target_serial: serial,
              },
            },
          }));
        }
        window.dispatchEvent(new CustomEvent('pixelflasher:message', {
          detail: {
            version: 2,
            event: 'snapshot',
            revision: hostSnapshot.revision + 129,
            payload: {
              ...hostSnapshot,
              revision: hostSnapshot.revision + 129,
              activeOperation: null,
              active_operation: null,
            },
          },
        }));
        respond(activeRequest, {
          status: 'CANCELLED',
          code: 'logcat_cancelled',
          value: {},
          operation_id: operationId,
          revision: hostSnapshot.revision + 129,
        });
      });

      expect(await within(workspace).findByText('Log collection cancelled.')).toBeVisible();
      const output = await within(workspace).findByLabelText('Logcat output');
      const renderedLines = output.textContent?.split('\n') ?? [];
      expect(renderedLines).toHaveLength(128);
      expect(renderedLines[0]).toBe('host-batch-line-1');
      expect(renderedLines.at(-1)).toBe('host-batch-line-128');
      expect(queuedFrames.size).toBe(0);
    } finally {
      requestFrame.mockRestore();
      cancelFrame.mockRestore();
    }
  });

  it('fails closed on divergent text, excessive redaction counts, foreign serials, and invalid export sizes', () => {
    const serial = adbDevice().serial;
    const valid = report(serial);
    expect(parseLogcatReport(valid, serial, 'snapshot', 'strict')).not.toBeNull();
    expect(parseLogcatReport({ ...valid, text: 'different' }, serial, 'snapshot', 'strict')).toBeNull();
    expect(parseLogcatReport({ ...valid, redactedCount: 3 }, serial, 'snapshot', 'strict')).toBeNull();
    expect(parseLogcatReport({ ...valid, targetSerial: 'OTHER' }, serial, 'snapshot', 'strict')).toBeNull();
    const oversizedUtf8Line = 'é'.repeat(2_049);
    expect(parseLogcatReport({
      ...valid,
      lineCount: 1,
      lines: [oversizedUtf8Line],
      text: oversizedUtf8Line,
      redactedCount: 0,
    }, serial, 'snapshot', 'strict')).toBeNull();
    expect(parseLogcatReport({
      ...valid,
      export: { fileName: 'logcat.txt', sha256: DIGEST, size: 1 },
    }, serial, 'snapshot', 'strict')).toBeNull();
  });

  it('parses only the exact verified remote-clear receipt', () => {
    const serial = adbDevice().serial;
    const valid = clearReceipt(serial);

    expect(parseLogcatClearReceipt(valid, serial)).toEqual(valid);
    expect(parseLogcatClearReceipt({ ...valid, transcript: ['logcat -c'] }, serial)).toBeNull();
    expect(parseLogcatClearReceipt({ ...valid, buffers: ['main'] }, serial)).toBeNull();
    expect(parseLogcatClearReceipt({ ...valid, controlCommandVerified: false }, serial)).toBeNull();
    expect(parseLogcatClearReceipt({ ...valid, targetSerial: 'OTHER' }, serial)).toBeNull();
    const { verificationEntryRetained: _omitted, ...missingProof } = valid;
    expect(parseLogcatClearReceipt(missingProof, serial)).toBeNull();
  });
});
