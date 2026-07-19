import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import axe from 'axe-core';
import { describe, expect, it, vi } from 'vitest';
import type { BridgeCommand } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import { DevicePage } from '../pages/Pages';
import {
  OtaDiagnosticsPanel,
  parseOtaDiagnosticReport,
} from '../pages/device/OtaDiagnosticsPanel';
import type { ActiveOperation, Device, HostSnapshot } from '../types';
import type { SharedPageProps } from '../pages/shared';

const MAX_LOG_LINES = 5_000;
const REQUESTED_LOG_LINES = 1_000;

function adbDevice(): Device {
  return { ...structuredClone(demoSnapshot.devices[0]), mode: 'adb' };
}

function renderPanel({
  device = adbDevice(),
  toolchainReady = true,
  activeOperation = null,
  onCommand,
}: {
  device?: Device;
  toolchainReady?: boolean;
  activeOperation?: ActiveOperation | null;
  onCommand: SharedPageProps['onCommand'];
}) {
  return render(
    <I18nProvider locale="en">
      <OtaDiagnosticsPanel
        device={device}
        toolchainReady={toolchainReady}
        activeOperation={activeOperation}
        onCommand={onCommand}
      />
    </I18nProvider>,
  );
}

function certificateValue() {
  return {
    action: 'certificates',
    archivePresent: true,
    count: 2,
    entries: ['META-INF/com/android/otacert.x509.pem', 'releasekey.x509.pem'],
    bounded: true,
  };
}

function logsValue() {
  return {
    action: 'logs',
    lineCount: 2,
    lines: [
      '07-18 I update_engine: serial=<serial> token=<redacted>',
      '07-18 E update_engine_client: password=<redacted>',
    ],
    redactedCount: 2,
    bounded: true,
  };
}

describe('OTA diagnostics', () => {
  it('inspects a closed certificate archive DTO without claiming cryptographic verification', async () => {
    const user = userEvent.setup();
    const device = adbDevice();
    const onCommand: SharedPageProps['onCommand'] = vi.fn(async () => ({
      result: {
        status: 'SUCCESS',
        code: 'ota_certificates_inspected',
        stdout: 'RAW-PRIVATE-STDOUT',
        value: certificateValue(),
      },
    }));
    renderPanel({ device, onCommand });

    await user.click(screen.getByRole('button', { name: 'OTA certificates' }));
    expect(onCommand).toHaveBeenCalledWith(
      'device.ota.certificates',
      { serial: device.serial },
      { returnCancelled: true },
    );
    const heading = await screen.findByRole('heading', { name: 'OTA certificates' });
    await waitFor(() => expect(heading.closest('section')).toHaveFocus());
    expect(screen.getByText('Certificate archive')).toBeVisible();
    expect(screen.getByText('Present')).toBeVisible();
    expect(screen.getByText('META-INF/com/android/otacert.x509.pem')).toBeVisible();
    expect(screen.queryByText(/verified|cryptographic/i)).not.toBeInTheDocument();
    expect(screen.queryByText('RAW-PRIVATE-STDOUT')).not.toBeInTheDocument();
  });

  it('requests a fixed bounded update_engine snapshot and renders only typed redacted lines', async () => {
    const user = userEvent.setup();
    const device = adbDevice();
    const onCommand: SharedPageProps['onCommand'] = vi.fn(async () => ({
      result: { status: 'SUCCESS', value: logsValue(), stderr: 'PRIVATE-STDERR' },
    }));
    const { container } = renderPanel({ device, onCommand });

    await user.click(screen.getByRole('button', { name: 'update_engine snapshot' }));
    expect(onCommand).toHaveBeenCalledWith(
      'device.ota.logs',
      { serial: device.serial, maxLines: REQUESTED_LOG_LINES },
      { returnCancelled: true },
    );
    expect(await screen.findByText('2 log lines')).toBeVisible();
    expect(screen.getByText('2 redacted')).toBeVisible();
    const result = screen.getByRole('heading', { name: 'update_engine snapshot' }).closest('section');
    expect(result?.querySelector('pre')).toHaveTextContent('token=<redacted>');
    expect(screen.queryByText('PRIVATE-STDERR')).not.toBeInTheDocument();

    const results = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations).toEqual([]);
  });

  it('uses the snapshot operation ID for cancellation and preserves the cancelled terminal state', async () => {
    const user = userEvent.setup();
    const device = adbDevice();
    let finish: ((response: { result: Record<string, unknown> }) => void) | undefined;
    const onCommand: SharedPageProps['onCommand'] = vi.fn((command: BridgeCommand) => {
      if (command === 'operation.cancel') {
        return Promise.resolve({ result: { status: 'SUCCESS', accepted: true } });
      }
      return new Promise<{ result: Record<string, unknown> }>((resolve) => { finish = resolve; });
    });
    const view = renderPanel({ device, onCommand });

    await user.click(screen.getByRole('button', { name: 'update_engine snapshot' }));
    expect(screen.getByText('Running OTA diagnostic...').closest('[role="status"]')).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Cancel diagnostic' })).not.toBeInTheDocument();

    view.rerender(
      <I18nProvider locale="en">
        <OtaDiagnosticsPanel
          device={device}
          toolchainReady
          activeOperation={{
            id: 'different-destructive-operation',
            kind: 'flash.execute',
            label: 'Flash device',
            status: 'running',
          }}
          onCommand={onCommand}
        />
      </I18nProvider>,
    );
    expect(screen.queryByRole('button', { name: 'Cancel diagnostic' })).not.toBeInTheDocument();

    view.rerender(
      <I18nProvider locale="en">
        <OtaDiagnosticsPanel
          device={device}
          toolchainReady
          activeOperation={{
            id: 'ota-diagnostic-operation',
            kind: 'device.ota.logs',
            label: 'OTA logs',
            status: 'running',
            progress: 37,
          }}
          onCommand={onCommand}
        />
      </I18nProvider>,
    );
    expect(screen.getByRole('progressbar', { name: 'OTA diagnostic progress' })).toHaveAttribute('value', '37');
    await user.click(screen.getByRole('button', { name: 'Cancel diagnostic' }));
    expect(onCommand).toHaveBeenCalledWith('operation.cancel', { operationId: 'ota-diagnostic-operation' });
    expect(screen.getByText('Cancelling diagnostic...')).toBeVisible();

    await act(async () => {
      finish?.({ result: { status: 'CANCELLED', code: 'operation_cancelled' } });
    });
    const cancelled = await screen.findByText('OTA diagnostic cancelled');
    await waitFor(() => expect(cancelled.closest('section')).toHaveFocus());
  });

  it('is unavailable without exactly one selected ADB device and a ready toolchain', () => {
    const snapshot = structuredClone(demoSnapshot) as HostSnapshot;
    snapshot.devices = [adbDevice(), { ...adbDevice(), serial: 'SECOND-DEVICE' }];
    snapshot.selectedSerials = snapshot.devices.map((device) => device.serial);
    const onCommand: SharedPageProps['onCommand'] = vi.fn(async () => ({ result: {} }));
    render(
      <I18nProvider locale="en">
        <DevicePage
          snapshot={snapshot}
          selectedSerials={snapshot.selectedSerials}
          onSelectionChange={vi.fn()}
          onCommand={onCommand}
          expertMode={false}
        />
      </I18nProvider>,
    );
    const card = screen.getByText('OTA diagnostics').closest('.card') as HTMLElement;
    expect(within(card).getByText(/exactly one device in ADB mode/i)).toBeVisible();
    expect(within(card).getByRole('button', { name: 'OTA certificates' })).toBeDisabled();
    expect(within(card).getByRole('button', { name: 'update_engine snapshot' })).toBeDisabled();

    const unavailable = renderPanel({ device: adbDevice(), toolchainReady: false, onCommand });
    const unavailableCard = within(unavailable.container).getByText('OTA diagnostics').closest('.card') as HTMLElement;
    expect(within(unavailableCard).getByRole('button', { name: 'OTA certificates' })).toBeDisabled();
  });

  it('rejects open, mismatched, unsafe and oversized DTOs before rendering', async () => {
    expect(parseOtaDiagnosticReport('certificates', certificateValue())).not.toBeNull();
    expect(parseOtaDiagnosticReport('certificates', { ...certificateValue(), signed: true })).toBeNull();
    expect(parseOtaDiagnosticReport('certificates', { ...certificateValue(), action: 'logs' })).toBeNull();
    expect(parseOtaDiagnosticReport('certificates', {
      ...certificateValue(),
      entries: ['../releasekey.x509.pem', 'releasekey.x509.pem'],
    })).toBeNull();
    expect(parseOtaDiagnosticReport('logs', logsValue())).not.toBeNull();
    expect(parseOtaDiagnosticReport('logs', {
      ...logsValue(),
      lines: Array.from({ length: MAX_LOG_LINES + 1 }, () => 'update_engine: bounded'),
      lineCount: MAX_LOG_LINES + 1,
    })).toBeNull();
    expect(parseOtaDiagnosticReport('logs', {
      ...logsValue(),
      lines: ['ActivityManager: not an OTA line'],
      lineCount: 1,
    })).toBeNull();

    const user = userEvent.setup();
    const invalid: SharedPageProps['onCommand'] = vi.fn(async () => ({
      result: { status: 'SUCCESS', value: { ...logsValue(), unexpected: 'not closed' } },
    }));
    renderPanel({ onCommand: invalid });
    await user.click(screen.getByRole('button', { name: 'update_engine snapshot' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('valid typed report');
    expect(screen.queryByText('not closed')).not.toBeInTheDocument();
  });

  it('ships non-empty gettext entries for all six supported locales', () => {
    const locales = ['en', 'es', 'fr', 'it', 'zh_CN', 'zh_TW'];
    const keys = [
      'otaTitle', 'otaDetail', 'otaGuard', 'otaCertificates', 'otaCertificatesDetail',
      'otaLogs', 'otaLogsDetail', 'otaRunning', 'otaCancelling', 'otaCancel',
      'otaCancelled', 'otaFailed', 'otaProgress', 'otaArchive', 'otaPresent',
      'otaCertificateCount', 'otaBound', 'otaBounded', 'otaLogLines', 'otaRedacted',
      'otaNoLogs',
    ];
    for (const locale of locales) {
      const catalog = readFileSync(
        resolve(process.cwd(), '..', '..', 'locale', locale, 'LC_MESSAGES', 'pixelflasher.po'),
        'utf8',
      );
      for (const key of keys) {
        const match = catalog.match(new RegExp(
          `msgctxt "web\\.device\\.${key}"\\r?\\nmsgid "[^"]+"\\r?\\nmsgstr "([^"]+)"`,
        ));
        expect(match?.[1], `${locale}:${key}`).toBeTruthy();
      }
    }
  });
});
