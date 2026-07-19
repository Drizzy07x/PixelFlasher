import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import axe from 'axe-core';
import { describe, expect, it, vi } from 'vitest';
import App from '../App';
import type { BridgeCommand } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import { DevicePage } from '../pages/Pages';
import { parseDeviceInspectionReport } from '../pages/device/DeviceInspectionPanel';
import type { BridgeRequest, HostSnapshot } from '../types';

function snapshotWithOneAdbDevice(): HostSnapshot {
  const snapshot = structuredClone(demoSnapshot);
  snapshot.devices = [snapshot.devices[0]];
  snapshot.selectedSerials = [snapshot.devices[0].serial];
  return snapshot;
}

function renderDevice(
  snapshot: HostSnapshot,
  onCommand: (command: BridgeCommand, payload?: Record<string, unknown>) => Promise<{
    result: Record<string, unknown>;
    revision?: number;
  } | null>,
) {
  return render(
    <I18nProvider locale="en">
      <DevicePage
        snapshot={snapshot}
        selectedSerials={snapshot.selectedSerials ?? []}
        onSelectionChange={vi.fn()}
        onCommand={onCommand}
        expertMode
      />
    </I18nProvider>,
  );
}

function propertiesValue(serial: string) {
  return {
    action: 'properties',
    targetSerial: serial,
    count: 3,
    properties: {
      'ro.product.model': 'Google Pixel 8a',
      'ro.build.id': 'AP4A.250205.002',
      'ro.serialno': '[REDACTED]',
    },
    redactedKeys: ['ro.serialno'],
    summary: {
      manufacturer: 'Google',
      model: 'Google Pixel 8a',
      codename: 'akita',
      androidVersion: '15',
      build: 'AP4A.250205.002',
      securityPatch: '2025-02-05',
      bootloader: 'akita-15.2-12345678',
    },
  };
}

describe('modern device inspection', () => {
  it('runs against one ADB serial, renders only typed data and copies the sanitized report', async () => {
    const user = userEvent.setup();
    const snapshot = snapshotWithOneAdbDevice();
    const serial = snapshot.devices[0].serial;
    const onCommand = vi.fn(async () => ({
      result: {
        status: 'SUCCESS',
        code: 'device_inspection_properties_succeeded',
        stdout: 'PRIVATE-RAW-STDOUT',
        stderr: 'PRIVATE-RAW-STDERR',
        value: propertiesValue(serial),
      },
    }));
    renderDevice(snapshot, onCommand);

    await user.click(screen.getByRole('button', { name: 'Properties' }));
    expect(onCommand).toHaveBeenCalledWith('device.inspect', { serial, action: 'properties' });
    const heading = await screen.findByRole('heading', { name: 'Properties' });
    await waitFor(() => expect(heading.closest('section')).toHaveFocus());
    expect(screen.getAllByText('Google Pixel 8a').length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText('3 properties')).toBeVisible();
    expect(screen.queryByText(/PRIVATE-RAW/)).not.toBeInTheDocument();

    const writeText = vi.spyOn(navigator.clipboard, 'writeText');
    await user.click(screen.getByRole('button', { name: 'Copy report' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledOnce());
    const copied = String(writeText.mock.calls[0][0]);
    expect(copied).toContain('"ro.serialno": "[REDACTED]"');
    expect(copied).not.toContain('PRIVATE-RAW');
    expect(await screen.findByText('Copied')).toBeVisible();
  });

  it('presents Screen XML, bootloader and PIF responses through action-specific views', async () => {
    const user = userEvent.setup();
    const snapshot = snapshotWithOneAdbDevice();
    const serial = snapshot.devices[0].serial;
    const values: Record<string, Record<string, unknown>> = {
      screenXml: {
        action: 'screenXml',
        targetSerial: serial,
        xml: '<?xml version="1.0" encoding="UTF-8"?>\n<hierarchy rotation="0"><node text="[REDACTED]" /></hierarchy>',
        sha256: 'b'.repeat(64),
        nodeCount: 2,
        redactedFields: 1,
      },
      bootloaderVersions: {
        action: 'bootloaderVersions',
        targetSerial: serial,
        source: 'adb_getprop',
        current: 'akita-15.2-12345678',
        slot: 'a',
        versions: { 'ro.bootloader': 'akita-15.2-12345678' },
      },
      pifPrint: {
        action: 'pifPrint',
        targetSerial: serial,
        format: 'playintegrityfork-v5-compatible',
        profile: {
          MANUFACTURER: 'Google',
          MODEL: 'Pixel 8a',
          FINGERPRINT: 'google/akita/akita:15/AP4A:user/release-keys',
          PRODUCT: 'akita',
          DEVICE: 'akita',
          SECURITY_PATCH: '2025-02-05',
          DEVICE_INITIAL_SDK_INT: '32',
        },
        json: 'UNTRUSTED-DUPLICATE-JSON',
      },
    };
    const onCommand = vi.fn(async (_command: BridgeCommand, payload: Record<string, unknown> = {}) => ({
      result: { status: 'SUCCESS', value: values[String(payload.action)] },
    }));
    renderDevice(snapshot, onCommand);

    await user.click(screen.getByRole('button', { name: 'Screen XML' }));
    expect(await screen.findByText('Report digest')).toBeVisible();
    const screenReport = screen.getByRole('heading', { name: 'Screen XML' }).closest('section');
    expect(screenReport?.querySelector('pre')).toHaveTextContent('[REDACTED]');

    await user.click(screen.getByRole('button', { name: 'Bootloader versions' }));
    expect(await screen.findByText('akita-15.2-12345678')).toBeVisible();
    expect(screen.getByText('adb_getprop')).toBeVisible();

    await user.click(screen.getByRole('button', { name: 'PIF profile' }));
    expect(await screen.findByText('DEVICE_INITIAL_SDK_INT')).toBeVisible();
    expect(screen.getByText('google/akita/akita:15/AP4A:user/release-keys')).toBeVisible();
    expect(screen.queryByText('UNTRUSTED-DUPLICATE-JSON')).not.toBeInTheDocument();
  });

  it('shows busy, cancel, cancelled and malformed-result states without stale data', async () => {
    const user = userEvent.setup();
    const snapshot = snapshotWithOneAdbDevice();
    const serial = snapshot.devices[0].serial;
    snapshot.activeOperation = { id: 'inspect-operation', label: 'Inspect', status: 'running' };
    let finishInspection: ((value: { result: Record<string, unknown> }) => void) | undefined;
    const onCommand = vi.fn((command: BridgeCommand) => {
      if (command === 'operation.cancel') {
        return Promise.resolve({ result: { accepted: true } });
      }
      return new Promise<{ result: Record<string, unknown> }>((resolve) => { finishInspection = resolve; });
    });
    renderDevice(snapshot, onCommand);

    await user.click(screen.getByRole('button', { name: 'Properties' }));
    expect(screen.getByText('Inspecting device...').closest('[role="status"]')).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Cancel inspection' }));
    expect(onCommand).toHaveBeenCalledWith('operation.cancel', { operationId: 'inspect-operation' });
    expect(screen.getByText('Cancelling inspection...').closest('[role="status"]')).toBeVisible();
    finishInspection?.({ result: { status: 'CANCELLED', code: 'operation_cancelled' } });
    expect(await screen.findByText('Inspection cancelled')).toBeVisible();

    const invalid = vi.fn(async () => ({
      result: { status: 'SUCCESS', value: propertiesValue('OTHER-SERIAL') },
    }));
    const invalidView = renderDevice(snapshotWithOneAdbDevice(), invalid);
    const inspectionCards = screen.getAllByText('Device inspection');
    const invalidCard = inspectionCards.at(-1)?.closest('.card');
    await user.click(within(invalidCard as HTMLElement).getByRole('button', { name: 'Properties' }));
    expect(await within(invalidView.container).findByRole('alert')).toHaveTextContent('valid typed report');
  });

  it('keeps inspection disabled without exactly one selected ADB target', () => {
    const snapshot = snapshotWithOneAdbDevice();
    snapshot.devices[0].mode = 'fastboot';
    const onCommand = vi.fn(async () => ({ result: {} }));
    renderDevice(snapshot, onCommand);
    expect(screen.getByText('Select exactly one device in ADB mode to inspect it.')).toBeVisible();
    for (const name of ['Properties', 'Screen XML', 'Bootloader versions', 'PIF profile']) {
      expect(screen.getByRole('button', { name })).toBeDisabled();
    }
  });

  it('rejects untyped reports before they can reach a copy surface', () => {
    const valid = propertiesValue('SERIAL');
    expect(parseDeviceInspectionReport('properties', valid, 'SERIAL')).not.toBeNull();
    expect(parseDeviceInspectionReport('properties', { ...valid, targetSerial: 'OTHER' }, 'SERIAL')).toBeNull();
    expect(parseDeviceInspectionReport('properties', {
      ...valid,
      properties: { ...valid.properties, 'ro.serialno': 'PRIVATE-SERIAL' },
    }, 'SERIAL')).toBeNull();
  });

  it('sends the current expectedRevision and has no automated accessibility violations', async () => {
    const user = userEvent.setup();
    const host = window.pixelflasher;
    const postMessage = vi.spyOn(host!, 'postMessage');
    const { container } = render(<App />);
    await screen.findByRole('heading', { name: 'Modern UI' });
    await user.click(within(screen.getByRole('navigation', { name: 'Tasks' })).getByRole('button', { name: 'Device' }));
    await user.click(await screen.findByRole('button', { name: 'Properties' }));
    expect(await screen.findByRole('heading', { name: 'Properties' })).toBeVisible();
    const request = postMessage.mock.calls
      .map(([raw]) => JSON.parse(String(raw)) as BridgeRequest)
      .find((candidate) => candidate.command === 'device.inspect');
    expect(request).toMatchObject({
      version: 2,
      payload: { action: 'properties', serial: snapshotWithOneAdbDevice().devices[0].serial },
    });
    expect(typeof request?.expectedRevision).toBe('number');

    const results = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations).toEqual([]);
  });
});
