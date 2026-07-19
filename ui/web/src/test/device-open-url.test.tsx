import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import axe from 'axe-core';
import { describe, expect, it, vi } from 'vitest';
import type { BridgeCommand } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import { DeviceOpenUrlPanel, parseOpenUrlReceipt } from '../pages/device/DeviceOpenUrlPanel';
import type { Device } from '../types';

const device = structuredClone(demoSnapshot.devices[0]);

function renderPanel(onCommand: (
  command: BridgeCommand,
  payload?: Record<string, unknown>,
) => Promise<{ result: Record<string, unknown> } | null>, mode: Device['mode'] = 'adb') {
  const target = { ...device, mode };
  return render(
    <I18nProvider locale="en">
      <DeviceOpenUrlPanel
        device={target}
        toolchainReady
        activeOperation={null}
        onCommand={onCommand}
      />
    </I18nProvider>,
  );
}

function receipt(serial = device.serial) {
  return {
    action: 'openUrl',
    targetSerial: serial,
    scheme: 'https',
    host: 'example.com',
    urlSha256: 'a'.repeat(64),
    intentAccepted: true,
  };
}

describe('modern device URL launcher', () => {
  it('submits once, accepts only the closed receipt and never renders the full URL', async () => {
    const user = userEvent.setup();
    let finish: ((value: { result: Record<string, unknown> }) => void) | undefined;
    const onCommand = vi.fn((_command: BridgeCommand) => new Promise<{ result: Record<string, unknown> }>((resolve) => {
      finish = resolve;
    }));
    renderPanel(onCommand);

    const input = screen.getByRole('textbox', { name: 'Web address' });
    await user.clear(input);
    await user.type(input, 'https://example.com/private?token=secret');
    await user.dblClick(screen.getByRole('button', { name: 'Open on device' }));

    expect(onCommand).toHaveBeenCalledOnce();
    expect(onCommand).toHaveBeenCalledWith('device.openUrl', {
      serial: device.serial,
      url: 'https://example.com/private?token=secret',
    });
    expect(screen.getByText('Opening the validated address...')).toBeVisible();

    finish?.({ result: { status: 'SUCCESS', code: 'device_open_url_succeeded', value: receipt() } });
    expect(await screen.findByText('The device accepted the browser intent.')).toBeVisible();
    expect(screen.getByText('https · example.com')).toBeVisible();
    expect(screen.getByText('a'.repeat(64))).toBeVisible();
    expect(screen.queryByText(/private\?token=secret/)).not.toBeInTheDocument();
    expect(input).toHaveValue('https://');
  });

  it('rejects extra, mismatched and malformed receipt fields', () => {
    expect(parseOpenUrlReceipt(receipt(), device.serial)).toEqual(receipt());
    expect(parseOpenUrlReceipt({ ...receipt(), targetSerial: 'OTHER' }, device.serial)).toBeNull();
    expect(parseOpenUrlReceipt({ ...receipt(), fullUrl: 'https://example.com/private' }, device.serial)).toBeNull();
    expect(parseOpenUrlReceipt({ ...receipt(), urlSha256: 'not-a-digest' }, device.serial)).toBeNull();
    expect(parseOpenUrlReceipt({ ...receipt(), urlSha256: 'A'.repeat(64) }, device.serial)).toBeNull();
    expect(parseOpenUrlReceipt({ ...receipt(), host: 'example.com/path' }, device.serial)).toBeNull();
    expect(parseOpenUrlReceipt({ ...receipt(), host: 'example..com' }, device.serial)).toBeNull();
  });

  it('preserves the input on typed failure and disables the action outside ADB', async () => {
    const user = userEvent.setup();
    const onCommand = vi.fn(async () => ({
      result: { status: 'FAILED', code: 'outcome_unknown' },
    }));
    const view = renderPanel(onCommand);
    const input = screen.getByRole('textbox', { name: 'Web address' });
    await user.clear(input);
    await user.type(input, 'https://example.com/retry');
    await user.click(screen.getByRole('button', { name: 'Open on device' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('outcome_unknown');
    expect(input).toHaveValue('https://example.com/retry');

    view.unmount();
    renderPanel(vi.fn(async () => ({ result: {} })), 'fastboot');
    expect(screen.getByText('Select exactly one device in ADB mode to open a URL.')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Open on device' })).toBeDisabled();
  });

  it('has no automated accessibility violations', async () => {
    const { container } = renderPanel(vi.fn(async () => ({ result: {} })));
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Web address' })).toBeVisible());
    const results = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations).toEqual([]);
  });
});
