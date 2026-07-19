import axe from 'axe-core';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { normalizeSnapshot } from '../bridge';
import type { BridgeCommand } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import { DeviceManagerPanel } from '../pages/device/DeviceManagerPanel';
import { DevicePage } from '../pages/Pages';
import type { DeviceManagementState, HostSnapshot } from '../types';

const management: DeviceManagementState = {
  schemaVersion: 1,
  scanEnabled: true,
  scanScope: 'enabled',
  devices: [
    {
      serial: 'A:B',
      label: 'Daily phone',
      enabled: true,
      model: 'Google Pixel 8a',
      codename: 'akita',
      connected: true,
      mode: 'adb',
      firstSeen: 10,
      lastSeen: 20,
    },
    {
      serial: 'AB',
      label: '',
      enabled: false,
      model: 'Google Pixel 7',
      codename: 'panther',
      connected: false,
      mode: 'offline',
      firstSeen: 5,
      lastSeen: 15,
    },
  ],
};

function host() {
  return vi.fn(async (_command: BridgeCommand, _payload: Record<string, unknown> = {}) => ({
    result: { status: 'SUCCESS' },
  }));
}

function renderManager(onCommand = host(), value = management) {
  return {
    onCommand,
    ...render(
      <I18nProvider locale="en">
        <DeviceManagerPanel management={value} onCommand={onCommand} />
      </I18nProvider>,
    ),
  };
}

describe('modern device manager', () => {
  it('updates scan policy, aliases and enabled state through typed commands', async () => {
    const user = userEvent.setup();
    const { onCommand } = renderManager();

    expect(screen.getByText('Scanning')).toBeVisible();
    expect(screen.getByRole('radio', { name: 'Enabled devices only' })).toBeChecked();
    await user.click(screen.getByRole('button', { name: 'Pause scanning' }));
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith('device.manager.policy', { scanEnabled: false }));

    await user.click(screen.getByRole('radio', { name: 'All detected devices' }));
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith('device.manager.policy', { scanScope: 'all' }));

    const connectedRow = screen.getByText('A:B').closest('li');
    expect(connectedRow).not.toBeNull();
    const alias = within(connectedRow!).getByRole('textbox', { name: 'Device label for A:B' });
    await user.clear(alias);
    await user.type(alias, 'Travel phone');
    await user.click(within(connectedRow!).getByRole('button', { name: 'Save label' }));
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith('device.manager.update', {
      serial: 'A:B',
      label: 'Travel phone',
    }));

    await user.click(within(connectedRow!).getByRole('button', { name: 'Disable' }));
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith('device.manager.update', {
      serial: 'A:B',
      enabled: false,
    }));
    expect(within(screen.getByText('AB').closest('li')!).getByText('Remembered')).toBeVisible();
  });

  it('requires an inline confirmation before removing remembered metadata', async () => {
    const user = userEvent.setup();
    const { onCommand } = renderManager();
    const row = screen.getByText('AB').closest('li');
    expect(row).not.toBeNull();

    const removeButton = within(row!).getByRole('button', { name: 'Remove' });
    await user.click(removeButton);
    const confirmation = within(row!).getByRole('group', { name: 'Remove remembered device AB' });
    expect(within(confirmation).getByText('Remove this remembered device?')).toBeVisible();
    expect(within(confirmation).getByRole('button', { name: 'Confirm removal' })).toHaveFocus();
    expect(onCommand).not.toHaveBeenCalledWith('device.manager.remove', expect.anything());

    await user.click(within(confirmation).getByRole('button', { name: 'Cancel' }));
    expect(within(row!).queryByRole('group', { name: 'Remove remembered device AB' })).not.toBeInTheDocument();
    const restoredRemoveButton = within(row!).getByRole('button', { name: 'Remove' });
    expect(restoredRemoveButton).toHaveFocus();
    await user.click(restoredRemoveButton);
    await user.click(within(row!).getByRole('button', { name: 'Confirm removal' }));
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith('device.manager.remove', { serial: 'AB' }));
    expect(screen.getByRole('group', { name: 'Device manager' })).toHaveFocus();
  });

  it('disables live refresh while scanning is paused and remains axe-clean', async () => {
    const user = userEvent.setup();
    const snapshot = structuredClone(demoSnapshot) as HostSnapshot;
    snapshot.deviceManagement = { ...management, scanEnabled: false };
    snapshot.device_management = snapshot.deviceManagement;
    const onCommand = host();
    const view = render(
      <I18nProvider locale="en">
        <DevicePage
          snapshot={snapshot}
          selectedSerials={[snapshot.devices[0].serial]}
          onSelectionChange={vi.fn()}
          onCommand={onCommand}
          expertMode
        />
      </I18nProvider>,
    );

    expect(screen.getByRole('button', { name: 'Refresh' })).toBeDisabled();
    expect(screen.getByText('Paused')).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Resume scanning' }));
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith('device.manager.policy', { scanEnabled: true }));
    const results = await axe.run(view.container, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations).toEqual([]);
  });

  it('normalizes the snake-case host state into the closed public DTO', () => {
    const raw = structuredClone(demoSnapshot) as HostSnapshot;
    raw.deviceManagement = undefined;
    raw.device_management = {
      ...management,
      devices: [{ ...management.devices[0] }],
    };
    const normalized = normalizeSnapshot(raw);

    expect(normalized.deviceManagement).toEqual({
      ...management,
      devices: [management.devices[0]],
    });
    expect(normalized.deviceManagement?.devices[0]).toMatchObject({ firstSeen: 10, lastSeen: 20 });
    expect(normalized.device_management).toBe(normalized.deviceManagement);
  });

  it('rejects timestamps outside the renderable contract and degrades safely', () => {
    const raw = structuredClone(demoSnapshot) as HostSnapshot;
    raw.deviceManagement = {
      ...management,
      devices: [{ ...management.devices[0], lastSeen: Number.MAX_SAFE_INTEGER }],
    };
    raw.device_management = raw.deviceManagement;
    expect(normalizeSnapshot(raw).deviceManagement?.devices).toEqual([]);

    renderManager(host(), {
      ...management,
      devices: [{ ...management.devices[0], lastSeen: Number.MAX_SAFE_INTEGER }],
    });
    expect(screen.getByText('Not seen yet')).toBeVisible();
  });
});
