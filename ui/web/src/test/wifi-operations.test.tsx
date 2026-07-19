import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { commands } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import { ToolsPage } from '../pages/tooling/ToolsPage';
import type { SharedPageProps } from '../pages/shared';
import type { HostSnapshot } from '../types';

type CommandResponse = NonNullable<Awaited<ReturnType<SharedPageProps['onCommand']>>>;

function snapshotWithoutSelection() {
  const snapshot = structuredClone(demoSnapshot) as HostSnapshot;
  snapshot.selectedSerial = null;
  snapshot.selected_serial = null;
  snapshot.selectedSerials = [];
  snapshot.selected_serials = [];
  return snapshot;
}

function renderTools({
  onCommand,
  snapshot = snapshotWithoutSelection(),
  selectedSerials = [],
  onSelectionChange = vi.fn(),
}: {
  onCommand: SharedPageProps['onCommand'];
  snapshot?: HostSnapshot;
  selectedSerials?: string[];
  onSelectionChange?: SharedPageProps['onSelectionChange'];
}) {
  render(
    <I18nProvider locale="en">
      <ToolsPage
        snapshot={snapshot}
        selectedSerials={selectedSerials}
        onSelectionChange={onSelectionChange}
        onCommand={onCommand}
        expertMode={false}
      />
    </I18nProvider>,
  );
  return { onSelectionChange };
}

async function openWifi() {
  const user = userEvent.setup();
  await user.click(screen.getByRole('button', { name: /Wireless ADB/i }));
  const workspace = document.querySelector('.tool-workspace') as HTMLElement;
  expect(workspace).toBeVisible();
  return { user, workspace };
}

function operationResult(status: 'SUCCESS' | 'FAILED' | 'CANCELLED'): CommandResponse {
  return {
    result: {
      status,
      code: `wifi_${status.toLowerCase()}`,
      message: `Wireless ADB ${status.toLowerCase()}`,
    },
  };
}

describe('Wireless ADB operations', () => {
  it('enables pair, connect, and disconnect without a selection while keeping status disabled', async () => {
    const onCommand = vi.fn<SharedPageProps['onCommand']>();
    const { onSelectionChange } = renderTools({ onCommand });
    const { user, workspace } = await openWifi();
    const action = within(workspace).getByRole('combobox', { name: 'Action' });
    const apply = within(workspace).getByRole('button', { name: 'Apply changes' });

    expect(action).toHaveValue('status');
    expect(apply).toBeDisabled();
    for (const endpointAction of ['pair', 'connect', 'disconnect'] as const) {
      await user.selectOptions(action, endpointAction);
      expect(apply).toBeEnabled();
    }
    expect(onCommand).not.toHaveBeenCalled();
    expect(onSelectionChange).not.toHaveBeenCalled();
  });

  it('runs status only for one selected ADB device with its exact serial payload', async () => {
    const snapshot = structuredClone(demoSnapshot) as HostSnapshot;
    const serial = snapshot.devices.find((device) => device.mode === 'adb')?.serial;
    expect(serial).toBeTruthy();
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async () => operationResult('SUCCESS'));
    const onSelectionChange = vi.fn<SharedPageProps['onSelectionChange']>();
    renderTools({ onCommand, snapshot, selectedSerials: [serial!], onSelectionChange });
    const { user, workspace } = await openWifi();

    await user.click(within(workspace).getByRole('button', { name: 'Apply changes' }));

    await waitFor(() => expect(onCommand).toHaveBeenCalledTimes(1));
    expect(onCommand).toHaveBeenCalledWith(commands.toolsWifiStatus, { serial });
    expect(onCommand.mock.calls.some(([command]) => command === commands.deviceScan)).toBe(false);
    expect(onCommand.mock.calls.some(([command]) => command === commands.deviceSelect)).toBe(false);
    expect(onSelectionChange).not.toHaveBeenCalled();
  });

  it('issues a fresh one-use grant for every pair and binds each operation to the returned revision', async () => {
    const grants = ['g'.repeat(64), 'h'.repeat(64)];
    const revisions = [41, 43];
    let issued = 0;
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async (command) => {
      if (command === commands.secretIssue) {
        const index = issued++;
        return {
          result: {
            status: 'SUCCESS',
            data: { grant: grants[index] },
          },
          revision: revisions[index],
        };
      }
      return { ...operationResult('SUCCESS'), revision: 50 + issued };
    });
    const onSelectionChange = vi.fn<SharedPageProps['onSelectionChange']>();
    renderTools({ onCommand, onSelectionChange });
    const { user, workspace } = await openWifi();
    await user.selectOptions(within(workspace).getByRole('combobox', { name: 'Action' }), 'pair');

    for (const [index, pairingCode] of ['123456', '654321'].entries()) {
      await user.click(within(workspace).getByRole('button', { name: 'Apply changes' }));
      const dialog = await screen.findByRole('dialog', { name: 'Six-digit pairing code' });
      await user.type(within(dialog).getByLabelText('Six-digit pairing code'), pairingCode);
      await user.click(within(dialog).getByRole('button', { name: 'Continue' }));
      await waitFor(() => {
        expect(onCommand.mock.calls.filter(([command]) => command === commands.toolsWifi)).toHaveLength(index + 1);
      });
      expect(within(workspace).getByText('Wireless ADB success')).toBeVisible();
    }

    const secretCalls = onCommand.mock.calls.filter(([command]) => command === commands.secretIssue);
    const pairCalls = onCommand.mock.calls.filter(([command]) => command === commands.toolsWifi);
    expect(secretCalls).toHaveLength(2);
    expect(pairCalls).toHaveLength(2);
    expect(secretCalls.map(([, payload]) => payload)).toEqual([
      { purpose: 'wifi.pairingCode', secret: '123456' },
      { purpose: 'wifi.pairingCode', secret: '654321' },
    ]);
    expect(pairCalls).toEqual([
      [
        commands.toolsWifi,
        { action: 'pair', host: '192.168.1.42', port: 5555, secretGrant: grants[0] },
        { expectedRevision: revisions[0] },
      ],
      [
        commands.toolsWifi,
        { action: 'pair', host: '192.168.1.42', port: 5555, secretGrant: grants[1] },
        { expectedRevision: revisions[1] },
      ],
    ]);
    expect(onCommand.mock.calls.some(([command]) => command === commands.deviceScan)).toBe(false);
    expect(onCommand.mock.calls.some(([command]) => command === commands.deviceSelect)).toBe(false);
    expect(onSelectionChange).not.toHaveBeenCalled();
    expect(document.body.textContent).not.toContain('123456');
    expect(document.body.textContent).not.toContain('654321');
  });

  it.each(['connect', 'disconnect'] as const)(
    'scans exactly once after successful %s using the operation revision and never selects the device',
    async (action) => {
      const onCommand = vi.fn<SharedPageProps['onCommand']>(async (command) => {
        if (command === commands.toolsWifi) return { ...operationResult('SUCCESS'), revision: 73 };
        if (command === commands.deviceScan) return { ...operationResult('SUCCESS'), revision: 74 };
        return null;
      });
      const onSelectionChange = vi.fn<SharedPageProps['onSelectionChange']>();
      renderTools({ onCommand, onSelectionChange });
      const { user, workspace } = await openWifi();
      await user.selectOptions(within(workspace).getByRole('combobox', { name: 'Action' }), action);

      await user.click(within(workspace).getByRole('button', { name: 'Apply changes' }));

      await waitFor(() => {
        expect(onCommand.mock.calls.filter(([command]) => command === commands.deviceScan)).toHaveLength(1);
      });
      expect(onCommand.mock.calls.filter(([command]) => command === commands.toolsWifi)).toEqual([
        [commands.toolsWifi, { action, host: '192.168.1.42', port: 5555 }],
      ]);
      expect(onCommand.mock.calls.filter(([command]) => command === commands.deviceScan)).toEqual([
        [commands.deviceScan, {}, { expectedRevision: 73 }],
      ]);
      expect(onCommand.mock.calls.some(([command]) => command === commands.deviceSelect)).toBe(false);
      expect(onSelectionChange).not.toHaveBeenCalled();
    },
  );

  it.each([
    ['failed', operationResult('FAILED')],
    ['cancelled', operationResult('CANCELLED')],
    ['null', null],
    ['success without a revision', operationResult('SUCCESS')],
  ] as const)('does not scan after a %s connect result', async (_label, wifiResponse) => {
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async () => wifiResponse);
    const onSelectionChange = vi.fn<SharedPageProps['onSelectionChange']>();
    renderTools({ onCommand, onSelectionChange });
    const { user, workspace } = await openWifi();
    await user.selectOptions(within(workspace).getByRole('combobox', { name: 'Action' }), 'connect');

    await user.click(within(workspace).getByRole('button', { name: 'Apply changes' }));

    await waitFor(() => {
      expect(onCommand.mock.calls.filter(([command]) => command === commands.toolsWifi)).toHaveLength(1);
    });
    expect(onCommand.mock.calls.some(([command]) => command === commands.deviceScan)).toBe(false);
    expect(onCommand.mock.calls.some(([command]) => command === commands.deviceSelect)).toBe(false);
    expect(onSelectionChange).not.toHaveBeenCalled();
  });
});
