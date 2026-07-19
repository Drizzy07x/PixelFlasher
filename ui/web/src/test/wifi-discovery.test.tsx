import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { commands } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import { ToolsPage } from '../pages/tooling/ToolsPage';
import type { SharedPageProps } from '../pages/shared';
import type { HostSnapshot } from '../types';

const discoveredServices = [
  {
    id: '02e5260c5fcf00453dc38bde63a6b55f5959227225d78b4953d60789f1ce4014',
    instance: 'Pixel-Pairing',
    serviceType: 'pairing',
    host: '192.168.1.20',
    port: 37123,
    endpoint: '192.168.1.20:37123',
    addressFamily: 'ipv4',
  },
  {
    id: 'a295e746f3ba85c3979face9e83657dab888def2a8c8333f3d1621eae5243d8f',
    instance: 'Pixel-Connect',
    serviceType: 'connect',
    host: '192.168.1.20',
    port: 39001,
    endpoint: '192.168.1.20:39001',
    addressFamily: 'ipv4',
  },
  {
    id: 'd2a3ac40435bd63ac88e1d98ea8363a1689834dc565a61a3640300a859cca5ac',
    instance: 'Pixel-Legacy',
    serviceType: 'legacy',
    host: '192.168.1.21',
    port: 5555,
    endpoint: '192.168.1.21:5555',
    addressFamily: 'ipv4',
  },
] as const;

function snapshotWithoutSelection() {
  const snapshot = structuredClone(demoSnapshot) as HostSnapshot;
  snapshot.selectedSerial = null;
  snapshot.selected_serial = null;
  snapshot.selectedSerials = [];
  snapshot.selected_serials = [];
  return snapshot;
}

function discoveryCommand() {
  const onCommand = vi.fn<SharedPageProps['onCommand']>(async () => ({
    result: {
      status: 'SUCCESS',
      code: 'wifi_mdns_discovery_succeeded',
      message: 'Discovered 3 wireless ADB services',
      value: {
        action: 'discover',
        count: discoveredServices.length,
        services: discoveredServices,
        discardedCount: 0,
        bounded: true,
      },
    },
  }));
  return onCommand;
}

function renderTools(onCommand: SharedPageProps['onCommand']) {
  const snapshot = snapshotWithoutSelection();
  return render(
    <I18nProvider locale="en">
      <ToolsPage
        snapshot={snapshot}
        selectedSerials={[]}
        onSelectionChange={vi.fn()}
        onCommand={onCommand}
        expertMode={false}
      />
    </I18nProvider>,
  );
}

async function discover(onCommand: SharedPageProps['onCommand']) {
  const user = userEvent.setup();
  const wifiCard = screen.getByRole('button', { name: /Wireless ADB/i });
  expect(wifiCard).toBeEnabled();
  await user.click(wifiCard);

  const workspace = document.querySelector('.tool-workspace') as HTMLElement;
  expect(workspace).toBeVisible();
  await user.click(within(workspace).getByRole('button', { name: 'Discover devices' }));

  expect(onCommand).toHaveBeenCalledTimes(1);
  expect(onCommand).toHaveBeenCalledWith(commands.toolsWifiDiscover, {});
  expect(await within(workspace).findByRole('list', { name: 'Discovered wireless devices' })).toBeVisible();
  return { user, workspace };
}

describe('Wireless ADB discovery', () => {
  it('opens with Platform Tools but no selected device and sends an empty discovery payload', async () => {
    const onCommand = discoveryCommand();
    renderTools(onCommand);

    const { workspace } = await discover(onCommand);

    expect(within(workspace).getByText('Pixel-Pairing')).toBeVisible();
    expect(within(workspace).getByText('Pixel-Connect')).toBeVisible();
    expect(within(workspace).getByText('Pixel-Legacy')).toBeVisible();
  });

  it('uses advertisements only to populate the form and keeps Apply disabled without an ADB selection', async () => {
    const onCommand = discoveryCommand();
    renderTools(onCommand);
    const { user, workspace } = await discover(onCommand);
    const action = within(workspace).getByRole('combobox', { name: 'Action' });
    const apply = within(workspace).getByRole('button', { name: 'Apply changes' });

    const pairing = within(workspace).getByRole('button', { name: /Pixel-Pairing/i });
    expect(pairing).toHaveAttribute('aria-pressed', 'false');
    await user.click(pairing);
    expect(pairing).toHaveAttribute('aria-pressed', 'true');
    expect(action).toHaveValue('pair');
    expect(within(workspace).getByRole('textbox', { name: 'Numeric IP address' })).toHaveValue('192.168.1.20');
    expect(within(workspace).getByRole('spinbutton', { name: 'Port' })).toHaveValue(37123);
    expect(apply).toBeDisabled();
    expect(onCommand.mock.calls.map(([command]) => command)).toEqual([commands.toolsWifiDiscover]);

    await user.click(within(workspace).getByRole('button', { name: /Pixel-Connect/i }));
    expect(action).toHaveValue('connect');
    expect(within(workspace).getByRole('textbox', { name: 'Numeric IP address' })).toHaveValue('192.168.1.20');
    expect(within(workspace).getByRole('spinbutton', { name: 'Port' })).toHaveValue(39001);
    expect(apply).toBeDisabled();
    expect(onCommand.mock.calls.map(([command]) => command)).toEqual([commands.toolsWifiDiscover]);

    await user.click(within(workspace).getByRole('button', { name: /Pixel-Legacy/i }));
    expect(action).toHaveValue('connect');
    expect(within(workspace).getByRole('textbox', { name: 'Numeric IP address' })).toHaveValue('192.168.1.21');
    expect(within(workspace).getByRole('spinbutton', { name: 'Port' })).toHaveValue(5555);
    expect(apply).toBeDisabled();
    expect(onCommand.mock.calls.map(([command]) => command)).toEqual([commands.toolsWifiDiscover]);
  });

  it('does not turn a failed discovery into a verified empty result', async () => {
    const user = userEvent.setup();
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async () => ({
      result: {
        status: 'FAILED',
        code: 'wifi_mdns_timed_out',
        message: 'Wireless ADB discovery timed out',
      },
    }));
    renderTools(onCommand);

    await user.click(screen.getByRole('button', { name: /Wireless ADB/i }));
    const workspace = document.querySelector('.tool-workspace') as HTMLElement;
    await user.click(within(workspace).getByRole('button', { name: 'Discover devices' }));

    expect(within(workspace).queryByText('No compatible wireless ADB services were found.')).not.toBeInTheDocument();
    expect(within(workspace).queryByRole('list', { name: 'Discovered wireless devices' })).not.toBeInTheDocument();
    expect(await within(workspace).findByText('Wireless ADB discovery timed out')).toBeVisible();
  });
});
