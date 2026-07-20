import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { BridgeCommand } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import { RootPage } from '../pages/Pages';

const zygiskModule = {
  id: 'zygisk_next',
  name: 'Zygisk Next',
  version: '1.0.0',
  versionCode: 100,
  author: 'Test author',
  description: 'Test module',
  state: 'enabled',
  updateMetadata: 'available',
};

function renderRoot(onCommand: (
  command: BridgeCommand,
  payload?: Record<string, unknown>,
  options?: { expectedRevision?: number; suppressNotice?: boolean },
) => Promise<{ result: Record<string, unknown>; revision?: number } | null>) {
  const snapshot = structuredClone(demoSnapshot);
  return render(
    <I18nProvider locale="en">
      <RootPage
        snapshot={snapshot}
        selectedSerials={[snapshot.devices[0].serial]}
        onSelectionChange={vi.fn()}
        onCommand={onCommand}
      />
    </I18nProvider>,
  );
}

describe('Magisk module state refresh', () => {
  it('re-reads canonical device state after a successful mutation', async () => {
    const user = userEvent.setup();
    const onCommand = vi.fn(async (command: BridgeCommand) => {
      if (command === 'root.modules.list') {
        return { result: { status: 'SUCCESS', value: { modules: [zygiskModule] } }, revision: 8 };
      }
      return { result: { status: 'SUCCESS', value: { action: 'disable', moduleId: 'zygisk_next' } }, revision: 9 };
    });
    renderRoot(onCommand);

    const card = screen.getByText('Magisk Modules').closest('.card');
    if (!card) throw new Error('Magisk modules card missing');
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Refresh' }));
    const row = (await within(card as HTMLElement).findByText('Zygisk Next')).closest('[role="listitem"]');
    if (!row) throw new Error('module row missing');
    await user.click(within(row as HTMLElement).getByRole('button', { name: 'Disable' }));

    await waitFor(() => expect(onCommand).toHaveBeenCalledWith(
      'root.modules.list',
      { serial: demoSnapshot.devices[0].serial },
      { expectedRevision: 9, suppressNotice: true },
    ));
    expect(onCommand.mock.calls.filter(([command]) => command === 'root.modules.list')).toHaveLength(2);
  });

  it('does not refresh or invent local state after a failed mutation', async () => {
    const user = userEvent.setup();
    const onCommand = vi.fn(async (command: BridgeCommand) => {
      if (command === 'root.modules.list') {
        return { result: { status: 'SUCCESS', value: { modules: [zygiskModule] } }, revision: 8 };
      }
      return { result: { status: 'FAILED', code: 'postcondition_mismatch' }, revision: 9 };
    });
    renderRoot(onCommand);

    const card = screen.getByText('Magisk Modules').closest('.card');
    if (!card) throw new Error('Magisk modules card missing');
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Refresh' }));
    const row = (await within(card as HTMLElement).findByText('Zygisk Next')).closest('[role="listitem"]');
    if (!row) throw new Error('module row missing');
    await user.click(within(row as HTMLElement).getByRole('button', { name: 'Remove' }));

    await waitFor(() => expect(onCommand).toHaveBeenCalledWith('root.modules.action', {
      serial: demoSnapshot.devices[0].serial,
      action: 'remove',
      moduleId: 'zygisk_next',
    }));
    expect(onCommand.mock.calls.filter(([command]) => command === 'root.modules.list')).toHaveLength(1);
    expect(within(card as HTMLElement).getByText('Zygisk Next')).toBeVisible();
  });

  it('starts Shizuku through the closed recovery command', async () => {
    const user = userEvent.setup();
    const onCommand = vi.fn(async () => ({
      result: {
        status: 'SUCCESS',
        value: { action: 'startShizuku', targetSerial: demoSnapshot.devices[0].serial, verified: true },
      },
      revision: 9,
    }));
    renderRoot(onCommand);

    await user.click(screen.getByRole('button', { name: 'Start Shizuku' }));

    expect(onCommand).toHaveBeenCalledWith('tools.shizuku', {
      serial: demoSnapshot.devices[0].serial,
      action: 'start',
    });
  });

  it('requires exact SOS text and refreshes modules only after verified success', async () => {
    const user = userEvent.setup();
    const onCommand = vi.fn(async (command: BridgeCommand) => {
      if (command === 'tools.sos') {
        return {
          result: {
            status: 'SUCCESS',
            value: { action: 'disableModules', targetSerial: demoSnapshot.devices[0].serial, verified: true },
          },
          revision: 11,
        };
      }
      return { result: { status: 'SUCCESS', value: { modules: [zygiskModule] } }, revision: 11 };
    });
    renderRoot(onCommand);

    const input = screen.getByRole('textbox', { name: 'SOS: disable all modules' });
    const button = screen.getByRole('button', { name: 'Disable all modules' });
    expect(button).toBeDisabled();
    await user.type(input, 'SOS WRONG');
    expect(button).toBeDisabled();
    await user.clear(input);
    const phrase = `SOS ${demoSnapshot.devices[0].serial.slice(-6).toUpperCase()}`;
    await user.type(input, phrase);
    expect(button).toBeEnabled();
    await user.click(button);

    expect(onCommand).toHaveBeenCalledWith('tools.sos', {
      serial: demoSnapshot.devices[0].serial,
      action: 'disableModules',
      confirmationText: phrase,
    });
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith(
      'root.modules.list',
      { serial: demoSnapshot.devices[0].serial },
      { expectedRevision: 11, suppressNotice: true },
    ));
    expect(input).toHaveValue('');
  });
});
