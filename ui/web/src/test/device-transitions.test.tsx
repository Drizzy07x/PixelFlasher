import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { BridgeCommand } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import { DevicePage } from '../pages/Pages';
import type { Device, HostSnapshot } from '../types';
import type { SharedPageProps } from '../pages/shared';

function snapshotFor(mode: Device['mode'], rooted: boolean): HostSnapshot {
  const snapshot = structuredClone(demoSnapshot);
  const device = { ...snapshot.devices[0], mode, rooted };
  snapshot.devices = [device];
  snapshot.selectedSerial = device.serial;
  snapshot.selectedSerials = [device.serial];
  snapshot.activeOperation = null;
  snapshot.active_operation = null;
  return snapshot;
}

function renderDevice(snapshot: HostSnapshot, onCommand: SharedPageProps['onCommand']) {
  const serial = snapshot.devices[0]?.serial ?? '';
  return render(
    <I18nProvider locale="en">
      <DevicePage
        snapshot={snapshot}
        selectedSerials={serial ? [serial] : []}
        onSelectionChange={vi.fn()}
        onCommand={onCommand}
        expertMode={false}
      />
    </I18nProvider>,
  );
}

const successfulCommand: SharedPageProps['onCommand'] = vi.fn(async () => ({
  result: { status: 'SUCCESS' },
}));

describe('device reboot transitions', () => {
  it('uses backend-observed mode and root eligibility and never exposes download mode', () => {
    const cases: Array<{
      mode: Device['mode'];
      rooted: boolean;
      sideload: boolean;
      safeMode: boolean;
    }> = [
      { mode: 'adb', rooted: true, sideload: true, safeMode: true },
      { mode: 'adb', rooted: false, sideload: true, safeMode: false },
      { mode: 'recovery', rooted: true, sideload: true, safeMode: false },
      { mode: 'sideload', rooted: true, sideload: false, safeMode: false },
      { mode: 'fastboot', rooted: true, sideload: false, safeMode: false },
    ];

    for (const item of cases) {
      const view = renderDevice(snapshotFor(item.mode, item.rooted), successfulCommand);
      const target = screen.getByRole('combobox', { name: 'Reboot destination' });
      const sideload = within(target).getByRole('option', { name: 'ADB sideload' });
      const safeMode = within(target).getByRole('option', { name: 'Safe mode' });
      if (item.sideload) expect(sideload).toBeEnabled();
      else expect(sideload).toBeDisabled();
      if (item.safeMode) expect(safeMode).toBeEnabled();
      else expect(safeMode).toBeDisabled();
      expect(within(target).queryByRole('option', { name: /download/i })).not.toBeInTheDocument();

      if (!item.safeMode) {
        fireEvent.change(target, { target: { value: 'safemode' } });
        expect(screen.getByRole('button', { name: 'Reboot now' })).toBeDisabled();
      }
      view.unmount();
    }
  });

  it('dispatches sideload and safe mode as typed modes and reports verified success', async () => {
    const user = userEvent.setup();
    const snapshot = snapshotFor('adb', true);
    const onCommand: SharedPageProps['onCommand'] = vi.fn(async () => ({
      result: { status: 'SUCCESS' },
    }));
    renderDevice(snapshot, onCommand);
    const target = screen.getByRole('combobox', { name: 'Reboot destination' });

    await user.selectOptions(target, 'safemode');
    await user.click(screen.getByRole('button', { name: 'Reboot now' }));
    expect(await screen.findByText('Device reached Safe mode')).toBeVisible();
    expect(onCommand).toHaveBeenCalledWith(
      'device.reboot',
      { serial: snapshot.devices[0].serial, mode: 'safemode' },
      { returnCancelled: true },
    );

    await user.selectOptions(target, 'sideload');
    await user.click(screen.getByRole('button', { name: 'Reboot now' }));
    expect(await screen.findByText('Device reached ADB sideload')).toBeVisible();
    expect(onCommand).toHaveBeenCalledWith(
      'device.reboot',
      { serial: snapshot.devices[0].serial, mode: 'sideload' },
      { returnCancelled: true },
    );
  });

  it('uses the active operation for progress and cancellation and preserves CANCELLED', async () => {
    const user = userEvent.setup();
    const snapshot = snapshotFor('adb', true);
    let finishTransition: ((value: { result: Record<string, unknown> }) => void) | undefined;
    const onCommand: SharedPageProps['onCommand'] = vi.fn((command: BridgeCommand) => {
      if (command === 'device.reboot') {
        return new Promise<{ result: Record<string, unknown>; revision?: number } | null>(
          (resolve) => { finishTransition = resolve; },
        );
      }
      if (command === 'operation.cancel') {
        return Promise.resolve({ result: { status: 'SUCCESS' } });
      }
      return Promise.resolve({ result: { status: 'FAILED' } });
    });
    const view = renderDevice(snapshot, onCommand);

    await user.selectOptions(screen.getByRole('combobox', { name: 'Reboot destination' }), 'sideload');
    await user.click(screen.getByRole('button', { name: 'Reboot now' }));
    expect(await screen.findByText('Changing device mode to ADB sideload...')).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Cancel transition' })).not.toBeInTheDocument();

    const running = structuredClone(snapshot);
    running.activeOperation = {
      id: 'device-transition-operation',
      label: 'Device transition',
      status: 'running',
      progress: 42,
    };
    view.rerender(
      <I18nProvider locale="en">
        <DevicePage
          snapshot={running}
          selectedSerials={[running.devices[0].serial]}
          onSelectionChange={vi.fn()}
          onCommand={onCommand}
          expertMode={false}
        />
      </I18nProvider>,
    );

    expect(screen.getByRole('progressbar', { name: 'Device transition progress' })).toHaveAttribute('value', '42');
    await user.click(screen.getByRole('button', { name: 'Cancel transition' }));
    expect(onCommand).toHaveBeenCalledWith('operation.cancel', {
      operationId: 'device-transition-operation',
    });
    expect(await screen.findByText('Cancelling device transition...')).toBeVisible();

    await act(async () => {
      finishTransition?.({ result: { status: 'CANCELLED', code: 'operation_cancelled' } });
    });
    expect(await screen.findByText('Device transition cancelled')).toBeVisible();
    await waitFor(() => expect(screen.queryByText('Cancelling device transition...')).not.toBeInTheDocument());
  });
});
