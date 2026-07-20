import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import axe from 'axe-core';
import { describe, expect, it, vi } from 'vitest';
import { commands } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import { ToolsPage } from '../pages/tooling/ToolsPage';
import type { SharedPageProps } from '../pages/shared';
import type { HostSnapshot } from '../types';

const PARTITION = 'boot_a';

function fastbootSnapshot(activeOperation: HostSnapshot['activeOperation'] = null) {
  const snapshot = structuredClone(demoSnapshot) as HostSnapshot;
  const device = snapshot.devices.find((candidate) => candidate.mode === 'fastboot')
    ?? snapshot.devices[0];
  device.mode = 'fastboot';
  snapshot.selectedSerial = device.serial;
  snapshot.selected_serial = device.serial;
  snapshot.selectedSerials = [device.serial];
  snapshot.selected_serials = [device.serial];
  snapshot.toolchain = { adb: true, fastboot: true, ready: true };
  if (activeOperation) {
    activeOperation.targetSerial = device.serial;
    activeOperation.target_serial = device.serial;
  }
  snapshot.activeOperation = activeOperation;
  snapshot.active_operation = activeOperation;
  return snapshot;
}

function renderTools(snapshot: HostSnapshot, onCommand: SharedPageProps['onCommand']) {
  const view = render(
    <I18nProvider locale="en">
      <ToolsPage
        snapshot={snapshot}
        selectedSerials={snapshot.selectedSerials ?? []}
        onSelectionChange={vi.fn()}
        onCommand={onCommand}
        expertMode
      />
    </I18nProvider>,
  );
  return {
    ...view,
    update(next: HostSnapshot) {
      view.rerender(
        <I18nProvider locale="en">
          <ToolsPage
            snapshot={next}
            selectedSerials={next.selectedSerials ?? []}
            onSelectionChange={vi.fn()}
            onCommand={onCommand}
            expertMode
          />
        </I18nProvider>,
      );
    },
  };
}

async function openPartitionPanel(
  user: ReturnType<typeof userEvent.setup>,
) {
  await user.click(screen.getByRole('button', { name: /Partition manager/i }));
  const workspace = document.querySelector('.tool-workspace') as HTMLElement;
  await user.click(within(workspace).getByRole('button', { name: 'Refresh' }));
  await waitFor(() => expect(within(workspace).getByLabelText('Selected partition')).toHaveValue(PARTITION));
  return workspace;
}

describe('verified partition operations', () => {
  it('shows bounded progress, supports cancellation, and passes accessibility checks', async () => {
    const user = userEvent.setup();
    const snapshot = fastbootSnapshot();
    let finish: ((value: Awaited<ReturnType<SharedPageProps['onCommand']>>) => void) | null = null;
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async (command, _payload, options) => {
      if (command === commands.partitionsList) {
        return { result: { status: 'SUCCESS', value: { count: 1, partitions: [{ name: PARTITION, size_bytes: 4096, partition_type: 'raw' }] } } };
      }
      if (command === commands.nativeSaveFile) {
        return { result: { status: 'SUCCESS', value: { data: { grant: 'partition-write-once' } } }, revision: snapshot.revision };
      }
      if (command === commands.operationCancel) {
        return { result: { status: 'SUCCESS', code: 'cancellation_requested' } };
      }
      if (command === commands.partitionsRead) {
        options?.onOperationAccepted?.('partition-read-operation');
        return new Promise((resolve) => { finish = resolve; });
      }
      return null;
    });
    const view = renderTools(snapshot, onCommand);
    const workspace = await openPartitionPanel(user);

    await user.click(within(workspace).getByRole('button', { name: 'Read image' }));
    view.update(fastbootSnapshot({
      id: 'partition-read-operation',
      kind: commands.partitionsRead,
      label: 'Read boot_a',
      status: 'running',
      progress: 42,
      detail: 'Private staging hash in progress',
    }));

    expect(await within(workspace).findByRole('progressbar', { name: 'Partition operation progress' })).toHaveAttribute('value', '42');
    expect(within(workspace).getByText('Private staging hash in progress')).toBeVisible();
    const accessibility = await axe.run(workspace);
    expect(accessibility.violations).toHaveLength(0);

    await user.click(within(workspace).getByRole('button', { name: 'Cancel' }));
    expect(onCommand).toHaveBeenCalledWith(commands.operationCancel, { operationId: 'partition-read-operation' });
    await act(async () => {
      finish?.({ result: { status: 'CANCELLED', code: 'partition_read_preflight_cancelled' } });
    });
    view.update(fastbootSnapshot());
    expect(await within(workspace).findByText('Partition operation cancelled before a verified result.')).toBeVisible();
  });

  it('never retries automatically and requires a fresh picker-backed plan', async () => {
    const user = userEvent.setup();
    const snapshot = fastbootSnapshot();
    let writeCalls = 0;
    let pickerCalls = 0;
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async (command) => {
      if (command === commands.partitionsList) {
        return { result: { status: 'SUCCESS', value: { count: 1, partitions: [{ name: PARTITION, size_bytes: 4096, partition_type: 'raw' }] } } };
      }
      if (command === commands.nativePickFile) {
        pickerCalls += 1;
        return { result: { status: 'SUCCESS', value: { data: { grant: `partition-source-${pickerCalls}` } } }, revision: snapshot.revision };
      }
      if (command === commands.partitionsWrite) {
        writeCalls += 1;
        return { result: { status: 'FAILED', code: 'outcome_unknown' } };
      }
      return null;
    });
    renderTools(snapshot, onCommand);
    const workspace = await openPartitionPanel(user);

    await user.click(within(workspace).getByRole('button', { name: 'Write image' }));
    expect(await within(workspace).findByText('Partition outcome unknown')).toBeVisible();
    expect(writeCalls).toBe(1);
    expect(pickerCalls).toBe(1);

    await act(async () => Promise.resolve());
    expect(writeCalls).toBe(1);
    await user.click(within(workspace).getByRole('button', { name: 'Retry with a new plan' }));
    await waitFor(() => expect(writeCalls).toBe(2));
    expect(pickerCalls).toBe(2);
    const writes = onCommand.mock.calls.filter(([command]) => command === commands.partitionsWrite);
    expect(writes[0]?.[1]).toMatchObject({ grant: 'partition-source-1' });
    expect(writes[1]?.[1]).toMatchObject({ grant: 'partition-source-2' });
  });
});
