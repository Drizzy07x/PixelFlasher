import { useState } from 'react';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import axe from 'axe-core';
import { describe, expect, it, vi } from 'vitest';
import { commands } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import {
  ToolsPage,
  initialPushUiState,
  type PushUiState,
} from '../pages/tooling/ToolsPage';
import type { SharedPageProps } from '../pages/shared';
import type { HostSnapshot } from '../types';

const GRANTS = ['g'.repeat(64), 'h'.repeat(64)];
const DIGESTS = ['a'.repeat(64), 'b'.repeat(64)];

function adbSnapshot(activeOperation: HostSnapshot['activeOperation'] = null) {
  const snapshot = structuredClone(demoSnapshot) as HostSnapshot;
  const device = snapshot.devices.find((candidate) => candidate.mode === 'adb') ?? snapshot.devices[0];
  device.mode = 'adb';
  snapshot.selectedSerial = device.serial;
  snapshot.selected_serial = device.serial;
  snapshot.selectedSerials = [device.serial];
  snapshot.selected_serials = [device.serial];
  if (activeOperation) {
    activeOperation.targetSerial = device.serial;
    activeOperation.target_serial = device.serial;
  }
  snapshot.activeOperation = activeOperation;
  snapshot.active_operation = activeOperation;
  snapshot.toolchain = { adb: true, fastboot: true, ready: true };
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
        expertMode={false}
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
            expertMode={false}
          />
        </I18nProvider>,
      );
    },
  };
}

function PersistentToolsHarness({
  show,
  snapshot,
  onCommand,
}: {
  show: boolean;
  snapshot: HostSnapshot;
  onCommand: SharedPageProps['onCommand'];
}) {
  const [pushUiState, setPushUiState] = useState<PushUiState>(initialPushUiState);
  return show ? (
    <I18nProvider locale="en">
      <ToolsPage
        snapshot={snapshot}
        selectedSerials={snapshot.selectedSerials ?? []}
        onSelectionChange={vi.fn()}
        onCommand={onCommand}
        expertMode={false}
        pushUiState={pushUiState}
        onPushUiStateChange={setPushUiState}
      />
    </I18nProvider>
  ) : <div>Other route</div>;
}

async function openPushAndChoose(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: /Push files/i }));
  const workspace = document.querySelector('.tool-workspace') as HTMLElement;
  await user.click(within(workspace).getByRole('button', { name: 'Choose files' }));
  return workspace;
}

function verifiedResult(targetSerial: string) {
  return {
    result: {
      status: 'SUCCESS',
      code: 'files_pushed',
      message: 'Pushed and verified 2 files.',
      value: {
        targetSerial,
        count: 2,
        files: [
          {
            displayName: 'alpha.bin',
            destination: '/sdcard/Download/alpha.bin',
            sha256: DIGESTS[0],
            sizeBytes: 5,
            verified: true,
          },
          {
            displayName: 'beta.zip',
            destination: '/sdcard/Download/beta.zip',
            sha256: DIGESTS[1],
            sizeBytes: 2048,
            verified: true,
          },
        ],
      },
    },
  };
}

describe('verified file push', () => {
  it('uses opaque grants and renders only strict remote verification receipts', async () => {
    const user = userEvent.setup();
    const snapshot = adbSnapshot();
    const serial = snapshot.selectedSerial as string;
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async (command) => {
      if (command === commands.nativePickFiles) {
        return {
          result: { status: 'SUCCESS', data: { grants: GRANTS.map((grant) => ({ grant })) } },
          revision: 12,
        };
      }
      return verifiedResult(serial);
    });
    renderTools(snapshot, onCommand);

    const workspace = await openPushAndChoose(user);

    await waitFor(() => expect(onCommand).toHaveBeenCalledWith(
      commands.toolsPushFiles,
      { serial, grants: GRANTS, destination: '/sdcard/Download/' },
      {
        returnCancelled: true,
        returnFailed: true,
        suppressNotice: true,
        expectedRevision: 12,
        onOperationAccepted: expect.any(Function),
      },
    ));
    expect(within(workspace).getAllByText('Verified').length).toBeGreaterThan(0);
    expect(within(workspace).getByRole('list', { name: 'Verified file receipts' })).toBeVisible();
    expect(within(workspace).getByText('alpha.bin')).toBeVisible();
    expect(within(workspace).getByText(DIGESTS[0])).toBeVisible();
    expect(within(workspace).queryByText(/C:\\|\/home\/|\/Users\//)).not.toBeInTheDocument();
    expect(within(workspace).queryByRole('button', { name: 'Retry with a new plan' })).not.toBeInTheDocument();
    const results = await axe.run(workspace, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations).toEqual([]);
  });

  it('shows per-file progress, cancels by operation ID, and retries only on request', async () => {
    const user = userEvent.setup();
    const base = adbSnapshot();
    let finish: ((value: { result: Record<string, unknown> }) => void) | undefined;
    let pushCalls = 0;
    const onCommand = vi.fn<SharedPageProps['onCommand']>((command) => {
      if (command === commands.nativePickFiles) {
        return Promise.resolve({
          result: { status: 'SUCCESS', data: { grants: GRANTS.map((grant) => ({ grant })) } },
          revision: 21,
        });
      }
      if (command === commands.operationCancel) {
        return Promise.resolve({ result: { status: 'SUCCESS', code: 'cancellation_requested' } });
      }
      pushCalls += 1;
      if (pushCalls === 1) {
        return new Promise((resolve) => { finish = resolve; });
      }
      return Promise.resolve(verifiedResult(base.selectedSerial as string));
    });
    const view = renderTools(base, onCommand);
    const workspace = await openPushAndChoose(user);

    view.update(adbSnapshot({
      id: 'push-operation-1',
      kind: commands.toolsPushFiles,
      label: 'Pushing files',
      status: 'running',
      progress: 42,
      current: 1,
      total: 2,
      item: 'alpha.bin',
    }));
    expect(within(workspace).getByRole('progressbar', { name: 'File transfer progress' })).toHaveAttribute('value', '42');
    expect(within(workspace).getByText('File 1/2 · alpha.bin')).toBeVisible();

    await user.click(within(workspace).getByRole('button', { name: 'Cancel transfer' }));
    expect(onCommand).toHaveBeenCalledWith(commands.operationCancel, { operationId: 'push-operation-1' });
    expect(within(workspace).getByText('Cancelling file transfer…')).toBeVisible();

    await act(async () => {
      finish?.({ result: { status: 'CANCELLED', code: 'push_cancelled', message: 'File transfer cancelled.' } });
    });
    view.update(adbSnapshot());
    const retry = within(workspace).getByRole('button', { name: 'Retry with a new plan' });
    expect(retry).toBeEnabled();
    expect(pushCalls).toBe(1);

    await user.click(retry);
    await waitFor(() => expect(pushCalls).toBe(2));
    expect(onCommand.mock.calls.filter(([command]) => command === commands.toolsPushFiles)[1]).toEqual([
      commands.toolsPushFiles,
      { serial: base.selectedSerial, grants: GRANTS, destination: '/sdcard/Download/' },
      {
        returnCancelled: true,
        returnFailed: true,
        suppressNotice: true,
        onOperationAccepted: expect.any(Function),
      },
    ]);
  });

  it('invalidates a retry grant batch when the user changes the remote destination', async () => {
    const user = userEvent.setup();
    const snapshot = adbSnapshot();
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async (command) => {
      if (command === commands.nativePickFiles) {
        return {
          result: { status: 'SUCCESS', data: { grants: GRANTS.map((grant) => ({ grant })) } },
          revision: 22,
        };
      }
      return { result: { status: 'CANCELLED', code: 'push_cancelled' } };
    });
    renderTools(snapshot, onCommand);
    const workspace = await openPushAndChoose(user);
    expect(await within(workspace).findByRole('button', { name: 'Retry with a new plan' })).toBeEnabled();

    await user.selectOptions(
      within(workspace).getByRole('combobox', { name: 'Device destination' }),
      '/data/local/tmp/',
    );

    expect(within(workspace).queryByRole('button', { name: 'Retry with a new plan' })).not.toBeInTheDocument();
  });

  it('cancels by the accepted request ID while the push is still queued', async () => {
    const user = userEvent.setup();
    const snapshot = adbSnapshot();
    let finish: ((value: { result: Record<string, unknown> }) => void) | undefined;
    const onCommand = vi.fn<SharedPageProps['onCommand']>((command, _payload, options) => {
      if (command === commands.nativePickFiles) {
        return Promise.resolve({
          result: { status: 'SUCCESS', data: { grants: GRANTS.map((grant) => ({ grant })) } },
          revision: 25,
        });
      }
      if (command === commands.operationCancel) {
        return Promise.resolve({ result: { status: 'SUCCESS', code: 'cancellation_requested' } });
      }
      options?.onOperationAccepted?.('queued-push-request');
      return new Promise((resolve) => { finish = resolve; });
    });
    renderTools(snapshot, onCommand);
    const workspace = await openPushAndChoose(user);

    const cancel = await within(workspace).findByRole('button', { name: 'Cancel transfer' });
    await user.click(cancel);

    expect(onCommand).toHaveBeenCalledWith(
      commands.operationCancel,
      { operationId: 'queued-push-request' },
    );
    await act(async () => {
      finish?.({ result: { status: 'CANCELLED', code: 'cancelled' } });
    });
  });

  it('keeps the terminal receipts when the Tools route is left during transfer', async () => {
    const user = userEvent.setup();
    const snapshot = adbSnapshot();
    let finish: ((value: { result: Record<string, unknown> }) => void) | undefined;
    const onCommand = vi.fn<SharedPageProps['onCommand']>((command) => {
      if (command === commands.nativePickFiles) {
        return Promise.resolve({
          result: { status: 'SUCCESS', data: { grants: GRANTS.map((grant) => ({ grant })) } },
          revision: 23,
        });
      }
      return new Promise((resolve) => { finish = resolve; });
    });
    const view = render(
      <PersistentToolsHarness show snapshot={snapshot} onCommand={onCommand} />,
    );
    await openPushAndChoose(user);

    view.rerender(
      <PersistentToolsHarness show={false} snapshot={snapshot} onCommand={onCommand} />,
    );
    await act(async () => {
      finish?.(verifiedResult(snapshot.selectedSerial as string));
    });
    view.rerender(
      <PersistentToolsHarness show snapshot={snapshot} onCommand={onCommand} />,
    );

    const workspace = document.querySelector('.tool-workspace') as HTMLElement;
    expect(await within(workspace).findByText('alpha.bin')).toBeVisible();
    expect(within(workspace).getByRole('list', { name: 'Verified file receipts' })).toBeVisible();
  });

  it('restores cancellation controls when the backend rejects cancellation', async () => {
    const user = userEvent.setup();
    const base = adbSnapshot({
      id: 'push-operation-rejected-cancel',
      kind: commands.toolsPushFiles,
      label: 'Pushing files',
      status: 'running',
      progress: 25,
      current: 1,
      total: 2,
      item: 'alpha.bin',
    });
    let finish: ((value: { result: Record<string, unknown> }) => void) | undefined;
    const onCommand = vi.fn<SharedPageProps['onCommand']>((command) => {
      if (command === commands.nativePickFiles) {
        return Promise.resolve({
          result: { status: 'SUCCESS', data: { grants: GRANTS.map((grant) => ({ grant })) } },
          revision: 24,
        });
      }
      if (command === commands.operationCancel) {
        return Promise.resolve({ result: { status: 'FAILED', code: 'operation_not_active' } });
      }
      return new Promise((resolve) => { finish = resolve; });
    });
    const view = renderTools(adbSnapshot(), onCommand);
    const workspace = await openPushAndChoose(user);
    view.update(base);

    const cancel = within(workspace).getByRole('button', { name: 'Cancel transfer' });
    await user.click(cancel);

    await waitFor(() => expect(within(workspace).getByText('File transfer in progress')).toBeVisible());
    expect(cancel).toBeEnabled();
    await act(async () => {
      finish?.({ result: { status: 'CANCELLED', code: 'push_cancelled' } });
    });
  });

  it('removes receipts and retry grants when the selected device changes', async () => {
    const user = userEvent.setup();
    const first = adbSnapshot();
    const firstSerial = first.selectedSerial as string;
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async (command) => {
      if (command === commands.nativePickFiles) {
        return {
          result: { status: 'SUCCESS', data: { grants: GRANTS.map((grant) => ({ grant })) } },
          revision: 31,
        };
      }
      return verifiedResult(firstSerial);
    });
    const view = renderTools(first, onCommand);
    const workspace = await openPushAndChoose(user);
    expect(await within(workspace).findByText('alpha.bin')).toBeVisible();

    const second = structuredClone(first);
    const other = second.devices.find((device) => device.serial !== firstSerial)!;
    other.mode = 'adb';
    second.selectedSerial = other.serial;
    second.selected_serial = other.serial;
    second.selectedSerials = [other.serial];
    second.selected_serials = [other.serial];
    view.update(second);

    await waitFor(() => expect(within(workspace).queryByText('alpha.bin')).not.toBeInTheDocument());
    expect(within(workspace).queryByRole('button', { name: 'Retry with a new plan' })).not.toBeInTheDocument();
  });

  it('rejects a malformed success receipt and keeps an explicit retry path', async () => {
    const user = userEvent.setup();
    const snapshot = adbSnapshot();
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async (command) => {
      if (command === commands.nativePickFiles) {
        return {
          result: { status: 'SUCCESS', data: { grants: [{ grant: GRANTS[0] }] } },
          revision: 8,
        };
      }
      return {
        result: {
          status: 'SUCCESS',
          value: {
            targetSerial: 'OTHER-SERIAL',
            count: 1,
            files: [{ ...verifiedResult(snapshot.selectedSerial as string).result.value.files[0], source: 'C:\\private\\alpha.bin' }],
          },
        },
      };
    });
    renderTools(snapshot, onCommand);

    const workspace = await openPushAndChoose(user);

    expect(await within(workspace).findByText('The host returned an invalid verification receipt.')).toBeVisible();
    expect(within(workspace).getByRole('button', { name: 'Retry with a new plan' })).toBeEnabled();
    expect(document.body.textContent).not.toContain('C:\\private');
  });
});
