import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import axe from 'axe-core';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import App from '../App';
import type { BridgeCommand } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import { AppsPage } from '../pages/Pages';
import type { CommandRunOptions, SharedPageProps } from '../pages/shared';
import type { BridgeRequest, HostSnapshot } from '../types';

const developmentBridge = window.pixelflasher;

function freshSnapshot(): HostSnapshot {
  return structuredClone(demoSnapshot);
}

function renderApps(
  snapshot: HostSnapshot,
  onCommand: SharedPageProps['onCommand'],
) {
  const selectedSerials = snapshot.selectedSerials ?? snapshot.selected_serials ?? [];
  return render(
    <I18nProvider locale="en">
      <AppsPage
        snapshot={snapshot}
        selectedSerials={selectedSerials}
        onSelectionChange={vi.fn()}
        onCommand={onCommand}
      />
    </I18nProvider>,
  );
}

describe('modern APK installation', () => {
  beforeEach(() => {
    window.pixelflasher = { postMessage: vi.fn() };
  });

  it('uses one opaque grant, all six typed options and refreshes only after explicit success', async () => {
    const user = userEvent.setup();
    const snapshot = freshSnapshot();
    const serial = snapshot.selectedSerials?.[0] ?? '';
    const calls: Array<{
      command: BridgeCommand;
      payload: Record<string, unknown>;
      options?: CommandRunOptions;
    }> = [];
    const onCommand: SharedPageProps['onCommand'] = vi.fn(async (command, payload = {}, options) => {
      calls.push({ command, payload, options });
      if (command === 'native.pickFile') {
        return { result: { status: 'SUCCESS', data: { grant: 'opaque-apk-grant' } } };
      }
      if (command === 'apps.action') {
        return {
          result: {
            status: 'SUCCESS',
            code: 'apps_action_succeeded',
            value: {
              action: 'install',
              apkIdentity: {
                packageName: 'com.example.verified',
                sha256: 'a'.repeat(64),
                verified: true,
              },
            },
          },
        };
      }
      return {
        result: {
          status: 'SUCCESS',
          value: {
            packages: [{ package: 'com.example.verified', apk_path: '/data/app/verified.apk' }],
          },
        },
      };
    });
    const { container } = renderApps(snapshot, onCommand);

    await user.click(screen.getByRole('checkbox', { name: /^Grant runtime permissions/ }));
    await user.click(screen.getByRole('checkbox', { name: /^Allow version downgrade/ }));
    await user.click(screen.getByRole('checkbox', { name: /^Allow test-only packages/ }));
    await user.click(screen.getByRole('checkbox', { name: /^Make package queryable/ }));
    await user.click(screen.getByRole('checkbox', { name: /^Bypass low target SDK block/ }));
    await user.click(screen.getByRole('button', { name: 'Choose APK and install' }));

    expect(await screen.findByText('Installed com.example.verified')).toBeVisible();
    await waitFor(() => expect(document.activeElement).toHaveTextContent('Installed com.example.verified'));
    expect(calls.map((call) => call.command)).toEqual(['native.pickFile', 'apps.action', 'apps.list']);
    expect(calls[0]).toEqual({
      command: 'native.pickFile',
      payload: {
        purpose: 'apps.install.source',
        title: 'Install APK',
        filters: [{ label: 'Android application packages', extensions: ['apk'] }],
      },
      options: { returnCancelled: true },
    });
    expect(calls[1]).toEqual({
      command: 'apps.action',
      payload: {
        serial,
        action: 'install',
        grant: 'opaque-apk-grant',
        options: {
          replace: true,
          grantPermissions: true,
          allowDowngrade: true,
          allowTest: true,
          forceQueryable: true,
          bypassLowTargetSdk: true,
        },
      },
      options: { returnCancelled: true },
    });
    expect(JSON.stringify(calls)).not.toMatch(/(?:[A-Z]:\\|\/home\/|\/Users\/)/);
    const results = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations).toEqual([]);
  });

  it('keeps picker cancellation and malformed failure distinct without executing a stale action', async () => {
    const user = userEvent.setup();
    const cancelled = vi.fn(async () => ({
      result: { status: 'CANCELLED', code: 'user_cancelled' },
    }));
    const first = renderApps(freshSnapshot(), cancelled);
    await user.click(screen.getByRole('button', { name: 'Choose APK and install' }));
    expect(await within(first.container).findByText('APK installation cancelled')).toBeVisible();
    expect(cancelled).toHaveBeenCalledTimes(1);

    first.unmount();
    const failed = vi.fn(async (command: BridgeCommand) => command === 'native.pickFile'
      ? { result: { status: 'SUCCESS', data: { grant: 'opaque-apk-grant' } } }
      : null);
    const second = renderApps(freshSnapshot(), failed);
    await user.click(screen.getByRole('button', { name: 'Choose APK and install' }));
    expect(await within(second.container).findByRole('alert')).toHaveTextContent('The APK was not installed.');
    expect(failed).toHaveBeenCalledTimes(2);
  });

  it('cancels the active install by operation ID and preserves CANCELLED as a terminal state', async () => {
    const user = userEvent.setup();
    const snapshot = freshSnapshot();
    let finishInstall: ((result: { result: Record<string, unknown> }) => void) | undefined;
    const onCommand: SharedPageProps['onCommand'] = vi.fn((command) => {
      if (command === 'native.pickFile') {
        return Promise.resolve({ result: { status: 'SUCCESS', data: { grant: 'opaque-apk-grant' } } });
      }
      if (command === 'operation.cancel') {
        return Promise.resolve({ result: { status: 'SUCCESS', code: 'cancellation_requested' } });
      }
      if (command === 'apps.action') {
        return new Promise<{ result: Record<string, unknown> }>((resolve) => { finishInstall = resolve; });
      }
      return Promise.resolve({ result: { status: 'SUCCESS', value: { packages: [] } } });
    });
    const view = renderApps(snapshot, onCommand);
    await user.click(screen.getByRole('button', { name: 'Choose APK and install' }));
    expect(await screen.findByRole('status')).toHaveTextContent('Installing APK...');

    const running = freshSnapshot();
    running.activeOperation = { id: 'apk-install-operation', label: 'Install APK', status: 'running' };
    view.rerender(
      <I18nProvider locale="en">
        <AppsPage
          snapshot={running}
          selectedSerials={running.selectedSerials ?? []}
          onSelectionChange={vi.fn()}
          onCommand={onCommand}
        />
      </I18nProvider>,
    );
    await user.click(await screen.findByRole('button', { name: 'Cancel installation' }));
    expect(onCommand).toHaveBeenCalledWith('operation.cancel', { operationId: 'apk-install-operation' });
    expect(screen.getByRole('status')).toHaveTextContent('Cancelling installation...');
    await act(async () => {
      finishInstall?.({ result: { status: 'CANCELLED', code: 'operation_cancelled' } });
    });
    expect(await screen.findByText('APK installation cancelled')).toBeVisible();
  });

  it('sends the current expectedRevision through the real bridge and remains axe-clean', async () => {
    window.pixelflasher = developmentBridge;
    developmentBridge?.__reset?.();
    const postMessage = vi.spyOn(developmentBridge!, 'postMessage');
    const user = userEvent.setup();
    const { container } = render(<App />);
    await screen.findByRole('heading', { name: 'Modern UI' });
    await user.click(within(screen.getByRole('navigation', { name: 'Tasks' })).getByRole('button', { name: 'Apps' }));
    await user.click(await screen.findByRole('button', { name: 'Choose APK and install' }));
    expect(await screen.findByText('Installed com.example.selected')).toBeVisible();

    const requests = postMessage.mock.calls.map(([raw]) => JSON.parse(String(raw)) as BridgeRequest);
    const picker = requests.find((request) => request.command === 'native.pickFile' && request.payload.purpose === 'apps.install.source');
    const install = requests.find((request) => request.command === 'apps.action' && request.payload.action === 'install');
    const refresh = requests.find((request) => request.command === 'apps.list');
    for (const request of [picker, install, refresh]) {
      expect(typeof request?.expectedRevision).toBe('number');
    }
    expect(install?.payload).toMatchObject({
      serial: '47161FDJH00A8L',
      action: 'install',
      grant: 'g'.repeat(64),
    });
    expect(install?.payload).not.toHaveProperty('path');
    const results = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations).toEqual([]);
  });
});
