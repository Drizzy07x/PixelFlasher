import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { commands } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import type { SharedPageProps } from '../pages/shared';
import { ToolsPage } from '../pages/tooling/ToolsPage';
import type { HostSnapshot } from '../types';

function factorySnapshot(ready = true) {
  const snapshot = structuredClone(demoSnapshot) as HostSnapshot;
  snapshot.firmware = {
    ...snapshot.firmware!,
    kind: 'factory',
    verified: ready,
    processed: ready,
    hash: ready ? 'f'.repeat(64) : undefined,
  };
  return snapshot;
}

function renderTools(snapshot: HostSnapshot, onCommand: SharedPageProps['onCommand']) {
  return render(
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
}

function success() {
  return {
    result: {
      status: 'SUCCESS',
      code: 'downgrade_artifact_registered',
      message: 'Verified downgrade artifact created.',
      value: {
        artifact: {
          role: 'downgrade:boot',
          sha256: 'a'.repeat(64),
          securityPatch: '2025-02-05',
          verified: true,
        },
      },
    },
    revision: 21,
  };
}

describe('AVB downgrade workspace', () => {
  it('uses a purpose-bound native grant and the picker revision without exposing host paths', async () => {
    const user = userEvent.setup();
    const calls: Parameters<SharedPageProps['onCommand']>[] = [];
    const onCommand: SharedPageProps['onCommand'] = vi.fn(async (command, payload = {}, options) => {
      calls.push([command, payload, options]);
      if (command === commands.nativePickFile) {
        return {
          result: { status: 'SUCCESS', data: { grant: 'opaque-current-boot-grant' } },
          revision: 19,
        };
      }
      return success();
    });
    renderTools(factorySnapshot(), onCommand);

    await user.click(screen.getByRole('button', { name: /AVB downgrade patch/i }));
    const workspace = document.querySelector('.tool-workspace') as HTMLElement;
    await user.click(within(workspace).getByRole('button', { name: 'Choose current boot image' }));

    expect(calls).toEqual([
      [commands.nativePickFile, {
        purpose: 'tools.avb.currentBoot',
        title: 'Choose current boot image',
        filters: [{ label: 'Current boot image', extensions: ['img'] }],
      }, undefined],
      [commands.toolsAvb, {
        action: 'prepareDowngrade',
        grant: 'opaque-current-boot-grant',
        patchFingerprint: true,
      }, {
        expectedRevision: 19,
        returnCancelled: true,
        returnFailed: true,
      }],
    ]);
    expect(JSON.stringify(calls)).not.toMatch(/currentBootPath|[A-Z]:\\|\/home\/|\/Users\//);
    expect(await within(workspace).findByText('Verified artifact')).toBeVisible();
    expect(within(workspace).getByText('a'.repeat(64))).toBeVisible();
  });

  it('sends a manual SPL as the exclusive source and disables fingerprint patching', async () => {
    const user = userEvent.setup();
    const onCommand = vi.fn<SharedPageProps['onCommand']>(async () => success());
    renderTools(factorySnapshot(), onCommand);

    await user.click(screen.getByRole('button', { name: /AVB downgrade patch/i }));
    const workspace = document.querySelector('.tool-workspace') as HTMLElement;
    await user.click(within(workspace).getByRole('radio', { name: 'Security patch date' }));
    await user.type(within(workspace).getByLabelText('Security patch date', { selector: 'input[type="date"]' }), '2025-03-05');
    await user.click(within(workspace).getByRole('button', { name: 'Prepare downgrade artifact' }));

    expect(onCommand).toHaveBeenCalledWith(commands.toolsAvb, {
      action: 'prepareDowngrade',
      currentSecurityPatch: '2025-03-05',
      patchFingerprint: false,
    }, {
      returnCancelled: true,
      returnFailed: true,
    });
    expect(onCommand).toHaveBeenCalledTimes(1);
  });

  it('keeps the command unavailable until factory firmware is verified and processed', () => {
    renderTools(factorySnapshot(false), vi.fn<SharedPageProps['onCommand']>());

    expect(screen.getByRole('button', { name: /AVB downgrade patch/i })).toBeDisabled();
  });
});
