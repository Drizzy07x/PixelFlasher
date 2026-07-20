import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { commands } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import type { SharedPageProps } from '../pages/shared';
import { ToolsPage } from '../pages/tooling/ToolsPage';
import type { HostSnapshot } from '../types';

function renderTools(onCommand: SharedPageProps['onCommand']) {
  const snapshot = structuredClone(demoSnapshot) as HostSnapshot;
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

describe('My Tools Expert workspace', () => {
  it('creates and runs a shell-free profile while keeping legacy raw blocked', async () => {
    const user = userEvent.setup();
    const calls: Parameters<SharedPageProps['onCommand']>[] = [];
    const safeTool = {
      id: 'a'.repeat(32),
      title: 'Device report',
      mode: 'safeArgv',
      displayName: 'report.exe',
      sha256: 'b'.repeat(64),
      arguments: ['--literal', 'a && b'],
      enabled: true,
    };
    const legacy = {
      id: 'legacy:1',
      title: 'Old raw command',
      mode: 'legacyRaw',
      displayName: 'Legacy 9.x',
      sha256: '',
      arguments: [],
      enabled: true,
      permissionGranted: false,
      blockedReason: 'legacy_raw_permission_required',
    };
    let saved = false;
    const onCommand: SharedPageProps['onCommand'] = vi.fn(async (command, payload = {}, options) => {
      calls.push([command, payload, options]);
      if (command === commands.nativePickFile) {
        return {
          result: { status: 'SUCCESS', data: { grant: 'g'.repeat(64), displayName: 'report.exe' } },
          revision: 41,
        };
      }
      if (command === commands.toolsMyTools && payload.action === 'list') {
        return {
          result: {
            status: 'SUCCESS',
            value: { schemaVersion: 1, tools: saved ? [safeTool] : [], legacyRaw: [legacy], revision: 41 },
          },
          revision: 41,
        };
      }
      if (command === commands.toolsMyTools && payload.action === 'save') {
        saved = true;
        return { result: { status: 'SUCCESS', value: { tool: safeTool, revision: 41 } }, revision: 41 };
      }
      return { result: { status: 'SUCCESS', value: { tool: safeTool, revision: 41 } }, revision: 41 };
    });
    renderTools(onCommand);

    await user.click(screen.getByRole('button', { name: /My Tools/i }));
    const workspace = document.querySelector('.tool-workspace') as HTMLElement;
    expect(await within(workspace).findByText('Old raw command')).toBeVisible();
    expect(within(workspace).getByText('Blocked')).toBeVisible();

    await user.type(within(workspace).getByLabelText('Title'), 'Device report');
    await user.click(within(workspace).getByRole('button', { name: 'Choose executable' }));
    await user.type(within(workspace).getByLabelText('Arguments'), '--literal{enter}a && b');
    await user.click(within(workspace).getByRole('button', { name: 'Save profile' }));

    expect(await within(workspace).findByText('report.exe')).toBeVisible();
    await user.click(within(workspace).getByRole('button', { name: 'Run' }));

    expect(calls).toContainEqual([
      commands.nativePickFile,
      {
        purpose: 'tools.myTools.executable',
        title: 'Choose executable',
      },
      undefined,
    ]);
    expect(calls).toContainEqual([
      commands.toolsMyTools,
      {
        action: 'save',
        title: 'Device report',
        grant: 'g'.repeat(64),
        arguments: ['--literal', 'a && b'],
        enabled: true,
      },
      { expectedRevision: 41, returnFailed: true },
    ]);
    expect(calls).toContainEqual([
      commands.toolsMyTools,
      { action: 'run', toolId: 'a'.repeat(32) },
      { returnCancelled: true, returnFailed: true },
    ]);
    expect(JSON.stringify(calls)).not.toMatch(/cmd\.exe|\/c |shell|workingDirectory|environment/i);
  });
});
