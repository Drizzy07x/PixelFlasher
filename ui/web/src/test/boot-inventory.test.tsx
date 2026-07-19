import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { BridgeCommand } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import { RootPage } from '../pages/Pages';

const bootEntry = {
  bootId: 'a'.repeat(32),
  sha256: 'b'.repeat(64),
  size: 67_108_864,
  provenance: 'user_supplied',
  createdAt: 1_721_260_800,
  partition: 'boot',
  deviceCodenames: ['akita'],
  patcher: '',
  patcherVersion: '',
  signature: '',
  sourceHash: '',
  patched: false,
  verified: true,
};

function renderRoot(onCommand: (
  command: BridgeCommand,
  payload?: Record<string, unknown>,
) => Promise<{ result: Record<string, unknown> } | null>) {
  const snapshot = structuredClone(demoSnapshot);
  snapshot.boot = null;
  return render(
    <I18nProvider locale="en">
      <RootPage
        snapshot={snapshot}
        selectedSerials={snapshot.selectedSerials ?? []}
        onSelectionChange={vi.fn()}
        onCommand={onCommand}
      />
    </I18nProvider>,
  );
}

describe('boot image inventory', () => {
  it('lists bridge-safe metadata and selects only by repository boot ID', async () => {
    const user = userEvent.setup();
    const onCommand = vi.fn(async (command: BridgeCommand) => {
      if (command === 'boot.inventory') {
        return { result: { value: { boots: [bootEntry], selectedBootId: null, revision: 4 } } };
      }
      return { result: { value: { selected: bootEntry, revision: 5 } } };
    });
    renderRoot(onCommand);

    const card = screen.getByText('Boot image inventory').closest('.card');
    if (!card) throw new Error('boot inventory card missing');
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Refresh' }));
    const inventory = screen.getByRole('list', { name: 'Boot image inventory' });
    expect(await within(inventory).findByText('boot')).toBeVisible();
    expect(within(inventory).getByText('Stock')).toBeVisible();
    expect(within(inventory).getByText('Ready')).toBeVisible();
    expect(within(inventory).getByText('Provenance: user_supplied')).toBeVisible();
    expect(document.body.textContent).not.toContain('C:\\');
    expect(document.body.textContent).not.toContain('/home/');

    await user.click(screen.getByRole('button', { name: 'Use image' }));
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith('boot.select', {
      bootId: bootEntry.bootId,
    }));
  });

  it('imports through a dedicated opaque grant and never sends a browser path', async () => {
    const user = userEvent.setup();
    const imported = { ...bootEntry, bootId: 'c'.repeat(32), partition: 'init_boot' };
    const onCommand = vi.fn(async (command: BridgeCommand, payload: Record<string, unknown> = {}) => {
      if (command === 'native.pickFile') {
        return { result: { data: { grant: 'opaque-boot-read-grant' } } };
      }
      if (command === 'boot.select') {
        return { result: { value: { selected: imported, revision: 5 } } };
      }
      return { result: { value: { boots: [] } } };
    });
    renderRoot(onCommand);

    await user.selectOptions(screen.getByRole('combobox', { name: 'Image partition' }), 'init_boot');
    await user.click(screen.getByRole('button', { name: 'Import boot image' }));

    await waitFor(() => expect(onCommand).toHaveBeenCalledWith('native.pickFile', {
      purpose: 'boot.select.source',
      title: 'Import boot image',
      filters: [{ label: 'Android boot images', extensions: ['img'] }],
    }));
    expect(onCommand).toHaveBeenCalledWith('boot.select', {
      grant: 'opaque-boot-read-grant',
      partition: 'init_boot',
    });
    expect(JSON.stringify(onCommand.mock.calls)).not.toMatch(/(?:[A-Za-z]:\\|\/home\/)/);
    const inventory = screen.getByRole('list', { name: 'Boot image inventory' });
    expect(await within(inventory).findByText('init_boot')).toBeVisible();
  });

  it('rejects inventory records with unknown fields before rendering them', async () => {
    const user = userEvent.setup();
    const onCommand = vi.fn(async () => ({
      result: {
        value: {
          boots: [{ ...bootEntry, path: 'C:\\private\\boot.img' }],
          selectedBootId: null,
          revision: 4,
        },
      },
    }));
    renderRoot(onCommand);

    const card = screen.getByText('Boot image inventory').closest('.card');
    if (!card) throw new Error('boot inventory card missing');
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Refresh' }));
    expect(await screen.findByText('No boot images are stored in the local repository.')).toBeVisible();
    expect(document.body.textContent).not.toContain('private');
  });
});
