import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import axe from 'axe-core';
import { describe, expect, it, vi } from 'vitest';
import type { BridgeCommand } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import { BackupsPage } from '../pages/Pages';

function success(value: Record<string, unknown>) {
  return { result: { status: 'SUCCESS', value }, revision: demoSnapshot.revision };
}

describe('Magisk backup inventory', () => {
  it('uses an opaque grant, verifies inventory state and requires device-bound deletion text', async () => {
    const user = userEvent.setup();
    const snapshot = structuredClone(demoSnapshot);
    const device = snapshot.devices[0];
    const sha1 = 'a'.repeat(40);
    const onCommand = vi.fn(async (command: BridgeCommand) => {
      if (command === 'backups.list') {
        return success({
          backups: [], count: 0, totalCount: 0, filteredSerial: device.serial,
          revision: snapshot.revision, bounded: true, truncated: false,
        });
      }
      if (command === 'backups.magisk.list') {
        return success({
          action: 'list', targetSerial: device.serial, count: 1, bounded: true,
          backups: [{ sha1, sizeBytes: 8_388_608, createdAt: 1_752_816_600, integrity: 'corrupt' }],
        });
      }
      if (command === 'native.pickFile') {
        return success({ data: { grant: 'magisk-read-session' } });
      }
      return success({ action: command.endsWith('delete') ? 'delete' : 'import', targetSerial: device.serial, sha1, verified: true });
    });

    const view = render(
      <I18nProvider locale="en">
        <BackupsPage
          snapshot={snapshot}
          selectedSerials={[device.serial]}
          onSelectionChange={vi.fn()}
          onCommand={onCommand}
        />
      </I18nProvider>,
    );

    expect(await screen.findByText('Stock boot image')).toBeVisible();
    expect(screen.getByText('Corrupt')).toBeVisible();
    const results = await axe.run(view.container, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations).toEqual([]);

    await user.click(screen.getByRole('button', { name: 'Import stock boot image' }));
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith('native.pickFile', {
      purpose: 'backups.magisk.import.source',
      title: 'Import stock boot image',
      filters: [{ label: 'Boot images', extensions: ['img'] }],
    }, { returnCancelled: true }));
    expect(onCommand).toHaveBeenCalledWith('backups.magisk.import', {
      serial: device.serial,
      grant: 'magisk-read-session',
    }, { returnCancelled: true });

    await user.click(screen.getByRole('button', { name: 'Delete backup' }));
    const confirmation = `DELETE MAGISK ${sha1.slice(-8).toUpperCase()} ${device.serial.slice(-6).toUpperCase()}`;
    await user.type(screen.getByLabelText('Backup deletion confirmation'), confirmation);
    await user.click(screen.getByRole('button', { name: 'Delete permanently' }));
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith('backups.magisk.delete', {
      serial: device.serial,
      sha1,
      confirmationText: confirmation,
    }));
    expect(JSON.stringify(onCommand.mock.calls)).not.toContain('.img');
    expect(JSON.stringify(onCommand.mock.calls)).not.toContain('\\Users\\');
  });

  it('does not query Magisk without one rooted ADB device', async () => {
    const snapshot = structuredClone(demoSnapshot);
    const device = snapshot.devices[1];
    const onCommand = vi.fn(async (_command: BridgeCommand) => success({
      backups: [], count: 0, totalCount: 0, filteredSerial: device.serial,
      revision: snapshot.revision, bounded: true, truncated: false,
    }));

    render(
      <I18nProvider locale="en">
        <BackupsPage
          snapshot={snapshot}
          selectedSerials={[device.serial]}
          onSelectionChange={vi.fn()}
          onCommand={onCommand}
        />
      </I18nProvider>,
    );

    expect(await screen.findByText('Select one rooted device connected through ADB to manage Magisk backups.')).toBeVisible();
    expect(onCommand.mock.calls.some(([command]) => command === 'backups.magisk.list')).toBe(false);
  });
});
