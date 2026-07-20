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

describe('/data/adb backups', () => {
  it('uses opaque grants and exact device-bound confirmations', async () => {
    const user = userEvent.setup();
    const snapshot = structuredClone(demoSnapshot);
    const device = snapshot.devices[0];
    device.mode = 'adb';
    device.rooted = true;
    const onCommand = vi.fn(async (command: BridgeCommand) => {
      if (command === 'backups.list') {
        return success({
          backups: [], count: 0, totalCount: 0, filteredSerial: device.serial,
          revision: snapshot.revision, bounded: true, truncated: false,
        });
      }
      if (command === 'backups.magisk.list') {
        return success({ action: 'list', targetSerial: device.serial, count: 0, backups: [], bounded: true });
      }
      if (command === 'native.saveFile') return success({ data: { grant: 'opaque-write' } });
      if (command === 'native.pickFile') return success({ data: { grant: 'opaque-read' } });
      if (command === 'root.dataAdb.backup') {
        return success({
          action: 'backup', targetSerial: device.serial, fileName: 'data-adb.pfdataadb',
          sha256: 'a'.repeat(64), sizeBytes: 2048, payloadSha256: 'b'.repeat(64),
          entryCount: 3, contentFingerprint: 'c'.repeat(64), deviceCodename: device.codename,
          verified: true, remoteCleaned: true,
        });
      }
      if (command === 'root.dataAdb.restore') {
        return success({
          action: 'restore', targetSerial: device.serial, payloadSha256: 'b'.repeat(64),
          entryCount: 3, contentFingerprint: 'c'.repeat(64), deviceCodename: device.codename,
          verified: true, remoteCleaned: true,
        });
      }
      return success({ action: 'clear', targetSerial: device.serial, empty: true, verified: true });
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

    expect(screen.getByRole('region', { name: '/data/adb backup' })).toBeVisible();
    const accessibility = await axe.run(view.container, { rules: { 'color-contrast': { enabled: false } } });
    expect(accessibility.violations).toEqual([]);

    await user.click(screen.getByRole('button', { name: 'Back up /data/adb' }));
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith('native.saveFile', {
      purpose: 'root.dataAdb.backup.destination',
      title: 'Back up /data/adb',
      defaultName: `data-adb-${device.serial.slice(-6).toLowerCase()}.pfdataadb`,
      filters: [{ label: 'PixelFlasher data/adb backups', extensions: ['pfdataadb'] }],
    }, { returnCancelled: true }));
    expect(onCommand).toHaveBeenCalledWith(
      'root.dataAdb.backup',
      { serial: device.serial, grant: 'opaque-write' },
      { returnCancelled: true },
    );

    await user.click(screen.getByRole('button', { name: 'Restore /data/adb' }));
    const restoreText = `RESTORE DATAADB ${device.serial.slice(-6).toUpperCase()}`;
    await user.type(screen.getByLabelText('Backup deletion confirmation'), restoreText);
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith(
      'root.dataAdb.restore',
      { serial: device.serial, grant: 'opaque-read', confirmationText: restoreText },
      { returnCancelled: true },
    ));

    await user.click(screen.getByRole('button', { name: 'Clear /data/adb' }));
    const clearText = `CLEAR DATAADB ${device.serial.slice(-6).toUpperCase()}`;
    await user.type(screen.getByLabelText('Backup deletion confirmation'), clearText);
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith(
      'root.dataAdb.clear',
      { serial: device.serial, confirmationText: clearText },
      { returnCancelled: true },
    ));

    const calls = JSON.stringify(onCommand.mock.calls);
    expect(calls).not.toContain('C:\\');
    expect(calls).not.toContain('/Users/');
  });

  it('disables all mutations without one rooted ADB device', async () => {
    const snapshot = structuredClone(demoSnapshot);
    const device = snapshot.devices[1];
    const onCommand = vi.fn(async () => success({
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

    expect(screen.getByText('Select one rooted device in ADB mode to manage /data/adb.')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Back up /data/adb' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Restore /data/adb' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Clear /data/adb' })).toBeDisabled();
  });
});
