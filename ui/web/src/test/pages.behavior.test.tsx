import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { BridgeCommand } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import {
  AppsPage,
  BackupsPage,
  DashboardPage,
  DevicePage,
  FirmwarePage,
  SettingsPage,
} from '../pages/Pages';
import type { HostSnapshot } from '../types';

type CommandResult = { result: Record<string, unknown>; revision?: number } | null;

function freshSnapshot(): HostSnapshot {
  return structuredClone(demoSnapshot);
}

function page(ui: React.ReactNode) {
  return render(<I18nProvider locale="en">{ui}</I18nProvider>);
}

function commandHost(
  handler: (command: BridgeCommand, payload: Record<string, unknown>) => CommandResult | Promise<CommandResult>,
) {
  return vi.fn(async (command: BridgeCommand, payload: Record<string, unknown> = {}) => handler(command, payload));
}

const selection = vi.fn();

beforeEach(() => {
  window.pixelflasher = { postMessage: vi.fn() };
  selection.mockReset();
});

describe('dashboard and firmware host-backed states', () => {
  it('offers official setup or an existing folder without exposing host paths', async () => {
    const user = userEvent.setup();
    const snapshot: HostSnapshot = {
      revision: 0,
      preferences: demoSnapshot.preferences,
      devices: [],
      selectedSerials: [],
      firmware: null,
      toolchain: { adb: false, fastboot: false, ready: false },
    };
    let pickCount = 0;
    const onCommand = commandHost((command) => {
      if (command === 'native.pickDirectory') {
        pickCount += 1;
        return pickCount === 1
          ? null
          : { result: { value: { data: { grant: 'directory-grant' } } } };
      }
      return { result: { status: 'SUCCESS' } };
    });
    page(
      <DashboardPage
        snapshot={snapshot}
        selectedSerials={[]}
        onSelectionChange={selection}
        onCommand={onCommand}
      />,
    );

    expect(screen.getByRole('alert')).toHaveTextContent('Platform Tools need attention');
    expect(screen.getAllByText('OFFLINE')).toHaveLength(2);
    expect(screen.getAllByRole('button', { name: /Scan Devices|Reboot Device|Switch Slot/ })).toHaveLength(3);
    for (const action of screen.getAllByRole('button', { name: /Scan Devices|Reboot Device|Switch Slot/ })) {
      expect(action).toBeDisabled();
    }

    await user.click(screen.getByRole('button', { name: 'Install official tools' }));
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith('platformTools.setup', { source: 'official' }));

    const existingFolder = screen.getByRole('button', { name: 'Use existing folder' });
    await user.click(existingFolder);
    await user.click(existingFolder);
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith('native.pickDirectory', {
      purpose: 'platformTools.setup.directory',
      title: 'Use existing folder',
    }));
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith('platformTools.setup', {
      source: 'directory',
      grant: 'directory-grant',
    }));
    expect(JSON.stringify(onCommand.mock.calls)).not.toContain('C:\\');
  });

  it('renders the real-host empty firmware library and imports through a read grant', async () => {
    const user = userEvent.setup();
    const snapshot = { ...freshSnapshot(), firmware: null };
    let picks = 0;
    const onCommand = commandHost((command) => {
      if (command === 'native.pickFile') {
        picks += 1;
        return picks === 1 ? null : { result: { data: { grant: 'firmware-grant' } } };
      }
      return { result: { status: 'SUCCESS' } };
    });
    page(
      <FirmwarePage
        snapshot={snapshot}
        selectedSerials={[]}
        onSelectionChange={selection}
        onCommand={onCommand}
      />,
    );
    expect(screen.getByText('None')).toBeVisible();
    const importButton = screen.getByRole('button', { name: 'Import factory or OTA' });
    await user.click(importButton);
    await user.click(importButton);
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith('firmware.select', {
      grant: 'firmware-grant',
      expectedKind: 'stock',
    }));

    await user.click(screen.getByRole('button', { name: 'Import custom ROM' }));
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith('firmware.select', {
      grant: 'firmware-grant',
      expectedKind: 'custom',
    }));
  });

  it('processes an unprocessed real-host firmware and shows verified ready state after rerender', async () => {
    const user = userEvent.setup();
    const snapshot = freshSnapshot();
    snapshot.firmware = { ...snapshot.firmware!, processed: false, channel: 'beta', kind: 'ota' };
    const onCommand = commandHost(() => ({ result: { status: 'SUCCESS' } }));
    const { rerender } = page(
      <FirmwarePage snapshot={snapshot} selectedSerials={[]} onSelectionChange={selection} onCommand={onCommand} />,
    );
    expect(screen.queryByRole('checkbox', { name: /Low-memory processing/ })).not.toBeInTheDocument();
    expect(screen.getByText('beta')).toHaveClass('badge--warning');
    await user.click(screen.getByRole('button', { name: 'Process package' }));
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith('firmware.process'));

    snapshot.firmware = { ...snapshot.firmware, processed: true };
    rerender(<I18nProvider locale="en"><FirmwarePage snapshot={snapshot} selectedSerials={[]} onSelectionChange={selection} onCommand={onCommand} /></I18nProvider>);
    expect(screen.getByText('Ready')).toBeVisible();
  });
});

describe('device operation guards and evidence', () => {
  it('shows a single-target guard when selection is ambiguous', () => {
    const snapshot = freshSnapshot();
    const onCommand = commandHost(() => ({ result: {} }));
    page(
      <DevicePage
        snapshot={snapshot}
        selectedSerials={snapshot.devices.slice(0, 2).map((device) => device.serial)}
        onSelectionChange={selection}
        onCommand={onCommand}
        expertMode
      />,
    );
    expect(screen.getByText('Select exactly one device to run an operation.')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Reboot now' })).toBeDisabled();
  });

  it('unlocks a locked fastboot target and exercises reboot mode selection', async () => {
    const user = userEvent.setup();
    const snapshot = freshSnapshot();
    const locked = { ...snapshot.devices[1], bootloader: 'locked' as const, slot: 'unknown' as const };
    snapshot.devices = [locked];
    snapshot.boot = { id: 'unverified-boot', image: 'boot.img', hash: 'not-a-hash', flavor: 'unknown' };
    const onCommand = commandHost(() => ({ result: { status: 'SUCCESS' } }));
    page(
      <DevicePage snapshot={snapshot} selectedSerials={[locked.serial]} onSelectionChange={selection} onCommand={onCommand} expertMode />,
    );
    expect(screen.getByRole('button', { name: 'Unlock bootloader' })).toBeEnabled();
    expect(screen.getByText('Select or patch a verified boot image first.')).toBeVisible();
    expect(screen.getByRole('button', { name: /Switch to slot/ })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Unlock bootloader' }));
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith('device.bootloader.unlock', { serial: locked.serial }));

    await user.selectOptions(screen.getByLabelText('Reboot destination'), 'recovery');
    await user.click(screen.getByRole('button', { name: 'Reboot now' }));
    expect(onCommand).toHaveBeenCalledWith(
      'device.reboot',
      { serial: locked.serial, mode: 'recovery' },
      { returnCancelled: true },
    );
  });

  it('allows relock only with current backend evidence and includes an explicit flash slot', async () => {
    const user = userEvent.setup();
    const snapshot = freshSnapshot();
    const fastboot = snapshot.devices[1];
    snapshot.devices = [fastboot];
    snapshot.boot = { id: 'stock-init-boot', image: 'init_boot.img', hash: 'c'.repeat(64), flavor: 'init_boot', patched: false, verified: true };
    snapshot.bootloaderLockEvidence = [{
      serial: fastboot.serial,
      snapshot_revision: snapshot.revision,
    }];
    const onCommand = commandHost(() => ({ result: { status: 'SUCCESS' } }));
    page(
      <DevicePage snapshot={snapshot} selectedSerials={[fastboot.serial]} onSelectionChange={selection} onCommand={onCommand} expertMode />,
    );
    expect(screen.getByRole('button', { name: 'Lock bootloader' })).toBeEnabled();
    await user.click(screen.getByRole('button', { name: 'Lock bootloader' }));
    await user.selectOptions(screen.getByLabelText('Target slot'), 'a');
    await user.click(screen.getByRole('button', { name: 'Flash image' }));
    await waitFor(() => {
      expect(onCommand).toHaveBeenCalledWith('device.bootloader.lock', { serial: fastboot.serial });
      expect(onCommand).toHaveBeenCalledWith('boot.flash', { serial: fastboot.serial, partition: 'init_boot', slot: 'a' });
    });
    expect(screen.getByRole('button', { name: 'Live boot' })).toBeDisabled();
  });
});

describe('apps, backups and settings workflows', () => {
  it('refreshes, filters, selects and updates host package inventory', async () => {
    const user = userEvent.setup();
    const snapshot = freshSnapshot();
    const serial = snapshot.devices[0].serial;
    const onCommand = commandHost((command) => {
      if (command === 'apps.list') {
        return { result: { status: 'SUCCESS', value: { packages: [
          { package: 'com.example.system', apk_path: '/system/app/example.apk' },
          { package: 'com.example.user', apk_path: '/data/app/example.apk' },
          { package: '', apk_path: '/bad' },
          null,
        ] } } };
      }
      if (command === 'native.pickFile') {
        return { result: { status: 'SUCCESS', value: { data: { grant: 'apk-read-grant' } } } };
      }
      if (command === 'apps.action') {
        return { result: {
          status: 'SUCCESS',
          value: {
            action: 'install',
            apkIdentity: {
              packageName: 'com.example.installed',
              sha256: 'a'.repeat(64),
              verified: true,
            },
          },
        } };
      }
      return { result: { status: 'SUCCESS' } };
    });
    page(
      <AppsPage snapshot={snapshot} selectedSerials={[serial]} onSelectionChange={selection} onCommand={onCommand} />,
    );
    await user.click(screen.getByRole('button', { name: 'Refresh' }));
    expect(await screen.findAllByText('com.example.system')).toHaveLength(2);
    expect(screen.getAllByText('System').length).toBeGreaterThan(0);
    expect(screen.getAllByText('User').length).toBeGreaterThan(0);

    await user.type(screen.getByPlaceholderText('Filter packages'), 'user');
    expect(screen.queryByText('com.example.system')).not.toBeInTheDocument();
    const packageToggle = screen.getByRole('checkbox', { name: /com.example.user/ });
    await user.click(packageToggle);
    await user.selectOptions(screen.getByLabelText('Apply changes'), 'enable');
    await user.click(screen.getByRole('button', { name: 'Apply changes' }));
    await waitFor(() => expect(onCommand).toHaveBeenCalledWith('apps.action', {
      serial,
      packages: ['com.example.user'],
      action: 'enable',
    }));

    await user.click(screen.getByRole('checkbox', { name: /^Allow version downgrade/ }));
    await user.click(screen.getByRole('button', { name: 'Choose APK and install' }));
    await waitFor(() => {
      expect(onCommand).toHaveBeenCalledWith('native.pickFile', {
        purpose: 'apps.install.source',
        title: 'Install APK',
        filters: [{ label: 'Android application packages', extensions: ['apk'] }],
      }, { returnCancelled: true });
      expect(onCommand).toHaveBeenCalledWith('apps.action', {
        serial,
        action: 'install',
        grant: 'apk-read-grant',
        options: {
          playStoreOwnership: false,
          replace: true,
          grantPermissions: false,
          allowDowngrade: true,
          allowTest: false,
          forceQueryable: false,
          bypassLowTargetSdk: false,
        },
      }, { returnCancelled: true });
    });
  });

  it('runs extended package actions and renders a bounded permission report', async () => {
    const user = userEvent.setup();
    const snapshot = freshSnapshot();
    const serial = snapshot.devices[0].serial;
    const onCommand = commandHost((command, payload) => {
      if (command === 'apps.list') return { result: { status: 'SUCCESS', value: { packages: [
        { package: 'com.example.user', apk_path: '/data/app/example.apk', uid: 10123 },
      ] } } };
      if (command === 'native.saveFile') return { result: { status: 'SUCCESS', value: { data: { grant: 'apk-write-once' } } } };
      if (command === 'apps.action' && payload.action === 'permissions') return { result: {
        status: 'SUCCESS',
        value: {
          action: 'permissions',
          report: {
            package: 'com.example.user',
            requested: ['android.permission.CAMERA'],
            runtimeGranted: ['android.permission.CAMERA'],
            runtimeDenied: [],
            requestedCount: 1,
            runtimeCount: 1,
            bounded: true,
          },
        },
      } };
      return { result: { status: 'SUCCESS', value: { action: payload.action } } };
    });
    page(
      <AppsPage snapshot={snapshot} selectedSerials={[serial]} onSelectionChange={selection} onCommand={onCommand} />,
    );

    await user.click(screen.getByRole('button', { name: 'Refresh' }));
    await user.click(await screen.findByRole('checkbox', { name: /com.example.user/ }));
    await user.selectOptions(screen.getByLabelText('Apply changes'), 'permissions');
    await user.click(screen.getByRole('button', { name: 'Apply changes' }));

    expect(await screen.findByText('Package permissions')).toBeVisible();
    expect(screen.getAllByText('android.permission.CAMERA')).toHaveLength(2);
    expect(onCommand).toHaveBeenCalledWith('apps.action', {
      serial,
      packages: ['com.example.user'],
      action: 'permissions',
    });

    await user.selectOptions(screen.getByLabelText('Apply changes'), 'suPolicy');
    await user.selectOptions(screen.getByLabelText('Policy'), 'deny');
    await user.selectOptions(screen.getByLabelText('Duration'), '20');
    await user.click(screen.getByRole('button', { name: 'Apply changes' }));

    await waitFor(() => expect(onCommand).toHaveBeenCalledWith('apps.action', {
      serial,
      package: 'com.example.user',
      action: 'suPolicy',
      options: {
        uid: 10123,
        policy: 'deny',
        logging: true,
        notification: true,
        durationMinutes: 20,
      },
    }));

    await user.click(await screen.findByRole('checkbox', { name: /com.example.user/ }));
    await user.selectOptions(screen.getByLabelText('Apply changes'), 'export');
    await user.click(screen.getByRole('button', { name: 'Apply changes' }));

    await waitFor(() => expect(onCommand).toHaveBeenCalledWith('native.saveFile', {
      purpose: 'apps.export.destination',
      title: 'Export APK',
      defaultName: 'com.example.user.apk',
      filters: [{ label: 'Android application packages', extensions: ['apk'] }],
    }, { returnCancelled: true }));
    expect(onCommand).toHaveBeenCalledWith('apps.action', {
      serial,
      package: 'com.example.user',
      action: 'export',
      grant: 'apk-write-once',
    });
  });

  it('creates, restores and deletes route-free managed backups', async () => {
    const user = userEvent.setup();
    const snapshot = freshSnapshot();
    const fastboot = snapshot.devices[1];
    const backupId = `${'a'.repeat(24)}12345678`;
    const managedBackup = {
      id: backupId,
      sha256: 'b'.repeat(64),
      sizeBytes: 64 * 1024 * 1024,
      createdAt: 1_752_816_600,
      targetSerial: fastboot.serial,
      deviceCodename: fastboot.codename,
      partition: 'init_boot',
      slot: 'a',
      targetPartition: 'init_boot_a',
      provenance: 'created',
      available: true,
      integrity: 'stored',
    };
    const onCommand = commandHost((command) => {
      if (command === 'native.saveFile') return { result: { value: { data: { grant: 'write-once' } } } };
      if (command === 'native.pickFile') return { result: { value: { data: { grant: 'read-session' } } } };
      if (command === 'backups.list') return { result: {
        status: 'SUCCESS',
        value: {
          backups: [managedBackup], count: 1, totalCount: 1,
          filteredSerial: fastboot.serial, revision: snapshot.revision,
          bounded: true, truncated: false,
        },
      } };
      return { result: { status: 'SUCCESS' } };
    });
    page(
      <BackupsPage snapshot={snapshot} selectedSerials={[fastboot.serial]} onSelectionChange={selection} onCommand={onCommand} />,
    );
    expect(await screen.findByText('init_boot_a')).toBeVisible();
    await user.selectOptions(screen.getByLabelText('Partition manager'), 'init_boot');
    await user.selectOptions(screen.getByLabelText('Target slot'), 'a');
    await user.click(screen.getByRole('button', { name: 'Create backup' }));
    await user.click(screen.getByRole('button', { name: 'Restore external image' }));
    await user.click(screen.getByRole('button', { name: 'Restore backup' }));
    await user.click(screen.getByRole('button', { name: 'Delete backup' }));
    await user.type(screen.getByLabelText('Backup deletion confirmation'), 'DELETE 12345678');
    await user.click(screen.getByRole('button', { name: 'Delete permanently' }));
    await waitFor(() => {
      expect(onCommand).toHaveBeenCalledWith('backups.list', { serial: fastboot.serial }, undefined);
      expect(onCommand).toHaveBeenCalledWith('backups.create', {
        serial: fastboot.serial, partition: 'init_boot', slot: 'a', grant: 'write-once',
      });
      expect(onCommand).toHaveBeenCalledWith('backups.restore', {
        serial: fastboot.serial, partition: 'init_boot', slot: 'a', grant: 'read-session',
      });
      expect(onCommand).toHaveBeenCalledWith('backups.restore', {
        serial: fastboot.serial, partition: 'init_boot', slot: 'a', backupId,
      });
      expect(onCommand).toHaveBeenCalledWith('backups.delete', {
        backupId, confirmationText: 'DELETE 12345678',
      });
    });
    expect(JSON.stringify(onCommand.mock.calls)).not.toContain('/safe/');
  });

  it('exposes bounded appearance and accessibility controls', async () => {
    const user = userEvent.setup();
    const callbacks = {
      theme: vi.fn(), locale: vi.fn(), contrast: vi.fn(), motion: vi.fn(), zoom: vi.fn(), expert: vi.fn(), maintenance: vi.fn(), application: vi.fn(), consoleClear: vi.fn(), consoleExport: vi.fn(),
    };
    const { rerender } = page(
      <SettingsPage
        theme="dark" onThemeChange={callbacks.theme}
        locale="en" onLocaleChange={callbacks.locale}
        highContrast={false} onHighContrastChange={callbacks.contrast}
        reducedMotion={false} onReducedMotionChange={callbacks.motion}
        zoom={80} onZoomChange={callbacks.zoom}
        expertMode={false} onExpertModeChange={callbacks.expert}
        preferences={demoSnapshot.preferences} onMaintenancePreferenceChange={callbacks.maintenance}
        onApplicationCommand={callbacks.application}
        applicationConsoleLines={['[PROGRESS 50%] Processing firmware.']}
        onApplicationConsoleClear={callbacks.consoleClear}
        onApplicationConsoleExport={callbacks.consoleExport}
      />,
    );
    await user.click(screen.getByRole('button', { name: 'Light' }));
    await user.selectOptions(screen.getByLabelText('Language'), 'zh_TW');
    await user.click(screen.getByRole('checkbox', { name: /High contrast/ }));
    await user.click(screen.getByRole('checkbox', { name: /Reduce motion/ }));
    await user.click(screen.getByRole('checkbox', { name: /Expert Mode/ }));
    await user.click(screen.getByRole('checkbox', { name: /Require minimum disk space/ }));
    await user.click(screen.getByRole('checkbox', { name: /Automatic application update checks/ }));
    expect(screen.getByLabelText('Monospace font')).toBeDisabled();
    await user.click(screen.getByRole('checkbox', { name: /Custom monospace font/ }));
    await user.selectOptions(screen.getByLabelText('Toolbar position'), 'right');
    await user.click(screen.getByRole('checkbox', { name: /Device context/ }));
    await user.click(screen.getByRole('checkbox', { name: /Theme controls/ }));
    await user.click(screen.getByRole('checkbox', { name: /Language control/ }));
    fireEvent.change(screen.getByRole('spinbutton', { name: /Android startup timeout/ }), { target: { value: '180' } });
    await user.click(screen.getByRole('button', { name: 'Zoom out' }));
    await user.click(screen.getByRole('button', { name: 'Reset zoom' }));
    await user.click(screen.getByRole('button', { name: 'Open configuration folder' }));
    await user.click(screen.getByRole('button', { name: 'Open logs folder' }));
    await user.click(screen.getByRole('button', { name: 'Open verified cache' }));
    await user.click(screen.getByRole('button', { name: 'Exit PixelFlasher' }));
    await user.click(screen.getByRole('button', { name: 'Clear console' }));
    await user.click(screen.getByRole('button', { name: 'Export redacted console' }));
    expect(callbacks.theme).toHaveBeenCalledWith('light');
    expect(callbacks.locale).toHaveBeenCalledWith('zh_TW');
    expect(callbacks.contrast).toHaveBeenCalledWith(true);
    expect(callbacks.motion).toHaveBeenCalledWith(true);
    expect(callbacks.expert).toHaveBeenCalledWith(true);
    expect(callbacks.maintenance).toHaveBeenCalledWith('checkDiskSpace', false);
    expect(callbacks.maintenance).toHaveBeenCalledWith('automaticUpdateCheck', true);
    expect(callbacks.maintenance).toHaveBeenCalledWith('customizeFont', true);
    expect(callbacks.maintenance).toHaveBeenCalledWith('toolbarPosition', 'right');
    expect(callbacks.maintenance).toHaveBeenCalledWith('toolbarShowDevice', false);
    expect(callbacks.maintenance).toHaveBeenCalledWith('toolbarShowTheme', false);
    expect(callbacks.maintenance).toHaveBeenCalledWith('toolbarShowLanguage', false);
    expect(callbacks.maintenance).toHaveBeenCalledWith('rebootTimeoutSeconds', 180);
    expect(callbacks.zoom).toHaveBeenCalledWith(80);
    expect(callbacks.zoom).toHaveBeenCalledWith(100);
    expect(callbacks.application).toHaveBeenCalledWith('openFolder', 'configuration');
    expect(callbacks.application).toHaveBeenCalledWith('openFolder', 'logs');
    expect(callbacks.application).toHaveBeenCalledWith('openFolder', 'cache');
    expect(callbacks.application).toHaveBeenCalledWith('exit');
    expect(callbacks.consoleClear).toHaveBeenCalledOnce();
    expect(callbacks.consoleExport).toHaveBeenCalledOnce();

    rerender(<I18nProvider locale="en"><SettingsPage
      theme="light" onThemeChange={callbacks.theme}
      locale="en" onLocaleChange={callbacks.locale}
      highContrast onHighContrastChange={callbacks.contrast}
      reducedMotion onReducedMotionChange={callbacks.motion}
      zoom={200} onZoomChange={callbacks.zoom}
      expertMode onExpertModeChange={callbacks.expert}
      preferences={{ ...demoSnapshot.preferences, expertMode: true, rebootTimeoutSeconds: 200 }} onMaintenancePreferenceChange={callbacks.maintenance}
      onApplicationCommand={callbacks.application}
      applicationConsoleLines={[]}
      onApplicationConsoleClear={callbacks.consoleClear}
      onApplicationConsoleExport={callbacks.consoleExport}
    /></I18nProvider>);
    await user.click(screen.getByRole('button', { name: 'Zoom in' }));
    await user.click(screen.getByRole('checkbox', { name: /Low-memory processing/ }));
    expect(callbacks.maintenance).toHaveBeenCalledWith('lowMemoryMode', true);
    expect(callbacks.zoom).toHaveBeenCalledWith(200);
    expect(screen.getByRole('button', { name: 'Light' })).toHaveAttribute('aria-pressed', 'true');
  });
});
