import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import axe from 'axe-core';
import { afterEach, describe, expect, it, vi } from 'vitest';
import App from '../App';
import type { BridgeRequest, HostSnapshot, ModernPreferences } from '../types';

const developmentBridge = window.pixelflasher;

const hostPreferences: ModernPreferences = {
  schemaVersion: 1,
  theme: 'dark',
  locale: 'en',
  highContrast: false,
  reducedMotion: false,
  zoom: 100,
};

function installPreferencesHost(
  initial: ModernPreferences,
  options: { failUpdate?: boolean } = {},
) {
  let preferences = initial;
  const requests: BridgeRequest[] = [];
  window.pixelflasher = {
    postMessage(raw) {
      const request = JSON.parse(raw) as BridgeRequest;
      requests.push(request);
      queueMicrotask(() => {
        let result: Record<string, unknown>;
        if (request.command === 'snapshot.get') {
          result = {
            revision: 7,
            devices: [],
            selected_serials: [],
            firmware: null,
            toolchain: { adb: '', fastboot: '', ready: false },
          };
        } else if (request.command === 'settings.get') {
          result = {
            status: 'SUCCESS',
            code: 'settings_loaded',
            message: 'Preferences loaded.',
            value: { preferences },
          };
        } else if (request.command === 'settings.update' && options.failUpdate) {
          result = {
            status: 'FAILED',
            code: 'settings_save_failed',
            message: 'Disk full.',
          };
        } else if (request.command === 'settings.update') {
          preferences = { ...preferences, ...request.payload } as ModernPreferences;
          result = {
            status: 'SUCCESS',
            code: 'settings_updated',
            message: 'Preferences saved.',
            value: { preferences },
          };
        } else {
          result = { status: 'SUCCESS', message: 'Command accepted.' };
        }
        window.dispatchEvent(new CustomEvent('pixelflasher:message', {
          detail: {
            version: 2,
            requestId: request.requestId,
            ok: true,
            result: { ...result, revision: 7 },
          },
        }));
      });
    },
  };
  return requests;
}

afterEach(() => {
  developmentBridge?.__reset?.();
  window.pixelflasher = developmentBridge;
});

describe('PixelFlasher web workspace', () => {
  it('renders the faithful dashboard and exposes all nine tasks', async () => {
    render(<App />);
    expect(await screen.findByRole('heading', { name: 'Modern UI' })).toBeVisible();
    expect(screen.getByText('Platform Tools Ready')).toBeVisible();
    expect(screen.getByText('Pixel 8a')).toBeVisible();
    const navigation = within(screen.getByRole('navigation', { name: 'Tasks' }));
    for (const task of ['Dashboard', 'Device', 'Flash', 'Firmware', 'Root', 'Apps', 'Backups', 'Tools', 'Settings']) {
      expect(navigation.getByRole('button', { name: task })).toBeVisible();
    }
  });

  it('supports keyboard task navigation and interface zoom', async () => {
    render(<App />);
    await screen.findByRole('heading', { name: 'Modern UI' });
    fireEvent.keyDown(window, { key: '2', altKey: true });
    expect(await screen.findByRole('heading', { name: 'Device workspace' })).toBeVisible();

    fireEvent.keyDown(window, { key: '+', ctrlKey: true });
    await waitFor(() => expect(document.documentElement.style.fontSize).toBe('110%'));
    fireEvent.keyDown(window, { key: '0', ctrlKey: true });
    await waitFor(() => expect(document.documentElement.style.fontSize).toBe('100%'));
  });

  it('runs typed Device operations with exact targets and reinforced confirmation', async () => {
    const user = userEvent.setup();
    const postMessage = vi.spyOn(developmentBridge!, 'postMessage');
    render(<App />);
    const navigation = within(await screen.findByRole('navigation', { name: 'Tasks' }));
    await user.click(navigation.getByRole('button', { name: 'Device' }));
    expect(await screen.findByRole('heading', { name: 'Device workspace' })).toBeVisible();

    await user.click(screen.getByLabelText(/Pixel 8a/i));
    expect(await screen.findByText('0 selected for batch actions')).toBeVisible();
    await user.click(screen.getByLabelText(/Pixel 8 Pro/i));
    expect(await screen.findByText('1 selected for batch actions')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Switch to slot A' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Live boot' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Flash image' })).toBeEnabled();
    expect(screen.queryByRole('button', { name: 'Lock bootloader' })).not.toBeInTheDocument();

    await user.click(screen.getByRole('checkbox', { name: 'Expert Mode' }));
    expect(await screen.findByRole('button', { name: 'Lock bootloader' })).toBeDisabled();
    expect(screen.getByText(/Locking stays blocked until PixelFlasher verifies a complete compatible stock factory flash/i)).toBeVisible();

    const acceptInteraction = async () => {
      const dialog = await screen.findByRole('alertdialog');
      await user.click(within(dialog).getByRole('button', { name: 'Continue' }));
      await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    };
    const acceptReinforced = async (requiredText: string) => {
      const typedDialog = await screen.findByRole('alertdialog');
      const field = within(typedDialog).getByPlaceholderText(requiredText);
      const continueButton = within(typedDialog).getByRole('button', { name: 'Continue' });
      expect(continueButton).toBeDisabled();
      await user.type(field, requiredText);
      expect(continueButton).toBeEnabled();
      await user.click(continueButton);
      await waitFor(() => {
        const dialog = screen.getByRole('alertdialog');
        expect(within(dialog).queryByRole('textbox')).not.toBeInTheDocument();
      });
      await acceptInteraction();
    };

    await user.click(screen.getByRole('button', { name: 'Switch to slot A' }));
    await acceptReinforced('SWITCH 4B281FDH2003L7 TO SLOT a');
    expect(await screen.findByText('Switched 4B281FDH2003L7 to slot a.')).toBeVisible();

    await user.click(screen.getByRole('button', { name: 'Live boot' }));
    await acceptInteraction();
    expect(await screen.findByText('Live boot started on 4B281FDH2003L7.')).toBeVisible();

    await user.click(screen.getByRole('button', { name: 'Flash image' }));
    await acceptInteraction();
    expect(await screen.findByText('Flashed boot image on 4B281FDH2003L7.')).toBeVisible();

    const requests = postMessage.mock.calls.map(([raw]) => JSON.parse(raw) as BridgeRequest);
    const slotRequests = requests.filter((request) => request.command === 'device.switchSlot');
    expect(slotRequests).toHaveLength(2);
    expect(slotRequests[0].payload).toEqual({ serial: '4B281FDH2003L7', slot: 'a' });
    expect(slotRequests[1].payload).toEqual({
      serial: '4B281FDH2003L7',
      slot: 'a',
      confirmationText: 'SWITCH 4B281FDH2003L7 TO SLOT a',
    });
    expect(requests.find((request) => request.command === 'boot.live')?.payload).toEqual({ serial: '4B281FDH2003L7' });
    expect(requests.find((request) => request.command === 'boot.flash')?.payload).toEqual({ serial: '4B281FDH2003L7', partition: 'boot' });
    expect(requests.some((request) => request.command === 'device.bootloader.lock')).toBe(false);
  });

  it('processes only the canonical selected firmware and renders the promoted ready state', async () => {
    const user = userEvent.setup();
    const postMessage = vi.spyOn(developmentBridge!, 'postMessage');
    const dispatchEvent = vi.spyOn(window, 'dispatchEvent');
    render(<App />);
    const navigation = within(await screen.findByRole('navigation', { name: 'Tasks' }));
    await user.click(navigation.getByRole('button', { name: 'Firmware' }));
    expect(await screen.findByRole('heading', { name: 'Firmware library' })).toBeVisible();

    await user.click(screen.getByRole('button', { name: 'Process package' }));
    expect(await screen.findByText('factory firmware processed successfully')).toBeVisible();
    const activeFirmware = screen.getByText('Pixel 8a Factory Image').closest('[role="listitem"]') as HTMLElement;
    expect(await within(activeFirmware).findByText('Ready')).toBeVisible();

    const processRequest = postMessage.mock.calls
      .map(([raw]) => JSON.parse(raw) as BridgeRequest)
      .find((request) => request.command === 'firmware.process');
    expect(processRequest?.payload).toEqual({});
    expect(typeof processRequest?.expectedRevision).toBe('number');
    const promoted = dispatchEvent.mock.calls
      .map(([event]) => (event as CustomEvent<{ event?: string; payload?: HostSnapshot }>).detail)
      .find((detail) => detail?.event === 'snapshot' && detail.payload?.firmware?.processed === true);
    expect(promoted?.payload?.firmware).toMatchObject({ verified: true, processed: true, hash: '8'.repeat(64) });
    expect(promoted?.payload?.boot).toMatchObject({ flavor: 'init_boot', patched: false });
  });

  it('uses verified rooting app inventory and exact guarded patch and module commands', async () => {
    const user = userEvent.setup();
    const postMessage = vi.spyOn(developmentBridge!, 'postMessage');
    const dispatchEvent = vi.spyOn(window, 'dispatchEvent');
    render(<App />);
    const navigation = within(await screen.findByRole('navigation', { name: 'Tasks' }));
    await user.click(navigation.getByRole('button', { name: 'Root' }));
    expect(await screen.findByRole('heading', { name: 'Root workspace' })).toBeVisible();

    const patchButton = screen.getByRole('button', { name: 'Patch selected boot image' });
    expect(patchButton).toBeDisabled();
    expect(screen.getAllByRole('radio')).toHaveLength(7);
    for (const method of ['KernelSU Next', 'Wild_KSU', 'KernelSU Legacy']) {
      expect(screen.getByLabelText(new RegExp(method, 'i'))).toBeVisible();
    }

    const appsCard = screen.getByText('Rooting Apps').closest('.card') as HTMLElement;
    const appsRefresh = within(appsCard).getByRole('button', { name: 'Refresh' });
    await user.click(appsRefresh);
    expect(await within(appsCard).findByText('Magisk')).toBeVisible();
    expect(patchButton).toBeEnabled();

    const acceptInteraction = async () => {
      const dialog = await screen.findByRole('alertdialog');
      await user.click(within(dialog).getByRole('button', { name: 'Continue' }));
      await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    };

    await user.click(patchButton);
    await screen.findByRole('alertdialog');
    expect(appsRefresh).toBeDisabled();
    const patchRequest = postMessage.mock.calls
      .map(([raw]) => JSON.parse(raw) as BridgeRequest)
      .find((request) => request.command === 'boot.patch');
    expect(patchRequest?.payload).toEqual({
      serial: '47161FDJH00A8L',
      flavor: 'magisk',
      appId: 'a'.repeat(64),
      grant: 'w'.repeat(64),
    });
    expect(typeof patchRequest?.expectedRevision).toBe('number');
    await acceptInteraction();
    expect(await screen.findByText('patched boot with magisk')).toBeVisible();
    const patchedSnapshot = dispatchEvent.mock.calls
      .map(([event]) => (event as CustomEvent<{ event?: string; payload?: HostSnapshot }>).detail)
      .find((detail) => detail?.event === 'snapshot' && detail.payload?.boot?.patched === true);
    expect(patchedSnapshot?.payload?.boot).toMatchObject({
      image: 'boot.img',
      flavor: 'boot',
      patched: true,
    });

    await user.click(screen.getByRole('radio', { name: /APatch/i }));
    await user.click(patchButton);
    const apatchDialog = await screen.findByRole('dialog', { name: 'APatch' });
    const apatchField = within(apatchDialog).getByLabelText('APatch');
    await user.type(apatchField, 'correct-horse');
    await user.click(within(apatchDialog).getByRole('button', { name: 'Continue' }));
    expect(screen.queryByDisplayValue('correct-horse')).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain('correct-horse');
    await acceptInteraction();
    expect(await screen.findByText('patched boot with apatch')).toBeVisible();

    const apatchRequests = postMessage.mock.calls
      .map(([raw]) => JSON.parse(raw) as BridgeRequest);
    expect(apatchRequests.find((request) => request.command === 'secret.issue' && request.payload.purpose === 'apatch.superkey')?.payload).toEqual({
      purpose: 'apatch.superkey',
      secret: 'correct-horse',
    });
    expect(apatchRequests.find((request) => request.command === 'boot.patch' && request.payload.flavor === 'apatch')?.payload).toEqual({
      serial: '47161FDJH00A8L',
      flavor: 'apatch',
      appId: 'c'.repeat(64),
      grant: 'w'.repeat(64),
      secretGrant: 's'.repeat(64),
    });
    expect(postMessage.mock.calls.map(([raw]) => raw).filter((raw) => raw.includes('correct-horse'))).toHaveLength(1);

    await user.click(within(appsCard).getAllByRole('button', { name: 'Install app' })[0]);
    await screen.findByRole('alertdialog');
    expect(appsRefresh).toBeDisabled();
    await acceptInteraction();
    expect(await screen.findByText('installed Magisk stable')).toBeVisible();

    const modulesCard = screen.getByText('Magisk Modules').closest('.card') as HTMLElement;
    const modulesRefresh = within(modulesCard).getByRole('button', { name: 'Refresh' });
    await user.click(modulesRefresh);
    const moduleName = await within(modulesCard).findByText('play_integrity_fix');
    const moduleRow = moduleName.closest('[role="listitem"]') as HTMLElement;

    for (const action of ['Enable', 'Disable'] as const) {
      await user.click(within(moduleRow).getByRole('button', { name: action }));
      await screen.findByRole('alertdialog');
      expect(modulesRefresh).toBeDisabled();
      await acceptInteraction();
      expect(await screen.findByText(`${action.toLowerCase()} Magisk module play_integrity_fix`)).toBeVisible();
    }

    await user.click(within(moduleRow).getByRole('button', { name: 'Remove' }));
    await screen.findByRole('alertdialog');
    await acceptInteraction();
    await waitFor(() => expect(within(modulesCard).queryByText('play_integrity_fix')).not.toBeInTheDocument());

    await user.click(within(modulesCard).getByRole('button', { name: 'Install module ZIP' }));
    await screen.findByRole('alertdialog');
    await acceptInteraction();
    expect(await within(modulesCard).findByText('mock_module')).toBeVisible();

    const rootRequests = postMessage.mock.calls
      .map(([raw]) => JSON.parse(raw) as BridgeRequest)
      .filter((request) => request.command.startsWith('root.'));
    expect(rootRequests.find((request) => request.command === 'root.apps.list')?.payload).toEqual({});
    expect(rootRequests.find((request) => request.command === 'root.apps.install')?.payload).toEqual({
      serial: '47161FDJH00A8L',
      appId: 'a'.repeat(64),
    });
    expect(rootRequests.find((request) => request.command === 'root.modules.list')?.payload).toEqual({
      serial: '47161FDJH00A8L',
    });
    for (const action of ['enable', 'disable', 'remove'] as const) {
      expect(rootRequests.find((request) => request.command === 'root.modules.action' && request.payload.action === action)?.payload).toEqual({
        serial: '47161FDJH00A8L',
        action,
        moduleId: 'play_integrity_fix',
      });
    }
    expect(rootRequests.find((request) => request.command === 'root.modules.action' && request.payload.action === 'install')?.payload).toEqual({
      serial: '47161FDJH00A8L',
      action: 'install',
      grant: 'g'.repeat(64),
    });
  });

  it('runs the five-step wizard with one explicit target and destructive confirmation', async () => {
    const user = userEvent.setup();
    const { container } = render(<App />);
    const navigation = within(await screen.findByRole('navigation', { name: 'Tasks' }));
    await user.click(navigation.getByRole('button', { name: 'Flash' }));
    expect(await screen.findByRole('heading', { name: 'Devices' })).toBeVisible();

    await user.click(screen.getByLabelText(/Pixel 8 Pro/i));
    await waitFor(() => expect(screen.getByLabelText(/Pixel 8 Pro/i)).toBeChecked());
    expect(await screen.findByText(/1 selected/i)).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('heading', { name: 'Firmware' })).toBeVisible();
    await user.click(screen.getByLabelText(/Pixel 8 Pro Quarterly Beta/i));
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('heading', { name: 'Options' })).toBeVisible();

    await user.click(screen.getByLabelText(/Clean install/i));
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('heading', { name: 'Plan' })).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Prepare review' }));
    expect(await screen.findByRole('heading', { name: 'Review' })).toBeVisible();
    expect(screen.getByText('Exact backend plan')).toBeVisible();
    const exactCommands = Array.from(container.querySelectorAll('.exact-plan__commands code')).map((node) => node.textContent ?? '');
    expect(exactCommands).toContainEqual(expect.stringMatching(/fastboot\.exe.*-s.*4B281FDH2003L7.*update/i));
    expect(screen.queryByText(/2 target devices/i)).not.toBeInTheDocument();
    const start = screen.getByRole('button', { name: 'Start flash' });
    expect(start).toBeDisabled();
    const confirmation = screen.getByPlaceholderText('WIPE 4B281FDH2003L7 husky');
    await user.type(confirmation, 'WIPE 4B281FDH2003L7 husky');
    expect(start).toBeEnabled();
    await user.click(start);
    const dialog = await screen.findByRole('alertdialog');
    await waitFor(() => expect(within(dialog).getByRole('button', { name: 'Cancel' })).toHaveFocus());
    await user.click(within(dialog).getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(await screen.findByText('Flash in progress')).toBeVisible();
    expect(await screen.findByText('Flash completed successfully', {}, { timeout: 3000 })).toBeVisible();
  });

  it('reveals bounded advanced tools only in Expert Mode', async () => {
    const user = userEvent.setup();
    render(<App />);
    const navigation = within(await screen.findByRole('navigation', { name: 'Tasks' }));
    await user.click(navigation.getByRole('button', { name: 'Tools' }));

    expect(await screen.findByRole('button', { name: /Recovery tools/i })).toBeEnabled();
    expect(screen.queryByRole('button', { name: /Logcat/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Partition manager/i })).not.toBeInTheDocument();

    await user.click(screen.getByRole('checkbox', { name: /Expert Mode/i }));
    expect(await screen.findByRole('button', { name: /Logcat/i })).toBeEnabled();
    expect(screen.getByRole('button', { name: /Partition manager/i })).toBeDisabled();
    expect(screen.getByRole('button', { name: /Bootloader console/i })).toBeEnabled();
    expect(screen.getByRole('button', { name: /ADB Shell/i })).toBeDisabled();
    expect(screen.getByRole('button', { name: /Integrity check/i })).toBeDisabled();
  });

  it('emits exact bounded Tools payloads and clears the Wi-Fi pairing secret', async () => {
    const user = userEvent.setup();
    const postMessage = vi.spyOn(developmentBridge!, 'postMessage');
    render(<App />);
    const navigation = within(await screen.findByRole('navigation', { name: 'Tasks' }));
    await user.click(navigation.getByRole('button', { name: 'Tools' }));
    expect(await screen.findByRole('heading', { name: 'Device tools' })).toBeVisible();
    postMessage.mockClear();

    await user.click(screen.getByRole('button', { name: /Scrcpy/i }));
    expect(await screen.findByText('scrcpy launched for the selected device')).toBeVisible();

    await user.click(screen.getByRole('button', { name: /Wireless ADB/i }));
    const wifiPanel = document.querySelector('.tool-workspace') as HTMLElement;
    await user.selectOptions(within(wifiPanel).getByLabelText('Action'), 'pair');
    expect(within(wifiPanel).getByText('Six-digit pairing code')).toBeVisible();
    await user.click(within(wifiPanel).getByRole('button', { name: 'Apply changes' }));
    const secretDialog = await screen.findByRole('dialog', { name: 'Six-digit pairing code' });
    const pairingField = within(secretDialog).getByLabelText('Six-digit pairing code');
    await user.type(pairingField, '123456');
    await user.click(within(secretDialog).getByRole('button', { name: 'Continue' }));
    expect(await screen.findAllByText('ADB Wi-Fi pair succeeded')).not.toHaveLength(0);
    expect(screen.queryByDisplayValue('123456')).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain('123456');
    await user.click(within(wifiPanel).getByRole('button', { name: 'Close' }));

    await user.click(screen.getByRole('checkbox', { name: /Expert Mode/i }));
    await user.click(await screen.findByRole('button', { name: /Logcat/i }));
    const logcatPanel = document.querySelector('.tool-workspace') as HTMLElement;
    await user.click(within(logcatPanel).getByRole('button', { name: 'Collect logs' }));
    expect(await within(logcatPanel).findByText(/PixelFlasher test ready/)).toBeVisible();
    await user.click(within(logcatPanel).getByRole('button', { name: 'Close' }));

    await user.click(screen.getByRole('button', { name: /Push files/i }));
    const pushPanel = document.querySelector('.tool-workspace') as HTMLElement;
    await user.click(within(pushPanel).getByRole('button', { name: 'Choose files' }));
    const pushDialog = await screen.findByRole('alertdialog');
    expect(within(pushDialog).getByText(/Push selected files/i)).toBeVisible();
    await user.click(within(pushDialog).getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(await within(pushPanel).findByText('Pushed 2 files.')).toBeVisible();
    await user.click(within(pushPanel).getByRole('button', { name: 'Close' }));

    await user.click(screen.getByRole('button', { name: /Support package/i }));
    expect(await screen.findByText('Created redacted support package.')).toBeVisible();

    const rawRequests = postMessage.mock.calls.map(([raw]) => raw);
    const requests = rawRequests.map((raw) => JSON.parse(raw) as BridgeRequest);
    expect(requests.find((request) => request.command === 'tools.scrcpy')?.payload).toEqual({
      serial: '47161FDJH00A8L',
    });
    expect(requests.find((request) => request.command === 'tools.wifi')?.payload).toEqual({
      serial: '47161FDJH00A8L',
      action: 'pair',
      host: '192.168.1.42',
      port: 5555,
      secretGrant: 's'.repeat(64),
    });
    expect(rawRequests.filter((raw) => raw.includes('123456'))).toHaveLength(1);
    expect(requests.find((request) => request.command === 'secret.issue')?.payload).toEqual({
      purpose: 'wifi.pairingCode',
      secret: '123456',
    });
    expect(requests.find((request) => request.command === 'tools.logcat')?.payload).toEqual({
      serial: '47161FDJH00A8L',
      buffers: ['main'],
      format: 'threadtime',
      maxLines: 500,
      timeoutSeconds: 30,
    });
    expect(requests.find((request) => request.command === 'native.pickFiles')?.payload).toEqual({
      purpose: 'tools.pushFiles.sources',
      title: 'Choose files',
    });
    expect(requests.find((request) => request.command === 'tools.pushFiles')?.payload).toEqual({
      serial: '47161FDJH00A8L',
      grants: ['g'.repeat(64), 'h'.repeat(64)],
      destination: '/sdcard/Download/',
    });
    expect(requests.find((request) => request.command === 'interaction.respond')?.payload).toMatchObject({
      decision: 'accepted',
    });
    expect(requests.find((request) => request.command === 'native.saveFile')?.payload).toEqual({
      title: 'Support package',
      purpose: 'support.create.destination',
      defaultName: 'PixelFlasher-support.zip',
      filters: [{ label: 'Support package', extensions: ['zip'] }],
    });
    expect(requests.find((request) => request.command === 'support.create')?.payload).toEqual({
      grant: 'w'.repeat(64),
      includeConfig: true,
      includeLogs: true,
      includeState: true,
      includeSystemInfo: true,
    });
  });

  it('enables partitions only for Fastboot and requires the exact ERASE challenge', async () => {
    const user = userEvent.setup();
    const postMessage = vi.spyOn(developmentBridge!, 'postMessage');
    render(<App />);
    const navigation = within(await screen.findByRole('navigation', { name: 'Tasks' }));
    await user.click(navigation.getByRole('button', { name: 'Device' }));
    expect(await screen.findByRole('heading', { name: 'Device workspace' })).toBeVisible();
    await user.click(screen.getByLabelText(/Pixel 8a/i));
    expect(await screen.findByText('0 selected for batch actions')).toBeVisible();
    await user.click(screen.getByLabelText(/Pixel 8 Pro/i));
    expect(await screen.findByText('1 selected for batch actions')).toBeVisible();

    await user.click(navigation.getByRole('button', { name: 'Tools' }));
    await user.click(screen.getByRole('checkbox', { name: /Expert Mode/i }));
    const partitionCard = await screen.findByRole('button', { name: /Partition manager/i });
    expect(partitionCard).toBeEnabled();
    postMessage.mockClear();
    await user.click(partitionCard);
    const partitionPanel = document.querySelector('.tool-workspace') as HTMLElement;
    await user.click(within(partitionPanel).getByRole('button', { name: 'Refresh' }));
    expect(await within(partitionPanel).findByRole('option', { name: 'boot_a' })).toBeInTheDocument();
    await waitFor(() => expect(within(partitionPanel).getByLabelText('Selected partition')).toHaveValue('boot_a'));

    await user.click(within(partitionPanel).getByRole('button', { name: 'Erase partition' }));
    const reinforced = await screen.findByRole('alertdialog');
    const requiredText = 'ERASE 4B281FDH2003L7 boot_a';
    const field = within(reinforced).getByPlaceholderText(requiredText);
    const continueButton = within(reinforced).getByRole('button', { name: 'Continue' });
    expect(continueButton).toBeDisabled();
    await user.type(field, requiredText);
    expect(continueButton).toBeEnabled();
    await user.click(continueButton);

    await waitFor(() => {
      const confirmation = screen.getByRole('alertdialog');
      expect(within(confirmation).queryByRole('textbox')).not.toBeInTheDocument();
    });
    const confirmation = screen.getByRole('alertdialog');
    await user.click(within(confirmation).getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(await screen.findAllByText('Erased boot_a.')).not.toHaveLength(0);

    const requests = postMessage.mock.calls.map(([raw]) => JSON.parse(raw) as BridgeRequest);
    expect(requests.find((request) => request.command === 'partitions.list')?.payload).toEqual({
      serial: '4B281FDH2003L7',
    });
    const eraseRequests = requests.filter((request) => request.command === 'partitions.erase');
    expect(eraseRequests).toHaveLength(2);
    expect(eraseRequests[0].payload).toEqual({
      serial: '4B281FDH2003L7',
      partition: 'boot_a',
    });
    expect(eraseRequests[1].payload).toEqual({
      serial: '4B281FDH2003L7',
      partition: 'boot_a',
      confirmationText: requiredText,
    });
    expect(requests.find((request) => request.command === 'interaction.respond')?.payload).toMatchObject({
      decision: 'accepted',
    });
  });

  it('has no automated accessibility violations in the bounded Tools workspace', async () => {
    const user = userEvent.setup();
    const { container } = render(<App />);
    const navigation = within(await screen.findByRole('navigation', { name: 'Tasks' }));
    await user.click(navigation.getByRole('button', { name: 'Tools' }));
    await user.click(screen.getByRole('checkbox', { name: /Expert Mode/i }));
    await user.click(await screen.findByRole('button', { name: /Wireless ADB/i }));
    expect(await screen.findByRole('combobox', { name: 'Action' })).toBeVisible();

    const results = await axe.run(container, {
      rules: {
        'color-contrast': { enabled: false },
      },
    });
    expect(results.violations).toEqual([]);
  });

  it('has no automated accessibility violations on the primary dashboard', async () => {
    const { container } = render(<App />);
    await screen.findByRole('heading', { name: 'Modern UI' });
    const results = await axe.run(container, {
      rules: {
        'color-contrast': { enabled: false },
      },
    });
    expect(results.violations).toEqual([]);
  });

  it('loads gettext-backed translations when the language changes', async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole('heading', { name: 'Modern UI' });
    await new Promise((resolve) => window.setTimeout(resolve, 80));
    const language = screen.getAllByRole('combobox')[0];
    await user.selectOptions(language, 'es');
    expect(await screen.findByText('Configuración')).toBeVisible();
  });

  it('uses localStorage only as the development mock fallback', async () => {
    window.localStorage.setItem('pf.theme', JSON.stringify('light'));
    window.localStorage.setItem('pf.locale', JSON.stringify('it'));
    window.localStorage.setItem('pf.highContrast', JSON.stringify(true));
    window.localStorage.setItem('pf.reducedMotion', JSON.stringify(true));
    window.localStorage.setItem('pf.zoom', JSON.stringify(80));
    const postMessage = vi.spyOn(developmentBridge!, 'postMessage');

    render(<App />);
    await screen.findByRole('heading', { name: 'Modern UI' });
    await waitFor(() => {
      expect(document.documentElement.dataset.theme).toBe('light');
      expect(document.documentElement.dataset.contrast).toBe('high');
      expect(document.documentElement.dataset.motion).toBe('reduced');
      expect(document.documentElement.style.fontSize).toBe('80%');
      expect(document.documentElement.lang).toBe('it');
    });
    const commands = postMessage.mock.calls.map(([raw]) => (JSON.parse(raw) as BridgeRequest).command);
    expect(commands).not.toContain('settings.get');
    expect(commands).not.toContain('settings.update');
  });

  it('loads real host preferences without writing them back on startup', async () => {
    await new Promise((resolve) => window.setTimeout(resolve, 80));
    const requests = installPreferencesHost({
      ...hostPreferences,
      theme: 'light',
      locale: 'fr',
      highContrast: true,
      reducedMotion: true,
      zoom: 200,
    });

    render(<App />);
    await waitFor(() => {
      expect(document.documentElement.dataset.theme).toBe('light');
      expect(document.documentElement.dataset.contrast).toBe('high');
      expect(document.documentElement.dataset.motion).toBe('reduced');
      expect(document.documentElement.style.fontSize).toBe('200%');
      expect(document.documentElement.lang).toBe('fr');
    });
    expect(requests.some((request) => request.command === 'settings.get')).toBe(true);
    expect(requests.some((request) => request.command === 'settings.update')).toBe(false);
    expect(window.localStorage.length).toBe(0);
  });

  it('persists preference changes through the real host and only applies confirmed success', async () => {
    const user = userEvent.setup();
    await new Promise((resolve) => window.setTimeout(resolve, 80));
    const requests = installPreferencesHost(hostPreferences);
    render(<App />);
    await waitFor(() => expect(requests.some((request) => request.command === 'settings.get')).toBe(true));

    await user.click(screen.getAllByRole('button', { name: 'Light' })[0]);
    await waitFor(() => expect(document.documentElement.dataset.theme).toBe('light'));
    expect(await screen.findByText('Preferences saved.')).toBeVisible();
    expect(requests.find((request) => request.command === 'settings.update')).toMatchObject({
      payload: { theme: 'light' },
      expectedRevision: 7,
    });
    expect(window.localStorage.length).toBe(0);
  });

  it('does not apply or announce a failed host preference update as success', async () => {
    const user = userEvent.setup();
    await new Promise((resolve) => window.setTimeout(resolve, 80));
    const requests = installPreferencesHost(hostPreferences, { failUpdate: true });
    render(<App />);
    await waitFor(() => expect(requests.some((request) => request.command === 'settings.get')).toBe(true));

    await user.click(screen.getAllByRole('button', { name: 'Light' })[0]);
    expect(await screen.findByText('Disk full.')).toBeVisible();
    expect(document.documentElement.dataset.theme).toBe('dark');
    expect(screen.queryByText('Preferences saved.')).not.toBeInTheDocument();
  });

  it('never exposes preview inventories through the real host bridge', async () => {
    const previousBridge = window.pixelflasher;
    window.pixelflasher = {
      postMessage(raw) {
        const request = JSON.parse(raw) as { requestId: string; command: string };
        queueMicrotask(() => window.dispatchEvent(new CustomEvent('pixelflasher:message', {
          detail: {
            version: 2,
            requestId: request.requestId,
            ok: true,
            result: request.command === 'settings.get'
              ? {
                  status: 'SUCCESS',
                  value: { preferences: hostPreferences },
                  revision: 0,
                }
              : {
                  revision: 0,
                  devices: [],
                  selected_serials: [],
                  firmware: null,
                  toolchain: { adb: '', fastboot: '', ready: false },
                },
          },
        })));
      },
    };
    // Let any delayed mock events from the preceding test drain before this
    // component subscribes to the replacement real-host bridge.
    await new Promise((resolve) => window.setTimeout(resolve, 80));

    const user = userEvent.setup();
    render(<App />);
    expect(await screen.findByText('Platform Tools need attention')).toBeVisible();
    expect(screen.queryByText('Pixel 8a')).not.toBeInTheDocument();
    expect(screen.queryByText('Selected firmware')).not.toBeInTheDocument();
    expect(screen.queryByText('Verified Boot active')).not.toBeInTheDocument();
    const navigation = within(screen.getByRole('navigation', { name: 'Tasks' }));
    await user.click(navigation.getByRole('button', { name: 'Firmware' }));
    expect(await screen.findByRole('heading', { name: 'Firmware library' })).toBeVisible();
    expect(screen.queryByText('Pixel 8a Factory Image')).not.toBeInTheDocument();
    await user.click(navigation.getByRole('button', { name: 'Root' }));
    expect(await screen.findByRole('heading', { name: 'Root workspace' })).toBeVisible();
    expect(screen.queryByText('Magisk')).not.toBeInTheDocument();
    await user.click(navigation.getByRole('button', { name: 'Apps' }));
    expect(await screen.findByRole('heading', { name: 'Application manager' })).toBeVisible();
    expect(screen.queryByText('Pixel Launcher')).not.toBeInTheDocument();
    await user.click(navigation.getByRole('button', { name: 'Backups' }));
    expect(await screen.findByRole('heading', { name: 'Backups' })).toBeVisible();
    expect(screen.queryByText('2025-02-13 21:42')).not.toBeInTheDocument();
    await user.click(navigation.getByRole('button', { name: 'Tools' }));
    expect(await screen.findByRole('heading', { name: 'Device tools' })).toBeVisible();
    const toolCards = screen.getAllByRole('button').filter((button) => button.classList.contains('tool-card'));
    expect(screen.getByRole('button', { name: /Support package/i })).toBeEnabled();
    for (const tool of toolCards.filter((button) => !button.textContent?.includes('Support package'))) {
      expect(tool).toBeDisabled();
    }
    window.pixelflasher = previousBridge;
  });
});
