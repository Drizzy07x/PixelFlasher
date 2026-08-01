import { render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { BridgeCommand } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import { RootPage } from '../pages/Pages';
import { patchMethodAcceptsPartition } from '../pages/root/RootPage';
import type { DeviceMode } from '../types';

const ADB_REQUIRED = 'Select exactly one device in ADB mode to patch a boot image.';
const BOOT_REQUIRED = 'Select a verified boot image to patch.';
const APPS_REQUIRED = 'Refresh Rooting Apps and choose a compatible verified app.';

function renderRoot(mode: DeviceMode, keepBoot: boolean) {
  const snapshot = structuredClone(demoSnapshot);
  const device = snapshot.devices[0];
  device.mode = mode;
  snapshot.selectedSerials = [device.serial];
  if (!keepBoot) snapshot.boot = null;
  const onCommand = vi.fn(async (command: BridgeCommand) => {
    if (command === 'boot.inventory') {
      return { result: { value: { boots: [], selectedBootId: null, revision: 4 } } };
    }
    return { result: { value: {} } };
  });
  render(
    <I18nProvider locale="en">
      <RootPage
        snapshot={snapshot}
        selectedSerials={snapshot.selectedSerials}
        onSelectionChange={vi.fn()}
        onCommand={onCommand}
      />
    </I18nProvider>,
  );
}

describe('the patch footer names the condition that actually disables the button', () => {
  it('tells a fastboot-mode user to switch to ADB instead of blaming the app catalog', async () => {
    renderRoot('fastboot', true);

    await waitFor(() => expect(screen.getByText(ADB_REQUIRED)).toBeTruthy());
    expect(screen.queryByText(APPS_REQUIRED)).toBeNull();
  });

  it('asks for a boot image when the device is ready but nothing is selected', async () => {
    renderRoot('adb', false);

    await waitFor(() => expect(screen.getByText(BOOT_REQUIRED)).toBeTruthy());
    expect(screen.queryByText(ADB_REQUIRED)).toBeNull();
    expect(screen.queryByText(APPS_REQUIRED)).toBeNull();
  });
});

describe('the partition rule matches BootPatchService', () => {
  // Reported from a Pixel 9 Pro XL: selecting the init_boot image with KernelSU
  // let the operation start and fail with boot_partition_incompatible.
  it('refuses every non-Magisk flavor on an init_boot image', () => {
    for (const method of ['kernelsu', 'kernelsu-next', 'apatch', 'sukisu', 'wild-ksu', 'legacy']) {
      expect(patchMethodAcceptsPartition(method, 'init_boot')).toBe(false);
    }
  });

  it('accepts every flavor on a boot image', () => {
    for (const method of ['magisk', 'kernelsu', 'apatch', 'sukisu']) {
      expect(patchMethodAcceptsPartition(method, 'boot')).toBe(true);
    }
  });

  it('lets Magisk patch init_boot, which is the modern Pixel layout', () => {
    expect(patchMethodAcceptsPartition('magisk', 'init_boot')).toBe(true);
  });

  it('treats an unknown partition as incompatible for kernel-replacing flavors', () => {
    expect(patchMethodAcceptsPartition('kernelsu', '')).toBe(false);
    expect(patchMethodAcceptsPartition('magisk', '')).toBe(true);
  });
});
