import { render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { BridgeCommand } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import { RootPage } from '../pages/Pages';
import { patchAcceptsPartition } from '../pages/root/RootPage';
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
  // Measured on a Pixel 9 Pro XL: its boot image declares a zero-length ramdisk
  // and init_boot carries the whole 2670961-byte one. Every provider rewrites a
  // ramdisk, so blocking init_boot by flavor aimed the KernelSU family at an
  // image with nothing to patch. It patched, flashed and booted with no root.
  it('accepts init_boot for every flavor, which is the modern Pixel layout', () => {
    expect(patchAcceptsPartition('init_boot')).toBe(true);
  });

  it('accepts boot, which is where older devices keep the ramdisk', () => {
    expect(patchAcceptsPartition('boot')).toBe(true);
  });

  it('accepts an unset partition, which the backend defaults to boot', () => {
    expect(patchAcceptsPartition('')).toBe(true);
  });

  it('refuses a partition no patcher handles', () => {
    for (const partition of ['vendor_boot', 'recovery', 'system', 'dtbo']) {
      expect(patchAcceptsPartition(partition)).toBe(false);
    }
  });
});
