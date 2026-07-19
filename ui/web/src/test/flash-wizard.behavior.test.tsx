import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { FlashWizard, type FlashPlan, type FlashPreview } from '../components/FlashWizard';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';

const previewWithoutMutation: FlashPreview = {
  revision: 18,
  destructive: false,
  requiredConfirmation: '',
  label: 'Verified dry run',
  targetSerial: demoSnapshot.devices[1].serial,
  targetSerials: [demoSnapshot.devices[1].serial],
  expectedDeviceState: 'fastboot',
  dataBehavior: 'preserve',
  partitions: [],
  slots: [],
  commands: [],
};

function wizard(
  overrides: Partial<React.ComponentProps<typeof FlashWizard>> = {},
) {
  const props: React.ComponentProps<typeof FlashWizard> = {
    devices: demoSnapshot.devices,
    selectedSerials: [demoSnapshot.devices[1].serial],
    activeFirmware: demoSnapshot.firmware,
    expertMode: true,
    operation: null,
    onSelectionChange: vi.fn(async () => undefined),
    onFirmwareChange: vi.fn(async () => undefined),
    onPrepare: vi.fn(async () => previewWithoutMutation),
    onStart: vi.fn(async () => undefined),
    ...overrides,
  };
  return {
    props,
    ...render(<I18nProvider locale="en"><FlashWizard {...props} /></I18nProvider>),
  };
}

beforeEach(() => {
  window.pixelflasher = { postMessage: vi.fn() };
});

describe('five-step flash planning edge behavior', () => {
  it('builds an expert dry-run plan and keeps failed/cancelled outcomes distinct', async () => {
    const user = userEvent.setup();
    const onPrepare = vi.fn(async (plan: FlashPlan) => ({
      ...previewWithoutMutation,
      targetSerial: plan.serials[0],
      targetSerials: [...plan.serials],
    }));
    const onStart = vi.fn(async () => { throw 'backend unavailable'; });
    const { props, rerender } = wizard({ onPrepare, onStart });

    await user.click(screen.getByRole('button', { name: 'Continue' }));
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('heading', { name: 'Options' })).toBeVisible();

    await user.click(screen.getByRole('radio', { name: /Clean install/ }));
    await user.click(screen.getByRole('radio', { name: /Both slots/ }));
    expect(screen.getByRole('checkbox', { name: 'Verify package checksums before flashing' })).toBeChecked();
    expect(screen.getByRole('checkbox', { name: 'Verify package checksums before flashing' })).toBeDisabled();
    expect(screen.getByRole('checkbox', { name: /^Allow firmware downgrade/ })).toBeDisabled();
    for (const label of [
      'Disable dm-verity',
      'Disable Android Verified Boot verification',
      'Force flash when host compatibility checks warn',
      'Do not reboot after flashing',
      'Boot a patched image for temporary root',
      'Dry run only — do not write partitions',
    ]) {
      await user.click(screen.getByRole('checkbox', { name: label }));
    }

    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByText('Simulate partition writes')).toBeVisible();
    expect(screen.getByText('Reboot after verification')).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Prepare review' }));
    expect(await screen.findByText('Verified dry run')).toBeVisible();
    expect(screen.getAllByText('—').length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText('Dry run — no writes')).toHaveClass('badge--accent');
    expect(screen.getByText('Checksum verification')).toBeVisible();
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();

    expect(onPrepare).toHaveBeenCalledWith(expect.objectContaining({
      mode: 'wipe', slotTarget: 'both', verify: true, disableVerity: true,
      disableVerification: true, force: true, noReboot: false, downgrade: false,
      temporaryRoot: true, dryRun: true,
    }));
    await user.click(screen.getByRole('button', { name: 'Run simulation' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not complete the request');

    rerender(<I18nProvider locale="en"><FlashWizard {...props} operation={{ status: 'failed', detail: 'Postcondition mismatch' }} /></I18nProvider>);
    expect(screen.getByText('Flash failed — review the operation log')).toBeVisible();
    expect(screen.getByRole('progressbar', { name: 'Postcondition mismatch' })).toHaveAttribute('aria-valuenow', '0');
    rerender(<I18nProvider locale="en"><FlashWizard {...props} operation={{ status: 'cancelled', progress: 35 }} /></I18nProvider>);
    expect(screen.getByText('Flash was cancelled')).toBeVisible();
  });

  it('preserves multi-selection, resets OTA-incompatible options and recovers from preparation errors', async () => {
    const user = userEvent.setup();
    const onSelectionChange = vi.fn(async () => undefined);
    const onFirmwareChange = vi.fn()
      .mockRejectedValueOnce(new Error('Firmware verification failed.'))
      .mockResolvedValue(undefined);
    const onPrepare = vi.fn()
      .mockRejectedValueOnce(new Error('Device changed before planning.'))
      .mockResolvedValue(previewWithoutMutation);
    const { props, rerender } = wizard({
      selectedSerials: demoSnapshot.devices.slice(0, 2).map((device) => device.serial),
      onSelectionChange,
      onFirmwareChange,
      onPrepare,
    });
    expect(screen.getByLabelText(new RegExp(demoSnapshot.devices[0].name, 'i'))).toBeChecked();
    expect(screen.getByLabelText(new RegExp(demoSnapshot.devices[1].name, 'i'))).toBeChecked();
    expect(screen.getByText('2 selected')).toBeVisible();
    expect(onSelectionChange).not.toHaveBeenCalled();

    rerender(<I18nProvider locale="en"><FlashWizard {...props} selectedSerials={[demoSnapshot.devices[0].serial]} /></I18nProvider>);
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('heading', { name: 'Firmware' })).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('heading', { name: 'Options' })).toBeVisible();

    await user.click(screen.getByRole('checkbox', { name: 'Disable dm-verity' }));
    await user.click(screen.getByRole('checkbox', { name: 'Force flash when host compatibility checks warn' }));
    await user.click(screen.getByRole('checkbox', { name: 'Allow firmware downgrade' }));
    await user.click(screen.getByRole('checkbox', { name: 'Boot a patched image for temporary root' }));
    await user.click(screen.getByRole('radio', { name: /OTA sideload/ }));
    await waitFor(() => {
      expect(screen.getByRole('checkbox', { name: /^Disable dm-verity/ })).not.toBeChecked();
      expect(screen.getByRole('checkbox', { name: /^Disable dm-verity/ })).toBeDisabled();
      expect(screen.getByRole('checkbox', { name: /^Allow firmware downgrade/ })).toBeDisabled();
    });

    rerender(<I18nProvider locale="en"><FlashWizard {...props} selectedSerials={[demoSnapshot.devices[0].serial]} expertMode={false} /></I18nProvider>);
    expect(screen.queryByRole('radio', { name: /Both slots/ })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    await user.click(screen.getByRole('button', { name: 'Prepare review' }));
    expect(screen.getByRole('heading', { name: 'Plan' })).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Prepare review' }));
    expect(await screen.findByRole('heading', { name: 'Review' })).toBeVisible();
  });
});
