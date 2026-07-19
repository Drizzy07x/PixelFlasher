import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import { FirmwarePage } from '../pages/firmware/FirmwarePage';
import type { SharedPageProps } from '../pages/shared';

function renderPage(onCommand: SharedPageProps['onCommand']) {
  return render(
    <I18nProvider locale="en">
      <FirmwarePage
        snapshot={structuredClone(demoSnapshot)}
        selectedSerials={demoSnapshot.selectedSerials ?? []}
        onSelectionChange={vi.fn()}
        onCommand={onCommand}
      />
    </I18nProvider>,
  );
}

describe('official firmware catalog', () => {
  it('refreshes a closed catalog and downloads only by opaque artifact ID', async () => {
    const user = userEvent.setup();
    const artifactId = 'a'.repeat(32);
    const entry = {
      artifactId,
      device: demoSnapshot.devices[0].codename,
      channel: 'stable',
      kind: 'factory',
      version: 'AP4A.260719.001',
      sha256: 'b'.repeat(64),
      size: 2 * 1024 ** 3,
      license: 'Google Terms',
      provenance: 'Google Pixel official images',
    };
    const onCommand: SharedPageProps['onCommand'] = vi.fn(async (command) => ({
      result: command === 'firmware.catalog.refresh'
        ? { status: 'SUCCESS', value: { count: 1, entries: [entry] } }
        : { status: 'SUCCESS', value: { artifact: entry } },
    }));
    renderPage(onCommand);

    await user.click(screen.getByRole('button', { name: 'Refresh official catalog' }));
    expect(onCommand).toHaveBeenCalledWith('firmware.catalog.refresh', {
      device: demoSnapshot.devices[0].codename.toLowerCase(),
      channel: 'stable',
    });
    expect(await screen.findByText('AP4A.260719.001')).toBeVisible();
    expect(screen.queryByText(/https?:\/\//)).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Download and select' }));
    expect(onCommand).toHaveBeenCalledWith('firmware.download', { artifactId });
  });

  it('fails closed for an open catalog DTO', async () => {
    const user = userEvent.setup();
    const onCommand: SharedPageProps['onCommand'] = vi.fn(async () => ({
      result: {
        status: 'SUCCESS',
        value: {
          count: 1,
          entries: [{ artifactId: 'a'.repeat(32), url: 'https://private.example' }],
        },
      },
    }));
    renderPage(onCommand);

    await user.click(screen.getByRole('button', { name: 'Refresh official catalog' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('could not be verified');
    expect(screen.queryByText('https://private.example')).not.toBeInTheDocument();
  });
});
