import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import axe from 'axe-core';
import { describe, expect, it, vi } from 'vitest';
import type { BridgeCommand } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import { RootPage } from '../pages/Pages';

const configKinds = [
  'pif_custom_json', 'pif_custom_prop', 'pif_module_json', 'pif_legacy_json',
  'pif_app_replace', 'pif_scripts_only', 'tricky_spoof', 'tricky_target',
  'tricky_security_patch', 'tricky_tee', 'targeted_targets', 'keybox',
];

function report(codename: string) {
  return {
    schemaVersion: 1,
    redacted: true,
    complete: true,
    device: {
      codename,
      build: 'AP4A.260101.001',
      rootAccess: 'verified',
      testKeys: false,
      overlayVisible: false,
    },
    packages: [
      { id: 'gms', installed: true, version: '25.20.33', versionCode: 252033000 },
      { id: 'play_store', installed: false, version: '', versionCode: 0 },
    ],
    modules: [
      { id: 'playintegrityfix', state: 'enabled' },
      { id: 'tricky_store', state: 'disabled' },
    ],
    configs: configKinds.map((kind) => ({
      kind,
      present: kind === 'pif_custom_json' || kind === 'keybox',
      size: kind === 'pif_custom_json' ? 512 : kind === 'keybox' ? 2048 : 0,
      sha256: kind === 'pif_custom_json' ? 'a'.repeat(64) : null,
    })),
    signals: { targetedFixTargetCount: 2, magiskDenylistCount: 5, droidGuardVmCount: 1 },
    withheld: ['android_ids', 'device_serial', 'keybox_material', 'raw_config_contents', 'raw_logs', 'target_package_names'],
  };
}

function renderRoot(onCommand: (command: BridgeCommand, payload?: Record<string, unknown>) => Promise<{ result: Record<string, unknown>; revision?: number } | null>, rooted = true) {
  const snapshot = structuredClone(demoSnapshot);
  snapshot.devices[0].mode = 'adb';
  snapshot.devices[0].rooted = rooted;
  const rendered = render(
    <I18nProvider locale="en">
      <RootPage
        snapshot={snapshot}
        selectedSerials={[snapshot.devices[0].serial]}
        onSelectionChange={vi.fn()}
        onCommand={onCommand}
      />
    </I18nProvider>,
  );
  return { ...rendered, snapshot };
}

describe('redacted Play Integrity analysis', () => {
  it('requests the closed command and renders only the bounded receipt', async () => {
    const user = userEvent.setup();
    let deviceCodename = '';
    const onCommand = vi.fn(async () => ({
      result: { status: 'SUCCESS', value: report(deviceCodename) },
      revision: demoSnapshot.revision,
    }));
    const { snapshot } = renderRoot(onCommand);
    deviceCodename = snapshot.devices[0].codename;

    const card = screen.getByText('Play Integrity analysis').closest('.card');
    if (!card) throw new Error('Play Integrity analysis card missing');
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Run redacted analysis' }));

    expect(onCommand).toHaveBeenCalledWith('tools.piAnalysis', {
      serial: snapshot.devices[0].serial,
      action: 'analyze',
    });
    expect(await within(card as HTMLElement).findByText('Redacted and complete')).toBeVisible();
    expect(within(card as HTMLElement).getByText('2 root modules')).toBeVisible();
    expect(within(card as HTMLElement).getByText('2 integrity configurations detected')).toBeVisible();
    expect(within(card as HTMLElement).getByText('5')).toBeVisible();
    expect(card.textContent).not.toContain(snapshot.devices[0].serial);
    expect(card.textContent).not.toContain('/data/adb');
    expect(card.textContent).not.toContain('BEGIN CERTIFICATE');
  });

  it('fails closed on an incomplete receipt and disables analysis without root', async () => {
    const user = userEvent.setup();
    const onCommand = vi.fn(async () => ({
      result: { status: 'SUCCESS', value: { ...report('akita'), complete: false } },
      revision: demoSnapshot.revision,
    }));
    renderRoot(onCommand);
    await user.click(screen.getByRole('button', { name: 'Run redacted analysis' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('incomplete or unsafe');
    expect(screen.queryByText('Redacted and complete')).not.toBeInTheDocument();

    const rootless = vi.fn(async () => null);
    renderRoot(rootless, false);
    const buttons = screen.getAllByRole('button', { name: 'Run redacted analysis' });
    expect(buttons.at(-1)).toBeDisabled();
  });

  it('has no detectable accessibility violations', async () => {
    const onCommand = vi.fn(async () => null);
    const { container } = renderRoot(onCommand);
    expect((await axe.run(container)).violations).toEqual([]);
  });
});
