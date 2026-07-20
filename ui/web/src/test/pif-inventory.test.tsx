import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import axe from 'axe-core';
import { describe, expect, it, vi } from 'vitest';
import type { BridgeCommand } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import { RootPage } from '../pages/Pages';

const specs = [
  ['pif.custom_json', 'playintegrityfix', 'json'],
  ['pif.custom_prop', 'playintegrityfix', 'prop'],
  ['pif.module_json', 'playintegrityfix', 'json'],
  ['pif.legacy_json', 'playintegrityfix', 'json'],
  ['pif.app_replace', 'playintegrityfix', 'list'],
  ['pif.scripts_only', 'playintegrityfix', 'marker'],
  ['tricky.spoof', 'tricky_store', 'prop'],
  ['tricky.target', 'tricky_store', 'list'],
  ['tricky.security_patch', 'tricky_store', 'text'],
  ['tricky.tee', 'tricky_store', 'text'],
  ['targeted.targets', 'targetedfix', 'list'],
] as const;

function inventory() {
  const profiles = specs.map(([id, module, format], index) => ({
    id, module, format, present: index === 0, size: index === 0 ? 512 : 0,
    sha256: index === 0 ? 'a'.repeat(64) : null,
  }));
  return {
    schemaVersion: 1, rootAccess: 'verified', bounded: true, count: profiles.length, profiles,
    targetCount: 1,
    targets: [{ packageName: 'com.google.android.gms', format: 'json', present: true, size: 64, sha256: 'b'.repeat(64) }],
  };
}

function renderRoot(onCommand: (command: BridgeCommand, payload?: Record<string, unknown>) => Promise<{ result: Record<string, unknown> } | null>) {
  const snapshot = structuredClone(demoSnapshot);
  snapshot.devices[0].mode = 'adb';
  snapshot.devices[0].rooted = true;
  const rendered = render(
    <I18nProvider locale="en">
      <RootPage snapshot={snapshot} selectedSerials={[snapshot.devices[0].serial]} onSelectionChange={vi.fn()} onCommand={onCommand} />
    </I18nProvider>,
  );
  return { ...rendered, snapshot };
}

describe('PIF and TargetedFix inventory', () => {
  it('uses the closed read command and renders metadata without routes or keybox data', async () => {
    const user = userEvent.setup();
    const onCommand = vi.fn(async () => ({ result: { status: 'SUCCESS', value: inventory() } }));
    const { snapshot } = renderRoot(onCommand);
    const card = screen.getByText('PIF and TargetedFix profiles').closest('.card');
    if (!card) throw new Error('PIF inventory card missing');

    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Refresh' }));

    expect(onCommand).toHaveBeenCalledWith('root.pif.inventory', { serial: snapshot.devices[0].serial });
    expect(await within(card as HTMLElement).findByText('pif.custom_json')).toBeVisible();
    expect(within(card as HTMLElement).getByText('com.google.android.gms')).toBeVisible();
    expect(card.textContent).not.toContain('/data/adb');
    expect(card.textContent).not.toContain('BEGIN CERTIFICATE');
  });

  it('fails closed on a reordered receipt and remains accessible', async () => {
    const user = userEvent.setup();
    const hostile = inventory();
    hostile.profiles.reverse();
    const onCommand = vi.fn(async () => ({ result: { status: 'SUCCESS', value: hostile } }));
    const { container } = renderRoot(onCommand);
    const card = screen.getByText('PIF and TargetedFix profiles').closest('.card');
    if (!card) throw new Error('PIF inventory card missing');
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Refresh' }));
    expect(await within(card as HTMLElement).findByRole('alert')).toHaveTextContent('incomplete or unsafe');
    expect((await axe.run(container)).violations).toEqual([]);
  });
});
