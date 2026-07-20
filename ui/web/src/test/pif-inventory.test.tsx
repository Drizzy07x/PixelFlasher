import { fireEvent, render, screen, within } from '@testing-library/react';
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
    const profileLabels = await within(card as HTMLElement).findAllByText('pif.custom_json');
    expect(profileLabels.some((element) => element.tagName === 'STRONG')).toBe(true);
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

  it('requires the serial-bound phrase before deleting a canonical profile', async () => {
    const user = userEvent.setup();
    const onCommand = vi.fn(async (command: BridgeCommand) => ({
      result: command === 'root.pif.inventory'
        ? { status: 'SUCCESS', value: inventory() }
        : { status: 'SUCCESS', value: { action: 'deleteProfile', profileId: 'pif.custom_json' } },
    }));
    const { snapshot } = renderRoot(onCommand);
    const card = screen.getByText('PIF and TargetedFix profiles').closest('.card');
    if (!card) throw new Error('PIF inventory card missing');
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Refresh' }));
    await within(card as HTMLElement).findByRole('button', { name: 'Delete profile' });
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Delete profile' }));

    const confirmation = `DELETE PIF pif.custom_json ${snapshot.devices[0].serial.slice(-6).toUpperCase()}`;
    const run = within(card as HTMLElement).getByRole('button', { name: 'Delete verified profile' });
    expect(run).toBeDisabled();
    await user.type(within(card as HTMLElement).getByLabelText(/Confirm deletion/), confirmation);
    expect(run).toBeEnabled();
    await user.click(run);

    expect(onCommand).toHaveBeenLastCalledWith('tools.pif', {
      serial: snapshot.devices[0].serial,
      action: 'deleteProfile',
      profileId: 'pif.custom_json',
      confirmationText: confirmation,
    });
    expect(within(card as HTMLElement).queryByRole('button', { name: 'Delete profile' })).not.toBeInTheDocument();
  });

  it('imports through an opaque grant and requires remote hash verification metadata', async () => {
    const user = userEvent.setup();
    const onCommand = vi.fn(async (command: BridgeCommand) => {
      if (command === 'native.pickFile') return { result: { value: { data: { grant: 'opaque-pif-grant' } } } };
      return { result: { status: 'SUCCESS', value: { action: 'importProfile', profileId: 'pif.custom_json', sha256: 'c'.repeat(64), size: 512 } } };
    });
    const { snapshot } = renderRoot(onCommand);
    const card = screen.getByText('PIF and TargetedFix profiles').closest('.card');
    if (!card) throw new Error('PIF inventory card missing');
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Import profile' }));
    const phrase = `IMPORT PIF pif.custom_json ${snapshot.devices[0].serial.slice(-6).toUpperCase()}`;
    await user.type(within(card as HTMLElement).getByLabelText(/Confirm import/), phrase);
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Import and verify profile' }));
    expect(onCommand).toHaveBeenNthCalledWith(1, 'native.pickFile', {
      purpose: 'root.pif.import',
      title: 'Import profile',
      filters: [{ label: 'PIF and TargetedFix profiles', extensions: ['json', 'prop', 'txt', 'list'] }],
    });
    expect(onCommand).toHaveBeenLastCalledWith('tools.pif', {
      serial: snapshot.devices[0].serial,
      action: 'importProfile',
      profileId: 'pif.custom_json',
      confirmationText: phrase,
      grant: 'opaque-pif-grant',
    });
  });

  it('adds and deletes TargetedFix packages with serial-bound verified mutations', async () => {
    const user = userEvent.setup();
    const onCommand = vi.fn(async (command: BridgeCommand, payload?: Record<string, unknown>) => ({
      result: command === 'root.pif.inventory'
        ? { status: 'SUCCESS', value: inventory() }
        : { status: 'SUCCESS', value: { action: payload?.action, targetPackage: payload?.targetPackage } },
    }));
    const { snapshot } = renderRoot(onCommand);
    const card = screen.getByText('PIF and TargetedFix profiles').closest('.card');
    if (!card) throw new Error('PIF inventory card missing');
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Refresh' }));

    const packageName = 'com.example.app';
    await user.type(within(card as HTMLElement).getByLabelText('Installed package ID'), packageName);
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Add TargetedFix target' }));
    const addPhrase = `ADD TARGET ${packageName} ${snapshot.devices[0].serial.slice(-6).toUpperCase()}`;
    await user.type(within(card as HTMLElement).getByLabelText(/Confirm TargetedFix change/), addPhrase);
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Add and verify target' }));
    expect(onCommand).toHaveBeenLastCalledWith('tools.pif', {
      serial: snapshot.devices[0].serial,
      action: 'addTarget',
      targetPackage: packageName,
      confirmationText: addPhrase,
    });

    const targetRow = within(card as HTMLElement).getByText(packageName).closest('.root-inventory__row');
    if (!targetRow) throw new Error('Added TargetedFix row missing');
    await user.click(within(targetRow as HTMLElement).getByRole('button', { name: 'Delete target' }));
    const deletePhrase = `DELETE TARGET ${packageName} ${snapshot.devices[0].serial.slice(-6).toUpperCase()}`;
    await user.type(within(card as HTMLElement).getByLabelText(/Confirm TargetedFix change/), deletePhrase);
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Delete and verify target' }));
    expect(onCommand).toHaveBeenLastCalledWith('tools.pif', {
      serial: snapshot.devices[0].serial,
      action: 'deleteTarget',
      targetPackage: packageName,
      confirmationText: deletePhrase,
    });
  });

  it('imports a TargetedFix package profile through a purpose-bound opaque grant', async () => {
    const user = userEvent.setup();
    const packageName = 'com.google.android.gms';
    const onCommand = vi.fn(async (command: BridgeCommand) => {
      if (command === 'root.pif.inventory') return { result: { status: 'SUCCESS', value: inventory() } };
      if (command === 'native.pickFile') return { result: { value: { data: { grant: 'opaque-target-grant' } } } };
      return {
        result: {
          status: 'SUCCESS',
          value: { action: 'importTargetProfile', targetPackage: packageName, targetFormat: 'prop', sha256: 'd'.repeat(64), size: 512 },
        },
      };
    });
    const { snapshot } = renderRoot(onCommand);
    const card = screen.getByText('PIF and TargetedFix profiles').closest('.card');
    if (!card) throw new Error('PIF inventory card missing');
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Refresh' }));
    await user.selectOptions(within(card as HTMLElement).getByLabelText('Target profile format'), 'prop');
    const targetRow = within(card as HTMLElement).getByText(packageName).closest('.root-inventory__row');
    if (!targetRow) throw new Error('TargetedFix row missing');
    await user.click(within(targetRow as HTMLElement).getByRole('button', { name: 'Import target profile' }));
    const phrase = `IMPORT TARGET ${packageName} PROP ${snapshot.devices[0].serial.slice(-6).toUpperCase()}`;
    await user.type(within(card as HTMLElement).getByLabelText(/Confirm profile import/), phrase);
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Import and verify target profile' }));
    expect(onCommand).toHaveBeenNthCalledWith(2, 'native.pickFile', {
      purpose: 'root.pif.target.import',
      title: 'Import target profile',
      filters: [{ label: 'TargetedFix package profile', extensions: ['prop'] }],
    });
    expect(onCommand).toHaveBeenLastCalledWith('tools.pif', {
      serial: snapshot.devices[0].serial,
      action: 'importTargetProfile',
      targetPackage: packageName,
      targetFormat: 'prop',
      confirmationText: phrase,
      grant: 'opaque-target-grant',
    });
  });

  it('requires the serial-bound phrase before cleaning DroidGuard cache', async () => {
    const user = userEvent.setup();
    const onCommand = vi.fn(async () => ({
      result: { status: 'SUCCESS', value: { action: 'cleanupDroidGuard', verified: true } },
    }));
    const { snapshot } = renderRoot(onCommand);
    const card = screen.getByText('PIF and TargetedFix profiles').closest('.card');
    if (!card) throw new Error('PIF inventory card missing');
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Clean DroidGuard cache' }));
    const phrase = `CLEANUP DG ${snapshot.devices[0].serial.slice(-6).toUpperCase()}`;
    const run = within(card as HTMLElement).getByRole('button', { name: 'Clean and verify cache' });
    expect(run).toBeDisabled();
    await user.type(within(card as HTMLElement).getByLabelText(/Confirm DroidGuard cache deletion/), phrase);
    await user.click(run);
    expect(onCommand).toHaveBeenLastCalledWith('tools.pif', {
      serial: snapshot.devices[0].serial,
      action: 'cleanupDroidGuard',
      confirmationText: phrase,
    });
  });

  it('opens only an allow-listed integrity checker after serial-bound confirmation', async () => {
    const user = userEvent.setup();
    const onCommand = vi.fn(async () => ({
      result: { status: 'SUCCESS', value: { action: 'launchIntegrityCheck', checker: 'spic', verified: true } },
    }));
    const { snapshot } = renderRoot(onCommand);
    const card = screen.getByText('PIF and TargetedFix profiles').closest('.card');
    if (!card) throw new Error('PIF inventory card missing');

    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Open integrity checker' }));
    await user.selectOptions(within(card as HTMLElement).getByLabelText('Integrity checker'), 'spic');
    const phrase = `OPEN PI spic ${snapshot.devices[0].serial.slice(-6).toUpperCase()}`;
    const run = within(card as HTMLElement).getByRole('button', { name: 'Open and verify checker' });
    expect(run).toBeDisabled();
    await user.type(within(card as HTMLElement).getByLabelText('Confirm integrity checker launch'), phrase);
    expect(run).toBeEnabled();
    await user.click(run);

    expect(onCommand).toHaveBeenLastCalledWith('tools.pif', {
      serial: snapshot.devices[0].serial,
      action: 'launchIntegrityCheck',
      checker: 'spic',
      confirmationText: phrase,
    });
  });

  it('loads, edits, and hash-verifies a bounded PIF document without device paths', async () => {
    const user = userEvent.setup();
    const original = '{"PRODUCT":"akita"}';
    const updated = '{"PRODUCT":"bramble"}';
    const onCommand = vi.fn(async (command: BridgeCommand) => {
      if (command === 'root.pif.document') {
        return {
          result: {
            status: 'SUCCESS',
            value: {
              schemaVersion: 1, profileId: 'pif.custom_json', format: 'json', present: true,
              content: original, size: new TextEncoder().encode(original).length,
              sha256: 'a'.repeat(64), editable: true, bounded: true,
            },
          },
        };
      }
      return {
        result: {
          status: 'SUCCESS',
          value: {
            action: 'updateProfile', profileId: 'pif.custom_json',
            sha256: 'b'.repeat(64), size: new TextEncoder().encode(updated).length,
          },
        },
      };
    });
    const { snapshot, container } = renderRoot(onCommand);
    const card = screen.getByText('PIF and TargetedFix profiles').closest('.card');
    if (!card) throw new Error('PIF inventory card missing');

    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Edit profile' }));
    expect(onCommand).toHaveBeenCalledWith('root.pif.document', {
      serial: snapshot.devices[0].serial,
      profileId: 'pif.custom_json',
    });
    const editor = within(card as HTMLElement).getByLabelText('PIF profile content');
    expect(editor).toHaveValue(original);
    expect(card.textContent).not.toContain('/data/adb');
    fireEvent.change(editor, { target: { value: updated } });

    const phrase = `SAVE PIF pif.custom_json ${snapshot.devices[0].serial.slice(-6).toUpperCase()}`;
    const save = within(card as HTMLElement).getByRole('button', { name: 'Save and verify profile' });
    expect(save).toBeDisabled();
    await user.type(within(card as HTMLElement).getByLabelText('Confirm profile save'), phrase);
    expect(save).toBeEnabled();
    await user.click(save);
    expect(onCommand).toHaveBeenLastCalledWith('tools.pif', {
      serial: snapshot.devices[0].serial,
      action: 'updateProfile',
      profileId: 'pif.custom_json',
      content: updated,
      baseSha256: 'a'.repeat(64),
      confirmationText: phrase,
    });
    expect(within(card as HTMLElement).getByText('Unchanged')).toBeVisible();
    expect((await axe.run(container)).violations).toEqual([]);
  });

  it('normalizes profiles and manages revisioned local favorites through closed commands', async () => {
    const user = userEvent.setup();
    const original = '{"BRAND":"google","MODEL":"Pixel 9"}';
    const normalized = '{\n  "BRAND": "google",\n  "MODEL": "Pixel 9"\n}\n';
    const favoriteId = 'c'.repeat(64);
    const favorite = {
      favoriteId, label: 'Pixel 9 stable', createdAt: '2026-07-20T12:00:00+00:00',
      sha256: favoriteId, size: new TextEncoder().encode(normalized).length,
    };
    const onCommand = vi.fn(async (command: BridgeCommand, payload?: Record<string, unknown>) => {
      if (command === 'root.pif.document') return { result: { status: 'SUCCESS', value: {
        schemaVersion: 1, profileId: 'pif.custom_json', format: 'json', present: true,
        content: original, size: new TextEncoder().encode(original).length,
        sha256: 'a'.repeat(64), editable: true, bounded: true,
      } } };
      if (command === 'root.pif.favorites.list') return { result: { status: 'SUCCESS', value: {
        schemaVersion: 1, revision: 0, count: 0, favorites: [], bounded: true,
      } } };
      if (command === 'root.pif.transform') return { result: { status: 'SUCCESS', value: {
        schemaVersion: 1, format: payload?.outputFormat ?? 'json', content: normalized,
        sha256: 'b'.repeat(64), size: new TextEncoder().encode(normalized).length,
        fieldCount: 2, bounded: true,
      } } };
      if (command === 'root.pif.favorites.save') return { revision: 8, result: { status: 'SUCCESS', value: {
        schemaVersion: 1, action: 'saved', revision: 1, snapshotRevision: 8,
        favorite, bounded: true,
      } } };
      if (command === 'root.pif.favorites.get') return { result: { status: 'SUCCESS', value: {
        schemaVersion: 1, revision: 1, favorite: { ...favorite, content: normalized }, bounded: true,
      } } };
      if (command === 'root.pif.favorites.delete') return { revision: 9, result: { status: 'SUCCESS', value: {
        schemaVersion: 1, action: 'deleted', revision: 2, snapshotRevision: 9,
        favorite, bounded: true,
      } } };
      return { result: { status: 'FAILED' } };
    });
    const { container } = renderRoot(onCommand);
    const card = screen.getByText('PIF and TargetedFix profiles').closest('.card');
    if (!card) throw new Error('PIF inventory card missing');
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Edit profile' }));
    expect(await within(card as HTMLElement).findByRole('button', { name: 'Normalize editor' })).toBeVisible();
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Normalize editor' }));
    expect(onCommand).toHaveBeenCalledWith('root.pif.transform', {
      content: original, inputFormat: 'json', outputFormat: 'json', normalize: true,
      keepUnknown: true, sortKeys: true,
    });
    expect(within(card as HTMLElement).getByLabelText('PIF profile content')).toHaveValue(normalized);

    await user.type(within(card as HTMLElement).getByLabelText('Favorite label'), 'Pixel 9 stable');
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Save favorite' }));
    expect(onCommand).toHaveBeenCalledWith('root.pif.favorites.save', {
      label: 'Pixel 9 stable', content: normalized,
    });
    expect(await within(card as HTMLElement).findByText('Pixel 9 stable')).toBeVisible();
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Load favorite' }));
    expect(onCommand).toHaveBeenCalledWith('root.pif.favorites.get', { favoriteId });
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Delete favorite' }));
    await user.click(within(card as HTMLElement).getByRole('button', { name: 'Confirm favorite deletion' }));
    expect(onCommand).toHaveBeenCalledWith('root.pif.favorites.delete', { favoriteId });
    expect(within(card as HTMLElement).queryByText('Pixel 9 stable')).not.toBeInTheDocument();
    expect((await axe.run(container)).violations).toEqual([]);
  });
});
