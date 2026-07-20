import { render, screen } from '@testing-library/react';
import axe from 'axe-core';
import { describe, expect, it, vi } from 'vitest';
import { bridgeCommandMetadata, isBridgeCommand } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import {
  ToolsPage,
  resolveToolAvailability,
  type ToolAvailabilityContext,
} from '../pages/tooling/ToolsPage';
import type { HostSnapshot } from '../types';

const ready: ToolAvailabilityContext = {
  busy: false,
  hasDevice: true,
  toolchainReady: true,
  adbReady: true,
  fastbootReady: false,
  firmwareReady: true,
};

describe('Tools capability catalog', () => {
  it('explains every blocked prerequisite deterministically', () => {
    expect(resolveToolAvailability('none', ready)).toBe('available');
    expect(resolveToolAvailability('adb', { ...ready, busy: true })).toBe('busy');
    expect(resolveToolAvailability('device', { ...ready, hasDevice: false })).toBe('needs_device');
    expect(resolveToolAvailability('toolchain', { ...ready, toolchainReady: false })).toBe('needs_toolchain');
    expect(resolveToolAvailability('adb', { ...ready, adbReady: false })).toBe('needs_adb');
    expect(resolveToolAvailability('fastboot', { ...ready, fastbootReady: false })).toBe('needs_fastboot');
    expect(resolveToolAvailability('firmware', { ...ready, firmwareReady: false })).toBe('needs_firmware');
  });

  it('binds every visible card to a registered command owner and visible availability', async () => {
    const snapshot = structuredClone(demoSnapshot) as HostSnapshot;
    const { container } = render(
      <I18nProvider locale="en">
        <ToolsPage
          snapshot={snapshot}
          selectedSerials={snapshot.selectedSerials ?? []}
          onSelectionChange={vi.fn()}
          onCommand={vi.fn(async () => ({ result: { status: 'SUCCESS' } }))}
          expertMode
        />
      </I18nProvider>,
    );

    const cards = screen.getAllByRole('button').filter((button) => button.classList.contains('tool-card'));
    expect(cards).toHaveLength(13);
    for (const card of cards) {
      const command = card.dataset.command;
      expect(isBridgeCommand(command)).toBe(true);
      if (!isBridgeCommand(command)) throw new Error(`Unregistered Tools command: ${command ?? '<missing>'}`);
      expect(card.dataset.owner).toBe(bridgeCommandMetadata[command].owner);
      expect(card.dataset.availability).toMatch(/^(available|needs_)/);
      expect(card).toHaveTextContent('Owner:');
      expect(card).toHaveTextContent(/Available|Requires|Select|Set up/);
    }
    expect((await axe.run(container)).violations).toEqual([]);
  });
});
