import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import App, { boundedConsoleExportLines } from '../App';
import type { BridgeCommand } from '../commands';
import { demoSnapshot } from '../demoData';
import { I18nProvider } from '../i18n';
import { BackupsPage, RootPage } from '../pages/Pages';
import { FlashWizard, type FlashPreview } from '../pages/flash/FlashWizard';
import type { BridgeRequest } from '../types';

const developmentBridge = window.pixelflasher;

function success(value: Record<string, unknown>) {
  return { result: { status: 'SUCCESS', value }, revision: demoSnapshot.revision };
}

describe('BUG-40 skip link keeps the current route', () => {
  it('ignores an in-page fragment anchor instead of falling back to the dashboard', async () => {
    const user = userEvent.setup();
    render(<App />);
    const navigation = within(await screen.findByRole('navigation', { name: 'Tasks' }));
    await user.click(navigation.getByRole('button', { name: 'Tools' }));
    expect(await screen.findByRole('heading', { name: 'Device tools' })).toBeVisible();

    const skipLink = screen.getByRole('link', { name: 'Skip to main content' });
    expect(skipLink).toHaveAttribute('href', '#main-content');

    // Activating the skip link rewrites the hash to a non-route fragment.
    window.location.hash = '#main-content';
    window.dispatchEvent(new HashChangeEvent('hashchange'));

    expect(await screen.findByRole('heading', { name: 'Device tools' })).toBeVisible();
    expect(navigation.getByRole('button', { name: 'Tools' })).toHaveAttribute('aria-current', 'page');
  });

  it('still routes on a deliberate route hash', async () => {
    const user = userEvent.setup();
    render(<App />);
    const navigation = within(await screen.findByRole('navigation', { name: 'Tasks' }));
    await user.click(navigation.getByRole('button', { name: 'Tools' }));
    expect(await screen.findByRole('heading', { name: 'Device tools' })).toBeVisible();

    window.location.hash = '#/backups';
    window.dispatchEvent(new HashChangeEvent('hashchange'));
    expect(await screen.findByRole('heading', { name: 'Backups' })).toBeVisible();

    window.location.hash = '';
    window.dispatchEvent(new HashChangeEvent('hashchange'));
    await waitFor(() => expect(navigation.getByRole('button', { name: 'Dashboard' })).toHaveAttribute('aria-current', 'page'));
  });
});

describe('BUG-51 console export stays inside the bridge payload bound', () => {
  it('keeps the newest lines that fit and passes short buffers through untouched', () => {
    const encoder = new TextEncoder();
    const lines = Array.from(
      { length: 200 },
      (_, index) => `[RUNNING] ${String(index).padStart(3, '0')} ${'x'.repeat(460)}`,
    );
    const bounded = boundedConsoleExportLines(lines);

    expect(bounded.length).toBeGreaterThan(0);
    expect(bounded.length).toBeLessThan(lines.length);
    expect(bounded.at(-1)).toBe(lines.at(-1));
    expect(lines.slice(-bounded.length)).toEqual(bounded);
    expect(
      encoder.encode(JSON.stringify({ grant: 'w'.repeat(64), lines: bounded })).length,
    ).toBeLessThanOrEqual(64 * 1024);
    // The host also bounds the raw UTF-8 payload of app.console.export.
    expect(
      bounded.reduce((total, line) => total + encoder.encode(line).length + 1, 0),
    ).toBeLessThanOrEqual(65_536);

    expect(boundedConsoleExportLines(['[RUNNING 50%] Processing firmware.']))
      .toEqual(['[RUNNING 50%] Processing firmware.']);
  });

  it('exports a payload the bridge accepts after a long run of progress messages', async () => {
    const user = userEvent.setup();
    const postMessage = vi.spyOn(developmentBridge!, 'postMessage');
    render(<App />);
    const navigation = within(await screen.findByRole('navigation', { name: 'Tasks' }));

    for (let index = 0; index < 200; index += 1) {
      window.dispatchEvent(new CustomEvent('pixelflasher:message', {
        detail: {
          version: 2,
          event: 'progress',
          revision: 7,
          payload: {
            operation_id: 'console-operation',
            phase: 'running',
            status: 'running',
            message: `Processing firmware ${String(index).padStart(3, '0')} ${'x'.repeat(450)}`,
          },
        },
      }));
    }

    await user.click(navigation.getByRole('button', { name: 'Settings' }));
    postMessage.mockClear();
    await user.click(await screen.findByRole('button', { name: 'Export redacted console' }));

    let exported: BridgeRequest | undefined;
    await waitFor(() => {
      exported = postMessage.mock.calls
        .map(([raw]) => JSON.parse(raw) as BridgeRequest)
        .find((request) => request.command === 'app.console.export');
      expect(exported).toBeDefined();
    });

    const lines = exported?.payload.lines as string[];
    expect(lines.length).toBeGreaterThan(0);
    expect(lines.length).toBeLessThan(200);
    expect(lines.at(-1)).toContain('Processing firmware 199');
    expect(new TextEncoder().encode(JSON.stringify(exported?.payload)).length).toBeLessThanOrEqual(64 * 1024);
  });
});

const rootAppDigest = '1'.repeat(64);

function catalogEntry(architecture: string, artifactId: string) {
  return {
    artifactId,
    provider: 'SukiSU Ultra',
    channel: 'stable',
    flavor: 'ultra',
    version: '2.0',
    architecture,
    packageName: 'com.sukisu.ultra',
    signerSha256: ['a'.repeat(64)],
    sha256: rootAppDigest,
    size: 4096,
    license: 'GPL-3.0',
    provenance: 'verified-download',
  };
}

function downloadedApp(architecture: string) {
  return {
    id: 'd'.repeat(64),
    provider: 'SukiSU Ultra',
    flavor: 'ultra',
    version: '2.0',
    sha256: rootAppDigest,
    provenance: 'verified-download',
    packageName: 'com.sukisu.ultra',
    signerSha256: ['a'.repeat(64)],
    schemes: ['kernelsu'],
    architecture,
  };
}

function architectureOf(row: HTMLElement) {
  return Array.from(row.querySelectorAll('.badge')).map((badge) => badge.textContent ?? '');
}

function rootAppRows() {
  return within(screen.getByRole('list', { name: 'Rooting Apps' })).getAllByRole('listitem');
}

describe('BUG-41 root-app catalog availability is architecture aware', () => {
  it('keeps the device architecture downloadable after a wrong-architecture download', async () => {
    const user = userEvent.setup();
    const snapshot = structuredClone(demoSnapshot);
    const device = snapshot.devices[0];
    device.mode = 'adb';
    device.architecture = 'arm64';
    // The backend sorts entries by architecture, so "arm" precedes "arm64".
    const entries = [
      catalogEntry('arm', '1'.repeat(32)),
      catalogEntry('arm64', '2'.repeat(32)),
      catalogEntry('x86_64', '3'.repeat(32)),
    ];
    const onCommand = vi.fn(async (command: BridgeCommand, payload?: Record<string, unknown>) => {
      if (command === 'root.apps.catalog.refresh') return success({ entries, count: entries.length });
      if (command === 'root.apps.download') {
        const entry = entries.find((candidate) => candidate.artifactId === payload?.artifactId);
        return success({ app: downloadedApp(entry?.architecture ?? 'arm') });
      }
      return success({});
    });

    render(
      <I18nProvider locale="en">
        <RootPage
          snapshot={snapshot}
          selectedSerials={[device.serial]}
          onSelectionChange={vi.fn()}
          onCommand={onCommand}
        />
      </I18nProvider>,
    );

    await user.click(screen.getByRole('button', { name: 'Load catalog' }));
    await waitFor(() => expect(rootAppRows()).toHaveLength(3));
    // The row the connected device can actually use is presented first.
    expect(architectureOf(rootAppRows()[0])).toContain('arm64');

    const armRow = rootAppRows().find((row) => architectureOf(row).includes('arm'));
    await user.click(within(armRow!).getByRole('button', { name: 'Download app' }));

    await waitFor(() => expect(onCommand).toHaveBeenCalledWith(
      'root.apps.download',
      { artifactId: '1'.repeat(32) },
    ));

    await waitFor(() => {
      const arm64Row = rootAppRows().find((row) => architectureOf(row).includes('arm64'));
      expect(within(arm64Row!).getByRole('button', { name: 'Download app' })).toBeVisible();
    });
    const arm64Row = rootAppRows().find((row) => architectureOf(row).includes('arm64'));
    expect(within(arm64Row!).queryByText('Available locally')).not.toBeInTheDocument();

    const armRowAfter = rootAppRows().find((row) => architectureOf(row).includes('arm'));
    expect(within(armRowAfter!).getByText('Available locally')).toBeVisible();
  });
});

describe('long operations expose an abort affordance', () => {
  it('cancels an accepted backups.create through operation.cancel', async () => {
    const user = userEvent.setup();
    const snapshot = structuredClone(demoSnapshot);
    const device = snapshot.devices[0];
    device.mode = 'fastboot';
    snapshot.activeOperation = {
      id: 'backup-operation-1',
      kind: 'backups.create',
      label: 'Creating backup',
      status: 'running',
    };
    let releaseCreate: (() => void) | null = null;
    const onCommand = vi.fn(async (command: BridgeCommand) => {
      if (command === 'backups.list') {
        return success({
          backups: [], count: 0, totalCount: 0, filteredSerial: device.serial,
          revision: snapshot.revision, bounded: true, truncated: false,
        });
      }
      if (command === 'native.saveFile') return success({ data: { grant: 'opaque-write' } });
      if (command === 'backups.create') {
        await new Promise<void>((resolve) => { releaseCreate = resolve; });
        return success({ action: 'create' });
      }
      return success({});
    });

    render(
      <I18nProvider locale="en">
        <BackupsPage
          snapshot={snapshot}
          selectedSerials={[device.serial]}
          onSelectionChange={vi.fn()}
          onCommand={onCommand}
        />
      </I18nProvider>,
    );

    expect(screen.queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Create backup' }));
    const cancel = await screen.findByRole('button', { name: 'Cancel' });
    await user.click(cancel);

    await waitFor(() => expect(onCommand).toHaveBeenCalledWith(
      'operation.cancel',
      { operationId: 'backup-operation-1' },
    ));
    expect(await screen.findByRole('button', { name: 'Cancel' })).toBeDisabled();
    releaseCreate!();
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument());
  });

  it('offers a cancel control for a running flash', async () => {
    const user = userEvent.setup();
    const onCancel = vi.fn();
    const preview: FlashPreview = {
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
    const props = {
      devices: demoSnapshot.devices,
      selectedSerials: [demoSnapshot.devices[1].serial],
      activeFirmware: demoSnapshot.firmware,
      activeBoot: demoSnapshot.boot,
      expertMode: false,
      operation: null,
      onSelectionChange: vi.fn(async () => undefined),
      onFirmwareChange: vi.fn(async () => undefined),
      onPrepare: vi.fn(async () => preview),
      onStart: vi.fn(async () => undefined),
    };
    const { rerender } = render(
      <I18nProvider locale="en"><FlashWizard {...props} /></I18nProvider>,
    );

    await user.click(screen.getByRole('button', { name: 'Continue' }));
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    await user.click(screen.getByRole('button', { name: 'Prepare review' }));
    expect(await screen.findByRole('heading', { name: 'Review' })).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument();

    rerender(
      <I18nProvider locale="en">
        <FlashWizard
          {...props}
          operation={{ status: 'running', progress: 12 }}
          onCancel={onCancel}
        />
      </I18nProvider>,
    );
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });
});
