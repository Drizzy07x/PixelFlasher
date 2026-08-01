import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import axe from 'axe-core';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { BridgeRequest } from '../types';
import { I18nProvider } from '../i18n';

const xtermState = vi.hoisted(() => ({
  instances: [] as Array<{
    cols: number;
    rows: number;
    options: Record<string, unknown>;
    writes: Uint8Array[];
    input: ((data: string) => void) | null;
  }>,
}));

vi.mock('@xterm/xterm', () => ({
  Terminal: class MockTerminal {
    cols = 100;
    rows = 30;
    options: Record<string, unknown>;
    writes: Uint8Array[] = [];
    input: ((data: string) => void) | null = null;

    constructor(options: Record<string, unknown>) {
      this.options = { ...options };
      xtermState.instances.push(this);
    }

    loadAddon() {}
    open() {}
    clear() {}
    focus() {}
    dispose() {}
    write(data: Uint8Array) { this.writes.push(data); }
    onData(listener: (data: string) => void) {
      this.input = listener;
      return { dispose() {} };
    }
  },
}));

vi.mock('@xterm/addon-fit', () => ({
  FitAddon: class MockFitAddon {
    fit() {}
  },
}));

import { AdbShellPanel } from '../pages/tooling/AdbShellPanel';

describe('ADB shell React terminal', () => {
  beforeEach(async () => {
    xtermState.instances.length = 0;
    const [{ Terminal }, { FitAddon }] = await Promise.all([
      import('@xterm/xterm'),
      import('@xterm/addon-fit'),
    ]);
    window.PixelFlasherTerminalRuntime = { Terminal, FitAddon };
    Object.defineProperty(window, 'matchMedia', {
      configurable: true,
      value: () => ({ matches: false }),
    });
    vi.stubGlobal('ResizeObserver', class MockResizeObserver {
      observe() {}
      disconnect() {}
    });
  });

  it('opens one revision-bound session, streams binary output, writes input, and closes it', async () => {
    const requests: BridgeRequest[] = [];
    window.pixelflasher = {
      postMessage(raw) {
        const request = JSON.parse(raw) as BridgeRequest;
        requests.push(request);
        const sessionId = 'terminal-session-1';
        queueMicrotask(() => window.dispatchEvent(new CustomEvent('pixelflasher:message', {
          detail: {
            version: 2,
            requestId: request.requestId,
            ok: true,
            result: {
              accepted: true,
              code: request.command === 'tools.adbShell' ? 'terminal_opened' : 'terminal_command_accepted',
              message: 'accepted',
              sessionId,
              revision: 17,
            },
          },
        })));
      },
    };

    const user = userEvent.setup();
    render(<AdbShellPanel serial="SERIAL-17" revision={17} />);
    await user.click(screen.getByRole('button', { name: 'Open shell' }));

    await waitFor(() => expect(requests[0]).toMatchObject({
      version: 2,
      command: 'tools.adbShell',
      expectedRevision: 17,
      payload: { serial: 'SERIAL-17', columns: 100, rows: 30 },
    }));
    expect(await screen.findByText('ADB shell connected to the selected device.')).toBeVisible();

    window.dispatchEvent(new CustomEvent('pixelflasher:message', {
      detail: {
        version: 2,
        event: 'terminal',
        revision: 17,
        payload: {
          type: 'output',
          sessionId: 'terminal-session-1',
          sequence: 1,
          encoding: 'base64',
          data: 'aG9zdGlsZQ==',
          unexpected: true,
        },
      },
    }));
    await Promise.resolve();
    expect(xtermState.instances[0].writes).toHaveLength(0);

    window.dispatchEvent(new CustomEvent('pixelflasher:message', {
      detail: {
        version: 2,
        event: 'terminal',
        revision: 17,
        payload: {
          type: 'output',
          sessionId: 'terminal-session-1',
          sequence: 1,
          encoding: 'base64',
          data: 'aWQ9MTAwMA0K',
        },
      },
    }));
    await waitFor(() => expect(xtermState.instances[0].writes).toHaveLength(1));
    expect(new TextDecoder().decode(xtermState.instances[0].writes[0])).toBe('id=1000\r\n');

    xtermState.instances[0].input?.('pwd\r');
    await waitFor(() => expect(requests.some((request) => (
      request.command === 'tools.adbShell.write'
      && request.payload.data === 'pwd\r'
      && request.payload.sessionId === 'terminal-session-1'
    ))).toBe(true));

    await user.click(screen.getByRole('button', { name: 'Close shell' }));
    await waitFor(() => expect(requests.some((request) => (
      request.command === 'tools.adbShell.close'
      && request.payload.sessionId === 'terminal-session-1'
    ))).toBe(true));
    expect(await screen.findByText('ADB shell session closed.')).toBeVisible();
  });

  it('exposes a named screen-reader terminal with bounded accessible status updates', async () => {
    const { container } = render(
      <I18nProvider locale="en">
        <AdbShellPanel serial="SERIAL-A11Y" revision={21} />
      </I18nProvider>,
    );

    const terminalRegion = await screen.findByRole('region', {
      name: 'ADB shell terminal for SERIAL-A11Y',
    });
    expect(terminalRegion).toBeVisible();
    expect(screen.getByRole('status')).toHaveAttribute('aria-live', 'polite');
    expect(xtermState.instances[0].options).toMatchObject({
      disableStdin: true,
      minimumContrastRatio: 7,
      screenReaderMode: true,
      scrollback: 5000,
    });

    const results = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } },
    });
    expect(results.violations).toEqual([]);
  });
});
