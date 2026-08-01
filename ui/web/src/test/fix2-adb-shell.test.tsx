import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { BridgeRequest } from '../types';

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

type HostReply = { ok: true; result: Record<string, unknown> } | { ok: false; code: string; message: string };

function installHost(reply: (request: BridgeRequest) => HostReply) {
  const requests: BridgeRequest[] = [];
  window.pixelflasher = {
    postMessage(raw) {
      const request = JSON.parse(raw) as BridgeRequest;
      requests.push(request);
      const answer = reply(request);
      queueMicrotask(() => window.dispatchEvent(new CustomEvent('pixelflasher:message', {
        detail: answer.ok
          ? { version: 2, requestId: request.requestId, ok: true, result: answer.result }
          : {
            version: 2,
            requestId: request.requestId,
            ok: false,
            error: { code: answer.code, message: answer.message },
          },
      })));
    },
  };
  return requests;
}

const accepted = (sessionId: string, revision: number) => ({
  ok: true as const,
  result: { accepted: true, code: 'terminal_opened', message: 'accepted', sessionId, revision },
});

describe('ADB shell session ownership', () => {
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

  it('keeps the session across a benign revision bump and writes at the new revision', async () => {
    const requests = installHost(() => accepted('terminal-session-1', 17));
    const user = userEvent.setup();
    const { rerender } = render(<AdbShellPanel serial="SERIAL-17" revision={17} />);
    await user.click(screen.getByRole('button', { name: 'Open shell' }));
    expect(await screen.findByText('ADB shell connected to the selected device.')).toBeVisible();

    rerender(<AdbShellPanel serial="SERIAL-17" revision={18} />);

    xtermState.instances[0].input?.('id\r');
    await waitFor(() => expect(requests.some((request) => (
      request.command === 'tools.adbShell.write'
      && request.payload.sessionId === 'terminal-session-1'
      && request.expectedRevision === 18
    ))).toBe(true));
    expect(requests.some((request) => request.command === 'tools.adbShell.close')).toBe(false);
    expect(screen.getByRole('button', { name: 'Close shell' })).toBeEnabled();
  });

  it('closes the host session whenever it drops the session locally', async () => {
    const requests = installHost((request) => (request.command === 'tools.adbShell.write'
      ? { ok: false as const, code: 'terminal_write_failed', message: 'Terminal input could not be written.' }
      : accepted('terminal-session-2', 21)));
    const user = userEvent.setup();
    render(<AdbShellPanel serial="SERIAL-21" revision={21} />);
    await user.click(screen.getByRole('button', { name: 'Open shell' }));
    expect(await screen.findByText('ADB shell connected to the selected device.')).toBeVisible();

    xtermState.instances[0].input?.('id\r');

    await waitFor(() => expect(requests.some((request) => (
      request.command === 'tools.adbShell.close'
      && request.payload.sessionId === 'terminal-session-2'
    ))).toBe(true));
  });

  it('retries once when the host releases a session left behind by a reload', async () => {
    let refused = false;
    const requests = installHost((request) => {
      if (request.command === 'tools.adbShell' && !refused) {
        refused = true;
        return {
          ok: false as const,
          code: 'terminal_session_active',
          message: 'The previous ADB Shell was released; open it again.',
        };
      }
      return accepted('terminal-session-3', 5);
    });
    const user = userEvent.setup();
    render(<AdbShellPanel serial="SERIAL-5" revision={5} />);

    await user.click(screen.getByRole('button', { name: 'Open shell' }));

    expect(await screen.findByText('ADB shell connected to the selected device.')).toBeVisible();
    expect(requests.filter((request) => request.command === 'tools.adbShell')).toHaveLength(2);
  });
});
