import { useCallback, useEffect, useRef, useState } from 'react';
import type { FitAddon as XtermFitAddon } from '@xterm/addon-fit';
import type { Terminal as XtermTerminal } from '@xterm/xterm';
import { BridgeError, bridge } from '../../bridge';
import { commands } from '../../commands';
import { useI18n } from '../../i18n';
import { Button } from '../../components/ui';

type SessionStatus = 'idle' | 'opening' | 'open' | 'closing' | 'closed' | 'failed';
type TerminalRuntime = {
  Terminal: typeof import('@xterm/xterm').Terminal;
  FitAddon: typeof import('@xterm/addon-fit').FitAddon;
};

declare global {
  interface Window {
    PixelFlasherTerminalRuntime?: TerminalRuntime;
  }
}

type TerminalResult = {
  accepted?: unknown;
  code?: unknown;
  message?: unknown;
  sessionId?: unknown;
  revision?: unknown;
};

const MAX_INPUT_CODEPOINTS = 8192;
let terminalRuntimePromise: Promise<TerminalRuntime> | null = null;

function loadTerminalRuntime() {
  if (window.PixelFlasherTerminalRuntime) return Promise.resolve(window.PixelFlasherTerminalRuntime);
  if (terminalRuntimePromise) return terminalRuntimePromise;
  terminalRuntimePromise = new Promise<TerminalRuntime>((resolve, reject) => {
    if (!document.querySelector('link[data-pixelflasher-terminal]')) {
      const styles = document.createElement('link');
      styles.rel = 'stylesheet';
      styles.href = new URL('./assets/adb-terminal.css', document.baseURI).href;
      styles.dataset.pixelflasherTerminal = 'true';
      document.head.append(styles);
    }
    const finish = () => {
      const runtime = window.PixelFlasherTerminalRuntime;
      if (runtime) resolve(runtime);
      else reject(new Error('ADB terminal runtime did not register.'));
    };
    const existing = document.querySelector<HTMLScriptElement>('script[data-pixelflasher-terminal]');
    if (existing) {
      existing.addEventListener('load', finish, { once: true });
      existing.addEventListener('error', () => reject(new Error('ADB terminal runtime failed to load.')), { once: true });
      return;
    }
    const script = document.createElement('script');
    script.src = new URL('./assets/adb-terminal.js', document.baseURI).href;
    script.async = true;
    script.dataset.pixelflasherTerminal = 'true';
    script.addEventListener('load', finish, { once: true });
    script.addEventListener('error', () => reject(new Error('ADB terminal runtime failed to load.')), { once: true });
    document.head.append(script);
  }).catch((error: unknown) => {
    terminalRuntimePromise = null;
    throw error;
  });
  return terminalRuntimePromise;
}

function exactTerminalEvent(payload: Record<string, unknown>) {
  const type = payload.type;
  if (
    typeof payload.sessionId !== 'string'
    || !payload.sessionId
    || typeof payload.sequence !== 'number'
    || !Number.isSafeInteger(payload.sequence)
    || payload.sequence < 1
  ) return false;
  const base = ['sessionId', 'sequence', 'type'];
  const expected = type === 'output'
    ? [...base, 'data', 'encoding']
    : type === 'closed'
      ? [...base, 'code', 'exitCode', 'message']
      : [];
  const keys = Object.keys(payload).sort();
  const sortedExpected = [...expected].sort();
  const exactKeys = sortedExpected.length > 0
    && keys.length === expected.length
    && keys.every((key, index) => key === sortedExpected[index]);
  if (!exactKeys) return false;
  if (type === 'output') {
    return payload.encoding === 'base64' && typeof payload.data === 'string';
  }
  return typeof payload.code === 'string'
    && typeof payload.message === 'string'
    && (payload.exitCode === null
      || (typeof payload.exitCode === 'number' && Number.isSafeInteger(payload.exitCode)));
}

function decodedOutput(data: unknown): Uint8Array | null {
  if (typeof data !== 'string' || data.length > 90_000) return null;
  try {
    const binary = atob(data);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return bytes.byteLength <= 65_536 ? bytes : null;
  } catch {
    return null;
  }
}

export function AdbShellPanel({ serial, revision }: { serial: string; revision: number }) {
  const { t } = useI18n();
  const containerRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<XtermTerminal | null>(null);
  const fitRef = useRef<XtermFitAddon | null>(null);
  const sessionRef = useRef<string | null>(null);
  const revisionRef = useRef(revision);
  const sequenceRef = useRef(0);
  const inputQueueRef = useRef<string[]>([]);
  const inputTimerRef = useRef<number | null>(null);
  const resizeTimerRef = useRef<number | null>(null);
  const [status, setStatus] = useState<SessionStatus>('idle');
  const [message, setMessage] = useState(t('tools.shellOpening'));
  const [terminalRuntime, setTerminalRuntime] = useState<TerminalRuntime | null>(
    () => window.PixelFlasherTerminalRuntime ?? null,
  );

  useEffect(() => {
    if (terminalRuntime) return undefined;
    let active = true;
    void loadTerminalRuntime().then((runtime) => {
      if (!active) return;
      setTerminalRuntime(runtime);
      setMessage(t('tools.shellReady'));
    }).catch(() => {
      if (!active) return;
      setStatus('failed');
      setMessage(t('tools.shellOpenFailed'));
    });
    return () => { active = false; };
  }, [t, terminalRuntime]);

  const clearTimers = useCallback(() => {
    if (inputTimerRef.current !== null) window.clearTimeout(inputTimerRef.current);
    if (resizeTimerRef.current !== null) window.clearTimeout(resizeTimerRef.current);
    inputTimerRef.current = null;
    resizeTimerRef.current = null;
  }, []);

  const closeSession = useCallback(async () => {
    const sessionId = sessionRef.current;
    if (!sessionId) return;
    sessionRef.current = null;
    inputQueueRef.current = [];
    setStatus('closing');
    try {
      await bridge.command(
        commands.toolsAdbShellClose,
        { sessionId },
        revisionRef.current,
      );
      setStatus('closed');
      setMessage(t('tools.shellClosed'));
    } catch (error) {
      setStatus('failed');
      setMessage(error instanceof BridgeError ? error.message : t('tools.shellCloseFailed'));
    }
  }, [t]);

  const flushInput = useCallback(async () => {
    inputTimerRef.current = null;
    const sessionId = sessionRef.current;
    const data = inputQueueRef.current.shift();
    if (!sessionId || !data) return;
    try {
      await bridge.command(
        commands.toolsAdbShellWrite,
        { sessionId, data },
        revisionRef.current,
      );
    } catch (error) {
      sessionRef.current = null;
      inputQueueRef.current = [];
      setStatus('failed');
      setMessage(error instanceof BridgeError ? error.message : t('tools.shellWriteFailed'));
      return;
    }
    if (inputQueueRef.current.length) {
      inputTimerRef.current = window.setTimeout(() => void flushInput(), 8);
    }
  }, [t]);

  const enqueueInput = useCallback((data: string) => {
    if (!sessionRef.current || !data) return;
    const codepoints = [...data];
    for (let index = 0; index < codepoints.length; index += MAX_INPUT_CODEPOINTS) {
      inputQueueRef.current.push(codepoints.slice(index, index + MAX_INPUT_CODEPOINTS).join(''));
    }
    if (inputTimerRef.current === null) {
      inputTimerRef.current = window.setTimeout(() => void flushInput(), 8);
    }
  }, [flushInput]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container || !terminalRuntime) return undefined;
    const terminal = new terminalRuntime.Terminal({
      allowProposedApi: false,
      convertEol: false,
      cursorBlink: !window.matchMedia('(prefers-reduced-motion: reduce)').matches,
      disableStdin: true,
      fontFamily: 'var(--font-mono, Consolas, monospace)',
      fontSize: 13,
      minimumContrastRatio: 7,
      screenReaderMode: true,
      scrollback: 5000,
      theme: {
        background: '#07111f',
        foreground: '#e8eefc',
        cursor: '#8b7dff',
        selectionBackground: '#3157a8',
      },
    });
    const fit = new terminalRuntime.FitAddon();
    terminal.loadAddon(fit);
    terminal.open(container);
    fit.fit();
    terminalRef.current = terminal;
    fitRef.current = fit;
    const dataSubscription = terminal.onData(enqueueInput);
    const unsubscribe = bridge.subscribe((event) => {
      if (event.event !== 'terminal' || !exactTerminalEvent(event.payload)) return;
      const payload = event.payload;
      if (payload.sessionId !== sessionRef.current
        || typeof payload.sequence !== 'number'
        || !Number.isSafeInteger(payload.sequence)
        || payload.sequence <= sequenceRef.current) return;
      sequenceRef.current = payload.sequence;
      if (payload.type === 'output' && payload.encoding === 'base64') {
        const output = decodedOutput(payload.data);
        if (output) terminal.write(output);
        return;
      }
      if (payload.type === 'closed'
        && typeof payload.code === 'string'
        && typeof payload.message === 'string') {
        sessionRef.current = null;
        terminal.options.disableStdin = true;
        setStatus(payload.code === 'terminal_process_exited' && payload.exitCode === 0 ? 'closed' : 'failed');
        setMessage(payload.message);
      }
    });
    const observer = new ResizeObserver(() => {
      fit.fit();
      if (resizeTimerRef.current !== null) window.clearTimeout(resizeTimerRef.current);
      resizeTimerRef.current = window.setTimeout(() => {
        resizeTimerRef.current = null;
        const sessionId = sessionRef.current;
        if (!sessionId) return;
        void bridge.command(
          commands.toolsAdbShellResize,
          { sessionId, columns: terminal.cols, rows: terminal.rows },
          revisionRef.current,
        ).catch(() => {
          sessionRef.current = null;
          terminal.options.disableStdin = true;
          setStatus('failed');
          setMessage(t('tools.shellResizeFailed'));
        });
      }, 100);
    });
    observer.observe(container);
    return () => {
      const sessionId = sessionRef.current;
      sessionRef.current = null;
      clearTimers();
      inputQueueRef.current = [];
      observer.disconnect();
      unsubscribe();
      dataSubscription.dispose();
      terminal.dispose();
      terminalRef.current = null;
      fitRef.current = null;
      if (sessionId) {
        void bridge.command(
          commands.toolsAdbShellClose,
          { sessionId },
          revisionRef.current,
        ).catch(() => undefined);
      }
    };
  }, [clearTimers, enqueueInput, t, terminalRuntime]);

  useEffect(() => {
    if (revision === revisionRef.current) return;
    revisionRef.current = revision;
    if (sessionRef.current) {
      sessionRef.current = null;
      const terminal = terminalRef.current;
      if (terminal) terminal.options.disableStdin = true;
      setStatus('closed');
      setMessage(t('tools.shellStateChanged'));
    }
  }, [revision, t]);

  const startSession = async () => {
    const terminal = terminalRef.current;
    const fit = fitRef.current;
    if (!terminal || !fit || status === 'opening' || status === 'open') return;
    fit.fit();
    setStatus('opening');
    setMessage(t('tools.shellOpening'));
    try {
      const response = await bridge.command<TerminalResult>(
        commands.toolsAdbShell,
        { serial, columns: terminal.cols, rows: terminal.rows },
        revision,
      );
      const result = response.result;
      if (result.accepted !== true || typeof result.sessionId !== 'string' || !result.sessionId) {
        throw new BridgeError(typeof result.message === 'string' ? result.message : t('tools.shellOpenFailed'));
      }
      sessionRef.current = result.sessionId;
      revisionRef.current = typeof result.revision === 'number' ? result.revision : revision;
      sequenceRef.current = 0;
      terminal.clear();
      terminal.options.disableStdin = false;
      terminal.focus();
      setStatus('open');
      setMessage(t('tools.shellOpen'));
    } catch (error) {
      terminal.options.disableStdin = true;
      setStatus('failed');
      setMessage(error instanceof BridgeError ? error.message : t('tools.shellOpenFailed'));
    }
  };

  return (
    <div className="adb-shell-panel">
      <p className="tool-help">{t('tools.shellDetail')}</p>
      <div className="adb-shell-panel__toolbar">
        <span role="status" aria-live="polite">{message}</span>
        <div className="button-row">
          <Button onClick={() => void startSession()} disabled={!terminalRuntime || status === 'opening' || status === 'open'}>
            {status === 'closed' || status === 'failed' ? t('tools.shellReconnect') : t('tools.shellStart')}
          </Button>
          <Button variant="secondary" onClick={() => void closeSession()} disabled={status !== 'open'}>
            {t('tools.shellClose')}
          </Button>
        </div>
      </div>
      <div
        ref={containerRef}
        className="adb-shell-panel__terminal"
        role="region"
        aria-label={t('tools.shellTerminalLabel', { serial })}
      />
    </div>
  );
}
