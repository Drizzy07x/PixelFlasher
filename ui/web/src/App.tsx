import { useCallback, useEffect, useMemo, useRef, useState, type SetStateAction } from 'react';
import { assets, type AssetName } from './assets';
import { BridgeError, bridge, interactionFromEvent, normalizeOperationStatus, operationFromEvent, snapshotFromEvent } from './bridge';
import { commands, type BridgeCommand } from './commands';
import { FlashWizard, type FlashPlan, type FlashPreview } from './pages/flash/FlashPage';
import { Badge, Icon, PageHeader } from './components/ui';
import { demoSnapshot } from './demoData';
import { I18nProvider, localeOptions, useI18n } from './i18n';
import {
  AppsPage,
  BackupsPage,
  DashboardPage,
  DevicePage,
  FirmwarePage,
  MAX_LOGCAT_PREVIEW_LINES,
  RootPage,
  SettingsPage,
  ToolsPage,
  appendLogcatProgressBatch,
  initialLogcatUiState,
  initialPushUiState,
  purgeUnredactedLogcatState,
  useLogcatExpertGuard,
  type LogcatUiState,
  type PushUiState,
} from './pages/Pages';
import type { ActiveOperation, HostSnapshot, InteractionRequest, Locale, ModernPreferences, RouteId, Theme } from './types';

type Notice = { tone: 'success' | 'warning' | 'error'; message: string };
type CommandResponse = { result: Record<string, unknown>; revision?: number };
type ReinforcedChallenge = {
  command: BridgeCommand;
  payload: Record<string, unknown>;
  requiredText: string;
};

function objectValue(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? value as Record<string, unknown> : {};
}

const routeIds: RouteId[] = ['dashboard', 'device', 'flash', 'firmware', 'root', 'apps', 'backups', 'tools', 'settings'];

const navIcons: Record<RouteId, AssetName> = {
  dashboard: 'dashboard',
  device: 'devices',
  flash: 'flash',
  firmware: 'firmware',
  root: 'root',
  apps: 'android',
  backups: 'backup',
  tools: 'tools',
  settings: 'settings',
};

function initialRoute(): RouteId {
  const candidate = window.location.hash.replace('#/', '') as RouteId;
  return routeIds.includes(candidate) ? candidate : 'dashboard';
}

function storedValue<T>(key: string, fallback: T): T {
  try {
    const value = window.localStorage.getItem(key);
    return value === null ? fallback : JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

function persist(key: string, value: unknown) {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // The embedded host may disable persistent storage; runtime state still works.
  }
}

const defaultPreferences: ModernPreferences = {
  schemaVersion: 1,
  theme: 'dark',
  locale: 'en',
  highContrast: false,
  reducedMotion: false,
  zoom: 100,
  expertMode: false,
  automaticUpdateCheck: false,
  checkDiskSpace: true,
  checkBootloaderUnlocked: true,
  checkFirmwareHash: true,
  checkModuleUpdates: false,
  showNotifications: false,
  rebootTimeoutSeconds: 90,
};

function mockPreferences(): ModernPreferences {
  const theme = storedValue<unknown>('pf.theme', defaultPreferences.theme);
  const locale = storedValue<unknown>('pf.locale', defaultPreferences.locale);
  const highContrast = storedValue<unknown>('pf.highContrast', defaultPreferences.highContrast);
  const reducedMotion = storedValue<unknown>('pf.reducedMotion', defaultPreferences.reducedMotion);
  const zoom = storedValue<unknown>('pf.zoom', defaultPreferences.zoom);
  const expertMode = storedValue<unknown>('pf.expertMode', defaultPreferences.expertMode);
  const automaticUpdateCheck = storedValue<unknown>('pf.automaticUpdateCheck', defaultPreferences.automaticUpdateCheck);
  const checkDiskSpace = storedValue<unknown>('pf.checkDiskSpace', defaultPreferences.checkDiskSpace);
  const checkBootloaderUnlocked = storedValue<unknown>('pf.checkBootloaderUnlocked', defaultPreferences.checkBootloaderUnlocked);
  const checkFirmwareHash = storedValue<unknown>('pf.checkFirmwareHash', defaultPreferences.checkFirmwareHash);
  const checkModuleUpdates = storedValue<unknown>('pf.checkModuleUpdates', defaultPreferences.checkModuleUpdates);
  const showNotifications = storedValue<unknown>('pf.showNotifications', defaultPreferences.showNotifications);
  const rebootTimeoutSeconds = storedValue<unknown>('pf.rebootTimeoutSeconds', defaultPreferences.rebootTimeoutSeconds);
  return {
    schemaVersion: 1,
    theme: theme === 'light' ? 'light' : 'dark',
    locale: typeof locale === 'string' && ['en', 'es', 'fr', 'it', 'zh_CN', 'zh_TW'].includes(locale)
      ? locale as Locale
      : 'en',
    highContrast: typeof highContrast === 'boolean' ? highContrast : false,
    reducedMotion: typeof reducedMotion === 'boolean' ? reducedMotion : false,
    zoom: typeof zoom === 'number' && Number.isInteger(zoom) && zoom >= 80 && zoom <= 200 ? zoom : 100,
    expertMode: typeof expertMode === 'boolean' ? expertMode : false,
    automaticUpdateCheck: typeof automaticUpdateCheck === 'boolean' ? automaticUpdateCheck : false,
    checkDiskSpace: typeof checkDiskSpace === 'boolean' ? checkDiskSpace : true,
    checkBootloaderUnlocked: typeof checkBootloaderUnlocked === 'boolean' ? checkBootloaderUnlocked : true,
    checkFirmwareHash: typeof checkFirmwareHash === 'boolean' ? checkFirmwareHash : true,
    checkModuleUpdates: typeof checkModuleUpdates === 'boolean' ? checkModuleUpdates : false,
    showNotifications: typeof showNotifications === 'boolean' ? showNotifications : false,
    rebootTimeoutSeconds: typeof rebootTimeoutSeconds === 'number' && Number.isInteger(rebootTimeoutSeconds)
      && rebootTimeoutSeconds >= 1 && rebootTimeoutSeconds <= 3600 ? rebootTimeoutSeconds : 90,
  };
}

const emptyHostSnapshot: HostSnapshot = {
  revision: 0,
  preferences: defaultPreferences,
  devices: [],
  selectedSerial: null,
  selected_serial: null,
  selectedSerials: [],
  selected_serials: [],
  firmware: null,
  boot: null,
  plan: null,
  toolchain: { adb: false, fastboot: false, ready: false },
  activeOperation: null,
  active_operation: null,
  lastResult: null,
  last_result: null,
};

function stripLogcatPayload(
  operation: ActiveOperation | null | undefined,
  forceLogcat = false,
): ActiveOperation | null {
  if (!operation || (!forceLogcat && operation.kind !== commands.toolsLogcat)) return operation ?? null;
  return {
    id: operation.id,
    kind: operation.kind ?? commands.toolsLogcat,
    label: commands.toolsLogcat,
    status: operation.status,
    progress: operation.progress,
    current: operation.current,
    total: operation.total,
    targetSerial: operation.targetSerial,
    target_serial: operation.target_serial,
  };
}

export default function App() {
  const [isMockHost] = useState(() => window.pixelflasher?.__mock === true);
  const [initialPreferences] = useState<ModernPreferences>(() => isMockHost ? mockPreferences() : defaultPreferences);
  const [locale, setLocale] = useState<Locale>(initialPreferences.locale);
  return (
    <I18nProvider locale={locale}>
      <PixelFlasherApp
        locale={locale}
        onLocaleChange={setLocale}
        initialPreferences={initialPreferences}
        isMockHost={isMockHost}
      />
    </I18nProvider>
  );
}

function PixelFlasherApp({
  locale,
  onLocaleChange,
  initialPreferences,
  isMockHost,
}: {
  locale: Locale;
  onLocaleChange: (locale: Locale) => void;
  initialPreferences: ModernPreferences;
  isMockHost: boolean;
}) {
  const { t } = useI18n();
  const [route, setRoute] = useState<RouteId>(initialRoute);
  const [snapshot, setSnapshot] = useState<HostSnapshot>(() => window.pixelflasher?.__mock ? demoSnapshot : emptyHostSnapshot);
  const selectedSerials = snapshot.selectedSerials ?? [];
  const [theme, setTheme] = useState<Theme>(initialPreferences.theme);
  const [expertMode, setExpertMode] = useState(initialPreferences.expertMode);
  const [highContrast, setHighContrast] = useState(initialPreferences.highContrast);
  const [reducedMotion, setReducedMotion] = useState(initialPreferences.reducedMotion);
  const [zoom, setZoom] = useState(initialPreferences.zoom);
  const [applicationPreferences, setApplicationPreferences] = useState(initialPreferences);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [logcatUiState, setLogcatUiState] = useState<LogcatUiState>(initialLogcatUiState);
  const [logcatProgressBatch, setLogcatProgressBatch] = useState<readonly ActiveOperation[]>([]);
  const [pushUiState, setPushUiState] = useState<PushUiState>(initialPushUiState);
  const [bridgeState, setBridgeState] = useState<'connecting' | 'ready' | 'error'>('connecting');
  const [interaction, setInteraction] = useState<InteractionRequest | null>(null);
  const [interactionBusy, setInteractionBusy] = useState(false);
  const interactionDialogRef = useRef<HTMLElement | null>(null);
  const [reinforcedChallenge, setReinforcedChallenge] = useState<ReinforcedChallenge | null>(null);
  const [reinforcedText, setReinforcedText] = useState('');
  const [reinforcedBusy, setReinforcedBusy] = useState(false);
  const reinforcedDialogRef = useRef<HTMLElement | null>(null);
  const reinforcedResolveRef = useRef<((response: CommandResponse | null) => void) | null>(null);
  const snapshotRevisionRef = useRef(snapshot.revision);
  const preferencesRef = useRef(initialPreferences);
  const preferencesLoadRef = useRef<Promise<void> | null>(null);
  const preferencesQueueRef = useRef<Promise<void>>(Promise.resolve());
  const preferencesMountedRef = useRef(true);
  const activeOperationRef = useRef<ActiveOperation | null>(snapshot.activeOperation ?? null);
  const logcatProgressQueueRef = useRef<ActiveOperation[]>([]);
  const logcatProgressLatestRef = useRef<{ operation: ActiveOperation; revision?: number } | null>(null);
  const logcatProgressFrameRef = useRef<number | null>(null);
  const expertModeRef = useRef(expertMode);
  const logcatUiStateRef = useRef(logcatUiState);
  expertModeRef.current = expertMode;
  logcatUiStateRef.current = logcatUiState;
  const updateLogcatUiState = useCallback((update: SetStateAction<LogcatUiState>) => {
    setLogcatUiState((current) => {
      const next = typeof update === 'function' ? update(current) : update;
      return expertModeRef.current ? next : purgeUnredactedLogcatState(next);
    });
  }, []);
  const clearLogcatProgress = useCallback(() => {
    if (logcatProgressFrameRef.current !== null) {
      window.cancelAnimationFrame(logcatProgressFrameRef.current);
      logcatProgressFrameRef.current = null;
    }
    logcatProgressQueueRef.current = [];
    logcatProgressLatestRef.current = null;
    setLogcatProgressBatch((current) => (current.length ? [] : current));
  }, []);
  const flushLogcatProgress = useCallback(() => {
    if (logcatProgressFrameRef.current !== null) {
      window.cancelAnimationFrame(logcatProgressFrameRef.current);
      logcatProgressFrameRef.current = null;
    }
    const batch = logcatProgressQueueRef.current;
    logcatProgressQueueRef.current = [];
    logcatProgressLatestRef.current = null;
    if (batch.length) {
      updateLogcatUiState((current) => appendLogcatProgressBatch(current, batch));
    }
    setLogcatProgressBatch((current) => (current.length ? [] : current));
  }, [updateLogcatUiState]);
  const purgeLogcatProgress = useCallback(() => {
    clearLogcatProgress();
    activeOperationRef.current = stripLogcatPayload(
      activeOperationRef.current,
      activeOperationRef.current?.id === logcatUiStateRef.current.operationId,
    );
    setSnapshot((current) => {
      const active = stripLogcatPayload(
        current.activeOperation,
        current.activeOperation?.id === logcatUiStateRef.current.operationId,
      );
      if (active === current.activeOperation) return current;
      return { ...current, activeOperation: active, active_operation: active };
    });
  }, [clearLogcatProgress]);

  const selectedPushDevice = selectedSerials.length === 1
    ? snapshot.devices.find((device) => device.serial === selectedSerials[0])
    : undefined;
  useEffect(() => {
    const serial = selectedPushDevice?.serial ?? null;
    const mode = selectedPushDevice?.mode ?? null;
    setPushUiState((current) => (
      current.contextSerial === serial && current.contextMode === mode
        ? current
        : {
            ...current,
            retry: null,
            operationId: null,
            outcome: { status: 'idle', targetSerial: null, message: '', receipts: [] },
            contextSerial: serial,
            contextMode: mode,
          }
    ));
  }, [selectedPushDevice?.mode, selectedPushDevice?.serial]);

  const navigate = useCallback((nextRoute: RouteId) => {
    setRoute(nextRoute);
    window.location.hash = `/${nextRoute}`;
    window.requestAnimationFrame(() => {
      document.querySelector<HTMLElement>('#main-content')?.scrollTo?.({ top: 0, left: 0 });
      document.querySelector<HTMLElement>('#main-content h1')?.focus({ preventScroll: true });
    });
  }, []);

  useEffect(() => {
    const onHashChange = () => setRoute(initialRoute());
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.dataset.contrast = highContrast ? 'high' : 'normal';
    document.documentElement.dataset.motion = reducedMotion ? 'reduced' : 'full';
    document.documentElement.style.fontSize = `${zoom}%`;
    if (isMockHost) {
      persist('pf.theme', theme);
      persist('pf.highContrast', highContrast);
      persist('pf.reducedMotion', reducedMotion);
      persist('pf.zoom', zoom);
      persist('pf.locale', locale);
      persist('pf.expertMode', expertMode);
    }
  }, [theme, highContrast, reducedMotion, zoom, locale, expertMode, isMockHost]);

  useEffect(() => {
    snapshotRevisionRef.current = snapshot.revision;
  }, [snapshot.revision]);

  useEffect(() => {
    let mounted = true;
    const scheduleLogcatProgress = () => {
      if (logcatProgressFrameRef.current !== null) return;
      logcatProgressFrameRef.current = window.requestAnimationFrame(() => {
        logcatProgressFrameRef.current = null;
        const batch = logcatProgressQueueRef.current;
        const latest = logcatProgressLatestRef.current;
        logcatProgressQueueRef.current = [];
        logcatProgressLatestRef.current = null;
        if (!mounted || !latest) return;
        if (batch.length) {
          updateLogcatUiState((current) => appendLogcatProgressBatch(current, batch));
        }
        setLogcatProgressBatch(batch);
        setSnapshot((current) => ({
          ...current,
          revision: latest.revision ?? current.revision,
          activeOperation: latest.operation,
          active_operation: latest.operation,
        }));
      });
    };
    const unsubscribe = bridge.subscribe((event) => {
      const nextSnapshot = snapshotFromEvent(event);
      if (nextSnapshot) {
        // A completion snapshot is delivered after the final progress event
        // and can arrive before the next animation frame. Commit that FIFO
        // first so cancelled/failed streams retain their bounded final tail.
        flushLogcatProgress();
        const unsafeOutsideExpert = !expertModeRef.current
          && logcatUiStateRef.current.requestedRedaction === 'none';
        const nextActive = unsafeOutsideExpert
          ? stripLogcatPayload(
              nextSnapshot.activeOperation,
              nextSnapshot.activeOperation?.id === logcatUiStateRef.current.operationId,
            )
          : nextSnapshot.activeOperation ?? null;
        const exposedSnapshot = nextActive === nextSnapshot.activeOperation
          ? nextSnapshot
          : { ...nextSnapshot, activeOperation: nextActive, active_operation: nextActive };
        activeOperationRef.current = nextActive;
        snapshotRevisionRef.current = exposedSnapshot.revision;
        setSnapshot(exposedSnapshot);
        setBridgeState('ready');
      }
      const operation = operationFromEvent(event, activeOperationRef.current);
      if (operation) {
        if (typeof event.revision === 'number') snapshotRevisionRef.current = event.revision;
        if (operation.kind === commands.toolsLogcat) {
          const unsafeOutsideExpert = !expertModeRef.current
            && logcatUiStateRef.current.requestedRedaction === 'none';
          const exposedOperation: ActiveOperation = unsafeOutsideExpert
            ? stripLogcatPayload(operation, true) as ActiveOperation
            : operation;
          activeOperationRef.current = exposedOperation;
          logcatProgressLatestRef.current = {
            operation: exposedOperation,
            ...(typeof event.revision === 'number' ? { revision: event.revision } : {}),
          };
          if (!unsafeOutsideExpert) {
            logcatProgressQueueRef.current.push(operation);
            if (logcatProgressQueueRef.current.length > MAX_LOGCAT_PREVIEW_LINES) {
              logcatProgressQueueRef.current.splice(
                0,
                logcatProgressQueueRef.current.length - MAX_LOGCAT_PREVIEW_LINES,
              );
            }
          }
          scheduleLogcatProgress();
        } else {
          activeOperationRef.current = operation;
          setSnapshot((current) => ({
            ...current,
            revision: event.revision ?? current.revision,
            activeOperation: operation,
            active_operation: operation,
          }));
        }
      }
      const requestedInteraction = interactionFromEvent(event);
      if (requestedInteraction) setInteraction(requestedInteraction);
    });

    bridge.getSnapshot()
      .then((nextSnapshot) => {
        if (!mounted) return;
        snapshotRevisionRef.current = nextSnapshot.revision;
        setSnapshot(nextSnapshot);
        setBridgeState('ready');
      })
      .catch((error: unknown) => {
        if (!mounted) return;
        setBridgeState('error');
        setNotice({ tone: 'error', message: error instanceof Error ? error.message : t('notice.error') });
      });

    return () => {
      mounted = false;
      unsubscribe();
      if (logcatProgressFrameRef.current !== null) {
        window.cancelAnimationFrame(logcatProgressFrameRef.current);
        logcatProgressFrameRef.current = null;
      }
      logcatProgressQueueRef.current = [];
      logcatProgressLatestRef.current = null;
    };
  }, [flushLogcatProgress, updateLogcatUiState]);

  const reportError = useCallback((error: unknown) => {
    const code = error instanceof BridgeError && typeof error.response?.error === 'object'
      ? error.response.error.code
      : undefined;
    setNotice({
      tone: code === 'user_cancelled' || code === 'operation_cancelled' ? 'warning' : 'error',
      message: error instanceof Error ? error.message : t('notice.error'),
    });
  }, [t]);

  const applyPreferences = useCallback((preferences: ModernPreferences) => {
    preferencesRef.current = preferences;
    setTheme(preferences.theme);
    onLocaleChange(preferences.locale);
    setHighContrast(preferences.highContrast);
    setReducedMotion(preferences.reducedMotion);
    setZoom(preferences.zoom);
    setExpertMode(preferences.expertMode);
    setApplicationPreferences(preferences);
  }, [onLocaleChange]);

  useEffect(() => {
    preferencesMountedRef.current = true;
    if (!isMockHost && !preferencesLoadRef.current) {
      const loading = bridge.getPreferences()
        .then((preferences) => {
          if (preferencesMountedRef.current) applyPreferences(preferences);
        })
        .catch((error: unknown) => {
          if (preferencesMountedRef.current) reportError(error);
          throw error;
        });
      preferencesLoadRef.current = loading;
      preferencesQueueRef.current = loading.then(() => undefined, () => undefined);
    }
    return () => {
      preferencesMountedRef.current = false;
    };
  }, [applyPreferences, isMockHost, reportError]);

  const changePreferences = useCallback((patch: Partial<Omit<ModernPreferences, 'schemaVersion'>>) => {
    setNotice(null);
    const update = preferencesQueueRef.current.then(async () => {
      const response = await bridge.updatePreferences(patch, snapshotRevisionRef.current);
      if (!preferencesMountedRef.current) return;
      applyPreferences(response.preferences);
      if (response.message.trim()) setNotice({ tone: 'success', message: response.message });
    });
    const completed = update.catch((error: unknown) => {
      if (preferencesMountedRef.current) reportError(error);
    });
    preferencesQueueRef.current = completed;
    return completed;
  }, [applyPreferences, reportError]);

  const changeTheme = useCallback((nextTheme: Theme) => {
    void changePreferences({ theme: nextTheme });
  }, [changePreferences]);

  const changeLocale = useCallback((nextLocale: Locale) => {
    void changePreferences({ locale: nextLocale });
  }, [changePreferences]);

  const changeHighContrast = useCallback((value: boolean) => {
    void changePreferences({ highContrast: value });
  }, [changePreferences]);

  const changeReducedMotion = useCallback((value: boolean) => {
    void changePreferences({ reducedMotion: value });
  }, [changePreferences]);

  const changeZoom = useCallback((value: number) => {
    void changePreferences({ zoom: Math.max(80, Math.min(200, value)) });
  }, [changePreferences]);

  const changeExpertMode = useCallback((value: boolean) => {
    void changePreferences({ expertMode: value });
  }, [changePreferences]);

  const changeMaintenancePreference = useCallback((
    field: 'automaticUpdateCheck' | 'checkDiskSpace' | 'checkBootloaderUnlocked' | 'checkFirmwareHash' | 'checkModuleUpdates' | 'showNotifications' | 'rebootTimeoutSeconds',
    value: boolean | number,
  ) => {
    void changePreferences({ [field]: value });
  }, [changePreferences]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const target = event.target instanceof Element ? event.target : null;
      const isFormControl = target?.matches('input, textarea, select, [contenteditable="true"]');
      if (event.altKey && !event.ctrlKey && !event.metaKey && /^[1-9]$/.test(event.key) && !isFormControl) {
        event.preventDefault();
        navigate(routeIds[Number(event.key) - 1]);
        return;
      }
      if (!(event.ctrlKey || event.metaKey) || event.altKey || isFormControl) return;
      if (event.key === '+' || event.key === '=') {
        event.preventDefault();
        changeZoom(preferencesRef.current.zoom + 10);
      } else if (event.key === '-') {
        event.preventDefault();
        changeZoom(preferencesRef.current.zoom - 10);
      } else if (event.key === '0') {
        event.preventDefault();
        changeZoom(100);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [changeZoom, navigate]);

  const respondToInteraction = useCallback(async (decision: 'accepted' | 'cancelled') => {
    if (!interaction || interactionBusy) return;
    setInteractionBusy(true);
    try {
      await bridge.command(
        commands.interactionRespond,
        { operationId: interaction.operationId, decision },
        interaction.expectedRevision,
      );
      setInteraction(null);
    } catch (error) {
      reportError(error);
      setInteraction(null);
    } finally {
      setInteractionBusy(false);
    }
  }, [interaction, interactionBusy, reportError]);

  useEffect(() => {
    if (!interaction) return;
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    window.requestAnimationFrame(() => interactionDialogRef.current?.querySelector<HTMLButtonElement>('button')?.focus());
    return () => previousFocus?.focus({ preventScroll: true });
  }, [interaction]);

  const runCommand = useCallback(async (
    command: BridgeCommand,
    payload: Record<string, unknown> = {},
    options: {
      returnCancelled?: boolean;
      returnFailed?: boolean;
      suppressNotice?: boolean;
      expectedRevision?: number;
      onOperationAccepted?: (operationId: string) => void;
    } = {},
  ): Promise<CommandResponse | null> => {
    setNotice(null);
    try {
      const expectedRevision = options.expectedRevision ?? snapshot.revision;
      const response = options.onOperationAccepted
        ? await bridge.command<Record<string, unknown>>(
            command,
            payload,
            expectedRevision,
            options.onOperationAccepted,
          )
        : await bridge.command<Record<string, unknown>>(
            command,
            payload,
            expectedRevision,
          );
      if (typeof response.revision === 'number') {
        setSnapshot((current) => ({ ...current, revision: response.revision ?? current.revision }));
      }
      const result = objectValue(response.result);
      const operationId = typeof result.operation_id === 'string' ? result.operation_id : '';
      if (operationId) {
        setSnapshot((current) => current.activeOperation?.id === operationId
          ? { ...current, activeOperation: null, active_operation: null }
          : current);
      }
      const status = normalizeOperationStatus(result.status);
      if (
        !options.suppressNotice
        && command !== commands.toolsPushFiles
        && status === 'success'
        && typeof result.message === 'string'
        && result.message.trim()
      ) {
        setNotice({ tone: 'success', message: result.message });
      }
      return response;
    } catch (error) {
      const code = error instanceof BridgeError && typeof error.response?.error === 'object'
        ? error.response.error.code
        : undefined;
      const errorDetails = error instanceof BridgeError
        ? objectValue(error.response?.error.details)
        : {};
      if (
        (options.returnCancelled || options.returnFailed)
        && error instanceof BridgeError
        && code !== 'confirmation_text_required'
        && (
          (options.returnCancelled && normalizeOperationStatus(errorDetails.status) === 'cancelled')
          || (options.returnFailed && normalizeOperationStatus(errorDetails.status) === 'failed')
        )
      ) {
        const revision = typeof errorDetails.revision === 'number' ? errorDetails.revision : undefined;
        const operationId = typeof errorDetails.operation_id === 'string'
          ? errorDetails.operation_id
          : '';
        setSnapshot((current) => ({
          ...current,
          ...(revision === undefined ? {} : { revision }),
          ...(operationId && current.activeOperation?.id === operationId
            ? { activeOperation: null, active_operation: null }
            : {}),
        }));
        return { result: errorDetails, revision };
      }
      if (error instanceof BridgeError && code === 'confirmation_text_required') {
        const result = errorDetails;
        const value = objectValue(result.value);
        const confirmation = objectValue(value.confirmation);
        const requiredText = typeof confirmation.required_text === 'string'
          ? confirmation.required_text
          : '';
        if (requiredText && !reinforcedResolveRef.current) {
          setReinforcedText('');
          setReinforcedChallenge({ command, payload, requiredText });
          return new Promise<CommandResponse | null>((resolve) => {
            reinforcedResolveRef.current = resolve;
          });
        }
      }
      if (!options.suppressNotice) reportError(error);
      return null;
    }
  }, [reportError, snapshot.revision]);

  const cancelUnsafeLogcat = useCallback((operationId: string) => runCommand(
    commands.operationCancel,
    { operationId },
    { returnFailed: true, suppressNotice: true },
  ), [runCommand]);
  useLogcatExpertGuard({
    expertMode,
    state: logcatUiState,
    setState: setLogcatUiState,
    cancelOperation: cancelUnsafeLogcat,
    clearBufferedProgress: purgeLogcatProgress,
  });

  const finishReinforcedChallenge = useCallback(async (accepted: boolean) => {
    const challenge = reinforcedChallenge;
    const resolve = reinforcedResolveRef.current;
    if (!challenge || !resolve || reinforcedBusy) return;
    if (!accepted) {
      reinforcedResolveRef.current = null;
      setReinforcedChallenge(null);
      setReinforcedText('');
      resolve(null);
      return;
    }
    if (reinforcedText !== challenge.requiredText) return;
    setReinforcedBusy(true);
    reinforcedResolveRef.current = null;
    setReinforcedChallenge(null);
    setReinforcedText('');
    try {
      const response = await runCommand(challenge.command, {
        ...challenge.payload,
        confirmationText: challenge.requiredText,
      });
      resolve(response);
    } finally {
      setReinforcedBusy(false);
    }
  }, [reinforcedBusy, reinforcedChallenge, reinforcedText, runCommand]);

  useEffect(() => {
    if (!reinforcedChallenge) return;
    window.requestAnimationFrame(() => reinforcedDialogRef.current?.querySelector<HTMLInputElement>('input')?.focus());
  }, [reinforcedChallenge]);

  const changeSelection = useCallback(async (serials: string[]) => {
    await runCommand(commands.deviceSelect, { serials });
  }, [runCommand]);

  const changeFirmware = useCallback(async (firmware: HostSnapshot['firmware']) => {
    // Firmware paths are backend-only. A different local package can only be
    // introduced through the native picker, which returns a purpose-bound grant.
    if (!firmware) throw new Error(t('notice.error'));
    if (firmware.id === snapshot.firmware?.id) return;
    if (!window.pixelflasher?.__mock) throw new Error(t('notice.error'));
    const response = await runCommand(commands.firmwareSelect, { firmwareId: firmware.id });
    if (!response) throw new Error(t('notice.error'));
  }, [runCommand, snapshot.firmware?.id, t]);

  const prepareFlash = useCallback(async (plan: FlashPlan): Promise<FlashPreview> => {
    setNotice(null);
    const serial = plan.serials[0];
    if (!serial) throw new Error(t('flash.needDevice'));
    const options: Record<string, unknown> = {};
    if (plan.slotTarget === 'both') options.slot = 'both';
    else if (plan.slotTarget === 'inactive') options.slot = 'inactive';
    else delete options.slot;
    options.dataBehavior = plan.mode === 'wipe' ? 'wipe' : 'preserve';
    options.wipe = plan.mode === 'wipe';
    options.verify = plan.verify;
    options.disableVerity = plan.disableVerity;
    options.disableVerification = plan.disableVerification;
    options.force = plan.force;
    options.noReboot = plan.noReboot;
    options.downgrade = plan.downgrade;
    options.temporaryRoot = plan.temporaryRoot;
    options.dryRun = plan.dryRun;
    const mode = plan.mode === 'ota'
      ? 'ota'
      : plan.mode === 'wipe'
        ? 'wipe'
        : plan.firmware.kind === 'custom' ? 'customFlash' : 'factory';

    try {
      const updated = await bridge.command<Record<string, unknown>>(
        commands.flashPlanUpdate,
        { mode, options },
        snapshot.revision,
      );
      const updatedRevision = updated.revision ?? snapshot.revision;
      setSnapshot((current) => ({ ...current, revision: updatedRevision }));
      const previewed = await bridge.command<Record<string, unknown>>(
        commands.flashPlanPreview,
        plan.serials.length > 1 ? {} : { serial },
        updatedRevision,
      );
      const result = objectValue(previewed.result);
      const value = objectValue(result.value);
      const compiled = objectValue(value.compiled);
      const confirmation = objectValue(compiled.confirmation);
      const compiledBatch = objectValue(compiled.batch);
      const batchPlans = Array.isArray(compiledBatch.plans)
        ? compiledBatch.plans.map(objectValue)
        : [];
      const compiledPlan = objectValue(compiled.plan);
      const compiledPlans = batchPlans.length ? batchPlans : [compiledPlan];
      const requests = compiledPlans.flatMap((item) => Array.isArray(item.requests) ? item.requests : []);
      const exactCommands = requests
        .map((request) => objectValue(request).argv)
        .filter((argv): argv is unknown[] => Array.isArray(argv))
        .map((argv) => argv.filter((argument): argument is string => typeof argument === 'string'))
        .filter((argv) => argv.length > 0);
      return {
        revision: previewed.revision ?? updatedRevision,
        destructive: compiled.destructive === true,
        requiredConfirmation: typeof confirmation.required_text === 'string' ? confirmation.required_text : '',
        label: batchPlans.length ? `${batchPlans.length} ${t('flash.review.targets')}` : typeof compiledPlan.label === 'string' ? compiledPlan.label : '',
        targetSerial: typeof compiledPlan.target_serial === 'string' ? compiledPlan.target_serial : serial,
        targetSerials: batchPlans.length
          ? batchPlans.map((item) => item.target_serial).filter((value): value is string => typeof value === 'string')
          : [typeof compiledPlan.target_serial === 'string' ? compiledPlan.target_serial : serial],
        expectedDeviceState: typeof compiledPlans[0]?.expected_device_state === 'string' ? compiledPlans[0].expected_device_state : '',
        dataBehavior: typeof compiledPlans[0]?.data_behavior === 'string' ? compiledPlans[0].data_behavior : '',
        partitions: [...new Set(compiledPlans.flatMap((item) => Array.isArray(item.partitions) ? item.partitions.filter((value): value is string => typeof value === 'string') : []))],
        slots: [...new Set(compiledPlans.flatMap((item) => Array.isArray(item.slots) ? item.slots.filter((value): value is string => typeof value === 'string') : []))],
        commands: exactCommands,
      };
    } catch (error) {
      reportError(error);
      throw error;
    }
  }, [reportError, snapshot.devices, snapshot.revision, t]);

  const startFlash = useCallback(async (plan: FlashPlan, confirmation: string, preview: FlashPreview) => {
    setNotice(null);
    const serial = plan.serials[0];
    if (!serial) throw new Error(t('flash.needDevice'));
    try {
      const payload: Record<string, unknown> = plan.serials.length > 1 ? {} : { serial };
      if (preview.requiredConfirmation) payload.confirmationText = confirmation;
      const response = await bridge.command<Record<string, unknown>>(
        commands.flashExecute,
        payload,
        preview.revision,
      );
      const result = objectValue(response.result);
      const status = normalizeOperationStatus(result.status);
      if (status === 'success' && typeof result.message === 'string' && result.message.trim()) {
        setNotice({ tone: 'success', message: result.message });
      }
      if (typeof response.revision === 'number') {
        setSnapshot((current) => ({ ...current, revision: response.revision ?? current.revision }));
      }
    } catch (error) {
      reportError(error);
      throw error;
    }
  }, [reportError, t]);

  const sharedProps = useMemo(() => ({ snapshot, selectedSerials, onSelectionChange: changeSelection, onCommand: runCommand }), [snapshot, selectedSerials, changeSelection, runCommand]);

  const content = (() => {
    switch (route) {
      case 'dashboard': return <DashboardPage {...sharedProps} />;
      case 'device': return <DevicePage {...sharedProps} expertMode={expertMode} />;
      case 'flash': return (
        <>
          <PageHeader title={t('flash.title')} subtitle={t('flash.subtitle')} />
          <FlashWizard
            devices={snapshot.devices}
            selectedSerials={selectedSerials}
            onSelectionChange={changeSelection}
            activeFirmware={snapshot.firmware}
            operation={snapshot.activeOperation}
            expertMode={expertMode}
            onFirmwareChange={changeFirmware}
            onPrepare={prepareFlash}
            onStart={startFlash}
          />
        </>
      );
      case 'firmware': return <FirmwarePage {...sharedProps} />;
      case 'root': return <RootPage {...sharedProps} />;
      case 'apps': return <AppsPage {...sharedProps} />;
      case 'backups': return <BackupsPage {...sharedProps} />;
      case 'tools': return (
        <ToolsPage
          {...sharedProps}
           expertMode={expertMode}
           logcatUiState={logcatUiState}
           logcatProgressBatch={logcatProgressBatch}
           onLogcatUiStateChange={updateLogcatUiState}
          pushUiState={pushUiState}
          onPushUiStateChange={setPushUiState}
        />
      );
      case 'settings': return (
        <SettingsPage
          theme={theme}
          onThemeChange={changeTheme}
          locale={locale}
          onLocaleChange={changeLocale}
          highContrast={highContrast}
          onHighContrastChange={changeHighContrast}
          reducedMotion={reducedMotion}
          onReducedMotionChange={changeReducedMotion}
          zoom={zoom}
          onZoomChange={changeZoom}
          expertMode={expertMode}
          onExpertModeChange={changeExpertMode}
          preferences={applicationPreferences}
          onMaintenancePreferenceChange={changeMaintenancePreference}
        />
      );
    }
  })();

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">{t('skip.content')}</a>
      <aside className="sidebar">
        <div className="brand">
          <img src={assets.appLogo} width="42" height="42" alt="" aria-hidden="true" />
          <span><strong>PixelFlasher</strong><small>{t('app.tagline')}</small></span>
        </div>
        <span className="nav-label">{t('nav.tasks')}</span>
        <nav className="task-nav" aria-label={t('nav.tasks')}>
          {routeIds.map((item, index) => (
            <button
              type="button"
              className={route === item ? 'is-active' : ''}
              onClick={() => navigate(item)}
              aria-label={t(`nav.${item}`)}
              aria-current={route === item ? 'page' : undefined}
              aria-keyshortcuts={`Alt+${index + 1}`}
              key={item}
            >
              <Icon name={navIcons[item]} size={20} />
              <span>{t(`nav.${item}`)}</span>
              <kbd>{index + 1}</kbd>
            </button>
          ))}
        </nav>
        <div className="sidebar__spacer" />
        <label className="expert-toggle">
          <span><Icon name="tools" size={18} /><strong>{t('mode.expert')}</strong></span>
          <input type="checkbox" checked={expertMode} onChange={(event) => changeExpertMode(event.currentTarget.checked)} aria-label={t('mode.expert')} />
          <span className="expert-toggle__track" aria-hidden="true"><span /></span>
        </label>
        <div className="sidebar__meta">
          <span className={`connection-dot connection-dot--${bridgeState}`} />
          <span>{bridgeState === 'ready' ? t('status.ready') : bridgeState === 'connecting' ? t('status.connecting') : t('status.error')}</span>
          {window.pixelflasher?.__mock ? <Badge tone="neutral">Mock</Badge> : null}
        </div>
      </aside>

      <div className="workspace">
        <div className="workspace-toolbar">
          <div className="device-context">
            <span className="device-context__icon"><Icon name="devices" size={18} /></span>
            <span><strong>{selectedSerials.length || snapshot.devices.length}</strong><small>{t('status.devices', { count: snapshot.devices.length })}</small></span>
          </div>
          <div className="toolbar-controls">
            <div className="mini-segmented" role="group" aria-label={t('settings.theme')}>
              <button type="button" onClick={() => changeTheme('dark')} aria-pressed={theme === 'dark'}>{t('settings.dark')}</button>
              <button type="button" onClick={() => changeTheme('light')} aria-pressed={theme === 'light'}>{t('settings.light')}</button>
            </div>
            <label className="toolbar-locale">
              <span className="sr-only">{t('settings.language')}</span>
              <select value={locale} onChange={(event) => changeLocale(event.currentTarget.value as Locale)}>
                {localeOptions.map((option) => <option value={option.value} key={option.value}>{option.label}</option>)}
              </select>
            </label>
          </div>
        </div>
        <main id="main-content" className="main-content" tabIndex={-1}>
          {notice ? (
            <div className={`global-notice global-notice--${notice.tone}`} role={notice.tone === 'error' ? 'alert' : 'status'}>
              <Icon name={notice.tone === 'success' ? 'check' : 'warningPng'} size={20} />
              <span>{notice.message}</span>
              <button type="button" onClick={() => setNotice(null)} aria-label={t('notice.dismiss')}>
                <Icon name="close" size={16} />
              </button>
            </div>
          ) : null}
          {content}
        </main>
        <footer className="status-bar">
          <span><span className="status-dot" />{t('status.ready')}</span>
          <span>ADB / Fastboot</span>
          <span>{t('status.devices', { count: snapshot.devices.length })}</span>
          <span>{t('settings.zoom')} {zoom}%</span>
          <span className="status-bar__spacer" />
          <span>{t('status.revision', { revision: snapshot.revision })}</span>
        </footer>
      </div>
      {interaction ? (
        <div className="interaction-backdrop">
          <section
            ref={interactionDialogRef}
            className={`interaction-dialog ${interaction.destructive ? 'interaction-dialog--danger' : ''}`}
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="interaction-title"
            aria-describedby="interaction-message"
            onKeyDown={(event) => {
              if (event.key === 'Escape') {
                event.preventDefault();
                void respondToInteraction('cancelled');
                return;
              }
              if (event.key !== 'Tab') return;
              const controls = Array.from(interactionDialogRef.current?.querySelectorAll<HTMLButtonElement>('button:not(:disabled)') ?? []);
              if (!controls.length) return;
              const currentIndex = controls.indexOf(document.activeElement as HTMLButtonElement);
              const nextIndex = event.shiftKey
                ? (currentIndex <= 0 ? controls.length - 1 : currentIndex - 1)
                : (currentIndex >= controls.length - 1 ? 0 : currentIndex + 1);
              event.preventDefault();
              controls[nextIndex].focus();
            }}
          >
            <span className="interaction-dialog__icon"><Icon name={interaction.destructive ? 'warningPng' : 'shield'} size={26} /></span>
            <div className="interaction-dialog__copy">
              <span className="interaction-dialog__eyebrow">{interaction.targetSerial ?? t('flash.review.targets')}</span>
              <h2 id="interaction-title">{interaction.destructive ? t('flash.confirm.title') : t('common.apply')}</h2>
              <p id="interaction-message">{interaction.message}</p>
            </div>
            <div className="interaction-dialog__actions">
              <button type="button" className="button button--ghost" onClick={() => void respondToInteraction('cancelled')} disabled={interactionBusy}>{t('common.cancel')}</button>
              <button type="button" className="button button--primary" onClick={() => void respondToInteraction('accepted')} disabled={interactionBusy}>{t('common.continue')}</button>
            </div>
          </section>
        </div>
      ) : null}
      {reinforcedChallenge ? (
        <div className="interaction-backdrop">
          <section
            ref={reinforcedDialogRef}
            className="interaction-dialog interaction-dialog--danger"
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="reinforced-title"
            aria-describedby="reinforced-message"
            onKeyDown={(event) => {
              if (event.key === 'Escape') {
                event.preventDefault();
                void finishReinforcedChallenge(false);
                return;
              }
              if (event.key !== 'Tab') return;
              const controls = Array.from(reinforcedDialogRef.current?.querySelectorAll<HTMLElement>('input:not(:disabled), button:not(:disabled)') ?? []);
              if (!controls.length) return;
              const currentIndex = controls.indexOf(document.activeElement as HTMLElement);
              const nextIndex = event.shiftKey
                ? (currentIndex <= 0 ? controls.length - 1 : currentIndex - 1)
                : (currentIndex >= controls.length - 1 ? 0 : currentIndex + 1);
              event.preventDefault();
              controls[nextIndex].focus();
            }}
          >
            <span className="interaction-dialog__icon"><Icon name="warningPng" size={26} /></span>
            <div className="interaction-dialog__copy">
              <span className="interaction-dialog__eyebrow">{t('device.bootloader')}</span>
              <h2 id="reinforced-title">{t('flash.confirm.title')}</h2>
              <p id="reinforced-message">{t('flash.confirm.detail', { confirmation: reinforcedChallenge.requiredText })}</p>
              <label className="reinforced-confirmation-field">
                <span className="sr-only">{reinforcedChallenge.requiredText}</span>
                <input
                  type="text"
                  value={reinforcedText}
                  onChange={(event) => setReinforcedText(event.currentTarget.value)}
                  placeholder={reinforcedChallenge.requiredText}
                  autoComplete="off"
                  spellCheck={false}
                />
              </label>
            </div>
            <div className="interaction-dialog__actions">
              <button type="button" className="button button--ghost" onClick={() => void finishReinforcedChallenge(false)} disabled={reinforcedBusy}>{t('common.cancel')}</button>
              <button type="button" className="button button--primary" onClick={() => void finishReinforcedChallenge(true)} disabled={reinforcedBusy || reinforcedText !== reinforcedChallenge.requiredText}>{t('common.continue')}</button>
            </div>
          </section>
        </div>
      ) : null}
    </div>
  );
}
