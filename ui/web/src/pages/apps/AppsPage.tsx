import { useEffect, useMemo, useRef, useState } from 'react';
import { commands } from '../../commands';
import { demoApps } from '../../demoData';
import { useI18n } from '../../i18n';
import type { HostSnapshot } from '../../types';
import { Badge, Button, Card, CardTitle, EmptyState, Icon, PageHeader, Toggle } from '../../components/ui';
import { isToolchainReady, record, selectedGrant, type SharedPageProps } from '../shared';

type PackageRow = (typeof demoApps)[number];

type InstallOptions = {
  replace: boolean;
  grantPermissions: boolean;
  allowDowngrade: boolean;
  allowTest: boolean;
  forceQueryable: boolean;
  bypassLowTargetSdk: boolean;
};

type InstalledApkIdentity = {
  packageName: string;
  sha256: string;
};

type InstallState =
  | { phase: 'idle' }
  | { phase: 'picking' | 'installing' | 'cancelling' }
  | { phase: 'cancelled' }
  | { phase: 'error'; code?: string }
  | { phase: 'success'; identity: InstalledApkIdentity; inventoryRefreshed: boolean };

const PACKAGE_NAME = /^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$/;
const SHA256 = /^[0-9a-f]{64}$/i;
const SAFE_CODE = /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/;

function operationStatus(result: Record<string, unknown>) {
  return typeof result.status === 'string' ? result.status.toLowerCase() : '';
}

function resultCode(result: Record<string, unknown>) {
  return typeof result.code === 'string' && SAFE_CODE.test(result.code) ? result.code : undefined;
}

function installedIdentity(result: Record<string, unknown>): InstalledApkIdentity | null {
  const value = record(result.value);
  const identity = record(value.apkIdentity);
  if (
    value.action !== 'install'
    || identity.verified !== true
    || typeof identity.packageName !== 'string'
    || !PACKAGE_NAME.test(identity.packageName)
    || typeof identity.sha256 !== 'string'
    || !SHA256.test(identity.sha256)
  ) return null;
  return { packageName: identity.packageName, sha256: identity.sha256.toLowerCase() };
}

function packageRows(result: Record<string, unknown>): PackageRow[] | null {
  if (operationStatus(result) !== 'success') return null;
  const value = record(result.value);
  if (!Array.isArray(value.packages)) return null;
  return value.packages.flatMap((entry) => {
    const item = record(entry);
    if (typeof item.package !== 'string' || !PACKAGE_NAME.test(item.package)) return [];
    return [{
      id: item.package,
      name: item.package,
      version: '—',
      scope: String(item.apk_path ?? '').startsWith('/system') ? 'System' : 'User',
      enabled: true,
    } satisfies PackageRow];
  });
}

export function AppsPage({ snapshot, selectedSerials, onCommand }: SharedPageProps) {
  const { t } = useI18n();
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<string[]>([]);
  const [action, setAction] = useState<'enable' | 'disable'>('disable');
  const [listedApps, setListedApps] = useState<PackageRow[]>([]);
  const [inventoryBusy, setInventoryBusy] = useState(false);
  const [installState, setInstallState] = useState<InstallState>({ phase: 'idle' });
  const [installOptions, setInstallOptions] = useState<InstallOptions>({
    replace: true,
    grantPermissions: false,
    allowDowngrade: false,
    allowTest: false,
    forceQueryable: false,
    bypassLowTargetSdk: false,
  });
  const installEpoch = useRef(0);
  const feedbackRef = useRef<HTMLElement>(null);
  const snapshotApps = (snapshot as HostSnapshot & { apps?: PackageRow[] }).apps;
  const available = window.pixelflasher?.__mock
    ? demoApps
    : listedApps.length
      ? listedApps
      : Array.isArray(snapshotApps) ? snapshotApps : [];
  const filtered = useMemo(
    () => available.filter((app) => `${app.name} ${app.id}`.toLowerCase().includes(query.toLowerCase())),
    [available, query],
  );
  const serial = selectedSerials.length === 1 ? selectedSerials[0] : '';
  const device = snapshot.devices.find((candidate) => candidate.serial === serial);
  const activeOperation = snapshot.activeOperation ?? snapshot.active_operation;
  const operationRunning = Boolean(
    activeOperation && ['pending', 'running'].includes(activeOperation.status.toLowerCase()),
  );
  const installBusy = ['picking', 'installing', 'cancelling'].includes(installState.phase);
  const deviceReady = Boolean(serial && device?.mode === 'adb' && isToolchainReady(snapshot));
  const installReady = deviceReady && (!operationRunning || installBusy);
  const cancellableOperation = ['installing', 'cancelling'].includes(installState.phase)
    && operationRunning
    ? activeOperation
    : null;

  useEffect(() => {
    installEpoch.current += 1;
    setInstallState({ phase: 'idle' });
  }, [device?.mode, serial, selectedSerials.length]);

  useEffect(() => () => { installEpoch.current += 1; }, []);

  useEffect(() => {
    if (['success', 'cancelled', 'error'].includes(installState.phase)) {
      window.requestAnimationFrame(() => feedbackRef.current?.focus());
    }
  }, [installState.phase]);

  const refreshPackages = async (allowWhileBusy = false, expectedEpoch?: number) => {
    if (!deviceReady || (inventoryBusy && !allowWhileBusy)) return false;
    if (!allowWhileBusy) setInventoryBusy(true);
    try {
      const response = await onCommand(commands.appsList, { serial, scope: 'all' });
      if (expectedEpoch !== undefined && installEpoch.current !== expectedEpoch) return false;
      if (!response) return false;
      const packages = packageRows(record(response.result));
      if (!packages) return false;
      setListedApps(packages);
      setSelected([]);
      return true;
    } catch {
      return false;
    } finally {
      if (!allowWhileBusy) setInventoryBusy(false);
    }
  };

  const applyAction = async () => {
    if (!deviceReady || !selected.length || inventoryBusy || installBusy) return;
    setInventoryBusy(true);
    try {
      const response = await onCommand(commands.appsAction, { serial, packages: selected, action });
      if (!response || operationStatus(record(response.result)) !== 'success') return;
      setListedApps((apps) => apps.map((app) => selected.includes(app.id)
        ? { ...app, enabled: action === 'enable' }
        : app));
      setSelected([]);
    } finally {
      setInventoryBusy(false);
    }
  };

  const installApk = async () => {
    if (!installReady || installBusy || inventoryBusy) return;
    const epoch = installEpoch.current + 1;
    installEpoch.current = epoch;
    setInstallState({ phase: 'picking' });
    try {
      const picked = await onCommand(commands.nativePickFile, {
        purpose: 'apps.install.source',
        title: t('apps.install'),
        filters: [{ label: t('apps.apkFiles'), extensions: ['apk'] }],
      }, { returnCancelled: true });
      if (installEpoch.current !== epoch) return;
      const pickerResult = record(picked?.result);
      if (operationStatus(pickerResult) === 'cancelled') {
        setInstallState({ phase: 'cancelled' });
        return;
      }
      const grant = selectedGrant(picked);
      if (!picked || operationStatus(pickerResult) !== 'success' || !grant) {
        setInstallState({ phase: 'error', code: resultCode(pickerResult) });
        return;
      }

      setInstallState({ phase: 'installing' });
      const response = await onCommand(commands.appsAction, {
        serial,
        action: 'install',
        grant,
        options: installOptions,
      }, { returnCancelled: true });
      if (installEpoch.current !== epoch) return;
      const result = record(response?.result);
      if (operationStatus(result) === 'cancelled') {
        setInstallState({ phase: 'cancelled' });
        return;
      }
      const identity = operationStatus(result) === 'success' ? installedIdentity(result) : null;
      if (!response || !identity) {
        setInstallState({ phase: 'error', code: resultCode(result) ?? 'invalid_install_result' });
        return;
      }
      const inventoryRefreshed = await refreshPackages(true, epoch);
      if (installEpoch.current === epoch) {
        setInstallState({ phase: 'success', identity, inventoryRefreshed });
      }
    } catch {
      if (installEpoch.current === epoch) setInstallState({ phase: 'error' });
    }
  };

  const cancelInstall = async () => {
    if (!cancellableOperation || installState.phase !== 'installing') return;
    setInstallState({ phase: 'cancelling' });
    try {
      const response = await onCommand(commands.operationCancel, {
        operationId: cancellableOperation.id,
      });
      if (!response || operationStatus(record(response.result)) !== 'success') {
        setInstallState({ phase: 'installing' });
      }
    } catch {
      setInstallState({ phase: 'installing' });
    }
  };

  const setInstallOption = (name: keyof InstallOptions, value: boolean) => {
    setInstallOptions((current) => ({ ...current, [name]: value }));
  };

  return (
    <>
      <PageHeader
        title={t('apps.title')}
        subtitle={t('apps.subtitle')}
        actions={(
          <div className="page-header__controls">
            <Button icon="scan" onClick={() => void refreshPackages()} disabled={!deviceReady || inventoryBusy || installBusy}>{t('common.refresh')}</Button>
            <label className="toolbar-locale">
              <span className="sr-only">{t('common.apply')}</span>
              <select value={action} onChange={(event) => setAction(event.currentTarget.value as 'enable' | 'disable')} disabled={inventoryBusy || installBusy}>
                <option value="disable">{t('common.disabled')}</option>
                <option value="enable">{t('common.enabled')}</option>
              </select>
            </label>
            <Button variant="primary" icon="check" onClick={() => void applyAction()} disabled={inventoryBusy || installBusy || !selected.length || !deviceReady || !available.length}>{t('common.apply')}</Button>
          </div>
        )}
      />
      <Card className="apps-install-card" aria-busy={installBusy}>
        <CardTitle icon="android">{t('apps.install')}</CardTitle>
        {!deviceReady && !installBusy ? (
          <div className="inline-alert inline-alert--warning apps-install-card__guard" role="status">
            <Icon name="warning" size={18} />
            <span>{t('apps.installGuard')}</span>
          </div>
        ) : null}
        <fieldset className="toggle-stack apps-install-options" disabled={installBusy || inventoryBusy}>
          <legend className="sr-only">{t('apps.installOptions')}</legend>
          <Toggle checked={installOptions.replace} onChange={(value) => setInstallOption('replace', value)} label={t('apps.replace')} description={t('apps.replaceDetail')} disabled={installBusy || inventoryBusy} />
          <Toggle checked={installOptions.grantPermissions} onChange={(value) => setInstallOption('grantPermissions', value)} label={t('apps.grantPermissions')} description={t('apps.grantPermissionsDetail')} disabled={installBusy || inventoryBusy} />
          <Toggle checked={installOptions.allowDowngrade} onChange={(value) => setInstallOption('allowDowngrade', value)} label={t('apps.allowDowngrade')} description={t('apps.allowDowngradeDetail')} disabled={installBusy || inventoryBusy} />
          <Toggle checked={installOptions.allowTest} onChange={(value) => setInstallOption('allowTest', value)} label={t('apps.allowTest')} description={t('apps.allowTestDetail')} disabled={installBusy || inventoryBusy} />
          <Toggle checked={installOptions.forceQueryable} onChange={(value) => setInstallOption('forceQueryable', value)} label={t('apps.forceQueryable')} description={t('apps.forceQueryableDetail')} disabled={installBusy || inventoryBusy} />
          <Toggle checked={installOptions.bypassLowTargetSdk} onChange={(value) => setInstallOption('bypassLowTargetSdk', value)} label={t('apps.bypassLowTargetSdk')} description={t('apps.bypassLowTargetSdkDetail')} disabled={installBusy || inventoryBusy} />
        </fieldset>
        <div className="apps-install-card__actions">
          <Button variant="primary" icon="download" onClick={() => void installApk()} disabled={!installReady || installBusy || inventoryBusy}>
            {t(installState.phase === 'picking' ? 'apps.picking' : installState.phase === 'installing' || installState.phase === 'cancelling' ? 'apps.installing' : 'apps.chooseApk')}
          </Button>
          {cancellableOperation ? (
            <Button variant="danger" onClick={() => void cancelInstall()} disabled={installState.phase === 'cancelling'}>
              {t(installState.phase === 'cancelling' ? 'apps.cancelling' : 'apps.cancelInstall')}
            </Button>
          ) : null}
        </div>
        {installState.phase === 'picking' || installState.phase === 'installing' || installState.phase === 'cancelling' ? (
          <div className="apps-install-feedback" role="status" aria-live="polite">
            <Icon name="processFile" size={18} />
            <span>{t(installState.phase === 'picking' ? 'apps.picking' : installState.phase === 'cancelling' ? 'apps.cancelling' : 'apps.installing')}</span>
          </div>
        ) : null}
        {installState.phase === 'cancelled' ? (
          <section className="apps-install-feedback" ref={feedbackRef} tabIndex={-1} role="status">
            <Icon name="warning" size={18} />
            <span>{t('apps.installCancelled')}</span>
          </section>
        ) : null}
        {installState.phase === 'error' ? (
          <section className="apps-install-feedback apps-install-feedback--error" ref={feedbackRef} tabIndex={-1} role="alert">
            <Icon name="warning" size={18} />
            <span>{t('apps.installFailed')}{installState.code ? <code>{installState.code}</code> : null}</span>
          </section>
        ) : null}
        {installState.phase === 'success' ? (
          <section className="apps-install-feedback apps-install-feedback--success" ref={feedbackRef} tabIndex={-1} role="status">
            <Icon name="check" size={18} />
            <span>
              {t('apps.installSucceeded', { package: installState.identity.packageName })}
              {!installState.inventoryRefreshed ? <small>{t('apps.inventoryRefreshFailed')}</small> : null}
            </span>
          </section>
        ) : null}
      </Card>
      <Card>
        <div className="table-toolbar">
          <CardTitle icon="android">{t('apps.title')}</CardTitle>
          <label className="search-field">
            <Icon name="scan" size={18} />
            <span className="sr-only">{t('apps.filter')}</span>
            <input type="search" value={query} onChange={(event) => setQuery(event.currentTarget.value)} placeholder={t('apps.filter')} />
          </label>
        </div>
        <div className="data-table" role="table" aria-label={t('apps.title')}>
          <div className="data-table__head" role="row">
            <span role="columnheader"><span className="sr-only">{t('common.selected')}</span></span>
            <span role="columnheader">{t('apps.package')}</span>
            <span role="columnheader">{t('apps.version')}</span>
            <span role="columnheader">{t('apps.scope')}</span>
            <span role="columnheader">{t('apps.state')}</span>
          </div>
          {filtered.map((app) => (
            <div className="data-table__row" role="row" key={app.id}>
              <span role="cell"><input type="checkbox" checked={selected.includes(app.id)} onChange={() => setSelected((value) => value.includes(app.id) ? value.filter((id) => id !== app.id) : [...value, app.id])} aria-label={`${t('apps.package')}: ${app.name}`} /></span>
              <span role="cell"><strong>{app.name}</strong><small>{app.id}</small></span>
              <span role="cell">{app.version}</span>
              <span role="cell">{t(app.scope === 'System' ? 'common.system' : 'common.user')}</span>
              <span role="cell"><Badge tone={app.enabled ? 'success' : 'neutral'}>{t(app.enabled ? 'common.enabled' : 'common.disabled')}</Badge></span>
            </div>
          ))}
          {!available.length ? <EmptyState icon="android" title={t('common.none')} detail={t('apps.subtitle')} /> : null}
        </div>
      </Card>
    </>
  );
}
