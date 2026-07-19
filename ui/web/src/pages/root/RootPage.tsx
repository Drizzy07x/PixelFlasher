import { useEffect, useRef, useState } from 'react';
import { assets } from '../../assets';
import { commands } from '../../commands';
import { useI18n } from '../../i18n';
import { Badge, Button, Card, CardTitle, EmptyState, Icon, PageHeader } from '../../components/ui';
import { record, selectedGrant, type SharedPageProps } from '../shared';

interface RootAppEntry {
  id: string;
  provider: string;
  flavor: string;
  version: string;
  sha256: string;
  provenance: string;
}

interface RootModuleEntry {
  id: string;
}

interface BootInventoryEntry {
  bootId: string;
  sha256: string;
  size: number;
  provenance: string;
  createdAt: number;
  partition: 'boot' | 'init_boot' | 'vendor_boot' | 'vendor_kernel_boot';
  deviceCodenames: string[];
  patcher: string;
  patcherVersion: string;
  signature: string;
  sourceHash: string;
  patched: boolean;
  verified: boolean;
}

const bootEntryFields = [
  'bootId',
  'sha256',
  'size',
  'provenance',
  'createdAt',
  'partition',
  'deviceCodenames',
  'patcher',
  'patcherVersion',
  'signature',
  'sourceHash',
  'patched',
  'verified',
] as const;

function parseBootEntry(value: unknown): BootInventoryEntry | null {
  const entry = record(value);
  const keys = Object.keys(entry).sort();
  const expected = [...bootEntryFields].sort();
  const partition = entry.partition;
  if (
    keys.length !== expected.length || !keys.every((key, index) => key === expected[index]) ||
    typeof entry.bootId !== 'string' || !/^[0-9a-f]{32}$/.test(entry.bootId) ||
    typeof entry.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(entry.sha256) ||
    typeof entry.size !== 'number' || !Number.isSafeInteger(entry.size) || entry.size < 0 ||
    typeof entry.provenance !== 'string' || !entry.provenance ||
    typeof entry.createdAt !== 'number' || !Number.isSafeInteger(entry.createdAt) || entry.createdAt < 0 ||
    typeof partition !== 'string' || !['boot', 'init_boot', 'vendor_boot', 'vendor_kernel_boot'].includes(partition) ||
    !Array.isArray(entry.deviceCodenames) || !entry.deviceCodenames.every((item) => typeof item === 'string') ||
    typeof entry.patcher !== 'string' || typeof entry.patcherVersion !== 'string' ||
    typeof entry.signature !== 'string' || typeof entry.sourceHash !== 'string' ||
    typeof entry.patched !== 'boolean' || typeof entry.verified !== 'boolean'
  ) return null;
  return entry as unknown as BootInventoryEntry;
}

function providerKey(provider: string) {
  const normalized = provider.trim().toLowerCase().replaceAll(' ', '-');
  if (normalized === 'wild-ksu') return 'wild_ksu';
  if (normalized === 'kernelsu-legacy') return 'kernelsu';
  return normalized;
}

function patchProvider(method: string) {
  const providers: Record<string, string> = {
    magisk: 'magisk',
    apatch: 'apatch',
    kernelsu: 'kernelsu',
    'kernelsu-next': 'kernelsu-next',
    sukisu: 'sukisu',
    'wild-ksu': 'wild_ksu',
    legacy: 'kernelsu',
  };
  return providers[method] ?? '';
}

function methodForProvider(provider: string) {
  const providerName = provider.trim().toLowerCase().replaceAll(' ', '-');
  if (providerName === 'kernelsu-legacy') return 'legacy';
  const normalized = providerKey(provider);
  if (normalized === 'wild_ksu') return 'wild-ksu';
  return ['magisk', 'apatch', 'kernelsu', 'kernelsu-next', 'sukisu'].includes(normalized)
    ? normalized
    : '';
}

export function RootPage({ snapshot, selectedSerials, onCommand }: SharedPageProps) {
  const { t } = useI18n();
  type RootMethod = { id: string; name: string; version: string; icon: 'magisk' | 'kernelSu' | 'apatch' | 'sukiSu' | 'wildKsu'; detail: string };
  const methodCatalog: RootMethod[] = [
    { id: 'magisk', name: 'Magisk', version: '28.1', icon: 'magisk', detail: t('root.magiskDetail') },
    { id: 'kernelsu', name: 'KernelSU', version: '1.0.2', icon: 'kernelSu', detail: t('root.kernelSuDetail') },
    { id: 'kernelsu-next', name: 'KernelSU Next', version: '—', icon: 'kernelSu', detail: t('root.kernelSuDetail') },
    { id: 'apatch', name: 'APatch', version: '11039', icon: 'apatch', detail: t('root.apatchDetail') },
    { id: 'sukisu', name: 'SukiSU Ultra', version: '2.0', icon: 'sukiSu', detail: t('root.sukisuDetail') },
    { id: 'wild-ksu', name: 'Wild_KSU', version: '—', icon: 'wildKsu', detail: t('root.kernelSuDetail') },
    { id: 'legacy', name: 'KernelSU Legacy', version: '—', icon: 'kernelSu', detail: t('root.kernelSuDetail') },
  ];
  const [rootApps, setRootApps] = useState<RootAppEntry[]>([]);
  const [appsLoaded, setAppsLoaded] = useState(false);
  const [modules, setModules] = useState<RootModuleEntry[]>([]);
  const [modulesLoaded, setModulesLoaded] = useState(false);
  const [bootImages, setBootImages] = useState<BootInventoryEntry[]>([]);
  const [bootImagesLoaded, setBootImagesLoaded] = useState(false);
  const [bootPartition, setBootPartition] = useState<BootInventoryEntry['partition']>('boot');
  const [confirmBootDelete, setConfirmBootDelete] = useState('');
  const [bootDeleteNotice, setBootDeleteNotice] = useState<'failed' | 'deferred' | ''>('');
  const [busy, setBusy] = useState('');
  const [apatchPromptOpen, setApatchPromptOpen] = useState(false);
  const [apatchSecret, setApatchSecret] = useState('');
  const apatchResolverRef = useRef<((value: string | null) => void) | null>(null);
  const apatchDialogRef = useRef<HTMLElement>(null);
  const apatchInputRef = useRef<HTMLInputElement>(null);
  const bootDeleteConfirmRef = useRef<HTMLButtonElement>(null);
  const inventoryMethods = rootApps.flatMap((app) => {
    const id = methodForProvider(app.provider);
    const definition = methodCatalog.find((entry) => entry.id === id);
    return definition ? [{ ...definition, version: app.version }] : [];
  }).filter((entry, index, entries) => entries.findIndex((candidate) => candidate.id === entry.id) === index);
  const methods: readonly RootMethod[] = window.pixelflasher?.__mock
    ? methodCatalog
    : inventoryMethods;
  const [method, setMethod] = useState<string>(() => window.pixelflasher?.__mock ? 'magisk' : '');
  const primary = selectedSerials.length === 1
    ? snapshot.devices.find((device) => device.serial === selectedSerials[0])
    : undefined;
  const singleAdb = selectedSerials.length === 1 && primary?.mode === 'adb';
  const rootedAdb = singleAdb && primary?.rooted === true;
  const compatibleApps = rootApps.filter((app) => providerKey(app.provider) === patchProvider(method));
  const compatibleApp = compatibleApps.find((app) => methodForProvider(app.provider) === method) ?? compatibleApps[0];

  useEffect(() => {
    if (!apatchPromptOpen) return;
    window.requestAnimationFrame(() => apatchInputRef.current?.focus());
  }, [apatchPromptOpen]);

  useEffect(() => {
    if (!confirmBootDelete) return;
    window.requestAnimationFrame(() => bootDeleteConfirmRef.current?.focus());
  }, [confirmBootDelete]);

  useEffect(() => () => {
    apatchResolverRef.current?.(null);
    apatchResolverRef.current = null;
  }, []);

  const requestApatchSecret = () => new Promise<string | null>((resolve) => {
    apatchResolverRef.current = resolve;
    setApatchSecret('');
    setApatchPromptOpen(true);
  });

  const finishApatchPrompt = (value: string | null) => {
    const resolve = apatchResolverRef.current;
    apatchResolverRef.current = null;
    setApatchSecret('');
    setApatchPromptOpen(false);
    resolve?.(value);
  };

  const refreshRootApps = async () => {
    if (busy) return;
    setBusy('apps-list');
    try {
      const response = await onCommand(commands.rootAppsList);
      if (!response) return;
      const value = record(record(response.result).value);
      const parsed = (Array.isArray(value.apps) ? value.apps : []).flatMap((entry) => {
        const app = record(entry);
        if (
          typeof app.id !== 'string' || !/^[0-9a-f]{64}$/i.test(app.id) ||
          typeof app.provider !== 'string' || !app.provider ||
          typeof app.flavor !== 'string' ||
          typeof app.version !== 'string' ||
          typeof app.sha256 !== 'string' || !/^[0-9a-f]{64}$/i.test(app.sha256) ||
          typeof app.provenance !== 'string'
        ) return [];
        return [{
          id: app.id,
          provider: app.provider,
          flavor: app.flavor,
          version: app.version,
          sha256: app.sha256,
          provenance: app.provenance,
        }];
      });
      setRootApps(parsed);
      setAppsLoaded(true);
      setMethod((current) => {
        const availableMethods = parsed.map((app) => methodForProvider(app.provider)).filter(Boolean);
        if (current && availableMethods.includes(current)) return current;
        return availableMethods[0] ?? '';
      });
    } finally {
      setBusy('');
    }
  };

  const installRootApp = async (appId: string) => {
    if (!singleAdb || !primary || busy) return;
    setBusy(`app:${appId}`);
    try {
      await onCommand(commands.rootAppsInstall, { serial: primary.serial, appId });
    } finally {
      setBusy('');
    }
  };

  const refreshModules = async () => {
    if (!rootedAdb || !primary || busy) return;
    setBusy('modules-list');
    try {
      const response = await onCommand(commands.rootModulesList, { serial: primary.serial });
      if (!response) return;
      const value = record(record(response.result).value);
      const parsed = (Array.isArray(value.modules) ? value.modules : []).flatMap((entry) => {
        const module = record(entry);
        return typeof module.id === 'string' && /^[A-Za-z][A-Za-z0-9._-]{0,63}$/.test(module.id)
          ? [{ id: module.id }]
          : [];
      });
      setModules(parsed);
      setModulesLoaded(true);
    } finally {
      setBusy('');
    }
  };

  const runModuleAction = async (action: 'enable' | 'disable' | 'remove', moduleId: string) => {
    if (!rootedAdb || !primary || busy) return;
    setBusy(`module:${action}:${moduleId}`);
    try {
      const response = await onCommand(commands.rootModulesAction, { serial: primary.serial, action, moduleId });
      if (response && action === 'remove') {
        setModules((current) => current.filter((module) => module.id !== moduleId));
      }
    } finally {
      setBusy('');
    }
  };

  const installModule = async () => {
    if (!rootedAdb || !primary || busy) return;
    setBusy('module:install');
    try {
      const picked = await onCommand(commands.nativePickFile, {
        purpose: 'root.modules.install',
        title: t('root.moduleInstall'),
        filters: [{ label: t('root.modulesTitle'), extensions: ['zip'] }],
      });
      const grant = selectedGrant(picked);
      if (!grant) return;
      const response = await onCommand(commands.rootModulesAction, { serial: primary.serial, action: 'install', grant });
      if (!response) return;
      const value = record(record(response.result).value);
      if (typeof value.moduleId === 'string' && /^[A-Za-z][A-Za-z0-9._-]{0,63}$/.test(value.moduleId)) {
        setModules((current) => current.some((module) => module.id === value.moduleId)
          ? current
          : [...current, { id: value.moduleId as string }]);
        setModulesLoaded(true);
      }
    } finally {
      setBusy('');
    }
  };

  const refreshBootImages = async () => {
    if (busy) return;
    setBusy('boot:list');
    try {
      const response = await onCommand(commands.bootInventory);
      if (!response) return;
      const value = record(record(response.result).value);
      const parsed = (Array.isArray(value.boots) ? value.boots : [])
        .map(parseBootEntry)
        .filter((entry): entry is BootInventoryEntry => entry !== null);
      setBootImages(parsed);
      setBootImagesLoaded(true);
    } finally {
      setBusy('');
    }
  };

  const importBootImage = async () => {
    if (busy) return;
    setBusy('boot:import');
    try {
      const picked = await onCommand(commands.nativePickFile, {
        purpose: 'boot.select.source',
        title: t('boot.import'),
        filters: [{ label: t('boot.imageFiles'), extensions: ['img'] }],
      });
      const grant = selectedGrant(picked);
      if (!grant) return;
      const response = await onCommand(commands.bootSelect, { grant, partition: bootPartition });
      if (!response) return;
      const value = record(record(response.result).value);
      const selected = parseBootEntry(value.selected);
      if (!selected) return;
      setBootImages((current) => [selected, ...current.filter((entry) => entry.bootId !== selected.bootId)]);
      setBootImagesLoaded(true);
    } finally {
      setBusy('');
    }
  };

  const selectBootImage = async (bootId: string) => {
    if (busy) return;
    setBusy(`boot:select:${bootId}`);
    try {
      await onCommand(commands.bootSelect, { bootId });
    } finally {
      setBusy('');
    }
  };

  const deleteBootImage = async (bootId: string) => {
    if (busy || confirmBootDelete !== bootId) return;
    setBusy(`boot:delete:${bootId}`);
    setBootDeleteNotice('');
    try {
      const response = await onCommand(commands.bootDelete, { bootId });
      if (!response) return;
      const receipt = record(record(response.result).value);
      const keys = Object.keys(receipt).sort();
      const expected = ['bootId', 'cleanupDeferred', 'objectRetained', 'revision', 'sha256'];
      if (
        keys.length !== expected.length || !keys.every((key, index) => key === expected[index]) ||
        receipt.bootId !== bootId ||
        typeof receipt.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(receipt.sha256) ||
        typeof receipt.objectRetained !== 'boolean' ||
        typeof receipt.cleanupDeferred !== 'boolean' ||
        typeof receipt.revision !== 'number' || !Number.isSafeInteger(receipt.revision) || receipt.revision < 0
      ) {
        setBootDeleteNotice('failed');
        return;
      }
      setBootImages((current) => current.filter((entry) => entry.bootId !== bootId));
      setConfirmBootDelete('');
      setBootDeleteNotice(receipt.cleanupDeferred ? 'deferred' : '');
    } finally {
      setBusy('');
    }
  };

  const patchBoot = async () => {
    if (!singleAdb || !primary || !method || !compatibleApp || !snapshot.boot || busy) return;
    setBusy('boot-patch');
    try {
      const picked = await onCommand(commands.nativeSaveFile, {
        purpose: 'boot.patch.destination',
        title: t('root.patch'),
        defaultName: `patched-${method}.img`,
        filters: [{ label: t('root.patch'), extensions: ['img'] }],
      });
      const grant = selectedGrant(picked);
      if (!grant) return;
      let secretGrant = '';
      if (method === 'apatch') {
        let secret = await requestApatchSecret();
        if (!secret) return;
        let issued;
        try {
          issued = await onCommand(commands.secretIssue, {
            purpose: 'apatch.superkey',
            secret,
          });
        } finally {
          secret = '';
        }
        secretGrant = selectedGrant(issued);
        if (!secretGrant) return;
      }
      await onCommand(commands.bootPatch, {
        serial: primary.serial,
        flavor: method,
        appId: compatibleApp.id,
        grant,
        ...(secretGrant ? { secretGrant } : {}),
      });
    } finally {
      setBusy('');
    }
  };

  return (
    <>
      <PageHeader title={t('root.title')} subtitle={t('root.subtitle')} />
      <div className="inline-alert inline-alert--warning root-warning">
        <Icon name="warningPng" size={20} />
        <span>{t('root.warning')}</span>
      </div>
      <Card className="root-manager" aria-busy={busy.startsWith('boot:')}>
        <CardTitle icon="firmware" after={(
          <div className="button-row button-row--wrap">
            <label className="select-field select-field--compact">
              <span>{t('boot.partition')}</span>
              <select
                value={bootPartition}
                onChange={(event) => setBootPartition(event.currentTarget.value as BootInventoryEntry['partition'])}
                disabled={Boolean(busy)}
              >
                <option value="boot">boot</option>
                <option value="init_boot">init_boot</option>
                <option value="vendor_boot">vendor_boot</option>
                <option value="vendor_kernel_boot">vendor_kernel_boot</option>
              </select>
            </label>
            <Button icon="scan" onClick={() => void refreshBootImages()} disabled={Boolean(busy)}>{t('common.refresh')}</Button>
            <Button variant="primary" icon="folderPng" onClick={() => void importBootImage()} disabled={Boolean(busy)}>{t('boot.import')}</Button>
          </div>
        )}>{t('boot.inventoryTitle')}</CardTitle>
        <p className="root-manager__detail">{t('boot.inventoryDetail')}</p>
        {bootDeleteNotice === 'failed' ? <p className="root-manager__guard" role="alert"><Icon name="warningPng" size={16} />{t('boot.deleteFailed')}</p> : null}
        {bootDeleteNotice === 'deferred' ? <p className="root-manager__guard" role="status"><Icon name="warningPng" size={16} />{t('boot.cleanupDeferred')}</p> : null}
        <div className="root-inventory" role="list" aria-label={t('boot.inventoryTitle')}>
          {bootImages.map((entry) => {
            const selected = snapshot.boot?.id === entry.bootId;
            return (
              <article className="root-inventory__row" role="listitem" key={entry.bootId}>
                <span className="root-inventory__icon"><Icon name="firmware" size={24} /></span>
                <span className="root-inventory__copy">
                  <strong>{entry.partition}</strong>
                  <span>
                    <Badge tone={entry.verified ? 'success' : 'warning'}>{entry.verified ? t('status.ready') : t('boot.integrityFailed')}</Badge>
                    <Badge tone={entry.patched ? 'accent' : 'neutral'}>{entry.patched ? t('boot.patched') : t('boot.stock')}</Badge>
                    <Badge tone="neutral">{t('boot.provenance', { value: entry.provenance })}</Badge>
                  </span>
                  <small>{t('common.size')}: {entry.size.toLocaleString()} · <code title={entry.sha256}>{entry.sha256.slice(0, 12)}…</code></small>
                </span>
                {selected ? (
                  <Badge tone="success">{t('common.selected')}</Badge>
                ) : (
                  <span className="root-inventory__actions">
                    {confirmBootDelete === entry.bootId ? (
                      <span className="root-inventory__delete-confirm" role="group" aria-label={t('boot.deletePrompt')}>
                        <span>{t('boot.deletePrompt')}</span>
                        <Button
                          ref={bootDeleteConfirmRef}
                          variant="danger"
                          onClick={() => void deleteBootImage(entry.bootId)}
                          disabled={Boolean(busy)}
                        >{t('boot.deleteConfirm')}</Button>
                        <Button variant="ghost" onClick={() => setConfirmBootDelete('')} disabled={Boolean(busy)}>{t('common.cancel')}</Button>
                      </span>
                    ) : (
                      <>
                        <Button icon="right" onClick={() => void selectBootImage(entry.bootId)} disabled={Boolean(busy) || !entry.verified}>{t('boot.use')}</Button>
                        <Button variant="danger" onClick={() => { setBootDeleteNotice(''); setConfirmBootDelete(entry.bootId); }} disabled={Boolean(busy)}>{t('boot.delete')}</Button>
                      </>
                    )}
                  </span>
                )}
              </article>
            );
          })}
          {!bootImages.length ? <EmptyState icon="firmware" title={t('common.none')} detail={bootImagesLoaded ? t('boot.inventoryEmpty') : t('boot.inventoryLoad')} /> : null}
        </div>
      </Card>
      <Card>
        <CardTitle icon="root">{t('root.choose')}</CardTitle>
        <div className="root-methods" role="radiogroup" aria-label={t('root.choose')}>
          {methods.map((entry) => (
            <label className={`root-method ${method === entry.id ? 'is-selected' : ''}`} key={entry.id}>
              <input type="radio" name="root-method" checked={method === entry.id} onChange={() => setMethod(entry.id)} />
              <img src={assets[entry.icon]} width={48} height={48} alt="" aria-hidden="true" />
              <span><strong>{entry.name}</strong><Badge tone="neutral">{entry.version}</Badge><small>{entry.detail}</small></span>
            </label>
          ))}
          {!methods.length ? <EmptyState icon="root" title={t('common.none')} detail={t('root.subtitle')} /> : null}
        </div>
        <div className="root-footer">
          <span>{compatibleApp ? `${compatibleApp.provider} ${compatibleApp.version}` : t('root.patchAppsRequired')}</span>
          <Button variant="primary" icon="patch" onClick={() => void patchBoot()} disabled={Boolean(busy) || !singleAdb || !snapshot.boot || !method || !compatibleApp}>
            {t('root.patch')}
          </Button>
        </div>
      </Card>

      <div className="root-management-grid">
        <Card className="root-manager" aria-busy={busy.startsWith('app') || busy === 'apps-list'}>
          <CardTitle icon="android" after={(
            <Button icon="scan" onClick={() => void refreshRootApps()} disabled={Boolean(busy)}>{t('common.refresh')}</Button>
          )}>{t('root.appsTitle')}</CardTitle>
          <p className="root-manager__detail">{t('root.appsDetail')}</p>
          {!singleAdb ? <p className="root-manager__guard"><Icon name="warningPng" size={16} />{t('root.appDeviceRequired')}</p> : null}
          <div className="root-inventory" role="list" aria-label={t('root.appsTitle')}>
            {rootApps.map((app) => (
              <article className="root-inventory__row" role="listitem" key={app.id}>
                <span className="root-inventory__icon"><Icon name="androidPng" size={24} /></span>
                <span className="root-inventory__copy">
                  <strong>{app.provider}</strong>
                  <span><Badge tone="accent">{app.flavor || '—'}</Badge><Badge tone="neutral">{app.provenance || '—'}</Badge></span>
                  <small>{app.version || '—'} · <code title={app.sha256}>{app.sha256.slice(0, 12)}…</code></small>
                </span>
                <Button icon="download" onClick={() => void installRootApp(app.id)} disabled={Boolean(busy) || !singleAdb}>{t('root.appInstall')}</Button>
              </article>
            ))}
            {!rootApps.length ? <EmptyState icon="android" title={t('common.none')} detail={appsLoaded ? t('common.none') : t('root.appsEmpty')} /> : null}
          </div>
        </Card>

        <Card className="root-manager" aria-busy={busy.startsWith('module')}>
          <CardTitle icon="packages" after={(
            <div className="button-row">
              <Button icon="scan" onClick={() => void refreshModules()} disabled={Boolean(busy) || !rootedAdb}>{t('common.refresh')}</Button>
              <Button variant="primary" icon="folderPng" onClick={() => void installModule()} disabled={Boolean(busy) || !rootedAdb}>{t('root.moduleInstall')}</Button>
            </div>
          )}>{t('root.modulesTitle')}</CardTitle>
          <p className="root-manager__detail">{t('root.modulesDetail')}</p>
          {!rootedAdb ? <p className="root-manager__guard"><Icon name="warningPng" size={16} />{t('root.moduleDeviceRequired')}</p> : null}
          <div className="root-inventory" role="list" aria-label={t('root.modulesTitle')}>
            {modules.map((module) => (
              <article className="root-inventory__row root-inventory__row--module" role="listitem" key={module.id}>
                <span className="root-inventory__icon"><Icon name="packages" size={24} /></span>
                <span className="root-inventory__copy"><strong>{module.id}</strong><small>Magisk</small></span>
                <span className="root-inventory__actions">
                  <Button variant="ghost" onClick={() => void runModuleAction('enable', module.id)} disabled={Boolean(busy)}>{t('root.moduleEnable')}</Button>
                  <Button variant="ghost" onClick={() => void runModuleAction('disable', module.id)} disabled={Boolean(busy)}>{t('root.moduleDisable')}</Button>
                  <Button variant="danger" onClick={() => void runModuleAction('remove', module.id)} disabled={Boolean(busy)}>{t('root.moduleRemove')}</Button>
                </span>
              </article>
            ))}
            {!modules.length ? <EmptyState icon="packages" title={t('common.none')} detail={rootedAdb && !modulesLoaded ? t('root.modulesEmpty') : rootedAdb ? t('common.none') : t('root.moduleDeviceRequired')} /> : null}
          </div>
        </Card>
      </div>
      {apatchPromptOpen ? (
        <div className="interaction-backdrop">
          <section
            ref={apatchDialogRef}
            className="interaction-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="apatch-secret-title"
            aria-describedby="apatch-secret-message"
            onKeyDown={(event) => {
              if (event.key === 'Escape') {
                event.preventDefault();
                finishApatchPrompt(null);
                return;
              }
              if (event.key !== 'Tab') return;
              const controls = Array.from(apatchDialogRef.current?.querySelectorAll<HTMLElement>('input:not(:disabled), button:not(:disabled)') ?? []);
              if (!controls.length) return;
              const currentIndex = controls.indexOf(document.activeElement as HTMLElement);
              const nextIndex = event.shiftKey
                ? (currentIndex <= 0 ? controls.length - 1 : currentIndex - 1)
                : (currentIndex >= controls.length - 1 ? 0 : currentIndex + 1);
              event.preventDefault();
              controls[nextIndex].focus();
            }}
          >
            <span className="interaction-dialog__icon"><Icon name="root" size={26} /></span>
            <div className="interaction-dialog__copy">
              <h2 id="apatch-secret-title">APatch</h2>
              <p id="apatch-secret-message">{t('root.apatchDetail')}</p>
              <label className="reinforced-confirmation-field">
                <span>APatch</span>
                <input
                  ref={apatchInputRef}
                  type="password"
                  value={apatchSecret}
                  onChange={(event) => setApatchSecret(event.currentTarget.value.replaceAll('\0', '').slice(0, 128))}
                  minLength={8}
                  maxLength={128}
                  autoComplete="new-password"
                />
              </label>
            </div>
            <div className="interaction-dialog__actions">
              <button type="button" className="button button--ghost" onClick={() => finishApatchPrompt(null)}>{t('common.cancel')}</button>
              <button type="button" className="button button--primary" onClick={() => finishApatchPrompt(apatchSecret)} disabled={apatchSecret.length < 8 || apatchSecret.length > 128}>{t('common.continue')}</button>
            </div>
          </section>
        </div>
      ) : null}
    </>
  );
}
