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
  packageName: string;
  signerSha256: string[];
  schemes: string[];
  architecture: string;
}

interface RootAppCatalogEntry {
  artifactId: string;
  provider: string;
  channel: 'stable' | 'beta' | 'canary';
  flavor: string;
  version: string;
  architecture: string;
  packageName: string;
  signerSha256: string[];
  sha256: string;
  size: number;
  license: string;
  provenance: string;
}

const rootAppFields = [
  'id', 'provider', 'flavor', 'version', 'sha256', 'provenance', 'packageName',
  'signerSha256', 'schemes', 'architecture',
] as const;

function parseRootApp(value: unknown): RootAppEntry | null {
  const app = record(value);
  const keys = Object.keys(app).sort();
  const expected = [...rootAppFields].sort();
  if (
    keys.length !== expected.length || !keys.every((key, index) => key === expected[index]) ||
    typeof app.id !== 'string' || !/^[0-9a-f]{64}$/.test(app.id) ||
    typeof app.provider !== 'string' || !app.provider ||
    typeof app.flavor !== 'string' || !app.flavor ||
    typeof app.version !== 'string' || !app.version ||
    typeof app.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(app.sha256) ||
    typeof app.provenance !== 'string' || !app.provenance ||
    typeof app.packageName !== 'string' || !app.packageName ||
    !Array.isArray(app.signerSha256) || !app.signerSha256.every((item) => typeof item === 'string' && /^[0-9a-f]{64}$/.test(item)) ||
    !Array.isArray(app.schemes) || !app.schemes.every((item) => typeof item === 'string') ||
    typeof app.architecture !== 'string' || !app.architecture
  ) return null;
  return app as unknown as RootAppEntry;
}

const rootAppCatalogFields = [
  'artifactId', 'provider', 'channel', 'flavor', 'version', 'architecture',
  'packageName', 'signerSha256', 'sha256', 'size', 'license', 'provenance',
] as const;

function parseRootAppCatalogEntry(value: unknown): RootAppCatalogEntry | null {
  const entry = record(value);
  const keys = Object.keys(entry).sort();
  const expected = [...rootAppCatalogFields].sort();
  if (
    keys.length !== expected.length || !keys.every((key, index) => key === expected[index]) ||
    typeof entry.artifactId !== 'string' || !/^[0-9a-f]{32}$/.test(entry.artifactId) ||
    typeof entry.provider !== 'string' || !entry.provider ||
    !['stable', 'beta', 'canary'].includes(String(entry.channel)) ||
    typeof entry.flavor !== 'string' || !entry.flavor ||
    typeof entry.version !== 'string' || !entry.version ||
    typeof entry.architecture !== 'string' || !entry.architecture ||
    typeof entry.packageName !== 'string' || !entry.packageName ||
    !Array.isArray(entry.signerSha256) || !entry.signerSha256.length || !entry.signerSha256.every((item) => typeof item === 'string' && /^[0-9a-f]{64}$/.test(item)) ||
    typeof entry.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(entry.sha256) ||
    typeof entry.size !== 'number' || !Number.isSafeInteger(entry.size) || entry.size < 0 ||
    typeof entry.license !== 'string' || !entry.license ||
    typeof entry.provenance !== 'string' || !entry.provenance
  ) return null;
  return entry as unknown as RootAppCatalogEntry;
}

function operationSucceeded(response: Awaited<ReturnType<SharedPageProps['onCommand']>>) {
  return Boolean(response && String(record(response.result).status).toLowerCase() === 'success');
}

interface RootModuleEntry {
  id: string;
  name: string;
  version: string;
  versionCode: number | null;
  author: string;
  description: string;
  state: 'enabled' | 'disabled' | 'pending_remove' | 'corrupt';
  updateMetadata: 'available' | 'absent';
}

interface PiAnalysisReport {
  schemaVersion: 1;
  redacted: true;
  complete: true;
  device: {
    codename: string;
    build: string;
    rootAccess: 'verified';
    testKeys: boolean;
    overlayVisible: boolean;
  };
  packages: { id: 'gms' | 'play_store'; installed: boolean; version: string; versionCode: number }[];
  modules: { id: string; state: RootModuleEntry['state'] }[];
  configs: { kind: string; present: boolean; size: number; sha256: string | null }[];
  signals: {
    targetedFixTargetCount: number;
    magiskDenylistCount: number;
    droidGuardVmCount: number;
  };
  withheld: string[];
}

interface PifInventory {
  schemaVersion: 1;
  rootAccess: 'verified';
  bounded: true;
  count: number;
  profiles: { id: string; module: string; format: string; present: boolean; size: number; sha256: string | null }[];
  targetCount: number;
  targets: { packageName: string; format: 'json' | 'prop'; present: boolean; size: number; sha256: string | null }[];
}

interface PifDocument {
  schemaVersion: 1;
  profileId: string;
  format: 'json' | 'prop' | 'list' | 'text';
  present: boolean;
  content: string;
  size: number;
  sha256: string | null;
  editable: true;
  bounded: true;
}

const pifProfileSpecs = [
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

const pifEditableProfileIds = new Set([
  'pif.custom_json', 'pif.custom_prop', 'pif.module_json', 'pif.legacy_json',
  'pif.app_replace', 'tricky.spoof', 'tricky.target', 'tricky.security_patch',
]);

const pifEditorFormats = new Map<string, PifDocument['format']>([
  ['pif.custom_json', 'json'],
  ['pif.custom_prop', 'prop'],
  ['pif.module_json', 'json'],
  ['pif.legacy_json', 'json'],
  ['pif.app_replace', 'list'],
  ['tricky.spoof', 'prop'],
  ['tricky.target', 'list'],
  ['tricky.security_patch', 'text'],
]);

function parsePifDocument(value: unknown): PifDocument | null {
  const document = record(value);
  const expectedFormat = typeof document.profileId === 'string'
    ? pifEditorFormats.get(document.profileId)
    : undefined;
  if (
    !exactKeys(document, ['schemaVersion', 'profileId', 'format', 'present', 'content', 'size', 'sha256', 'editable', 'bounded'])
    || document.schemaVersion !== 1 || !expectedFormat || document.format !== expectedFormat
    || typeof document.present !== 'boolean' || typeof document.content !== 'string'
    || !boundedCount(document.size, 32 * 1024) || document.editable !== true || document.bounded !== true
  ) return null;
  const encodedSize = new TextEncoder().encode(document.content).length;
  if (document.present) {
    if (encodedSize !== document.size || typeof document.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(document.sha256)) return null;
  } else if (document.content || document.size !== 0 || document.sha256 !== null) return null;
  return document as unknown as PifDocument;
}

function validPifEditorContent(format: PifDocument['format'], content: string) {
  if (!content || new TextEncoder().encode(content).length > 32 * 1024 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(content)) return false;
  const lines = content.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith('#'));
  if (format === 'json') {
    try {
      const parsed: unknown = JSON.parse(content);
      return Boolean(parsed && typeof parsed === 'object' && !Array.isArray(parsed) && Object.keys(parsed).length);
    } catch {
      return false;
    }
  }
  if (format === 'prop') return Boolean(lines.length) && lines.length <= 1024 && lines.every((line) => /^[A-Za-z_][A-Za-z0-9_.-]{0,127}=/.test(line));
  if (format === 'list') {
    const identities = lines.map((line) => line.toLowerCase());
    return Boolean(lines.length) && lines.length <= 1024
      && lines.every((line) => /^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$/.test(line))
      && new Set(identities).size === identities.length;
  }
  return Boolean(content.trim()) && lines.length <= 1024;
}

function validPifFile(item: Record<string, unknown>) {
  return typeof item.present === 'boolean'
    && boundedCount(item.size, 4 * 1024 * 1024)
    && (item.present
      ? typeof item.sha256 === 'string' && /^[0-9a-f]{64}$/.test(item.sha256)
      : item.size === 0 && item.sha256 === null);
}

function parsePifInventory(value: unknown): PifInventory | null {
  const inventory = record(value);
  if (
    !exactKeys(inventory, ['schemaVersion', 'rootAccess', 'bounded', 'count', 'profiles', 'targetCount', 'targets'])
    || inventory.schemaVersion !== 1 || inventory.rootAccess !== 'verified' || inventory.bounded !== true
    || inventory.count !== pifProfileSpecs.length || !Array.isArray(inventory.profiles)
    || inventory.profiles.length !== pifProfileSpecs.length || !boundedCount(inventory.targetCount, 256)
    || !Array.isArray(inventory.targets) || inventory.targets.length !== inventory.targetCount
  ) return null;
  const profiles = inventory.profiles.flatMap((raw, index) => {
    const item = record(raw);
    const expected = pifProfileSpecs[index];
    if (
      !exactKeys(item, ['id', 'module', 'format', 'present', 'size', 'sha256'])
      || item.id !== expected[0] || item.module !== expected[1] || item.format !== expected[2]
      || !validPifFile(item)
    ) return [];
    return [item as unknown as PifInventory['profiles'][number]];
  });
  const targets = inventory.targets.flatMap((raw) => {
    const item = record(raw);
    if (
      !exactKeys(item, ['packageName', 'format', 'present', 'size', 'sha256'])
      || typeof item.packageName !== 'string'
      || !/^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$/.test(item.packageName)
      || item.format !== 'json' || !validPifFile(item)
    ) return [];
    return [item as unknown as PifInventory['targets'][number]];
  });
  const targetIds = targets.map((item) => item.packageName.toLowerCase());
  if (
    profiles.length !== pifProfileSpecs.length || targets.length !== inventory.targets.length
    || targetIds.join(',') !== [...new Set(targetIds)].sort().join(',')
  ) return null;
  return { ...inventory, profiles, targets } as PifInventory;
}

const piConfigKinds = [
  'pif_custom_json', 'pif_custom_prop', 'pif_module_json', 'pif_legacy_json',
  'pif_app_replace', 'pif_scripts_only', 'tricky_spoof', 'tricky_target',
  'tricky_security_patch', 'tricky_tee', 'targeted_targets', 'keybox',
] as const;

const piWithheld = [
  'android_ids', 'device_serial', 'keybox_material', 'raw_config_contents',
  'raw_logs', 'target_package_names',
] as const;

function exactKeys(value: Record<string, unknown>, expected: readonly string[]) {
  const keys = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return keys.length === sorted.length && keys.every((key, index) => key === sorted[index]);
}

function boundedCount(value: unknown, maximum = 4096) {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

function parsePiAnalysis(value: unknown): PiAnalysisReport | null {
  const report = record(value);
  if (
    !exactKeys(report, ['schemaVersion', 'redacted', 'complete', 'device', 'packages', 'modules', 'configs', 'signals', 'withheld'])
    || report.schemaVersion !== 1 || report.redacted !== true || report.complete !== true
  ) return null;
  const device = record(report.device);
  if (
    !exactKeys(device, ['codename', 'build', 'rootAccess', 'testKeys', 'overlayVisible'])
    || typeof device.codename !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(device.codename)
    || typeof device.build !== 'string' || device.build.length > 256
    || device.rootAccess !== 'verified' || typeof device.testKeys !== 'boolean'
    || typeof device.overlayVisible !== 'boolean'
  ) return null;
  if (!Array.isArray(report.packages) || report.packages.length !== 2) return null;
  const packages = report.packages.flatMap((raw) => {
    const item = record(raw);
    if (
      !exactKeys(item, ['id', 'installed', 'version', 'versionCode'])
      || !['gms', 'play_store'].includes(String(item.id))
      || typeof item.installed !== 'boolean' || typeof item.version !== 'string'
      || item.version.length > 128 || !boundedCount(item.versionCode, Number.MAX_SAFE_INTEGER)
      || (!item.installed && (item.version || item.versionCode !== 0))
    ) return [];
    return [item as unknown as PiAnalysisReport['packages'][number]];
  });
  if (packages.length !== 2 || packages.map((item) => item.id).join(',') !== 'gms,play_store') return null;
  if (!Array.isArray(report.modules) || report.modules.length > 256) return null;
  const modules = report.modules.flatMap((raw) => {
    const item = record(raw);
    if (
      !exactKeys(item, ['id', 'state']) || typeof item.id !== 'string'
      || !/^[A-Za-z][A-Za-z0-9._-]{0,63}$/.test(item.id)
      || !['enabled', 'disabled', 'pending_remove', 'corrupt'].includes(String(item.state))
    ) return [];
    return [item as unknown as PiAnalysisReport['modules'][number]];
  });
  const moduleIds = modules.map((item) => item.id.toLowerCase());
  if (modules.length !== report.modules.length || moduleIds.join(',') !== [...new Set(moduleIds)].sort().join(',')) return null;
  if (!Array.isArray(report.configs) || report.configs.length !== piConfigKinds.length) return null;
  const configs = report.configs.flatMap((raw) => {
    const item = record(raw);
    if (
      !exactKeys(item, ['kind', 'present', 'size', 'sha256'])
      || !piConfigKinds.includes(item.kind as typeof piConfigKinds[number])
      || typeof item.present !== 'boolean' || !boundedCount(item.size, 4 * 1024 * 1024)
      || ((!item.present || item.kind === 'keybox') && item.sha256 !== null)
      || (item.present && item.kind !== 'keybox' && (typeof item.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(item.sha256)))
      || (!item.present && item.size !== 0)
    ) return [];
    return [item as unknown as PiAnalysisReport['configs'][number]];
  });
  if (configs.length !== piConfigKinds.length || configs.map((item) => item.kind).join(',') !== piConfigKinds.join(',')) return null;
  const signals = record(report.signals);
  if (
    !exactKeys(signals, ['targetedFixTargetCount', 'magiskDenylistCount', 'droidGuardVmCount'])
    || !boundedCount(signals.targetedFixTargetCount)
    || !boundedCount(signals.magiskDenylistCount)
    || !boundedCount(signals.droidGuardVmCount)
    || !Array.isArray(report.withheld)
    || report.withheld.join(',') !== piWithheld.join(',')
  ) return null;
  return { ...report, device, packages, modules, configs, signals, withheld: [...piWithheld] } as PiAnalysisReport;
}

function parseRootModule(value: unknown): RootModuleEntry | null {
  const module = record(value);
  const expected = ['author', 'description', 'id', 'name', 'state', 'updateMetadata', 'version', 'versionCode'];
  const keys = Object.keys(module).sort();
  if (
    keys.length !== expected.length || !keys.every((key, index) => key === expected[index])
    || typeof module.id !== 'string' || !/^[A-Za-z][A-Za-z0-9._-]{0,63}$/.test(module.id)
    || typeof module.name !== 'string' || module.name.length > 256
    || typeof module.version !== 'string' || module.version.length > 128
    || (module.versionCode !== null && (typeof module.versionCode !== 'number' || !Number.isSafeInteger(module.versionCode) || module.versionCode < 0))
    || typeof module.author !== 'string' || module.author.length > 256
    || typeof module.description !== 'string' || module.description.length > 1024
    || !['enabled', 'disabled', 'pending_remove', 'corrupt'].includes(String(module.state))
    || !['available', 'absent'].includes(String(module.updateMetadata))
  ) return null;
  return module as unknown as RootModuleEntry;
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
  const [rootAppCatalog, setRootAppCatalog] = useState<RootAppCatalogEntry[]>([]);
  const [rootCatalogLoaded, setRootCatalogLoaded] = useState(false);
  const [rootChannel, setRootChannel] = useState<RootAppCatalogEntry['channel']>('stable');
  const [modules, setModules] = useState<RootModuleEntry[]>([]);
  const [modulesLoaded, setModulesLoaded] = useState(false);
  const [bootImages, setBootImages] = useState<BootInventoryEntry[]>([]);
  const [bootImagesLoaded, setBootImagesLoaded] = useState(false);
  const [bootPartition, setBootPartition] = useState<BootInventoryEntry['partition']>('boot');
  const [confirmBootDelete, setConfirmBootDelete] = useState('');
  const [bootDeleteNotice, setBootDeleteNotice] = useState<'failed' | 'deferred' | ''>('');
  const [sosConfirmation, setSosConfirmation] = useState('');
  const [piAnalysis, setPiAnalysis] = useState<PiAnalysisReport | null>(null);
  const [piAnalysisInvalid, setPiAnalysisInvalid] = useState(false);
  const [pifInventory, setPifInventory] = useState<PifInventory | null>(null);
  const [pifInventoryInvalid, setPifInventoryInvalid] = useState(false);
  const [pifDeleteProfile, setPifDeleteProfile] = useState('');
  const [pifDeleteConfirmation, setPifDeleteConfirmation] = useState('');
  const [pifImportProfile, setPifImportProfile] = useState('pif.custom_json');
  const [pifImportGrant, setPifImportGrant] = useState('');
  const [pifImportConfirmation, setPifImportConfirmation] = useState('');
  const [pifDocument, setPifDocument] = useState<PifDocument | null>(null);
  const [pifEditorContent, setPifEditorContent] = useState('');
  const [pifEditorConfirmation, setPifEditorConfirmation] = useState('');
  const [pifEditorInvalid, setPifEditorInvalid] = useState(false);
  const [targetedFixPackage, setTargetedFixPackage] = useState('');
  const [targetedFixAction, setTargetedFixAction] = useState<'addTarget' | 'deleteTarget' | ''>('');
  const [targetedFixConfirmation, setTargetedFixConfirmation] = useState('');
  const [targetedFixProfileFormat, setTargetedFixProfileFormat] = useState<'json' | 'prop'>('json');
  const [targetedFixImportPackage, setTargetedFixImportPackage] = useState('');
  const [targetedFixImportGrant, setTargetedFixImportGrant] = useState('');
  const [targetedFixImportConfirmation, setTargetedFixImportConfirmation] = useState('');
  const [droidGuardConfirmation, setDroidGuardConfirmation] = useState('');
  const [droidGuardPending, setDroidGuardPending] = useState(false);
  const [integrityChecker, setIntegrityChecker] = useState<'piac' | 'spic' | 'aic' | 'playStore'>('piac');
  const [integrityCheckPending, setIntegrityCheckPending] = useState(false);
  const [integrityCheckConfirmation, setIntegrityCheckConfirmation] = useState('');
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

  useEffect(() => {
    setPifDocument(null);
    setPifEditorContent('');
    setPifEditorConfirmation('');
    setPifEditorInvalid(false);
  }, [primary?.serial]);

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
        const app = parseRootApp(entry);
        return app ? [app] : [];
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

  const refreshRootAppCatalog = async () => {
    if (busy) return;
    setBusy('app-catalog');
    try {
      const response = await onCommand(commands.rootAppsCatalogRefresh, { channel: rootChannel });
      if (!response) return;
      const value = record(record(response.result).value);
      const parsed = (Array.isArray(value.entries) ? value.entries : []).flatMap((entry) => {
        const catalogEntry = parseRootAppCatalogEntry(entry);
        return catalogEntry ? [catalogEntry] : [];
      });
      setRootAppCatalog(parsed);
      setRootCatalogLoaded(true);
    } finally {
      setBusy('');
    }
  };

  const downloadRootApp = async (artifactId: string) => {
    if (busy) return;
    setBusy(`app-download:${artifactId}`);
    try {
      const response = await onCommand(commands.rootAppsDownload, { artifactId });
      if (!response) return;
      const value = record(record(response.result).value);
      const app = parseRootApp(value.app);
      if (!app) return;
      setRootApps((current) => [app, ...current.filter((entry) => entry.id !== app.id)]);
      setAppsLoaded(true);
      setMethod((current) => current || methodForProvider(app.provider));
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

  const refreshModules = async (expectedRevision?: number) => {
    if (!rootedAdb || !primary || (busy && expectedRevision === undefined)) return false;
    const ownsBusyState = expectedRevision === undefined;
    if (ownsBusyState) setBusy('modules-list');
    try {
      const response = await onCommand(
        commands.rootModulesList,
        { serial: primary.serial },
        expectedRevision === undefined ? undefined : { expectedRevision, suppressNotice: true },
      );
      if (!response) return false;
      const value = record(record(response.result).value);
      const parsed = (Array.isArray(value.modules) ? value.modules : []).flatMap((entry) => {
        const module = parseRootModule(entry);
        return module ? [module] : [];
      });
      setModules(parsed);
      setModulesLoaded(true);
      return true;
    } finally {
      if (ownsBusyState) setBusy('');
    }
  };

  const runModuleAction = async (action: 'enable' | 'disable' | 'remove', moduleId: string) => {
    if (!rootedAdb || !primary || busy) return;
    setBusy(`module:${action}:${moduleId}`);
    try {
      const response = await onCommand(commands.rootModulesAction, { serial: primary.serial, action, moduleId });
      if (operationSucceeded(response)) {
        await refreshModules(response?.revision);
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
      if (operationSucceeded(response)) {
        await refreshModules(response?.revision);
      }
    } finally {
      setBusy('');
    }
  };

  const startShizuku = async () => {
    if (!singleAdb || !primary || busy) return;
    setBusy('recovery:shizuku');
    try {
      await onCommand(commands.toolsShizuku, {
        serial: primary.serial,
        action: 'start',
      });
    } finally {
      setBusy('');
    }
  };

  const disableAllModules = async () => {
    if (!rootedAdb || !primary || busy) return;
    const required = `SOS ${primary.serial.slice(-6).toUpperCase()}`;
    if (sosConfirmation !== required) return;
    setBusy('recovery:sos');
    try {
      const response = await onCommand(commands.toolsSos, {
        serial: primary.serial,
        action: 'disableModules',
        confirmationText: sosConfirmation,
      });
      if (operationSucceeded(response)) {
        setSosConfirmation('');
        await refreshModules(response?.revision);
      }
    } finally {
      setBusy('');
    }
  };

  const runPiAnalysis = async () => {
    if (!rootedAdb || !primary || busy) return;
    setBusy('pi-analysis');
    setPiAnalysisInvalid(false);
    try {
      const response = await onCommand(commands.toolsPiAnalysis, {
        serial: primary.serial,
        action: 'analyze',
      });
      if (!operationSucceeded(response)) return;
      const parsed = parsePiAnalysis(record(response?.result).value);
      if (!parsed) {
        setPiAnalysis(null);
        setPiAnalysisInvalid(true);
        return;
      }
      setPiAnalysis(parsed);
    } finally {
      setBusy('');
    }
  };

  const refreshPifInventory = async () => {
    if (!rootedAdb || !primary || busy) return;
    setBusy('pif-inventory');
    setPifInventoryInvalid(false);
    try {
      const response = await onCommand(commands.rootPifInventory, { serial: primary.serial });
      if (!operationSucceeded(response)) return;
      const parsed = parsePifInventory(record(response?.result).value);
      if (!parsed) {
        setPifInventory(null);
        setPifInventoryInvalid(true);
        return;
      }
      setPifInventory(parsed);
    } finally {
      setBusy('');
    }
  };

  const closePifEditor = () => {
    setPifDocument(null);
    setPifEditorContent('');
    setPifEditorConfirmation('');
    setPifEditorInvalid(false);
  };

  const loadPifDocument = async (profileId: string) => {
    if (!rootedAdb || !primary || busy || !pifEditableProfileIds.has(profileId)) return;
    setBusy(`pif-document:${profileId}`);
    setPifEditorInvalid(false);
    try {
      const response = await onCommand(commands.rootPifDocument, {
        serial: primary.serial,
        profileId,
      });
      if (!operationSucceeded(response)) return;
      const parsed = parsePifDocument(record(response?.result).value);
      if (!parsed || parsed.profileId !== profileId) {
        closePifEditor();
        setPifEditorInvalid(true);
        return;
      }
      setPifDocument(parsed);
      setPifEditorContent(parsed.content);
      setPifEditorConfirmation('');
    } finally {
      setBusy('');
    }
  };

  const savePifDocument = async () => {
    if (!rootedAdb || !primary || !pifDocument || busy) return;
    const required = `SAVE PIF ${pifDocument.profileId} ${primary.serial.slice(-6).toUpperCase()}`;
    if (
      pifEditorConfirmation !== required
      || !validPifEditorContent(pifDocument.format, pifEditorContent)
      || pifEditorContent === pifDocument.content
    ) return;
    setBusy(`pif-editor-save:${pifDocument.profileId}`);
    setPifEditorInvalid(false);
    try {
      const response = await onCommand(commands.toolsPif, {
        serial: primary.serial,
        action: 'updateProfile',
        profileId: pifDocument.profileId,
        content: pifEditorContent,
        baseSha256: pifDocument.sha256 ?? 'absent',
        confirmationText: pifEditorConfirmation,
      });
      if (!operationSucceeded(response)) return;
      const value = record(record(response?.result).value);
      const size = new TextEncoder().encode(pifEditorContent).length;
      if (
        value.action !== 'updateProfile'
        || value.profileId !== pifDocument.profileId
        || typeof value.sha256 !== 'string'
        || !/^[0-9a-f]{64}$/.test(value.sha256)
        || value.size !== size
      ) {
        setPifEditorInvalid(true);
        return;
      }
      const updated: PifDocument = {
        ...pifDocument,
        present: true,
        content: pifEditorContent,
        size,
        sha256: value.sha256,
      };
      setPifDocument(updated);
      setPifEditorConfirmation('');
      setPifInventory((current) => current ? {
        ...current,
        profiles: current.profiles.map((item) => item.id === updated.profileId
          ? { ...item, present: true, size: updated.size, sha256: updated.sha256 }
          : item),
      } : current);
    } finally {
      setBusy('');
    }
  };

  const deletePifProfile = async () => {
    if (!rootedAdb || !primary || busy || !pifDeleteProfile) return;
    const required = `DELETE PIF ${pifDeleteProfile} ${primary.serial.slice(-6).toUpperCase()}`;
    if (pifDeleteConfirmation !== required) return;
    setBusy(`pif-delete:${pifDeleteProfile}`);
    try {
      const response = await onCommand(commands.toolsPif, {
        serial: primary.serial,
        action: 'deleteProfile',
        profileId: pifDeleteProfile,
        confirmationText: pifDeleteConfirmation,
      });
      if (operationSucceeded(response)) {
        setPifInventory((current) => current ? {
          ...current,
          profiles: current.profiles.map((item) => item.id === pifDeleteProfile
            ? { ...item, present: false, size: 0, sha256: null }
            : item),
          ...(pifDeleteProfile === 'targeted.targets' ? { targetCount: 0, targets: [] } : {}),
        } : current);
        setPifDeleteProfile('');
        setPifDeleteConfirmation('');
      }
    } finally {
      setBusy('');
    }
  };

  const preparePifImport = async () => {
    if (!rootedAdb || !primary || busy) return;
    const picked = await onCommand(commands.nativePickFile, {
      purpose: 'root.pif.import',
      title: t('root.pifImport'),
      filters: [{ label: t('root.pifInventoryTitle'), extensions: ['json', 'prop', 'txt', 'list'] }],
    });
    const grant = selectedGrant(picked);
    if (!grant) return;
    setPifImportGrant(grant);
    setPifImportConfirmation('');
  };

  const importPifProfile = async () => {
    if (!rootedAdb || !primary || busy || !pifImportGrant) return;
    const required = `IMPORT PIF ${pifImportProfile} ${primary.serial.slice(-6).toUpperCase()}`;
    if (pifImportConfirmation !== required) return;
    setBusy(`pif-import:${pifImportProfile}`);
    try {
      const response = await onCommand(commands.toolsPif, {
        serial: primary.serial,
        action: 'importProfile',
        profileId: pifImportProfile,
        confirmationText: pifImportConfirmation,
        grant: pifImportGrant,
      });
      if (operationSucceeded(response)) {
        const value = record(record(response?.result).value);
        if (typeof value.sha256 === 'string' && /^[0-9a-f]{64}$/.test(value.sha256) && boundedCount(value.size, 1024 * 1024)) {
          setPifInventory((current) => current ? {
            ...current,
            profiles: current.profiles.map((item) => item.id === pifImportProfile
              ? { ...item, present: true, size: value.size as number, sha256: value.sha256 as string }
              : item),
          } : current);
        }
        setPifImportGrant('');
        setPifImportConfirmation('');
      }
    } finally {
      setBusy('');
    }
  };

  const mutateTargetedFix = async () => {
    if (!rootedAdb || !primary || busy || !targetedFixAction) return;
    const packageName = targetedFixPackage.trim();
    if (!/^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$/.test(packageName) || packageName.length > 255) return;
    const verb = targetedFixAction === 'addTarget' ? 'ADD' : 'DELETE';
    const required = `${verb} TARGET ${packageName} ${primary.serial.slice(-6).toUpperCase()}`;
    if (targetedFixConfirmation !== required) return;
    setBusy(`targeted-fix:${targetedFixAction}`);
    try {
      const response = await onCommand(commands.toolsPif, {
        serial: primary.serial,
        action: targetedFixAction,
        targetPackage: packageName,
        confirmationText: targetedFixConfirmation,
      });
      if (!operationSucceeded(response)) return;
      const value = record(record(response?.result).value);
      if (value.action !== targetedFixAction || value.targetPackage !== packageName) {
        setPifInventoryInvalid(true);
        return;
      }
      setPifInventory((current) => {
        if (!current) return current;
        const retained = current.targets.filter((item) => item.packageName !== packageName);
        const targets = targetedFixAction === 'addTarget'
          ? [...retained, { packageName, format: 'json' as const, present: false, size: 0, sha256: null }].sort((a, b) => a.packageName.localeCompare(b.packageName))
          : retained;
        return { ...current, targets, targetCount: targets.length };
      });
      setTargetedFixAction('');
      setTargetedFixConfirmation('');
      if (targetedFixAction === 'addTarget') setTargetedFixPackage('');
    } finally {
      setBusy('');
    }
  };

  const prepareTargetedFixProfileImport = async (packageName: string) => {
    if (!rootedAdb || !primary || busy) return;
    const picked = await onCommand(commands.nativePickFile, {
      purpose: 'root.pif.target.import',
      title: t('root.targetedFixImport'),
      filters: [{ label: t('root.targetedFixProfile'), extensions: [targetedFixProfileFormat] }],
    });
    const grant = selectedGrant(picked);
    if (!grant) return;
    setTargetedFixImportPackage(packageName);
    setTargetedFixImportGrant(grant);
    setTargetedFixImportConfirmation('');
  };

  const importTargetedFixProfile = async () => {
    if (!rootedAdb || !primary || busy || !targetedFixImportPackage || !targetedFixImportGrant) return;
    const required = `IMPORT TARGET ${targetedFixImportPackage} ${targetedFixProfileFormat.toUpperCase()} ${primary.serial.slice(-6).toUpperCase()}`;
    if (targetedFixImportConfirmation !== required) return;
    setBusy(`targeted-fix-import:${targetedFixImportPackage}`);
    try {
      const response = await onCommand(commands.toolsPif, {
        serial: primary.serial,
        action: 'importTargetProfile',
        targetPackage: targetedFixImportPackage,
        targetFormat: targetedFixProfileFormat,
        confirmationText: targetedFixImportConfirmation,
        grant: targetedFixImportGrant,
      });
      if (!operationSucceeded(response)) return;
      const value = record(record(response?.result).value);
      if (
        value.action !== 'importTargetProfile'
        || value.targetPackage !== targetedFixImportPackage
        || value.targetFormat !== targetedFixProfileFormat
        || typeof value.sha256 !== 'string'
        || !/^[0-9a-f]{64}$/.test(value.sha256)
        || !boundedCount(value.size, 1024 * 1024)
      ) {
        setPifInventoryInvalid(true);
        return;
      }
      setPifInventory((current) => current ? {
        ...current,
        targets: current.targets.map((item) => item.packageName === targetedFixImportPackage
          ? { ...item, format: targetedFixProfileFormat, present: true, size: value.size as number, sha256: value.sha256 as string }
          : item),
      } : current);
      setTargetedFixImportPackage('');
      setTargetedFixImportGrant('');
      setTargetedFixImportConfirmation('');
    } finally {
      setBusy('');
    }
  };

  const cleanupDroidGuard = async () => {
    if (!rootedAdb || !primary || busy) return;
    const required = `CLEANUP DG ${primary.serial.slice(-6).toUpperCase()}`;
    if (droidGuardConfirmation !== required) return;
    setBusy('droidguard-cleanup');
    try {
      const response = await onCommand(commands.toolsPif, {
        serial: primary.serial,
        action: 'cleanupDroidGuard',
        confirmationText: droidGuardConfirmation,
      });
      if (operationSucceeded(response)) {
        setDroidGuardPending(false);
        setDroidGuardConfirmation('');
      }
    } finally {
      setBusy('');
    }
  };

  const launchIntegrityCheck = async () => {
    if (!rootedAdb || !primary || busy) return;
    const required = `OPEN PI ${integrityChecker} ${primary.serial.slice(-6).toUpperCase()}`;
    if (integrityCheckConfirmation !== required) return;
    setBusy('integrity-check-launch');
    try {
      const response = await onCommand(commands.toolsPif, {
        serial: primary.serial,
        action: 'launchIntegrityCheck',
        checker: integrityChecker,
        confirmationText: integrityCheckConfirmation,
      });
      if (operationSucceeded(response)) {
        setIntegrityCheckPending(false);
        setIntegrityCheckConfirmation('');
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
        <div className="root-inventory" role={bootImages.length ? 'list' : undefined} aria-label={t('boot.inventoryTitle')}>
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
            <div className="button-row button-row--wrap">
              <label className="select-field select-field--compact">
                <span>{t('root.appChannel')}</span>
                <select
                  value={rootChannel}
                  onChange={(event) => setRootChannel(event.currentTarget.value as RootAppCatalogEntry['channel'])}
                  disabled={Boolean(busy)}
                >
                  <option value="stable">{t('common.stable')}</option>
                  <option value="beta">{t('common.beta')}</option>
                  <option value="canary">{t('firmware.canary')}</option>
                </select>
              </label>
              <Button icon="download" onClick={() => void refreshRootAppCatalog()} disabled={Boolean(busy)}>{t('root.appCatalog')}</Button>
              <Button icon="scan" onClick={() => void refreshRootApps()} disabled={Boolean(busy)}>{t('common.refresh')}</Button>
            </div>
          )}>{t('root.appsTitle')}</CardTitle>
          <p className="root-manager__detail">{t('root.appsDetail')}</p>
          {!singleAdb ? <p className="root-manager__guard"><Icon name="warningPng" size={16} />{t('root.appDeviceRequired')}</p> : null}
          <div className="root-inventory" role={rootApps.length || rootAppCatalog.length ? 'list' : undefined} aria-label={t('root.appsTitle')}>
            {rootAppCatalog.map((entry) => {
              const available = rootApps.some((app) => app.sha256 === entry.sha256);
              return (
                <article className="root-inventory__row" role="listitem" key={entry.artifactId}>
                  <span className="root-inventory__icon"><Icon name="download" size={24} /></span>
                  <span className="root-inventory__copy">
                    <strong>{entry.provider}</strong>
                    <span>
                      <Badge tone="accent">{entry.channel}</Badge>
                      <Badge tone="neutral">{entry.architecture}</Badge>
                      <Badge tone="neutral">{entry.version}</Badge>
                    </span>
                    <small>{entry.packageName} · <code title={entry.sha256}>{entry.sha256.slice(0, 12)}…</code></small>
                  </span>
                  {available ? (
                    <Badge tone="success">{t('root.appAvailable')}</Badge>
                  ) : (
                    <Button icon="download" onClick={() => void downloadRootApp(entry.artifactId)} disabled={Boolean(busy)}>{t('root.appDownload')}</Button>
                  )}
                </article>
              );
            })}
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
            {!rootApps.length && !rootAppCatalog.length ? <EmptyState icon="android" title={t('common.none')} detail={appsLoaded || rootCatalogLoaded ? t('common.none') : t('root.appsEmpty')} /> : null}
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
          <div className="root-inventory" role={modules.length ? 'list' : undefined} aria-label={t('root.modulesTitle')}>
            {modules.map((module) => (
              <article className="root-inventory__row root-inventory__row--module" role="listitem" key={module.id}>
                <span className="root-inventory__icon"><Icon name="packages" size={24} /></span>
                <span className="root-inventory__copy">
                  <strong>{module.name || module.id}</strong>
                  <span>
                    <Badge tone={module.state === 'enabled' ? 'success' : module.state === 'corrupt' ? 'danger' : 'warning'}>{t(`root.moduleState.${module.state}`)}</Badge>
                    {module.version ? <Badge tone="neutral">{module.version}</Badge> : null}
                    {module.updateMetadata === 'available' ? <Badge tone="accent">{t('root.moduleUpdateAvailable')}</Badge> : null}
                  </span>
                  <small>{module.id}{module.author ? ` · ${module.author}` : ''}</small>
                  {module.description ? <small>{module.description}</small> : null}
                </span>
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
      <Card className="root-manager" aria-busy={busy === 'pif-inventory'}>
        <CardTitle icon="shield" after={(
          <div className="button-row button-row--wrap">
            <label className="select-field select-field--compact">
              <span>{t('root.pifImportTarget')}</span>
              <select value={pifImportProfile} onChange={(event) => { setPifImportProfile(event.currentTarget.value); setPifImportGrant(''); }} disabled={Boolean(busy)}>
                {pifProfileSpecs.map(([id]) => <option value={id} key={id}>{id}</option>)}
              </select>
            </label>
            <Button onClick={() => void loadPifDocument(pifImportProfile)} disabled={Boolean(busy) || !rootedAdb || !pifEditableProfileIds.has(pifImportProfile)}>{t('root.pifEdit')}</Button>
            <Button icon="folderPng" onClick={() => void preparePifImport()} disabled={Boolean(busy) || !rootedAdb}>{t('root.pifImport')}</Button>
            <Button variant="danger" onClick={() => { setDroidGuardPending(true); setDroidGuardConfirmation(''); }} disabled={Boolean(busy) || !rootedAdb}>{t('root.droidGuardCleanup')}</Button>
            <Button onClick={() => { setIntegrityCheckPending(true); setIntegrityCheckConfirmation(''); }} disabled={Boolean(busy) || !rootedAdb}>{t('root.integrityCheckOpen')}</Button>
            <Button icon="scan" onClick={() => void refreshPifInventory()} disabled={Boolean(busy) || !rootedAdb}>{t('common.refresh')}</Button>
          </div>
        )}>{t('root.pifInventoryTitle')}</CardTitle>
        <p className="root-manager__detail">{t('root.pifInventoryDetail')}</p>
        {!rootedAdb ? <p className="root-manager__guard"><Icon name="warningPng" size={16} />{t('root.moduleDeviceRequired')}</p> : null}
        {pifInventoryInvalid ? <p className="root-manager__guard" role="alert"><Icon name="warningPng" size={16} />{t('root.pifInventoryInvalid')}</p> : null}
        {pifEditorInvalid ? <p className="root-manager__guard" role="alert"><Icon name="warningPng" size={16} />{t('root.pifEditorInvalid')}</p> : null}
        {rootedAdb ? (
          <div className="root-footer root-footer--wrap">
            <label className="select-field">
              <span>{t('root.targetedFixPackage')}</span>
              <input
                value={targetedFixPackage}
                onChange={(event) => { setTargetedFixPackage(event.currentTarget.value.slice(0, 255)); setTargetedFixAction(''); setTargetedFixConfirmation(''); }}
                placeholder="com.example.app"
                autoComplete="off"
                spellCheck={false}
                disabled={Boolean(busy)}
              />
            </label>
            <Button
              variant="secondary"
              onClick={() => { setTargetedFixPackage(targetedFixPackage.trim()); setTargetedFixAction('addTarget'); setTargetedFixConfirmation(''); }}
              disabled={Boolean(busy) || !/^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$/.test(targetedFixPackage.trim()) || targetedFixPackage.trim().length > 255 || Boolean(pifInventory?.targets.some((item) => item.packageName === targetedFixPackage.trim()))}
            >{t('root.targetedFixAdd')}</Button>
            <label className="select-field select-field--compact">
              <span>{t('root.targetedFixFormat')}</span>
              <select value={targetedFixProfileFormat} onChange={(event) => setTargetedFixProfileFormat(event.currentTarget.value as 'json' | 'prop')} disabled={Boolean(busy) || Boolean(targetedFixImportGrant)}>
                <option value="json">JSON</option>
                <option value="prop">PROP</option>
              </select>
            </label>
          </div>
        ) : null}
        {pifInventory ? (
          <div className="root-inventory" role="list" aria-label={t('root.pifInventoryTitle')}>
            {pifInventory.profiles.filter((item) => item.present).map((item) => (
              <div className="root-inventory__row" role="listitem" key={item.id}>
                <span className="root-inventory__icon"><Icon name="shield" size={24} /></span>
                <span className="root-inventory__copy">
                  <strong>{item.id}</strong>
                  <span><Badge tone="success">{t('root.pifPresent')}</Badge><Badge tone="neutral">{item.module}</Badge><Badge tone="neutral">{item.format}</Badge></span>
                  <small>{item.size.toLocaleString()} · <code title={item.sha256 ?? undefined}>{item.sha256?.slice(0, 12)}…</code></small>
                </span>
                <span className="root-inventory__actions">
                  {pifEditableProfileIds.has(item.id) ? <Button variant="secondary" onClick={() => void loadPifDocument(item.id)} disabled={Boolean(busy)}>{t('root.pifEdit')}</Button> : null}
                  <Button
                    variant="danger"
                    onClick={() => { setPifDeleteProfile(item.id); setPifDeleteConfirmation(''); }}
                    disabled={Boolean(busy)}
                  >{t('root.pifDelete')}</Button>
                </span>
              </div>
            ))}
            {pifInventory.targets.map((item) => (
              <div className="root-inventory__row" role="listitem" key={item.packageName}>
                <span className="root-inventory__icon"><Icon name="androidPng" size={24} /></span>
                <span className="root-inventory__copy"><strong>{item.packageName}</strong><small>{t('root.pifTargetedFix')}</small></span>
                <span className="root-inventory__actions">
                  <Badge tone={item.present ? 'success' : 'warning'}>{item.present ? t('root.pifPresent') : t('root.pifMissing')}</Badge>
                  <Badge tone="neutral">{item.format.toUpperCase()}</Badge>
                  <Button variant="secondary" onClick={() => void prepareTargetedFixProfileImport(item.packageName)} disabled={Boolean(busy)}>{t('root.targetedFixImport')}</Button>
                  <Button variant="danger" onClick={() => { setTargetedFixPackage(item.packageName); setTargetedFixAction('deleteTarget'); setTargetedFixConfirmation(''); }} disabled={Boolean(busy)}>{t('root.targetedFixDelete')}</Button>
                </span>
              </div>
            ))}
            {!pifInventory.profiles.some((item) => item.present) && !pifInventory.targets.length
              ? <EmptyState icon="shield" title={t('common.none')} detail={t('root.pifInventoryEmpty')} /> : null}
          </div>
        ) : <EmptyState icon="shield" title={t('root.pifInventoryEmpty')} detail={t('root.pifInventoryDetail')} />}
        {pifDocument && primary ? (
          <section className="pif-editor" aria-label={t('root.pifEditorTitle', { profile: pifDocument.profileId })}>
            <header className="pif-editor__header">
              <span>
                <strong>{t('root.pifEditorTitle', { profile: pifDocument.profileId })}</strong>
                <small>{t('root.pifEditorDetail')}</small>
              </span>
              <span className="button-row">
                <Badge tone={validPifEditorContent(pifDocument.format, pifEditorContent) ? 'success' : 'danger'}>{pifDocument.format.toUpperCase()}</Badge>
                <Badge tone={pifEditorContent === pifDocument.content ? 'neutral' : 'warning'}>{pifEditorContent === pifDocument.content ? t('root.pifEditorUnchanged') : t('root.pifEditorModified')}</Badge>
                <Badge tone={new TextEncoder().encode(pifEditorContent).length <= 32 * 1024 ? 'neutral' : 'danger'}>{new TextEncoder().encode(pifEditorContent).length.toLocaleString()} / 32 KiB</Badge>
              </span>
            </header>
            <textarea
              className="pif-editor__textarea"
              aria-label={t('root.pifEditorContent')}
              value={pifEditorContent}
              onChange={(event) => { setPifEditorContent(event.currentTarget.value.slice(0, 32 * 1024)); setPifEditorConfirmation(''); }}
              rows={14}
              wrap="off"
              spellCheck={false}
              disabled={Boolean(busy)}
            />
            <footer className="pif-editor__footer">
              <label className="select-field">
                <span>{t('root.pifEditorConfirm')}</span>
                <small><code>{`SAVE PIF ${pifDocument.profileId} ${primary.serial.slice(-6).toUpperCase()}`}</code></small>
                <input
                  aria-label={t('root.pifEditorConfirm')}
                  value={pifEditorConfirmation}
                  onChange={(event) => setPifEditorConfirmation(event.currentTarget.value.slice(0, 320))}
                  autoComplete="off"
                  spellCheck={false}
                  disabled={Boolean(busy)}
                />
              </label>
              <span className="button-row">
                <Button onClick={() => void loadPifDocument(pifDocument.profileId)} disabled={Boolean(busy)}>{t('root.pifEditorReload')}</Button>
                <Button
                  variant="primary"
                  onClick={() => void savePifDocument()}
                  disabled={Boolean(busy) || pifEditorContent === pifDocument.content || !validPifEditorContent(pifDocument.format, pifEditorContent) || pifEditorConfirmation !== `SAVE PIF ${pifDocument.profileId} ${primary.serial.slice(-6).toUpperCase()}`}
                >{t('root.pifEditorSave')}</Button>
                <Button variant="ghost" onClick={closePifEditor} disabled={Boolean(busy)}>{t('common.close')}</Button>
              </span>
            </footer>
          </section>
        ) : null}
        {pifDeleteProfile && primary ? (
          <div className="root-footer root-footer--wrap">
            <label className="select-field">
              <span>{t('root.pifDeleteConfirm', { profile: pifDeleteProfile })}</span>
              <small><code>{`DELETE PIF ${pifDeleteProfile} ${primary.serial.slice(-6).toUpperCase()}`}</code></small>
              <input
                value={pifDeleteConfirmation}
                onChange={(event) => setPifDeleteConfirmation(event.currentTarget.value.slice(0, 320))}
                autoComplete="off"
                spellCheck={false}
                disabled={Boolean(busy)}
              />
            </label>
            <span className="button-row">
              <Button
                variant="danger"
                onClick={() => void deletePifProfile()}
                disabled={Boolean(busy) || pifDeleteConfirmation !== `DELETE PIF ${pifDeleteProfile} ${primary.serial.slice(-6).toUpperCase()}`}
              >{t('root.pifDeleteRun')}</Button>
              <Button variant="ghost" onClick={() => { setPifDeleteProfile(''); setPifDeleteConfirmation(''); }} disabled={Boolean(busy)}>{t('common.cancel')}</Button>
            </span>
          </div>
        ) : null}
        {pifImportGrant && primary ? (
          <div className="root-footer root-footer--wrap">
            <label className="select-field">
              <span>{t('root.pifImportConfirm', { profile: pifImportProfile })}</span>
              <small><code>{`IMPORT PIF ${pifImportProfile} ${primary.serial.slice(-6).toUpperCase()}`}</code></small>
              <input value={pifImportConfirmation} onChange={(event) => setPifImportConfirmation(event.currentTarget.value.slice(0, 320))} autoComplete="off" spellCheck={false} disabled={Boolean(busy)} />
            </label>
            <span className="button-row">
              <Button variant="danger" onClick={() => void importPifProfile()} disabled={Boolean(busy) || pifImportConfirmation !== `IMPORT PIF ${pifImportProfile} ${primary.serial.slice(-6).toUpperCase()}`}>{t('root.pifImportRun')}</Button>
              <Button variant="ghost" onClick={() => { setPifImportGrant(''); setPifImportConfirmation(''); }} disabled={Boolean(busy)}>{t('common.cancel')}</Button>
            </span>
          </div>
        ) : null}
        {targetedFixAction && primary ? (
          <div className="root-footer root-footer--wrap">
            <label className="select-field">
              <span>{t('root.targetedFixConfirm', { package: targetedFixPackage })}</span>
              <small><code>{`${targetedFixAction === 'addTarget' ? 'ADD' : 'DELETE'} TARGET ${targetedFixPackage} ${primary.serial.slice(-6).toUpperCase()}`}</code></small>
              <input value={targetedFixConfirmation} onChange={(event) => setTargetedFixConfirmation(event.currentTarget.value.slice(0, 360))} autoComplete="off" spellCheck={false} disabled={Boolean(busy)} />
            </label>
            <span className="button-row">
              <Button
                variant={targetedFixAction === 'deleteTarget' ? 'danger' : 'primary'}
                onClick={() => void mutateTargetedFix()}
                disabled={Boolean(busy) || targetedFixConfirmation !== `${targetedFixAction === 'addTarget' ? 'ADD' : 'DELETE'} TARGET ${targetedFixPackage} ${primary.serial.slice(-6).toUpperCase()}`}
              >{targetedFixAction === 'addTarget' ? t('root.targetedFixAddRun') : t('root.targetedFixDeleteRun')}</Button>
              <Button variant="ghost" onClick={() => { setTargetedFixAction(''); setTargetedFixConfirmation(''); }} disabled={Boolean(busy)}>{t('common.cancel')}</Button>
            </span>
          </div>
        ) : null}
        {targetedFixImportGrant && primary ? (
          <div className="root-footer root-footer--wrap">
            <label className="select-field">
              <span>{t('root.targetedFixImportConfirm', { package: targetedFixImportPackage })}</span>
              <small><code>{`IMPORT TARGET ${targetedFixImportPackage} ${targetedFixProfileFormat.toUpperCase()} ${primary.serial.slice(-6).toUpperCase()}`}</code></small>
              <input value={targetedFixImportConfirmation} onChange={(event) => setTargetedFixImportConfirmation(event.currentTarget.value.slice(0, 360))} autoComplete="off" spellCheck={false} disabled={Boolean(busy)} />
            </label>
            <span className="button-row">
              <Button variant="danger" onClick={() => void importTargetedFixProfile()} disabled={Boolean(busy) || targetedFixImportConfirmation !== `IMPORT TARGET ${targetedFixImportPackage} ${targetedFixProfileFormat.toUpperCase()} ${primary.serial.slice(-6).toUpperCase()}`}>{t('root.targetedFixImportRun')}</Button>
              <Button variant="ghost" onClick={() => { setTargetedFixImportPackage(''); setTargetedFixImportGrant(''); setTargetedFixImportConfirmation(''); }} disabled={Boolean(busy)}>{t('common.cancel')}</Button>
            </span>
          </div>
        ) : null}
        {droidGuardPending && primary ? (
          <div className="root-footer root-footer--wrap">
            <label className="select-field">
              <span>{t('root.droidGuardConfirm')}</span>
              <small><code>{`CLEANUP DG ${primary.serial.slice(-6).toUpperCase()}`}</code></small>
              <input value={droidGuardConfirmation} onChange={(event) => setDroidGuardConfirmation(event.currentTarget.value.slice(0, 128))} autoComplete="off" spellCheck={false} disabled={Boolean(busy)} />
            </label>
            <span className="button-row">
              <Button variant="danger" onClick={() => void cleanupDroidGuard()} disabled={Boolean(busy) || droidGuardConfirmation !== `CLEANUP DG ${primary.serial.slice(-6).toUpperCase()}`}>{t('root.droidGuardCleanupRun')}</Button>
              <Button variant="ghost" onClick={() => { setDroidGuardPending(false); setDroidGuardConfirmation(''); }} disabled={Boolean(busy)}>{t('common.cancel')}</Button>
            </span>
          </div>
        ) : null}
        {integrityCheckPending && primary ? (
          <div className="root-footer root-footer--wrap">
            <label className="select-field">
              <span>{t('root.integrityChecker')}</span>
              <select aria-label={t('root.integrityChecker')} value={integrityChecker} onChange={(event) => { setIntegrityChecker(event.currentTarget.value as typeof integrityChecker); setIntegrityCheckConfirmation(''); }} disabled={Boolean(busy)}>
                <option value="piac">{t('root.integrityChecker.piac')}</option>
                <option value="spic">{t('root.integrityChecker.spic')}</option>
                <option value="aic">{t('root.integrityChecker.aic')}</option>
                <option value="playStore">{t('root.integrityChecker.playStore')}</option>
              </select>
              <small><code>{`OPEN PI ${integrityChecker} ${primary.serial.slice(-6).toUpperCase()}`}</code></small>
              <input aria-label={t('root.integrityCheckConfirm')} value={integrityCheckConfirmation} onChange={(event) => setIntegrityCheckConfirmation(event.currentTarget.value.slice(0, 128))} autoComplete="off" spellCheck={false} disabled={Boolean(busy)} />
            </label>
            <span className="button-row">
              <Button variant="primary" onClick={() => void launchIntegrityCheck()} disabled={Boolean(busy) || integrityCheckConfirmation !== `OPEN PI ${integrityChecker} ${primary.serial.slice(-6).toUpperCase()}`}>{t('root.integrityCheckRun')}</Button>
              <Button variant="ghost" onClick={() => { setIntegrityCheckPending(false); setIntegrityCheckConfirmation(''); }} disabled={Boolean(busy)}>{t('common.cancel')}</Button>
            </span>
          </div>
        ) : null}
      </Card>
      <Card className="root-manager" aria-busy={busy === 'pi-analysis'}>
        <CardTitle icon="shield" after={(
          <Button
            variant="primary"
            icon="scan"
            onClick={() => void runPiAnalysis()}
            disabled={Boolean(busy) || !rootedAdb}
          >{t('root.piAnalysisRun')}</Button>
        )}>{t('root.piAnalysisTitle')}</CardTitle>
        <p className="root-manager__detail">{t('root.piAnalysisDetail')}</p>
        {!rootedAdb ? <p className="root-manager__guard"><Icon name="warningPng" size={16} />{t('root.piAnalysisGuard')}</p> : null}
        {piAnalysisInvalid ? <p className="root-manager__guard" role="alert"><Icon name="warningPng" size={16} />{t('root.piAnalysisInvalid')}</p> : null}
        {piAnalysis ? (
          <div className="root-inventory" aria-label={t('root.piAnalysisTitle')}>
            <div className="root-inventory__row">
              <span className="root-inventory__icon"><Icon name="shield" size={24} /></span>
              <span className="root-inventory__copy">
                <strong>{piAnalysis.device.codename} · {piAnalysis.device.build || '—'}</strong>
                <span>
                  <Badge tone="success">{t('root.piAnalysisRedacted')}</Badge>
                  <Badge tone={piAnalysis.device.testKeys ? 'danger' : 'success'}>{piAnalysis.device.testKeys ? t('root.piAnalysisTestKeys') : t('root.piAnalysisReleaseKeys')}</Badge>
                  <Badge tone="neutral">{t('root.piAnalysisModules', { count: piAnalysis.modules.length })}</Badge>
                </span>
                <small>{t('root.piAnalysisConfigs', { count: piAnalysis.configs.filter((item) => item.present).length })}</small>
              </span>
            </div>
            <dl className="device-inspection-profile">
              <div><dt>{t('root.piAnalysisTargets')}</dt><dd>{piAnalysis.signals.targetedFixTargetCount}</dd></div>
              <div><dt>{t('root.piAnalysisDenylist')}</dt><dd>{piAnalysis.signals.magiskDenylistCount}</dd></div>
              <div><dt>{t('root.piAnalysisDroidGuard')}</dt><dd>{piAnalysis.signals.droidGuardVmCount}</dd></div>
              <div><dt>{t('root.piAnalysisOverlay')}</dt><dd>{piAnalysis.device.overlayVisible ? t('common.enabled') : t('common.disabled')}</dd></div>
            </dl>
            <p className="root-manager__detail">{t('root.piAnalysisWithheld')}</p>
          </div>
        ) : <EmptyState icon="shield" title={t('root.piAnalysisEmpty')} detail={t('root.piAnalysisDetail')} />}
      </Card>
      <Card className="root-manager" aria-busy={busy.startsWith('recovery:')}>
        <CardTitle icon="warningPng">{t('root.recoveryTitle')}</CardTitle>
        <p className="root-manager__detail">{t('root.recoveryDetail')}</p>
        <div className="root-footer root-footer--wrap">
          <div>
            <strong>{t('root.shizukuTitle')}</strong>
            <small>{t('root.shizukuDetail')}</small>
          </div>
          <Button
            variant="primary"
            onClick={() => void startShizuku()}
            disabled={Boolean(busy) || !singleAdb}
          >{t('root.shizukuStart')}</Button>
        </div>
        <div className="root-footer root-footer--wrap">
          <label className="select-field">
            <span id="root-sos-label">{t('root.sosTitle')}</span>
            <small id="root-sos-detail">{t('root.sosDetail')}</small>
            <input
              aria-labelledby="root-sos-label"
              aria-describedby="root-sos-detail"
              value={sosConfirmation}
              onChange={(event) => setSosConfirmation(event.currentTarget.value)}
              placeholder={primary ? `SOS ${primary.serial.slice(-6).toUpperCase()}` : 'SOS'}
              disabled={Boolean(busy) || !rootedAdb}
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          <Button
            variant="danger"
            onClick={() => void disableAllModules()}
            disabled={
              Boolean(busy)
              || !rootedAdb
              || !primary
              || sosConfirmation !== `SOS ${primary.serial.slice(-6).toUpperCase()}`
            }
          >{t('root.sosRun')}</Button>
        </div>
      </Card>
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
