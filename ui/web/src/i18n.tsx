import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import type { Locale } from './types';

// English msgids are the UI source contract. Runtime translations come only from
// gettext-exported JSON in public/i18n; there are no duplicated translated catalogs here.
export const sourceMessages = {
  'app.tagline': 'Android device management suite',
  'nav.tasks': 'Tasks',
  'nav.dashboard': 'Dashboard',
  'nav.device': 'Device',
  'nav.flash': 'Flash',
  'nav.firmware': 'Firmware',
  'nav.root': 'Root',
  'nav.apps': 'Apps',
  'nav.backups': 'Backups',
  'nav.tools': 'Tools',
  'nav.settings': 'Settings',
  'mode.expert': 'Expert Mode',
  'status.ready': 'Ready',
  'status.connecting': 'Connecting',
  'status.error': 'Bridge error',
  'status.host': 'Local bridge',
  'status.devices': '{count} devices connected',
  'status.targets': '{count} target devices',
  'status.revision': 'Revision {revision}',
  'common.selected': 'Selected',
  'common.cancel': 'Cancel',
  'common.continue': 'Continue',
  'common.back': 'Back',
  'common.apply': 'Apply changes',
  'common.refresh': 'Refresh',
  'common.search': 'Search',
  'common.stable': 'Stable',
  'common.beta': 'Beta',
  'common.system': 'System',
  'common.user': 'User',
  'common.enabled': 'Enabled',
  'common.disabled': 'Disabled',
  'common.none': 'None',
  'common.close': 'Close',
  'common.minimize': 'Minimize',
  'common.maximize': 'Maximize',
  'common.targets': 'Targets',
  'common.build': 'Build',
  'common.size': 'Size',
  'common.date': 'Date',
  'dashboard.title': 'Modern UI',
  'dashboard.subtitle': 'Your Android device command center',
  'dashboard.toolsReady': 'Platform Tools Ready',
  'dashboard.toolsDetail': 'ADB and Fastboot are configured and ready to use.',
  'dashboard.toolsNeeded': 'Platform Tools need attention',
  'dashboard.toolsNeededDetail': 'Set up and validate ADB and Fastboot before running device actions.',
  'dashboard.toolsSetup': 'Set up Platform Tools',
  'dashboard.connected': 'Connected Device',
  'dashboard.quick': 'Quick Actions',
  'dashboard.scan': 'Scan Devices',
  'dashboard.scanDetail': 'Refresh ADB and Fastboot connections',
  'dashboard.reboot': 'Reboot Device',
  'dashboard.rebootDetail': 'Restart the primary selected device',
  'dashboard.slot': 'Switch Slot',
  'dashboard.slotDetail': 'Change the active boot slot safely',
  'dashboard.patch': 'Patch Boot',
  'dashboard.patchDetail': 'Prepare a boot image for root',
  'dashboard.firmware': 'Loaded firmware',
  'dashboard.security': 'Security patch',
  'dashboard.deviceMode': 'Device mode',
  'device.title': 'Device workspace',
  'device.subtitle': 'Select one or more devices and inspect their current state.',
  'device.choose': 'Connected devices',
  'device.details': 'Primary device details',
  'device.multi': '{count} selected for batch actions',
  'device.bootloader': 'Bootloader',
  'device.battery': 'Battery',
  'device.connection': 'Connection',
  'device.root': 'Root access',
  'device.rooted': 'Rooted',
  'device.stock': 'Stock',
  'device.model': 'Model',
  'device.codename': 'Codename',
  'device.actions': 'Device operations',
  'device.singleActionGuard': 'Select exactly one device to run an operation.',
  'device.rebootTarget': 'Reboot destination',
  'device.rebootSystem': 'Android system',
  'device.rebootRecovery': 'Recovery',
  'device.rebootBootloader': 'Bootloader',
  'device.rebootFastbootd': 'Fastbootd',
  'device.rebootNow': 'Reboot now',
  'device.slotBootloader': 'Slot and bootloader',
  'device.switchToSlot': 'Switch to slot {slot}',
  'device.lockBootloader': 'Lock bootloader',
  'device.lockRequiresStockEvidence': 'Locking stays blocked until PixelFlasher verifies a complete compatible stock factory flash with no later state changes.',
  'device.unlockBootloader': 'Unlock bootloader',
  'device.bootImage': 'Selected boot image',
  'device.noBootImage': 'Select or patch a verified boot image first.',
  'device.partition': 'Partition',
  'device.defaultSlot': 'Current / default slot',
  'device.liveBoot': 'Live boot',
  'device.flashBoot': 'Flash image',
  'flash.title': 'Flash Wizard',
  'flash.subtitle': 'Build and verify a safe flash plan in five focused steps.',
  'flash.step.devices': 'Devices',
  'flash.step.firmware': 'Firmware',
  'flash.step.options': 'Options',
  'flash.step.plan': 'Plan',
  'flash.step.review': 'Review',
  'flash.devicesTitle': 'Choose target devices',
  'flash.devicesDetail': 'Compatible devices can be flashed together. Each device is validated again before any write.',
  'flash.singleDeviceTitle': 'Choose one target device',
  'flash.singleDeviceDetail': 'Flash operations run on one device at a time. The engine validates it again before any write.',
  'flash.firmwareTitle': 'Choose a firmware package',
  'flash.firmwareDetail': 'Select a local package that matches the target device family.',
  'flash.optionsTitle': 'Configure flash behavior',
  'flash.mode.keep': 'Keep data',
  'flash.mode.keepDetail': 'Update system partitions without wiping user data.',
  'flash.mode.wipe': 'Clean install',
  'flash.mode.wipeDetail': 'Erase user data before flashing for a clean baseline.',
  'flash.mode.ota': 'OTA sideload',
  'flash.mode.otaDetail': 'Apply the package through recovery where supported.',
  'flash.slot.title': 'Target slot',
  'flash.slot.default': 'Default',
  'flash.slot.defaultDetail': 'Let the package and device choose the correct slot.',
  'flash.slot.inactive': 'Inactive slot',
  'flash.slot.inactiveDetail': 'Write the currently inactive slot, then switch to it.',
  'flash.slot.both': 'Both slots',
  'flash.slot.bothDetail': 'Write matching partitions to slot A and slot B.',
  'flash.option.verify': 'Verify package checksums before flashing',
  'flash.option.disableVerity': 'Disable dm-verity',
  'flash.option.disableVerification': 'Disable Android Verified Boot verification',
  'flash.option.force': 'Force flash when host compatibility checks warn',
  'flash.option.noReboot': 'Do not reboot after flashing',
  'flash.option.downgrade': 'Allow firmware downgrade',
  'flash.option.temporaryRoot': 'Boot a patched image for temporary root',
  'flash.option.dryRun': 'Dry run only — do not write partitions',
  'flash.option.otaDisabled': 'Unavailable for OTA sideload.',
  'flash.planTitle': 'Generated flash plan',
  'flash.planDetail': 'Review the exact sequence PixelFlasher will execute.',
  'flash.plan.validate': 'Validate device connectivity and mode',
  'flash.plan.validateDetail': '{count} target devices',
  'flash.plan.verify': 'Verify package signature and checksums',
  'flash.plan.verifyEnabled': 'Checksum verification is enabled',
  'flash.plan.verifySkipped': 'Checksum verification was disabled',
  'flash.plan.simulate': 'Simulate partition writes',
  'flash.plan.write': 'Flash selected partitions',
  'flash.plan.slotDefault': 'Use package slot strategy',
  'flash.plan.slotInactive': 'Write inactive slot and switch',
  'flash.plan.slotBoth': 'Write slot A and slot B',
  'flash.plan.finish': 'Verify result and finish operation',
  'flash.plan.reboot': 'Reboot after verification',
  'flash.plan.noReboot': 'Leave device in its resulting mode',
  'flash.plan.safeNotice': 'PixelFlasher will stop before writing if any validation fails.',
  'flash.plan.dryNotice': 'Dry run is enabled; no partitions will be written.',
  'flash.reviewTitle': 'Ready to flash',
  'flash.reviewDetail': 'Confirm the targets, package, safeguards, and risks before starting.',
  'flash.review.targets': 'Targets',
  'flash.review.firmware': 'Firmware',
  'flash.review.mode': 'Install mode',
  'flash.review.slot': 'Target slot',
  'flash.review.safeguards': 'Safeguards',
  'flash.review.risks': 'Risk options',
  'flash.review.checksums': 'Checksum verification',
  'flash.review.noRisk': 'No advanced risk options enabled',
  'flash.review.disableVerity': 'dm-verity disabled',
  'flash.review.disableVerification': 'Verified Boot verification disabled',
  'flash.review.force': 'Compatibility warnings may be overridden',
  'flash.review.downgrade': 'Firmware downgrade allowed',
  'flash.review.noReboot': 'Automatic reboot disabled',
  'flash.review.temporaryRoot': 'Temporary root boot enabled',
  'flash.review.dryRun': 'Dry run — no writes',
  'flash.exactPlan': 'Exact backend plan',
  'flash.exactCommands': 'Exact commands',
  'flash.confirm.title': 'Destructive action confirmation',
  'flash.confirm.detail': 'Type {confirmation} to confirm this high-risk plan.',
  'flash.confirm.placeholder': 'Type the device name or serial',
  'flash.start': 'Start flash',
  'flash.simulate': 'Run simulation',
  'flash.prepare': 'Prepare review',
  'flash.preparing': 'Preparing verified plan…',
  'flash.running': 'Flash in progress',
  'flash.success': 'Flash completed successfully',
  'flash.cancelled': 'Flash was cancelled',
  'flash.failed': 'Flash failed — review the operation log',
  'flash.needDevice': 'Select at least one device to continue.',
  'firmware.title': 'Firmware library',
  'firmware.subtitle': 'Manage verified factory images, OTA packages, and custom ROMs.',
  'firmware.active': 'Active package',
  'firmware.available': 'Available locally',
  'firmware.use': 'Use package',
  'firmware.import': 'Import package',
  'firmware.process': 'Process package',
  'root.title': 'Root workspace',
  'root.subtitle': 'Patch a boot image with the root solution you trust.',
  'root.choose': 'Choose patch method',
  'root.patch': 'Patch selected boot image',
  'root.warning': 'Rooting changes device security. Verify the boot image matches the installed build.',
  'root.magiskDetail': 'Broad module ecosystem and Zygisk support.',
  'root.kernelSuDetail': 'Kernel-based root for supported devices.',
  'root.apatchDetail': 'Kernel patching with AndroidPatch.',
  'root.sukisuDetail': 'KernelSU-based advanced patch method.',
  'root.patchAppsRequired': 'Refresh Rooting Apps and choose a compatible verified app.',
  'root.appsTitle': 'Rooting Apps',
  'root.appsDetail': 'Verified local APK inventory supplied by the backend.',
  'root.appsEmpty': 'Refresh to discover verified local rooting APKs.',
  'root.appInstall': 'Install app',
  'root.appDeviceRequired': 'Select exactly one device in ADB mode to install.',
  'root.modulesTitle': 'Magisk Modules',
  'root.modulesDetail': 'Manage modules on one rooted device in ADB mode.',
  'root.modulesEmpty': 'Refresh to list installed modules.',
  'root.moduleInstall': 'Install module ZIP',
  'root.moduleEnable': 'Enable',
  'root.moduleDisable': 'Disable',
  'root.moduleRemove': 'Remove',
  'root.moduleDeviceRequired': 'Select exactly one rooted device in ADB mode.',
  'apps.title': 'Application manager',
  'apps.subtitle': 'Review and batch-manage packages on selected devices.',
  'apps.filter': 'Filter packages',
  'apps.package': 'Package',
  'apps.version': 'Version',
  'apps.scope': 'Scope',
  'apps.state': 'State',
  'backups.title': 'Backups',
  'backups.subtitle': 'Create and restore device snapshots with clear provenance.',
  'backups.create': 'Create backup',
  'backups.restore': 'Restore backup',
  'backups.contents': 'Contents',
  'tools.title': 'Device tools',
  'tools.subtitle': 'Open focused utilities for diagnostics and recovery.',
  'tools.shell': 'ADB Shell',
  'tools.logs': 'Logcat',
  'tools.recovery': 'Recovery tools',
  'tools.partition': 'Partition manager',
  'tools.bootloader': 'Bootloader console',
  'tools.integrity': 'Integrity check',
  'tools.recoveryDetail': 'Reboot, sideload, and inspect recovery state.',
  'tools.shellBlocked': 'Arbitrary shell input stays unavailable until a bounded command policy exists.',
  'tools.logcatDetail': 'Collect a bounded Android system log snapshot.',
  'tools.partitionDetail': 'Inspect allow-listed slots and partition metadata.',
  'tools.bootloaderDetail': 'Reboot the selected device into the bootloader.',
  'tools.integrityBlocked': 'AVB mutation stays unavailable until its typed policy is implemented.',
  'tools.scrcpy': 'Scrcpy',
  'tools.scrcpyDetail': 'Mirror and control the selected ADB device.',
  'tools.wifi': 'Wireless ADB',
  'tools.wifiDetail': 'Pair, connect, disconnect, and verify a numeric endpoint.',
  'tools.push': 'Push files',
  'tools.pushDetail': 'Send selected files to one allow-listed device folder.',
  'tools.support': 'Support package',
  'tools.supportDetail': 'Create a redacted diagnostic archive at a native destination.',
  'tools.action': 'Action',
  'tools.status': 'Check status',
  'tools.pair': 'Pair',
  'tools.connect': 'Connect',
  'tools.disconnect': 'Disconnect',
  'tools.host': 'Numeric IP address',
  'tools.port': 'Port',
  'tools.pairingCode': 'Six-digit pairing code',
  'tools.maxLines': 'Maximum lines',
  'tools.collectLogs': 'Collect logs',
  'tools.selectPartition': 'Selected partition',
  'tools.partitionRead': 'Read image',
  'tools.partitionWrite': 'Write image',
  'tools.partitionErase': 'Erase partition',
  'tools.destination': 'Device destination',
  'tools.chooseFiles': 'Choose files',
  'tools.results': 'Result',
  'settings.title': 'Settings',
  'settings.subtitle': 'Tune the workspace for your display, language, and workflow.',
  'settings.appearance': 'Appearance',
  'settings.theme': 'Theme',
  'settings.dark': 'Dark',
  'settings.light': 'Light',
  'settings.language': 'Language',
  'settings.accessibility': 'Accessibility',
  'settings.contrast': 'High contrast',
  'settings.motion': 'Reduce motion',
  'settings.contrastDetail': 'Stronger borders and text contrast throughout the workspace.',
  'settings.motionDetail': 'Disables non-essential transitions and animated progress.',
  'settings.zoom': 'Interface zoom',
  'settings.zoomOut': 'Zoom out',
  'settings.zoomReset': 'Reset zoom',
  'settings.zoomIn': 'Zoom in',
  'settings.shortcuts': 'Keyboard shortcuts',
  'settings.shortcutNav': 'Alt + 1…9 changes task',
  'settings.shortcutZoom': 'Ctrl/Cmd + Plus, Minus, or 0 changes zoom',
  'settings.shortcutFocus': 'Tab moves focus; Enter or Space activates controls',
  'settings.localPersistence': 'Preferences are saved by the PixelFlasher host on this computer.',
  'notice.mock': 'Development mock active',
  'notice.updated': 'Workspace updated',
  'notice.error': 'Could not complete the request',
  'notice.dismiss': 'Dismiss message',
  'skip.content': 'Skip to main content',
} as const;

export type MessageKey = keyof typeof sourceMessages;
type Catalog = Record<string, string>;

declare const __PIXELFLASHER_CATALOGS__: Partial<Record<Locale, Catalog>>;

export const localeOptions: Array<{ value: Locale; label: string }> = [
  { value: 'en', label: 'English' },
  { value: 'es', label: 'Español' },
  { value: 'fr', label: 'Français' },
  { value: 'it', label: 'Italiano' },
  { value: 'zh_CN', label: '简体中文' },
  { value: 'zh_TW', label: '繁體中文' },
];

const catalogCache = new Map<Locale, Catalog>();

async function loadCatalog(locale: Locale): Promise<Catalog> {
  if (locale === 'en') return {};
  const cached = catalogCache.get(locale);
  if (cached) return cached;
  const bundled = typeof __PIXELFLASHER_CATALOGS__ !== 'undefined' ? __PIXELFLASHER_CATALOGS__[locale] : undefined;
  if (bundled) {
    catalogCache.set(locale, bundled);
    return bundled;
  }
  try {
    const url = `${import.meta.env.BASE_URL}i18n/${locale}.json`;
    const response = await fetch(url, { cache: 'no-cache' });
    if (!response.ok) return {};
    const catalog = await response.json() as Catalog;
    catalogCache.set(locale, catalog);
    return catalog;
  } catch {
    return {};
  }
}

function lookup(catalog: Catalog, key: MessageKey) {
  const msgid = sourceMessages[key];
  const contextual = catalog[`web.${key}\u0004${msgid}`];
  const compact = catalog[`web.${key}`] ?? catalog[`${key}\u0004${msgid}`];
  const generic = catalog[msgid];
  if (contextual && contextual !== msgid) return contextual;
  if (compact && compact !== msgid) return compact;
  if (generic && generic !== msgid) return generic;
  return contextual ?? compact ?? generic ?? msgid;
}

interface I18nValue {
  locale: Locale;
  t: (key: MessageKey, values?: Record<string, string | number>) => string;
}

const I18nContext = createContext<I18nValue>({
  locale: 'en',
  t: (key) => sourceMessages[key],
});

export function I18nProvider({ locale, children }: { locale: Locale; children: ReactNode }) {
  const [catalog, setCatalog] = useState<Catalog>({});

  useEffect(() => {
    document.documentElement.lang = locale.replace('_', '-');
    let active = true;
    setCatalog({});
    void loadCatalog(locale).then((nextCatalog) => {
      if (active) setCatalog(nextCatalog);
    });
    return () => { active = false; };
  }, [locale]);

  const value = useMemo<I18nValue>(() => ({
    locale,
    t: (key, values = {}) => {
      const template = lookup(catalog, key);
      return Object.entries(values).reduce(
        (message, [name, replacement]) => message.replaceAll(`{${name}}`, String(replacement)),
        template,
      );
    },
  }), [catalog, locale]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n() {
  return useContext(I18nContext);
}
