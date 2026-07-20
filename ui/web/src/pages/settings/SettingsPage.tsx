import { localeOptions, useI18n } from '../../i18n';
import type { Locale, ModernPreferences, Theme, ToolbarPosition } from '../../types';
import { Button, Card, CardTitle, Icon, PageHeader, Toggle } from '../../components/ui';

export type UpdateCheckState = {
  phase: 'idle' | 'checking' | 'current' | 'available' | 'failed';
  latestVersion?: string;
};

export function SettingsPage({
  theme,
  onThemeChange,
  locale,
  onLocaleChange,
  highContrast,
  onHighContrastChange,
  reducedMotion,
  onReducedMotionChange,
  zoom,
  onZoomChange,
  expertMode,
  onExpertModeChange,
  preferences,
  onMaintenancePreferenceChange,
  onApplicationCommand,
  applicationVersion,
  updateCheckState,
  onUpdateCheck,
  applicationConsoleLines,
  onApplicationConsoleClear,
  onApplicationConsoleExport,
}: {
  theme: Theme;
  onThemeChange: (theme: Theme) => void;
  locale: Locale;
  onLocaleChange: (locale: Locale) => void;
  highContrast: boolean;
  onHighContrastChange: (value: boolean) => void;
  reducedMotion: boolean;
  onReducedMotionChange: (value: boolean) => void;
  zoom: number;
  onZoomChange: (value: number) => void;
  expertMode: boolean;
  onExpertModeChange: (value: boolean) => void;
  preferences: ModernPreferences;
  onMaintenancePreferenceChange: (
    field: 'automaticUpdateCheck' | 'checkDiskSpace' | 'checkBootloaderUnlocked' | 'checkFirmwareHash' | 'checkModuleUpdates' | 'showNotifications' | 'rebootTimeoutSeconds' | 'offerPatchMethods' | 'showRecoveryPatching' | 'keepPatchTemporaryFiles' | 'useBusyboxShell' | 'lowMemoryMode' | 'extraImageExtracts' | 'showCustomRomOptions' | 'keyboxIndex' | 'customizeFont' | 'fontFace' | 'fontSize' | 'toolbarPosition' | 'toolbarShowDevice' | 'toolbarShowTheme' | 'toolbarShowLanguage' | 'createBootTar',
    value: boolean | number | string,
  ) => void;
  onApplicationCommand: (
    action: 'openFolder' | 'openLink' | 'exit',
    target?: 'configuration' | 'logs' | 'cache' | 'documentation' | 'license' | 'releases' | 'reportIssue' | 'source',
  ) => void;
  applicationVersion: string;
  updateCheckState: UpdateCheckState;
  onUpdateCheck: () => void;
  applicationConsoleLines: readonly string[];
  onApplicationConsoleClear: () => void;
  onApplicationConsoleExport: () => void;
}) {
  const { t } = useI18n();
  const standardFontFaces = ['Courier', 'Cascadia Code', 'Consolas', 'SFMono-Regular', 'Menlo', 'Monaco', 'DejaVu Sans Mono', 'Liberation Mono', 'Noto Sans Mono'];
  const fontFaces = standardFontFaces.includes(preferences.fontFace)
    ? standardFontFaces
    : [preferences.fontFace, ...standardFontFaces];
  return (
    <>
      <PageHeader title={t('settings.title')} subtitle={t('settings.subtitle')} />
      <div className="inline-alert" role="status">
        <Icon name="shield" size={18} />
        <span>{t('settings.localPersistence')}</span>
      </div>
      <div className="settings-grid">
        <Card>
          <CardTitle icon="settings">{t('settings.appearance')}</CardTitle>
          <div className="settings-section">
            <label className="field-label" id="theme-label">{t('settings.theme')}</label>
            <div className="segmented" role="group" aria-labelledby="theme-label">
              <button type="button" className={theme === 'dark' ? 'is-active' : ''} aria-pressed={theme === 'dark'} onClick={() => onThemeChange('dark')}>{t('settings.dark')}</button>
              <button type="button" className={theme === 'light' ? 'is-active' : ''} aria-pressed={theme === 'light'} onClick={() => onThemeChange('light')}>{t('settings.light')}</button>
            </div>
          </div>
          <label className="select-field">
            <span>{t('settings.language')}</span>
            <select value={locale} onChange={(event) => onLocaleChange(event.currentTarget.value as Locale)}>
              {localeOptions.map((option) => <option value={option.value} key={option.value}>{option.label}</option>)}
            </select>
          </label>
          <div className="settings-section">
            <div className="zoom-row">
              <span><strong>{t('settings.zoom')}</strong><small>{zoom}%</small></span>
              <div className="zoom-controls">
                <Button variant="ghost" onClick={() => onZoomChange(Math.max(80, zoom - 10))} aria-label={t('settings.zoomOut')}>−</Button>
                <Button variant="ghost" onClick={() => onZoomChange(100)} aria-label={t('settings.zoomReset')}>100%</Button>
                <Button variant="ghost" onClick={() => onZoomChange(Math.min(200, zoom + 10))} aria-label={t('settings.zoomIn')}>+</Button>
              </div>
            </div>
          </div>
          <div className="toggle-stack">
            <Toggle checked={preferences.customizeFont} onChange={(value) => onMaintenancePreferenceChange('customizeFont', value)} label={t('settings.customFont')} description={t('settings.customFontDetail')} />
          </div>
          <label className="select-field">
            <span>{t('settings.fontFace')}</span>
            <select disabled={!preferences.customizeFont} value={preferences.fontFace} onChange={(event) => onMaintenancePreferenceChange('fontFace', event.currentTarget.value)}>
              {fontFaces.map((fontFace) => <option value={fontFace} key={fontFace}>{fontFace}</option>)}
            </select>
          </label>
          <label className="select-field">
            <span>{t('settings.fontSize')}</span>
            <input
              type="number"
              min={6}
              max={50}
              disabled={!preferences.customizeFont}
              value={preferences.fontSize}
              onChange={(event) => {
                const value = event.currentTarget.valueAsNumber;
                if (Number.isInteger(value) && value >= 6 && value <= 50) onMaintenancePreferenceChange('fontSize', value);
              }}
              aria-describedby="font-size-detail"
            />
            <small id="font-size-detail">{t('settings.fontSizeDetail')}</small>
          </label>
          <div className="settings-section settings-toolbar-layout">
            <label className="select-field">
              <span>{t('settings.toolbarPosition')}</span>
              <select value={preferences.toolbarPosition} onChange={(event) => onMaintenancePreferenceChange('toolbarPosition', event.currentTarget.value as ToolbarPosition)}>
                <option value="top">{t('settings.toolbarTop')}</option>
                <option value="right">{t('settings.toolbarRight')}</option>
                <option value="bottom">{t('settings.toolbarBottom')}</option>
                <option value="left">{t('settings.toolbarLeft')}</option>
              </select>
            </label>
            <div className="toggle-stack">
              <Toggle checked={preferences.toolbarShowDevice} onChange={(value) => onMaintenancePreferenceChange('toolbarShowDevice', value)} label={t('settings.toolbarDevice')} description={t('settings.toolbarDeviceDetail')} />
              <Toggle checked={preferences.toolbarShowTheme} onChange={(value) => onMaintenancePreferenceChange('toolbarShowTheme', value)} label={t('settings.toolbarTheme')} description={t('settings.toolbarThemeDetail')} />
              <Toggle checked={preferences.toolbarShowLanguage} onChange={(value) => onMaintenancePreferenceChange('toolbarShowLanguage', value)} label={t('settings.toolbarLanguage')} description={t('settings.toolbarLanguageDetail')} />
            </div>
          </div>
        </Card>
        <Card>
          <CardTitle icon="tools">{t('mode.expert')}</CardTitle>
          <div className="toggle-stack">
            <Toggle checked={expertMode} onChange={onExpertModeChange} label={t('mode.expert')} description={t('settings.expertDetail')} />
            {expertMode ? <>
              <Toggle checked={preferences.offerPatchMethods} onChange={(value) => onMaintenancePreferenceChange('offerPatchMethods', value)} label={t('settings.patchMethods')} description={t('settings.patchMethodsDetail')} />
              <Toggle checked={preferences.showRecoveryPatching} onChange={(value) => onMaintenancePreferenceChange('showRecoveryPatching', value)} label={t('settings.recoveryPatching')} description={t('settings.recoveryPatchingDetail')} />
              <Toggle checked={preferences.keepPatchTemporaryFiles} onChange={(value) => onMaintenancePreferenceChange('keepPatchTemporaryFiles', value)} label={t('settings.keepPatchFiles')} description={t('settings.keepPatchFilesDetail')} />
              <Toggle checked={preferences.createBootTar} onChange={(value) => onMaintenancePreferenceChange('createBootTar', value)} label={t('settings.createBootTar')} description={t('settings.createBootTarDetail')} />
              <Toggle checked={preferences.useBusyboxShell} onChange={(value) => onMaintenancePreferenceChange('useBusyboxShell', value)} label={t('settings.busyboxShell')} description={t('settings.busyboxShellDetail')} />
              <Toggle checked={preferences.lowMemoryMode} onChange={(value) => onMaintenancePreferenceChange('lowMemoryMode', value)} label={t('settings.lowMemory')} description={t('settings.lowMemoryDetail')} />
              <Toggle checked={preferences.extraImageExtracts} onChange={(value) => onMaintenancePreferenceChange('extraImageExtracts', value)} label={t('settings.extraImages')} description={t('settings.extraImagesDetail')} />
              <Toggle checked={preferences.showCustomRomOptions} onChange={(value) => onMaintenancePreferenceChange('showCustomRomOptions', value)} label={t('settings.customRomOptions')} description={t('settings.customRomOptionsDetail')} />
              <Toggle checked={preferences.keyboxIndex} onChange={(value) => onMaintenancePreferenceChange('keyboxIndex', value)} label={t('settings.keyboxIndex')} description={t('settings.keyboxIndexDetail')} />
            </> : null}
          </div>
        </Card>
        <Card>
          <CardTitle icon="shield">{t('settings.accessibility')}</CardTitle>
          <div className="toggle-stack">
            <Toggle checked={highContrast} onChange={onHighContrastChange} label={t('settings.contrast')} description={t('settings.contrastDetail')} />
            <Toggle checked={reducedMotion} onChange={onReducedMotionChange} label={t('settings.motion')} description={t('settings.motionDetail')} />
          </div>
        </Card>
        <Card>
          <CardTitle icon="shield">{t('settings.safety')}</CardTitle>
          <div className="toggle-stack">
            <Toggle checked={preferences.checkDiskSpace} onChange={(value) => onMaintenancePreferenceChange('checkDiskSpace', value)} label={t('settings.diskCheck')} description={t('settings.diskCheckDetail')} />
            <Toggle checked={preferences.checkBootloaderUnlocked} onChange={(value) => onMaintenancePreferenceChange('checkBootloaderUnlocked', value)} label={t('settings.bootloaderCheck')} description={t('settings.bootloaderCheckDetail')} />
            <Toggle checked={preferences.checkFirmwareHash} onChange={(value) => onMaintenancePreferenceChange('checkFirmwareHash', value)} label={t('settings.firmwareHashCheck')} description={t('settings.firmwareHashCheckDetail')} />
          </div>
          <label className="select-field">
            <span>{t('settings.rebootTimeout')}</span>
            <input
              type="number"
              min={1}
              max={3600}
              value={preferences.rebootTimeoutSeconds}
              onChange={(event) => {
                const value = event.currentTarget.valueAsNumber;
                if (Number.isInteger(value) && value >= 1 && value <= 3600) onMaintenancePreferenceChange('rebootTimeoutSeconds', value);
              }}
              aria-describedby="reboot-timeout-detail"
            />
            <small id="reboot-timeout-detail">{t('settings.rebootTimeoutDetail')}</small>
          </label>
        </Card>
        <Card>
          <CardTitle icon="settings">{t('settings.maintenance')}</CardTitle>
          <div className="toggle-stack">
            <Toggle checked={preferences.automaticUpdateCheck} onChange={(value) => onMaintenancePreferenceChange('automaticUpdateCheck', value)} label={t('settings.updateCheck')} description={t('settings.updateCheckDetail')} />
            <Toggle checked={preferences.checkModuleUpdates} onChange={(value) => onMaintenancePreferenceChange('checkModuleUpdates', value)} label={t('settings.moduleUpdates')} description={t('settings.moduleUpdatesDetail')} />
            <Toggle checked={preferences.showNotifications} onChange={(value) => onMaintenancePreferenceChange('showNotifications', value)} label={t('settings.notifications')} description={t('settings.notificationsDetail')} />
          </div>
          <div className="settings-update-check">
            <Button icon="download" disabled={updateCheckState.phase === 'checking'} onClick={onUpdateCheck}>
              {t(updateCheckState.phase === 'checking' ? 'settings.checkingUpdates' : 'settings.checkUpdates')}
            </Button>
            <span role="status" aria-live="polite">
              {updateCheckState.phase === 'current' ? t('settings.applicationCurrent') : null}
              {updateCheckState.phase === 'available' ? t('settings.updateAvailable') : null}
              {updateCheckState.phase === 'failed' ? t('settings.updateCheckFailed') : null}
              {updateCheckState.latestVersion ? <strong>{updateCheckState.latestVersion}</strong> : null}
            </span>
          </div>
        </Card>
        <Card className="settings-shortcuts">
          <CardTitle icon="tools">{t('settings.shortcuts')}</CardTitle>
          <ul>
            <li><kbd>Alt</kbd><kbd>1…9</kbd><span>{t('settings.shortcutNav')}</span></li>
            <li><kbd>Ctrl</kbd><kbd>+</kbd><kbd>−</kbd><kbd>0</kbd><span>{t('settings.shortcutZoom')}</span></li>
            <li><kbd>Tab</kbd><kbd>Enter</kbd><span>{t('settings.shortcutFocus')}</span></li>
          </ul>
        </Card>
        <Card className="settings-application-shell">
          <CardTitle icon="folder">{t('settings.applicationFiles')}</CardTitle>
          <p className="settings-card-detail">{t('settings.applicationFilesDetail')}</p>
          <div className="settings-shell-actions">
            <Button icon="settings" onClick={() => onApplicationCommand('openFolder', 'configuration')}>{t('settings.openConfiguration')}</Button>
            <Button icon="logs" onClick={() => onApplicationCommand('openFolder', 'logs')}>{t('settings.openLogs')}</Button>
            <Button icon="folder" onClick={() => onApplicationCommand('openFolder', 'cache')}>{t('settings.openCache')}</Button>
            <Button variant="danger" icon="close" onClick={() => onApplicationCommand('exit')}>{t('settings.exitApplication')}</Button>
          </div>
        </Card>
        <Card className="settings-about">
          <CardTitle icon="settings">{t('settings.about')}</CardTitle>
          <p className="settings-card-detail">{t('settings.aboutDetail')}</p>
          <dl className="settings-about-details">
            <div><dt>{t('settings.version')}</dt><dd>{applicationVersion || t('settings.versionUnavailable')}</dd></div>
            <div><dt>{t('settings.license')}</dt><dd>GNU GPL v3</dd></div>
          </dl>
          <div className="settings-shell-actions" aria-label={t('settings.helpLinks')}>
            <Button icon="tools" onClick={() => onApplicationCommand('openLink', 'documentation')}>{t('settings.documentation')}</Button>
            <Button icon="logs" onClick={() => onApplicationCommand('openLink', 'releases')}>{t('settings.releaseNotes')}</Button>
            <Button icon="warning" onClick={() => onApplicationCommand('openLink', 'reportIssue')}>{t('settings.reportIssue')}</Button>
            <Button icon="folder" onClick={() => onApplicationCommand('openLink', 'source')}>{t('settings.sourceCode')}</Button>
            <Button variant="ghost" icon="shield" onClick={() => onApplicationCommand('openLink', 'license')}>{t('settings.viewLicense')}</Button>
          </div>
        </Card>
        <Card className="settings-console">
          <CardTitle icon="logs">{t('settings.console')}</CardTitle>
          <p className="settings-card-detail">{t('settings.consoleDetail')}</p>
          <div className="settings-console-output" role="log" aria-live="polite" aria-label={t('settings.console')}>
            {applicationConsoleLines.length
              ? applicationConsoleLines.map((line, index) => <div key={`${index}-${line}`}>{line}</div>)
              : <span>{t('settings.consoleEmpty')}</span>}
          </div>
          <div className="settings-shell-actions">
            <Button icon="close" disabled={!applicationConsoleLines.length} onClick={onApplicationConsoleClear}>{t('settings.consoleClear')}</Button>
            <Button icon="backup" disabled={!applicationConsoleLines.length} onClick={onApplicationConsoleExport}>{t('settings.consoleExport')}</Button>
          </div>
        </Card>
      </div>
    </>
  );
}
