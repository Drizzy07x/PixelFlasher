import { localeOptions, useI18n } from '../../i18n';
import type { Locale, ModernPreferences, Theme } from '../../types';
import { Button, Card, CardTitle, Icon, PageHeader, Toggle } from '../../components/ui';

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
    field: 'automaticUpdateCheck' | 'checkDiskSpace' | 'checkBootloaderUnlocked' | 'checkFirmwareHash' | 'checkModuleUpdates' | 'showNotifications' | 'rebootTimeoutSeconds',
    value: boolean | number,
  ) => void;
}) {
  const { t } = useI18n();
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
        </Card>
        <Card>
          <CardTitle icon="tools">{t('mode.expert')}</CardTitle>
          <div className="toggle-stack">
            <Toggle checked={expertMode} onChange={onExpertModeChange} label={t('mode.expert')} description={t('settings.expertDetail')} />
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
        </Card>
        <Card className="settings-shortcuts">
          <CardTitle icon="tools">{t('settings.shortcuts')}</CardTitle>
          <ul>
            <li><kbd>Alt</kbd><kbd>1…9</kbd><span>{t('settings.shortcutNav')}</span></li>
            <li><kbd>Ctrl</kbd><kbd>+</kbd><kbd>−</kbd><kbd>0</kbd><span>{t('settings.shortcutZoom')}</span></li>
            <li><kbd>Tab</kbd><kbd>Enter</kbd><span>{t('settings.shortcutFocus')}</span></li>
          </ul>
        </Card>
      </div>
    </>
  );
}
