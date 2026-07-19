import { useState } from 'react';
import { assets } from '../../assets';
import { commands } from '../../commands';
import { demoFirmwares } from '../../demoData';
import { useI18n } from '../../i18n';
import { Badge, Button, Card, CardTitle, Icon, Meter, PageHeader } from '../../components/ui';
import { isToolchainReady, selectedGrant, type SharedPageProps } from '../shared';

export function DashboardPage({ snapshot, selectedSerials, onCommand }: SharedPageProps) {
  const { t } = useI18n();
  const primary = snapshot.devices.find((device) => selectedSerials.includes(device.serial)) ?? snapshot.devices[0];
  const firmware = snapshot.firmware ?? (window.pixelflasher?.__mock ? demoFirmwares[0] : null);
  const toolchainReady = isToolchainReady(snapshot);
  const [setupSource, setSetupSource] = useState<'official' | 'directory' | null>(null);

  const installOfficialPlatformTools = async () => {
    if (setupSource) return;
    setSetupSource('official');
    try {
      await onCommand(commands.platformToolsSetup, { source: 'official' });
    } finally {
      setSetupSource(null);
    }
  };

  const choosePlatformToolsDirectory = async () => {
    if (setupSource) return;
    setSetupSource('directory');
    try {
      const picked = await onCommand(commands.nativePickDirectory, {
        purpose: 'platformTools.setup.directory',
        title: t('dashboard.toolsChooseDirectory'),
      });
      const grant = selectedGrant(picked);
      if (grant) {
        await onCommand(commands.platformToolsSetup, { source: 'directory', grant });
      }
    } finally {
      setSetupSource(null);
    }
  };

  const quickActions = [
    { icon: 'scan', title: t('dashboard.scan'), detail: t('dashboard.scanDetail'), command: commands.deviceScan, payload: {}, disabled: !toolchainReady },
    { icon: 'rebootPng', title: t('dashboard.reboot'), detail: t('dashboard.rebootDetail'), command: commands.deviceReboot, payload: { serial: primary?.serial, mode: 'system' }, disabled: !primary },
    { icon: 'switchSlot', title: t('dashboard.slot'), detail: t('dashboard.slotDetail'), command: commands.deviceSwitchSlot, payload: { serial: primary?.serial, slot: primary?.slot === 'a' ? 'b' : 'a' }, disabled: !primary || primary.mode !== 'fastboot' || primary.slot === 'unknown' },
  ] as const;

  return (
    <>
      <PageHeader title={t('dashboard.title')} subtitle={t('dashboard.subtitle')} />

      <div className={`platform-banner ${toolchainReady ? '' : 'platform-banner--warning'}`} role={toolchainReady ? 'status' : 'alert'}>
        <span className="platform-banner__icon"><Icon name={toolchainReady ? 'check' : 'warningPng'} size={19} /></span>
        <span><strong>{t(toolchainReady ? 'dashboard.toolsReady' : 'dashboard.toolsNeeded')}</strong><small>{t(toolchainReady ? 'dashboard.toolsDetail' : 'dashboard.toolsNeededDetail')}</small></span>
        {toolchainReady ? (
          <Badge tone="accent">ADB {snapshot.toolchain?.version ?? ''}</Badge>
        ) : (
          <div className="platform-banner__actions">
            <Button variant="primary" icon="tools" onClick={() => void installOfficialPlatformTools()} disabled={setupSource !== null}>{t('dashboard.toolsInstallOfficial')}</Button>
            <Button icon="folder" onClick={() => void choosePlatformToolsDirectory()} disabled={setupSource !== null}>{t('dashboard.toolsChooseDirectory')}</Button>
          </div>
        )}
      </div>

      <div className="dashboard-grid">
        <Card className="device-hero">
          <CardTitle icon="devices" after={<Badge tone={primary?.mode.startsWith('fastboot') ? 'warning' : 'success'}>{primary?.mode.toUpperCase() ?? 'OFFLINE'}</Badge>}>
            {t('dashboard.connected')}
          </CardTitle>
          {primary ? (
            <div className="device-hero__content">
              <img className="device-hero__render" src={assets.phoneRender} alt="" aria-hidden="true" />
              <div className="device-hero__details">
                <span className="eyebrow">{primary.model}</span>
                <h2>{primary.name}</h2>
                <code>{primary.serial}</code>
                <dl className="spec-grid">
                  <div><dt>Android</dt><dd>{primary.androidVersion}</dd></div>
                  <div><dt>{t('common.build')}</dt><dd>{primary.build}</dd></div>
                  <div><dt>{t('flash.review.slot')}</dt><dd>{primary.slot.toUpperCase()}</dd></div>
                  <div><dt>{t('device.bootloader')}</dt><dd>{primary.bootloader}</dd></div>
                </dl>
                <Meter value={primary.battery} label={t('device.battery')} />
              </div>
            </div>
          ) : null}
        </Card>

        <Card className="quick-card">
          <CardTitle icon="flash">{t('dashboard.quick')}</CardTitle>
          <div className="quick-list">
            {quickActions.map((action) => (
              <button type="button" className="quick-action" key={action.command} onClick={() => void onCommand(action.command, action.payload)} disabled={action.disabled}>
                <span className="quick-action__icon"><Icon name={action.icon} size={22} /></span>
                <span><strong>{action.title}</strong><small>{action.detail}</small></span>
                <Icon name="right" size={17} />
              </button>
            ))}
          </div>
        </Card>
      </div>

      <div className="summary-grid">
        <Card className="summary-card">
          <span className="summary-card__icon"><Icon name="firmware" size={23} /></span>
          <span><small>{t('dashboard.firmware')}</small><strong>{firmware?.build ?? '—'}</strong><em>{firmware?.name ?? t('common.none')}</em></span>
        </Card>
        <Card className="summary-card">
          <span className="summary-card__icon"><Icon name="shield" size={23} /></span>
          <span><small>{t('dashboard.security')}</small><strong>{primary?.securityPatch ?? '—'}</strong><em>{primary ? `Verified Boot ${primary.bootloader === 'unlocked' ? 'unlocked' : primary.bootloader === 'locked' ? 'active' : 'unknown'}` : t('common.none')}</em></span>
        </Card>
        <Card className="summary-card">
          <span className="summary-card__icon"><Icon name="adb" size={23} /></span>
          <span><small>{t('dashboard.deviceMode')}</small><strong>{primary?.mode.toUpperCase() ?? 'OFFLINE'}</strong><em>{primary?.connection ?? 'No connection'}</em></span>
        </Card>
      </div>
    </>
  );
}
