import adb from './assets/icons/adb.svg';
import android from './assets/icons/android.svg';
import backup from './assets/icons/backup.svg';
import bootloader from './assets/icons/bootloader.svg';
import dashboard from './assets/icons/dashboard.svg';
import devices from './assets/icons/devices.svg';
import firmware from './assets/icons/firmware.svg';
import flash from './assets/icons/flash.svg';
import folder from './assets/icons/folder.svg';
import logs from './assets/icons/logs.svg';
import patchBoot from './assets/icons/patch_boot.svg';
import reboot from './assets/icons/reboot.svg';
import root from './assets/icons/root.svg';
import settings from './assets/icons/settings.svg';
import slot from './assets/icons/slot.svg';
import tools from './assets/icons/tools.svg';
import warning from './assets/icons/warning.svg';

import appLogo from './assets/images/icon-dark-256.png';
import phoneRender from './assets/images/device-pixel-render.png';
import scan from './assets/images/scan-24.png';
import rebootPng from './assets/images/reboot-24.png';
import switchSlot from './assets/images/switch-slot-24.png';
import installMagisk from './assets/images/install-magisk-24.png';
import packages from './assets/images/packages-24.png';
import backupPng from './assets/images/backup-24.png';
import folderPng from './assets/images/folder-24.png';
import settingsPng from './assets/images/settings-24.png';
import flashPng from './assets/images/flash-24.png';
import patch from './assets/images/patch-24.png';
import check from './assets/images/check-24.png';
import warningPng from './assets/images/warning-24.png';
import left from './assets/images/left-24.png';
import right from './assets/images/right-24.png';
import minimize from './assets/images/bottom-24.png';
import maximize from './assets/images/advanced-config-24.png';
import close from './assets/images/exit-24.png';
import download from './assets/images/cloud-download-24.png';
import restore from './assets/images/restore-24.png';
import wrench from './assets/images/wrench-24.png';
import shell from './assets/images/shell-24.png';
import shield from './assets/images/shield-24.png';
import lock from './assets/images/lock-24.png';
import unlock from './assets/images/unlock-24.png';
import androidPng from './assets/images/android-24.png';
import processFile from './assets/images/process_file-24.png';
import boot from './assets/images/boot-24.png';
import slotA from './assets/images/slot-a-48.png';
import slotB from './assets/images/slot-b-48.png';
import magisk from './assets/images/magisk-48.png';
import apatch from './assets/images/apatch-48.png';
import kernelSu from './assets/images/kernelsu-48.png';
import sukiSu from './assets/images/sukisu-24.png';
import wildKsu from './assets/images/wild_ksu-24.png';

export const assets = {
  adb,
  android,
  backup,
  bootloader,
  dashboard,
  devices,
  firmware,
  flash,
  folder,
  logs,
  patchBoot,
  reboot,
  root,
  settings,
  slot,
  tools,
  warning,
  appLogo,
  phoneRender,
  scan,
  rebootPng,
  switchSlot,
  installMagisk,
  packages,
  backupPng,
  folderPng,
  settingsPng,
  flashPng,
  patch,
  check,
  warningPng,
  left,
  right,
  minimize,
  maximize,
  close,
  download,
  restore,
  wrench,
  shell,
  shield,
  lock,
  unlock,
  androidPng,
  processFile,
  boot,
  slotA,
  slotB,
  magisk,
  apatch,
  kernelSu,
  sukiSu,
  wildKsu,
} as const;

export type AssetName = keyof typeof assets;
