// Stable public surface for the route shell and existing tests. Page implementations
// live with their feature so changes in one workflow do not couple every route.
export { DashboardPage } from './dashboard/DashboardPage';
export { DevicePage } from './device/DevicePage';
export { FirmwarePage } from './firmware/FirmwarePage';
export { RootPage } from './root/RootPage';
export { AppsPage } from './apps/AppsPage';
export { BackupsPage } from './backups/BackupsPage';
export {
  ToolsPage,
  MAX_LOGCAT_PREVIEW_LINES,
  appendLogcatProgressBatch,
  hasUnredactedLogcatState,
  initialLogcatUiState,
  initialPushUiState,
  purgeUnredactedLogcatState,
  useLogcatExpertGuard,
  type LogcatUiState,
  type PushUiState,
} from './tooling/ToolsPage';
export { SettingsPage } from './settings/SettingsPage';
export type { UpdateCheckState } from './settings/SettingsPage';
