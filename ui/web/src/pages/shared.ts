import type { BridgeCommand } from '../commands';
import type { HostSnapshot } from '../types';

export interface SharedPageProps {
  snapshot: HostSnapshot;
  selectedSerials: string[];
  onSelectionChange: (serials: string[]) => void | Promise<void>;
  onCommand: (
    command: BridgeCommand,
    payload?: Record<string, unknown>,
    options?: CommandRunOptions,
  ) => Promise<{
    result: Record<string, unknown>;
    revision?: number;
  } | null>;
}

export interface CommandRunOptions {
  /** Return the typed CANCELLED result instead of reporting it as an error. */
  returnCancelled?: boolean;
  /** Bind a follow-up command to the revision returned by its predecessor. */
  expectedRevision?: number;
}

export function record(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? value as Record<string, unknown> : {};
}

export function selectedGrant(response: Awaited<ReturnType<SharedPageProps['onCommand']>>) {
  if (!response) return '';
  const result = record(response.result);
  const value = record(result.value);
  const data = record(result.data ?? value.data);
  return typeof data.grant === 'string' ? data.grant : '';
}

export function selectedGrants(response: Awaited<ReturnType<SharedPageProps['onCommand']>>) {
  if (!response) return [];
  const result = record(response.result);
  const value = record(result.value);
  const data = record(result.data ?? value.data);
  return Array.isArray(data.grants)
    ? data.grants.flatMap((entry) => {
      const grant = record(entry).grant;
      return typeof grant === 'string' && grant ? [grant] : [];
    })
    : [];
}

export function isToolchainReady(snapshot: HostSnapshot) {
  return snapshot.toolchain?.ready ?? Boolean(snapshot.toolchain?.adb && snapshot.toolchain?.fastboot);
}
