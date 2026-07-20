import { describe, expect, it, vi } from 'vitest';
import { bridge, commandTimeoutMs, normalizeOperationStatus, normalizePreferences, normalizeSnapshot, parseBridgeMessage, snapshotFromEvent } from '../bridge';
import { commands } from '../commands';
import type { BridgeRequest, HostSnapshot } from '../types';

const snapshotPreferences = {
  schemaVersion: 1 as const,
  theme: 'dark' as const,
  locale: 'en' as const,
  highContrast: false,
      reducedMotion: false,
      zoom: 100,
      expertMode: false,
};

function hostFor(responseResult: (request: BridgeRequest) => Record<string, unknown>) {
  const postMessage = vi.fn((raw: string) => {
    const request = JSON.parse(raw) as BridgeRequest;
    queueMicrotask(() => {
      window.dispatchEvent(new CustomEvent('pixelflasher:message', {
        detail: {
          version: 2,
          requestId: request.requestId,
          ok: true,
          result: { ...responseResult(request), revision: 22 },
        },
      }));
    });
  });
  window.pixelflasher = { postMessage };
  return postMessage;
}

describe('PixelFlasher bridge protocol', () => {
  it('allows long-running firmware processing and flash execution to finish', () => {
    expect(commandTimeoutMs(commands.firmwareProcess)).toBe(2 * 60 * 60_000);
    expect(commandTimeoutMs(commands.flashExecute)).toBe(4 * 60 * 60_000);
    expect(commandTimeoutMs(commands.firmwareSelect)).toBe(60 * 60_000);
    expect(commandTimeoutMs(commands.bootPatch)).toBe(3 * 60 * 60_000);
    expect(commandTimeoutMs(commands.bootFlash)).toBe(20 * 60_000);
    expect(commandTimeoutMs(commands.bootLive)).toBe(10 * 60_000);
    expect(commandTimeoutMs(commands.partitionsRead)).toBe(20 * 60_000);
    expect(commandTimeoutMs(commands.partitionsWrite)).toBe(20 * 60_000);
    expect(commandTimeoutMs(commands.partitionsErase)).toBe(10 * 60_000);
    expect(commandTimeoutMs(commands.toolsPushFiles)).toBe(6 * 60 * 60_000);
    expect(commandTimeoutMs(commands.supportCreate)).toBe(30 * 60_000);
    expect(commandTimeoutMs(commands.toolsLogcat)).toBe(3 * 60_000);
    expect(commandTimeoutMs(commands.deviceScan)).toBe(10 * 60_000);
  });

  it('always sends v2 and requires expectedRevision for mutations', async () => {
    const postMessage = hostFor(() => ({ accepted: true }));
    await bridge.command(commands.nativePickFile, { purpose: 'firmware.select', title: 'Choose file' }, 22);
    const request = JSON.parse(postMessage.mock.calls[0][0]) as BridgeRequest;
    expect(request).toMatchObject({
      version: 2,
      command: 'native.pickFile',
      payload: { purpose: 'firmware.select', title: 'Choose file' },
      expectedRevision: 22,
    });
    expect(request.requestId).toEqual(expect.any(String));
    await expect(bridge.command(commands.nativePickFile, { purpose: 'firmware.select' }))
      .rejects.toThrow('current revision is required');
  });

  it('uses snapshot.get and preserves a numeric expected revision', async () => {
    const snakeSnapshot = {
      revision: 22,
      preferences: snapshotPreferences,
      devices: [],
      selected_serial: 'SERIAL-1',
      selected_serials: ['SERIAL-1'],
      active_operation: { id: 'op-1', label: 'Flash', status: 'SUCCESS', progress: 100 },
      last_result: { status: 'success' },
    } as unknown as HostSnapshot;
    const postMessage = hostFor((request) => request.command === 'snapshot.get'
      ? snakeSnapshot as unknown as Record<string, unknown>
      : {});
    const snapshot = await bridge.getSnapshot();
    const request = JSON.parse(postMessage.mock.calls[0][0]) as BridgeRequest;
    expect(request.command).toBe('snapshot.get');
    expect(request.expectedRevision).toBeNull();
    expect(snapshot.selectedSerials).toEqual(['SERIAL-1']);
    expect(snapshot.activeOperation?.status).toBe('success');
    expect(snapshot.lastResult).toMatchObject({ status: 'success' });

    await bridge.command(commands.deviceSelect, { serials: ['SERIAL-1'] }, 22);
    const revisioned = JSON.parse(postMessage.mock.calls[1][0]) as BridgeRequest;
    expect(revisioned.expectedRevision).toBe(22);
  });

  it('normalizes direct snake_case snapshot event payloads', () => {
    const eventSnapshot = snapshotFromEvent({
      version: 2,
      event: 'snapshot',
      payload: {
        revision: 9,
        preferences: snapshotPreferences,
        devices: [],
        selected_serial: 'ABC',
        selected_serials: ['ABC', 'DEF'],
        active_operation: { id: 'op', label: 'Work', status: 'cancelled' },
        last_result: { status: 'cancelled' },
      },
      revision: 9,
    });
    expect(eventSnapshot).toMatchObject({
      revision: 9,
      selectedSerial: 'ABC',
      selectedSerials: ['ABC', 'DEF'],
      activeOperation: { status: 'cancelled' },
      lastResult: { status: 'cancelled' },
    });
  });

  it('rejects wrong versions, aliases, and unknown envelope fields', () => {
    const response = {
      version: 2,
      requestId: 'strict-1',
      ok: true,
      result: {},
    };
    expect(parseBridgeMessage(response)).toEqual(response);
    expect(parseBridgeMessage({ ...response, version: 1 })).toBeNull();
    expect(parseBridgeMessage({ ...response, responseId: 'strict-1' })).toBeNull();
    expect(parseBridgeMessage({ ...response, snapshot: {} })).toBeNull();
  });

  it('loads and updates strictly validated host preferences', async () => {
    const preferences = {
      schemaVersion: 1 as const,
      theme: 'light' as const,
      locale: 'fr' as const,
      highContrast: true,
      reducedMotion: true,
      zoom: 120,
      expertMode: true,
    };
    const postMessage = hostFor((request) => ({
      status: 'SUCCESS',
      message: request.command === 'settings.update' ? 'Preferences saved.' : 'Preferences loaded.',
      value: {
        preferences: request.command === 'settings.update'
          ? { ...preferences, ...request.payload }
          : preferences,
      },
    }));

    await expect(bridge.getPreferences()).resolves.toEqual(preferences);
    const updated = await bridge.updatePreferences({ theme: 'dark' }, 22);
    expect(updated).toMatchObject({
      preferences: { ...preferences, theme: 'dark' },
      message: 'Preferences saved.',
      revision: 22,
    });

    const getRequest = JSON.parse(postMessage.mock.calls[0][0]) as BridgeRequest;
    const updateRequest = JSON.parse(postMessage.mock.calls[1][0]) as BridgeRequest;
    expect(getRequest).toMatchObject({ command: 'settings.get', payload: {}, expectedRevision: null });
    expect(updateRequest).toMatchObject({ command: 'settings.update', payload: { theme: 'dark' }, expectedRevision: 22 });
    expect(normalizePreferences({ ...preferences, zoom: 80 }).zoom).toBe(80);
    expect(normalizePreferences({ ...preferences, zoom: 200 }).zoom).toBe(200);
    expect(() => normalizePreferences({ ...preferences, zoom: 79 })).toThrow('invalid preferences');
    expect(() => normalizePreferences({ ...preferences, zoom: 201 })).toThrow('invalid preferences');
  });

  it('keeps terminal operation outcomes distinct and never infers empty success', () => {
    expect(normalizeOperationStatus('success')).toBe('success');
    expect(normalizeOperationStatus('CANCELLED')).toBe('cancelled');
    expect(normalizeOperationStatus('failed')).toBe('failed');
    expect(normalizeOperationStatus(undefined)).toBe('idle');
    expect(normalizeSnapshot({
      revision: 1,
      preferences: snapshotPreferences,
      devices: [],
      active_operation: null,
    } as HostSnapshot).activeOperation).toBeNull();
    expect(normalizeSnapshot({
      revision: 2,
      preferences: snapshotPreferences,
      devices: [],
      active_operation: {
        operation_id: 'operation-123',
        kind: 'apps.action',
        label: 'Install APK',
      },
    } as unknown as HostSnapshot).activeOperation).toEqual({
      id: 'operation-123',
      kind: 'apps.action',
      label: 'Install APK',
      status: 'running',
    });
  });
});
