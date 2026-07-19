import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  BridgeError,
  bridge,
  interactionFromEvent,
  normalizeOperationStatus,
  normalizePreferences,
  normalizeSnapshot,
  operationFromEvent,
  parseBridgeMessage,
  snapshotFromEvent,
} from '../bridge';
import { commands } from '../commands';
import type { BridgeEvent, BridgeRequest, Device, HostSnapshot } from '../types';

const snapshotPreferences = {
  schemaVersion: 1 as const,
  theme: 'dark' as const,
  locale: 'en' as const,
  highContrast: false,
  reducedMotion: false,
  zoom: 100,
};

const originalBridge = window.pixelflasher;

function dispatch(detail: unknown) {
  window.dispatchEvent(new CustomEvent('pixelflasher:message', { detail }));
}

function respondingHost(
  reply: (request: BridgeRequest) => unknown,
) {
  const postMessage = vi.fn((raw: string) => {
    const request = JSON.parse(raw) as BridgeRequest;
    const response = reply(request);
    if (response !== undefined) queueMicrotask(() => dispatch(response));
  });
  window.pixelflasher = { postMessage };
  return postMessage;
}

afterEach(() => {
  vi.useRealTimers();
  window.pixelflasher = originalBridge;
});

describe('bridge v2 validation boundaries', () => {
  it.each([
    null,
    3,
    {},
    { schemaVersion: 0, theme: 'dark', locale: 'en', highContrast: false, reducedMotion: false, zoom: 100 },
    { schemaVersion: 1, theme: 'system', locale: 'en', highContrast: false, reducedMotion: false, zoom: 100 },
    { schemaVersion: 1, theme: 'dark', locale: 4, highContrast: false, reducedMotion: false, zoom: 100 },
    { schemaVersion: 1, theme: 'dark', locale: 'de', highContrast: false, reducedMotion: false, zoom: 100 },
    { schemaVersion: 1, theme: 'dark', locale: 'en', highContrast: 'no', reducedMotion: false, zoom: 100 },
    { schemaVersion: 1, theme: 'dark', locale: 'en', highContrast: false, reducedMotion: 'no', zoom: 100 },
    { schemaVersion: 1, theme: 'dark', locale: 'en', highContrast: false, reducedMotion: false, zoom: '100' },
    { schemaVersion: 1, theme: 'dark', locale: 'en', highContrast: false, reducedMotion: false, zoom: 100.5 },
    { schemaVersion: 1, theme: 'dark', locale: 'en', highContrast: false, reducedMotion: false, zoom: 79 },
    { schemaVersion: 1, theme: 'dark', locale: 'en', highContrast: false, reducedMotion: false, zoom: 201 },
  ])('rejects malformed preferences %#', (value) => {
    expect(() => normalizePreferences(value)).toThrow(BridgeError);
  });

  it('accepts every supported locale at the preference boundary', () => {
    for (const locale of ['en', 'es', 'fr', 'it', 'zh_CN', 'zh_TW'] as const) {
      expect(normalizePreferences({
        schemaVersion: 1,
        theme: locale === 'en' ? 'light' : 'dark',
        locale,
        highContrast: locale === 'fr',
        reducedMotion: locale === 'it',
        zoom: 100,
      }).locale).toBe(locale);
    }
  });

  it('accepts only exact success, failure and event envelopes', () => {
    const success = { version: 2, requestId: 'ok', ok: true, result: {} };
    const failure = {
      version: 2,
      requestId: 'failure',
      ok: false,
      error: { code: 'denied', message: 'No.', details: { field: 'grant' } },
    };
    const event = { version: 2, event: 'runtime', revision: 4, payload: { state: 'ready' } };
    expect(parseBridgeMessage(JSON.stringify(success))).toEqual(success);
    expect(parseBridgeMessage(failure)).toEqual(failure);
    expect(parseBridgeMessage(event)).toEqual(event);

    const malformed: unknown[] = [
      '{', null, [], { version: 1 },
      { ...success, requestId: 7 },
      { ...success, requestId: 'x'.repeat(129) },
      { ...success, result: [] },
      { ...success, extra: true },
      { version: 2, requestId: 'maybe', ok: 'yes', result: {} },
      { ...failure, error: null },
      { ...failure, error: { code: 4, message: 'No.' } },
      { ...failure, error: { code: 'denied', message: 4 } },
      { ...failure, error: { code: 'denied', message: 'No.', details: [] } },
      { ...failure, error: { code: 'denied', message: 'No.', mystery: true } },
      { version: 2, event: 'unknown', revision: 0, payload: {} },
      { ...event, payload: [] },
      { ...event, revision: -1 },
      { ...event, revision: 1.5 },
      { ...event, extra: true },
    ];
    for (const candidate of malformed) expect(parseBridgeMessage(candidate)).toBeNull();
  });

  it('normalizes every terminal and active operation spelling', () => {
    for (const value of ['success', 'succeeded', 'complete', 'completed']) {
      expect(normalizeOperationStatus(` ${value.toUpperCase()} `)).toBe('success');
    }
    for (const value of ['cancelled', 'canceled']) expect(normalizeOperationStatus(value)).toBe('cancelled');
    for (const value of ['failed', 'failure', 'error']) expect(normalizeOperationStatus(value)).toBe('failed');
    for (const value of ['pending', 'queued']) expect(normalizeOperationStatus(value)).toBe('pending');
    for (const value of ['running', 'active', 'in_progress']) expect(normalizeOperationStatus(value)).toBe('running');
    expect(normalizeOperationStatus(7)).toBe('idle');
    expect(normalizeOperationStatus('unexpected')).toBe('idle');
  });

  it('normalizes sparse devices, firmware aliases and lock evidence safely', () => {
    const sparseDevice = {
      serial: 'SPARSE',
      codename: 'akita',
      android_version: '16',
      security_patch: '2026-01-01',
      root: 1,
      bootloader: 'invalid',
      slot: 'invalid',
      connection: 'Bluetooth',
    } as unknown as Device;
    const evidence = {
      serial: 'SPARSE',
      device_codename: 'akita',
      firmware_hash: 'a'.repeat(64),
      firmware_build: 'BUILD',
      flash_operation_id: 'op',
      flash_plan_fingerprint: 'fingerprint',
      snapshot_revision: 3,
      required_partitions: ['boot'],
      flashed_partitions: ['boot'],
      slots: ['a'],
    };
    const normalized = normalizeSnapshot({
      revision: Number.NaN,
      preferences: snapshotPreferences,
      devices: [sparseDevice],
      selected_serial: 'SPARSE',
      active_operation: { id: 'op', label: 'Queued', status: 'QUEUED' },
      last_result: { status: 'failed' },
      firmware: {
        path: '/tmp/ota.zip',
        build: 'BUILD',
        type: 'ota',
        channel: 'beta',
      },
      bootloader_lock_evidence: [evidence, null, { serial: 'bad' }],
    } as unknown as HostSnapshot);

    expect(normalized).toMatchObject({
      revision: 0,
      selectedSerial: 'SPARSE',
      selectedSerials: ['SPARSE'],
      activeOperation: { status: 'pending' },
      lastResult: { status: 'failed' },
      firmware: {
        id: 'BUILD',
        name: 'BUILD',
        kind: 'ota',
        channel: 'beta',
        size: '—',
      },
    });
    expect(normalized.devices[0]).toMatchObject({
      name: 'akita', model: 'akita', mode: 'offline', androidVersion: '16',
      securityPatch: '2026-01-01', bootloader: 'unknown', slot: 'unknown',
      battery: 0, connection: 'USB', rooted: true,
    });
    expect(normalized.bootloaderLockEvidence).toEqual([{
      serial: 'SPARSE',
      snapshot_revision: 3,
    }]);
  });

  it('normalizes firmware variants and selection fallbacks', () => {
    const base = { revision: 2, preferences: snapshotPreferences, devices: [] };
    expect(normalizeSnapshot({ ...base, selectedSerial: 'ONLY' } as unknown as HostSnapshot).selectedSerials).toEqual(['ONLY']);
    expect(normalizeSnapshot({ ...base, selectedSerials: [] } as unknown as HostSnapshot).selectedSerial).toBeNull();
    expect(normalizeSnapshot({ ...base, firmware: {} } as unknown as HostSnapshot).firmware).toBeNull();

    const custom = normalizeSnapshot({
      ...base,
      firmware: { hash: 'b'.repeat(64), type: 'custom_rom', name: '', version: 1, device: 2 },
    } as unknown as HostSnapshot).firmware;
    expect(custom).toMatchObject({ id: 'b'.repeat(64), name: 'Selected firmware', kind: 'custom', channel: 'stable' });

    const factory = normalizeSnapshot({
      ...base,
      firmware: { build: 'F', type: 'other', name: 'Factory', kind: 'invalid' },
    } as unknown as HostSnapshot).firmware;
    expect(factory).toMatchObject({ id: 'F', name: 'Factory', kind: 'factory' });
  });

  it('extracts only well-formed snapshot, progress and interaction events', () => {
    const runtime = { version: 2, event: 'runtime', revision: 1, payload: {} } as BridgeEvent;
    expect(snapshotFromEvent(runtime)).toBeNull();
    expect(operationFromEvent(runtime)).toBeNull();
    expect(interactionFromEvent(runtime)).toBeNull();

    expect(operationFromEvent({ ...runtime, event: 'progress', payload: {} })).toBeNull();
    expect(operationFromEvent({
      ...runtime,
      event: 'progress',
      payload: { operation_id: 'op', phase: 'finished', percent: 100, message: 'Done' },
    })).toEqual({ id: 'op', label: 'Done', status: 'success', progress: 100, detail: 'Done' });
    expect(operationFromEvent({
      ...runtime,
      event: 'progress',
      payload: { operation_id: 'op-2', phase: 3 },
    })).toEqual({ id: 'op-2', label: 'running', status: 'running', progress: undefined, detail: undefined });

    expect(interactionFromEvent({ ...runtime, event: 'interaction', payload: {} })).toBeNull();
    expect(interactionFromEvent({
      ...runtime,
      event: 'interaction',
      payload: { operation_id: 'op', expected_revision: 8 },
    })).toEqual({
      operationId: 'op', kind: 'confirm', title: '', message: '', expectedRevision: 8,
      targetSerial: null, destructive: false, reinforced: false,
    });
    expect(interactionFromEvent({
      ...runtime,
      event: 'interaction',
      payload: {
        operation_id: 'op', expected_revision: 8, kind: 'warning', title: 'Careful',
        message: 'Proceed?', target_serial: 'SERIAL', destructive: true, reinforced: true,
      },
    })).toMatchObject({ kind: 'warning', title: 'Careful', targetSerial: 'SERIAL', destructive: true, reinforced: true });
  });
});

describe('bridge client failure and lifecycle behavior', () => {
  it('rejects when the host bridge is absent', async () => {
    window.pixelflasher = undefined;
    await expect(bridge.getSnapshot()).rejects.toThrow('host bridge is unavailable');
  });

  it('surfaces exact host failures and ignores orphan responses', async () => {
    const postMessage = respondingHost((request) => ({
      version: 2,
      requestId: request.requestId,
      ok: false,
      error: { code: 'policy_denied', message: 'Denied by safety policy.' },
    }));
    dispatch({ version: 2, requestId: 'orphan', ok: true, result: {} });
    const error = await bridge.command(commands.deviceScan, {}, 1).catch((reason: unknown) => reason);
    expect(error).toBeInstanceOf(BridgeError);
    expect(error).toMatchObject({ message: 'Denied by safety policy.', response: { error: { code: 'policy_denied' } } });
    expect(postMessage).toHaveBeenCalledOnce();
  });

  it('notifies subscribers and supports deterministic unsubscribe', () => {
    const listener = vi.fn();
    const unsubscribe = bridge.subscribe(listener);
    const event = { version: 2, event: 'runtime', revision: 1, payload: { status: 'ready' } };
    dispatch(event);
    expect(listener).toHaveBeenCalledWith(event);
    expect(unsubscribe()).toBe(true);
    dispatch(event);
    expect(listener).toHaveBeenCalledOnce();
  });

  it('rejects timed-out commands and cleans the pending request', async () => {
    vi.useFakeTimers();
    window.pixelflasher = { postMessage: vi.fn() };
    const pending = bridge.command(commands.deviceScan, {}, 1);
    const assertion = expect(pending).rejects.toThrow('Timed out waiting for device.scan');
    await vi.advanceTimersByTimeAsync(60_000);
    await assertion;
  });

  it('rejects failed and malformed preference result shapes', async () => {
    respondingHost((request) => ({
      version: 2,
      requestId: request.requestId,
      ok: true,
      result: { status: 'FAILED' },
    }));
    await expect(bridge.getPreferences()).rejects.toThrow('did not save preferences');

    respondingHost((request) => ({
      version: 2,
      requestId: request.requestId,
      ok: true,
      result: { status: 'SUCCESS', message: 4, value: {} },
    }));
    await expect(bridge.getPreferences()).rejects.toThrow('invalid preferences result');
  });

  it('returns an undefined revision when the host omits a valid monotonic revision', async () => {
    respondingHost((request) => ({
      version: 2,
      requestId: request.requestId,
      ok: true,
      result: { accepted: true, revision: '7' },
    }));
    await expect(bridge.command(commands.deviceScan, {}, 1)).resolves.toMatchObject({ revision: undefined });
  });
});
