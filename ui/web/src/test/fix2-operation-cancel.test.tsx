import { act, renderHook } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { commands } from '../commands';
import { useOperationCancel } from '../pages/useOperationCancel';
import type { ActiveOperation } from '../types';

const flash: ActiveOperation = {
  id: 'flash-operation-1',
  kind: commands.flashExecute,
  label: 'Flashing firmware',
  status: 'running',
};
const backup: ActiveOperation = {
  id: 'backup-operation-1',
  kind: commands.backupsCreate,
  label: 'Creating backup',
  status: 'running',
};

describe('useOperationCancel only aborts operations the feature owns', () => {
  it('ignores an unrelated running flash while the feature waits to be dispatched', async () => {
    const onCommand = vi.fn(async () => ({ ok: true } as never));
    const { result } = renderHook(() => useOperationCancel(
      onCommand,
      flash,
      true,
      [commands.backupsCreate, commands.backupsRestore],
    ));

    expect(result.current.operation).toBeNull();
    await act(async () => { await result.current.cancel(); });
    expect(onCommand).not.toHaveBeenCalled();
  });

  it('still cancels the operation the feature started', async () => {
    const onCommand = vi.fn(async () => ({ ok: true } as never));
    const { result } = renderHook(() => useOperationCancel(
      onCommand,
      backup,
      true,
      [commands.backupsCreate, commands.backupsRestore],
    ));

    expect(result.current.operation).toBe(backup);
    await act(async () => { await result.current.cancel(); });
    expect(onCommand).toHaveBeenCalledWith(
      commands.operationCancel,
      { operationId: 'backup-operation-1' },
    );
  });

  it('refuses an operation with no kind when the feature declares its kinds', () => {
    const { result } = renderHook(() => useOperationCancel(
      vi.fn(),
      { ...backup, kind: undefined },
      true,
      [commands.backupsCreate],
    ));

    expect(result.current.operation).toBeNull();
  });
});
