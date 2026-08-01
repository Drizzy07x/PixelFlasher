import { useCallback, useState } from 'react';
import { commands } from '../commands';
import { type SharedPageProps } from './shared';
import type { ActiveOperation } from '../types';

export interface OperationCancelController {
  /** The running host operation this feature may abort, when there is one. */
  operation: ActiveOperation | null;
  cancelling: boolean;
  cancel: () => Promise<void>;
}

/**
 * The host dispatches commands through a single serial worker, so a long request
 * without an abort control blocks every later command. `pending` is the feature's
 * own "my long request is in flight" flag; combined with the host operation it
 * yields the `operation.cancel` a feature renders as a Cancel button.
 *
 * `pending` is set synchronously on click while the host is still serialising the
 * request, so the operation on screen at that moment can belong to an unrelated
 * earlier command. `kinds` lists the operation kinds the calling feature actually
 * starts, and only those may be aborted. It is required precisely because an
 * omitted list silently restores the defect it exists to prevent: a Cancel button
 * in one panel aborting a flash started somewhere else.
 */
export function useOperationCancel(
  onCommand: SharedPageProps['onCommand'],
  activeOperation: ActiveOperation | null | undefined,
  pending: boolean,
  kinds: readonly string[],
): OperationCancelController {
  const [cancellingId, setCancellingId] = useState('');
  const operation = pending
    && activeOperation
    && kinds.includes(activeOperation.kind ?? '')
    && ['pending', 'running'].includes(activeOperation.status.toLowerCase())
    ? activeOperation
    : null;
  const operationId = operation?.id ?? '';

  const cancel = useCallback(async () => {
    if (!operationId || cancellingId === operationId) return;
    setCancellingId(operationId);
    const response = await onCommand(commands.operationCancel, { operationId });
    // A refused cancellation leaves the operation running; restore the control.
    if (!response) setCancellingId('');
  }, [cancellingId, onCommand, operationId]);

  return { operation, cancelling: Boolean(operationId) && cancellingId === operationId, cancel };
}
