"""Stateful v2 operation runner with postcondition-gated success."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
import tempfile
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol, cast

from .contracts import (
    AppCommand,
    AppSnapshot,
    CommandKind,
    FileArtifact,
    OperationBatch,
    OperationPlan,
    OperationPostcondition,
    OperationResult,
    OperationRisk,
    OperationStatus,
    ProcessRequest,
)
from .executor import CancellationReason, CancellationToken, CommandExecutor
from .observer import (
    DeviceObservation,
    HostPostconditionSpec,
    ObservationResult,
    ObservationStatus,
    PostconditionSpec,
)
from .safety import SafetyPolicy

SnapshotProvider = Callable[[str], AppSnapshot]
OperationExecutor = Callable[
    [AppCommand, OperationPlan, CancellationToken],
    OperationResult,
]
OperationResultTransformer = Callable[
    [OperationResult, CancellationToken],
    OperationResult,
]
CancellationCleanup = Callable[
    [OperationResult, CancellationToken],
    OperationResult,
]


@dataclass(frozen=True, slots=True)
class PostconditionObservation:
    satisfied: bool
    message: str = ""
    verified: bool = True


@dataclass(frozen=True, slots=True)
class ExecutionBoundaryAck:
    """Typed decision returned immediately before a process boundary."""

    allowed: bool
    code: str = "allowed"
    message: str = ""

    @classmethod
    def accepted(cls) -> ExecutionBoundaryAck:
        return cls(True)

    @classmethod
    def rejected(cls, code: str, message: str) -> ExecutionBoundaryAck:
        return cls(False, code, message)


ExecutionBoundary = Callable[
    [AppCommand, OperationPlan, AppSnapshot],
    ExecutionBoundaryAck,
]
BatchExecutionBoundary = Callable[
    [OperationBatch, AppSnapshot],
    ExecutionBoundaryAck,
]


class CallbackPostconditionObserver(Protocol):
    def observe(
        self,
        plan: OperationPlan,
        postcondition: OperationPostcondition,
        snapshot: AppSnapshot,
    ) -> PostconditionObservation | bool | Mapping[str, object]: ...


class PollingPostconditionObserver(Protocol):
    def verify(
        self,
        spec: PostconditionSpec,
        cancellation: CancellationToken | None = None,
    ) -> ObservationResult: ...

    def verify_host(
        self,
        spec: HostPostconditionSpec,
        cancellation: CancellationToken | None = None,
    ) -> ObservationResult: ...


PostconditionObserverLike = CallbackPostconditionObserver | PollingPostconditionObserver | Callable[..., object]


class _ArtifactStageError(RuntimeError):
    """Typed failure while materializing a hash-bound private input copy."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OperationRunner:
    """Execute immutable plans once and report success only after observation.

    The destructive lock is process-global across runner instances.  There is
    intentionally no retry loop: once a mutating process boundary has been
    crossed, cancellation is an unknown outcome rather than a successful
    cancellation.
    """

    _destructive_lock = threading.Lock()
    lock_poll_seconds = 0.05

    def __init__(
        self,
        executor: CommandExecutor | None = None,
        *,
        safety_policy: SafetyPolicy | None = None,
        snapshot_provider: SnapshotProvider | None = None,
        postcondition_observer: PostconditionObserverLike | None = None,
        postcondition_timeout_seconds: float = 120.0,
    ) -> None:
        if postcondition_timeout_seconds <= 0:
            raise ValueError("postcondition_timeout_seconds must be positive")
        self.executor = executor or CommandExecutor()
        self.safety_policy = safety_policy or SafetyPolicy()
        self.snapshot_provider = snapshot_provider
        self.postcondition_observer = postcondition_observer
        self.postcondition_timeout_seconds = float(postcondition_timeout_seconds)

    def execute(
        self,
        command: AppCommand,
        plan: OperationPlan | None = None,
        snapshot: AppSnapshot | None = None,
        *,
        cancellation: CancellationToken | None = None,
        snapshot_provider: SnapshotProvider | None = None,
        postcondition_observer: PostconditionObserverLike | None = None,
        operation_executor: OperationExecutor | None = None,
        result_transformer: OperationResultTransformer | None = None,
        cancellation_cleanup: CancellationCleanup | None = None,
        before_execution: ExecutionBoundary | None = None,
    ) -> OperationResult:
        """Execute one plan.  This method never returns ``None``."""

        if not isinstance(command, AppCommand):
            return OperationResult.failed(
                "invalid-operation",
                code="invalid_command",
                message="operation runner requires an AppCommand",
            )
        execution_plan = plan or command.operation_plan
        if not isinstance(execution_plan, OperationPlan):
            return OperationResult.failed(
                command.operation_id,
                code="operation_plan_required",
                message="operation runner requires an immutable OperationPlan",
            )
        token = cancellation or CancellationToken()
        provider = snapshot_provider or self.snapshot_provider
        observer = postcondition_observer or self.postcondition_observer
        current = self._snapshot_for(execution_plan, snapshot, provider)
        if isinstance(current, OperationResult):
            return current
        planned = replace(
            command,
            expected_revision=(current.revision if command.expected_revision is None else command.expected_revision),
            target_serial=execution_plan.target_serial or command.target_serial,
            operation_plan=execution_plan,
            destructive=(command.destructive or execution_plan.risk is OperationRisk.DESTRUCTIVE),
            requires_confirmation=(command.requires_confirmation or execution_plan.risk is OperationRisk.DESTRUCTIVE),
        )

        if token.cancelled:
            return self._stopped_before_mutation(
                token,
                command.operation_id,
                "before mutation",
            )

        destructive = execution_plan.risk is OperationRisk.DESTRUCTIVE
        acquired = False
        artifact_stage: tempfile.TemporaryDirectory[str] | None = None
        try:
            if destructive:
                acquired = self._acquire_destructive(token)
                if not acquired:
                    return self._stopped_before_mutation(
                        token,
                        command.operation_id,
                        "while waiting for the destructive operation lock",
                    )
            current = self._snapshot_for(execution_plan, snapshot, provider)
            if isinstance(current, OperationResult):
                return current
            decision = self.safety_policy.evaluate(planned, current)
            if not decision.allowed:
                return OperationResult.failed(
                    command.operation_id,
                    code=decision.code,
                    message=decision.message,
                )
            artifact_issue = self._revalidate_artifacts(execution_plan, token)
            if artifact_issue is not None:
                if artifact_issue[0] in {"cancelled", "timed_out"}:
                    return self._stopped_before_mutation(
                        token,
                        command.operation_id,
                        "while revalidating source artifacts",
                    )
                return OperationResult.failed(
                    command.operation_id,
                    code=artifact_issue[0],
                    message=artifact_issue[1],
                )
            current = self._snapshot_for(execution_plan, current, provider)
            if isinstance(current, OperationResult):
                return current
            decision = self.safety_policy.evaluate(planned, current)
            if not decision.allowed:
                return OperationResult.failed(
                    command.operation_id,
                    code=decision.code,
                    message=decision.message,
                )
            if token.cancelled:
                return self._stopped_before_mutation(
                    token,
                    command.operation_id,
                    "before verified artifact staging",
                )
            try:
                staged_plan, artifact_stage = self._stage_artifacts(
                    execution_plan,
                    token,
                )
            except InterruptedError:
                return self._stopped_before_mutation(
                    token,
                    command.operation_id,
                    "while preparing verified artifacts",
                )
            except _ArtifactStageError as error:
                return OperationResult.failed(
                    command.operation_id,
                    code=error.code,
                    message=str(error),
                )
            # Staging can take long enough for the selected device, firmware,
            # or canonical plan revision to change.  Re-read and authorize the
            # original, confirmation-bound plan after the private copy exists;
            # the execution boundary below then validates the staged paths.
            current = self._snapshot_for(execution_plan, current, provider)
            if isinstance(current, OperationResult):
                return current
            decision = self.safety_policy.evaluate(planned, current)
            if not decision.allowed:
                return OperationResult.failed(
                    command.operation_id,
                    code=decision.code,
                    message=decision.message,
                )
            if token.cancelled:
                return self._stopped_before_mutation(
                    token,
                    command.operation_id,
                    "before the process boundary",
                )
            staged_command = replace(planned, operation_plan=staged_plan)
            return self._execute_validated(
                staged_command,
                staged_plan,
                current,
                provider,
                observer,
                token,
                operation_executor,
                result_transformer,
                cancellation_cleanup,
                before_execution,
            )
        except Exception as error:
            return OperationResult.failed(
                command.operation_id,
                code="operation_runner_error",
                message=str(error),
            )
        finally:
            try:
                self._cleanup_artifact_stage(artifact_stage)
            finally:
                if acquired:
                    self._destructive_lock.release()

    def execute_batch(
        self,
        batch: OperationBatch,
        *,
        cancellation: CancellationToken | None = None,
        snapshot_provider: SnapshotProvider | None = None,
        postcondition_observer: PostconditionObserverLike | None = None,
        before_execution: BatchExecutionBoundary | None = None,
    ) -> OperationResult:
        """Execute batch plans sequentially, revalidating each target fail-fast."""

        if not isinstance(batch, OperationBatch):
            return OperationResult.failed(
                "invalid-batch",
                code="invalid_batch",
                message="operation runner requires an OperationBatch",
            )
        token = cancellation or CancellationToken()
        provider = snapshot_provider or self.snapshot_provider
        observer = postcondition_observer or self.postcondition_observer
        if provider is None:
            return OperationResult.failed(
                batch.batch_id,
                code="snapshot_provider_required",
                message="batch execution requires per-device current snapshots",
            )
        if observer is None:
            return OperationResult.failed(
                batch.batch_id,
                code="postcondition_unverified",
                message="batch execution requires a backend postcondition observer",
            )
        if token.cancelled:
            return self._stopped_before_mutation(
                token,
                batch.batch_id,
                "before batch mutation",
            )

        acquired = self._acquire_destructive(token)
        if not acquired:
            return self._stopped_before_mutation(
                token,
                batch.batch_id,
                "while waiting for the destructive batch lock",
            )
        mutated = False
        completed: list[dict[str, object]] = []
        execution_started = False
        last_mutated_plan: OperationPlan | None = None
        last_mutated_snapshot: AppSnapshot | None = None
        active_artifact_stage: tempfile.TemporaryDirectory[str] | None = None

        def unknown_after_batch_mutation(
            message: str,
            result: OperationResult | None = None,
        ) -> OperationResult:
            if last_mutated_plan is None or last_mutated_snapshot is None:
                outcome = self._unknown_outcome(batch.batch_id, message, result)
            else:
                outcome = self._unknown_after_mutation(
                    last_mutated_plan,
                    last_mutated_snapshot,
                    provider,
                    observer,
                    batch.batch_id,
                    message,
                    result,
                )
            details = self._result_value_mapping(cast(object, outcome.value))
            details["completed"] = list(completed)
            return replace(outcome, value=details)

        try:
            initial: dict[str, AppSnapshot] = {}
            for serial in batch.target_serials:
                snapshot = self._provided_snapshot(provider, serial, batch.batch_id)
                if isinstance(snapshot, OperationResult):
                    return snapshot
                initial[serial] = snapshot
            decision = self.safety_policy.evaluate_batch(batch, initial)
            if not decision.allowed:
                return OperationResult.failed(
                    batch.batch_id,
                    code=decision.code,
                    message=decision.message,
                )

            for index, plan in enumerate(batch.plans, start=1):
                serial = plan.target_serial or ""
                if token.cancelled:
                    return (
                        unknown_after_batch_mutation("batch cancellation arrived after a device may have been mutated")
                        if mutated
                        else self._stopped_before_mutation(
                            token,
                            batch.batch_id,
                            "before the next device mutation",
                        )
                    )
                current = self._provided_snapshot(provider, serial, batch.batch_id)
                if isinstance(current, OperationResult):
                    if mutated:
                        return unknown_after_batch_mutation(
                            "device state became unavailable after an earlier batch mutation",
                        )
                    return current

                authorized = replace(
                    plan,
                    confirmation_nonce=batch.confirmation_nonce,
                    confirmation_token=None,
                )
                authorized = replace(
                    authorized,
                    confirmation_token=authorized.confirmation_challenge(),
                )
                command = AppCommand(
                    CommandKind.FLASH_EXECUTE,
                    expected_revision=current.revision,
                    target_serial=serial,
                    operation_plan=authorized,
                    operation_id=f"{batch.batch_id}:{index}:{serial}",
                    destructive=True,
                    requires_confirmation=True,
                )
                plan_decision = self.safety_policy.evaluate(command, current)
                if not plan_decision.allowed:
                    return OperationResult.failed(
                        batch.batch_id,
                        code=plan_decision.code,
                        message=f"{serial}: {plan_decision.message}",
                    )
                artifact_issue = self._revalidate_artifacts(authorized, token)
                if artifact_issue is not None:
                    if artifact_issue[0] in {"cancelled", "timed_out"}:
                        return (
                            unknown_after_batch_mutation(
                                "batch interruption arrived while revalidating the next device artifacts"
                            )
                            if mutated
                            else self._stopped_before_mutation(
                                token,
                                batch.batch_id,
                                "while revalidating the next device artifacts",
                            )
                        )
                    return OperationResult.failed(
                        batch.batch_id,
                        code=artifact_issue[0],
                        message=f"{serial}: {artifact_issue[1]}",
                    )
                if batch.expires <= self.safety_policy.clock():
                    return OperationResult.failed(
                        batch.batch_id,
                        code="batch_expired",
                        message="operation batch expired before the next process boundary",
                    )
                current = self._provided_snapshot(provider, serial, batch.batch_id)
                if isinstance(current, OperationResult):
                    if mutated:
                        return unknown_after_batch_mutation(
                            "device state became unavailable after an earlier batch mutation",
                        )
                    return current
                plan_decision = self.safety_policy.evaluate(command, current)
                if not plan_decision.allowed:
                    return OperationResult.failed(
                        batch.batch_id,
                        code=plan_decision.code,
                        message=f"{serial}: {plan_decision.message}",
                    )
                if token.cancelled:
                    return (
                        unknown_after_batch_mutation("batch cancellation arrived before the next device mutation")
                        if mutated
                        else self._stopped_before_mutation(
                            token,
                            batch.batch_id,
                            "before the next device mutation",
                        )
                    )

                try:
                    staged_plan, active_artifact_stage = self._stage_artifacts(
                        authorized,
                        token,
                    )
                except InterruptedError:
                    return (
                        unknown_after_batch_mutation(
                            "batch cancellation arrived while preparing the next device artifacts"
                        )
                        if mutated
                        else self._stopped_before_mutation(
                            token,
                            batch.batch_id,
                            "while preparing the next device artifacts",
                        )
                    )
                except _ArtifactStageError as error:
                    return OperationResult.failed(
                        batch.batch_id,
                        code=error.code,
                        message=f"{serial}: {error}",
                    )
                authorized = staged_plan
                command = replace(command, operation_plan=authorized)

                if not execution_started and before_execution is not None:
                    boundary = before_execution(batch, current)
                    if not isinstance(boundary, ExecutionBoundaryAck):
                        return OperationResult.failed(
                            batch.batch_id,
                            code="execution_boundary_invalid",
                            message="batch execution boundary returned no typed acknowledgement",
                        )
                    if not boundary.allowed:
                        return OperationResult.failed(
                            batch.batch_id,
                            code=boundary.code,
                            message=boundary.message,
                        )
                execution_started = True

                mutated = True
                last_mutated_plan = authorized
                last_mutated_snapshot = current
                result = self.executor.execute(command, authorized, token)
                if not isinstance(result, OperationResult):
                    return unknown_after_batch_mutation(
                        "executor returned no typed result after mutation",
                    )
                if result.status is OperationStatus.CANCELLED or token.cancelled:
                    return unknown_after_batch_mutation(
                        "batch cancellation arrived after a device mutation began",
                        result,
                    )
                if not result.ok:
                    safety_observation = self._minimal_safety_observation(
                        authorized,
                        current,
                        provider,
                        observer,
                    )
                    if not self._safety_observation_is_reachable(safety_observation):
                        unknown = self._unknown_outcome(
                            batch.batch_id,
                            ("the flash command failed and the target could not be safely observed"),
                            result,
                            safety_observation=safety_observation,
                        )
                        details = self._result_value_mapping(cast(object, unknown.value))
                        details.update({"completed": list(completed), "failedSerial": serial})
                        return replace(unknown, value=details)
                    return replace(
                        OperationResult.failed(
                            batch.batch_id,
                            code="batch_failed",
                            message=f"{serial}: {result.code}: {result.message}",
                            exit_code=result.exit_code,
                            stdout=result.stdout,
                            stderr=result.stderr,
                        ),
                        value={
                            "completed": completed,
                            "failedSerial": serial,
                            "result": result.to_dict(),
                        },
                    )
                observed = self._verify_postconditions(
                    authorized,
                    current,
                    provider,
                    observer,
                    token,
                    command.operation_id,
                    result,
                )
                if not observed.ok:
                    observed_value = self._result_value_mapping(cast(object, observed.value))
                    observed_value.update({"completed": list(completed), "failedSerial": serial})
                    return replace(
                        observed,
                        operation_id=batch.batch_id,
                        value=observed_value,
                    )
                completed.append({"serial": serial, "result": result.to_dict()})
                if active_artifact_stage is not None:
                    self._cleanup_artifact_stage(active_artifact_stage)
                    active_artifact_stage = None

            return OperationResult.success(
                batch.batch_id,
                code="batch_succeeded",
                message=f"flashed {len(completed)} device(s) sequentially",
                value={"completed": completed, "fingerprint": batch.fingerprint},
            )
        except Exception:
            if mutated:
                return unknown_after_batch_mutation("batch execution failed after a device mutation may have begun")
            return OperationResult.failed(
                batch.batch_id,
                code="operation_runner_error",
                message="batch execution failed before mutation",
            )
        finally:
            try:
                self._cleanup_artifact_stage(active_artifact_stage)
            finally:
                self._destructive_lock.release()

    def _execute_validated(
        self,
        command: AppCommand,
        plan: OperationPlan,
        snapshot: AppSnapshot,
        provider: SnapshotProvider | None,
        observer: PostconditionObserverLike | None,
        token: CancellationToken,
        operation_executor: OperationExecutor | None,
        result_transformer: OperationResultTransformer | None,
        cancellation_cleanup: CancellationCleanup | None,
        before_execution: ExecutionBoundary | None,
    ) -> OperationResult:
        mutating = not plan.dry_run and (
            plan.risk is not OperationRisk.READ_ONLY
            or command.destructive
            or self.safety_policy.is_destructive(command)
        )
        if mutating and (not plan.postconditions or observer is None):
            return OperationResult.failed(
                command.operation_id,
                code="postcondition_unverified",
                message=("a mutating operation requires declared postconditions and a backend postcondition observer"),
            )
        verifier = getattr(observer, "verify", None) if observer is not None else None
        if mutating:
            try:
                for postcondition in plan.postconditions:
                    if self._is_execution_postcondition(postcondition.kind):
                        self._validate_execution_postcondition(postcondition)
                observable = tuple(
                    postcondition
                    for postcondition in plan.postconditions
                    if not self._is_execution_postcondition(postcondition.kind)
                )
                if plan.target_serial is None and observable:
                    host_verifier = getattr(observer, "verify_host", None)
                    if callable(host_verifier):
                        self._host_postcondition_spec(plan)
                    elif callable(verifier):
                        raise ValueError("no backend host postcondition observer is available")
                elif plan.target_serial is not None and callable(verifier):
                    self._postcondition_spec(plan)
            except (TypeError, ValueError) as error:
                return OperationResult.failed(
                    command.operation_id,
                    code="postcondition_unverified",
                    message=str(error),
                )
        if before_execution is not None:
            try:
                boundary = before_execution(command, plan, snapshot)
            except Exception as error:
                return OperationResult.failed(
                    command.operation_id,
                    code="execution_boundary_failed",
                    message=str(error),
                )
            if not isinstance(boundary, ExecutionBoundaryAck):
                return OperationResult.failed(
                    command.operation_id,
                    code="execution_boundary_invalid",
                    message="execution boundary returned an invalid acknowledgement",
                )
            if not boundary.allowed:
                return OperationResult.failed(
                    command.operation_id,
                    code=boundary.code,
                    message=boundary.message,
                )
        if token.cancelled:
            return self._stopped_before_mutation(
                token,
                command.operation_id,
                "before the process boundary",
            )
        execute = operation_executor or self.executor.execute
        try:
            result = execute(command, plan, token)
        except Exception:
            if mutating:
                return self._unknown_after_mutation(
                    plan,
                    snapshot,
                    provider,
                    observer,
                    command.operation_id,
                    "executor raised after mutation may have begun",
                )
            return OperationResult.failed(
                command.operation_id,
                code="executor_error",
                message="operation executor failed",
            )
        if not isinstance(result, OperationResult):
            return (
                self._unknown_after_mutation(
                    plan,
                    snapshot,
                    provider,
                    observer,
                    command.operation_id,
                    "executor returned no typed result after mutation",
                )
                if mutating
                else OperationResult.failed(
                    command.operation_id,
                    code="invalid_executor_result",
                    message="executor returned no typed result",
                )
            )
        if result_transformer is not None:
            try:
                result = result_transformer(result, token)
            except Exception:
                return (
                    self._unknown_after_mutation(
                        plan,
                        snapshot,
                        provider,
                        observer,
                        command.operation_id,
                        "result verification raised after mutation may have begun",
                    )
                    if mutating
                    else OperationResult.failed(
                        command.operation_id,
                        code="result_finalize_failed",
                        message="result verification failed",
                    )
                )
            if not isinstance(result, OperationResult):
                return (
                    self._unknown_after_mutation(
                        plan,
                        snapshot,
                        provider,
                        observer,
                        command.operation_id,
                        "result verification returned no typed result after mutation",
                    )
                    if mutating
                    else OperationResult.failed(
                        command.operation_id,
                        code="invalid_result_finalizer",
                        message="result verification returned no typed result",
                    )
                )
        # This single read is the read-only completion linearization point.
        # A stop already visible here owns cleanup; a later stop races after
        # the operation has truthfully completed and cannot rewrite success.
        cancelled_after_execution = token.cancelled
        if result.status is OperationStatus.CANCELLED or cancelled_after_execution:
            if mutating:
                return self._unknown_after_mutation(
                    plan,
                    snapshot,
                    provider,
                    observer,
                    command.operation_id,
                    "cancellation arrived after mutation began",
                    result,
                )
            if cancelled_after_execution and cancellation_cleanup is not None:
                try:
                    cleaned_result = cancellation_cleanup(result, token)
                except Exception:
                    return OperationResult.failed(
                        command.operation_id,
                        code="cancellation_cleanup_failed",
                        message="post-execution cancellation cleanup failed",
                    )
                if not isinstance(cleaned_result, OperationResult):
                    return OperationResult.failed(
                        command.operation_id,
                        code="invalid_cancellation_cleanup",
                        message="post-execution cancellation cleanup returned no typed result",
                    )
                result = cleaned_result
                if result.status is OperationStatus.FAILED:
                    return result
            if (
                result.status is OperationStatus.FAILED
                and result.code == "managed_process_termination_failed"
            ):
                return result
            if cancelled_after_execution and token.reason is CancellationReason.DEADLINE:
                return OperationResult.failed(
                    command.operation_id,
                    code="timed_out",
                    message="read-only operation deadline expired during execution",
                    exit_code=result.exit_code,
                    stdout=result.stdout,
                    stderr=result.stderr,
                )
            if result.status is OperationStatus.CANCELLED:
                return result
            return OperationResult.cancelled(
                command.operation_id,
                code="cancelled",
                message="read-only operation was cancelled during execution",
                stdout=result.stdout,
                stderr=result.stderr,
            )
        if not result.ok:
            if mutating:
                if command.kind in {"tools.pushFiles", "tools.logcat.clear"}:
                    # adb push may create or truncate a remote file before it
                    # reports non-zero. Likewise, logcat can clear some buffers
                    # before a later buffer fails. Reachability cannot prove a
                    # known-safe outcome for either multi-step mutation.
                    return self._unknown_after_mutation(
                        plan,
                        snapshot,
                        provider,
                        observer,
                        command.operation_id,
                        (
                            "Logcat buffer clearing failed after a partial clear may have begun"
                            if command.kind == "tools.logcat.clear"
                            else "file transfer failed after a remote write may have begun"
                        ),
                        result,
                    )
                if result.code in {"timed_out", "output_limit_exceeded"}:
                    return self._unknown_after_mutation(
                        plan,
                        snapshot,
                        provider,
                        observer,
                        command.operation_id,
                        "forced process termination left the mutation outcome unknown",
                        result,
                    )
                safety_observation = self._minimal_safety_observation(
                    plan,
                    snapshot,
                    provider,
                    observer,
                )
                if not self._safety_observation_is_reachable(safety_observation):
                    return self._unknown_outcome(
                        command.operation_id,
                        ("the operation failed and the target could not be safely observed"),
                        result,
                        safety_observation=safety_observation,
                    )
            return result
        if not mutating:
            return result
        observed = self._verify_postconditions(
            plan,
            snapshot,
            provider,
            observer,
            token,
            command.operation_id,
            result,
        )
        if not observed.ok:
            return observed
        value = self._result_value_mapping(cast(object, result.value))
        value.update(
            {
                "planId": plan.plan_id,
                "postconditions": [item.to_dict() for item in plan.postconditions],
            }
        )
        return replace(
            result,
            code=("postconditions_satisfied" if result.code in {"ok", "process_succeeded"} else result.code),
            value=value,
        )

    def _verify_postconditions(
        self,
        plan: OperationPlan,
        snapshot: AppSnapshot,
        provider: SnapshotProvider | None,
        observer: PostconditionObserverLike | None,
        token: CancellationToken,
        operation_id: str,
        process_result: OperationResult,
    ) -> OperationResult:
        if token.cancelled:
            return self._unknown_after_mutation(
                plan,
                snapshot,
                provider,
                observer,
                operation_id,
                "cancellation arrived before postcondition observation",
            )
        if observer is None:
            return OperationResult.failed(
                operation_id,
                code="postcondition_unverified",
                message="no backend postcondition observer is available",
            )
        execution_evidence = self._verify_execution_postconditions(
            plan,
            process_result,
            token,
        )
        if execution_evidence.status is OperationStatus.CANCELLED:
            return self._unknown_after_mutation(
                plan,
                snapshot,
                provider,
                observer,
                operation_id,
                "cancellation arrived during host postcondition observation",
                process_result,
            )
        if not execution_evidence.ok:
            return replace(execution_evidence, operation_id=operation_id)
        observable = tuple(
            postcondition
            for postcondition in plan.postconditions
            if not self._is_execution_postcondition(postcondition.kind)
        )
        if not observable:
            return OperationResult.success(
                operation_id,
                code="postconditions_satisfied",
                message="all execution postconditions were verified",
            )
        if plan.target_serial is None:
            host_verifier = getattr(observer, "verify_host", None)
            if callable(host_verifier):
                return self._verify_with_host_polling_observer(
                    plan,
                    host_verifier,
                    token,
                    operation_id,
                )
        verifier = getattr(observer, "verify", None) if observer is not None else None
        if callable(verifier):
            return self._verify_with_polling_observer(
                plan,
                verifier,
                token,
                operation_id,
            )
        fresh = self._snapshot_for(plan, snapshot, provider)
        if isinstance(fresh, OperationResult):
            return OperationResult.failed(
                operation_id,
                code="postcondition_unverified",
                message="current device state is unavailable after mutation",
            )
        for postcondition in plan.postconditions:
            if self._is_execution_postcondition(postcondition.kind):
                continue
            if token.cancelled:
                return self._unknown_after_mutation(
                    plan,
                    fresh,
                    provider,
                    observer,
                    operation_id,
                    "cancellation arrived during postcondition observation",
                )
            try:
                observation = self._observe(plan, postcondition, fresh, observer)
            except Exception as error:
                return OperationResult.failed(
                    operation_id,
                    code="postcondition_unverified",
                    message=f"{postcondition.kind}: {error}",
                )
            if token.cancelled:
                return self._unknown_after_mutation(
                    plan,
                    fresh,
                    provider,
                    observer,
                    operation_id,
                    "cancellation arrived during postcondition observation",
                )
            if not observation.verified:
                return OperationResult.failed(
                    operation_id,
                    code="postcondition_unverified",
                    message=(observation.message or f"postcondition could not be verified: {postcondition.kind}"),
                )
            if not observation.satisfied:
                return OperationResult.failed(
                    operation_id,
                    code="postcondition_mismatch",
                    message=(observation.message or f"postcondition evidence did not match: {postcondition.kind}"),
                )
        return OperationResult.success(
            operation_id,
            code="postconditions_satisfied",
        )

    def _verify_with_polling_observer(
        self,
        plan: OperationPlan,
        verifier: Callable[..., object],
        token: CancellationToken,
        operation_id: str,
    ) -> OperationResult:
        """Adapt the core polling observer to the v2 plan contract."""

        try:
            spec = self._postcondition_spec(plan)
        except (TypeError, ValueError) as error:
            return OperationResult.failed(
                operation_id,
                code="postcondition_unverified",
                message=str(error),
            )
        try:
            result = verifier(spec, token)
        except Exception as error:
            if token.cancelled:
                return self._unknown_outcome(
                    operation_id,
                    "cancellation arrived during postcondition observation",
                    safety_observation=self._minimal_verifier_observation(
                        plan,
                        verifier,
                    ),
                )
            return OperationResult.failed(
                operation_id,
                code="postcondition_unverified",
                message=str(error),
            )
        if token.cancelled:
            return self._unknown_outcome(
                operation_id,
                "cancellation arrived during postcondition observation",
                safety_observation=self._minimal_verifier_observation(plan, verifier),
            )
        if not isinstance(result, ObservationResult):
            return OperationResult.failed(
                operation_id,
                code="postcondition_unverified",
                message="postcondition verifier returned an invalid result",
            )
        if result.status is ObservationStatus.CANCELLED:
            return self._unknown_outcome(
                operation_id,
                "postcondition observation was cancelled after mutation",
                safety_observation=self._minimal_verifier_observation(plan, verifier),
            )
        if isinstance(result.observation, DeviceObservation) and not result.observation.connected:
            return self._unknown_outcome(
                operation_id,
                "the target disconnected during postcondition observation",
                safety_observation=self._observation_result_summary(result),
            )
        if result.status is ObservationStatus.MISMATCH:
            return OperationResult.failed(
                operation_id,
                code="postcondition_mismatch",
                message=result.message,
            )
        if result.status is not ObservationStatus.VERIFIED:
            return OperationResult.failed(
                operation_id,
                code="postcondition_unverified",
                message=result.message,
            )
        return OperationResult.success(
            operation_id,
            code="postconditions_satisfied",
            message=result.message,
        )

    def _verify_with_host_polling_observer(
        self,
        plan: OperationPlan,
        verifier: Callable[..., object],
        token: CancellationToken,
        operation_id: str,
    ) -> OperationResult:
        try:
            spec = self._host_postcondition_spec(plan)
        except (TypeError, ValueError) as error:
            return OperationResult.failed(
                operation_id,
                code="postcondition_unverified",
                message=str(error),
            )
        try:
            result = verifier(spec, token)
        except Exception as error:
            if token.cancelled:
                return self._unknown_outcome(
                    operation_id,
                    "cancellation arrived during host postcondition observation",
                    safety_observation=self._minimal_host_verifier_observation(
                        plan,
                        verifier,
                    ),
                )
            return OperationResult.failed(
                operation_id,
                code="postcondition_unverified",
                message=str(error),
            )
        if token.cancelled or (
            isinstance(result, ObservationResult)
            and result.status is ObservationStatus.CANCELLED
        ):
            return self._unknown_outcome(
                operation_id,
                "host postcondition observation was cancelled after mutation",
                safety_observation=self._minimal_host_verifier_observation(
                    plan,
                    verifier,
                ),
            )
        if not isinstance(result, ObservationResult):
            return OperationResult.failed(
                operation_id,
                code="postcondition_unverified",
                message="host postcondition verifier returned an invalid result",
            )
        if result.status is ObservationStatus.MISMATCH:
            return OperationResult.failed(
                operation_id,
                code="postcondition_mismatch",
                message=result.message,
            )
        if result.status is not ObservationStatus.VERIFIED:
            return OperationResult.failed(
                operation_id,
                code="postcondition_unverified",
                message=result.message,
            )
        return OperationResult.success(
            operation_id,
            code="postconditions_satisfied",
            message=result.message,
        )

    def _unknown_after_mutation(
        self,
        plan: OperationPlan,
        snapshot: AppSnapshot,
        provider: SnapshotProvider | None,
        observer: PostconditionObserverLike | None,
        operation_id: str,
        message: str,
        result: OperationResult | None = None,
    ) -> OperationResult:
        """Keep an unknown outcome while collecting bounded read-only evidence."""

        safety_observation = self._minimal_safety_observation(
            plan,
            snapshot,
            provider,
            observer,
        )
        return self._unknown_outcome(
            operation_id,
            message,
            result,
            safety_observation=safety_observation,
        )

    def _minimal_safety_observation(
        self,
        plan: OperationPlan,
        snapshot: AppSnapshot,
        provider: SnapshotProvider | None,
        observer: PostconditionObserverLike | None,
    ) -> dict[str, object]:
        """Attempt one independent safety observation after cancellation.

        The caller's cancellation token is intentionally not reused: it has
        already been cancelled, while this final read-only check must still be
        allowed to determine whether the target is reachable. Its outcome is
        diagnostic only and can never turn ``outcome_unknown`` into success.
        """

        if observer is None:
            return {
                "status": "unverified",
                "code": "safety_observer_unavailable",
            }
        if plan.target_serial is None:
            host_verifier = getattr(observer, "verify_host", None)
            if callable(host_verifier):
                return self._minimal_host_verifier_observation(plan, host_verifier)
        verifier = getattr(observer, "verify", None)
        if callable(verifier):
            return self._minimal_verifier_observation(plan, verifier)
        fresh = self._snapshot_for(plan, snapshot, provider)
        if isinstance(fresh, OperationResult):
            return {
                "status": "unverified",
                "code": "safety_snapshot_unavailable",
            }
        try:
            observation = self._observe(
                plan,
                OperationPostcondition("device_reachable"),
                fresh,
                observer,
            )
        except Exception:
            return {
                "status": "unverified",
                "code": "safety_observation_failed",
            }
        return {
            "status": (
                "verified"
                if observation.verified and observation.satisfied
                else "mismatch"
                if observation.verified
                else "unverified"
            ),
            "code": "safety_device_reachable",
        }

    def _minimal_verifier_observation(
        self,
        plan: OperationPlan,
        verifier: Callable[..., object],
    ) -> dict[str, object]:
        serial = plan.target_serial or ""
        if not serial:
            return {
                "status": "unverified",
                "code": "safety_target_unavailable",
            }
        spec = PostconditionSpec(
            serial,
            min(self.postcondition_timeout_seconds, 5.0),
        )
        try:
            result = verifier(spec, CancellationToken())
        except Exception:
            return {
                "status": "unverified",
                "code": "safety_observation_failed",
            }
        if not isinstance(result, ObservationResult):
            return {
                "status": "unverified",
                "code": "safety_observation_invalid",
            }
        return self._observation_result_summary(result)

    def _minimal_host_verifier_observation(
        self,
        plan: OperationPlan,
        verifier: Callable[..., object],
    ) -> dict[str, object]:
        try:
            planned = self._host_postcondition_spec(plan)
            spec = HostPostconditionSpec(
                min(planned.timeout_seconds, 5.0),
                planned.expected_adb_endpoints,
            )
            result = verifier(spec, CancellationToken())
        except Exception:
            return {
                "status": "unverified",
                "code": "safety_observation_failed",
            }
        if not isinstance(result, ObservationResult):
            return {
                "status": "unverified",
                "code": "safety_observation_invalid",
            }
        return self._observation_result_summary(result)

    @staticmethod
    def _observation_result_summary(result: ObservationResult) -> dict[str, object]:
        """Return bounded, non-sensitive diagnostic evidence from an observation."""

        summary: dict[str, object] = {
            "status": result.status.value,
            "code": result.code,
            "attempts": result.attempts,
        }
        observation = result.observation
        if isinstance(observation, DeviceObservation):
            summary["connected"] = observation.connected
            if observation.mode is not None:
                summary["mode"] = observation.mode
            if observation.slot is not None:
                summary["slot"] = observation.slot
            if observation.bootloader is not None:
                summary["bootloader"] = observation.bootloader
            if observation.boot_completed is not None:
                summary["bootCompleted"] = observation.boot_completed
            if observation.safe_mode is not None:
                summary["safeMode"] = observation.safe_mode
            if observation.build is not None:
                summary["build"] = observation.build
        return summary

    @staticmethod
    def _safety_observation_is_reachable(
        observation: Mapping[str, object],
    ) -> bool:
        return observation.get("status") == ObservationStatus.VERIFIED.value and (
            observation.get("connected", True) is True
        )

    @staticmethod
    def _is_execution_postcondition(kind: str) -> bool:
        return kind in {
            "host_artifact_written",
            "adb_wifi_pairing_recorded",
            "package_data_cleared",
            "package_export_verified",
            "data_adb_backup_verified",
            "data_adb_restore_verified",
            "logcat_buffers_cleared",
            "view_intent_accepted",
        }

    def _validate_execution_postcondition(
        self,
        postcondition: OperationPostcondition,
    ) -> None:
        expected = postcondition.expected
        if postcondition.kind == "data_adb_backup_verified":
            if set(expected) != {"fileName"}:
                raise ValueError("/data/adb backup postcondition fields are invalid")
            file_name = expected.get("fileName")
            if (
                not isinstance(file_name, str)
                or re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9._ -]{0,191}\.pfdataadb",
                    file_name,
                    re.I,
                )
                is None
            ):
                raise ValueError("/data/adb backup file name is invalid")
            return
        if postcondition.kind == "data_adb_restore_verified":
            if set(expected) != {"contentFingerprint", "entryCount"}:
                raise ValueError("/data/adb restore postcondition fields are invalid")
            fingerprint = expected.get("contentFingerprint")
            entry_count = expected.get("entryCount")
            if (
                not isinstance(fingerprint, str)
                or not self._sha256_valid(fingerprint)
                or not isinstance(entry_count, int)
                or isinstance(entry_count, bool)
                or not 0 <= entry_count <= 20_000
            ):
                raise ValueError("/data/adb restore identity is invalid")
            return
        if postcondition.kind == "package_export_verified":
            if set(expected) != {"package", "fileName"}:
                raise ValueError("APK export postcondition fields are invalid")
            package = expected.get("package")
            file_name = expected.get("fileName")
            if (
                not isinstance(package, str)
                or re.fullmatch(
                    r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+",
                    package,
                )
                is None
                or not isinstance(file_name, str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,254}\.apk", file_name, re.I)
                is None
            ):
                raise ValueError("APK export identity is invalid")
            return
        if postcondition.kind == "adb_wifi_pairing_recorded":
            if set(expected) != {"endpoint"}:
                raise ValueError("ADB Wi-Fi pairing postcondition fields are invalid")
            endpoint = expected.get("endpoint")
            if not isinstance(endpoint, str) or not endpoint:
                raise ValueError("ADB Wi-Fi pairing endpoint is unavailable")
            # Reuse the production observer's endpoint validator through the
            # immutable spec constructor without launching a process.
            PostconditionSpec(
                "validation",
                1,
                expected_adb_endpoints={endpoint: True},
            )
            return
        if postcondition.kind == "package_data_cleared":
            if set(expected) != {"packages", "successCount"}:
                raise ValueError("package clear postcondition fields are invalid")
            packages = expected.get("packages")
            success_count = expected.get("successCount")
            if isinstance(packages, str) or not isinstance(packages, (tuple, list)):
                raise TypeError("package clear targets must be a bounded string array")
            package_values = cast(tuple[object, ...] | list[object], packages)
            if (
                not package_values
                or len(package_values) > 100
                or any(not isinstance(item, str) or not item for item in package_values)
            ):
                raise TypeError("package clear targets must be a bounded string array")
            if (
                not isinstance(success_count, int)
                or isinstance(success_count, bool)
                or success_count != len(package_values)
            ):
                raise ValueError("package clear success count does not match its targets")
            return
        if postcondition.kind == "logcat_buffers_cleared":
            if set(expected) != {
                "buffers",
                "preMarker",
                "postMarker",
                "preStartMarker",
                "preEndMarker",
                "postStartMarker",
                "postEndMarker",
            }:
                raise ValueError("Logcat clear postcondition fields are invalid")
            buffers = expected.get("buffers")
            if buffers != ("all",):
                raise ValueError("Logcat clear must verify the complete buffer set")
            marker_fields = (
                ("preMarker", "PRE"),
                ("postMarker", "POST"),
                ("preStartMarker", "PRE_START"),
                ("preEndMarker", "PRE_END"),
                ("postStartMarker", "POST_START"),
                ("postEndMarker", "POST_END"),
            )
            markers = tuple(expected.get(name) for name, _prefix in marker_fields)
            if (
                any(
                    not isinstance(marker, str)
                    or re.fullmatch(rf"PF10_{prefix}_[0-9a-f]{{32}}", marker) is None
                    for marker, (_name, prefix) in zip(markers, marker_fields, strict=True)
                )
                or len(set(markers)) != 6
            ):
                raise ValueError("Logcat clear verification markers are invalid")
            return
        if postcondition.kind == "view_intent_accepted":
            if set(expected) != {"targetSerial", "scheme", "host", "urlSha256"}:
                raise ValueError("browser intent postcondition fields are invalid")
            target_serial = expected.get("targetSerial")
            scheme = expected.get("scheme")
            host = expected.get("host")
            digest = expected.get("urlSha256")
            if (
                not isinstance(target_serial, str)
                or not target_serial
                or len(target_serial) > 256
                or any(character.isspace() or ord(character) < 0x20 for character in target_serial)
            ):
                raise ValueError("browser intent target serial is invalid")
            if scheme not in {"http", "https"}:
                raise ValueError("browser intent scheme is invalid")
            if (
                not isinstance(host, str)
                or not host
                or not host.isascii()
                or len(host) > 253
                or any(character.isspace() or ord(character) < 0x20 for character in host)
            ):
                raise ValueError("browser intent host is invalid")
            if not isinstance(digest, str) or not self._sha256_valid(digest):
                raise ValueError("browser intent URL digest is invalid")
            return
        if postcondition.kind != "host_artifact_written":
            raise ValueError(f"no execution-evidence mapping exists for {postcondition.kind}")
        allowed = {
            "path",
            "sourceSha256",
            "expectedSha256",
            "requireDifferentSha256",
            "minimumBytes",
            "maximumBytes",
        }
        if set(expected) - allowed:
            raise ValueError("host artifact postcondition contains unknown fields")
        path = expected.get("path")
        source_digest = expected.get("sourceSha256")
        expected_digest = expected.get("expectedSha256")
        require_different = expected.get("requireDifferentSha256", False)
        minimum_bytes = expected.get("minimumBytes", 1)
        maximum_bytes = expected.get("maximumBytes", 2 * 1024 * 1024 * 1024)
        if not isinstance(path, str) or not path or not Path(path).is_absolute():
            raise ValueError("host artifact postcondition path must be absolute")
        for name, digest in (
            ("sourceSha256", source_digest),
            ("expectedSha256", expected_digest),
        ):
            if digest is not None and (not isinstance(digest, str) or not self._sha256_valid(digest)):
                raise ValueError(f"host artifact {name} is invalid")
        if not isinstance(require_different, bool):
            raise TypeError("host artifact difference requirement must be a boolean")
        if (
            not isinstance(minimum_bytes, int)
            or isinstance(minimum_bytes, bool)
            or minimum_bytes < 0
            or not isinstance(maximum_bytes, int)
            or isinstance(maximum_bytes, bool)
            or maximum_bytes <= 0
            or minimum_bytes > maximum_bytes
            or maximum_bytes > 2 * 1024 * 1024 * 1024
        ):
            raise ValueError("host artifact size bounds are invalid")
        if require_different and source_digest is None:
            raise ValueError("host artifact source hash is required for comparison")

    def _verify_execution_postconditions(
        self,
        plan: OperationPlan,
        result: OperationResult,
        token: CancellationToken,
    ) -> OperationResult:
        for postcondition in plan.postconditions:
            if not self._is_execution_postcondition(postcondition.kind):
                continue
            try:
                self._validate_execution_postcondition(postcondition)
            except (TypeError, ValueError) as error:
                return OperationResult.failed(
                    plan.plan_id,
                    code="postcondition_unverified",
                    message=str(error),
                )
            if token.cancelled:
                return OperationResult.cancelled(
                    plan.plan_id,
                    code="postcondition_cancelled",
                    message="execution evidence observation was cancelled",
                )
            if postcondition.kind == "adb_wifi_pairing_recorded":
                evidence = self._verify_wifi_pairing_evidence(postcondition, result)
            elif postcondition.kind == "package_export_verified":
                evidence = self._verify_package_export_evidence(postcondition, result)
            elif postcondition.kind in {
                "data_adb_backup_verified",
                "data_adb_restore_verified",
            }:
                evidence = self._verify_data_adb_evidence(postcondition, result)
            elif postcondition.kind == "package_data_cleared":
                evidence = self._verify_package_clear_evidence(postcondition, result)
            elif postcondition.kind == "logcat_buffers_cleared":
                evidence = self._verify_logcat_clear_evidence(postcondition, result)
            elif postcondition.kind == "view_intent_accepted":
                evidence = self._verify_view_intent_evidence(postcondition, result)
            else:
                evidence = self._verify_host_artifact(postcondition, token)
            if evidence.status is OperationStatus.CANCELLED or not evidence.ok:
                return evidence
        return OperationResult.success(
            plan.plan_id,
            code="execution_postconditions_satisfied",
        )

    @staticmethod
    def _verify_data_adb_evidence(
        postcondition: OperationPostcondition,
        result: OperationResult,
    ) -> OperationResult:
        value = OperationRunner._result_value_mapping(cast(object, result.value))
        digest_fields = ("sha256", "payloadSha256", "contentFingerprint")
        if postcondition.kind == "data_adb_backup_verified":
            valid = (
                set(value)
                == {
                    "action",
                    "targetSerial",
                    "fileName",
                    "sha256",
                    "sizeBytes",
                    "payloadSha256",
                    "entryCount",
                    "contentFingerprint",
                    "deviceCodename",
                    "verified",
                    "remoteCleaned",
                }
                and value.get("action") == "backup"
                and value.get("fileName") == postcondition.expected["fileName"]
                and isinstance(value.get("sizeBytes"), int)
                and not isinstance(value.get("sizeBytes"), bool)
                and 1 <= cast(int, value.get("sizeBytes")) <= 2 * 1024 * 1024 * 1024 + 32 * 1024 * 1024
            )
        else:
            digest_fields = ("payloadSha256", "contentFingerprint")
            valid = (
                set(value)
                == {
                    "action",
                    "targetSerial",
                    "payloadSha256",
                    "entryCount",
                    "contentFingerprint",
                    "deviceCodename",
                    "verified",
                    "remoteCleaned",
                }
                and value.get("action") == "restore"
                and value.get("contentFingerprint")
                == postcondition.expected["contentFingerprint"]
                and value.get("entryCount") == postcondition.expected["entryCount"]
            )
        valid = (
            valid
            and isinstance(value.get("targetSerial"), str)
            and bool(value.get("targetSerial"))
            and isinstance(value.get("deviceCodename"), str)
            and bool(value.get("deviceCodename"))
            and isinstance(value.get("entryCount"), int)
            and not isinstance(value.get("entryCount"), bool)
            and 0 <= cast(int, value.get("entryCount")) <= 20_000
            and all(
                isinstance(value.get(field), str)
                and OperationRunner._sha256_valid(cast(str, value.get(field)))
                for field in digest_fields
            )
            and value.get("verified") is True
            and value.get("remoteCleaned") is True
        )
        if not valid:
            return OperationResult.failed(
                result.operation_id,
                code="postcondition_mismatch",
                message="/data/adb receipt does not prove identity, hashes, cleanup, and publication",
            )
        return OperationResult.success(
            result.operation_id,
            code=postcondition.kind,
        )

    @staticmethod
    def _verify_package_export_evidence(
        postcondition: OperationPostcondition,
        result: OperationResult,
    ) -> OperationResult:
        value = OperationRunner._result_value_mapping(cast(object, result.value))
        export = value.get("export")
        if not isinstance(export, Mapping):
            return OperationResult.failed(
                result.operation_id,
                code="postcondition_unverified",
                message="APK export returned no closed verification receipt",
            )
        receipt = cast(Mapping[object, object], export)
        package = postcondition.expected["package"]
        file_name = postcondition.expected["fileName"]
        digest = receipt.get("sha256")
        size = receipt.get("size")
        if (
            value.get("action") != "export"
            or set(receipt)
            != {
                "package",
                "fileName",
                "sha256",
                "size",
                "verified",
                "remoteCleaned",
            }
            or receipt.get("package") != package
            or receipt.get("fileName") != file_name
            or receipt.get("verified") is not True
            or receipt.get("remoteCleaned") is not True
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not 1 <= size <= 2 * 1024 * 1024 * 1024
        ):
            return OperationResult.failed(
                result.operation_id,
                code="postcondition_mismatch",
                message="APK export receipt does not prove identity, hash, publication, and cleanup",
            )
        return OperationResult.success(
            result.operation_id,
            code="package_export_verified",
        )

    def _verify_wifi_pairing_evidence(
        self,
        postcondition: OperationPostcondition,
        result: OperationResult,
    ) -> OperationResult:
        endpoint = cast(str, postcondition.expected["endpoint"])
        value: Mapping[str, object] = self._result_value_mapping(cast(object, result.value))
        if (
            value.get("protocolVerified") is True
            and value.get("endpoint") == endpoint
            and result.code == "wifi_pair_succeeded"
        ):
            return OperationResult.success(
                result.operation_id,
                code="pairing_protocol_verified",
            )
        normalized = tuple(
            line.strip().casefold()
            for line in (*result.stdout.splitlines(), *result.stderr.splitlines())
            if line.strip()
        )
        expected_lines = {
            f"successfully paired to {endpoint.casefold()}",
        }
        matches = any(
            line in expected_lines
            or (
                line.startswith("enter pairing code:")
                and line.endswith(f"successfully paired to {endpoint.casefold()}")
            )
            or (line.startswith(f"successfully paired to {endpoint.casefold()} [") and line.endswith("]"))
            for line in normalized
        )
        failed = any(marker in line for line in normalized for marker in ("failed", "cannot", "unable", "error"))
        if matches and not failed:
            return OperationResult.success(
                result.operation_id,
                code="pairing_protocol_verified",
            )
        return OperationResult.failed(
            result.operation_id,
            code="postcondition_mismatch",
            message="ADB did not provide exact cryptographic pairing success evidence",
        )

    @staticmethod
    def _verify_package_clear_evidence(
        postcondition: OperationPostcondition,
        result: OperationResult,
    ) -> OperationResult:
        expected_count = cast(int, postcondition.expected["successCount"])
        if result.stderr.strip():
            return OperationResult.failed(
                result.operation_id,
                code="postcondition_mismatch",
                message="pm clear produced unexpected diagnostic output",
            )
        lines = tuple(line.strip() for line in result.stdout.replace("\r", "").splitlines() if line.strip())
        if len(lines) != expected_count or any(line != "Success" for line in lines):
            return OperationResult.failed(
                result.operation_id,
                code="postcondition_mismatch",
                message="pm clear did not report one exact success record per package",
            )
        return OperationResult.success(
            result.operation_id,
            code="package_clear_protocol_verified",
        )

    @staticmethod
    def _verify_logcat_clear_evidence(
        postcondition: OperationPostcondition,
        result: OperationResult,
    ) -> OperationResult:
        pre_marker = cast(str, postcondition.expected["preMarker"])
        post_marker = cast(str, postcondition.expected["postMarker"])
        pre_start_marker = cast(str, postcondition.expected["preStartMarker"])
        pre_end_marker = cast(str, postcondition.expected["preEndMarker"])
        post_start_marker = cast(str, postcondition.expected["postStartMarker"])
        post_end_marker = cast(str, postcondition.expected["postEndMarker"])
        if result.code != "process_succeeded" or result.exit_code != 0:
            return OperationResult.failed(
                result.operation_id,
                code="postcondition_unverified",
                message="Logcat clear lacks an exact successful process transcript",
            )
        if result.stderr.strip():
            return OperationResult.failed(
                result.operation_id,
                code="postcondition_mismatch",
                message="Logcat clear produced unexpected diagnostic output",
            )
        normalized_stdout = result.stdout.replace("\r\n", "\n").replace("\r", "\n")
        lines = tuple(
            line
            for line in normalized_stdout.split("\n")
            if line
        )
        boundaries = (
            pre_start_marker,
            pre_end_marker,
            post_start_marker,
            post_end_marker,
        )
        if any(lines.count(marker) != 1 for marker in boundaries):
            return OperationResult.failed(
                result.operation_id,
                code="postcondition_unverified",
                message="the Logcat clear query boundaries were not observed exactly once",
            )
        positions = tuple(lines.index(marker) for marker in boundaries)
        if positions != tuple(sorted(positions)):
            return OperationResult.failed(
                result.operation_id,
                code="postcondition_unverified",
                message="the Logcat clear query boundaries were observed out of order",
            )
        pre_query = lines[positions[0] + 1 : positions[1]]
        post_query = lines[positions[2] + 1 : positions[3]]
        if pre_query.count(pre_marker) != 1 or post_query.count(post_marker) != 1:
            return OperationResult.failed(
                result.operation_id,
                code="postcondition_unverified",
                message="the Logcat clear probes could not be observed exactly once",
            )
        if (
            pre_marker in post_query
            or post_marker in pre_query
            or pre_query.count(post_marker)
            or post_query.count(pre_marker)
        ):
            return OperationResult.failed(
                result.operation_id,
                code="postcondition_mismatch",
                message="a pre-clear Logcat entry remained after the buffer clear",
            )
        return OperationResult.success(
            result.operation_id,
            code="logcat_clear_protocol_verified",
        )

    @staticmethod
    def _verify_view_intent_evidence(
        postcondition: OperationPostcondition,
        result: OperationResult,
    ) -> OperationResult:
        expected = postcondition.expected
        value = OperationRunner._result_value_mapping(cast(object, result.value))
        exact_fields = {
            "action",
            "targetSerial",
            "scheme",
            "host",
            "urlSha256",
            "intentAccepted",
        }
        digest = value.get("urlSha256")
        expected_digest = expected.get("urlSha256")
        verified = (
            result.code == "device_open_url_succeeded"
            and result.exit_code == 0
            and not result.stdout
            and not result.stderr
            and set(value) == exact_fields
            and value.get("action") == "openUrl"
            and isinstance(value.get("targetSerial"), str)
            and value.get("targetSerial") == expected.get("targetSerial")
            and value.get("scheme") == expected.get("scheme")
            and value.get("host") == expected.get("host")
            and value.get("intentAccepted") is True
            and isinstance(digest, str)
            and isinstance(expected_digest, str)
            and hmac.compare_digest(digest, expected_digest)
        )
        if not verified:
            return OperationResult.failed(
                result.operation_id,
                code="postcondition_mismatch",
                message="the browser VIEW intent receipt did not match its immutable plan",
            )
        return OperationResult.success(
            result.operation_id,
            code="view_intent_protocol_verified",
        )

    @classmethod
    def _verify_host_artifact(
        cls,
        postcondition: OperationPostcondition,
        token: CancellationToken,
    ) -> OperationResult:
        expected = postcondition.expected
        raw_path = cast(str, expected["path"])
        path = Path(raw_path)
        minimum_bytes = cast(int, expected.get("minimumBytes", 1))
        maximum_bytes = cast(
            int,
            expected.get("maximumBytes", 2 * 1024 * 1024 * 1024),
        )
        try:
            canonical = path.resolve(strict=True)
            size = canonical.stat().st_size
        except FileNotFoundError:
            return OperationResult.failed(
                "host-artifact",
                code="postcondition_mismatch",
                message="the planned host artifact was not created",
            )
        except OSError as error:
            return OperationResult.failed(
                "host-artifact",
                code="postcondition_unverified",
                message=str(error),
            )
        if canonical != path or path.is_symlink() or not canonical.is_file():
            return OperationResult.failed(
                "host-artifact",
                code="postcondition_mismatch",
                message="the planned host artifact is not the canonical regular file",
            )
        if not minimum_bytes <= size <= maximum_bytes:
            return OperationResult.failed(
                "host-artifact",
                code="postcondition_mismatch",
                message="the planned host artifact size is outside its verified bounds",
            )
        digest = hashlib.sha256()
        try:
            with canonical.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    if token.cancelled:
                        return OperationResult.cancelled(
                            "host-artifact",
                            code="postcondition_cancelled",
                            message="host artifact verification was cancelled",
                        )
                    digest.update(chunk)
        except OSError as error:
            return OperationResult.failed(
                "host-artifact",
                code="postcondition_unverified",
                message=str(error),
            )
        actual = digest.hexdigest()
        expected_digest = expected.get("expectedSha256")
        if isinstance(expected_digest, str) and not hmac.compare_digest(
            actual,
            expected_digest.casefold(),
        ):
            return OperationResult.failed(
                "host-artifact",
                code="postcondition_mismatch",
                message="the host artifact hash differs from the planned hash",
            )
        source_digest = expected.get("sourceSha256")
        if (
            expected.get("requireDifferentSha256") is True
            and isinstance(
                source_digest,
                str,
            )
            and hmac.compare_digest(actual, source_digest.casefold())
        ):
            return OperationResult.failed(
                "host-artifact",
                code="postcondition_mismatch",
                message="the host artifact is unchanged from its source",
            )
        return OperationResult.success(
            "host-artifact",
            code="host_artifact_verified",
            value={"path": raw_path, "sha256": actual, "size": size},
        )

    @staticmethod
    def _sha256_valid(value: str) -> bool:
        return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)

    def _host_postcondition_spec(self, plan: OperationPlan) -> HostPostconditionSpec:
        """Translate only application-scoped postconditions with host evidence."""

        if plan.target_serial is not None:
            raise ValueError("host postconditions cannot name a target serial")
        expected_adb_endpoints: dict[str, bool] = {}
        for postcondition in plan.postconditions:
            if self._is_execution_postcondition(postcondition.kind):
                continue
            if postcondition.kind != "adb_wifi_endpoint_state":
                raise ValueError(
                    f"no host observer mapping exists for postcondition: {postcondition.kind}"
                )
            expected = postcondition.expected
            if set(expected) != {"endpoint", "connected"}:
                raise ValueError("ADB Wi-Fi endpoint postcondition fields are invalid")
            endpoint = expected.get("endpoint")
            connected = expected.get("connected")
            if not isinstance(endpoint, str) or not endpoint:
                raise ValueError("ADB Wi-Fi endpoint is unavailable")
            if not isinstance(connected, bool):
                raise TypeError("ADB Wi-Fi endpoint state must be a boolean")
            current = expected_adb_endpoints.get(endpoint)
            if current is not None and current is not connected:
                raise ValueError("conflicting ADB Wi-Fi endpoint postconditions")
            expected_adb_endpoints[endpoint] = connected
        return HostPostconditionSpec(
            self.postcondition_timeout_seconds,
            expected_adb_endpoints,
        )

    def _postcondition_spec(self, plan: OperationPlan) -> PostconditionSpec:
        """Translate only postconditions for which the observer has evidence."""

        serial = plan.target_serial or ""
        if not serial:
            raise ValueError("postcondition target serial is unavailable")
        mode: str | None = None
        slot: str | None = None
        bootloader: str | None = None
        boot_completed: bool | None = None
        safe_mode: bool | None = None
        ota_idle: bool | None = None
        build: str | None = None
        remote_hashes: dict[str, str] = {}
        partition_hashes: dict[str, str] = {}
        expected_packages: dict[str, bool] = {}
        expected_package_states: dict[str, str] = {}
        expected_package_installers: dict[str, str] = {}
        expected_adb_endpoints: dict[str, bool] = {}
        expected_root_modules: dict[str, str] = {}
        expected_magisk_denylist: dict[str, bool] = {}
        expected_magisk_su_policies: dict[int, str] = {}
        expected_magisk_backups: dict[str, str] = {}
        expected_shizuku_running: bool | None = None
        expected_magisk_modules_disabled: bool | None = None
        expected_data_adb_empty: bool | None = None
        erased_partitions: list[str] = []

        def bind(current: object, value: object, name: str) -> object:
            if current is not None and current != value:
                raise ValueError(f"conflicting {name} postconditions")
            return value

        for postcondition in plan.postconditions:
            expected = postcondition.expected
            if postcondition.kind == "device_reachable":
                raw_mode = expected.get("mode")
                if raw_mode is not None:
                    normalized_mode = self._observed_mode(raw_mode)
                    mode = bind(mode, normalized_mode, "mode")  # type: ignore[assignment]
                raw_boot_completed = expected.get("bootCompleted")
                if raw_boot_completed is not None:
                    if not isinstance(raw_boot_completed, bool):
                        raise TypeError("bootCompleted postcondition must be a boolean")
                    boot_completed = bind(  # type: ignore[assignment]
                        boot_completed,
                        raw_boot_completed,
                        "boot completion",
                    )
            elif postcondition.kind == "device_mode":
                normalized_mode = self._observed_mode(expected.get("mode"))
                mode = bind(mode, normalized_mode, "mode")  # type: ignore[assignment]
            elif postcondition.kind == "safe_mode_active":
                active = expected.get("active")
                if not isinstance(active, bool):
                    raise TypeError("safe mode postcondition must contain a boolean active state")
                safe_mode = bind(  # type: ignore[assignment]
                    safe_mode,
                    active,
                    "safe mode",
                )
            elif postcondition.kind == "ota_idle_state":
                idle = expected.get("idle")
                if not isinstance(idle, bool):
                    raise TypeError("OTA idle postcondition must contain a boolean idle state")
                mode = bind(mode, "adb", "mode")  # type: ignore[assignment]
                ota_idle = bind(  # type: ignore[assignment]
                    ota_idle,
                    idle,
                    "OTA idle state",
                )
            elif postcondition.kind == "active_slot":
                expected_slot = expected.get("slot")
                if expected_slot not in {"a", "b"}:
                    raise ValueError("active slot postcondition must be a or b")
                slot = bind(slot, expected_slot, "slot")  # type: ignore[assignment]
            elif postcondition.kind == "bootloader_state":
                expected_state = expected.get("state")
                if not isinstance(expected_state, str) or not expected_state:
                    raise ValueError("bootloader postcondition state is unavailable")
                bootloader = bind(  # type: ignore[assignment]
                    bootloader,
                    expected_state,
                    "bootloader",
                )
            elif postcondition.kind == "partition_written":
                partition = expected.get("partition")
                digest = expected.get("sha256")
                target_slot = expected.get("slot", "")
                if not isinstance(partition, str) or not partition:
                    raise ValueError("partition postcondition target is unavailable")
                if not isinstance(digest, str) or not digest:
                    raise ValueError("partition postcondition hash is unavailable")
                if target_slot not in {"", "a", "b"}:
                    raise ValueError("partition postcondition slot is invalid")
                key = f"{partition}_{target_slot}" if target_slot else partition
                self._bind_partition_hash(partition_hashes, key, digest)
            elif postcondition.kind == "partition_erased":
                partition = expected.get("partition")
                if not isinstance(partition, str) or not partition:
                    raise ValueError("erased partition postcondition target is unavailable")
                if partition in erased_partitions:
                    raise ValueError("erased partition postcondition is duplicated")
                erased_partitions.append(partition)
            elif postcondition.kind == "live_boot_active":
                # fastboot's successful argv binds execution to the verified local
                # artifact. The observable postcondition is that the target reaches
                # Android and completes boot; Android exposes no trustworthy hash for
                # the transient RAM-loaded boot image.
                mode = bind(mode, "adb", "mode")  # type: ignore[assignment]
                boot_completed = bind(  # type: ignore[assignment]
                    boot_completed,
                    True,
                    "boot completion",
                )
            elif postcondition.kind == "root_app_installed":
                package_name = expected.get("packageName")
                if not isinstance(package_name, str) or not package_name:
                    raise ValueError("root-app package evidence is unavailable for installation verification")
                current_package = expected_packages.get(package_name)
                if current_package is not None and current_package is not True:
                    raise ValueError("conflicting root-app package postconditions")
                expected_packages[package_name] = True
            elif postcondition.kind == "package_state":
                package_values = expected.get("packages")
                package_state = expected.get("state")
                if isinstance(package_values, str) or not isinstance(
                    package_values,
                    (tuple, list),
                ):
                    raise TypeError("package state postcondition targets must be an array")
                if not isinstance(package_state, str) or not package_state:
                    raise ValueError("package state postcondition is unavailable")
                for package_name in cast(tuple[object, ...] | list[object], package_values):
                    if not isinstance(package_name, str) or not package_name:
                        raise TypeError("package state postcondition targets must be non-empty strings")
                    current_state = expected_package_states.get(package_name)
                    if current_state is not None and current_state != package_state:
                        raise ValueError("conflicting package state postconditions")
                    expected_package_states[package_name] = package_state
            elif postcondition.kind == "package_installer":
                if set(expected) != {"package", "installer"}:
                    raise ValueError("package installer postcondition fields are invalid")
                package_name = expected.get("package")
                installer = expected.get("installer")
                if (
                    not isinstance(package_name, str)
                    or not package_name
                    or not isinstance(installer, str)
                    or not installer
                ):
                    raise TypeError("package installer postcondition is invalid")
                current_installer = expected_package_installers.get(package_name)
                if current_installer is not None and current_installer != installer:
                    raise ValueError("conflicting package installer postconditions")
                expected_package_installers[package_name] = installer
            elif postcondition.kind == "magisk_denylist_state":
                if set(expected) != {"packages", "listed"}:
                    raise ValueError("Magisk denylist postcondition fields are invalid")
                package_values = expected.get("packages")
                listed = expected.get("listed")
                if isinstance(package_values, str) or not isinstance(
                    package_values,
                    (tuple, list),
                ):
                    raise TypeError("Magisk denylist targets must be an array")
                if not isinstance(listed, bool):
                    raise TypeError("Magisk denylist state must be a boolean")
                values = cast(tuple[object, ...] | list[object], package_values)
                if not values or len(values) > 100:
                    raise ValueError("Magisk denylist targets are outside their bounds")
                for package_name in values:
                    if not isinstance(package_name, str) or not package_name:
                        raise TypeError("Magisk denylist targets must be package names")
                    current = expected_magisk_denylist.get(package_name)
                    if current is not None and current is not listed:
                        raise ValueError("conflicting Magisk denylist postconditions")
                    expected_magisk_denylist[package_name] = listed
            elif postcondition.kind == "magisk_su_policy":
                if set(expected) != {
                    "package",
                    "uid",
                    "state",
                    "policy",
                    "logging",
                    "notification",
                    "until",
                }:
                    raise ValueError("Magisk SU postcondition fields are invalid")
                package_name = expected.get("package")
                uid = expected.get("uid")
                state = expected.get("state")
                policy = expected.get("policy")
                logging = expected.get("logging")
                notification = expected.get("notification")
                until = expected.get("until")
                if not isinstance(package_name, str) or not package_name:
                    raise TypeError("Magisk SU package is invalid")
                if (
                    not isinstance(uid, int)
                    or isinstance(uid, bool)
                    or not 0 <= uid <= 2_147_483_647
                ):
                    raise ValueError("Magisk SU UID is invalid")
                if state not in {"present", "absent"} or policy not in {
                    "allow",
                    "deny",
                    "revoke",
                }:
                    raise ValueError("Magisk SU policy state is invalid")
                if not isinstance(logging, bool) or not isinstance(notification, bool):
                    raise TypeError("Magisk SU flags are invalid")
                if (
                    not isinstance(until, int)
                    or isinstance(until, bool)
                    or not 0 <= until <= 9_999_999_999
                ):
                    raise ValueError("Magisk SU expiry is invalid")
                if state == "absent":
                    if policy != "revoke":
                        raise ValueError("absent Magisk SU policy must be a revocation")
                    canonical = "absent"
                else:
                    if policy not in {"allow", "deny"}:
                        raise ValueError("present Magisk SU policy must allow or deny")
                    canonical = (
                        f"{policy}:{int(logging)}:{int(notification)}:{until}"
                    )
                current = expected_magisk_su_policies.get(uid)
                if current is not None and current != canonical:
                    raise ValueError("conflicting Magisk SU policy postconditions")
                expected_magisk_su_policies[uid] = canonical
            elif postcondition.kind == "magisk_backup_state":
                if set(expected) != {"sha1", "state"}:
                    raise ValueError("Magisk backup postcondition fields are invalid")
                sha1 = expected.get("sha1")
                backup_state = expected.get("state")
                if (
                    not isinstance(sha1, str)
                    or re.fullmatch(r"[0-9a-f]{40}", sha1) is None
                    or backup_state not in {"verified", "absent"}
                ):
                    raise ValueError("Magisk backup postcondition is invalid")
                current_backup = expected_magisk_backups.get(sha1)
                if current_backup is not None and current_backup != backup_state:
                    raise ValueError("conflicting Magisk backup postconditions")
                expected_magisk_backups[sha1] = cast(str, backup_state)
            elif postcondition.kind == "shizuku_state":
                if set(expected) != {"running"}:
                    raise ValueError("Shizuku postcondition fields are invalid")
                running = expected.get("running")
                if not isinstance(running, bool):
                    raise TypeError("Shizuku running state must be a boolean")
                expected_shizuku_running = cast(
                    bool,
                    bind(expected_shizuku_running, running, "Shizuku state"),
                )
            elif postcondition.kind == "magisk_modules_state":
                if set(expected) != {"allDisabled"}:
                    raise ValueError("Magisk module aggregate postcondition fields are invalid")
                all_disabled = expected.get("allDisabled")
                if not isinstance(all_disabled, bool):
                    raise TypeError("Magisk module aggregate state must be a boolean")
                expected_magisk_modules_disabled = cast(
                    bool,
                    bind(
                        expected_magisk_modules_disabled,
                        all_disabled,
                        "Magisk module aggregate state",
                    ),
                )
            elif postcondition.kind == "data_adb_empty":
                if set(expected) != {"empty"}:
                    raise ValueError("/data/adb empty postcondition fields are invalid")
                empty = expected.get("empty")
                if not isinstance(empty, bool):
                    raise TypeError("/data/adb empty state must be a boolean")
                expected_data_adb_empty = cast(
                    bool,
                    bind(expected_data_adb_empty, empty, "/data/adb empty state"),
                )
            elif postcondition.kind == "remote_files_written":
                raw_mode = expected.get("mode")
                if raw_mode is not None:
                    normalized_mode = self._observed_mode(raw_mode)
                    mode = bind(mode, normalized_mode, "mode")  # type: ignore[assignment]
                raw_hashes = expected.get("hashes")
                if not isinstance(raw_hashes, Mapping) or not raw_hashes:
                    raise TypeError("remote file postcondition hashes must be an object")
                for raw_path, raw_digest in cast(
                    Mapping[object, object],
                    raw_hashes,
                ).items():
                    if not isinstance(raw_path, str) or not raw_path.startswith("/"):
                        raise TypeError("remote file postcondition paths must be absolute strings")
                    if not isinstance(raw_digest, str) or not self._sha256_valid(raw_digest):
                        raise ValueError("remote file postcondition hash is invalid")
                    current_digest = remote_hashes.get(raw_path)
                    normalized_digest = raw_digest.casefold()
                    if current_digest is not None and not hmac.compare_digest(
                        current_digest,
                        normalized_digest,
                    ):
                        raise ValueError("conflicting remote file postconditions")
                    remote_hashes[raw_path] = normalized_digest
            elif postcondition.kind == "adb_wifi_endpoint_state":
                endpoint = expected.get("endpoint")
                connected = expected.get("connected")
                if not isinstance(endpoint, str) or not endpoint:
                    raise ValueError("ADB Wi-Fi endpoint is unavailable")
                if not isinstance(connected, bool):
                    raise TypeError("ADB Wi-Fi endpoint state must be a boolean")
                current_endpoint = expected_adb_endpoints.get(endpoint)
                if current_endpoint is not None and current_endpoint is not connected:
                    raise ValueError("conflicting ADB Wi-Fi endpoint postconditions")
                expected_adb_endpoints[endpoint] = connected
            elif self._is_execution_postcondition(postcondition.kind):
                self._validate_execution_postcondition(postcondition)
            elif postcondition.kind == "root_module_state":
                module_id = expected.get("moduleId")
                module_state = expected.get("state")
                if not isinstance(module_id, str) or not module_id:
                    raise ValueError("root module postcondition ID is unavailable")
                if not isinstance(module_state, str) or not module_state:
                    raise ValueError("root module postcondition state is unavailable")
                current_module = expected_root_modules.get(module_id)
                if current_module is not None and current_module != module_state:
                    raise ValueError("conflicting root module postconditions")
                expected_root_modules[module_id] = module_state
            elif postcondition.kind == "flash_applied":
                hashes, flashed_partitions = self._planned_partition_hashes(plan)
                expected_partitions = expected.get("partitions", plan.partitions)
                if isinstance(expected_partitions, str) or not isinstance(
                    expected_partitions,
                    (tuple, list),
                ):
                    raise TypeError("flash postcondition partitions must be an array")
                normalized_partitions: set[str] = set()
                for item in cast(tuple[object, ...] | list[object], expected_partitions):
                    if not isinstance(item, str) or not item:
                        raise TypeError("flash postcondition partitions must contain non-empty strings")
                    normalized_partitions.add(item)
                missing = normalized_partitions - flashed_partitions
                if missing:
                    raise ValueError(f"partition hash evidence is unavailable for {sorted(missing)[0]}")
                for key, digest in hashes.items():
                    self._bind_partition_hash(partition_hashes, key, digest)
                raw_build = expected.get("build")
                if raw_build:
                    if not isinstance(raw_build, str):
                        raise TypeError("firmware build postcondition must be a string")
                    build = bind(build, raw_build, "firmware build")  # type: ignore[assignment]
            elif postcondition.kind == "firmware_applied":
                raw_build = expected.get("build")
                if not isinstance(raw_build, str) or not raw_build:
                    raise ValueError("installed firmware build evidence is unavailable for OTA verification")
                build = bind(build, raw_build, "firmware build")  # type: ignore[assignment]
            else:
                raise ValueError(f"no observer mapping exists for postcondition: {postcondition.kind}")

        return PostconditionSpec(
            serial,
            self.postcondition_timeout_seconds,
            expected_mode=mode,
            expected_slot=slot,
            expected_bootloader=bootloader,
            expected_boot_completed=boot_completed,
            expected_safe_mode=safe_mode,
            expected_ota_idle=ota_idle,
            expected_build=build,
            partition_hashes=partition_hashes,
            expected_packages=expected_packages,
            expected_package_states=expected_package_states,
            expected_package_installers=expected_package_installers,
            remote_hashes=remote_hashes,
            expected_adb_endpoints=expected_adb_endpoints,
            expected_root_modules=expected_root_modules,
            expected_magisk_denylist=expected_magisk_denylist,
            expected_magisk_su_policies=expected_magisk_su_policies,
            expected_magisk_backups=expected_magisk_backups,
            expected_shizuku_running=expected_shizuku_running,
            expected_magisk_modules_disabled=expected_magisk_modules_disabled,
            expected_data_adb_empty=expected_data_adb_empty,
            erased_partitions=tuple(erased_partitions),
        )

    @staticmethod
    def _observed_mode(value: object) -> str:
        if not isinstance(value, str) or not value:
            raise ValueError("device mode postcondition is unavailable")
        return {"system": "adb", "bootloader": "fastboot"}.get(value, value)

    @staticmethod
    def _bind_partition_hash(values: dict[str, str], key: str, digest: str) -> None:
        normalized = digest.casefold()
        current = values.get(key)
        if current is not None and not hmac.compare_digest(current, normalized):
            raise ValueError(f"conflicting partition hash postconditions for {key}")
        values[key] = normalized

    @staticmethod
    def _planned_partition_hashes(
        plan: OperationPlan,
    ) -> tuple[dict[str, str], set[str]]:
        artifacts = {artifact.path: artifact.sha256 for artifact in plan.artifacts}
        hashes: dict[str, str] = {}
        partitions: set[str] = set()
        for request in plan.requests:
            try:
                flash_index = request.argv.index("flash")
            except ValueError:
                continue
            if flash_index + 2 >= len(request.argv):
                continue
            partition = request.argv[flash_index + 1]
            digest = artifacts.get(request.argv[flash_index + 2])
            if digest is None:
                continue
            target_slot = next(
                (
                    argument.partition("=")[2]
                    for argument in request.argv[:flash_index]
                    if argument.startswith("--slot=")
                ),
                "",
            )
            key = f"{partition}_{target_slot}" if target_slot else partition
            current = hashes.get(key)
            if current is not None and not hmac.compare_digest(current, digest):
                raise ValueError(f"conflicting planned hashes for partition {key}")
            hashes[key] = digest
            partitions.add(partition)
        if not hashes:
            raise ValueError("no partition hash evidence is available for flash verification")
        return hashes, partitions

    def _observe(
        self,
        plan: OperationPlan,
        postcondition: OperationPostcondition,
        snapshot: AppSnapshot,
        observer: PostconditionObserverLike | None,
    ) -> PostconditionObservation:
        if observer is None:
            return self._observe_snapshot(plan, postcondition, snapshot)
        observer_method = getattr(observer, "observe", None)
        if callable(observer_method):
            target = observer_method
        elif callable(observer):
            target = observer
        else:
            raise TypeError("postcondition observer is not callable")
        outcome = target(plan, postcondition, snapshot)
        if isinstance(outcome, PostconditionObservation):
            return outcome
        if isinstance(outcome, bool):
            return PostconditionObservation(outcome)
        if isinstance(outcome, Mapping):
            values = cast(Mapping[object, object], outcome)
            satisfied = values.get("satisfied", values.get("ok"))
            if not isinstance(satisfied, bool):
                raise TypeError("observer mapping must contain boolean satisfied or ok")
            verified = values.get("verified", True)
            if not isinstance(verified, bool):
                raise TypeError("observer verified must be a boolean")
            message = values.get("message", "")
            if not isinstance(message, str):
                raise TypeError("observer message must be a string")
            return PostconditionObservation(satisfied, message, verified)
        raise TypeError("postcondition observer returned an invalid result")

    @staticmethod
    def _observe_snapshot(
        plan: OperationPlan,
        postcondition: OperationPostcondition,
        snapshot: AppSnapshot,
    ) -> PostconditionObservation:
        device = next(
            (item for item in snapshot.devices if item.serial == plan.target_serial),
            None,
        )
        expected = postcondition.expected
        if device is None:
            return PostconditionObservation(
                False,
                f"device evidence is unavailable for {plan.target_serial!r}",
                False,
            )
        if postcondition.kind == "device_reachable":
            if not device.online:
                return PostconditionObservation(False, "device was observed offline")
            if "bootCompleted" in expected:
                return PostconditionObservation(
                    False,
                    "boot completion is not represented in the application snapshot",
                    False,
                )
            target = expected.get("mode")
            if target is not None:
                aliases = {"system": "adb", "bootloader": "fastboot"}
                target = aliases.get(str(target), str(target))
                if not device.mode:
                    return PostconditionObservation(
                        False,
                        "device mode evidence is unavailable",
                        False,
                    )
                return PostconditionObservation(device.mode == target)
            return PostconditionObservation(True)
        if postcondition.kind == "device_mode":
            target = str(expected.get("mode", ""))
            aliases = {"system": "adb", "bootloader": "fastboot"}
            target = aliases.get(target, target)
            if not device.online:
                return PostconditionObservation(False, "device was observed offline")
            if not device.mode:
                return PostconditionObservation(
                    False,
                    "device mode evidence is unavailable",
                    False,
                )
            return PostconditionObservation(device.mode == target)
        if postcondition.kind == "safe_mode_active":
            return PostconditionObservation(
                False,
                "safe mode is not represented in the application snapshot",
                False,
            )
        if postcondition.kind == "active_slot":
            if device.slot not in {"a", "b"}:
                return PostconditionObservation(
                    False,
                    "active slot evidence is unavailable",
                    False,
                )
            return PostconditionObservation(device.slot == expected.get("slot"))
        if postcondition.kind == "bootloader_state":
            if device.bootloader in {"", "unknown"}:
                return PostconditionObservation(
                    False,
                    "bootloader state evidence is unavailable",
                    False,
                )
            return PostconditionObservation(device.bootloader == expected.get("state"))
        return PostconditionObservation(
            False,
            f"no observer is registered for postcondition: {postcondition.kind}",
            False,
        )

    def _snapshot_for(
        self,
        plan: OperationPlan,
        fallback: AppSnapshot | None,
        provider: SnapshotProvider | None,
    ) -> AppSnapshot | OperationResult:
        serial = plan.target_serial or ""
        if provider is not None:
            return self._provided_snapshot(provider, serial, plan.plan_id)
        if isinstance(fallback, AppSnapshot):
            return fallback
        return OperationResult.failed(
            plan.plan_id,
            code="snapshot_unavailable",
            message="current state is required for operation revalidation",
        )

    @staticmethod
    def _provided_snapshot(
        provider: SnapshotProvider,
        serial: str,
        operation_id: str,
    ) -> AppSnapshot | OperationResult:
        try:
            snapshot = provider(serial)
        except Exception as error:
            return OperationResult.failed(
                operation_id,
                code="snapshot_unavailable",
                message=str(error),
            )
        if not isinstance(snapshot, AppSnapshot):
            return OperationResult.failed(
                operation_id,
                code="snapshot_unavailable",
                message="snapshot provider returned an invalid value",
            )
        return snapshot

    def _acquire_destructive(self, token: CancellationToken) -> bool:
        while not token.cancelled:
            if self._destructive_lock.acquire(timeout=self.lock_poll_seconds):
                return True
        return False

    @staticmethod
    def _revalidate_artifacts(
        plan: OperationPlan,
        token: CancellationToken | None = None,
    ) -> tuple[str, str] | None:
        for artifact in plan.artifacts:
            if token is not None and token.cancelled:
                return (
                    "timed_out" if token.reason is CancellationReason.DEADLINE else "cancelled",
                    "artifact revalidation was interrupted",
                )
            path = Path(artifact.path)
            if not path.is_file():
                return "artifact_missing", f"artifact no longer exists: {artifact.path}"
            digest = hashlib.sha256()
            try:
                with path.open("rb") as stream:
                    while chunk := stream.read(1024 * 1024):
                        if token is not None and token.cancelled:
                            return (
                                "timed_out"
                                if token.reason is CancellationReason.DEADLINE
                                else "cancelled",
                                "artifact revalidation was interrupted",
                            )
                        digest.update(chunk)
            except OSError as error:
                return "artifact_read_failed", str(error)
            if not hmac.compare_digest(digest.hexdigest(), artifact.sha256):
                return "artifact_hash_mismatch", f"artifact hash changed: {artifact.path}"
        return None

    @staticmethod
    def _stopped_before_mutation(
        token: CancellationToken,
        operation_id: str,
        context: str,
    ) -> OperationResult:
        if token.reason is CancellationReason.DEADLINE:
            return OperationResult.failed(
                operation_id,
                code="timed_out",
                message=f"operation deadline expired {context}",
            )
        return OperationResult.cancelled(
            operation_id,
            code="cancelled",
            message=f"operation was cancelled {context}",
        )

    @classmethod
    def _stage_artifacts(
        cls,
        plan: OperationPlan,
        token: CancellationToken,
    ) -> tuple[OperationPlan, tempfile.TemporaryDirectory[str] | None]:
        """Materialize verified inputs under a private directory before execution.

        Hashing an attacker-controlled pathname and then handing that same path
        to ADB/fastboot leaves a validate-then-use race.  This boundary opens
        each source without following links, streams it into an exclusive
        backend-owned file, verifies the expected digest, and rewrites only
        exact argv path fields to the private copy.
        """

        if plan.dry_run or not plan.artifacts:
            return plan, None
        stage = tempfile.TemporaryDirectory(prefix="pixelflasher-artifacts-")
        root = Path(stage.name)
        try:
            try:
                root.chmod(0o700)
            except OSError as error:
                raise _ArtifactStageError(
                    "artifact_stage_unavailable",
                    "verified artifact staging could not be made private",
                ) from error

            replacements: dict[str, str] = {}
            replacement_roles: dict[str, set[str]] = {}
            staged_artifacts: list[FileArtifact] = []
            seen: dict[str, str] = {}
            for index, artifact in enumerate(plan.artifacts):
                if token.cancelled:
                    raise InterruptedError("artifact staging was cancelled")
                previous_digest = seen.get(artifact.path)
                if previous_digest is not None:
                    if not hmac.compare_digest(previous_digest, artifact.sha256):
                        raise _ArtifactStageError(
                            "artifact_plan_ambiguous",
                            "one artifact path is bound to conflicting SHA-256 values",
                        )
                    staged_artifacts.append(
                        FileArtifact(
                            replacements[artifact.path],
                            artifact.sha256,
                            artifact.role,
                        )
                    )
                    continue

                suffix = Path(artifact.path).suffix.casefold()
                if suffix not in {".apk", ".bin", ".img", ".zip"}:
                    suffix = ".bin"
                destination = root / f"{index:04d}-{artifact.sha256}{suffix}"
                cls._copy_verified_artifact(
                    Path(artifact.path),
                    destination,
                    artifact.sha256,
                    token,
                )
                staged_path = str(destination)
                seen[artifact.path] = artifact.sha256
                replacements[artifact.path] = staged_path
                staged_artifacts.append(
                    FileArtifact(staged_path, artifact.sha256, artifact.role)
                )

            for artifact in plan.artifacts:
                replacement_roles.setdefault(artifact.path, set()).add(artifact.role)

            staged_requests = tuple(
                cls._rewrite_staged_request(
                    request,
                    replacements,
                    replacement_roles,
                )
                for request in plan.requests
            )
            return (
                replace(
                    plan,
                    requests=staged_requests,
                    artifacts=tuple(staged_artifacts),
                ),
                stage,
            )
        except Exception:
            cls._cleanup_artifact_stage(stage)
            raise

    @staticmethod
    def _cleanup_artifact_stage(
        stage: tempfile.TemporaryDirectory[str] | None,
    ) -> None:
        """Best-effort cleanup must never retain a global execution lock."""

        if stage is None:
            return
        try:
            stage.cleanup()
        except Exception:
            # Temporary staging is private and content-addressed.  A platform
            # cleanup failure may leave recoverable residue, but it must not
            # replace the typed operation result or deadlock every later flash.
            pass

    @staticmethod
    def _rewrite_staged_request(
        request: ProcessRequest,
        replacements: Mapping[str, str],
        replacement_roles: Mapping[str, set[str]],
    ) -> ProcessRequest:
        """Rewrite only host-side argv positions for typed artifact roles."""

        argv = list(request.argv)
        push_index = next(
            (index for index, argument in enumerate(argv) if argument == "push"),
            None,
        )
        handled: set[str] = set()
        if push_index is not None and push_index + 2 < len(argv):
            source_index = push_index + 1
            source = argv[source_index]
            roles = replacement_roles.get(source, set())
            if "push-source" in roles and source in replacements:
                argv[source_index] = replacements[source]
                handled.add(source)

        for index, argument in enumerate(argv):
            if argument in handled:
                continue
            replacement = replacements.get(argument)
            if replacement is not None:
                argv[index] = replacement
        return replace(request, argv=tuple(argv))

    @classmethod
    def _copy_verified_artifact(
        cls,
        source: Path,
        destination: Path,
        expected_sha256: str,
        token: CancellationToken,
    ) -> None:
        source_descriptor: int | None = None
        destination_descriptor: int | None = None
        binary = int(getattr(os, "O_BINARY", 0))
        nofollow = int(getattr(os, "O_NOFOLLOW", 0))
        try:
            before = source.lstat()
            if not stat.S_ISREG(before.st_mode) or source.is_symlink():
                raise _ArtifactStageError(
                    "artifact_not_regular",
                    "verified operation artifacts must be regular files",
                )
            source_descriptor = os.open(source, os.O_RDONLY | binary | nofollow)
            opened = os.fstat(source_descriptor)
            if not stat.S_ISREG(opened.st_mode) or not cls._same_open_file(before, opened):
                raise _ArtifactStageError(
                    "artifact_source_changed",
                    "artifact identity changed while it was opened",
                )
            destination_descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | binary | nofollow,
                0o600,
            )
            digest = hashlib.sha256()
            with (
                os.fdopen(source_descriptor, "rb", closefd=True) as input_stream,
                os.fdopen(destination_descriptor, "wb", closefd=True) as output_stream,
            ):
                source_descriptor = None
                destination_descriptor = None
                while chunk := input_stream.read(1024 * 1024):
                    if token.cancelled:
                        raise InterruptedError("artifact staging was cancelled")
                    digest.update(chunk)
                    output_stream.write(chunk)
                after = os.fstat(input_stream.fileno())
                if not cls._same_unchanged_file(opened, after):
                    raise _ArtifactStageError(
                        "artifact_source_changed",
                        "artifact changed while it was copied",
                    )
                output_stream.flush()
                os.fsync(output_stream.fileno())
            if not hmac.compare_digest(digest.hexdigest(), expected_sha256):
                raise _ArtifactStageError(
                    "artifact_hash_mismatch",
                    f"artifact hash changed: {source}",
                )
            destination.chmod(0o400)
            staged = destination.lstat()
            if not stat.S_ISREG(staged.st_mode) or destination.is_symlink():
                raise _ArtifactStageError(
                    "artifact_stage_invalid",
                    "verified artifact staging produced an invalid file",
                )
            cls._fsync_directory(destination.parent)
        except _ArtifactStageError:
            raise
        except InterruptedError:
            raise
        except OSError as error:
            raise _ArtifactStageError(
                "artifact_stage_failed",
                f"verified artifact staging failed: {type(error).__name__}",
            ) from error
        finally:
            if source_descriptor is not None:
                os.close(source_descriptor)
            if destination_descriptor is not None:
                os.close(destination_descriptor)

    @staticmethod
    def _same_open_file(left: os.stat_result, right: os.stat_result) -> bool:
        if left.st_ino and right.st_ino:
            return left.st_dev == right.st_dev and left.st_ino == right.st_ino
        return stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode) and left.st_size == right.st_size

    @classmethod
    def _same_unchanged_file(cls, left: os.stat_result, right: os.stat_result) -> bool:
        return (
            cls._same_open_file(left, right)
            and left.st_size == right.st_size
            and left.st_mtime_ns == right.st_mtime_ns
        )

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        directory_flag = int(getattr(os, "O_DIRECTORY", 0))
        try:
            descriptor = os.open(path, os.O_RDONLY | directory_flag)
        except OSError:
            if os.name == "nt":
                return
            raise
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _result_value_mapping(value: object) -> dict[str, object]:
        if not isinstance(value, Mapping):
            return {}
        values = cast(Mapping[object, object], value)
        return {key: item for key, item in values.items() if isinstance(key, str)}

    @staticmethod
    def _unknown_outcome(
        operation_id: str,
        message: str,
        result: OperationResult | None = None,
        *,
        safety_observation: Mapping[str, object] | None = None,
    ) -> OperationResult:
        outcome = OperationResult.failed(
            operation_id,
            code="outcome_unknown",
            message=message,
            exit_code=result.exit_code if result else None,
            stdout=result.stdout if result else "",
            stderr=result.stderr if result else "",
        )
        if safety_observation is None:
            return outcome
        return replace(
            outcome,
            value={"safetyObservation": dict(safety_observation)},
        )
