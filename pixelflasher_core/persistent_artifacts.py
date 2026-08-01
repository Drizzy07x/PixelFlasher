"""Persistent compatibility adapter for the operation planner artifact registry."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence

from .contracts import AppSnapshot, FileArtifact
from .planner import ProcessedArtifactCheckpoint, ProcessedArtifactRepository
from .repositories import ArtifactRecord, FirmwareRepository, RepositoryError

ProcessedMetadataProvider = Callable[[], Mapping[str, object]]
DeviceCodenameProvider = Callable[[], Iterable[str]]


class PersistentProcessedArtifactRepository(ProcessedArtifactRepository):
    """Use FirmwareRepository as truth while preserving the planner protocol."""

    def __init__(
        self,
        firmware_repository: FirmwareRepository,
        *,
        metadata_provider: ProcessedMetadataProvider | None = None,
        device_codename_provider: DeviceCodenameProvider | None = None,
    ) -> None:
        if not isinstance(firmware_repository, FirmwareRepository):
            raise TypeError("firmware_repository must be a FirmwareRepository")
        super().__init__()
        self.firmware_repository = firmware_repository
        self._metadata_provider = metadata_provider
        self._device_codename_provider = device_codename_provider

    def register(
        self,
        artifacts: Sequence[FileArtifact],
        *,
        firmware_hash: str = "",
        plan_fingerprint: str = "",
    ) -> None:
        records = self.firmware_repository.register_processed(
            artifacts,
            firmware_hash=firmware_hash,
            plan_fingerprint=plan_fingerprint,
            device_codenames=(
                self._device_codename_provider()
                if self._device_codename_provider is not None
                else ()
            ),
            metadata=(
                self._metadata_provider()
                if self._metadata_provider is not None
                else None
            ),
        )
        # register rebinds the key to exactly the artifacts supplied: callers
        # re-register the whole set for a firmware and rely on a superseded
        # role disappearing.  register_processed only ever adds rows, so the
        # rows this call did not produce have to go, or the planner sees two
        # artifacts for one role and refuses every flash mode.  Deleting after
        # the import keeps the previous set intact when the import fails.
        self._discard_superseded(
            firmware_hash.casefold(),
            plan_fingerprint,
            keep=frozenset(record.artifact_id for record in records),
        )

    def resolve(self, snapshot: AppSnapshot) -> tuple[FileArtifact, ...]:
        return self.resolve_binding(
            firmware_hash=snapshot.firmware.hash,
            plan_fingerprint=snapshot.plan.fingerprint,
        )

    def resolve_binding(
        self,
        *,
        firmware_hash: str = "",
        plan_fingerprint: str = "",
    ) -> tuple[FileArtifact, ...]:
        records = self.firmware_repository.resolve_processed(
            firmware_hash=firmware_hash,
            plan_fingerprint=plan_fingerprint,
        )
        return tuple(record.to_file_artifact() for record in records)

    def checkpoint(
        self,
        *,
        firmware_hash: str = "",
        plan_fingerprint: str = "",
    ) -> ProcessedArtifactCheckpoint:
        normalized_hash = firmware_hash.casefold()
        records = self._records_for_key(normalized_hash, plan_fingerprint)
        return ProcessedArtifactCheckpoint(
            firmware_hash=normalized_hash,
            plan_fingerprint=plan_fingerprint,
            existed=bool(records),
            artifact_ids=tuple(record.artifact_id for record in records),
        )

    def rollback(self, checkpoint: ProcessedArtifactCheckpoint) -> None:
        if not isinstance(checkpoint, ProcessedArtifactCheckpoint):
            raise TypeError("processed artifact checkpoint is required")
        previous_ids = frozenset(checkpoint.artifact_ids)
        current = self._records_for_key(
            checkpoint.firmware_hash,
            checkpoint.plan_fingerprint,
        )
        for record in current:
            if record.artifact_id in previous_ids:
                continue
            if not self.firmware_repository.repository.delete(record.artifact_id):
                raise RepositoryError(
                    "processed_artifact_rollback_failed",
                    "processed firmware artifact could not be removed",
                )

    def clear(self) -> None:
        """Drop no durable data; callers never own repository artifact lifetime."""

    def _records_for_key(
        self,
        firmware_hash: str,
        plan_fingerprint: str,
    ) -> tuple[ArtifactRecord, ...]:
        return tuple(
            record
            for record in self.firmware_repository.list()
            if record.metadata.get("recordType") == "processed_firmware_artifact"
            and record.metadata.get("firmwareHash") == firmware_hash
            and record.metadata.get("planFingerprint") == plan_fingerprint
        )

    def _discard_superseded(
        self,
        firmware_hash: str,
        plan_fingerprint: str,
        *,
        keep: frozenset[str],
    ) -> None:
        for record in self._records_for_key(firmware_hash, plan_fingerprint):
            if record.artifact_id in keep:
                continue
            # A False return means the row is already gone, which is exactly
            # the state this asks for; only a corrupt repository raises.
            self.firmware_repository.repository.delete(record.artifact_id)
