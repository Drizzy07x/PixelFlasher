"""Persistent compatibility adapter for the operation planner artifact registry."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence

from .contracts import AppSnapshot, FileArtifact
from .planner import ProcessedArtifactRepository
from .repositories import FirmwareRepository

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
        self.firmware_repository.register_processed(
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

    def resolve(self, snapshot: AppSnapshot) -> tuple[FileArtifact, ...]:
        records = self.firmware_repository.resolve_processed(
            firmware_hash=snapshot.firmware.hash,
            plan_fingerprint=snapshot.plan.fingerprint,
        )
        return tuple(record.to_file_artifact() for record in records)

    def clear(self) -> None:
        """Drop no durable data; callers never own repository artifact lifetime."""
