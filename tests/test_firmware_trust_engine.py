from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from pixelflasher_core import AppCommand, AppStateStore, InteractionKind, OperationStatus
from pixelflasher_core.repositories import ArtifactRepository, FirmwareRepository
from tests.command_engine_factory import make_test_command_engine
from tests.test_firmware_engine_integration import write_factory


def test_user_firmware_is_not_promoted_without_explicit_confirmation() -> None:
    with tempfile.TemporaryDirectory() as directory:
        package = Path(directory) / "factory.zip"
        write_factory(package)
        engine = make_test_command_engine()

        result = engine.execute(
            AppCommand(
                "firmware.select",
                expected_revision=0,
                payload={"path": str(package)},
            )
        )

        assert result.status is OperationStatus.CANCELLED
        assert result.code == "firmware_trust_not_confirmed"
        assert engine.store.snapshot().revision == 0
        assert not engine.store.snapshot().firmware.path


def test_confirmation_is_reinforced_and_bound_to_the_exact_archive_hash() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        package = root / "factory.zip"
        write_factory(package)
        digest = hashlib.sha256(package.read_bytes()).hexdigest()
        repository = ArtifactRepository(root / "repository")
        firmware_repository = FirmwareRepository(repository)
        requests = []
        engine = make_test_command_engine(
            interaction_handler=lambda request: requests.append(request) or True,
            firmware_repository=firmware_repository,
        )
        try:
            result = engine.execute(
                AppCommand(
                    "firmware.select",
                    expected_revision=0,
                    payload={"path": str(package)},
                )
            )

            assert result.ok
            assert len(requests) == 1
            request = requests[0]
            assert request.kind is InteractionKind.CONFIRM
            assert request.reinforced
            assert request.confirmation_nonce == f"TRUST FIRMWARE {digest[:8].upper()}"
            assert str(package) not in request.message
            inspection = result.value["inspection"]
            assert inspection["trust"]["status"] == "user_confirmed"
            assert inspection["trust"]["sourceAuthentication"] == "user_confirmation"
            record = firmware_repository.resolve_selection(sha256=digest)
            assert record is not None
            assert record.metadata["packageSignature"] == "user_confirmed"
        finally:
            repository.close()


def test_revision_change_while_confirming_prevents_import_and_promotion() -> None:
    with tempfile.TemporaryDirectory() as directory:
        package = Path(directory) / "factory.zip"
        write_factory(package)
        store = AppStateStore()

        def change_revision(_request: object) -> bool:
            store.update(expected_revision=0, selected_serials=())
            return True

        engine = make_test_command_engine(
            store=store,
            interaction_handler=change_revision,
        )
        result = engine.execute(
            AppCommand(
                "firmware.select",
                expected_revision=0,
                payload={"path": str(package)},
            )
        )

        assert result.status is OperationStatus.FAILED
        assert result.code == "stale_revision"
        assert store.snapshot().revision == 1
        assert not store.snapshot().firmware.path
