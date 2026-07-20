import hashlib
import io
import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    CancellationToken,
    CommandExecutor,
    DataAdbError,
    DataAdbService,
    DeviceInfo,
    GrantAccess,
    InteractionDecision,
    PathGrantStore,
    ProcessRequest,
    ToolchainInfo,
    TransportOutcome,
)
from pixelflasher_core.store import AppStateStore
from tests.command_engine_factory import make_test_command_engine


def _tar_payload(
    *,
    unsafe_name: str | None = None,
    link: bool = False,
    entry_type: bytes | None = None,
    duplicate_name: str | None = None,
    sparse: bool = False,
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        directory = tarfile.TarInfo("modules/")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o700
        directory.uid = 0
        directory.gid = 0
        archive.addfile(directory)

        data = b"module-id\n"
        item = tarfile.TarInfo(unsafe_name or "modules/example/module.prop")
        item.mode = 0o600
        item.uid = 0
        item.gid = 0
        if link:
            item.type = tarfile.SYMTYPE
            item.linkname = "/data/local/tmp/escape"
            item.size = 0
            archive.addfile(item)
        elif entry_type is not None:
            item.type = entry_type
            item.linkname = "modules/example/module.prop"
            if sparse:
                item.size = len(data)
                item.sparse = [(0, len(data))]
                archive.addfile(item, io.BytesIO(data))
            else:
                item.size = 0
                archive.addfile(item)
        else:
            item.size = len(data)
            archive.addfile(item, io.BytesIO(data))
        if duplicate_name is not None:
            duplicate = tarfile.TarInfo(duplicate_name)
            duplicate.mode = 0o600
            duplicate.uid = 0
            duplicate.gid = 0
            duplicate.size = len(data)
            archive.addfile(duplicate, io.BytesIO(data))
    return output.getvalue()


class _BackupTransport:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.calls: list[ProcessRequest] = []

    def run(
        self,
        request: ProcessRequest,
        cancellation: CancellationToken,
    ) -> TransportOutcome:
        self.calls.append(request)
        if cancellation.cancelled:
            return TransportOutcome(None, cancelled=True)
        if "pull" in request.argv:
            Path(request.argv[-1]).write_bytes(self.payload)
            return TransportOutcome(0)
        if "PF_DAB|%s|%s" in request.argv[-1]:
            digest = hashlib.sha256(self.payload).hexdigest()
            return TransportOutcome(0, f"PF_DAB|{digest}|{len(self.payload)}\n")
        return TransportOutcome(0)


class _RestoreTransport:
    def __init__(self, fingerprint: str, entry_count: int) -> None:
        self.fingerprint = fingerprint
        self.entry_count = entry_count
        self.calls: list[ProcessRequest] = []

    def run(
        self,
        request: ProcessRequest,
        cancellation: CancellationToken,
    ) -> TransportOutcome:
        self.calls.append(request)
        if cancellation.cancelled:
            return TransportOutcome(None, cancelled=True)
        if "PF_DAB_RESTORED" in request.argv[-1]:
            return TransportOutcome(
                0,
                f"PF_DAB_RESTORED|{self.fingerprint}|{self.entry_count}\n",
            )
        return TransportOutcome(0)


class _RestoreFailureTransport:
    def __init__(self, failure: str) -> None:
        self.failure = failure
        self.calls: list[ProcessRequest] = []

    def run(
        self,
        request: ProcessRequest,
        cancellation: CancellationToken,
    ) -> TransportOutcome:
        self.calls.append(request)
        if "PF_DAB_RESTORED" not in request.argv[-1]:
            return TransportOutcome(0)
        if self.failure == "cancelled":
            cancellation.cancel()
            return TransportOutcome(None, cancelled=True)
        if self.failure == "disconnected":
            return TransportOutcome(1, stderr="error: device disconnected")
        if self.failure == "pre_mutation":
            return TransportOutcome(114, stderr="staging extraction failed")
        if self.failure == "post_mutation":
            return TransportOutcome(115, stderr="target cleanup failed")
        raise AssertionError(f"unknown restore failure: {self.failure}")


class DataAdbServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.snapshot = AppSnapshot(
            revision=7,
            devices=(
                DeviceInfo(
                    "SERIAL123456",
                    codename="komodo",
                    mode="adb",
                    online=True,
                    root=True,
                    build="BP2A.260701.001",
                ),
            ),
            selected_serial="SERIAL123456",
            toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
        )

    def _command(self, kind: str, payload: dict[str, object]) -> AppCommand:
        return AppCommand(
            kind,
            expected_revision=self.snapshot.revision,
            target_serial="SERIAL123456",
            payload={"serial": "SERIAL123456"} | payload,
        )

    def _create_backup(self, directory: str, payload: bytes | None = None):
        tar_payload = payload or _tar_payload()
        destination = Path(directory) / "root-state.pfdataadb"
        grants = PathGrantStore()
        issued = grants.issue_file(
            destination,
            purpose="root.dataAdb.backup.destination",
            access=GrantAccess.WRITE,
        )
        bound = grants.resolve_bound_write_file(
            issued.token,
            purpose="root.dataAdb.backup.destination",
        )
        service = DataAdbService(directory)
        command = self._command("root.dataAdb.backup", {"destination": bound})
        compilation = service.compile(command, self.snapshot)
        transport = _BackupTransport(tar_payload)
        result = service.execute(
            compilation,
            command,
            CommandExecutor(transport),
            CancellationToken(),
        )
        return service, destination, result, transport

    def test_backup_verifies_tar_and_publishes_closed_container(self):
        with tempfile.TemporaryDirectory() as directory:
            _service, destination, result, transport = self._create_backup(directory)

            self.assertTrue(result.ok, result)
            self.assertEqual("data_adb_backup_created", result.code)
            self.assertEqual("komodo", result.value["deviceCodename"])
            self.assertTrue(result.value["remoteCleaned"])
            with zipfile.ZipFile(destination) as archive:
                self.assertEqual({"manifest.json", "payload.tar"}, set(archive.namelist()))
                manifest = json.loads(archive.read("manifest.json"))
            self.assertEqual("BP2A.260701.001", manifest["sourceBuild"])
            self.assertEqual(2, manifest["entryCount"])
            self.assertIn("rm", transport.calls[-1].argv)

    def test_backup_runs_through_engine_safety_and_execution_postcondition(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "engine-data-adb.pfdataadb"
            grants = PathGrantStore()
            issued = grants.issue_file(
                destination,
                purpose="root.dataAdb.backup.destination",
                access=GrantAccess.WRITE,
            )
            bound = grants.resolve_bound_write_file(
                issued.token,
                purpose="root.dataAdb.backup.destination",
            )
            service = DataAdbService(directory)
            transport = _BackupTransport(_tar_payload())
            engine = make_test_command_engine(
                store=AppStateStore(self.snapshot),
                executor=CommandExecutor(transport),
                data_adb_service=service,
                interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
            )

            result = engine.execute(
                self._command("root.dataAdb.backup", {"destination": bound})
            )

            self.assertTrue(result.ok, result)
            self.assertEqual("data_adb_backup_created", result.code)
            self.assertTrue(destination.is_file())
            self.assertEqual("backup", result.value["action"])

    def test_restore_revalidates_container_and_returns_closed_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            service, destination, backup, _transport = self._create_backup(directory)
            self.assertTrue(backup.ok, backup)
            grants = PathGrantStore()
            issued = grants.issue_file(
                destination,
                purpose="root.dataAdb.restore.source",
                access=GrantAccess.READ,
            )
            source = grants.resolve_bound_file(
                issued.token,
                purpose="root.dataAdb.restore.source",
            )
            command = self._command(
                "root.dataAdb.restore",
                {
                    "source": source,
                    "confirmationText": "RESTORE DATAADB 123456",
                },
            )
            compilation = service.compile(command, self.snapshot)
            self.assertIsNotNone(compilation.manifest)
            assert compilation.manifest is not None
            transport = _RestoreTransport(
                compilation.manifest.content_fingerprint,
                len(compilation.manifest.entries),
            )

            result = service.execute(
                compilation,
                command,
                CommandExecutor(transport),
                CancellationToken(),
            )

            self.assertTrue(result.ok, result)
            self.assertEqual("data_adb_restore_completed", result.code)
            self.assertEqual(2, result.value["entryCount"])
            self.assertTrue(result.value["verified"])
            self.assertTrue(result.value["remoteCleaned"])
            self.assertFalse(compilation.local_payload.exists())
            assert compilation.local_verification is not None
            self.assertFalse(compilation.local_verification.exists())

    def test_restore_rejects_incompatible_device_codename(self):
        with tempfile.TemporaryDirectory() as directory:
            service, destination, backup, _transport = self._create_backup(directory)
            self.assertTrue(backup.ok, backup)
            grants = PathGrantStore()
            issued = grants.issue_file(
                destination,
                purpose="root.dataAdb.restore.source",
                access=GrantAccess.READ,
            )
            source = grants.resolve_bound_file(
                issued.token,
                purpose="root.dataAdb.restore.source",
            )
            incompatible = AppSnapshot(
                revision=7,
                devices=(
                    DeviceInfo(
                        "SERIAL123456",
                        codename="akita",
                        mode="adb",
                        online=True,
                        root=True,
                        build="BP2A.260701.001",
                    ),
                ),
                selected_serial="SERIAL123456",
                toolchain=self.snapshot.toolchain,
            )
            with self.assertRaises(DataAdbError) as rejected:
                service.compile(
                    self._command(
                        "root.dataAdb.restore",
                        {
                            "source": source,
                            "confirmationText": "RESTORE DATAADB 123456",
                        },
                    ),
                    incompatible,
                )
            self.assertEqual("data_adb_device_incompatible", rejected.exception.code)

    def test_backup_rejects_traversal_and_links_without_publication(self):
        for payload in (
            _tar_payload(unsafe_name="../escape"),
            _tar_payload(link=True),
        ):
            with self.subTest(payload=hashlib.sha256(payload).hexdigest()):
                with tempfile.TemporaryDirectory() as directory:
                    _service, destination, result, _transport = self._create_backup(
                        directory,
                        payload,
                    )
                    self.assertFalse(result.ok)
                    self.assertFalse(destination.exists())
                    self.assertIn(
                        result.code,
                        {"data_adb_tar_path_unsafe", "data_adb_tar_type_unsafe"},
                    )

    def test_backup_rejects_every_unsafe_tar_shape_without_publication(self):
        hostile = (
            ("absolute", _tar_payload(unsafe_name="/data/adb/escape"), "data_adb_tar_path_unsafe"),
            ("backslash", _tar_payload(unsafe_name="modules\\escape"), "data_adb_tar_path_unsafe"),
            ("hardlink", _tar_payload(entry_type=tarfile.LNKTYPE), "data_adb_tar_type_unsafe"),
            ("fifo", _tar_payload(entry_type=tarfile.FIFOTYPE), "data_adb_tar_type_unsafe"),
            (
                "sparse",
                _tar_payload(entry_type=tarfile.GNUTYPE_SPARSE, sparse=True),
                "data_adb_tar_sparse_unsupported",
            ),
            (
                "duplicate",
                _tar_payload(duplicate_name="modules/example/module.prop"),
                "data_adb_tar_ambiguous",
            ),
            (
                "casefold_duplicate",
                _tar_payload(duplicate_name="MODULES/EXAMPLE/MODULE.PROP"),
                "data_adb_tar_ambiguous",
            ),
            (
                "long_path",
                _tar_payload(unsafe_name="a" * 513),
                "data_adb_tar_path_unsafe",
            ),
        )
        for label, payload, expected in hostile:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as directory:
                    _service, destination, result, _transport = self._create_backup(
                        directory,
                        payload,
                    )
                    self.assertFalse(result.ok)
                    self.assertEqual(expected, result.code)
                    self.assertFalse(destination.exists())

    def test_backup_rejects_per_member_and_aggregate_size_overflow(self):
        payload = _tar_payload()
        for limit, expected in (
            ("_MAX_MEMBER_BYTES", "data_adb_tar_member_oversized"),
            ("_MAX_PAYLOAD_BYTES", "data_adb_tar_oversized"),
        ):
            with self.subTest(limit=limit):
                with tempfile.TemporaryDirectory() as directory:
                    service = DataAdbService(directory)
                    staged = Path(directory) / "hostile.tar"
                    staged.write_bytes(payload)
                    with patch(f"pixelflasher_core.data_adb.{limit}", 4):
                        with self.assertRaises(DataAdbError) as rejected:
                            service._inspect_tar(staged, None)
                    self.assertEqual(expected, rejected.exception.code)

    def test_restore_distinguishes_pre_mutation_failure_from_unknown_outcome(self):
        cases = (
            ("pre_mutation", "process_failed"),
            ("post_mutation", "outcome_unknown"),
            ("disconnected", "outcome_unknown"),
            ("cancelled", "outcome_unknown"),
        )
        for failure, expected in cases:
            with self.subTest(failure=failure):
                with tempfile.TemporaryDirectory() as directory:
                    service, destination, backup, _transport = self._create_backup(directory)
                    self.assertTrue(backup.ok, backup)
                    grants = PathGrantStore()
                    issued = grants.issue_file(
                        destination,
                        purpose="root.dataAdb.restore.source",
                        access=GrantAccess.READ,
                    )
                    source = grants.resolve_bound_file(
                        issued.token,
                        purpose="root.dataAdb.restore.source",
                    )
                    command = self._command(
                        "root.dataAdb.restore",
                        {
                            "source": source,
                            "confirmationText": "RESTORE DATAADB 123456",
                        },
                    )
                    transport = _RestoreFailureTransport(failure)
                    engine = make_test_command_engine(
                        store=AppStateStore(self.snapshot),
                        executor=CommandExecutor(transport),
                        data_adb_service=service,
                        interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
                        postcondition_observer=lambda _plan, _condition, _snapshot: True,
                    )

                    result = engine.execute(command)

                    self.assertFalse(result.ok)
                    self.assertEqual(expected, result.code)
                    self.assertEqual(4, len(transport.calls))

    def test_restore_rejects_extra_zip_member_and_payload_hash_mismatch(self):
        for mutation in ("extra", "payload"):
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as directory:
                    service, destination, backup, _transport = self._create_backup(directory)
                    self.assertTrue(backup.ok, backup)
                    with zipfile.ZipFile(destination) as source:
                        manifest = source.read("manifest.json")
                        payload = source.read("payload.tar")
                    replacement = Path(directory) / "mutated.pfdataadb"
                    with zipfile.ZipFile(replacement, "w") as archive:
                        archive.writestr("manifest.json", manifest)
                        archive.writestr(
                            "payload.tar",
                            payload + (b"tampered" if mutation == "payload" else b""),
                        )
                        if mutation == "extra":
                            archive.writestr("extra.txt", b"forbidden")
                    grants = PathGrantStore()
                    issued = grants.issue_file(
                        replacement,
                        purpose="root.dataAdb.restore.source",
                        access=GrantAccess.READ,
                    )
                    source = grants.resolve_bound_file(
                        issued.token,
                        purpose="root.dataAdb.restore.source",
                    )
                    with self.assertRaises(DataAdbError) as rejected:
                        service.compile(
                            self._command(
                                "root.dataAdb.restore",
                                {
                                    "source": source,
                                    "confirmationText": "RESTORE DATAADB 123456",
                                },
                            ),
                            self.snapshot,
                        )
                    self.assertIn(
                        rejected.exception.code,
                        {
                            "data_adb_container_members_invalid",
                            "data_adb_payload_hash_mismatch",
                        },
                    )

    def test_clear_requires_exact_confirmation_and_exact_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            service = DataAdbService(directory)
            with self.assertRaises(DataAdbError) as rejected:
                service.compile(
                    self._command(
                        "root.dataAdb.clear",
                        {"confirmationText": "CLEAR DATAADB WRONG"},
                    ),
                    self.snapshot,
                )
            self.assertEqual("data_adb_clear_confirmation_required", rejected.exception.code)

            command = self._command(
                "root.dataAdb.clear",
                {"confirmationText": "CLEAR DATAADB 123456"},
            )
            compilation = service.compile(command, self.snapshot)

            class ClearTransport:
                def run(
                    self,
                    request: ProcessRequest,
                    cancellation: CancellationToken,
                ) -> TransportOutcome:
                    _ = request, cancellation
                    return TransportOutcome(0, "PF_DAB_CLEARED|0\n")

            result = service.execute(
                compilation,
                command,
                CommandExecutor(ClearTransport()),
                CancellationToken(),
            )
            self.assertTrue(result.ok, result)
            self.assertEqual(
                {
                    "action": "clear",
                    "targetSerial": "SERIAL123456",
                    "empty": True,
                    "verified": True,
                },
                result.value,
            )

    def test_clear_failure_or_cancellation_is_always_outcome_unknown(self):
        for failure in ("failed", "cancelled"):
            with self.subTest(failure=failure):
                with tempfile.TemporaryDirectory() as directory:
                    service = DataAdbService(directory)

                    class ClearFailureTransport:
                        def __init__(transport_self, selected_failure: str) -> None:
                            transport_self.failure = selected_failure
                            transport_self.calls = 0

                        def run(
                            transport_self,
                            request: ProcessRequest,
                            cancellation: CancellationToken,
                        ) -> TransportOutcome:
                            _ = request
                            transport_self.calls += 1
                            if transport_self.failure == "cancelled":
                                cancellation.cancel()
                                return TransportOutcome(None, cancelled=True)
                            return TransportOutcome(91, stderr="clear failed")

                    transport = ClearFailureTransport(failure)
                    engine = make_test_command_engine(
                        store=AppStateStore(self.snapshot),
                        executor=CommandExecutor(transport),
                        data_adb_service=service,
                        interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
                        postcondition_observer=lambda _plan, _condition, _snapshot: True,
                    )
                    command = self._command(
                        "root.dataAdb.clear",
                        {"confirmationText": "CLEAR DATAADB 123456"},
                    )

                    result = engine.execute(command)

                    self.assertFalse(result.ok)
                    self.assertEqual("outcome_unknown", result.code)
                    self.assertEqual(1, transport.calls)


if __name__ == "__main__":
    unittest.main()
