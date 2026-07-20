import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    AppStateStore,
    BoundWriteFile,
    CommandExecutor,
    DeviceInfo,
    GrantAccess,
    InteractionDecision,
    PathGrantStore,
    ToolchainInfo,
    TransportOutcome,
)
from pixelflasher_core.grants import AtomicWriteOutcomeUnknownError
from pixelflasher_core.partitions import PartitionService
from tests.command_engine_factory import make_test_command_engine
from tests.test_production_postcondition_observer import (
    FakeTime,
    StatefulDeviceTransport,
    observer,
)

SERIAL = "SERIAL"


class PartitionMutationTransport(StatefulDeviceTransport):
    def __init__(self, content: bytes, *, apply_mutation: bool = True) -> None:
        super().__init__(mode="fastboot", partitions={"metadata": content}, serial=SERIAL)
        self.apply_mutation = apply_mutation

    def _fastboot(self, argv: tuple[str, ...]) -> TransportOutcome:
        if len(argv) == 6 and argv[3] == "flash" and argv[4] == "metadata":
            if self.apply_mutation:
                content = Path(argv[5]).read_bytes()
                self.partitions["metadata"] = content
                self.partition_sizes["metadata"] = len(content)
            return TransportOutcome(0, stdout="Finished. Total time: 0.1s\n")
        if argv[3:] == ("erase", "metadata"):
            if self.apply_mutation:
                size = self.partition_sizes["metadata"]
                self.partitions["metadata"] = b"\x00" * size
            return TransportOutcome(0, stdout="Erasing 'metadata' OKAY\n")
        return super()._fastboot(argv)


def snapshot() -> AppSnapshot:
    return AppSnapshot(
        revision=4,
        devices=(DeviceInfo(SERIAL, codename="akita", mode="fastboot", online=True),),
        selected_serial=SERIAL,
        toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
    )


def engine(
    transport: PartitionMutationTransport,
    *,
    partition_service: PartitionService | None = None,
):
    postconditions = observer(transport, timer=FakeTime(), max_partition_bytes=1024)
    return make_test_command_engine(
        store=AppStateStore(snapshot()),
        executor=CommandExecutor(transport),
        postcondition_observer=postconditions,
        interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
        partition_service=partition_service,
    )


def write_destination(path: Path) -> BoundWriteFile:
    grants = PathGrantStore()
    grant = grants.issue_file(
        path,
        purpose="partitions.read.destination",
        access=GrantAccess.WRITE,
    )
    return grants.resolve_bound_write_file(
        grant.token,
        purpose="partitions.read.destination",
    )


class TamperingPartitionService(PartitionService):
    def validate_read_preflight(self, compilation, outcome, cancellation):
        decision = super().validate_read_preflight(
            compilation,
            outcome,
            cancellation,
        )
        if decision.allowed and compilation.local_payload is not None:
            compilation.local_payload.write_bytes(b"tampered after verification")
        return decision


class PartitionEnginePostconditionTests(unittest.TestCase):
    def test_read_fetches_privately_then_publishes_a_closed_verified_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "metadata.img"
            destination.write_bytes(b"old destination")
            transport = PartitionMutationTransport(b"verified remote partition")

            result = engine(transport).execute(
                AppCommand(
                    "partitions.read",
                    expected_revision=4,
                    target_serial=SERIAL,
                    payload={
                        "partition": "metadata",
                        "destination": write_destination(destination),
                        "overwrite": True,
                    },
                )
            )

            self.assertTrue(result.ok)
            self.assertEqual(b"verified remote partition", destination.read_bytes())
            self.assertEqual(
                {
                    "action",
                    "targetSerial",
                    "partition",
                    "fileName",
                    "sha256",
                    "sizeBytes",
                    "verified",
                },
                set(result.value),
            )
            self.assertEqual("metadata.img", result.value["fileName"])
            self.assertTrue(result.value["verified"])
            fetch = next(request for request in transport.calls if request.argv[3] == "fetch")
            self.assertNotEqual(destination.resolve(), Path(fetch.argv[-1]).resolve())
            self.assertFalse(Path(fetch.argv[-1]).exists())

    def test_read_cancellation_before_publication_preserves_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "metadata.img"
            destination.write_bytes(b"original")
            transport = PartitionMutationTransport(b"remote")
            transport.mode = "timeout"

            result = engine(transport).execute(
                AppCommand(
                    "partitions.read",
                    expected_revision=4,
                    target_serial=SERIAL,
                    payload={
                        "partition": "metadata",
                        "destination": write_destination(destination),
                        "overwrite": True,
                    },
                )
            )

            self.assertEqual("partition_read_preflight_timed_out", result.code)
            self.assertEqual(b"original", destination.read_bytes())

    def test_read_staging_tamper_fails_without_replacing_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "metadata.img"
            destination.write_bytes(b"original")
            transport = PartitionMutationTransport(b"remote")

            result = engine(
                transport,
                partition_service=TamperingPartitionService(),
            ).execute(
                AppCommand(
                    "partitions.read",
                    expected_revision=4,
                    target_serial=SERIAL,
                    payload={
                        "partition": "metadata",
                        "destination": write_destination(destination),
                        "overwrite": True,
                    },
                )
            )

            self.assertEqual("partition_read_staging_changed", result.code)
            self.assertEqual(b"original", destination.read_bytes())

    def test_read_atomic_publication_uncertainty_is_never_reported_as_success(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "metadata.img"
            destination.write_bytes(b"original")
            transport = PartitionMutationTransport(b"remote")

            with patch.object(
                BoundWriteFile,
                "begin_atomic_replace",
                side_effect=AtomicWriteOutcomeUnknownError("publication uncertain"),
            ):
                result = engine(transport).execute(
                    AppCommand(
                        "partitions.read",
                        expected_revision=4,
                        target_serial=SERIAL,
                        payload={
                            "partition": "metadata",
                            "destination": write_destination(destination),
                            "overwrite": True,
                        },
                    )
                )

            self.assertEqual("outcome_unknown", result.code)
            self.assertFalse(result.ok)

    def test_write_requires_independent_hash_readback_after_zero_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "metadata.img"
            image.write_bytes(b"new verified partition")
            verified_transport = PartitionMutationTransport(b"old partition")
            mismatch_transport = PartitionMutationTransport(
                b"same size but wrong data!",
                apply_mutation=False,
            )
            grants = PathGrantStore()
            source_grant = grants.issue_file(
                image,
                purpose="partitions.write.source",
                access=GrantAccess.READ,
            )
            bound_source = grants.resolve_bound_file(
                source_grant.token,
                purpose="partitions.write.source",
            )

            verified = engine(verified_transport).execute(
                AppCommand(
                    "partitions.write",
                    expected_revision=4,
                    target_serial=SERIAL,
                    payload={"partition": "metadata", "path": bound_source},
                )
            )
            mismatch = engine(mismatch_transport).execute(
                AppCommand(
                    "partitions.write",
                    expected_revision=4,
                    target_serial=SERIAL,
                    payload={"partition": "metadata", "path": bound_source},
                )
            )

        self.assertTrue(verified.ok)
        self.assertEqual("partition_write_verified", verified.code)
        self.assertEqual("write", verified.value["action"])
        self.assertTrue(verified.value["verified"])
        self.assertEqual("postcondition_mismatch", mismatch.code)
        self.assertTrue(any(request.argv[3] == "fetch" for request in verified_transport.calls))
        self.assertTrue(any(request.argv[3] == "fetch" for request in mismatch_transport.calls))

    def test_erase_requires_bounded_erased_content_readback(self):
        verified_transport = PartitionMutationTransport(b"private metadata")
        mismatch_transport = PartitionMutationTransport(
            b"private metadata",
            apply_mutation=False,
        )
        verified_engine = engine(verified_transport)
        mismatch_engine = engine(mismatch_transport)

        challenge = verified_engine.execute(
            AppCommand(
                "partitions.erase",
                expected_revision=4,
                target_serial=SERIAL,
                payload={"partition": "metadata"},
            )
        )
        required = challenge.value["confirmation"]["required_text"]
        verified = verified_engine.execute(
            AppCommand(
                "partitions.erase",
                expected_revision=4,
                target_serial=SERIAL,
                payload={"partition": "metadata", "confirmationText": required},
            )
        )
        mismatch_challenge = mismatch_engine.execute(
            AppCommand(
                "partitions.erase",
                expected_revision=4,
                target_serial=SERIAL,
                payload={"partition": "metadata"},
            )
        )
        mismatch = mismatch_engine.execute(
            AppCommand(
                "partitions.erase",
                expected_revision=4,
                target_serial=SERIAL,
                payload={
                    "partition": "metadata",
                    "confirmationText": mismatch_challenge.value["confirmation"]["required_text"],
                },
            )
        )

        self.assertEqual("ERASE metadata SERIAL", required)
        self.assertTrue(verified.ok)
        self.assertEqual("partition_erase_verified", verified.code)
        self.assertEqual(
            {
                "action": "erase",
                "targetSerial": SERIAL,
                "partition": "metadata",
                "erased": True,
                "verified": True,
            },
            verified.value,
        )
        self.assertEqual("postcondition_mismatch", mismatch.code)
        self.assertTrue(any(request.argv[3] == "fetch" for request in verified_transport.calls))
        self.assertTrue(any(request.argv[3] == "fetch" for request in mismatch_transport.calls))


if __name__ == "__main__":
    unittest.main()
