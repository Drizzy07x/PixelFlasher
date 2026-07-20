import tempfile
import unittest
from pathlib import Path

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    AppStateStore,
    CommandExecutor,
    DeviceInfo,
    InteractionDecision,
    ToolchainInfo,
    TransportOutcome,
)
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


def engine(transport: PartitionMutationTransport):
    postconditions = observer(transport, timer=FakeTime(), max_partition_bytes=1024)
    return make_test_command_engine(
        store=AppStateStore(snapshot()),
        executor=CommandExecutor(transport),
        postcondition_observer=postconditions,
        interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
    )


class PartitionEnginePostconditionTests(unittest.TestCase):
    def test_write_requires_independent_hash_readback_after_zero_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "metadata.img"
            image.write_bytes(b"new verified partition")
            verified_transport = PartitionMutationTransport(b"old partition")
            mismatch_transport = PartitionMutationTransport(
                b"same size but wrong data!",
                apply_mutation=False,
            )

            verified = engine(verified_transport).execute(
                AppCommand(
                    "partitions.write",
                    expected_revision=4,
                    target_serial=SERIAL,
                    payload={"partition": "metadata", "path": str(image)},
                )
            )
            mismatch = engine(mismatch_transport).execute(
                AppCommand(
                    "partitions.write",
                    expected_revision=4,
                    target_serial=SERIAL,
                    payload={"partition": "metadata", "path": str(image)},
                )
            )

        self.assertTrue(verified.ok)
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
        self.assertEqual("postcondition_mismatch", mismatch.code)
        self.assertTrue(any(request.argv[3] == "fetch" for request in verified_transport.calls))
        self.assertTrue(any(request.argv[3] == "fetch" for request in mismatch_transport.calls))


if __name__ == "__main__":
    unittest.main()
