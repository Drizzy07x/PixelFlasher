import hashlib
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    AppStateStore,
    BootInfo,
    CommandExecutor,
    DeviceInfo,
    FakeProcessTransport,
    FakeTransportStep,
    FileArtifact,
    FirmwareInfo,
    FlashPlan,
    InteractionDecision,
    OperationPlanner,
    OperationRunner,
    OperationStatus,
    ProcessedArtifactRepository,
    SafetyPolicy,
    ToolchainInfo,
    TransportOutcome,
)
from tests.artifact_stage_assertions import assert_exact_or_staged_argv
from tests.command_engine_factory import make_test_command_engine as CommandEngine
from tests.stateful_postcondition_observer import StatefulPostconditionObserver
from tests.stateful_slot_transport import StatefulSlotTransport, make_slot_observer


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def snapshot_for(
    mode,
    *,
    serial="SERIAL-A",
    root=False,
    plan=None,
    firmware=None,
    boot=None,
):
    return AppSnapshot(
        devices=(
            DeviceInfo(
                serial,
                codename="akita",
                mode=mode,
                root=root,
                online=True,
                bootloader="unlocked",
            ),
        ),
        selected_serial=serial,
        firmware=firmware or FirmwareInfo(),
        boot=boot or BootInfo(),
        plan=plan or FlashPlan(),
        toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
    )


def command(kind, *, payload=None, serial="SERIAL-A", revision=0, operation_id=None):
    values = {
        "kind": kind,
        "expected_revision": revision,
        "target_serial": serial,
        "payload": payload or {},
    }
    if operation_id is not None:
        values["operation_id"] = operation_id
    return AppCommand(**values)


class DevicePlannerGoldenTests(unittest.TestCase):
    def test_reboot_chooses_adb_or_fastboot_and_binds_serial(self):
        cases = (
            (
                "adb",
                {"mode": "recovery"},
                ("ADB", "-s", "SERIAL-A", "reboot", "recovery"),
            ),
            (
                "fastboot",
                {"mode": "system"},
                ("FASTBOOT", "-s", "SERIAL-A", "reboot"),
            ),
        )
        for device_mode, payload, expected in cases:
            with self.subTest(device_mode=device_mode):
                transport = FakeProcessTransport([TransportOutcome(0)])
                engine = CommandEngine(
                    store=AppStateStore(snapshot_for(device_mode)),
                    executor=CommandExecutor(transport),
                    postcondition_observer=StatefulPostconditionObserver(transport),
                )

                result = engine.execute(command("device.reboot", payload=payload))

                self.assertEqual(OperationStatus.SUCCESS, result.status)
                self.assertEqual([expected], [request.argv for request in transport.calls])

    def test_offline_device_and_ui_supplied_argv_fail_without_execution(self):
        offline = AppSnapshot(
            devices=(DeviceInfo("SERIAL-A", mode="offline", online=False),),
            selected_serial="SERIAL-A",
            toolchain=ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
        )
        transport = FakeProcessTransport([])
        engine = CommandEngine(
            store=AppStateStore(offline),
            executor=CommandExecutor(transport),
        )

        disconnected = engine.execute(command("device.reboot"))
        injected = CommandEngine(
            store=AppStateStore(snapshot_for("adb")),
            executor=CommandExecutor(transport),
        ).execute(command("device.reboot", payload={"argv": ["cmd", "/c", "evil"]}))

        self.assertEqual("device_disconnected", disconnected.code)
        self.assertEqual("invalid_plan_payload", injected.code)
        self.assertEqual([], transport.calls)

    def test_fastbootd_can_reboot_but_cannot_run_bootloader_only_commands(self):
        reboot_transport = FakeProcessTransport([TransportOutcome(0)])
        reboot = CommandEngine(
            store=AppStateStore(snapshot_for("fastbootd")),
            executor=CommandExecutor(reboot_transport),
            postcondition_observer=StatefulPostconditionObserver(reboot_transport),
        ).execute(command("device.reboot", payload={"mode": "system"}))
        blocked_transport = FakeProcessTransport([])
        blocked = CommandEngine(
            store=AppStateStore(snapshot_for("fastbootd")),
            executor=CommandExecutor(blocked_transport),
        ).execute(command("device.switchSlot", payload={"slot": "b"}))

        self.assertEqual(OperationStatus.SUCCESS, reboot.status)
        self.assertEqual(
            [("FASTBOOT", "-s", "SERIAL-A", "reboot")],
            [request.argv for request in reboot_transport.calls],
        )
        self.assertEqual("fastboot_required", blocked.code)
        self.assertEqual([], blocked_transport.calls)

    def test_sideload_reboot_is_exact_adb_only_and_requires_observed_mode(self):
        for source_mode in ("adb", "recovery"):
            with self.subTest(source_mode=source_mode):
                transport = FakeProcessTransport([TransportOutcome(0)])
                result = CommandEngine(
                    store=AppStateStore(snapshot_for(source_mode)),
                    executor=CommandExecutor(transport),
                    postcondition_observer=StatefulPostconditionObserver(transport),
                ).execute(command("device.reboot", payload={"mode": "sideload"}))

                self.assertEqual(OperationStatus.SUCCESS, result.status)
                self.assertEqual(
                    [("ADB", "-s", "SERIAL-A", "reboot", "sideload")],
                    [request.argv for request in transport.calls],
                )

        for source_mode in ("sideload", "fastboot", "fastbootd"):
            with self.subTest(rejected_source_mode=source_mode):
                transport = FakeProcessTransport([])
                result = CommandEngine(
                    store=AppStateStore(snapshot_for(source_mode)),
                    executor=CommandExecutor(transport),
                ).execute(command("device.reboot", payload={"mode": "sideload"}))

                self.assertEqual("sideload_reboot_adb_required", result.code)
                self.assertEqual([], transport.calls)

    def test_safe_mode_plan_is_rooted_adb_only_and_uses_fixed_argv(self):
        planner = OperationPlanner(confirmation_secret=b"s" * 32)
        rooted_adb = snapshot_for("adb", root=True)

        compilation = planner.compile(
            command("device.reboot", payload={"mode": "safeMode"}),
            rooted_adb,
        )

        self.assertTrue(compilation.ok)
        self.assertIsNotNone(compilation.plan)
        if compilation.plan is None:
            self.fail("safe mode compilation omitted its plan")
        self.assertEqual(
            [
                (
                    "ADB",
                    "-s",
                    "SERIAL-A",
                    "shell",
                    "su",
                    "-c",
                    "setprop persist.sys.safemode 1",
                ),
                ("ADB", "-s", "SERIAL-A", "reboot"),
            ],
            [request.argv for request in compilation.plan.requests],
        )
        self.assertTrue(
            all(
                request.cwd is None and request.env is None
                for request in compilation.plan.requests
            )
        )
        self.assertEqual(
            ["device_reachable", "safe_mode_active"],
            [item.kind for item in compilation.plan.postconditions],
        )
        self.assertEqual(
            {"mode": "system", "bootCompleted": True},
            dict(compilation.plan.postconditions[0].expected),
        )
        self.assertEqual(
            {"active": True},
            dict(compilation.plan.postconditions[1].expected),
        )

        unrooted = planner.compile(
            command("device.reboot", payload={"mode": "safeMode"}),
            snapshot_for("adb"),
        )
        wrong_transport = planner.compile(
            command("device.reboot", payload={"mode": "safeMode"}),
            snapshot_for("recovery", root=True),
        )
        self.assertEqual("safe_mode_root_required", unrooted.code)
        self.assertEqual("safe_mode_adb_required", wrong_transport.code)

    def test_download_reboot_is_explicitly_unverifiable_and_never_executes(self):
        for source_mode in ("adb", "fastboot", "fastbootd", "recovery"):
            with self.subTest(source_mode=source_mode):
                transport = FakeProcessTransport([])
                result = CommandEngine(
                    store=AppStateStore(snapshot_for(source_mode)),
                    executor=CommandExecutor(transport),
                ).execute(command("device.reboot", payload={"mode": "download"}))

                self.assertEqual("reboot_download_unverifiable", result.code)
                self.assertEqual([], transport.calls)

    def test_slot_switch_requires_backend_challenge_and_exact_text(self):
        snapshot = snapshot_for("fastboot")
        transport = StatefulSlotTransport(
            "SERIAL-A",
            active_slot="a",
            reconnect_cycles=1,
        )
        executor = CommandExecutor(transport)
        postcondition_observer = make_slot_observer(transport)
        safety_policy = SafetyPolicy()
        store = AppStateStore(snapshot)

        def snapshot_provider(_serial):
            return store.snapshot()

        interactions = []
        engine = CommandEngine(
            store=store,
            executor=executor,
            safety_policy=safety_policy,
            operation_runner=OperationRunner(
                executor,
                safety_policy=safety_policy,
                snapshot_provider=snapshot_provider,
                postcondition_observer=postcondition_observer,
                postcondition_timeout_seconds=0.2,
            ),
            snapshot_provider=snapshot_provider,
            postcondition_observer=postcondition_observer,
            interaction_handler=lambda request: interactions.append(request) or InteractionDecision.ACCEPTED,
        )

        preview = engine.execute(command("device.switchSlot", payload={"slot": "b"}))
        required = preview.value["confirmation"]["required_text"]
        wrong = engine.execute(
            command("device.switchSlot", payload={"slot": "b", "confirmationText": "SWITCH"})
        )
        executed = engine.execute(
            command("device.switchSlot", payload={"slot": "b", "confirmationText": required})
        )

        self.assertEqual("confirmation_text_required", preview.code)
        self.assertEqual("SLOT b RIAL-A", required)
        self.assertEqual("confirmation_text_mismatch", wrong.code)
        self.assertEqual(OperationStatus.SUCCESS, executed.status)
        self.assertEqual("postconditions_satisfied", executed.code)
        mutation = ("FASTBOOT", "-s", "SERIAL-A", "--set-active=b")
        mode_probe = ("FASTBOOT", "-s", "SERIAL-A", "getvar", "is-userspace")
        observation = ("FASTBOOT", "-s", "SERIAL-A", "getvar", "current-slot")
        self.assertEqual(
            [mutation],
            [request.argv for request in transport.calls if request.argv == mutation],
        )
        argv = [request.argv for request in transport.calls]
        self.assertIn(observation, argv)
        self.assertGreaterEqual(argv.count(mode_probe), 2)
        self.assertLess(argv.index(mutation), argv.index(observation))
        self.assertEqual("b", transport.active_slot)
        self.assertTrue(interactions[0].reinforced)

    def test_bootloader_unlock_is_backend_compiled_and_lock_fails_without_stock_evidence(self):
        lock_transport = FakeProcessTransport([])
        lock = CommandEngine(
            store=AppStateStore(snapshot_for("fastboot")),
            executor=CommandExecutor(lock_transport),
        ).execute(command("device.bootloader.lock"))

        self.assertEqual("bootloader_lock_stock_evidence_required", lock.code)
        self.assertEqual([], lock_transport.calls)

        unlock_transport = FakeProcessTransport([TransportOutcome(0)])
        engine = CommandEngine(
            store=AppStateStore(snapshot_for("fastboot")),
            executor=CommandExecutor(unlock_transport),
            postcondition_observer=StatefulPostconditionObserver(unlock_transport),
            interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
        )
        kind = "device.bootloader.unlock"
        challenge = engine.execute(command(kind))
        required = challenge.value["confirmation"]["required_text"]
        result = engine.execute(command(kind, payload={"confirmationText": required}))

        self.assertEqual(OperationStatus.SUCCESS, result.status)
        self.assertEqual(
            [("FASTBOOT", "-s", "SERIAL-A", "flashing", "unlock")],
            [request.argv for request in unlock_transport.calls],
        )


class BootPlannerGoldenTests(unittest.TestCase):
    def test_boot_flash_and_live_use_only_canonical_boot_artifact(self):
        with TemporaryDirectory() as directory:
            boot_path = Path(directory) / "boot.img"
            boot_path.write_bytes(b"verified boot")
            cases = (
                (
                    "boot.flash",
                    "init_boot",
                    {"slot": "a"},
                    ("FASTBOOT", "-s", "SERIAL-A", "--slot=a", "flash", "init_boot", str(boot_path.resolve())),
                ),
                (
                    "boot.live",
                    "boot",
                    {},
                    ("FASTBOOT", "-s", "SERIAL-A", "boot", str(boot_path.resolve())),
                ),
            )
            for kind, flavor, payload, expected in cases:
                with self.subTest(kind=kind):
                    boot = BootInfo("boot-id", str(boot_path), digest(boot_path), flavor, True)
                    transport = FakeProcessTransport([TransportOutcome(0)])
                    engine = CommandEngine(
                        store=AppStateStore(snapshot_for("fastboot", boot=boot)),
                        executor=CommandExecutor(transport),
                        postcondition_observer=StatefulPostconditionObserver(transport),
                        interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
                    )

                    result = engine.execute(command(kind, payload=payload))

                    self.assertEqual(OperationStatus.SUCCESS, result.status)
                    assert_exact_or_staged_argv(self, [expected], transport.calls)

    def test_boot_operations_require_unlocked_matching_boot_artifacts(self):
        with TemporaryDirectory() as directory:
            boot_path = Path(directory) / "boot.img"
            boot_path.write_bytes(b"verified boot")
            digest_value = digest(boot_path)
            init_boot = BootInfo("init-boot-id", str(boot_path), digest_value, "init_boot", True)

            mismatch = CommandEngine(
                store=AppStateStore(snapshot_for("fastboot", boot=init_boot)),
                executor=CommandExecutor(FakeProcessTransport([])),
            ).execute(command("boot.flash", payload={"partition": "vendor_boot"}))
            live_init_boot = CommandEngine(
                store=AppStateStore(snapshot_for("fastboot", boot=init_boot)),
                executor=CommandExecutor(FakeProcessTransport([])),
            ).execute(command("boot.live"))

            locked_snapshot = replace(
                snapshot_for(
                    "fastboot",
                    boot=BootInfo("boot-id", str(boot_path), digest_value, "boot", True),
                ),
                devices=(
                    DeviceInfo(
                        "SERIAL-A",
                        codename="akita",
                        mode="fastboot",
                        online=True,
                        bootloader="locked",
                    ),
                ),
            )
            locked = CommandEngine(
                store=AppStateStore(locked_snapshot),
                executor=CommandExecutor(FakeProcessTransport([])),
            ).execute(command("boot.live"))

            self.assertEqual("boot_partition_mismatch", mismatch.code)
            self.assertEqual("live_boot_partition_unsupported", live_init_boot.code)
            self.assertEqual("bootloader_unlocked_required", locked.code)

    def test_artifact_hash_is_revalidated_after_confirmation(self):
        with TemporaryDirectory() as directory:
            boot_path = Path(directory) / "boot.img"
            boot_path.write_bytes(b"original")
            boot = BootInfo("boot-id", str(boot_path), digest(boot_path), "boot", False)
            transport = FakeProcessTransport([TransportOutcome(0)])

            def mutate(_request):
                boot_path.write_bytes(b"changed after prompt")
                return InteractionDecision.ACCEPTED

            engine = CommandEngine(
                store=AppStateStore(snapshot_for("fastboot", boot=boot)),
                executor=CommandExecutor(transport),
                interaction_handler=mutate,
            )

            result = engine.execute(command("boot.flash"))

            self.assertEqual("artifact_hash_mismatch", result.code)
            self.assertEqual([], transport.calls)

    def test_partition_and_hash_validation_fail_closed(self):
        with TemporaryDirectory() as directory:
            boot_path = Path(directory) / "boot.img"
            boot_path.write_bytes(b"boot")
            bad_hash_boot = BootInfo("id", str(boot_path), "0" * 64, "boot", False)
            transport = FakeProcessTransport([])
            engine = CommandEngine(
                store=AppStateStore(snapshot_for("fastboot", boot=bad_hash_boot)),
                executor=CommandExecutor(transport),
            )

            bad_hash = engine.execute(command("boot.flash"))
            bad_partition = CommandEngine(
                store=AppStateStore(
                    snapshot_for(
                        "fastboot",
                        boot=BootInfo("id", str(boot_path), digest(boot_path), "boot", False),
                    )
                ),
                executor=CommandExecutor(transport),
            ).execute(command("boot.flash", payload={"partition": "boot; reboot"}))

            self.assertEqual("artifact_hash_mismatch", bad_hash.code)
            self.assertEqual("partition_not_allowed", bad_partition.code)
            self.assertEqual([], transport.calls)

    def test_cancellation_timeout_and_disconnect_are_never_reported_as_success(self):
        with TemporaryDirectory() as directory:
            boot_path = Path(directory) / "boot.img"
            boot_path.write_bytes(b"boot")
            boot = BootInfo("id", str(boot_path), digest(boot_path), "boot", False)

            started = threading.Event()
            release = threading.Event()
            cancel_transport = FakeProcessTransport(
                [FakeTransportStep(TransportOutcome(0), started, release)]
            )
            cancel_engine = CommandEngine(
                store=AppStateStore(snapshot_for("fastboot", boot=boot)),
                executor=CommandExecutor(cancel_transport),
                postcondition_observer=StatefulPostconditionObserver(cancel_transport),
                interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
            )
            results = []
            worker = threading.Thread(
                target=lambda: results.append(
                    cancel_engine.execute(command("boot.live", operation_id="cancel-boot"))
                ),
                daemon=True,
            )
            worker.start()
            self.assertTrue(started.wait(1))
            self.assertTrue(cancel_engine.cancel("cancel-boot"))
            worker.join(2)

            self.assertEqual(OperationStatus.FAILED, results[0].status)
            self.assertEqual("outcome_unknown", results[0].code)

            for outcome, expected_code in (
                (TransportOutcome(None, timed_out=True), "timed_out"),
                (TransportOutcome(1, stderr="device disconnected"), "process_failed"),
            ):
                with self.subTest(expected_code=expected_code):
                    transport = FakeProcessTransport([outcome])
                    engine = CommandEngine(
                        store=AppStateStore(snapshot_for("fastboot", boot=boot)),
                        executor=CommandExecutor(transport),
                        postcondition_observer=StatefulPostconditionObserver(transport),
                        interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
                    )
                    result = engine.execute(command("boot.live"))
                    self.assertEqual(OperationStatus.FAILED, result.status)
                    self.assertEqual(expected_code, result.code)


class FlashPlannerGoldenTests(unittest.TestCase):
    def test_explicit_dry_run_launches_zero_subprocesses(self):
        with TemporaryDirectory() as directory:
            image = Path(directory) / "boot.img"
            image.write_bytes(b"boot")
            plan = FlashPlan(
                "images",
                {"verify": True, "noReboot": True},
                4,
                "same-plan",
                dry_run=True,
            )
            snapshot = snapshot_for("fastboot", plan=plan)
            repository = ProcessedArtifactRepository()
            repository.register(
                (FileArtifact(str(image.resolve()), digest(image), "partition:boot"),),
                plan_fingerprint=plan.fingerprint,
            )
            planner = OperationPlanner(artifact_repository=repository)
            dry_compilation = planner.compile(command("flash.execute"), snapshot)
            real_compilation = planner.compile(
                command("flash.execute"),
                replace(snapshot, plan=replace(plan, dry_run=False)),
            )
            self.assertTrue(dry_compilation.ok)
            self.assertTrue(real_compilation.ok)
            self.assertEqual(
                [request.argv for request in real_compilation.plan.requests],
                [request.argv for request in dry_compilation.plan.requests],
            )

            transport = FakeProcessTransport([])
            engine = CommandEngine(
                store=AppStateStore(snapshot),
                executor=CommandExecutor(transport),
                operation_planner=planner,
                interaction_handler=lambda _request: self.fail("dry-run must not prompt"),
            )
            result = engine.execute(command("flash.execute"))

            self.assertEqual(OperationStatus.SUCCESS, result.status)
            self.assertEqual("dry_run_succeeded", result.code)
            self.assertEqual([], transport.calls)
            self.assertEqual(
                [["FASTBOOT", "-s", "SERIAL-A", "flash", "boot", str(image.resolve())]],
                [item["argv"] for item in result.value["planned_requests"]],
            )

    def test_custom_firmware_artifacts_require_canonical_processed_state(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "custom.zip"
            image = root / "boot.img"
            source.write_bytes(b"custom firmware")
            image.write_bytes(b"boot")
            firmware = FirmwareInfo(
                str(source),
                "custom",
                "42",
                digest(source),
                True,
                False,
            )
            plan = FlashPlan(
                "images",
                {"verify": True, "noReboot": True},
                fingerprint="custom-images",
                dry_run=True,
            )
            repository = ProcessedArtifactRepository()
            repository.register(
                (FileArtifact(str(image.resolve()), digest(image), "partition:boot"),),
                firmware_hash=firmware.hash,
            )
            planner = OperationPlanner(artifact_repository=repository)

            rejected = planner.compile(
                command("flash.execute"),
                snapshot_for("fastboot", plan=plan, firmware=firmware),
            )
            accepted = planner.compile(
                command("flash.execute"),
                snapshot_for(
                    "fastboot",
                    plan=plan,
                    firmware=replace(firmware, processed=True),
                ),
            )

            self.assertEqual("firmware_not_processed", rejected.code)
            self.assertIsNone(rejected.plan)
            self.assertTrue(accepted.ok)

    def test_ota_sideload_uses_exact_adb_command_and_verified_archive(self):
        with TemporaryDirectory() as directory:
            ota = Path(directory) / "ota.zip"
            ota.write_bytes(b"verified ota")
            firmware = FirmwareInfo(
                str(ota),
                "ota",
                "42",
                digest(ota),
                True,
                True,
            )
            transport = FakeProcessTransport([TransportOutcome(0)])
            engine = CommandEngine(
                store=AppStateStore(
                    snapshot_for(
                        "sideload",
                        plan=FlashPlan(
                            "OTA",
                            {"verify": True, "noReboot": True},
                            dry_run=False,
                        ),
                        firmware=firmware,
                    )
                ),
                executor=CommandExecutor(transport),
                postcondition_observer=StatefulPostconditionObserver(transport),
                interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
            )

            result = engine.execute(command("flash.execute"))

            self.assertEqual(OperationStatus.SUCCESS, result.status)
            assert_exact_or_staged_argv(
                self,
                [("ADB", "-s", "SERIAL-A", "sideload", str(ota.resolve()))],
                transport.calls,
            )

    def test_ota_no_reboot_false_appends_exact_adb_reboot(self):
        with TemporaryDirectory() as directory:
            ota = Path(directory) / "ota.zip"
            ota.write_bytes(b"ota")
            firmware = FirmwareInfo(str(ota), "ota", "42", digest(ota), True, True)
            transport = FakeProcessTransport([TransportOutcome(0), TransportOutcome(0)])
            engine = CommandEngine(
                store=AppStateStore(
                    snapshot_for(
                        "sideload",
                        plan=FlashPlan(
                            "OTA",
                            {"verify": True, "noReboot": False},
                            dry_run=False,
                        ),
                        firmware=firmware,
                    )
                ),
                executor=CommandExecutor(transport),
                postcondition_observer=StatefulPostconditionObserver(transport),
                interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
            )

            result = engine.execute(command("flash.execute"))

            self.assertEqual(OperationStatus.SUCCESS, result.status)
            assert_exact_or_staged_argv(
                self,
                [
                    ("ADB", "-s", "SERIAL-A", "sideload", str(ota.resolve())),
                    ("ADB", "-s", "SERIAL-A", "reboot"),
                ],
                transport.calls,
            )

    def test_ota_rejects_each_incompatible_marked_option_explicitly(self):
        with TemporaryDirectory() as directory:
            ota = Path(directory) / "ota.zip"
            ota.write_bytes(b"ota")
            firmware = FirmwareInfo(str(ota), "ota", "", digest(ota), True, True)
            for option in (
                "disableVerity",
                "disableVerification",
                "force",
                "downgrade",
                "temporaryRoot",
                "wipe",
            ):
                with self.subTest(option=option):
                    transport = FakeProcessTransport([])
                    engine = CommandEngine(
                        store=AppStateStore(
                            snapshot_for(
                                "sideload",
                                plan=FlashPlan(
                                    "OTA",
                                    {"verify": True, option: True},
                                    dry_run=False,
                                ),
                                firmware=firmware,
                            )
                        ),
                        executor=CommandExecutor(transport),
                    )
                    result = engine.execute(command("flash.execute"))
                    self.assertEqual("option_not_supported_for_mode", result.code)
                    self.assertEqual([], transport.calls)

    def test_ota_wrong_state_or_hash_fails_without_false_success(self):
        with TemporaryDirectory() as directory:
            ota = Path(directory) / "ota.zip"
            ota.write_bytes(b"ota")
            firmware = FirmwareInfo(str(ota), "ota", "", digest(ota), True, True)
            transport = FakeProcessTransport([])
            wrong_state = CommandEngine(
                store=AppStateStore(
                    snapshot_for("adb", plan=FlashPlan("OTA", dry_run=False), firmware=firmware)
                ),
                executor=CommandExecutor(transport),
            ).execute(command("flash.execute"))
            wrong_hash_firmware = FirmwareInfo(str(ota), "ota", "", "0" * 64, True, True)
            wrong_hash = CommandEngine(
                store=AppStateStore(
                    snapshot_for(
                        "sideload",
                        plan=FlashPlan("OTA", dry_run=False),
                        firmware=wrong_hash_firmware,
                    )
                ),
                executor=CommandExecutor(transport),
            ).execute(command("flash.execute"))

            self.assertEqual("ota_sideload_required", wrong_state.code)
            self.assertEqual("artifact_hash_mismatch", wrong_hash.code)
            self.assertEqual([], transport.calls)

    def test_processed_factory_images_compile_deterministic_exact_sequence(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            factory = root / "factory.zip"
            boot = root / "boot.img"
            vbmeta = root / "vbmeta.img"
            factory.write_bytes(b"factory")
            boot.write_bytes(b"boot")
            vbmeta.write_bytes(b"vbmeta")
            firmware = FirmwareInfo(str(factory), "factory", "42", digest(factory), True, True)
            plan = FlashPlan(
                "factory",
                {
                    "verify": True,
                    "slot": "b",
                    "dataBehavior": "preserve",
                    "disableVerity": True,
                    "disableVerification": True,
                    "force": True,
                    "noReboot": False,
                },
                4,
                "factory-plan",
                dry_run=False,
            )
            transport = FakeProcessTransport(
                [TransportOutcome(0), TransportOutcome(0), TransportOutcome(0)]
            )
            repository = ProcessedArtifactRepository()
            repository.register(
                (
                    FileArtifact(str(vbmeta.resolve()), digest(vbmeta), "partition:vbmeta"),
                    FileArtifact(str(boot.resolve()), digest(boot), "partition:boot"),
                ),
                firmware_hash=firmware.hash,
            )
            engine = CommandEngine(
                store=AppStateStore(snapshot_for("fastboot", plan=plan, firmware=firmware)),
                executor=CommandExecutor(transport),
                postcondition_observer=StatefulPostconditionObserver(transport),
                interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
                operation_planner=OperationPlanner(artifact_repository=repository),
            )

            result = engine.execute(command("flash.execute"))

            self.assertEqual(OperationStatus.SUCCESS, result.status)
            assert_exact_or_staged_argv(
                self,
                [
                    (
                        "FASTBOOT", "-s", "SERIAL-A", "--slot=b", "--disable-verity",
                        "--disable-verification", "--force", "flash", "boot", str(boot.resolve()),
                    ),
                    (
                        "FASTBOOT", "-s", "SERIAL-A", "--slot=b", "--disable-verity",
                        "--disable-verification", "--force", "flash", "vbmeta", str(vbmeta.resolve()),
                    ),
                    ("FASTBOOT", "-s", "SERIAL-A", "reboot"),
                ],
                transport.calls,
            )

    def test_factory_components_use_fixed_stages_before_os_partitions(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {
                name: root / f"{name}.img"
                for name in ("bootloader", "radio", "boot", "dtbo", "vbmeta")
            }
            factory = root / "factory.zip"
            factory.write_bytes(b"factory")
            for name, path in paths.items():
                path.write_bytes(name.encode("ascii"))
            firmware = FirmwareInfo(
                str(factory),
                "factory",
                "42",
                digest(factory),
                True,
                True,
            )
            plan = FlashPlan(
                "factory",
                {
                    "verify": True,
                    "slot": "b",
                    "disableVerity": True,
                    "disableVerification": True,
                    "force": True,
                    "noReboot": False,
                },
                fingerprint="staged-factory",
                dry_run=False,
            )
            # Deliberately register in an unsafe/random order. The repository
            # order must never influence factory execution stages.
            repository = ProcessedArtifactRepository()
            repository.register(
                tuple(
                    FileArtifact(
                        str(paths[name].resolve()),
                        digest(paths[name]),
                        f"partition:{name}",
                    )
                    for name in ("vbmeta", "radio", "dtbo", "bootloader", "boot")
                ),
                firmware_hash=firmware.hash,
            )
            snapshot = snapshot_for("fastboot", plan=plan, firmware=firmware)
            snapshot = replace(
                snapshot,
                devices=(replace(snapshot.devices[0], bootloader="unlocked"),),
            )
            planner = OperationPlanner(artifact_repository=repository)

            compilation = planner.compile(command("flash.execute"), snapshot)

            self.assertTrue(compilation.ok)
            self.assertEqual(
                ("bootloader", "radio", "boot", "dtbo", "vbmeta"),
                compilation.plan.partitions,
            )
            self.assertEqual(("b",), compilation.plan.slots)
            expected_requests = [
                ("FASTBOOT", "-s", "SERIAL-A", "flash", "bootloader", str(paths["bootloader"].resolve())),
                ("FASTBOOT", "-s", "SERIAL-A", "reboot-bootloader"),
                ("FASTBOOT", "-s", "SERIAL-A", "flash", "radio", str(paths["radio"].resolve())),
                ("FASTBOOT", "-s", "SERIAL-A", "reboot-bootloader"),
                (
                    "FASTBOOT", "-s", "SERIAL-A", "--slot=b", "--disable-verity",
                    "--disable-verification", "--force", "flash", "boot",
                    str(paths["boot"].resolve()),
                ),
                (
                    "FASTBOOT", "-s", "SERIAL-A", "--slot=b", "--disable-verity",
                    "--disable-verification", "--force", "flash", "dtbo",
                    str(paths["dtbo"].resolve()),
                ),
                (
                    "FASTBOOT", "-s", "SERIAL-A", "--slot=b", "--disable-verity",
                    "--disable-verification", "--force", "flash", "vbmeta",
                    str(paths["vbmeta"].resolve()),
                ),
                ("FASTBOOT", "-s", "SERIAL-A", "reboot"),
            ]
            self.assertEqual(
                expected_requests,
                [request.argv for request in compilation.plan.requests],
            )
            self.assertTrue(
                all(isinstance(request.argv, tuple) for request in compilation.plan.requests)
            )
            self.assertTrue(all(request.cwd is None for request in compilation.plan.requests))

            transport = FakeProcessTransport(
                [TransportOutcome(0) for _request in expected_requests]
            )
            engine = CommandEngine(
                store=AppStateStore(snapshot),
                executor=CommandExecutor(transport),
                postcondition_observer=StatefulPostconditionObserver(transport),
                interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
                operation_planner=planner,
            )
            result = engine.execute(command("flash.execute"))

            self.assertEqual(OperationStatus.SUCCESS, result.status)
            assert_exact_or_staged_argv(self, expected_requests, transport.calls)

    def test_factory_components_fail_closed_when_mode_state_or_artifacts_are_incomplete(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            factory = root / "factory.zip"
            factory.write_bytes(b"factory")
            paths = {
                name: root / f"{name}.img"
                for name in ("bootloader", "radio", "boot")
            }
            for name, path in paths.items():
                path.write_bytes(name.encode("ascii"))
            firmware = FirmwareInfo(
                str(factory),
                "factory",
                "42",
                digest(factory),
                True,
                True,
            )

            def compile_case(
                roles,
                *,
                mode="factory",
                device_mode="fastboot",
                bootloader_state="unlocked",
            ):
                plan = FlashPlan(mode, {"verify": True}, fingerprint=f"case-{mode}", dry_run=True)
                repository = ProcessedArtifactRepository()
                repository.register(
                    tuple(
                        FileArtifact(
                            str(paths[role].resolve()),
                            digest(paths[role]),
                            f"partition:{role}",
                        )
                        for role in roles
                    ),
                    firmware_hash=firmware.hash,
                )
                snapshot = snapshot_for(device_mode, plan=plan, firmware=firmware)
                snapshot = replace(
                    snapshot,
                    devices=(
                        replace(snapshot.devices[0], bootloader=bootloader_state),
                    ),
                )
                return OperationPlanner(artifact_repository=repository).compile(
                    command("flash.execute"),
                    snapshot,
                )

            cases = (
                (("radio", "boot"), {}, "factory_bootloader_artifact_required"),
                (("bootloader", "radio"), {}, "factory_partition_artifact_required"),
                (
                    ("bootloader", "boot"),
                    {"bootloader_state": "locked"},
                    "bootloader_unlocked_required",
                ),
                (
                    ("bootloader", "boot"),
                    {"mode": "images"},
                    "factory_component_mode_required",
                ),
                (
                    ("bootloader", "boot"),
                    {"device_mode": "adb"},
                    "fastboot_required",
                ),
            )
            for roles, options, expected_code in cases:
                with self.subTest(expected_code=expected_code):
                    compilation = compile_case(roles, **options)
                    self.assertFalse(compilation.ok)
                    self.assertEqual(expected_code, compilation.code)
                    self.assertIsNone(compilation.plan)

            wifi_factory = compile_case(("bootloader", "boot"))
            self.assertTrue(wifi_factory.ok)
            self.assertEqual(
                ["bootloader", "boot"],
                list(wifi_factory.plan.partitions),
            )

    def test_failed_factory_stage_reboot_stops_before_radio_and_os_images(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            factory = root / "factory.zip"
            factory.write_bytes(b"factory")
            paths = {
                name: root / f"{name}.img"
                for name in ("bootloader", "radio", "boot")
            }
            for name, path in paths.items():
                path.write_bytes(name.encode("ascii"))
            firmware = FirmwareInfo(
                str(factory),
                "factory",
                "42",
                digest(factory),
                True,
                True,
            )
            plan = FlashPlan(
                "factory",
                {"verify": True},
                fingerprint="factory-stop-on-reboot",
                dry_run=False,
            )
            repository = ProcessedArtifactRepository()
            repository.register(
                tuple(
                    FileArtifact(
                        str(paths[name].resolve()),
                        digest(paths[name]),
                        f"partition:{name}",
                    )
                    for name in ("boot", "radio", "bootloader")
                ),
                firmware_hash=firmware.hash,
            )
            snapshot = snapshot_for("fastboot", plan=plan, firmware=firmware)
            snapshot = replace(
                snapshot,
                devices=(replace(snapshot.devices[0], bootloader="unlocked"),),
            )
            transport = FakeProcessTransport(
                [TransportOutcome(0), TransportOutcome(1, stderr="reboot failed")]
            )
            engine = CommandEngine(
                store=AppStateStore(snapshot),
                executor=CommandExecutor(transport),
                postcondition_observer=StatefulPostconditionObserver(transport),
                interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
                operation_planner=OperationPlanner(artifact_repository=repository),
            )

            result = engine.execute(command("flash.execute"))

            self.assertEqual(OperationStatus.FAILED, result.status)
            self.assertEqual("outcome_unknown", result.code)
            assert_exact_or_staged_argv(
                self,
                [
                    (
                        "FASTBOOT", "-s", "SERIAL-A", "flash", "bootloader",
                        str(paths["bootloader"].resolve()),
                    ),
                    ("FASTBOOT", "-s", "SERIAL-A", "reboot-bootloader"),
                ],
                transport.calls,
            )

    def test_temporary_root_uses_only_canonical_patched_boot(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "boot.img"
            patched = root / "patched.img"
            original.write_bytes(b"original")
            patched.write_bytes(b"patched")
            plan = FlashPlan(
                "images",
                {"verify": True, "temporaryRoot": True, "noReboot": False},
                fingerprint="temporary-root-plan",
                dry_run=False,
            )
            repository = ProcessedArtifactRepository()
            repository.register(
                (FileArtifact(str(original.resolve()), digest(original), "partition:boot"),),
                plan_fingerprint=plan.fingerprint,
            )
            transport = FakeProcessTransport([TransportOutcome(0), TransportOutcome(0)])
            engine = CommandEngine(
                store=AppStateStore(
                    snapshot_for(
                        "fastboot",
                        plan=plan,
                        boot=BootInfo("patched", str(patched), digest(patched), "boot", True),
                    )
                ),
                executor=CommandExecutor(transport),
                postcondition_observer=StatefulPostconditionObserver(transport),
                interaction_handler=lambda _request: InteractionDecision.ACCEPTED,
                operation_planner=OperationPlanner(artifact_repository=repository),
            )

            result = engine.execute(command("flash.execute"))

            self.assertEqual(OperationStatus.SUCCESS, result.status)
            assert_exact_or_staged_argv(
                self,
                [
                    ("FASTBOOT", "-s", "SERIAL-A", "flash", "boot", str(original.resolve())),
                    ("FASTBOOT", "-s", "SERIAL-A", "boot", str(patched.resolve())),
                ],
                transport.calls,
            )

    def test_wipe_preview_issues_nonce_and_exact_text_before_execution(self):
        with TemporaryDirectory() as directory:
            boot = Path(directory) / "boot.img"
            boot.write_bytes(b"boot")
            plan = FlashPlan(
                "wipeData",
                {
                    "verify": True,
                    "dataBehavior": "wipe",
                },
                2,
                "wipe-plan",
                dry_run=False,
            )
            transport = FakeProcessTransport([TransportOutcome(0), TransportOutcome(0)])
            interactions = []
            repository = ProcessedArtifactRepository()
            repository.register(
                (FileArtifact(str(boot.resolve()), digest(boot), "partition:boot"),),
                plan_fingerprint=plan.fingerprint,
            )
            engine = CommandEngine(
                store=AppStateStore(snapshot_for("fastboot", plan=plan)),
                executor=CommandExecutor(transport),
                postcondition_observer=StatefulPostconditionObserver(transport),
                interaction_handler=lambda request: interactions.append(request) or InteractionDecision.ACCEPTED,
                operation_planner=OperationPlanner(artifact_repository=repository),
            )

            preview = engine.execute(command("flash.plan.preview"))
            confirmation = preview.value["compiled"]["confirmation"]
            rejected_token = engine.execute(
                command(
                    "flash.execute",
                    payload={
                        "confirmationText": confirmation["required_text"],
                        "confirmationToken": "browser-token",
                    },
                )
            )
            executed = engine.execute(
                command(
                    "flash.execute",
                    payload={"confirmationText": confirmation["required_text"]},
                )
            )

            self.assertEqual("flash_plan_preview", preview.code)
            self.assertTrue(confirmation["nonce"])
            self.assertEqual("WIPE RIAL-A", confirmation["required_text"])
            self.assertEqual("untrusted_confirmation_token", rejected_token.code)
            self.assertEqual(OperationStatus.SUCCESS, executed.status)
            self.assertTrue(interactions[0].reinforced)
            assert_exact_or_staged_argv(
                self,
                [
                    ("FASTBOOT", "-s", "SERIAL-A", "flash", "boot", str(boot.resolve())),
                    ("FASTBOOT", "-s", "SERIAL-A", "-w"),
                ],
                transport.calls,
            )

    def test_backend_artifacts_are_required_and_ui_metadata_is_rejected(self):
        transport = FakeProcessTransport([])
        no_images = CommandEngine(
            store=AppStateStore(
                snapshot_for(
                    "fastboot",
                    plan=FlashPlan("factory", dry_run=False),
                    firmware=FirmwareInfo(type="factory", verified=True, processed=True),
                )
            ),
            executor=CommandExecutor(transport),
        ).execute(command("flash.execute"))

        with TemporaryDirectory() as directory:
            image = Path(directory) / "bad.img"
            image.write_bytes(b"image")
            injected_plan = FlashPlan(
                "images",
                {"images": {"boot": {"path": str(image), "hash": digest(image)}}},
                dry_run=False,
            )
            injected = CommandEngine(
                store=AppStateStore(snapshot_for("fastboot", plan=injected_plan)),
                executor=CommandExecutor(transport),
            ).execute(command("flash.execute"))

            bad_plan = FlashPlan("images", fingerprint="bad-role", dry_run=False)
            repository = ProcessedArtifactRepository()
            repository.register(
                (FileArtifact(str(image.resolve()), digest(image), "partition:boot;erase"),),
                plan_fingerprint=bad_plan.fingerprint,
            )
            invalid_partition = CommandEngine(
                store=AppStateStore(snapshot_for("fastboot", plan=bad_plan)),
                executor=CommandExecutor(transport),
                operation_planner=OperationPlanner(artifact_repository=repository),
            ).execute(command("flash.execute"))

        self.assertEqual("processed_artifacts_unavailable", no_images.code)
        self.assertEqual("untrusted_artifact_metadata", injected.code)
        self.assertEqual("partition_not_allowed", invalid_partition.code)
        self.assertEqual([], transport.calls)

        updated = CommandEngine(
            store=AppStateStore(snapshot_for("fastboot")),
            executor=CommandExecutor(transport),
        ).execute(
            AppCommand(
                "flash.plan.update",
                expected_revision=0,
                payload={
                    "mode": "images",
                    "options": {
                        "images": {"boot": {"path": "C:/browser.img", "hash": "0" * 64}}
                    },
                },
            )
        )
        self.assertEqual("untrusted_artifact_metadata", updated.code)

    def test_each_unsupported_image_option_fails_explicitly(self):
        with TemporaryDirectory() as directory:
            image = Path(directory) / "boot.img"
            image.write_bytes(b"boot")
            repository = ProcessedArtifactRepository()
            repository.register(
                (FileArtifact(str(image.resolve()), digest(image), "partition:boot"),),
                plan_fingerprint="unsupported",
            )
            for options in (
                {"verify": False},
                {"downgrade": True},
                {"disableVerity": True},
            ):
                with self.subTest(options=options):
                    transport = FakeProcessTransport([])
                    plan = FlashPlan(
                        "images",
                        options,
                        fingerprint="unsupported",
                        dry_run=False,
                    )
                    result = CommandEngine(
                        store=AppStateStore(snapshot_for("fastboot", plan=plan)),
                        executor=CommandExecutor(transport),
                        operation_planner=OperationPlanner(artifact_repository=repository),
                    ).execute(command("flash.execute"))
                    self.assertEqual("option_not_supported_for_mode", result.code)
                    self.assertEqual([], transport.calls)

    def test_plan_fingerprint_change_during_prompt_blocks_subprocess(self):
        with TemporaryDirectory() as directory:
            image = Path(directory) / "boot.img"
            image.write_bytes(b"image")
            plan = FlashPlan(
                "images",
                {"verify": True},
                1,
                "original",
                dry_run=False,
            )
            store = AppStateStore(snapshot_for("fastboot", plan=plan))
            transport = FakeProcessTransport([TransportOutcome(0)])
            repository = ProcessedArtifactRepository()
            repository.register(
                (FileArtifact(str(image.resolve()), digest(image), "partition:boot"),),
                plan_fingerprint=plan.fingerprint,
            )

            def change_plan(_request):
                store.update(
                    expected_revision=0,
                    plan=FlashPlan("images", plan.options, 2, "changed", dry_run=False),
                )
                return InteractionDecision.ACCEPTED

            engine = CommandEngine(
                store=store,
                executor=CommandExecutor(transport),
                interaction_handler=change_plan,
                operation_planner=OperationPlanner(artifact_repository=repository),
            )

            result = engine.execute(command("flash.execute"))

            self.assertEqual("plan_revision_changed", result.code)
            self.assertEqual([], transport.calls)

    def test_reinforced_challenge_is_ttl_bounded_and_one_use(self):
        snapshot = snapshot_for("fastboot")
        challenge_time = [100.0]
        planner = OperationPlanner(
            confirmation_secret=b"stable-secret",
            challenge_ttl_seconds=20.0,
            maximum_pending_challenges=1,
            challenge_clock=lambda: challenge_time[0],
        )
        intent = command("device.switchSlot", payload={"slot": "b"})

        first = planner.compile(intent, snapshot)
        phrase = first.confirmation_text
        accepted = planner.compile(
            command(
                "device.switchSlot",
                payload={"slot": "b", "confirmationText": phrase},
            ),
            snapshot,
        )
        replay = planner.compile(
            command(
                "device.switchSlot",
                payload={"slot": "b", "confirmationText": phrase},
            ),
            snapshot,
        )
        stale_revision = planner.compile(
            command("device.switchSlot", payload={"slot": "b"}, revision=7),
            snapshot,
        )

        self.assertEqual("confirmation_text_required", first.code)
        self.assertTrue(accepted.ok)
        self.assertEqual("confirmation_preview_required", replay.code)
        self.assertEqual("stale_revision", stale_revision.code)
        self.assertLessEqual(len(planner._issued_challenges), 1)

        refreshed = planner.compile(intent, snapshot)
        challenge_time[0] += 20.0
        expired = planner.compile(
            command(
                "device.switchSlot",
                payload={"slot": "b", "confirmationText": refreshed.confirmation_text},
            ),
            snapshot,
        )
        self.assertEqual("confirmation_preview_required", expired.code)

    def test_dry_run_toggle_changes_fingerprint_and_stales_preview_revision(self):
        store = AppStateStore(snapshot_for("fastboot"))
        engine = CommandEngine(store=store)
        real = engine.execute(
            AppCommand(
                "flash.plan.update",
                expected_revision=0,
                payload={
                    "mode": "wipe",
                    "options": {"verify": True, "wipe": True, "dryRun": False},
                },
            )
        )
        real_fingerprint = store.snapshot().plan.fingerprint
        dry = engine.execute(
            AppCommand(
                "flash.plan.update",
                expected_revision=1,
                payload={
                    "mode": "wipe",
                    "options": {"verify": True, "wipe": True, "dryRun": True},
                },
            )
        )
        stale = engine.execute(
            AppCommand("flash.plan.preview", expected_revision=1, payload={"serial": "SERIAL-A"})
        )

        self.assertTrue(real.ok)
        self.assertTrue(dry.ok)
        self.assertNotEqual(real_fingerprint, store.snapshot().plan.fingerprint)
        self.assertEqual("stale_revision", stale.code)


if __name__ == "__main__":
    unittest.main()
