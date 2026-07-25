from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from pixelflasher_core import (
    AppCommand,
    AppSnapshot,
    BootInfo,
    DeviceInfo,
    FileArtifact,
    FirmwareInfo,
    FlashPlan,
    OperationBatch,
    OperationPlan,
    OperationPlanner,
    OperationPostcondition,
    OperationRisk,
    ProcessedArtifactRepository,
    ProcessRequest,
    ToolchainInfo,
)
from pixelflasher_core.planner import PlanningError

NOW = 1_000.0


def _command(
    kind: str = "flash.execute",
    *,
    revision: int | None = 0,
    serial: str | None = None,
    payload: dict[str, object] | None = None,
) -> AppCommand:
    return AppCommand(
        kind,
        expected_revision=revision,
        target_serial=serial,
        payload=payload or {},
    )


def _snapshot(
    *,
    devices: tuple[DeviceInfo, ...] | None = None,
    selected_serials: tuple[str, ...] = ("SERIAL-A",),
    firmware: FirmwareInfo | None = None,
    boot: BootInfo | None = None,
    plan: FlashPlan | None = None,
    toolchain: ToolchainInfo | None = None,
    revision: int = 0,
) -> AppSnapshot:
    actual_devices = devices or (
        DeviceInfo(
            "SERIAL-A",
            codename="akita",
            mode="fastboot",
            bootloader="unlocked",
            architecture="arm64",
            kmi="android15-6.1",
        ),
    )
    return AppSnapshot(
        revision=revision,
        devices=actual_devices,
        selected_serials=selected_serials,
        firmware=firmware or FirmwareInfo(hash="a" * 64),
        boot=boot or BootInfo(hash="b" * 64),
        plan=plan or FlashPlan(mode="images", revision=3, fingerprint="plan-fp", dry_run=False),
        toolchain=toolchain or ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True),
    )


def _bound_plan(planner: OperationPlanner, snapshot: AppSnapshot) -> OperationPlan:
    device = snapshot.devices[0]
    return planner._base_plan(
        snapshot,
        device,
        (ProcessRequest(("FASTBOOT", "--version")),),
        label="branch contract",
    )


class ProcessedArtifactRepositoryBranchTests(TestCase):
    def test_repository_rejects_untyped_or_unbound_registrations(self) -> None:
        repository = ProcessedArtifactRepository()
        with self.assertRaisesRegex(ValueError, "FileArtifact"):
            repository.register([], firmware_hash="a" * 64)
        with self.assertRaisesRegex(ValueError, "FileArtifact"):
            repository.register([object()], firmware_hash="a" * 64)  # type: ignore[list-item]
        with self.assertRaisesRegex(ValueError, "firmware_hash"):
            repository.register((FileArtifact("image.img", "a" * 64, "partition:boot"),))

    def test_checkpoint_rollback_fallback_resolution_and_clear_are_durable(self) -> None:
        repository = ProcessedArtifactRepository()
        original = (FileArtifact("old.img", "a" * 64, "partition:boot"),)
        replacement = (FileArtifact("new.img", "b" * 64, "partition:boot"),)
        repository.register(original, firmware_hash="A" * 64)
        existing = repository.checkpoint(firmware_hash="A" * 64)
        repository.register(replacement, firmware_hash="A" * 64)
        repository.rollback(existing)
        self.assertEqual(
            original,
            repository.resolve_binding(firmware_hash="a" * 64, plan_fingerprint="other"),
        )

        absent = repository.checkpoint(plan_fingerprint="new-plan")
        repository.register(replacement, plan_fingerprint="new-plan")
        repository.rollback(absent)
        self.assertEqual((), repository.resolve_binding(plan_fingerprint="new-plan"))
        with self.assertRaises(TypeError):
            repository.rollback(object())  # type: ignore[arg-type]
        repository.clear()
        self.assertEqual((), repository.resolve_binding(firmware_hash="a" * 64))


class PlannerBoundaryTests(TestCase):
    def test_planner_constructor_and_compile_front_door_fail_closed(self) -> None:
        for arguments in (
            {"hash_chunk_size": 0},
            {"challenge_ttl_seconds": 0},
            {"maximum_pending_challenges": 0},
        ):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                OperationPlanner(**arguments)

        planner = OperationPlanner(clock=lambda: NOW, challenge_clock=lambda: NOW)
        snapshot = _snapshot()
        self.assertEqual(
            "planner_not_supported",
            planner.compile(_command("unsupported"), snapshot).code,
        )
        self.assertEqual(
            "revision_required",
            planner.compile(_command("device.reboot", revision=None), snapshot).code,
        )

    def test_batch_and_preview_front_doors_reject_every_untrusted_shape(self) -> None:
        planner = OperationPlanner(clock=lambda: NOW, challenge_clock=lambda: NOW)
        one = _snapshot()
        batch_cases = (
            (_command("device.reboot"), "batch_kind_not_supported"),
            (_command(revision=None), "revision_required"),
            (_command(revision=1), "stale_revision"),
            (_command(serial="SERIAL-A"), "batch_target_not_allowed"),
            (_command(payload={"serial": "SERIAL-A"}), "batch_target_not_allowed"),
            (_command(payload={"fingerprint": "browser-owned"}), "untrusted_batch_metadata"),
            (_command(payload={"unexpected": True}), "invalid_plan_payload"),
            (_command(), "batch_targets_required"),
        )
        for app_command, code in batch_cases:
            with self.subTest(code=code):
                self.assertEqual(code, planner.compile_batch(app_command, one).code)

        preview_cases = (
            (_command("device.reboot"), one, "batch_kind_not_supported"),
            (_command(revision=None), one, "revision_required"),
            (_command(revision=1), one, "stale_revision"),
            (_command(serial="SERIAL-A"), one, "batch_target_not_allowed"),
            (_command(payload={"unexpected": True}), one, "invalid_plan_payload"),
            (_command(), one, "dry_run_required"),
            (
                _command(),
                replace(one, plan=replace(one.plan, dry_run=True)),
                "batch_targets_required",
            ),
        )
        for app_command, snapshot, code in preview_cases:
            with self.subTest(code=code):
                self.assertEqual(code, planner.compile_preview_batch(app_command, snapshot).code)

    def test_batch_internal_failures_never_escape_as_executable_plans(self) -> None:
        devices = (
            DeviceInfo("SERIAL-A", codename="akita", mode="fastboot", bootloader="unlocked"),
            DeviceInfo("SERIAL-B", codename="akita", mode="fastboot", bootloader="unlocked"),
        )
        snapshot = _snapshot(devices=devices, selected_serials=("SERIAL-A", "SERIAL-B"))
        planner = OperationPlanner(clock=lambda: NOW, challenge_clock=lambda: NOW)

        with patch.object(
            planner,
            "_flash",
            side_effect=PlanningError("device_changed", "injected"),
        ):
            self.assertEqual("device_changed", planner.compile_batch(_command(), snapshot).code)

        read_only = replace(_bound_plan(planner, snapshot), dry_run=True)
        with patch.object(planner, "_flash", return_value=(read_only, False, False)):
            self.assertEqual(
                "batch_plan_not_destructive",
                planner.compile_batch(_command(), snapshot).code,
            )

        executable = replace(
            _bound_plan(planner, snapshot),
            risk=OperationRisk.DESTRUCTIVE,
            postconditions=(OperationPostcondition("flash_applied", {}),),
        )
        with (
            patch.object(planner, "_flash", return_value=(executable, True, True)),
            patch("pixelflasher_core.planner.OperationBatch", side_effect=ValueError("injected")),
        ):
            self.assertEqual("batch_invalid", planner.compile_batch(_command(), snapshot).code)

        dry_snapshot = replace(snapshot, plan=replace(snapshot.plan, dry_run=True))
        with patch.object(
            planner,
            "_flash",
            side_effect=PlanningError("preview_changed", "injected"),
        ):
            self.assertEqual(
                "preview_changed",
                planner.compile_preview_batch(_command(), dry_snapshot).code,
            )
        with patch.object(planner, "_flash", return_value=(executable, True, True)):
            self.assertEqual(
                "preview_plan_not_read_only",
                planner.compile_preview_batch(_command(), dry_snapshot).code,
            )
        with (
            patch.object(planner, "_flash", return_value=(read_only, False, False)),
            patch(
                "pixelflasher_core.planner.OperationPreviewBatch",
                side_effect=ValueError("injected"),
            ),
        ):
            self.assertEqual(
                "preview_batch_invalid",
                planner.compile_preview_batch(_command(), dry_snapshot).code,
            )

    def test_revalidation_names_every_stale_device_and_snapshot_boundary(self) -> None:
        planner = OperationPlanner(clock=lambda: NOW, challenge_clock=lambda: NOW)
        snapshot = _snapshot()
        base = _bound_plan(planner, snapshot)
        device = snapshot.devices[0]
        cases = (
            (replace(base, created=NOW - 2, expires=NOW - 1), snapshot, "plan_expired"),
            (replace(base, created=NOW + 2, expires=NOW + 3), snapshot, "plan_created_in_future"),
            (base, replace(snapshot, selected_serials=("OTHER",), selected_serial="OTHER"), "target_serial_changed"),
            (base, replace(snapshot, devices=()), "device_disconnected"),
            (base, replace(snapshot, devices=(replace(device, online=False),)), "device_disconnected"),
            (base, replace(snapshot, devices=(replace(device, codename=""),)), "device_codename_unavailable"),
            (base, replace(snapshot, devices=(replace(device, codename="husky"),)), "device_codename_changed"),
            (base, replace(snapshot, devices=(replace(device, mode="adb"),)), "device_state_changed"),
            (
                replace(base, expected_architecture="arm64"),
                replace(snapshot, devices=(replace(device, architecture=""),)),
                "device_architecture_unavailable",
            ),
            (
                replace(base, expected_architecture="x86_64"),
                snapshot,
                "device_architecture_changed",
            ),
            (
                replace(base, expected_kmi="android15-6.1"),
                replace(snapshot, devices=(replace(device, kmi=""),)),
                "device_kmi_unavailable",
            ),
            (replace(base, expected_kmi="other"), snapshot, "device_kmi_changed"),
            (replace(base, plan_revision=99), snapshot, "plan_revision_changed"),
            (replace(base, fingerprint="other"), snapshot, "plan_fingerprint_changed"),
            (replace(base, firmware_hash="c" * 64), snapshot, "firmware_hash_changed"),
            (replace(base, boot_hash="c" * 64), snapshot, "boot_hash_changed"),
            (replace(base, snapshot_revision=1), snapshot, "snapshot_revision_changed"),
            (
                replace(base, expected_kmi="", plan_revision=99),
                snapshot,
                "plan_revision_changed",
            ),
            (
                replace(base, expected_kmi=device.kmi, plan_revision=99),
                snapshot,
                "plan_revision_changed",
            ),
        )
        for plan, current, code in cases:
            with self.subTest(code=code):
                issue = planner.revalidate(plan, current)
                self.assertIsNotNone(issue)
                self.assertEqual(code, issue[0] if issue else None)
        self.assertIsNone(planner.revalidate(base, snapshot))

    def test_reboot_and_boot_flash_reject_unsupported_backend_states(self) -> None:
        planner = OperationPlanner()
        snapshot = _snapshot()
        for mode in (7, "not-a-mode"):
            with self.subTest(mode=mode), self.assertRaises(PlanningError):
                planner._reboot(
                    _command("device.reboot", payload={"mode": mode}),
                    snapshot,
                )

        unsupported_transport = _snapshot(
            devices=(
                replace(snapshot.devices[0], mode="vendor-download"),
            ),
        )
        with self.assertRaises(PlanningError) as transport:
            planner._reboot(_command("device.reboot"), unsupported_transport)
        self.assertEqual("reboot_transport_unsupported", transport.exception.code)

        locked = _snapshot(
            devices=(replace(snapshot.devices[0], bootloader="locked"),),
        )
        with self.assertRaises(PlanningError) as bootloader:
            planner._boot_flash(_command("boot.flash"), locked)
        self.assertEqual("bootloader_unlocked_required", bootloader.exception.code)

    def test_flash_dispatch_rejects_invalid_ota_and_image_modes(self) -> None:
        planner = OperationPlanner()
        fastboot = _snapshot()

        dry_run_mode = replace(
            fastboot,
            plan=replace(fastboot.plan, mode="dry-run"),
        )
        with self.assertRaises(PlanningError) as unavailable:
            planner._flash(_command(), dry_run_mode)
        self.assertEqual("processed_artifacts_unavailable", unavailable.exception.code)

        unsupported = replace(
            fastboot,
            plan=replace(fastboot.plan, mode="unknown"),
        )
        with self.assertRaises(PlanningError) as mode:
            planner._flash(_command(), unsupported)
        self.assertEqual("flash_mode_unsupported", mode.exception.code)

        ota_device = replace(fastboot.devices[0], mode="adb")
        not_ota = _snapshot(
            devices=(ota_device,),
            firmware=FirmwareInfo(type="factory", hash="a" * 64),
            plan=replace(fastboot.plan, mode="ota"),
        )
        with self.assertRaises(PlanningError) as firmware_type:
            planner._flash(_command(), not_ota)
        self.assertEqual("ota_firmware_required", firmware_type.exception.code)

        unprocessed = replace(
            not_ota,
            firmware=FirmwareInfo(type="ota", hash="a" * 64),
        )
        with self.assertRaises(PlanningError) as processing:
            planner._flash(_command(), unprocessed)
        self.assertEqual("firmware_not_processed", processing.exception.code)

        processed = replace(
            unprocessed,
            firmware=replace(unprocessed.firmware, verified=True, processed=True),
        )
        with patch.object(planner, "_firmware_artifact", return_value=None):
            with self.assertRaises(PlanningError) as missing:
                planner._flash(_command(), processed)
        self.assertEqual("firmware_required", missing.exception.code)

    def test_image_flash_rejects_every_invalid_repository_shape(self) -> None:
        def compile_with(
            roles: tuple[str, ...],
            *,
            options: dict[str, object] | None = None,
            mode: str = "images",
            firmware_type: str = "custom",
            artifact_issue: tuple[str, str] | None = None,
            bypass_mode_validation: bool = False,
        ) -> str:
            snapshot = _snapshot(
                firmware=FirmwareInfo(
                    type=firmware_type,
                    hash="a" * 64,
                    verified=True,
                    processed=True,
                ),
                plan=FlashPlan(
                    mode=mode,
                    revision=3,
                    fingerprint="plan-fp",
                    options={},
                ),
            )
            repository = ProcessedArtifactRepository()
            repository.register(
                tuple(
                    FileArtifact(
                        f"{index}-{role.replace(':', '-')}.img",
                        f"{index + 1:064x}",
                        role,
                    )
                    for index, role in enumerate(roles)
                ),
                firmware_hash=snapshot.firmware.hash,
            )
            planner = OperationPlanner(artifact_repository=repository)
            validation = (
                patch.object(planner, "_validate_image_mode_options")
                if bypass_mode_validation
                else patch.object(
                    planner,
                    "_validate_image_mode_options",
                    wraps=planner._validate_image_mode_options,
                )
            )
            with (
                validation,
                patch.object(
                    planner,
                    "_revalidate_artifact",
                    return_value=artifact_issue,
                ),
                self.assertRaises(PlanningError) as raised,
            ):
                planner._image_flash(
                    _command(),
                    snapshot,
                    snapshot.devices[0],
                    mode,
                    options or {},
                )
            return raised.exception.code

        cases = (
            (
                ("partition:boot",),
                {"mode": "factory", "firmware_type": "custom", "bypass_mode_validation": True},
                "factory_firmware_required",
            ),
            (
                ("downgrade:boot", "downgrade:boot"),
                {},
                "processed_artifacts_invalid",
            ),
            (
                ("partition:boot", "partition:boot"),
                {},
                "processed_artifacts_invalid",
            ),
            (
                ("partition:boot",),
                {"artifact_issue": ("artifact_hash_mismatch", "injected")},
                "artifact_hash_mismatch",
            ),
            (("metadata:receipt",), {}, "processed_artifacts_unavailable"),
            (
                ("downgrade:boot", "partition:vendor"),
                {
                    "mode": "keepdata",
                    "firmware_type": "factory",
                    "options": {"downgrade": True},
                },
                "downgrade_source_unavailable",
            ),
            (
                ("partition:boot",),
                {"options": {"partitions": 7}},
                "partition_selection_invalid",
            ),
            (
                ("partition:boot",),
                {"options": {"partitions": []}},
                "partition_selection_empty",
            ),
            (
                ("partition:boot",),
                {"options": {"partitions": ["vendor"]}},
                "processed_artifact_missing",
            ),
            (
                ("downgrade:boot", "partition:boot", "partition:vendor"),
                {
                    "mode": "keepdata",
                    "firmware_type": "factory",
                    "options": {
                        "downgrade": True,
                        "partitions": ["vendor"],
                    },
                },
                "downgrade_boot_required",
            ),
            (
                ("partition:boot",),
                {
                    "options": {
                        "partitions": ["boot"],
                        "dataBehavior": "later",
                    },
                },
                "data_behavior_invalid",
            ),
        )
        for roles, arguments, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(expected, compile_with(roles, **arguments))

    def test_batch_and_service_confirmations_are_preview_bound_and_one_shot(self) -> None:
        planner = OperationPlanner(
            confirmation_secret=b"planner-branch-contract",
            clock=lambda: NOW,
            challenge_clock=lambda: NOW,
        )
        snapshot = _snapshot(
            devices=(
                _snapshot().devices[0],
                replace(_snapshot().devices[0], serial="SERIAL-B"),
            ),
            selected_serials=("SERIAL-A", "SERIAL-B"),
        )
        first = replace(
            _bound_plan(planner, snapshot),
            risk=OperationRisk.DESTRUCTIVE,
            postconditions=(OperationPostcondition("flash_applied", {}),),
        )
        second = replace(first, target_serial="SERIAL-B")
        batch = OperationBatch((first, second), created=NOW, expires=NOW + 100)
        text = batch.required_confirmation_text()

        required = planner._bind_batch_confirmation(_command(), snapshot, batch, False)
        self.assertEqual("confirmation_text_required", required.code)
        mismatch = planner._bind_batch_confirmation(
            _command(payload={"confirmationText": "wrong"}),
            snapshot,
            batch,
            False,
        )
        self.assertEqual("confirmation_text_mismatch", mismatch.code)

        fresh = OperationPlanner(
            confirmation_secret=b"planner-branch-contract",
            clock=lambda: NOW,
            challenge_clock=lambda: NOW,
        )
        without_preview = fresh._bind_batch_confirmation(
            _command(payload={"confirmationText": text}),
            snapshot,
            batch,
            False,
        )
        self.assertEqual("confirmation_preview_required", without_preview.code)

        preview = fresh._bind_batch_confirmation(_command(), snapshot, batch, True)
        self.assertIsNotNone(preview.batch)
        with patch.object(fresh, "_consume_challenge", return_value=False):
            race = fresh._bind_batch_confirmation(
                _command(payload={"confirmationText": text}),
                snapshot,
                batch,
                False,
            )
        self.assertEqual("confirmation_preview_required", race.code)

        service_plan = first
        service_preview = fresh.bind_reinforced_confirmation(
            _command("device.bootloader.unlock"),
            snapshot,
            service_plan,
            destructive=True,
            requires_confirmation=True,
            preview=True,
        )
        with patch.object(fresh, "_consume_challenge", return_value=False):
            service_race = fresh.bind_reinforced_confirmation(
                _command(
                    "device.bootloader.unlock",
                    payload={"confirmationText": service_preview.confirmation_text},
                ),
                snapshot,
                service_plan,
                destructive=True,
                requires_confirmation=True,
            )
        self.assertEqual("confirmation_preview_required", service_race.code)

        erase = replace(first, partitions=("userdata",))
        self.assertTrue(
            planner._required_confirmation_text(
                "partitions.erase",
                erase,
                snapshot,
            ).startswith("ERASE userdata"),
        )

    def test_artifact_revalidation_detects_missing_unreadable_and_changed_files(self) -> None:
        planner = OperationPlanner(hash_chunk_size=2)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "boot.img"
            path.write_bytes(b"boot")
            digest = hashlib.sha256(b"boot").hexdigest()
            artifact = FileArtifact(str(path.resolve()), digest, "boot")
            self.assertIsNone(planner._revalidate_artifact(artifact))
            path.write_bytes(b"changed")
            self.assertEqual("artifact_hash_mismatch", planner._revalidate_artifact(artifact)[0])
            path.unlink()
            self.assertEqual("artifact_missing", planner._revalidate_artifact(artifact)[0])
            path.write_bytes(b"boot")
            with patch.object(Path, "open", side_effect=OSError("injected")):
                self.assertEqual("artifact_read_failed", planner._revalidate_artifact(artifact)[0])

    def test_canonical_helpers_reject_ambiguous_targets_tools_and_metadata(self) -> None:
        planner = OperationPlanner()
        snapshot = _snapshot()
        invalid_devices = (
            (_command("device.reboot", serial=None, payload={"serial": 1}), snapshot, "target_serial_invalid"),
            (
                _command("device.reboot"),
                replace(snapshot, selected_serials=(), selected_serial=None),
                "target_serial_required",
            ),
            (
                _command("device.reboot", serial="SERIAL-A", payload={"serial": "SERIAL-B"}),
                snapshot,
                "ambiguous_target_serial",
            ),
            (_command("device.reboot", serial="OTHER"), snapshot, "target_serial_changed"),
            (
                _command("device.reboot", serial="SERIAL-A"),
                replace(snapshot, devices=()),
                "device_disconnected",
            ),
            (
                _command("device.reboot", serial="SERIAL-A"),
                replace(snapshot, devices=(replace(snapshot.devices[0], mode="offline"),)),
                "device_disconnected",
            ),
        )
        for app_command, current, code in invalid_devices:
            with self.subTest(code=code), self.assertRaises(PlanningError) as raised:
                planner._device(app_command, current)
            self.assertEqual(code, raised.exception.code)

        unavailable = replace(snapshot, toolchain=ToolchainInfo())
        for helper in (planner._adb, planner._fastboot):
            with self.subTest(helper=helper.__name__), self.assertRaises(PlanningError):
                helper(unavailable)
        for value in (None, 7, "c"):
            with self.subTest(partition=value), self.assertRaises(PlanningError):
                planner._partition(value)
        for value in (None, "all", 1):
            with self.subTest(slot=value), self.assertRaises(PlanningError):
                planner._slot(value)

    def test_artifact_metadata_and_confirmation_text_are_backend_owned(self) -> None:
        planner = OperationPlanner()
        snapshot = _snapshot()
        with self.assertRaisesRegex(PlanningError, "path"):
            planner._artifact(None, "a" * 64, "boot")
        with self.assertRaisesRegex(PlanningError, "SHA-256"):
            planner._artifact("boot.img", None, "boot")
        with self.assertRaises(PlanningError) as invalid_hash:
            planner._artifact("boot.img", "not-a-hash", "boot")
        self.assertEqual("artifact_metadata_invalid", invalid_hash.exception.code)
        with self.assertRaises(PlanningError):
            planner._boot_artifact(replace(snapshot, boot=BootInfo()))
        with self.assertRaises(PlanningError):
            planner._boot_artifact(replace(snapshot, boot=BootInfo(path="boot.img")))
        with self.assertRaises(PlanningError):
            planner._firmware_artifact(replace(snapshot, firmware=FirmwareInfo()), required=True)
        with self.assertRaises(PlanningError):
            planner._firmware_artifact(
                replace(snapshot, firmware=FirmwareInfo(path="firmware.zip")),
                required=False,
            )
        self.assertIsNone(
            planner._firmware_artifact(replace(snapshot, firmware=FirmwareInfo()), required=False)
        )

        plan = _bound_plan(planner, snapshot)
        with self.assertRaises(ValueError):
            planner._required_confirmation_text(
                "device.switchSlot",
                replace(plan, slots=()),
                snapshot,
            )
        with self.assertRaises(ValueError):
            planner._required_confirmation_text(
                "partitions.erase",
                replace(plan, partitions=()),
                snapshot,
            )

    def test_flash_option_normalization_and_ota_limits_are_closed(self) -> None:
        planner = OperationPlanner()
        with self.assertRaises(PlanningError) as unsupported:
            planner._normalized_flash_options({"browserPath": "image.img"})
        self.assertEqual("flash_metadata_unsupported", unsupported.exception.code)
        with self.assertRaises(PlanningError) as conflict:
            planner._normalized_flash_options(
                {"disableVerity": True, "disable_verity": False}
            )
        self.assertEqual("flash_option_conflict", conflict.exception.code)

        for options in (
            {"disableVerity": True},
            {"slot": "a"},
            {"partitions": ["boot"]},
            {"dataBehavior": "wipe"},
        ):
            with self.subTest(options=options), self.assertRaises(PlanningError):
                planner._validate_ota_options(options)

    def test_challenge_cache_expires_evicts_and_consumes_exactly_once(self) -> None:
        clock = [NOW]
        planner = OperationPlanner(
            challenge_clock=lambda: clock[0],
            challenge_ttl_seconds=5,
            maximum_pending_challenges=1,
        )
        planner._issue_challenge("first")
        planner._issue_challenge("second")
        self.assertFalse(planner._challenge_is_pending("first"))
        self.assertTrue(planner._challenge_is_pending("second"))
        self.assertTrue(planner._consume_challenge("second"))
        self.assertFalse(planner._consume_challenge("second"))
        planner._issue_challenge("expired")
        clock[0] += 6
        self.assertFalse(planner._challenge_is_pending("expired"))
