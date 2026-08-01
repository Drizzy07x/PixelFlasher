from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from pixelflasher_core.contracts import (
    AppSnapshot,
    DeviceInfo,
    FileArtifact,
    OperationPlan,
    OperationPostcondition,
    ProcessRequest,
)
from pixelflasher_core.operation_runner import (
    OperationRunner,
    PostconditionObservation,
)

SERIAL = "ABCDEF123456"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def condition(kind: str, expected: Mapping[str, object]) -> OperationPostcondition:
    return OperationPostcondition(kind, expected)


def plan_for(
    *postconditions: OperationPostcondition,
    target_serial: str | None = SERIAL,
    requests: Sequence[ProcessRequest] | None = None,
    artifacts: Sequence[FileArtifact] = (),
    partitions: Sequence[str] = (),
) -> OperationPlan:
    return OperationPlan(
        requests=tuple(requests or (ProcessRequest(("adb", "get-state")),)),
        target_serial=target_serial,
        postconditions=postconditions,
        artifacts=tuple(artifacts),
        partitions=tuple(partitions),
    )


def snapshot_with(
    *,
    serial: str = SERIAL,
    mode: str = "adb",
    slot: str = "a",
    bootloader: str = "unlocked",
    online: bool = True,
) -> AppSnapshot:
    return AppSnapshot(
        devices=(
            DeviceInfo(
                serial,
                mode=mode,
                slot=slot,
                bootloader=bootloader,
                online=online,
            ),
        ),
    )


class TestPostconditionCompilation:
    def test_compiles_the_full_observable_device_contract(self) -> None:
        runner = OperationRunner(postcondition_timeout_seconds=7)
        compiled = runner._postcondition_spec(
            plan_for(
                condition(
                    "device_reachable",
                    {"mode": "system", "bootCompleted": True},
                ),
                condition("bootloader_state", {"state": "unlocked"}),
                condition(
                    "partition_written",
                    {"partition": "boot", "slot": "b", "sha256": DIGEST_A.upper()},
                ),
                condition("partition_erased", {"partition": "metadata"}),
                condition(
                    "package_state",
                    {"packages": ["com.example.one", "com.example.two"], "state": "enabled"},
                ),
                condition("data_adb_empty", {"empty": True}),
                condition("droidguard_cache_state", {"empty": True}),
                condition(
                    "adb_wifi_endpoint_state",
                    {"endpoint": "192.0.2.10:5555", "connected": True},
                ),
                condition(
                    "root_module_version",
                    {"moduleId": "play_integrity_fix", "versionCode": 200},
                ),
                condition(
                    "pif_profile_state",
                    {"profileId": "pif.custom_json", "present": True},
                ),
                condition(
                    "pif_profile_hash",
                    {"profileId": "pif.custom_json", "sha256": DIGEST_B.upper()},
                ),
                condition(
                    "targeted_fix_target_state",
                    {"packageName": "com.example.one", "present": True},
                ),
                condition(
                    "targeted_fix_profile_hash",
                    {
                        "packageName": "com.example.one",
                        "format": "json",
                        "sha256": DIGEST_A,
                    },
                ),
                condition(
                    "magisk_su_policy",
                    {
                        "package": "com.example.one",
                        "uid": 10123,
                        "state": "absent",
                        "policy": "revoke",
                        "logging": False,
                        "notification": False,
                        "until": 0,
                    },
                ),
                condition("firmware_applied", {"build": "BP2A.250705.008"}),
            )
        )

        assert compiled.timeout_seconds == 7
        assert compiled.expected_mode == "adb"
        assert compiled.expected_boot_completed is True
        assert compiled.expected_bootloader == "unlocked"
        assert dict(compiled.partition_hashes) == {"boot_b": DIGEST_A}
        assert compiled.erased_partitions == ("metadata",)
        assert dict(compiled.expected_package_states) == {
            "com.example.one": "enabled",
            "com.example.two": "enabled",
        }
        assert compiled.expected_data_adb_empty is True
        assert compiled.expected_droidguard_cache_empty is True
        assert dict(compiled.expected_adb_endpoints) == {"192.0.2.10:5555": True}
        assert dict(compiled.expected_root_module_versions) == {"play_integrity_fix": 200}
        assert dict(compiled.expected_pif_profiles) == {"pif.custom_json": True}
        assert dict(compiled.expected_pif_profile_hashes) == {"pif.custom_json": DIGEST_B}
        assert dict(compiled.expected_targeted_fix_targets) == {"com.example.one": True}
        assert dict(compiled.expected_targeted_fix_profile_hashes) == {
            "com.example.one:json": DIGEST_A
        }
        assert dict(compiled.expected_magisk_su_policies) == {10123: "absent"}
        assert compiled.expected_build == "BP2A.250705.008"

    @pytest.mark.parametrize(
        ("postconditions", "error", "message"),
        [
            ((condition("device_reachable", {"bootCompleted": "yes"}),), TypeError, "bootCompleted"),
            ((condition("device_mode", {"mode": ""}),), ValueError, "mode"),
            ((condition("safe_mode_active", {"active": 1}),), TypeError, "safe mode"),
            ((condition("ota_idle_state", {"idle": "yes"}),), TypeError, "OTA idle"),
            ((condition("active_slot", {"slot": "c"}),), ValueError, "active slot"),
            ((condition("bootloader_state", {"state": ""}),), ValueError, "bootloader"),
            (
                (condition("partition_written", {"partition": "", "sha256": DIGEST_A}),),
                ValueError,
                "target",
            ),
            (
                (condition("partition_written", {"partition": "boot", "sha256": ""}),),
                ValueError,
                "hash",
            ),
            (
                (
                    condition(
                        "partition_written",
                        {"partition": "boot", "slot": "all", "sha256": DIGEST_A},
                    ),
                ),
                ValueError,
                "slot",
            ),
            ((condition("partition_erased", {"partition": ""}),), ValueError, "erased"),
            ((condition("root_app_installed", {"packageName": ""}),), ValueError, "package"),
            ((condition("package_state", {"packages": "com.example", "state": "enabled"}),), TypeError, "array"),
            ((condition("package_state", {"packages": [], "state": ""}),), ValueError, "state"),
            ((condition("package_state", {"packages": [""], "state": "enabled"}),), TypeError, "strings"),
            (
                (condition("package_installer", {"package": "com.example"}),),
                ValueError,
                "fields",
            ),
            (
                (condition("package_installer", {"package": "", "installer": "store"}),),
                TypeError,
                "invalid",
            ),
            (
                (condition("magisk_denylist_state", {"packages": [], "listed": False, "extra": 1}),),
                ValueError,
                "fields",
            ),
            (
                (condition("magisk_denylist_state", {"packages": "com.example", "listed": True}),),
                TypeError,
                "array",
            ),
            (
                (condition("magisk_denylist_state", {"packages": ["com.example"], "listed": 1}),),
                TypeError,
                "boolean",
            ),
            (
                (condition("magisk_denylist_state", {"packages": [], "listed": True}),),
                ValueError,
                "bounds",
            ),
            (
                (condition("magisk_denylist_state", {"packages": [""], "listed": True}),),
                TypeError,
                "package names",
            ),
            (
                (
                    condition(
                        "magisk_su_policy",
                        {
                            "package": "com.example",
                            "uid": 1,
                            "state": "present",
                            "policy": "allow",
                            "logging": True,
                            "notification": True,
                        },
                    ),
                ),
                ValueError,
                "fields",
            ),
            (
                (
                    condition(
                        "magisk_su_policy",
                        {
                            "package": "",
                            "uid": 1,
                            "state": "present",
                            "policy": "allow",
                            "logging": True,
                            "notification": True,
                            "until": 0,
                        },
                    ),
                ),
                TypeError,
                "package",
            ),
            (
                (
                    condition(
                        "magisk_su_policy",
                        {
                            "package": "com.example",
                            "uid": True,
                            "state": "present",
                            "policy": "allow",
                            "logging": True,
                            "notification": True,
                            "until": 0,
                        },
                    ),
                ),
                ValueError,
                "UID",
            ),
            (
                (
                    condition(
                        "magisk_su_policy",
                        {
                            "package": "com.example",
                            "uid": 1,
                            "state": "unknown",
                            "policy": "allow",
                            "logging": True,
                            "notification": True,
                            "until": 0,
                        },
                    ),
                ),
                ValueError,
                "policy state",
            ),
            (
                (
                    condition(
                        "magisk_su_policy",
                        {
                            "package": "com.example",
                            "uid": 1,
                            "state": "present",
                            "policy": "allow",
                            "logging": 1,
                            "notification": True,
                            "until": 0,
                        },
                    ),
                ),
                TypeError,
                "flags",
            ),
            (
                (
                    condition(
                        "magisk_su_policy",
                        {
                            "package": "com.example",
                            "uid": 1,
                            "state": "present",
                            "policy": "allow",
                            "logging": True,
                            "notification": True,
                            "until": -1,
                        },
                    ),
                ),
                ValueError,
                "expiry",
            ),
            (
                (
                    condition(
                        "magisk_su_policy",
                        {
                            "package": "com.example",
                            "uid": 1,
                            "state": "absent",
                            "policy": "allow",
                            "logging": True,
                            "notification": True,
                            "until": 0,
                        },
                    ),
                ),
                ValueError,
                "revocation",
            ),
            (
                (
                    condition(
                        "magisk_su_policy",
                        {
                            "package": "com.example",
                            "uid": 1,
                            "state": "present",
                            "policy": "revoke",
                            "logging": True,
                            "notification": True,
                            "until": 0,
                        },
                    ),
                ),
                ValueError,
                "allow or deny",
            ),
            ((condition("magisk_backup_state", {"sha1": "a" * 40}),), ValueError, "fields"),
            (
                (condition("magisk_backup_state", {"sha1": "not-a-sha1", "state": "verified"}),),
                ValueError,
                "invalid",
            ),
            ((condition("shizuku_state", {"running": True, "extra": False}),), ValueError, "fields"),
            ((condition("shizuku_state", {"running": 1}),), TypeError, "boolean"),
            ((condition("magisk_modules_state", {"allDisabled": True, "extra": 1}),), ValueError, "fields"),
            ((condition("magisk_modules_state", {"allDisabled": "yes"}),), TypeError, "boolean"),
            ((condition("data_adb_empty", {"empty": True, "extra": 1}),), ValueError, "fields"),
            ((condition("data_adb_empty", {"empty": "yes"}),), TypeError, "boolean"),
            ((condition("droidguard_cache_state", {"empty": False}),), ValueError, "empty=true"),
            (
                (condition("remote_files_written", {"hashes": {}}),),
                TypeError,
                "object",
            ),
            (
                (condition("remote_files_written", {"hashes": {"relative": DIGEST_A}}),),
                TypeError,
                "absolute",
            ),
            (
                (condition("remote_files_written", {"hashes": {"/data/file": "bad"}}),),
                ValueError,
                "hash",
            ),
            (
                (condition("adb_wifi_endpoint_state", {"endpoint": "", "connected": True}),),
                ValueError,
                "endpoint",
            ),
            (
                (condition("adb_wifi_endpoint_state", {"endpoint": "host:5555", "connected": 1}),),
                TypeError,
                "boolean",
            ),
            ((condition("root_module_state", {"moduleId": "", "state": "enabled"}),), ValueError, "ID"),
            ((condition("root_module_state", {"moduleId": "module", "state": ""}),), ValueError, "state"),
            (
                (condition("root_module_version", {"moduleId": "module"}),),
                ValueError,
                "fields",
            ),
            (
                (condition("root_module_version", {"moduleId": "", "versionCode": 1}),),
                ValueError,
                "ID",
            ),
            (
                (condition("root_module_version", {"moduleId": "module", "versionCode": True}),),
                ValueError,
                "invalid",
            ),
            ((condition("pif_profile_state", {"profileId": "id"}),), ValueError, "fields"),
            ((condition("pif_profile_state", {"profileId": "", "present": True}),), ValueError, "ID"),
            ((condition("pif_profile_state", {"profileId": "id", "present": 1}),), TypeError, "boolean"),
            ((condition("pif_profile_hash", {"profileId": "id"}),), ValueError, "fields"),
            ((condition("pif_profile_hash", {"profileId": "", "sha256": DIGEST_A}),), ValueError, "ID"),
            ((condition("pif_profile_hash", {"profileId": "id", "sha256": "bad"}),), ValueError, "hash"),
            (
                (condition("targeted_fix_target_state", {"packageName": "com.example"}),),
                ValueError,
                "fields",
            ),
            (
                (condition("targeted_fix_target_state", {"packageName": "", "present": True}),),
                ValueError,
                "package",
            ),
            (
                (condition("targeted_fix_target_state", {"packageName": "com.example", "present": 1}),),
                TypeError,
                "boolean",
            ),
            (
                (condition("targeted_fix_profile_hash", {"packageName": "com.example"}),),
                ValueError,
                "fields",
            ),
            (
                (
                    condition(
                        "targeted_fix_profile_hash",
                        {"packageName": "", "format": "json", "sha256": DIGEST_A},
                    ),
                ),
                ValueError,
                "package",
            ),
            (
                (
                    condition(
                        "targeted_fix_profile_hash",
                        {"packageName": "com.example", "format": "xml", "sha256": DIGEST_A},
                    ),
                ),
                ValueError,
                "format",
            ),
            (
                (
                    condition(
                        "targeted_fix_profile_hash",
                        {"packageName": "com.example", "format": "json", "sha256": "A" * 64},
                    ),
                ),
                ValueError,
                "hash",
            ),
            ((condition("firmware_applied", {"build": ""}),), ValueError, "build"),
            ((condition("unknown_observer_contract", {}),), ValueError, "no observer mapping"),
        ],
    )
    def test_rejects_malformed_observer_contracts(
        self,
        postconditions: tuple[OperationPostcondition, ...],
        error: type[Exception],
        message: str,
    ) -> None:
        with pytest.raises(error, match=message):
            OperationRunner()._postcondition_spec(plan_for(*postconditions))

    @pytest.mark.parametrize(
        "postconditions",
        [
            (
                condition("device_mode", {"mode": "adb"}),
                condition("device_mode", {"mode": "fastboot"}),
            ),
            (
                condition("partition_erased", {"partition": "metadata"}),
                condition("partition_erased", {"partition": "metadata"}),
            ),
            (
                condition("package_state", {"packages": ["com.example"], "state": "enabled"}),
                condition("package_state", {"packages": ["com.example"], "state": "disabled"}),
            ),
            (
                condition(
                    "package_installer",
                    {"package": "com.example", "installer": "store.one"},
                ),
                condition(
                    "package_installer",
                    {"package": "com.example", "installer": "store.two"},
                ),
            ),
            (
                condition("magisk_denylist_state", {"packages": ["com.example"], "listed": True}),
                condition("magisk_denylist_state", {"packages": ["com.example"], "listed": False}),
            ),
            (
                condition(
                    "magisk_backup_state",
                    {"sha1": "a" * 40, "state": "verified"},
                ),
                condition(
                    "magisk_backup_state",
                    {"sha1": "a" * 40, "state": "absent"},
                ),
            ),
            (
                condition("root_module_state", {"moduleId": "module", "state": "enabled"}),
                condition("root_module_state", {"moduleId": "module", "state": "disabled"}),
            ),
            (
                condition("root_module_version", {"moduleId": "module", "versionCode": 1}),
                condition("root_module_version", {"moduleId": "module", "versionCode": 2}),
            ),
            (
                condition("pif_profile_state", {"profileId": "id", "present": True}),
                condition("pif_profile_state", {"profileId": "id", "present": False}),
            ),
            (
                condition("pif_profile_hash", {"profileId": "id", "sha256": DIGEST_A}),
                condition("pif_profile_hash", {"profileId": "id", "sha256": DIGEST_B}),
            ),
            (
                condition(
                    "targeted_fix_target_state",
                    {"packageName": "com.example", "present": True},
                ),
                condition(
                    "targeted_fix_target_state",
                    {"packageName": "com.example", "present": False},
                ),
            ),
            (
                condition(
                    "targeted_fix_profile_hash",
                    {"packageName": "com.example", "format": "json", "sha256": DIGEST_A},
                ),
                condition(
                    "targeted_fix_profile_hash",
                    {"packageName": "com.example", "format": "json", "sha256": DIGEST_B},
                ),
            ),
            (
                condition("remote_files_written", {"hashes": {"/data/file": DIGEST_A}}),
                condition("remote_files_written", {"hashes": {"/data/file": DIGEST_B}}),
            ),
            (
                condition(
                    "adb_wifi_endpoint_state",
                    {"endpoint": "host:5555", "connected": True},
                ),
                condition(
                    "adb_wifi_endpoint_state",
                    {"endpoint": "host:5555", "connected": False},
                ),
            ),
        ],
    )
    def test_rejects_conflicting_duplicate_evidence(
        self,
        postconditions: tuple[OperationPostcondition, OperationPostcondition],
    ) -> None:
        with pytest.raises(ValueError, match="conflicting|duplicated"):
            OperationRunner()._postcondition_spec(plan_for(*postconditions))

    def test_flash_postcondition_binds_only_hash_backed_flash_requests(self) -> None:
        runner = OperationRunner()
        flash_plan = plan_for(
            condition("flash_applied", {"partitions": ["boot"], "build": "BUILD"}),
            requests=(
                ProcessRequest(("adb", "devices")),
                ProcessRequest(("fastboot", "flash")),
                ProcessRequest(("fastboot", "flash", "init_boot", "missing.img")),
                ProcessRequest(("fastboot", "--slot=b", "flash", "boot", "boot.img")),
            ),
            artifacts=(FileArtifact("boot.img", DIGEST_A),),
            partitions=("boot",),
        )

        compiled = runner._postcondition_spec(flash_plan)

        # A firmware flash cannot be proven by reading partitions back, so the
        # planned digests only gate the plan; the flashed build is the device
        # evidence, compared whenever the probe can reach a booted system.
        assert dict(compiled.partition_hashes) == {}
        assert compiled.expected_build is None
        assert compiled.flashed_build == "BUILD"
        assert runner._planned_partition_hashes(flash_plan) == ({"boot_b": DIGEST_A}, {"boot"})

        with pytest.raises(TypeError, match="array"):
            runner._postcondition_spec(
                plan_for(
                    condition("flash_applied", {"partitions": "boot"}),
                    requests=(ProcessRequest(("fastboot", "flash", "boot", "boot.img")),),
                    artifacts=(FileArtifact("boot.img", DIGEST_A),),
                )
            )
        with pytest.raises(TypeError, match="non-empty"):
            runner._postcondition_spec(
                plan_for(
                    condition("flash_applied", {"partitions": [""]}),
                    requests=(ProcessRequest(("fastboot", "flash", "boot", "boot.img")),),
                    artifacts=(FileArtifact("boot.img", DIGEST_A),),
                )
            )
        with pytest.raises(ValueError, match="unavailable for vendor"):
            runner._postcondition_spec(
                plan_for(
                    condition("flash_applied", {"partitions": ["vendor"]}),
                    requests=(ProcessRequest(("fastboot", "flash", "boot", "boot.img")),),
                    artifacts=(FileArtifact("boot.img", DIGEST_A),),
                )
            )
        with pytest.raises(TypeError, match="build"):
            runner._postcondition_spec(
                plan_for(
                    condition("flash_applied", {"partitions": ["boot"], "build": 42}),
                    requests=(ProcessRequest(("fastboot", "flash", "boot", "boot.img")),),
                    artifacts=(FileArtifact("boot.img", DIGEST_A),),
                )
            )

    def test_planned_partition_hashes_reject_absent_and_conflicting_evidence(self) -> None:
        runner = OperationRunner()
        with pytest.raises(ValueError, match="no partition hash evidence"):
            runner._planned_partition_hashes(plan_for())

        conflicting = plan_for(
            requests=(
                ProcessRequest(("fastboot", "flash", "boot", "one.img")),
                ProcessRequest(("fastboot", "flash", "boot", "two.img")),
            ),
            artifacts=(
                FileArtifact("one.img", DIGEST_A),
                FileArtifact("two.img", DIGEST_B),
            ),
        )
        with pytest.raises(ValueError, match="conflicting planned hashes"):
            runner._planned_partition_hashes(conflicting)

    def test_partition_hash_binding_is_case_insensitive_and_conflict_closed(self) -> None:
        values: dict[str, str] = {}
        OperationRunner._bind_partition_hash(values, "boot", DIGEST_A.upper())
        OperationRunner._bind_partition_hash(values, "boot", DIGEST_A)
        assert values == {"boot": DIGEST_A}

        with pytest.raises(ValueError, match="conflicting partition hash"):
            OperationRunner._bind_partition_hash(values, "boot", DIGEST_B)

    def test_device_postcondition_requires_a_target(self) -> None:
        with pytest.raises(ValueError, match="target serial"):
            OperationRunner()._postcondition_spec(
                plan_for(condition("device_mode", {"mode": "adb"}), target_serial=None)
            )


class TestHostPostconditionCompilation:
    def test_compiles_distinct_wifi_endpoints_and_ignores_execution_evidence(self) -> None:
        compiled = OperationRunner(postcondition_timeout_seconds=3)._host_postcondition_spec(
            plan_for(
                condition(
                    "adb_wifi_endpoint_state",
                    {"endpoint": "192.0.2.1:5555", "connected": True},
                ),
                condition(
                    "adb_wifi_endpoint_state",
                    {"endpoint": "192.0.2.2:5555", "connected": False},
                ),
                condition("host_artifact_written", {"path": "ignored-by-host-observer"}),
                target_serial=None,
            )
        )

        assert compiled.timeout_seconds == 3
        assert dict(compiled.expected_adb_endpoints) == {
            "192.0.2.1:5555": True,
            "192.0.2.2:5555": False,
        }

    @pytest.mark.parametrize(
        ("postconditions", "message"),
        [
            ((condition("device_mode", {"mode": "adb"}),), "no host observer mapping"),
            (
                (condition("adb_wifi_endpoint_state", {"endpoint": "host:5555"}),),
                "fields",
            ),
            (
                (
                    condition(
                        "adb_wifi_endpoint_state",
                        {"endpoint": "", "connected": True},
                    ),
                ),
                "endpoint",
            ),
            (
                (
                    condition(
                        "adb_wifi_endpoint_state",
                        {"endpoint": "host:5555", "connected": 1},
                    ),
                ),
                "boolean",
            ),
            (
                (
                    condition(
                        "adb_wifi_endpoint_state",
                        {"endpoint": "host:5555", "connected": True},
                    ),
                    condition(
                        "adb_wifi_endpoint_state",
                        {"endpoint": "host:5555", "connected": False},
                    ),
                ),
                "conflicting",
            ),
        ],
    )
    def test_rejects_invalid_host_observer_contracts(
        self,
        postconditions: tuple[OperationPostcondition, ...],
        message: str,
    ) -> None:
        with pytest.raises((TypeError, ValueError), match=message):
            OperationRunner()._host_postcondition_spec(
                plan_for(*postconditions, target_serial=None)
            )

    def test_rejects_target_bound_host_postconditions(self) -> None:
        with pytest.raises(ValueError, match="cannot name a target"):
            OperationRunner()._host_postcondition_spec(
                plan_for(
                    condition(
                        "adb_wifi_endpoint_state",
                        {"endpoint": "host:5555", "connected": True},
                    )
                )
            )


class TestExecutionEvidenceValidation:
    @pytest.mark.parametrize(
        "postcondition",
        [
            condition(
                "partition_read_verified",
                {
                    "targetSerial": SERIAL,
                    "partition": "init_boot",
                    "fileName": "init boot.img",
                },
            ),
            condition("data_adb_backup_verified", {"fileName": "backup.pfdataadb"}),
            condition(
                "data_adb_restore_verified",
                {"contentFingerprint": DIGEST_A.upper(), "entryCount": 20_000},
            ),
            condition(
                "package_export_verified",
                {"package": "com.example.app", "fileName": "Example App.apk"},
            ),
            condition("adb_wifi_pairing_recorded", {"endpoint": "192.0.2.1:5555"}),
            condition(
                "package_data_cleared",
                {"packages": ["com.example.one", "com.example.two"], "successCount": 2},
            ),
            condition(
                "logcat_buffers_cleared",
                {
                    "buffers": ("all",),
                    "preMarker": f"PF10_PRE_{'0' * 32}",
                    "postMarker": f"PF10_POST_{'1' * 32}",
                    "preStartMarker": f"PF10_PRE_START_{'2' * 32}",
                    "preEndMarker": f"PF10_PRE_END_{'3' * 32}",
                    "postStartMarker": f"PF10_POST_START_{'4' * 32}",
                    "postEndMarker": f"PF10_POST_END_{'5' * 32}",
                },
            ),
            condition(
                "view_intent_accepted",
                {
                    "targetSerial": SERIAL,
                    "scheme": "https",
                    "host": "example.test",
                    "urlSha256": DIGEST_A,
                },
            ),
            condition(
                "host_artifact_written",
                {
                    "path": str((Path.cwd() / "artifact.img").resolve()),
                    "sourceSha256": DIGEST_A,
                    "expectedSha256": DIGEST_B,
                    "requireDifferentSha256": True,
                    "minimumBytes": 1,
                    "maximumBytes": 1024,
                },
            ),
        ],
    )
    def test_accepts_bounded_typed_execution_evidence(
        self,
        postcondition: OperationPostcondition,
    ) -> None:
        OperationRunner()._validate_execution_postcondition(postcondition)

    @pytest.mark.parametrize(
        ("postcondition", "error", "message"),
        [
            (condition("partition_read_verified", {"partition": "boot"}), ValueError, "fields"),
            (
                condition(
                    "partition_read_verified",
                    {"targetSerial": "bad serial", "partition": "boot", "fileName": "boot.img"},
                ),
                ValueError,
                "identity",
            ),
            (
                condition("data_adb_backup_verified", {"fileName": "backup.pfdataadb", "extra": 1}),
                ValueError,
                "fields",
            ),
            (
                condition("data_adb_backup_verified", {"fileName": "../backup.pfdataadb"}),
                ValueError,
                "file name",
            ),
            (
                condition("data_adb_restore_verified", {"contentFingerprint": DIGEST_A}),
                ValueError,
                "fields",
            ),
            (
                condition(
                    "data_adb_restore_verified",
                    {"contentFingerprint": "bad", "entryCount": True},
                ),
                ValueError,
                "identity",
            ),
            (
                condition("package_export_verified", {"package": "com.example"}),
                ValueError,
                "fields",
            ),
            (
                condition(
                    "package_export_verified",
                    {"package": "not-a-package", "fileName": "app.exe"},
                ),
                ValueError,
                "identity",
            ),
            (
                condition("adb_wifi_pairing_recorded", {"endpoint": "host", "extra": 1}),
                ValueError,
                "fields",
            ),
            (
                condition("adb_wifi_pairing_recorded", {"endpoint": ""}),
                ValueError,
                "endpoint",
            ),
            (
                condition("package_data_cleared", {"packages": []}),
                ValueError,
                "fields",
            ),
            (
                condition("package_data_cleared", {"packages": "com.example", "successCount": 1}),
                TypeError,
                "bounded string array",
            ),
            (
                condition("package_data_cleared", {"packages": [], "successCount": 0}),
                TypeError,
                "bounded string array",
            ),
            (
                condition("package_data_cleared", {"packages": ["com.example"], "successCount": 0}),
                ValueError,
                "success count",
            ),
            (
                condition("logcat_buffers_cleared", {"buffers": ("all",)}),
                ValueError,
                "fields",
            ),
            (
                condition(
                    "logcat_buffers_cleared",
                    {
                        "buffers": ("main",),
                        "preMarker": "x",
                        "postMarker": "y",
                        "preStartMarker": "z",
                        "preEndMarker": "q",
                        "postStartMarker": "r",
                        "postEndMarker": "s",
                    },
                ),
                ValueError,
                "complete buffer",
            ),
            (
                condition(
                    "logcat_buffers_cleared",
                    {
                        "buffers": ("all",),
                        "preMarker": f"PF10_PRE_{'0' * 32}",
                        "postMarker": f"PF10_POST_{'0' * 32}",
                        "preStartMarker": f"PF10_PRE_START_{'0' * 32}",
                        "preEndMarker": f"PF10_PRE_END_{'0' * 32}",
                        "postStartMarker": f"PF10_POST_START_{'0' * 32}",
                        "postEndMarker": "invalid",
                    },
                ),
                ValueError,
                "markers",
            ),
            (
                condition("view_intent_accepted", {"targetSerial": SERIAL}),
                ValueError,
                "fields",
            ),
            (
                condition(
                    "view_intent_accepted",
                    {"targetSerial": "", "scheme": "https", "host": "example.test", "urlSha256": DIGEST_A},
                ),
                ValueError,
                "target serial",
            ),
            (
                condition(
                    "view_intent_accepted",
                    {"targetSerial": SERIAL, "scheme": "file", "host": "example.test", "urlSha256": DIGEST_A},
                ),
                ValueError,
                "scheme",
            ),
            (
                condition(
                    "view_intent_accepted",
                    {"targetSerial": SERIAL, "scheme": "https", "host": "bad host", "urlSha256": DIGEST_A},
                ),
                ValueError,
                "host",
            ),
            (
                condition(
                    "view_intent_accepted",
                    {"targetSerial": SERIAL, "scheme": "https", "host": "example.test", "urlSha256": "bad"},
                ),
                ValueError,
                "digest",
            ),
            (condition("unknown_execution_evidence", {}), ValueError, "no execution-evidence"),
            (
                condition(
                    "host_artifact_written",
                    {"path": str((Path.cwd() / "artifact.img").resolve()), "extra": 1},
                ),
                ValueError,
                "unknown fields",
            ),
            (
                condition("host_artifact_written", {"path": "relative.img"}),
                ValueError,
                "absolute",
            ),
            (
                condition(
                    "host_artifact_written",
                    {"path": str((Path.cwd() / "artifact.img").resolve()), "sourceSha256": "bad"},
                ),
                ValueError,
                "sourceSha256",
            ),
            (
                condition(
                    "host_artifact_written",
                    {
                        "path": str((Path.cwd() / "artifact.img").resolve()),
                        "requireDifferentSha256": 1,
                    },
                ),
                TypeError,
                "boolean",
            ),
            (
                condition(
                    "host_artifact_written",
                    {
                        "path": str((Path.cwd() / "artifact.img").resolve()),
                        "minimumBytes": 2,
                        "maximumBytes": 1,
                    },
                ),
                ValueError,
                "size bounds",
            ),
            (
                condition(
                    "host_artifact_written",
                    {
                        "path": str((Path.cwd() / "artifact.img").resolve()),
                        "requireDifferentSha256": True,
                    },
                ),
                ValueError,
                "source hash",
            ),
        ],
    )
    def test_rejects_ambiguous_execution_evidence(
        self,
        postcondition: OperationPostcondition,
        error: type[Exception],
        message: str,
    ) -> None:
        with pytest.raises(error, match=message):
            OperationRunner()._validate_execution_postcondition(postcondition)


class TestCallbackAndSnapshotObservation:
    def test_callback_observer_accepts_typed_boolean_and_mapping_results(self) -> None:
        runner = OperationRunner()
        plan = plan_for(condition("device_mode", {"mode": "adb"}))
        postcondition = plan.postconditions[0]
        snapshot = snapshot_with()

        typed = PostconditionObservation(True, "typed", False)
        assert runner._observe(plan, postcondition, snapshot, lambda *_: typed) is typed
        assert runner._observe(plan, postcondition, snapshot, lambda *_: True) == PostconditionObservation(True)
        assert runner._observe(
            plan,
            postcondition,
            snapshot,
            lambda *_: {"ok": False, "verified": False, "message": "not ready"},
        ) == PostconditionObservation(False, "not ready", False)

        class Observer:
            def observe(self, *_args: object) -> Mapping[str, object]:
                return {"satisfied": True}

        assert runner._observe(plan, postcondition, snapshot, Observer()).satisfied is True

    @pytest.mark.parametrize(
        ("observer", "message"),
        [
            (object(), "not callable"),
            (lambda *_: {"satisfied": "yes"}, "boolean satisfied"),
            (lambda *_: {"satisfied": True, "verified": 1}, "verified"),
            (lambda *_: {"satisfied": True, "message": 1}, "message"),
            (lambda *_: "yes", "invalid result"),
        ],
    )
    def test_callback_observer_rejects_ambiguous_results(
        self,
        observer: object,
        message: str,
    ) -> None:
        plan = plan_for(condition("device_mode", {"mode": "adb"}))
        with pytest.raises(TypeError, match=message):
            OperationRunner()._observe(
                plan,
                plan.postconditions[0],
                snapshot_with(),
                observer,  # type: ignore[arg-type]
            )

    @pytest.mark.parametrize(
        ("postcondition", "snapshot", "satisfied", "verified", "message"),
        [
            (
                condition("device_reachable", {}),
                AppSnapshot(),
                False,
                False,
                "unavailable",
            ),
            (
                condition("device_reachable", {}),
                snapshot_with(online=False),
                False,
                True,
                "offline",
            ),
            (
                condition("device_reachable", {"bootCompleted": True}),
                snapshot_with(),
                False,
                False,
                "not represented",
            ),
            (
                condition("device_reachable", {"mode": "system"}),
                snapshot_with(mode=""),
                False,
                False,
                "mode evidence",
            ),
            (
                condition("device_reachable", {"mode": "system"}),
                snapshot_with(mode="adb"),
                True,
                True,
                "",
            ),
            (
                condition("device_mode", {"mode": "bootloader"}),
                snapshot_with(mode="fastboot"),
                True,
                True,
                "",
            ),
            (
                condition("device_mode", {"mode": "adb"}),
                snapshot_with(online=False),
                False,
                True,
                "offline",
            ),
            (
                condition("device_mode", {"mode": "adb"}),
                snapshot_with(mode=""),
                False,
                False,
                "mode evidence",
            ),
            (
                condition("safe_mode_active", {"active": True}),
                snapshot_with(),
                False,
                False,
                "not represented",
            ),
            (
                condition("active_slot", {"slot": "a"}),
                snapshot_with(slot=""),
                False,
                False,
                "slot evidence",
            ),
            (
                condition("active_slot", {"slot": "a"}),
                snapshot_with(slot="a"),
                True,
                True,
                "",
            ),
            (
                condition("bootloader_state", {"state": "unlocked"}),
                snapshot_with(bootloader="unknown"),
                False,
                False,
                "bootloader state evidence",
            ),
            (
                condition("bootloader_state", {"state": "unlocked"}),
                snapshot_with(bootloader="unlocked"),
                True,
                True,
                "",
            ),
            (
                condition("unmapped", {}),
                snapshot_with(),
                False,
                False,
                "no observer",
            ),
        ],
    )
    def test_snapshot_observer_reports_evidence_quality(
        self,
        postcondition: OperationPostcondition,
        snapshot: AppSnapshot,
        satisfied: bool,
        verified: bool,
        message: str,
    ) -> None:
        plan = plan_for(postcondition)

        observed = OperationRunner()._observe(plan, postcondition, snapshot, None)

        assert observed.satisfied is satisfied
        assert observed.verified is verified
        assert message in observed.message
