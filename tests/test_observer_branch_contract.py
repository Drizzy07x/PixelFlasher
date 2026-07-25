from __future__ import annotations

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from pixelflasher_core import (
    CancellationToken,
    DeviceService,
    ToolchainInfo,
    TransportOutcome,
)
from pixelflasher_core.observer import (
    DeviceObservation,
    HostObservation,
    HostPostconditionSpec,
    ObservationProbeUnavailable,
    ObservationStatus,
    PostconditionObserver,
    PostconditionSpec,
    ProcessDeviceObservationProbe,
)
from tests.test_production_postcondition_observer import (
    SERIAL,
    FakeTime,
    StatefulDeviceTransport,
)

TOOLCHAIN = ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True)
SHA256_A = "a" * 64
SHA256_B = "b" * 64
SHA1_A = "a" * 40
PACKAGE = "com.example.app"
INSTALLER = "com.example.store"
ENDPOINT = "192.0.2.1:5555"
MODULE = "module.one"
PROFILE = "pif.custom_json"
TARGET_PROFILE = f"{PACKAGE}:json"
SU_STATE = "allow:1:1:0"


def _probe(
    transport: StatefulDeviceTransport | None = None,
    *,
    provider=lambda: TOOLCHAIN,
    **limits: object,
) -> ProcessDeviceObservationProbe:
    return ProcessDeviceObservationProbe(
        DeviceService(transport or StatefulDeviceTransport(mode="adb")),
        provider,
        **limits,
    )


class ObserverContractValidationTests(TestCase):
    def test_device_observation_rejects_every_invalid_evidence_family(self) -> None:
        cases = (
            {"safe_mode": "yes"},
            {"ota_idle": "yes"},
            {"shizuku_running": "yes"},
            {"magisk_modules_disabled": "yes"},
            {"data_adb_empty": "yes"},
            {"droidguard_cache_empty": "yes"},
            {"packages": {PACKAGE: "yes"}},
            {"package_states": {PACKAGE: True}},
            {"package_installers": {PACKAGE: "invalid"}},
            {"adb_endpoints": {ENDPOINT: "yes"}},
            {"root_modules": {MODULE: True}},
            {"root_module_versions": {MODULE: True}},
            {"pif_profiles": {"invalid": True}},
            {"pif_profile_hashes": {PROFILE: "bad"}},
            {"targeted_fix_targets": {"invalid": True}},
            {"targeted_fix_profile_hashes": {TARGET_PROFILE: "bad"}},
            {"magisk_denylist": {PACKAGE: "yes"}},
            {"magisk_su_policies": {True: SU_STATE}},
            {"magisk_backups": {SHA1_A: "unknown"}},
            {"erased_partitions": {"boot": "yes"}},
        )
        for values in cases:
            with self.subTest(values=values), self.assertRaises(TypeError):
                DeviceObservation(SERIAL, **values)

    def test_postcondition_spec_rejects_every_invalid_evidence_family(self) -> None:
        cases = (
            {"serial": ""},
            {"timeout_seconds": 0},
            {"expected_slot": "c"},
            {"expected_safe_mode": "yes"},
            {"expected_ota_idle": "yes"},
            {"expected_shizuku_running": "yes"},
            {"expected_magisk_modules_disabled": "yes"},
            {"expected_data_adb_empty": "yes"},
            {"expected_droidguard_cache_empty": "yes"},
            {"expected_packages": {PACKAGE: "yes"}},
            {"expected_package_states": {PACKAGE: "unknown"}},
            {"expected_package_installers": {PACKAGE: "invalid"}},
            {"expected_adb_endpoints": {"unsafe": True}},
            {"expected_root_modules": {MODULE: "unknown"}},
            {"expected_root_module_versions": {MODULE: True}},
            {"expected_pif_profiles": {"invalid": True}},
            {"expected_pif_profile_hashes": {PROFILE: "bad"}},
            {"expected_targeted_fix_targets": {"invalid": True}},
            {"expected_targeted_fix_profile_hashes": {TARGET_PROFILE: "bad"}},
            {"expected_magisk_denylist": {PACKAGE: "yes"}},
            {"expected_magisk_su_policies": {True: SU_STATE}},
            {"expected_magisk_backups": {SHA1_A: "corrupt"}},
            {"erased_partitions": ("boot", "boot")},
        )
        for overrides in cases:
            values: dict[str, object] = {
                "serial": SERIAL,
                "timeout_seconds": 1,
            }
            values.update(overrides)
            with self.subTest(overrides=overrides), self.assertRaises(
                (TypeError, ValueError),
            ):
                PostconditionSpec(**values)

    def test_host_contracts_validate_and_freeze_endpoint_evidence(self) -> None:
        for endpoints in ({ENDPOINT: "yes"}, {1: True}):
            with self.subTest(endpoints=endpoints), self.assertRaises(TypeError):
                HostObservation(endpoints)  # type: ignore[arg-type]
        for timeout, endpoints in (
            (0, {ENDPOINT: True}),
            (1, {}),
            (1, {"unsafe": True}),
        ):
            with self.subTest(timeout=timeout, endpoints=endpoints), self.assertRaises(ValueError):
                HostPostconditionSpec(timeout, endpoints)

        observed = HostObservation({ENDPOINT: True})
        with self.assertRaises(TypeError):
            observed.adb_endpoints[ENDPOINT] = False  # type: ignore[index]

    def test_probe_and_polling_limits_must_be_positive(self) -> None:
        for option in (
            {"command_timeout_seconds": 0},
            {"max_partition_bytes": 0},
            {"max_hash_targets": 0},
            {"max_remote_hash_targets": 0},
        ):
            with self.subTest(option=option), self.assertRaises(ValueError):
                _probe(**option)
        with self.assertRaises(ValueError):
            PostconditionObserver(object(), poll_interval_seconds=0)  # type: ignore[arg-type]


class ObserverComparisonBranchTests(TestCase):
    @staticmethod
    def _spec() -> PostconditionSpec:
        return PostconditionSpec(
            SERIAL,
            1,
            expected_mode="adb",
            expected_slot="a",
            expected_bootloader="unlocked",
            expected_boot_completed=True,
            expected_safe_mode=False,
            expected_build="BUILD",
            expected_ota_idle=True,
            expected_data_adb_empty=True,
            expected_droidguard_cache_empty=True,
            remote_hashes={"/data/local/tmp/file": SHA256_A},
            partition_hashes={"boot": SHA256_A},
            expected_packages={PACKAGE: True},
            expected_package_states={PACKAGE: "running"},
            expected_package_installers={PACKAGE: INSTALLER},
            expected_adb_endpoints={ENDPOINT: True},
            expected_root_modules={MODULE: "enabled"},
            expected_root_module_versions={MODULE: 7},
            expected_pif_profiles={PROFILE: True},
            expected_pif_profile_hashes={PROFILE: SHA256_A},
            expected_targeted_fix_targets={PACKAGE: True},
            expected_targeted_fix_profile_hashes={TARGET_PROFILE: SHA256_A},
            expected_magisk_denylist={PACKAGE: True},
            expected_magisk_su_policies={1000: SU_STATE},
            expected_magisk_backups={SHA1_A: "verified"},
            expected_shizuku_running=True,
            expected_magisk_modules_disabled=True,
            erased_partitions=("userdata",),
        )

    def test_compare_reports_every_missing_evidence_key(self) -> None:
        mismatches, missing = PostconditionObserver._compare(
            self._spec(),
            DeviceObservation("OTHER", connected=False),
        )
        self.assertEqual((SERIAL, "OTHER"), mismatches["serial"])
        expected_missing = {
            "connection",
            "mode",
            "slot",
            "bootloader",
            "boot_completed",
            "safe_mode",
            "build",
            "ota_idle",
            "data_adb_empty",
            "droidguard_cache_empty",
            "remote_hash:/data/local/tmp/file",
            "partition_hash:boot",
            f"package:{PACKAGE}",
            f"package_state:{PACKAGE}",
            f"package_installer:{PACKAGE}",
            f"adb_endpoint:{ENDPOINT}",
            f"root_module:{MODULE}",
            f"root_module_version:{MODULE}",
            f"pif_profile:{PROFILE}",
            f"pif_profile_hash:{PROFILE}",
            f"targeted_fix_target:{PACKAGE}",
            f"targeted_fix_profile_hash:{TARGET_PROFILE}",
            f"magisk_denylist:{PACKAGE}",
            "magisk_su_policy:1000",
            f"magisk_backup:{SHA1_A}",
            "shizuku_running",
            "magisk_modules_disabled",
            "partition_erased:userdata",
        }
        self.assertEqual(expected_missing, set(missing))

    def test_compare_reports_every_mismatch_family(self) -> None:
        observation = DeviceObservation(
            SERIAL,
            mode="fastboot",
            slot="b",
            bootloader="locked",
            boot_completed=False,
            safe_mode=True,
            build="OTHER",
            ota_idle=False,
            data_adb_empty=False,
            droidguard_cache_empty=False,
            remote_hashes={"/data/local/tmp/file": SHA256_B},
            partition_hashes={"boot": SHA256_B},
            packages={PACKAGE: False},
            package_states={PACKAGE: "stopped"},
            package_installers={PACKAGE: "com.other.store"},
            adb_endpoints={ENDPOINT: False},
            root_modules={MODULE: "disabled"},
            root_module_versions={MODULE: 8},
            pif_profiles={PROFILE: False},
            pif_profile_hashes={PROFILE: SHA256_B},
            targeted_fix_targets={PACKAGE: False},
            targeted_fix_profile_hashes={TARGET_PROFILE: SHA256_B},
            magisk_denylist={PACKAGE: False},
            magisk_su_policies={1000: "deny:0:0:1"},
            magisk_backups={SHA1_A: "absent"},
            shizuku_running=False,
            magisk_modules_disabled=False,
            erased_partitions={"userdata": False},
        )
        mismatches, missing = PostconditionObserver._compare(self._spec(), observation)
        self.assertFalse(missing)
        self.assertEqual(27, len(mismatches))

        match_values = {field: pair[0] for field, pair in mismatches.items()}
        self.assertEqual("adb", match_values["mode"])
        self.assertEqual(SHA256_A, match_values["partition_hash:boot"])

    def test_host_compare_distinguishes_missing_mismatch_and_match(self) -> None:
        spec = HostPostconditionSpec(1, {ENDPOINT: True})
        mismatch, missing = PostconditionObserver._compare_host(spec, HostObservation())
        self.assertFalse(mismatch)
        self.assertEqual((f"adb_endpoint:{ENDPOINT}",), missing)
        mismatch, missing = PostconditionObserver._compare_host(
            spec,
            HostObservation({ENDPOINT: False}),
        )
        self.assertFalse(missing)
        self.assertEqual((True, False), mismatch[f"adb_endpoint:{ENDPOINT}"])
        self.assertEqual(({}, ()), PostconditionObserver._compare_host(spec, HostObservation({ENDPOINT: True})))


class ObserverUtilityBranchTests(TestCase):
    def test_scalar_and_path_parsers_fail_closed_at_every_boundary(self) -> None:
        probe = ProcessDeviceObservationProbe
        self.assertIsNone(probe._single_value(""))
        self.assertIsNone(probe._single_value("a\nb"))
        self.assertIsNone(probe._single_value("a\x00b"))
        self.assertEqual("value", probe._single_value(" value\r\n"))
        self.assertFalse(probe._safe_property(""))
        self.assertFalse(probe._safe_property("x" * 257))
        self.assertFalse(probe._safe_property("x\x00"))
        self.assertTrue(probe._safe_property("BUILD"))

        for value in ("1", "true", "locked"):
            self.assertEqual("locked", probe._locked_state(value))
        for value in ("0", "false", "unlocked"):
            self.assertEqual("unlocked", probe._locked_state(value))
        self.assertIsNone(probe._locked_state("unknown"))
        for value in ("1", "true", "yes", "y", "unlocked"):
            self.assertIs(probe._boolean(value), True)
        for value in ("0", "false", "no", "n", "locked"):
            self.assertIs(probe._boolean(value), False)
        self.assertIsNone(probe._boolean(None))
        self.assertIsNone(probe._boolean("unknown"))

        self.assertTrue(probe._safe_remote_path("/data/local/tmp/file"))
        for path in ("relative", "/data/../file", "/" + "x" * 513):
            self.assertFalse(probe._safe_remote_path(path))
        self.assertTrue(probe._safe_partition("boot_a"))
        self.assertFalse(probe._safe_partition("../boot"))

    def test_transport_outcomes_have_strict_success_and_absence_semantics(self) -> None:
        probe = ProcessDeviceObservationProbe
        failures = (
            None,
            TransportOutcome(1),
            TransportOutcome(None, cancelled=True),
            TransportOutcome(None, timed_out=True),
            TransportOutcome(0, stdout="x" * 5),
        )
        for outcome in failures:
            with self.subTest(outcome=outcome):
                self.assertFalse(probe._successful(outcome, 4))
        self.assertTrue(probe._successful(TransportOutcome(0, "ok"), 4))

        for outcome in (
            None,
            TransportOutcome(None, cancelled=True),
            TransportOutcome(None, timed_out=True),
            TransportOutcome(0),
            TransportOutcome(1, stderr="other error"),
        ):
            self.assertFalse(probe._explicit_absence(outcome, SERIAL))
        self.assertTrue(
            probe._explicit_absence(
                TransportOutcome(1, stderr=f"error: device '{SERIAL}' not found"),
                SERIAL,
            ),
        )

    def test_hash_and_package_parsers_reject_ambiguous_output(self) -> None:
        probe = ProcessDeviceObservationProbe
        paths = ("/data/a", "/data/b")
        valid = TransportOutcome(
            0,
            f"{SHA256_A}  /data/a\n{SHA256_B}  /data/b\n",
        )
        self.assertEqual(
            {"/data/a": SHA256_A, "/data/b": SHA256_B},
            probe._parse_remote_hashes(valid, paths),
        )
        invalid_hashes = (
            None,
            TransportOutcome(0, f"{SHA256_A}  /data/a\n"),
            TransportOutcome(0, f"{SHA256_A}  /data/a\n", stderr="warning"),
            TransportOutcome(0, "not-a-hash  /data/a\n" + f"{SHA256_B}  /data/b\n"),
            TransportOutcome(0, f"{SHA256_A}  /data/a\n{SHA256_B}  /data/a\n"),
        )
        for outcome in invalid_hashes:
            self.assertEqual({}, probe._parse_remote_hashes(outcome, paths))

        self.assertIsNone(probe._package_installed(None))
        self.assertIsNone(probe._package_installed(TransportOutcome(0, stderr="warning")))
        self.assertFalse(probe._package_installed(TransportOutcome(0)))
        self.assertTrue(
            probe._package_installed(
                TransportOutcome(0, "package:/data/app/com.example/base.apk\n"),
            ),
        )
        self.assertIsNone(probe._package_installed(TransportOutcome(0, "unexpected\n")))

        self.assertIsNone(probe._package_list_contains(None, PACKAGE))
        self.assertIsNone(
            probe._package_list_contains(TransportOutcome(0, stderr="warning"), PACKAGE),
        )
        self.assertIsNone(
            probe._package_list_contains(TransportOutcome(0, "unexpected\n"), PACKAGE),
        )
        self.assertTrue(
            probe._package_list_contains(
                TransportOutcome(0, f"package:{PACKAGE}\n"),
                PACKAGE,
            ),
        )

        process_cases = (
            (None, None),
            (TransportOutcome(None, cancelled=True), None),
            (TransportOutcome(0, "x" * 4097), None),
            (TransportOutcome(0, stderr="warning"), None),
            (TransportOutcome(1), "stopped"),
            (TransportOutcome(2, "123"), None),
            (TransportOutcome(0, "abc"), None),
            (TransportOutcome(0, "123 456"), "running"),
        )
        for outcome, expected in process_cases:
            self.assertEqual(expected, probe._package_process_state(outcome))

    def test_bounded_file_readback_rejects_short_long_invalid_and_unreadable_files(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            exact = root / "exact.bin"
            exact.write_bytes(b"\x00\xff")
            self.assertEqual(
                hashlib.sha256(b"\x00\xff").hexdigest(),
                ProcessDeviceObservationProbe._bounded_file_sha256(exact, 2),
            )
            self.assertTrue(ProcessDeviceObservationProbe._bounded_erased_content(exact, 2))
            exact.write_bytes(b"\x00\x01")
            self.assertFalse(ProcessDeviceObservationProbe._bounded_erased_content(exact, 2))
            for size in (0, -1):
                self.assertIsNone(ProcessDeviceObservationProbe._bounded_file_sha256(exact, size))
                self.assertIsNone(ProcessDeviceObservationProbe._bounded_erased_content(exact, size))

            short = root / "short.bin"
            short.write_bytes(b"x")
            long = root / "long.bin"
            long.write_bytes(b"xxx")
            missing = root / "missing.bin"
            for path in (short, long, missing):
                self.assertIsNone(ProcessDeviceObservationProbe._bounded_file_sha256(path, 2))
                self.assertIsNone(ProcessDeviceObservationProbe._bounded_erased_content(path, 2))


class ObserverPollingBranchTests(TestCase):
    def test_probe_front_doors_handle_invalid_cancelled_and_unavailable_state(self) -> None:
        self.assertIsNone(_probe().observe(""))
        unavailable = _probe(provider=lambda: (_ for _ in ()).throw(RuntimeError("injected")))
        self.assertIsNone(unavailable.observe(SERIAL))

        cancelled = CancellationToken()
        cancelled.cancel()
        self.assertIsNone(_probe().observe_spec(PostconditionSpec(SERIAL, 1), cancelled))
        with self.assertRaises(ObservationProbeUnavailable):
            _probe().observe_spec(PostconditionSpec("bad serial", 1), CancellationToken())
        with self.assertRaises(ObservationProbeUnavailable):
            unavailable.observe_spec(PostconditionSpec(SERIAL, 1), CancellationToken())
        with self.assertRaises(ObservationProbeUnavailable):
            _probe(provider=lambda: ToolchainInfo()).observe_spec(
                PostconditionSpec(SERIAL, 1),
                CancellationToken(),
            )

        host_spec = HostPostconditionSpec(1, {ENDPOINT: True})
        self.assertIsNone(_probe().observe_host_spec(host_spec, cancelled))
        with self.assertRaises(ObservationProbeUnavailable):
            unavailable.observe_host_spec(host_spec, CancellationToken())
        with self.assertRaises(ObservationProbeUnavailable):
            _probe(provider=lambda: ToolchainInfo()).observe_host_spec(
                host_spec,
                CancellationToken(),
            )

    def test_run_returns_none_for_cancellation_and_transport_errors(self) -> None:
        probe = _probe()
        token = CancellationToken()
        token.cancel()
        self.assertIsNone(probe._run(("ADB", "devices", "-l"), token, 1))
        with patch.object(probe.transport, "run", side_effect=RuntimeError("injected")):
            self.assertIsNone(
                probe._run(("ADB", "devices", "-l"), CancellationToken(), 1),
            )

    def test_device_and_host_polling_return_every_terminal_status(self) -> None:
        class UnavailableProbe:
            def observe_spec(self, _spec, _token):
                raise ObservationProbeUnavailable("injected")

        unavailable = PostconditionObserver(UnavailableProbe())
        result = unavailable.verify(PostconditionSpec(SERIAL, 1))
        self.assertEqual(ObservationStatus.UNVERIFIED, result.status)
        self.assertEqual(("probe",), result.missing)

        class LegacyProbe:
            def observe(self, _serial):
                return None

        host_spec = HostPostconditionSpec(0.1, {ENDPOINT: True})
        result = PostconditionObserver(LegacyProbe()).verify_host(host_spec)
        self.assertEqual(ObservationStatus.UNVERIFIED, result.status)
        self.assertEqual(("probe",), result.missing)

        class HostProbe:
            def __init__(self, result=None, *, unavailable=False):
                self.result = result
                self.unavailable = unavailable

            def observe_host_spec(self, _spec, _token):
                if self.unavailable:
                    raise ObservationProbeUnavailable("injected")
                return self.result

        token = CancellationToken()
        token.cancel()
        cancelled = PostconditionObserver(HostProbe()).verify_host(host_spec, token)
        self.assertEqual(ObservationStatus.CANCELLED, cancelled.status)

        result = PostconditionObserver(HostProbe(unavailable=True)).verify_host(host_spec)
        self.assertEqual(ObservationStatus.UNVERIFIED, result.status)
        self.assertEqual(("probe",), result.missing)

        for observation, expected in (
            (HostObservation({ENDPOINT: True}), ObservationStatus.VERIFIED),
            (HostObservation({ENDPOINT: False}), ObservationStatus.MISMATCH),
            (HostObservation(), ObservationStatus.UNVERIFIED),
            (None, ObservationStatus.UNVERIFIED),
        ):
            timer = FakeTime()
            observer = PostconditionObserver(
                HostProbe(observation),
                poll_interval_seconds=0.1,
                clock=timer.clock,
                sleeper=timer.sleep,
            )
            result = observer.verify_host(host_spec)
            self.assertEqual(expected, result.status)

        self.assertTrue(
            PostconditionObserver(HostProbe(HostObservation({ENDPOINT: True})))
            .verify_host(host_spec)
            .verified,
        )


class ObserverProbeHelperBranchTests(TestCase):
    def test_host_observation_and_adb_mode_fallbacks_are_explicit(self) -> None:
        transport = StatefulDeviceTransport(
            mode="adb",
            adb_endpoints={ENDPOINT: "device"},
        )
        observed = _probe(transport).observe_host_spec(
            HostPostconditionSpec(1, {ENDPOINT: True}),
            CancellationToken(),
        )
        self.assertEqual({ENDPOINT: True}, dict(observed.adb_endpoints if observed else {}))

        probe = _probe()
        base = PostconditionSpec(SERIAL, 1, expected_mode="adb")
        with patch.object(probe, "_run", return_value=TransportOutcome(0, "unknown\n")):
            self.assertIsNone(
                probe._observe_adb(base, TOOLCHAIN, CancellationToken(), 1).observation,
            )

        recovery = PostconditionSpec(SERIAL, 1, expected_mode="recovery")
        with patch.object(probe, "_adb_property", return_value="recovery"):
            observation = probe._observe_adb(
                recovery,
                TOOLCHAIN,
                CancellationToken(),
                1,
            ).observation
        self.assertEqual("recovery", observation.mode if observation else None)

        bootloader = PostconditionSpec(
            SERIAL,
            1,
            expected_bootloader="unlocked",
        )
        with patch.object(
            probe,
            "_adb_property",
            side_effect=("normal", "unknown", "unlocked"),
        ):
            observation = probe._observe_adb(
                bootloader,
                TOOLCHAIN,
                CancellationToken(),
                1,
            ).observation
        self.assertEqual("unlocked", observation.bootloader if observation else None)
        with patch.object(
            probe,
            "_adb_property",
            side_effect=("normal", "unknown", "unknown"),
        ):
            observation = probe._observe_adb(
                bootloader,
                TOOLCHAIN,
                CancellationToken(),
                1,
            ).observation
        self.assertIsNone(observation.bootloader if observation else "missing")

        incomplete = PostconditionSpec(
            SERIAL,
            1,
            expected_boot_completed=True,
            expected_build="BUILD",
        )
        with patch.object(
            probe,
            "_adb_property",
            side_effect=("normal", "unknown", ""),
        ):
            observation = probe._observe_adb(
                incomplete,
                TOOLCHAIN,
                CancellationToken(),
                1,
            ).observation
        self.assertIsNone(observation.boot_completed if observation else "missing")
        self.assertIsNone(observation.build if observation else "missing")

    def test_fastboot_legacy_and_unknown_lock_evidence_remain_bounded(self) -> None:
        probe = _probe(StatefulDeviceTransport(mode="fastboot"))
        spec = PostconditionSpec(
            SERIAL,
            1,
            expected_mode="fastboot",
            expected_bootloader="locked",
        )
        with (
            patch.object(
                probe,
                "_run",
                side_effect=(TransportOutcome(1), TransportOutcome(0, "product: akita\n")),
            ),
            patch.object(probe, "_fastboot_value", side_effect=(None, "akita")),
            patch.object(probe, "_fastboot_getvar", return_value=None),
        ):
            observation = probe._observe_fastboot(
                spec,
                TOOLCHAIN,
                CancellationToken(),
                1,
            ).observation
        self.assertEqual("fastboot", observation.mode if observation else None)
        self.assertIsNone(observation.bootloader if observation else "missing")

    def test_remote_package_and_installer_helpers_cover_unverified_evidence(self) -> None:
        probe = _probe()
        token = CancellationToken()
        remote = PostconditionSpec(
            SERIAL,
            1,
            remote_hashes={"/data/a": SHA256_A},
        )
        valid_hash = TransportOutcome(0, f"{SHA256_A}  /data/a\n")
        with patch.object(probe, "_run", side_effect=(TransportOutcome(1), valid_hash)):
            self.assertEqual(
                {"/data/a": SHA256_A},
                probe._remote_hashes(remote, TOOLCHAIN, "adb", token, 1),
            )
        with patch.object(probe, "_run", return_value=TransportOutcome(1)):
            self.assertEqual({}, probe._remote_hashes(remote, TOOLCHAIN, "adb", token, 1))

        cancelled = CancellationToken()
        cancelled.cancel()
        packages = PostconditionSpec(SERIAL, 1, expected_packages={PACKAGE: True})
        self.assertEqual({}, probe._packages(packages, TOOLCHAIN, "adb", cancelled, 1))
        invalid_package = PostconditionSpec(SERIAL, 1, expected_packages={"bad": True})
        self.assertEqual(
            {},
            probe._packages(invalid_package, TOOLCHAIN, "adb", CancellationToken(), 1),
        )
        with patch.object(probe, "_package_installed", return_value=None):
            self.assertEqual(
                {},
                probe._packages(packages, TOOLCHAIN, "adb", CancellationToken(), 1),
            )

        state_specs = {
            "invalid": PostconditionSpec(
                SERIAL,
                1,
                expected_package_states={"bad": "enabled"},
            ),
            "enabled": PostconditionSpec(
                SERIAL,
                1,
                expected_package_states={PACKAGE: "enabled"},
            ),
            "running": PostconditionSpec(
                SERIAL,
                1,
                expected_package_states={PACKAGE: "running"},
            ),
        }
        self.assertEqual(
            {},
            probe._package_states(
                state_specs["invalid"],
                TOOLCHAIN,
                "adb",
                CancellationToken(),
                1,
            ),
        )
        with patch.object(probe, "_package_installed", return_value=None):
            self.assertEqual(
                {},
                probe._package_states(
                    state_specs["enabled"],
                    TOOLCHAIN,
                    "adb",
                    CancellationToken(),
                    1,
                ),
            )
        with (
            patch.object(probe, "_package_installed", return_value=True),
            patch.object(probe, "_package_list_contains", return_value=None),
        ):
            self.assertEqual(
                {},
                probe._package_states(
                    state_specs["enabled"],
                    TOOLCHAIN,
                    "adb",
                    CancellationToken(),
                    1,
                ),
            )
        with (
            patch.object(probe, "_package_installed", return_value=True),
            patch.object(probe, "_package_process_state", return_value=None),
        ):
            self.assertEqual(
                {},
                probe._package_states(
                    state_specs["running"],
                    TOOLCHAIN,
                    "adb",
                    CancellationToken(),
                    1,
                ),
            )

        installers = PostconditionSpec(
            SERIAL,
            1,
            expected_package_installers={PACKAGE: INSTALLER},
        )
        self.assertEqual(
            {},
            probe._package_installers(installers, TOOLCHAIN, "adb", cancelled, 1),
        )
        with patch.object(probe, "_run", return_value=TransportOutcome(1)):
            self.assertEqual(
                {},
                probe._package_installers(
                    installers,
                    TOOLCHAIN,
                    "adb",
                    CancellationToken(),
                    1,
                ),
            )
        with patch.object(
            probe,
            "_run",
            return_value=TransportOutcome(0, f"package:{PACKAGE} installer=bad\n"),
        ):
            self.assertEqual(
                {},
                probe._package_installers(
                    installers,
                    TOOLCHAIN,
                    "adb",
                    CancellationToken(),
                    1,
                ),
            )

    def test_root_module_helpers_do_not_infer_state_from_partial_evidence(self) -> None:
        probe = _probe()
        token = CancellationToken()
        module_spec = PostconditionSpec(
            SERIAL,
            1,
            expected_root_modules={MODULE: "enabled"},
        )
        with (
            patch.object(probe, "_root_available", return_value=True),
            patch.object(probe, "_root_test", return_value=None),
        ):
            self.assertEqual(
                {},
                probe._root_modules(module_spec, TOOLCHAIN, "adb", token, 1),
            )
        with (
            patch.object(probe, "_root_available", return_value=True),
            patch.object(probe, "_root_test", return_value=False),
        ):
            self.assertEqual(
                {MODULE: "absent"},
                probe._root_modules(module_spec, TOOLCHAIN, "adb", token, 1),
            )
        with (
            patch.object(probe, "_root_available", return_value=True),
            patch.object(probe, "_root_test", side_effect=(True, None, False)),
        ):
            self.assertEqual(
                {},
                probe._root_modules(module_spec, TOOLCHAIN, "adb", token, 1),
            )
        invalid = PostconditionSpec(
            SERIAL,
            1,
            expected_root_modules={"../bad": "enabled"},
        )
        with patch.object(probe, "_root_available", return_value=True):
            self.assertEqual(
                {},
                probe._root_modules(invalid, TOOLCHAIN, "adb", token, 1),
            )

        versions = PostconditionSpec(
            SERIAL,
            1,
            expected_root_module_versions={MODULE: 7},
        )
        cancelled = CancellationToken()
        cancelled.cancel()
        with patch.object(probe, "_root_available", return_value=True):
            self.assertEqual(
                {},
                probe._root_module_versions(
                    versions,
                    TOOLCHAIN,
                    "adb",
                    cancelled,
                    1,
                ),
            )
        with (
            patch.object(probe, "_root_available", return_value=True),
            patch.object(probe, "_run", return_value=TransportOutcome(1)),
        ):
            self.assertEqual(
                {},
                probe._root_module_versions(
                    versions,
                    TOOLCHAIN,
                    "adb",
                    token,
                    1,
                ),
            )
        for output in ("not-a-number", "2147483648"):
            with (
                patch.object(probe, "_root_available", return_value=True),
                patch.object(probe, "_run", return_value=TransportOutcome(0, output)),
            ):
                self.assertEqual(
                    {},
                    probe._root_module_versions(
                        versions,
                        TOOLCHAIN,
                        "adb",
                        token,
                        1,
                    ),
                )

    def test_root_feature_helpers_require_complete_independent_evidence(self) -> None:
        probe = _probe()
        token = CancellationToken()

        shizuku = PostconditionSpec(SERIAL, 1, expected_shizuku_running=True)
        with patch.object(probe, "_run", return_value=TransportOutcome(1)):
            self.assertIsNone(
                probe._shizuku_running(shizuku, TOOLCHAIN, "adb", token, 1),
            )

        families = (
            (
                "_pif_profile_states",
                PostconditionSpec(SERIAL, 1, expected_pif_profiles={PROFILE: True}),
            ),
            (
                "_pif_profile_hashes",
                PostconditionSpec(
                    SERIAL,
                    1,
                    expected_pif_profile_hashes={PROFILE: SHA256_A},
                ),
            ),
            (
                "_targeted_fix_target_states",
                PostconditionSpec(
                    SERIAL,
                    1,
                    expected_targeted_fix_targets={PACKAGE: True},
                ),
            ),
            (
                "_targeted_fix_profile_hashes",
                PostconditionSpec(
                    SERIAL,
                    1,
                    expected_targeted_fix_profile_hashes={TARGET_PROFILE: SHA256_A},
                ),
            ),
            (
                "_magisk_denylist_states",
                PostconditionSpec(
                    SERIAL,
                    1,
                    expected_magisk_denylist={PACKAGE: True},
                ),
            ),
            (
                "_magisk_su_policies",
                PostconditionSpec(
                    SERIAL,
                    1,
                    expected_magisk_su_policies={1000: SU_STATE},
                ),
            ),
            (
                "_magisk_backup_states",
                PostconditionSpec(
                    SERIAL,
                    1,
                    expected_magisk_backups={SHA1_A: "verified"},
                ),
            ),
        )
        for name, spec in families:
            with (
                self.subTest(name=name),
                patch.object(probe, "_root_available", return_value=False),
            ):
                self.assertEqual(
                    {},
                    getattr(probe, name)(spec, TOOLCHAIN, "adb", token, 1),
                )

        modules = PostconditionSpec(
            SERIAL,
            1,
            expected_magisk_modules_disabled=True,
        )
        droidguard = PostconditionSpec(
            SERIAL,
            1,
            expected_droidguard_cache_empty=True,
        )
        for name, spec in (
            ("_magisk_modules_disabled", modules),
            ("_droidguard_cache_empty", droidguard),
        ):
            with patch.object(probe, "_root_available", return_value=False):
                self.assertIsNone(
                    getattr(probe, name)(spec, TOOLCHAIN, "adb", token, 1),
                )

        outcomes = (
            None,
            TransportOutcome(None, timed_out=True),
            TransportOutcome(None, cancelled=True),
            TransportOutcome(0, output_limited=True),
            TransportOutcome(2),
        )
        for outcome in outcomes:
            with (
                patch.object(probe, "_root_available", return_value=True),
                patch.object(probe, "_run", return_value=outcome),
            ):
                self.assertIsNone(
                    probe._magisk_modules_disabled(
                        modules,
                        TOOLCHAIN,
                        "adb",
                        token,
                        1,
                    ),
                )

    def test_profile_and_magisk_parsers_skip_malformed_or_cancelled_rows(self) -> None:
        probe = _probe()
        token = CancellationToken()
        cancelled = CancellationToken()
        cancelled.cancel()

        pif_state = SimpleNamespace(
            serial=SERIAL,
            expected_pif_profiles={"invalid": True},
        )
        with patch.object(probe, "_root_available", return_value=True):
            self.assertEqual(
                {},
                probe._pif_profile_states(
                    pif_state,
                    TOOLCHAIN,
                    "adb",
                    cancelled,
                    1,
                ),
            )
            self.assertEqual(
                {},
                probe._pif_profile_states(
                    pif_state,
                    TOOLCHAIN,
                    "adb",
                    token,
                    1,
                ),
            )
        valid_pif_state = PostconditionSpec(
            SERIAL,
            1,
            expected_pif_profiles={PROFILE: True},
        )
        with (
            patch.object(probe, "_root_available", return_value=True),
            patch.object(probe, "_root_test", return_value=None),
        ):
            self.assertEqual(
                {},
                probe._pif_profile_states(
                    valid_pif_state,
                    TOOLCHAIN,
                    "adb",
                    token,
                    1,
                ),
            )
        pif_hash = PostconditionSpec(
            SERIAL,
            1,
            expected_pif_profile_hashes={PROFILE: SHA256_A},
        )
        with patch.object(probe, "_root_available", return_value=True):
            self.assertEqual(
                {},
                probe._pif_profile_hashes(
                    pif_hash,
                    TOOLCHAIN,
                    "adb",
                    cancelled,
                    1,
                ),
            )
        with (
            patch.object(probe, "_root_available", return_value=True),
            patch.object(probe, "_run", return_value=TransportOutcome(1)),
        ):
            self.assertEqual(
                {},
                probe._pif_profile_hashes(pif_hash, TOOLCHAIN, "adb", token, 1),
            )
        with (
            patch.object(probe, "_root_available", return_value=True),
            patch.object(probe, "_run", return_value=TransportOutcome(0, "bad")),
        ):
            self.assertEqual(
                {},
                probe._pif_profile_hashes(pif_hash, TOOLCHAIN, "adb", token, 1),
            )

        target = PostconditionSpec(
            SERIAL,
            1,
            expected_targeted_fix_targets={PACKAGE: True},
        )
        with patch.object(probe, "_root_available", return_value=True):
            self.assertEqual(
                {},
                probe._targeted_fix_target_states(
                    target,
                    TOOLCHAIN,
                    "adb",
                    cancelled,
                    1,
                ),
            )
        with (
            patch.object(probe, "_root_available", return_value=True),
            patch.object(probe, "_root_test", return_value=None),
        ):
            self.assertEqual(
                {},
                probe._targeted_fix_target_states(
                    target,
                    TOOLCHAIN,
                    "adb",
                    token,
                    1,
                ),
            )
        target_hash = PostconditionSpec(
            SERIAL,
            1,
            expected_targeted_fix_profile_hashes={TARGET_PROFILE: SHA256_A},
        )
        with patch.object(probe, "_root_available", return_value=True):
            self.assertEqual(
                {},
                probe._targeted_fix_profile_hashes(
                    target_hash,
                    TOOLCHAIN,
                    "adb",
                    cancelled,
                    1,
                ),
            )
        with (
            patch.object(probe, "_root_available", return_value=True),
            patch.object(probe, "_run", return_value=TransportOutcome(1)),
        ):
            self.assertEqual(
                {},
                probe._targeted_fix_profile_hashes(
                    target_hash,
                    TOOLCHAIN,
                    "adb",
                    token,
                    1,
                ),
            )
        with (
            patch.object(probe, "_root_available", return_value=True),
            patch.object(probe, "_run", return_value=TransportOutcome(0, "bad")),
        ):
            self.assertEqual(
                {},
                probe._targeted_fix_profile_hashes(
                    target_hash,
                    TOOLCHAIN,
                    "adb",
                    token,
                    1,
                ),
            )

        denylist = PostconditionSpec(
            SERIAL,
            1,
            expected_magisk_denylist={PACKAGE: True},
        )
        with (
            patch.object(probe, "_root_available", return_value=True),
            patch.object(probe, "_run", return_value=TransportOutcome(1)),
        ):
            self.assertEqual(
                {},
                probe._magisk_denylist_states(
                    denylist,
                    TOOLCHAIN,
                    "adb",
                    token,
                    1,
                ),
            )
        with (
            patch.object(probe, "_root_available", return_value=True),
            patch.object(probe, "_run", return_value=TransportOutcome(0, "invalid\n")),
        ):
            self.assertEqual(
                {PACKAGE: False},
                probe._magisk_denylist_states(
                    denylist,
                    TOOLCHAIN,
                    "adb",
                    token,
                    1,
                ),
            )

        policy = PostconditionSpec(
            SERIAL,
            1,
            expected_magisk_su_policies={1000: SU_STATE},
        )
        with patch.object(probe, "_root_available", return_value=True):
            self.assertEqual(
                {},
                probe._magisk_su_policies(
                    policy,
                    TOOLCHAIN,
                    "adb",
                    cancelled,
                    1,
                ),
            )
        for outcome in (
            TransportOutcome(1),
            TransportOutcome(0, "one\ntwo\n"),
            TransportOutcome(0, "PF_SU|2000|2|1|1|0\n"),
        ):
            with (
                patch.object(probe, "_root_available", return_value=True),
                patch.object(probe, "_run", return_value=outcome),
            ):
                self.assertEqual(
                    {},
                    probe._magisk_su_policies(
                        policy,
                        TOOLCHAIN,
                        "adb",
                        token,
                        1,
                    ),
                )

        backup = PostconditionSpec(
            SERIAL,
            1,
            expected_magisk_backups={SHA1_A: "verified"},
        )
        with patch.object(probe, "_root_available", return_value=True):
            self.assertEqual(
                {},
                probe._magisk_backup_states(
                    backup,
                    TOOLCHAIN,
                    "adb",
                    cancelled,
                    1,
                ),
            )
        for outcome in (TransportOutcome(1), TransportOutcome(0, "UNKNOWN\n")):
            with (
                patch.object(probe, "_root_available", return_value=True),
                patch.object(probe, "_run", return_value=outcome),
            ):
                self.assertEqual(
                    {},
                    probe._magisk_backup_states(
                        backup,
                        TOOLCHAIN,
                        "adb",
                        token,
                        1,
                    ),
                )

    def test_adb_inventory_endpoint_validation_and_parser_are_closed(self) -> None:
        probe = _probe()
        for endpoint in (
            1,
            "x",
            "hostname:5555",
            "0.0.0.0:5555",
            "224.0.0.1:5555",
            "192.0.2.1:0",
            "192.0.2.1:65536",
        ):
            self.assertFalse(ProcessDeviceObservationProbe.safe_adb_endpoint(endpoint))  # type: ignore[arg-type]

        spec = HostPostconditionSpec(1, {ENDPOINT: True})
        cancelled = CancellationToken()
        cancelled.cancel()
        self.assertEqual(
            {},
            probe._adb_endpoint_states(spec, TOOLCHAIN, cancelled, 1),
        )
        with patch.object(probe, "_run", return_value=TransportOutcome(1)):
            self.assertEqual(
                {},
                probe._adb_endpoint_states(
                    spec,
                    TOOLCHAIN,
                    CancellationToken(),
                    1,
                ),
            )

        parser = ProcessDeviceObservationProbe._parse_adb_device_states
        invalid = (
            None,
            TransportOutcome(0, "List of devices attached\n", stderr="warning"),
            TransportOutcome(0, "wrong header\n"),
            TransportOutcome(0, "List of devices attached\nmalformed\n"),
            TransportOutcome(
                0,
                f"List of devices attached\n{ENDPOINT} device\n{ENDPOINT} offline\n",
            ),
        )
        for outcome in invalid:
            self.assertIsNone(parser(outcome))

    def test_root_test_partition_and_property_helpers_fail_closed(self) -> None:
        probe = _probe()
        token = CancellationToken()
        for outcome in (
            None,
            TransportOutcome(None, timed_out=True),
            TransportOutcome(0, stdout="unexpected"),
            TransportOutcome(2),
        ):
            with patch.object(probe, "_run", return_value=outcome):
                self.assertIsNone(
                    probe._root_test(TOOLCHAIN, SERIAL, "test -e /x", token, 1),
                )

        hash_spec = PostconditionSpec(
            SERIAL,
            1,
            partition_hashes={"boot": SHA256_A},
        )
        erased_spec = PostconditionSpec(SERIAL, 1, erased_partitions=("userdata",))
        cancelled = CancellationToken()
        cancelled.cancel()
        self.assertEqual(
            {},
            probe._partition_hashes(hash_spec, TOOLCHAIN, cancelled, 1),
        )
        self.assertEqual(
            {},
            probe._erased_partitions(erased_spec, TOOLCHAIN, cancelled, 1),
        )
        for method, spec in (
            (probe._partition_hashes, hash_spec),
            (probe._erased_partitions, erased_spec),
        ):
            with patch.object(probe, "_partition_size", return_value=None):
                self.assertEqual({}, method(spec, TOOLCHAIN, token, 1))
            with (
                patch.object(probe, "_partition_size", return_value=1),
                patch.object(probe, "_fetch_supported", return_value=False),
            ):
                self.assertEqual({}, method(spec, TOOLCHAIN, token, 1))
            fetch_name = (
                "_fetch_partition_hash"
                if method == probe._partition_hashes
                else "_fetch_partition_erased"
            )
            with (
                patch.object(probe, "_partition_size", return_value=1),
                patch.object(probe, "_fetch_supported", return_value=True),
                patch.object(probe, fetch_name, return_value=None),
            ):
                self.assertEqual({}, method(spec, TOOLCHAIN, token, 1))

        two_hashes = PostconditionSpec(
            SERIAL,
            1,
            partition_hashes={"boot": SHA256_A, "vendor": SHA256_A},
        )
        two_erased = PostconditionSpec(
            SERIAL,
            1,
            erased_partitions=("userdata", "metadata"),
        )
        for method, spec, fetch_name in (
            (probe._partition_hashes, two_hashes, "_fetch_partition_hash"),
            (probe._erased_partitions, two_erased, "_fetch_partition_erased"),
        ):
            with (
                patch.object(probe, "_partition_size", return_value=1),
                patch.object(probe, "_fetch_supported", return_value=True) as supported,
                patch.object(probe, fetch_name, return_value=None),
            ):
                self.assertEqual({}, method(spec, TOOLCHAIN, token, 1))
            supported.assert_called_once()

        with patch.object(probe, "_run", return_value=TransportOutcome(1)):
            self.assertIsNone(probe._partition_size(TOOLCHAIN, SERIAL, "boot", token, 1))
            self.assertFalse(probe._fetch_supported(TOOLCHAIN, SERIAL, token, 1))
            self.assertIsNone(
                probe._adb_property(TOOLCHAIN, SERIAL, "ro.build.id", token, 1),
            )
            self.assertIsNone(probe._ota_idle(TOOLCHAIN, SERIAL, token, 1))
            self.assertIsNone(
                probe._fastboot_value(TransportOutcome(1), "current-slot"),
            )
        with patch.object(probe, "_run", return_value=TransportOutcome(0, "noise\n")):
            self.assertIsNone(probe._partition_size(TOOLCHAIN, SERIAL, "boot", token, 1))

    def test_partition_fetch_rejects_missing_wrong_sized_and_os_error_outputs(self) -> None:
        probe = _probe()
        token = CancellationToken()
        for method in (probe._fetch_partition_hash, probe._fetch_partition_erased):
            with patch.object(probe, "_run", return_value=TransportOutcome(1)):
                self.assertIsNone(method(TOOLCHAIN, SERIAL, "boot", 2, token, 1))
            with patch.object(probe, "_run", return_value=TransportOutcome(0)):
                self.assertIsNone(method(TOOLCHAIN, SERIAL, "boot", 2, token, 1))

            def write_wrong_size(request, _token):
                Path(request.argv[-1]).write_bytes(b"x")
                return TransportOutcome(0)

            with patch.object(probe.transport, "run", side_effect=write_wrong_size):
                self.assertIsNone(method(TOOLCHAIN, SERIAL, "boot", 2, token, 1))

            with patch(
                "pixelflasher_core.observer.tempfile.TemporaryDirectory",
                side_effect=OSError("injected"),
            ):
                self.assertIsNone(method(TOOLCHAIN, SERIAL, "boot", 2, token, 1))
