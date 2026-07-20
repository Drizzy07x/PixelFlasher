from __future__ import annotations

import hashlib
import re
import tempfile
import unittest
from pathlib import Path

from pixelflasher_core.contracts import ProcessRequest, ToolchainInfo
from pixelflasher_core.devices import DeviceService
from pixelflasher_core.executor import CancellationToken, TransportOutcome
from pixelflasher_core.observer import (
    ObservationStatus,
    PostconditionObserver,
    PostconditionSpec,
    ProcessDeviceObservationProbe,
)

SERIAL = "ABCDEF123456"
TOOLCHAIN = ToolchainInfo("ADB", "FASTBOOT", "36.0.0", True)


class FakeTime:
    def __init__(self) -> None:
        self.now = 0.0

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class StatefulDeviceTransport:
    """Small serial-aware fake for production observation argv."""

    def __init__(
        self,
        *,
        mode: str,
        properties: dict[str, str] | None = None,
        remote_hashes: dict[str, str] | None = None,
        packages: set[str] | None = None,
        package_states: dict[str, str] | None = None,
        package_installers: dict[str, str] | None = None,
        adb_endpoints: dict[str, str] | None = None,
        root_modules: dict[str, str] | None = None,
        pif_profiles: set[str] | None = None,
        pif_profile_hashes: dict[str, str] | None = None,
        targeted_fix_targets: set[str] | None = None,
        targeted_fix_profile_hashes: dict[str, str] | None = None,
        magisk_denylist: set[str] | None = None,
        magisk_su_policies: dict[int, str] | None = None,
        magisk_backups: dict[str, str] | None = None,
        shizuku_running: bool = False,
        all_modules_disabled: bool = False,
        data_adb_empty: bool = False,
        droidguard_cache_empty: bool = False,
        root_available: bool = True,
        partitions: dict[str, bytes] | None = None,
        partition_sizes: dict[str, int] | None = None,
        fetch_supported: bool = True,
        ota_status_output: str | None = None,
        serial: str = SERIAL,
    ) -> None:
        self.serial = serial
        self.mode = mode
        self.properties = properties or {}
        self.remote_hashes = remote_hashes or {}
        self.packages = packages or set()
        self.package_states = package_states or {}
        self.package_installers = package_installers or {}
        self.adb_endpoints = adb_endpoints or {}
        self.root_modules = root_modules or {}
        self.pif_profiles = pif_profiles or set()
        self.pif_profile_hashes = pif_profile_hashes or {}
        self.targeted_fix_targets = targeted_fix_targets or set()
        self.targeted_fix_profile_hashes = targeted_fix_profile_hashes or {}
        self.magisk_denylist = magisk_denylist or set()
        self.magisk_su_policies = magisk_su_policies or {}
        self.magisk_backups = magisk_backups or {}
        self.shizuku_running = shizuku_running
        self.all_modules_disabled = all_modules_disabled
        self.data_adb_empty = data_adb_empty
        self.droidguard_cache_empty = droidguard_cache_empty
        self.root_available = root_available
        self.partitions = partitions or {}
        self.partition_sizes = partition_sizes or {name: len(content) for name, content in self.partitions.items()}
        self.fetch_supported = fetch_supported
        self.ota_status_output = ota_status_output
        self.calls: list[ProcessRequest] = []

    def run(
        self,
        request: ProcessRequest,
        cancellation: CancellationToken,
    ) -> TransportOutcome:
        self.calls.append(request)
        if cancellation.cancelled:
            return TransportOutcome(None, cancelled=True)
        argv = request.argv
        if argv == ("ADB", "devices", "-l"):
            rows = "".join(
                f"{endpoint}\t{state} product:akita model:Pixel\n" for endpoint, state in self.adb_endpoints.items()
            )
            return TransportOutcome(0, f"List of devices attached\n{rows}\n")
        if len(argv) < 4 or argv[1:3] != ("-s", self.serial):
            return TransportOutcome(1, stderr="serial mismatch")
        if self.mode == "timeout":
            return TransportOutcome(None, timed_out=True)
        if self.mode == "disconnected":
            if argv[0] == "ADB":
                return TransportOutcome(
                    1,
                    stderr=f"error: device '{self.serial}' not found",
                )
            return TransportOutcome(
                1,
                stderr=f"fastboot: error: device '{self.serial}' not found",
            )
        if argv[0] == "ADB":
            return self._adb(argv)
        if argv[0] == "FASTBOOT":
            return self._fastboot(argv)
        return TransportOutcome(1)

    def _adb(self, argv: tuple[str, ...]) -> TransportOutcome:
        if argv[3:] == ("get-state",):
            if self.mode in {"adb", "recovery", "sideload"}:
                state = "device" if self.mode == "adb" else self.mode
                return TransportOutcome(0, f"{state}\n")
            return TransportOutcome(1)
        if self.mode not in {"adb", "recovery"}:
            return TransportOutcome(1)
        if argv[3:5] == ("shell", "getprop") and len(argv) == 6:
            name = argv[5]
            if name == "ro.bootmode":
                return TransportOutcome(
                    0,
                    "recovery\n" if self.mode == "recovery" else "normal\n",
                )
            return TransportOutcome(0, f"{self.properties.get(name, '')}\n")
        if argv[3:] == ("shell", "update_engine_client", "--status"):
            return (
                TransportOutcome(0, self.ota_status_output)
                if self.ota_status_output is not None
                else TransportOutcome(1, stderr="status unavailable")
            )
        if argv[3:6] == ("shell", "sha256sum", "--") and len(argv) >= 7:
            remote_paths = argv[6:]
            if any(path not in self.remote_hashes for path in remote_paths):
                return TransportOutcome(1)
            return TransportOutcome(
                0,
                "".join(f"{self.remote_hashes[path]}  {path}\n" for path in remote_paths),
            )
        if argv[3:7] == ("shell", "toybox", "sha256sum", "--") and len(argv) >= 8:
            remote_paths = argv[7:]
            if any(path not in self.remote_hashes for path in remote_paths):
                return TransportOutcome(1)
            return TransportOutcome(
                0,
                "".join(f"{self.remote_hashes[path]}  {path}\n" for path in remote_paths),
            )
        if argv[3:6] == ("shell", "pm", "path") and len(argv) == 7:
            package_name = argv[6]
            return (
                TransportOutcome(0, f"package:/data/app/{package_name}/base.apk\n")
                if package_name in self.packages
                else TransportOutcome(0)
            )
        if (
            argv[3:9] == ("shell", "pm", "list", "packages", "--user", "0")
            and len(argv) == 11
            and argv[9] in {"-e", "-d"}
        ):
            flag = argv[9]
            package_name = argv[10]
            expected = "enabled" if flag == "-e" else "disabled"
            state = self.package_states.get(package_name, "enabled")
            stdout = f"package:{package_name}\n" if package_name in self.packages and state == expected else ""
            return TransportOutcome(0, stdout)
        if (
            argv[3:9] == ("shell", "pm", "list", "packages", "-i", "--user")
            and len(argv) == 11
            and argv[9] == "0"
        ):
            package_name = argv[10]
            installer = self.package_installers.get(package_name)
            stdout = (
                f"package:{package_name} installer={installer}\n"
                if installer is not None
                else ""
            )
            return TransportOutcome(0, stdout)
        if argv[3:5] == ("shell", "pidof") and len(argv) == 6:
            package_name = argv[5]
            if package_name not in self.packages:
                return TransportOutcome(1)
            state = self.package_states.get(package_name, "stopped")
            return TransportOutcome(0, "1234\n") if state == "running" else TransportOutcome(1)
        if argv[3:] == ("shell", "ps", "-A"):
            process = "shell 123 1 shizuku_server\n" if self.shizuku_running else ""
            return TransportOutcome(0, f"USER PID PPID NAME\n{process}")
        if argv[3:6] == ("shell", "su", "-c") and len(argv) == 7:
            command = argv[6]
            if command == "id -u":
                return TransportOutcome(0, "0\n") if self.root_available else TransportOutcome(1)
            if command == "magisk --denylist ls":
                return TransportOutcome(
                    0,
                    "".join(f"{package}|{package}\n" for package in sorted(self.magisk_denylist)),
                )
            if command.startswith('magisk --sqlite "SELECT \'PF_SU|\''):
                match = re.search(r"WHERE uid = (\d+);", command)
                if match is None:
                    return TransportOutcome(1)
                uid = int(match.group(1))
                state = self.magisk_su_policies.get(uid)
                if state is None or state == "absent":
                    return TransportOutcome(0)
                policy, logging, notification, until = state.split(":", 3)
                value = "2" if policy == "allow" else "1"
                return TransportOutcome(
                    0,
                    f"PF_SU|{uid}|{value}|{logging}|{notification}|{until}\n",
                )
            if command.startswith("target=/data/magisk_backup_"):
                match = re.match(r"target=/data/magisk_backup_([0-9a-f]{40});", command)
                if match is None:
                    return TransportOutcome(1)
                state = self.magisk_backups.get(match.group(1), "absent")
                marker = {
                    "verified": "PF_MB_VERIFIED",
                    "absent": "PF_MB_ABSENT",
                    "corrupt": "PF_MB_CORRUPT",
                }.get(state)
                return TransportOutcome(0, f"{marker}\n") if marker else TransportOutcome(1)
            if command.startswith("for dir in /data/adb/modules/*;"):
                return TransportOutcome(0 if self.all_modules_disabled else 1)
            if command == 'test -d /data/adb && [ -z "$(find /data/adb -mindepth 1 -print -quit)" ]':
                return TransportOutcome(0 if self.data_adb_empty else 1)
            if command == (
                "[ ! -e /data/data/com.google.android.gms/app_dg_cache ] && "
                "{ [ ! -d /data/data/com.google.android.gms/databases ] || "
                "[ -z \"$(find /data/data/com.google.android.gms/databases -maxdepth 1 "
                "-name 'dg.db*' -print -quit 2>/dev/null)\" ]; }"
            ):
                return TransportOutcome(0 if self.droidguard_cache_empty else 1)
            pif_paths = {
                "pif.custom_json": "/data/adb/modules/playintegrityfix/custom.pif.json",
                "pif.custom_prop": "/data/adb/modules/playintegrityfix/custom.pif.prop",
                "pif.module_json": "/data/adb/modules/playintegrityfix/pif.json",
                "pif.legacy_json": "/data/adb/pif.json",
                "pif.app_replace": "/data/adb/modules/playintegrityfix/custom.app_replace.list",
                "pif.scripts_only": "/data/adb/modules/playintegrityfix/scripts-only-mode",
                "tricky.spoof": "/data/adb/tricky_store/spoof_build_vars",
                "tricky.target": "/data/adb/tricky_store/target.txt",
                "tricky.security_patch": "/data/adb/tricky_store/security_patch.txt",
                "tricky.tee": "/data/adb/tricky_store/tee_status",
                "targeted.targets": "/data/adb/modules/targetedfix/config/target.txt",
            }
            for profile_id, path in pif_paths.items():
                if command == f"test -f {path}":
                    return TransportOutcome(0 if profile_id in self.pif_profiles else 1)
                if command == f"sha256sum -- {path}":
                    digest = self.pif_profile_hashes.get(profile_id)
                    return TransportOutcome(0, f"{digest}  {path}\n") if digest else TransportOutcome(1)
            target_prefix = (
                "[ -f /data/adb/modules/targetedfix/config/target.txt ] || exit 1; "
                "grep -Fxq -- "
            )
            if command.startswith(target_prefix) and command.endswith(
                " /data/adb/modules/targetedfix/config/target.txt"
            ):
                package = command[len(target_prefix) :].split(" ", 1)[0]
                return TransportOutcome(0 if package in self.targeted_fix_targets else 1)
            profile_match = re.fullmatch(
                r"\[ -f (/data/adb/modules/targetedfix/config/([A-Za-z][A-Za-z0-9_.]*)\.(json|prop)) \] "
                r"&& \[ ! -f /data/adb/modules/targetedfix/config/\2\.(?:json|prop) \] \|\| exit 1; "
                r"sha256sum -- \1",
                command,
            )
            if profile_match is not None:
                path, package, profile_format = profile_match.groups()
                digest = self.targeted_fix_profile_hashes.get(f"{package}:{profile_format}")
                return TransportOutcome(0, f"{digest}  {path}\n") if digest else TransportOutcome(1)
            for module_id, state in self.root_modules.items():
                root = f"/data/adb/modules/{module_id}"
                if command == f"test -d {root}":
                    return TransportOutcome(0)
                if command == f"test -e {root}/disable":
                    return TransportOutcome(0 if state == "disabled" else 1)
                if command == f"test -e {root}/remove":
                    return TransportOutcome(0 if state == "pending_remove" else 1)
            if command.startswith("test -d /data/adb/modules/"):
                return TransportOutcome(1)
            return TransportOutcome(1, stderr="unsupported root test")
        return TransportOutcome(1)

    def _fastboot(self, argv: tuple[str, ...]) -> TransportOutcome:
        if self.mode not in {"fastboot", "fastbootd"}:
            return TransportOutcome(1)
        if argv[3:5] == ("getvar", "is-userspace"):
            value = "yes" if self.mode == "fastbootd" else "no"
            return TransportOutcome(0, stderr=f"(bootloader) is-userspace: {value}\n")
        if argv[3:5] == ("getvar", "current-slot"):
            return TransportOutcome(0, stderr="(bootloader) current-slot: b\n")
        if argv[3:5] == ("getvar", "unlocked"):
            return TransportOutcome(0, stderr="(bootloader) unlocked: yes\n")
        if len(argv) == 5 and argv[3] == "getvar":
            variable = argv[4]
            prefix = "partition-size:"
            if variable.startswith(prefix):
                partition = variable.removeprefix(prefix)
                size = self.partition_sizes.get(partition)
                return (
                    TransportOutcome(
                        0,
                        stderr=f"(bootloader) {variable}: 0x{size:x}\n",
                    )
                    if size is not None
                    else TransportOutcome(1)
                )
        if argv[3:] == ("help",):
            return (
                TransportOutcome(0, "fetch PARTITION OUT_FILE\n")
                if self.fetch_supported
                else TransportOutcome(0, "flash PARTITION FILE\n")
            )
        if len(argv) == 6 and argv[3] == "fetch":
            partition = argv[4]
            content = self.partitions.get(partition)
            if content is None:
                return TransportOutcome(1)
            Path(argv[5]).write_bytes(content)
            return TransportOutcome(0)
        return TransportOutcome(1)


def observer(
    transport: StatefulDeviceTransport,
    *,
    timer: FakeTime | None = None,
    max_partition_bytes: int = 1024,
    temporary_root: str | Path | None = None,
) -> PostconditionObserver:
    probe = ProcessDeviceObservationProbe(
        DeviceService(transport),
        lambda: TOOLCHAIN,
        command_timeout_seconds=0.25,
        max_partition_bytes=max_partition_bytes,
        temporary_root=temporary_root,
    )
    if timer is None:
        return PostconditionObserver(probe, poll_interval_seconds=0.01)
    return PostconditionObserver(
        probe,
        poll_interval_seconds=0.1,
        clock=timer.clock,
        sleeper=timer.sleep,
    )


class ProductionPostconditionObserverTests(unittest.TestCase):
    def test_mode_detection_covers_recovery_sideload_and_fastboot(self) -> None:
        for mode in ("recovery", "sideload", "fastboot"):
            with self.subTest(mode=mode):
                transport = StatefulDeviceTransport(mode=mode)
                result = observer(transport).verify(PostconditionSpec(SERIAL, 1, expected_mode=mode))

                self.assertEqual(ObservationStatus.VERIFIED, result.status)
                self.assertTrue(all(call.argv[1:3] == ("-s", SERIAL) for call in transport.calls))

    def test_scoped_ipv6_adb_serial_is_observed_without_losing_target_binding(self) -> None:
        serial = "[fe80::1%wlan0]:5555"
        transport = StatefulDeviceTransport(mode="adb", serial=serial)

        result = observer(transport).verify(
            PostconditionSpec(serial, 1, expected_mode="adb")
        )

        self.assertEqual(ObservationStatus.VERIFIED, result.status)
        self.assertTrue(transport.calls)
        self.assertTrue(all(call.argv[1:3] == ("-s", serial) for call in transport.calls))

    def test_adb_evidence_verifies_mode_slot_lock_boot_build_and_remote_hash(self) -> None:
        digest = hashlib.sha256(b"remote").hexdigest()
        transport = StatefulDeviceTransport(
            mode="adb",
            properties={
                "ro.boot.slot_suffix": "_b",
                "ro.boot.flash.locked": "0",
                "sys.boot_completed": "1",
                "ro.sys.safemode": "1",
                "ro.build.id": "BP2A.260718.001",
            },
            remote_hashes={"/sdcard/Download/patched.img": digest},
        )
        result = observer(transport).verify(
            PostconditionSpec(
                SERIAL,
                1,
                expected_mode="adb",
                expected_slot="b",
                expected_bootloader="unlocked",
                expected_boot_completed=True,
                expected_safe_mode=True,
                expected_build="BP2A.260718.001",
                remote_hashes={"/sdcard/Download/patched.img": digest.upper()},
            )
        )

        self.assertEqual(ObservationStatus.VERIFIED, result.status)
        observation = result.observation
        self.assertIsNotNone(observation)
        if observation is None:
            self.fail("verified result omitted its observation")
        self.assertEqual(
            digest,
            observation.remote_hashes["/sdcard/Download/patched.img"],
        )
        self.assertTrue(transport.calls)
        self.assertTrue(all(call.argv[1:3] == ("-s", SERIAL) for call in transport.calls))
        self.assertTrue(all(call.cwd is None and call.env is None for call in transport.calls))
        self.assertIn(
            ("ADB", "-s", SERIAL, "shell", "getprop", "ro.sys.safemode"),
            [call.argv for call in transport.calls],
        )

    def test_ota_idle_requires_independent_bounded_update_engine_status(self) -> None:
        idle_transport = StatefulDeviceTransport(
            mode="adb",
            ota_status_output=(
                "CURRENT_OP=UPDATE_STATUS_IDLE\n"
                "CURRENT_PROGRESS=0\n"
            ),
        )
        idle = observer(idle_transport).verify(
            PostconditionSpec(SERIAL, 1, expected_mode="adb", expected_ota_idle=True)
        )

        active_timer = FakeTime()
        active_transport = StatefulDeviceTransport(
            mode="adb",
            ota_status_output=(
                "CURRENT_OP=UPDATE_STATUS_DOWNLOADING\n"
                "CURRENT_PROGRESS=0.5\n"
            ),
        )
        active = observer(active_transport, timer=active_timer).verify(
            PostconditionSpec(SERIAL, 0.2, expected_mode="adb", expected_ota_idle=True)
        )

        malformed_timer = FakeTime()
        malformed_transport = StatefulDeviceTransport(
            mode="adb",
            ota_status_output="CURRENT_OP=UNTRUSTED\nCURRENT_PROGRESS=0\n",
        )
        malformed = observer(malformed_transport, timer=malformed_timer).verify(
            PostconditionSpec(SERIAL, 0.2, expected_mode="adb", expected_ota_idle=True)
        )

        self.assertEqual(ObservationStatus.VERIFIED, idle.status)
        status_calls = [
            call
            for call in idle_transport.calls
            if call.argv[3:] == ("shell", "update_engine_client", "--status")
        ]
        self.assertEqual(1, len(status_calls))
        self.assertEqual(64 * 1024, status_calls[0].output_limit_bytes)
        self.assertEqual(ObservationStatus.MISMATCH, active.status)
        self.assertEqual((True, False), active.mismatches["ota_idle"])
        self.assertEqual(ObservationStatus.UNVERIFIED, malformed.status)
        self.assertIn("ota_idle", malformed.missing)

    def test_push_observer_verifies_the_full_thirty_two_file_contract(self) -> None:
        remote_hashes = {
            f"/data/local/tmp/file-{index:02d}.bin": hashlib.sha256(
                bytes([index])
            ).hexdigest()
            for index in range(32)
        }
        transport = StatefulDeviceTransport(
            mode="adb",
            properties={"sys.boot_completed": "1"},
            remote_hashes=remote_hashes,
        )

        result = observer(transport).verify(
            PostconditionSpec(
                SERIAL,
                3,
                expected_mode="adb",
                remote_hashes=remote_hashes,
            )
        )

        self.assertEqual(ObservationStatus.VERIFIED, result.status)
        hash_calls = [
            call
            for call in transport.calls
            if "sha256sum" in call.argv or "toybox" in call.argv
        ]
        self.assertEqual(1, len(hash_calls))
        self.assertTrue(
            all(call.output_limit_bytes == 64 * 1024 for call in hash_calls)
        )
        self.assertEqual(tuple(remote_hashes), hash_calls[0].argv[6:])

    def test_safe_mode_property_is_required_and_not_inferred_from_adb(self) -> None:
        timer = FakeTime()
        missing_transport = StatefulDeviceTransport(
            mode="adb",
            properties={"sys.boot_completed": "1"},
        )
        missing = observer(missing_transport, timer=timer).verify(
            PostconditionSpec(
                SERIAL,
                0.2,
                expected_mode="adb",
                expected_boot_completed=True,
                expected_safe_mode=True,
            )
        )

        self.assertEqual(ObservationStatus.UNVERIFIED, missing.status)
        self.assertIn("safe_mode", missing.missing)

        mismatch_timer = FakeTime()
        mismatch_transport = StatefulDeviceTransport(
            mode="adb",
            properties={
                "sys.boot_completed": "1",
                "ro.sys.safemode": "0",
            },
        )
        mismatch = observer(mismatch_transport, timer=mismatch_timer).verify(
            PostconditionSpec(
                SERIAL,
                0.2,
                expected_mode="adb",
                expected_boot_completed=True,
                expected_safe_mode=True,
            )
        )

        self.assertEqual(ObservationStatus.MISMATCH, mismatch.status)
        self.assertEqual((True, False), mismatch.mismatches["safe_mode"])

    def test_stable_wrong_build_is_mismatch(self) -> None:
        timer = FakeTime()
        transport = StatefulDeviceTransport(
            mode="adb",
            properties={"ro.build.id": "ACTUAL"},
        )
        result = observer(transport, timer=timer).verify(
            PostconditionSpec(SERIAL, 0.2, expected_mode="adb", expected_build="expected")
        )

        self.assertEqual(ObservationStatus.MISMATCH, result.status)
        self.assertEqual(("expected", "ACTUAL"), result.mismatches["build"])

    def test_command_timeouts_remain_unverified(self) -> None:
        timer = FakeTime()
        transport = StatefulDeviceTransport(mode="timeout")
        result = observer(transport, timer=timer).verify(PostconditionSpec(SERIAL, 0.2, expected_mode="adb"))

        self.assertEqual(ObservationStatus.UNVERIFIED, result.status)
        self.assertIn("device", result.missing)
        self.assertTrue(transport.calls)
        self.assertTrue(all(call.timeout_seconds == 0.2 for call in transport.calls))
        self.assertTrue(all(call.argv[1:3] == ("-s", SERIAL) for call in transport.calls))

    def test_explicit_absence_is_distinct_from_unverified_timeout(self) -> None:
        timer = FakeTime()
        transport = StatefulDeviceTransport(mode="disconnected")
        result = observer(transport, timer=timer).verify(PostconditionSpec(SERIAL, 0.2, expected_mode="adb"))

        self.assertEqual(ObservationStatus.DISCONNECTED, result.status)
        self.assertEqual("postcondition_disconnected", result.code)
        observation = result.observation
        self.assertIsNotNone(observation)
        if observation is None:
            self.fail("disconnected result omitted its observation")
        self.assertFalse(observation.connected)

    def test_fastbootd_partition_hash_uses_bounded_confined_fetch(self) -> None:
        content = b"verified-boot-partition"
        digest = hashlib.sha256(content).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            transport = StatefulDeviceTransport(
                mode="fastbootd",
                partitions={"boot_b": content},
            )
            result = observer(
                transport,
                temporary_root=directory,
                max_partition_bytes=len(content),
            ).verify(
                PostconditionSpec(
                    SERIAL,
                    1,
                    expected_mode="fastbootd",
                    expected_slot="b",
                    expected_bootloader="unlocked",
                    partition_hashes={"boot_b": digest},
                )
            )

            self.assertEqual(ObservationStatus.VERIFIED, result.status)
            argv = [call.argv for call in transport.calls]
            size_index = next(
                index for index, value in enumerate(argv) if value[-2:] == ("getvar", "partition-size:boot_b")
            )
            help_index = next(index for index, value in enumerate(argv) if value[-1:] == ("help",))
            fetch_index = next(index for index, value in enumerate(argv) if "fetch" in value)
            self.assertLess(size_index, help_index)
            self.assertLess(help_index, fetch_index)
            fetch_path = Path(argv[fetch_index][-1])
            self.assertEqual(Path(directory).resolve(), fetch_path.parent.parent)
            self.assertFalse(fetch_path.exists())
            self.assertTrue(all(value[1:3] == ("-s", SERIAL) for value in argv))

    def test_partition_over_limit_is_unverified_without_help_or_fetch(self) -> None:
        timer = FakeTime()
        transport = StatefulDeviceTransport(
            mode="fastboot",
            partition_sizes={"userdata": 4096},
        )
        result = observer(
            transport,
            timer=timer,
            max_partition_bytes=64,
        ).verify(
            PostconditionSpec(
                SERIAL,
                0.2,
                expected_mode="fastboot",
                partition_hashes={"userdata": "0" * 64},
            )
        )

        self.assertEqual(ObservationStatus.UNVERIFIED, result.status)
        self.assertIn("partition_hash:userdata", result.missing)
        argv = [call.argv for call in transport.calls]
        self.assertFalse(any(value[-1:] == ("help",) for value in argv))
        self.assertFalse(any("fetch" in value for value in argv))

    def test_partition_fetch_is_not_attempted_when_tool_lacks_support(self) -> None:
        timer = FakeTime()
        content = b"boot"
        transport = StatefulDeviceTransport(
            mode="fastboot",
            partitions={"boot": content},
            fetch_supported=False,
        )
        result = observer(
            transport,
            timer=timer,
            max_partition_bytes=len(content),
        ).verify(
            PostconditionSpec(
                SERIAL,
                0.2,
                expected_mode="fastboot",
                partition_hashes={"boot": hashlib.sha256(content).hexdigest()},
            )
        )

        self.assertEqual(ObservationStatus.UNVERIFIED, result.status)
        argv = [call.argv for call in transport.calls]
        self.assertTrue(any(value[-1:] == ("help",) for value in argv))
        self.assertFalse(any("fetch" in value for value in argv))

    def test_erased_partition_requires_bounded_readback_content(self) -> None:
        erased = b"\xff\x00\xff\x00"
        written = b"\xffBOOT"
        verified_transport = StatefulDeviceTransport(
            mode="fastboot",
            partitions={"metadata": erased},
        )
        verified = observer(
            verified_transport,
            max_partition_bytes=len(erased),
        ).verify(
            PostconditionSpec(
                SERIAL,
                1,
                expected_mode="fastboot",
                erased_partitions=("metadata",),
            )
        )
        self.assertEqual(ObservationStatus.VERIFIED, verified.status)

        timer = FakeTime()
        mismatch_transport = StatefulDeviceTransport(
            mode="fastboot",
            partitions={"metadata": written},
        )
        mismatch = observer(
            mismatch_transport,
            timer=timer,
            max_partition_bytes=len(written),
        ).verify(
            PostconditionSpec(
                SERIAL,
                0.2,
                expected_mode="fastboot",
                erased_partitions=("metadata",),
            )
        )
        self.assertEqual(ObservationStatus.MISMATCH, mismatch.status)
        self.assertEqual(
            (True, False),
            mismatch.mismatches["partition_erased:metadata"],
        )

    def test_package_and_root_module_states_use_backend_owned_argv(self) -> None:
        package_name = "com.topjohnwu.magisk"
        module_id = "playintegrityfix"
        transport = StatefulDeviceTransport(
            mode="adb",
            packages={package_name},
            root_modules={module_id: "disabled"},
        )
        result = observer(transport).verify(
            PostconditionSpec(
                SERIAL,
                1,
                expected_mode="adb",
                expected_packages={package_name: True},
                expected_root_modules={module_id: "disabled"},
            )
        )

        self.assertEqual(ObservationStatus.VERIFIED, result.status)
        argv = [call.argv for call in transport.calls]
        self.assertIn(
            ("ADB", "-s", SERIAL, "shell", "pm", "path", package_name),
            argv,
        )
        self.assertIn(
            (
                "ADB",
                "-s",
                SERIAL,
                "shell",
                "su",
                "-c",
                f"test -d /data/adb/modules/{module_id}",
            ),
            argv,
        )

    def test_pif_profile_state_uses_only_canonical_backend_path(self) -> None:
        profile_id = "pif.custom_json"
        absent = observer(StatefulDeviceTransport(mode="adb")).verify(
            PostconditionSpec(
                SERIAL,
                1,
                expected_mode="adb",
                expected_pif_profiles={profile_id: False},
            )
        )
        self.assertEqual(ObservationStatus.VERIFIED, absent.status)

        timer = FakeTime()
        present = observer(
            StatefulDeviceTransport(mode="adb", pif_profiles={profile_id}),
            timer=timer,
        ).verify(
            PostconditionSpec(
                SERIAL,
                0.2,
                expected_pif_profiles={profile_id: False},
            )
        )
        self.assertEqual(ObservationStatus.MISMATCH, present.status)
        self.assertEqual((False, True), present.mismatches[f"pif_profile:{profile_id}"])

        with self.assertRaises(ValueError):
            PostconditionSpec(SERIAL, 1, expected_pif_profiles={"../private": False})

    def test_pif_profile_hash_requires_exact_root_readback(self) -> None:
        profile_id = "pif.custom_json"
        digest = "a" * 64
        verified = observer(
            StatefulDeviceTransport(mode="adb", pif_profile_hashes={profile_id: digest})
        ).verify(
            PostconditionSpec(SERIAL, 1, expected_pif_profile_hashes={profile_id: digest})
        )
        self.assertEqual(ObservationStatus.VERIFIED, verified.status)

        timer = FakeTime()
        mismatch = observer(
            StatefulDeviceTransport(mode="adb", pif_profile_hashes={profile_id: "b" * 64}),
            timer=timer,
        ).verify(
            PostconditionSpec(SERIAL, 0.2, expected_pif_profile_hashes={profile_id: digest})
        )
        self.assertEqual(ObservationStatus.MISMATCH, mismatch.status)
        self.assertEqual((digest, "b" * 64), mismatch.mismatches[f"pif_profile_hash:{profile_id}"])

    def test_targeted_fix_target_state_requires_exact_root_readback(self) -> None:
        package = "com.example.app"
        verified = observer(
            StatefulDeviceTransport(mode="adb", targeted_fix_targets={package})
        ).verify(
            PostconditionSpec(SERIAL, 1, expected_targeted_fix_targets={package: True})
        )
        self.assertEqual(ObservationStatus.VERIFIED, verified.status)

        timer = FakeTime()
        mismatch = observer(StatefulDeviceTransport(mode="adb"), timer=timer).verify(
            PostconditionSpec(SERIAL, 0.2, expected_targeted_fix_targets={package: True})
        )
        self.assertEqual(ObservationStatus.MISMATCH, mismatch.status)
        self.assertEqual((True, False), mismatch.mismatches[f"targeted_fix_target:{package}"])

        with self.assertRaises(ValueError):
            PostconditionSpec(SERIAL, 1, expected_targeted_fix_targets={"../private": True})

    def test_targeted_fix_profile_hash_requires_one_exact_active_format(self) -> None:
        identity = "com.example.app:json"
        digest = "d" * 64
        verified = observer(
            StatefulDeviceTransport(
                mode="adb",
                targeted_fix_profile_hashes={identity: digest},
            )
        ).verify(
            PostconditionSpec(
                SERIAL,
                1,
                expected_targeted_fix_profile_hashes={identity: digest},
            )
        )
        self.assertEqual(ObservationStatus.VERIFIED, verified.status)

        with self.assertRaises(ValueError):
            PostconditionSpec(
                SERIAL,
                1,
                expected_targeted_fix_profile_hashes={"../private:json": digest},
            )

    def test_droidguard_cleanup_requires_independent_absence_evidence(self) -> None:
        verified = observer(
            StatefulDeviceTransport(mode="adb", droidguard_cache_empty=True)
        ).verify(
            PostconditionSpec(SERIAL, 1, expected_droidguard_cache_empty=True)
        )
        self.assertEqual(ObservationStatus.VERIFIED, verified.status)

        timer = FakeTime()
        mismatch = observer(StatefulDeviceTransport(mode="adb"), timer=timer).verify(
            PostconditionSpec(SERIAL, 0.2, expected_droidguard_cache_empty=True)
        )
        self.assertEqual(ObservationStatus.MISMATCH, mismatch.status)

    def test_root_recovery_aggregate_states_require_explicit_device_evidence(self) -> None:
        verified = observer(
            StatefulDeviceTransport(
                mode="adb",
                shizuku_running=True,
                all_modules_disabled=True,
            )
        ).verify(
            PostconditionSpec(
                SERIAL,
                1,
                expected_mode="adb",
                expected_shizuku_running=True,
                expected_magisk_modules_disabled=True,
            )
        )
        self.assertEqual(ObservationStatus.VERIFIED, verified.status)

        timer = FakeTime()
        mismatch = observer(
            StatefulDeviceTransport(
                mode="adb",
                shizuku_running=False,
                all_modules_disabled=False,
            ),
            timer=timer,
        ).verify(
            PostconditionSpec(
                SERIAL,
                0.2,
                expected_mode="adb",
                expected_shizuku_running=True,
                expected_magisk_modules_disabled=True,
            )
        )
        self.assertEqual(ObservationStatus.MISMATCH, mismatch.status)
        self.assertEqual((True, False), mismatch.mismatches["shizuku_running"])
        self.assertEqual(
            (True, False),
            mismatch.mismatches["magisk_modules_disabled"],
        )
    def test_missing_package_is_explicit_mismatch_not_success(self) -> None:
        timer = FakeTime()
        package_name = "me.bmax.apatch"
        transport = StatefulDeviceTransport(mode="adb")
        result = observer(transport, timer=timer).verify(
            PostconditionSpec(
                SERIAL,
                0.2,
                expected_mode="adb",
                expected_packages={package_name: True},
            )
        )

        self.assertEqual(ObservationStatus.MISMATCH, result.status)
        self.assertEqual(
            (True, False),
            result.mismatches[f"package:{package_name}"],
        )

    def test_package_lifecycle_states_use_exact_serial_bound_argv(self) -> None:
        package_name = "com.example.application"
        cases: tuple[
            tuple[str, set[str], dict[str, str], tuple[str, ...] | None],
            ...,
        ] = (
            ("absent", set(), {}, None),
            ("installed", {package_name}, {}, None),
            (
                "enabled",
                {package_name},
                {package_name: "enabled"},
                ("ADB", "-s", SERIAL, "shell", "pm", "list", "packages", "--user", "0", "-e", package_name),
            ),
            (
                "disabled",
                {package_name},
                {package_name: "disabled"},
                ("ADB", "-s", SERIAL, "shell", "pm", "list", "packages", "--user", "0", "-d", package_name),
            ),
            (
                "running",
                {package_name},
                {package_name: "running"},
                ("ADB", "-s", SERIAL, "shell", "pidof", package_name),
            ),
            (
                "stopped",
                {package_name},
                {package_name: "stopped"},
                ("ADB", "-s", SERIAL, "shell", "pidof", package_name),
            ),
        )
        for expected, packages, states, evidence_argv in cases:
            with self.subTest(expected=expected):
                transport = StatefulDeviceTransport(
                    mode="adb",
                    packages=packages,
                    package_states=states,
                )
                result = observer(transport).verify(
                    PostconditionSpec(
                        SERIAL,
                        1,
                        expected_mode="adb",
                        expected_package_states={package_name: expected},
                    )
                )

                self.assertEqual(ObservationStatus.VERIFIED, result.status)
                argv = [call.argv for call in transport.calls]
                self.assertIn(
                    ("ADB", "-s", SERIAL, "shell", "pm", "path", package_name),
                    argv,
                )
                if evidence_argv is not None:
                    self.assertIn(evidence_argv, argv)
                self.assertTrue(all(call.argv[1:3] == ("-s", SERIAL) for call in transport.calls))

    def test_wrong_package_lifecycle_state_is_a_mismatch(self) -> None:
        timer = FakeTime()
        package_name = "com.example.application"
        transport = StatefulDeviceTransport(
            mode="adb",
            packages={package_name},
            package_states={package_name: "disabled"},
        )
        result = observer(transport, timer=timer).verify(
            PostconditionSpec(
                SERIAL,
                0.2,
                expected_mode="adb",
                expected_package_states={package_name: "enabled"},
            )
        )

        self.assertEqual(ObservationStatus.MISMATCH, result.status)
        self.assertEqual(
            ("enabled", "disabled"),
            result.mismatches[f"package_state:{package_name}"],
        )

    def test_package_installer_is_observed_independently(self) -> None:
        package_name = "com.example.application"
        transport = StatefulDeviceTransport(
            mode="adb",
            package_installers={package_name: "com.android.vending"},
        )
        result = observer(transport).verify(
            PostconditionSpec(
                SERIAL,
                1,
                expected_package_installers={package_name: "com.android.vending"},
            )
        )

        self.assertEqual(ObservationStatus.VERIFIED, result.status)
        self.assertIn(
            (
                "ADB",
                "-s",
                SERIAL,
                "shell",
                "pm",
                "list",
                "packages",
                "-i",
                "--user",
                "0",
                package_name,
            ),
            [call.argv for call in transport.calls],
        )

    def test_wrong_package_installer_is_a_mismatch(self) -> None:
        package_name = "com.example.application"
        result = observer(
            StatefulDeviceTransport(
                mode="adb",
                package_installers={package_name: "com.example.store"},
            )
        ).verify(
            PostconditionSpec(
                SERIAL,
                0.2,
                expected_package_installers={package_name: "com.android.vending"},
            )
        )

        self.assertEqual(ObservationStatus.MISMATCH, result.status)
        self.assertEqual(
            ("com.android.vending", "com.example.store"),
            result.mismatches[f"package_installer:{package_name}"],
        )

    def test_missing_package_installer_never_verifies_ownership(self) -> None:
        timer = FakeTime()
        package_name = "com.example.application"
        result = observer(
            StatefulDeviceTransport(mode="adb"),
            timer=timer,
        ).verify(
            PostconditionSpec(
                SERIAL,
                0.2,
                expected_package_installers={package_name: "com.android.vending"},
            )
        )

        self.assertEqual(ObservationStatus.UNVERIFIED, result.status)
        self.assertIn(f"package_installer:{package_name}", result.missing)

    def test_magisk_denylist_state_is_observed_independently(self) -> None:
        package_name = "com.example.application"
        transport = StatefulDeviceTransport(
            mode="adb",
            magisk_denylist={package_name},
        )
        result = observer(transport).verify(
            PostconditionSpec(
                SERIAL,
                1,
                expected_magisk_denylist={package_name: True},
            )
        )

        self.assertEqual(ObservationStatus.VERIFIED, result.status)
        self.assertIn(
            (
                "ADB",
                "-s",
                SERIAL,
                "shell",
                "su",
                "-c",
                "magisk --denylist ls",
            ),
            [call.argv for call in transport.calls],
        )

        mismatch = observer(
            StatefulDeviceTransport(mode="adb", magisk_denylist=set())
        ).verify(
            PostconditionSpec(
                SERIAL,
                1,
                expected_magisk_denylist={package_name: True},
            )
        )
        self.assertEqual(ObservationStatus.MISMATCH, mismatch.status)

    def test_magisk_su_policy_requires_exact_bounded_sql_evidence(self) -> None:
        uid = 10123
        expected = "allow:1:0:1700000600"
        transport = StatefulDeviceTransport(
            mode="adb",
            magisk_su_policies={uid: expected},
        )
        result = observer(transport).verify(
            PostconditionSpec(
                SERIAL,
                1,
                expected_magisk_su_policies={uid: expected},
            )
        )

        self.assertEqual(ObservationStatus.VERIFIED, result.status)
        query = next(
            call.argv[-1]
            for call in transport.calls
            if call.argv[3:6] == ("shell", "su", "-c")
            and call.argv[-1].startswith('magisk --sqlite "SELECT')
        )
        self.assertIn("WHERE uid = 10123;", query)

        absent = observer(
            StatefulDeviceTransport(mode="adb", magisk_su_policies={})
        ).verify(
            PostconditionSpec(
                SERIAL,
                1,
                expected_magisk_su_policies={uid: "absent"},
            )
        )
        self.assertEqual(ObservationStatus.VERIFIED, absent.status)

    def test_magisk_backup_state_requires_decompressed_hash_evidence(self) -> None:
        sha1 = "a" * 40
        verified = observer(
            StatefulDeviceTransport(
                mode="adb",
                magisk_backups={sha1: "verified"},
            )
        ).verify(
            PostconditionSpec(
                SERIAL,
                1,
                expected_magisk_backups={sha1: "verified"},
            )
        )
        self.assertEqual(ObservationStatus.VERIFIED, verified.status)

        corrupt = observer(
            StatefulDeviceTransport(
                mode="adb",
                magisk_backups={sha1: "corrupt"},
            )
        ).verify(
            PostconditionSpec(
                SERIAL,
                0.2,
                expected_magisk_backups={sha1: "verified"},
            )
        )
        self.assertEqual(ObservationStatus.MISMATCH, corrupt.status)
        self.assertEqual(
            ("verified", "corrupt"),
            corrupt.mismatches[f"magisk_backup:{sha1}"],
        )

        absent = observer(
            StatefulDeviceTransport(mode="adb", magisk_backups={})
        ).verify(
            PostconditionSpec(
                SERIAL,
                1,
                expected_magisk_backups={sha1: "absent"},
            )
        )
        self.assertEqual(ObservationStatus.VERIFIED, absent.status)

    def test_data_adb_empty_requires_root_and_distinguishes_mismatch(self) -> None:
        verified = observer(
            StatefulDeviceTransport(mode="adb", data_adb_empty=True)
        ).verify(
            PostconditionSpec(
                SERIAL,
                1,
                expected_data_adb_empty=True,
            )
        )
        self.assertEqual(ObservationStatus.VERIFIED, verified.status)

        mismatch = observer(
            StatefulDeviceTransport(mode="adb", data_adb_empty=False)
        ).verify(
            PostconditionSpec(
                SERIAL,
                1,
                expected_data_adb_empty=True,
            )
        )
        self.assertEqual(ObservationStatus.MISMATCH, mismatch.status)
        self.assertEqual((True, False), mismatch.mismatches["data_adb_empty"])

        unavailable = observer(
            StatefulDeviceTransport(
                mode="adb",
                data_adb_empty=True,
                root_available=False,
            ),
            timer=FakeTime(),
        ).verify(
            PostconditionSpec(
                SERIAL,
                0.2,
                expected_data_adb_empty=True,
            )
        )
        self.assertEqual(ObservationStatus.UNVERIFIED, unavailable.status)
        self.assertIn("data_adb_empty", unavailable.missing)

    def test_adb_wifi_endpoint_state_uses_bounded_host_inventory(self) -> None:
        endpoint = "192.0.2.20:5555"
        for expected, listed_state in ((True, "device"), (False, None)):
            with self.subTest(expected=expected):
                transport = StatefulDeviceTransport(
                    mode="adb",
                    adb_endpoints=({endpoint: listed_state} if listed_state is not None else {}),
                )
                result = observer(transport).verify(
                    PostconditionSpec(
                        SERIAL,
                        1,
                        expected_mode="adb",
                        expected_adb_endpoints={endpoint: expected},
                    )
                )

                self.assertEqual(ObservationStatus.VERIFIED, result.status)
                self.assertIn(
                    ("ADB", "devices", "-l"),
                    [call.argv for call in transport.calls],
                )
                self.assertTrue(all(call.cwd is None and call.env is None for call in transport.calls))

    def test_adb_wifi_endpoint_mismatch_and_invalid_input_fail_closed(self) -> None:
        endpoint = "192.0.2.20:5555"
        timer = FakeTime()
        transport = StatefulDeviceTransport(
            mode="adb",
            adb_endpoints={endpoint: "offline"},
        )
        result = observer(transport, timer=timer).verify(
            PostconditionSpec(
                SERIAL,
                0.2,
                expected_adb_endpoints={endpoint: True},
            )
        )

        self.assertEqual(ObservationStatus.MISMATCH, result.status)
        self.assertEqual(
            (True, False),
            result.mismatches[f"adb_endpoint:{endpoint}"],
        )
        with self.assertRaisesRegex(ValueError, "endpoint"):
            PostconditionSpec(
                SERIAL,
                1,
                expected_adb_endpoints={"example.com;reboot:5555": True},
            )

    def test_root_module_absence_is_unverified_without_proven_root_access(self) -> None:
        timer = FakeTime()
        module_id = "playintegrityfix"
        transport = StatefulDeviceTransport(
            mode="adb",
            root_available=False,
        )
        result = observer(transport, timer=timer).verify(
            PostconditionSpec(
                SERIAL,
                0.2,
                expected_mode="adb",
                expected_root_modules={module_id: "absent"},
            )
        )

        self.assertEqual(ObservationStatus.UNVERIFIED, result.status)
        self.assertIn(f"root_module:{module_id}", result.missing)

    def test_unsafe_remote_name_is_never_sent_to_adb_shell(self) -> None:
        timer = FakeTime()
        transport = StatefulDeviceTransport(mode="adb")
        unsafe = "/sdcard/file;reboot"
        result = observer(transport, timer=timer).verify(
            PostconditionSpec(
                SERIAL,
                0.2,
                expected_mode="adb",
                remote_hashes={unsafe: "0" * 64},
            )
        )

        self.assertEqual(ObservationStatus.UNVERIFIED, result.status)
        self.assertFalse(any("sha256sum" in call.argv for call in transport.calls))
        self.assertFalse(any(unsafe in call.argv for call in transport.calls))


if __name__ == "__main__":
    unittest.main()
