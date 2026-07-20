"""Stateful postcondition evidence for process-boundary integration tests.

The production runner deliberately refuses to infer success from a zero exit
code.  These tests use a fake transport, so this observer reconstructs the
simulated device state only from requests which actually crossed that fake
transport.  Unknown conditions fail closed instead of becoming a blanket
``lambda: True`` escape hatch.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol, cast

from pixelflasher_core.contracts import (
    AppSnapshot,
    OperationPlan,
    OperationPostcondition,
    ProcessRequest,
)


class RecordingTransport(Protocol):
    calls: list[ProcessRequest]


class StatefulPostconditionObserver:
    """Verify simulated postconditions against argv that really executed."""

    def __init__(self, transport: RecordingTransport) -> None:
        self.transport = transport

    def observe(
        self,
        plan: OperationPlan,
        postcondition: OperationPostcondition,
        _snapshot: AppSnapshot,
    ) -> Mapping[str, object]:
        calls = tuple(self.transport.calls)
        if not self._plan_crossed_transport(plan, calls):
            return self._unverified("the compiled plan did not cross the fake transport")

        expected = postcondition.expected
        kind = postcondition.kind
        if kind == "device_mode":
            return self._result(self._observed_mode(calls) == self._mode(expected.get("mode")))
        if kind == "device_reachable":
            mode = expected.get("mode")
            return self._result(bool(calls) and (mode is None or self._observed_mode(calls) == self._mode(mode)))
        if kind == "active_slot":
            return self._unverified(
                "active slot requires an independent device-side probe; "
                "--set-active only proves the requested intent"
            )
        if kind == "bootloader_state":
            return self._result(self._bootloader_state(calls) == expected.get("state"))
        if kind == "partition_written":
            return self._result(self._partition_written(calls, expected))
        if kind == "partition_erased":
            return self._result(self._partition_erased(calls, expected))
        if kind == "live_boot_active":
            return self._result(self._live_boot_active(calls, expected))
        if kind == "flash_applied":
            return self._result(self._flash_applied(plan, calls, expected))
        if kind == "firmware_applied":
            return self._result(self._firmware_applied(calls, expected))
        if kind == "root_app_installed":
            return self._result(self._root_app_installed(calls, expected))
        if kind == "package_state":
            return self._result(self._package_state(calls, expected))
        if kind == "package_installer":
            return self._result(self._package_installer(calls, expected))
        if kind == "magisk_denylist_state":
            return self._result(self._magisk_denylist_state(calls, expected))
        if kind == "magisk_su_policy":
            return self._result(self._magisk_su_policy(calls, expected))
        if kind == "magisk_backup_state":
            return self._result(self._magisk_backup_state(calls, expected))
        if kind == "shizuku_state":
            return self._result(
                expected.get("running") is True
                and any(
                    request.argv[:6]
                    == ("ADB", "-s", plan.target_serial, "shell", "sh", "-c")
                    and "moe.shizuku.privileged.api" in request.argv[6]
                    for request in calls
                )
            )
        if kind == "magisk_modules_state":
            return self._result(
                expected.get("allDisabled") is True
                and any(
                    request.argv[:6]
                    == ("ADB", "-s", plan.target_serial, "shell", "su", "-c")
                    and 'touch "$dir/disable"' in request.argv[6]
                    for request in calls
                )
            )
        if kind == "remote_files_written":
            return self._result(self._remote_files_written(calls, expected))
        if kind == "adb_wifi_endpoint_state":
            return self._result(self._adb_wifi_endpoint_state(calls, expected))
        if kind == "root_module_state":
            return self._result(self._root_module_state(plan, calls, expected))
        if kind == "pif_profile_state":
            return self._result(self._pif_profile_state(plan, calls, expected))
        return self._unverified(f"the fake has no probe for {kind}")

    @staticmethod
    def _plan_crossed_transport(
        plan: OperationPlan,
        calls: tuple[ProcessRequest, ...],
    ) -> bool:
        remaining = list(calls)
        for request in plan.requests:
            try:
                index = remaining.index(request)
            except ValueError:
                return False
            del remaining[index]
        return True

    @staticmethod
    def _mode(value: object) -> str:
        return {
            "system": "adb",
            "bootloader": "fastboot",
        }.get(str(value), str(value))

    @classmethod
    def _observed_mode(cls, calls: tuple[ProcessRequest, ...]) -> str:
        for request in reversed(calls):
            argv = request.argv
            if "reboot-bootloader" in argv:
                return "fastboot"
            if "reboot" not in argv:
                continue
            index = argv.index("reboot")
            target = argv[index + 1] if index + 1 < len(argv) else "system"
            return {
                "system": "adb",
                "recovery": "recovery",
                "bootloader": "fastboot",
                "fastboot": "fastbootd",
            }.get(target, target)
        for request in reversed(calls):
            executable = Path(request.argv[0]).name.casefold()
            if "fastboot" in executable:
                return "fastboot"
            if "adb" in executable:
                return "adb"
        return ""

    @staticmethod
    def _bootloader_state(calls: tuple[ProcessRequest, ...]) -> str:
        for request in reversed(calls):
            argv = request.argv
            for action, state in (("unlock", "unlocked"), ("lock", "locked")):
                if len(argv) >= 2 and argv[-2:] == ("flashing", action):
                    return state
        return ""

    @classmethod
    def _partition_written(
        cls,
        calls: tuple[ProcessRequest, ...],
        expected: Mapping[str, object],
    ) -> bool:
        partition = expected.get("partition")
        slot = expected.get("slot", "")
        sha256 = expected.get("sha256")
        if not isinstance(partition, str) or not isinstance(sha256, str):
            return False
        for request in calls:
            argv = request.argv
            try:
                index = argv.index("flash")
            except ValueError:
                continue
            if index + 2 >= len(argv) or argv[index + 1] != partition:
                continue
            actual_slot = next(
                (argument.partition("=")[2] for argument in argv[:index] if argument.startswith("--slot=")),
                "",
            )
            if actual_slot != slot:
                continue
            digest = cls._file_sha256(argv[index + 2])
            if digest == sha256.casefold():
                return True
        return False

    @staticmethod
    def _partition_erased(
        calls: tuple[ProcessRequest, ...],
        expected: Mapping[str, object],
    ) -> bool:
        partition = expected.get("partition")
        return isinstance(partition, str) and any(request.argv[-2:] == ("erase", partition) for request in calls)

    @classmethod
    def _live_boot_active(
        cls,
        calls: tuple[ProcessRequest, ...],
        expected: Mapping[str, object],
    ) -> bool:
        digest = expected.get("sha256")
        if not isinstance(digest, str):
            return False
        for request in calls:
            argv = request.argv
            if len(argv) >= 2 and argv[-2] == "boot":
                return cls._file_sha256(argv[-1]) == digest.casefold()
        return False

    @classmethod
    def _flash_applied(
        cls,
        plan: OperationPlan,
        calls: tuple[ProcessRequest, ...],
        expected: Mapping[str, object],
    ) -> bool:
        raw_partitions = expected.get("partitions", ())
        if isinstance(raw_partitions, str) or not isinstance(
            raw_partitions,
            Sequence,
        ):
            return False
        partitions = {item for item in cast(Sequence[object], raw_partitions) if isinstance(item, str)}
        observed: set[str] = set()
        artifact_hashes = {artifact.path: artifact.sha256 for artifact in plan.artifacts}
        for request in calls:
            argv = request.argv
            try:
                index = argv.index("flash")
            except ValueError:
                continue
            if index + 2 >= len(argv):
                continue
            partition, path = argv[index + 1 : index + 3]
            expected_hash = artifact_hashes.get(path)
            if expected_hash is None or cls._file_sha256(path) != expected_hash:
                continue
            observed.add(partition)
        return bool(partitions) and partitions <= observed

    @classmethod
    def _firmware_applied(
        cls,
        calls: tuple[ProcessRequest, ...],
        expected: Mapping[str, object],
    ) -> bool:
        digest = expected.get("firmwareSha256")
        build = expected.get("build")
        if not isinstance(digest, str) or not isinstance(build, str) or not build:
            return False
        return any(
            "sideload" in request.argv and cls._file_sha256(request.argv[-1]) == digest.casefold() for request in calls
        )

    @classmethod
    def _root_app_installed(
        cls,
        calls: tuple[ProcessRequest, ...],
        expected: Mapping[str, object],
    ) -> bool:
        digest = expected.get("apkSha256")
        if not isinstance(digest, str):
            return False
        return any(
            "install" in request.argv
            and request.argv[-1].casefold().endswith(".apk")
            and cls._file_sha256(request.argv[-1]) == digest.casefold()
            for request in calls
        )

    @staticmethod
    def _root_module_state(
        plan: OperationPlan,
        calls: tuple[ProcessRequest, ...],
        expected: Mapping[str, object],
    ) -> bool:
        module_id = expected.get("moduleId")
        state = expected.get("state")
        if not isinstance(module_id, str) or not isinstance(state, str):
            return False
        shell_text = "\n".join(" ".join(request.argv) for request in calls)
        module_root = f"/data/adb/modules/{module_id}"
        if state == "installed":
            role = f"root-module-zip:{module_id}"
            return any(artifact.role == role for artifact in plan.artifacts) and "magisk --install-module" in shell_text
        if state == "enabled":
            return f"rm -f {module_root}/disable {module_root}/remove" in shell_text
        if state == "disabled":
            return f"touch {module_root}/disable" in shell_text
        if state == "pending_remove":
            return f"touch {module_root}/remove" in shell_text
        return False

    @staticmethod
    def _pif_profile_state(
        plan: OperationPlan,
        calls: tuple[ProcessRequest, ...],
        expected: Mapping[str, object],
    ) -> bool:
        profile_id = expected.get("profileId")
        if not isinstance(profile_id, str) or expected.get("present") is not False:
            return False
        paths = {
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
        path = paths.get(profile_id)
        if path is None:
            return False
        return any(
            request.argv[:6] == ("ADB", "-s", plan.target_serial, "shell", "su", "-c")
            and request.argv[6] == f"rm -f -- {path}"
            for request in calls
        )

    @staticmethod
    def _package_state(
        calls: tuple[ProcessRequest, ...],
        expected: Mapping[str, object],
    ) -> bool:
        raw_packages = expected.get("packages")
        state = expected.get("state")
        if isinstance(raw_packages, str) or not isinstance(raw_packages, Sequence):
            return False
        package_values = cast(Sequence[object], raw_packages)
        packages = tuple(item for item in package_values if isinstance(item, str))
        if len(packages) != len(package_values) or not isinstance(state, str):
            return False
        suffix_by_state = {
            "enabled": ("pm", "enable", "--user", "0"),
            "disabled": ("pm", "disable-user", "--user", "0"),
            "absent": ("pm", "uninstall"),
            "cleared": ("pm", "clear", "--user", "0"),
            "stopped": ("am", "force-stop", "--user", "0"),
        }
        if state == "running":
            return all(
                any(
                    "monkey" in request.argv
                    and request.argv[-1] == package
                    and "android.intent.category.LAUNCHER" in request.argv
                    for request in calls
                )
                for package in packages
            )
        prefix = suffix_by_state.get(state)
        if prefix is None:
            return False
        return all(
            any(all(part in request.argv for part in prefix) and request.argv[-1] == package for request in calls)
            for package in packages
        )

    @staticmethod
    def _package_installer(
        calls: tuple[ProcessRequest, ...],
        expected: Mapping[str, object],
    ) -> bool:
        package = expected.get("package")
        installer = expected.get("installer")
        if not isinstance(package, str) or not isinstance(installer, str):
            return False
        return any(
            "install" in request.argv
            and request.argv[-1].casefold().endswith(".apk")
            and ("-i", installer) in tuple(zip(request.argv, request.argv[1:], strict=False))
            for request in calls
        )

    @staticmethod
    def _magisk_denylist_state(
        calls: tuple[ProcessRequest, ...],
        expected: Mapping[str, object],
    ) -> bool:
        raw_packages = expected.get("packages")
        listed = expected.get("listed")
        if isinstance(raw_packages, str) or not isinstance(raw_packages, Sequence):
            return False
        packages = tuple(item for item in cast(Sequence[object], raw_packages) if isinstance(item, str))
        if len(packages) != len(raw_packages) or not isinstance(listed, bool):
            return False
        verb = "add" if listed else "rm"
        expected_commands = {f"magisk --denylist {verb} {package}" for package in packages}
        actual = {
            argument
            for request in calls
            for argument in request.argv
            if argument.startswith("magisk --denylist ")
        }
        return expected_commands <= actual

    @staticmethod
    def _magisk_su_policy(
        calls: tuple[ProcessRequest, ...],
        expected: Mapping[str, object],
    ) -> bool:
        package = expected.get("package")
        uid = expected.get("uid")
        state = expected.get("state")
        policy = expected.get("policy")
        logging = expected.get("logging")
        notification = expected.get("notification")
        until = expected.get("until")
        if (
            not isinstance(package, str)
            or not isinstance(uid, int)
            or isinstance(uid, bool)
            or state not in {"present", "absent"}
            or policy not in {"allow", "deny", "revoke"}
            or not isinstance(logging, bool)
            or not isinstance(notification, bool)
            or not isinstance(until, int)
            or isinstance(until, bool)
        ):
            return False
        scripts = tuple(
            argument
            for request in calls
            for argument in request.argv
            if argument.startswith("observed=$(pm list packages -U ")
        )
        if len(scripts) != 1:
            return False
        script = scripts[0]
        if f"pm list packages -U {package}" not in script or f"package:{package} uid:{uid}" not in script:
            return False
        if state == "absent":
            return f"DELETE FROM policies WHERE uid = {uid};" in script
        value = 2 if policy == "allow" else 1
        values = f"VALUES ({uid}, {value}, {int(logging)}, {int(notification)}, {until});"
        return values in script

    @staticmethod
    def _magisk_backup_state(
        calls: tuple[ProcessRequest, ...],
        expected: Mapping[str, object],
    ) -> bool:
        sha1 = expected.get("sha1")
        state = expected.get("state")
        if not isinstance(sha1, str) or state not in {"verified", "absent"}:
            return False
        target = f"/data/magisk_backup_{sha1}"
        shell_text = "\n".join(" ".join(request.argv) for request in calls)
        if state == "verified":
            return (
                any("push" in request.argv and request.argv[-1].endswith(".img") for request in calls)
                and "run_migrations" in shell_text
                and sha1 in shell_text
            )
        return target in shell_text and "rm -rf --" in shell_text

    @classmethod
    def _remote_files_written(
        cls,
        calls: tuple[ProcessRequest, ...],
        expected: Mapping[str, object],
    ) -> bool:
        hashes = expected.get("hashes")
        if not isinstance(hashes, Mapping) or not hashes:
            return False
        expected_hashes = cast(Mapping[object, object], hashes)
        observed: dict[str, str] = {}
        for request in calls:
            argv = request.argv
            if "push" not in argv:
                continue
            index = argv.index("push")
            if index + 2 >= len(argv):
                continue
            source, remote_path = argv[index + 1 : index + 3]
            observed[remote_path] = cls._file_sha256(source)
        return all(
            isinstance(remote_path, str) and isinstance(digest, str) and observed.get(remote_path) == digest.casefold()
            for remote_path, digest in expected_hashes.items()
        )

    @staticmethod
    def _adb_wifi_endpoint_state(
        calls: tuple[ProcessRequest, ...],
        expected: Mapping[str, object],
    ) -> bool:
        endpoint = expected.get("endpoint")
        connected = expected.get("connected")
        if not isinstance(endpoint, str) or not isinstance(connected, bool):
            return False
        action = "connect" if connected else "disconnect"
        return any(request.argv[-2:] == (action, endpoint) and "shell" not in request.argv for request in calls)

    @staticmethod
    def _file_sha256(raw_path: str) -> str:
        try:
            return hashlib.sha256(Path(raw_path).read_bytes()).hexdigest()
        except OSError:
            return ""

    @staticmethod
    def _result(satisfied: bool) -> Mapping[str, object]:
        return {
            "satisfied": satisfied,
            "verified": True,
            "message": "simulated device state matched" if satisfied else "simulated state mismatch",
        }

    @staticmethod
    def _unverified(message: str) -> Mapping[str, object]:
        return {"satisfied": False, "verified": False, "message": message}


__all__ = ["StatefulPostconditionObserver"]
