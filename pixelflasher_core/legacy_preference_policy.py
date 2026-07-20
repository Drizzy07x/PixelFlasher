"""Closed migration policy for every setting exposed by PixelFlasher 9.x."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType


class LegacyPreferenceDisposition(StrEnum):
    MIGRATED = "migrated"
    REPLACED = "replaced"
    ENFORCED = "enforced"


@dataclass(frozen=True, slots=True)
class LegacyPreferencePolicy:
    legacy_key: str
    disposition: LegacyPreferenceDisposition
    owner: str
    modern_field: str | None
    rationale: str

    def __post_init__(self) -> None:
        if not self.legacy_key or not self.owner or not self.rationale:
            raise ValueError("legacy preference policy text must not be empty")
        if self.disposition is LegacyPreferenceDisposition.MIGRATED:
            if not self.modern_field:
                raise ValueError("migrated preferences require a modern field")
        elif self.modern_field is not None:
            raise ValueError("replaced or enforced preferences cannot claim a modern field")


def _migrated(legacy_key: str, modern_field: str, owner: str) -> LegacyPreferencePolicy:
    return LegacyPreferencePolicy(
        legacy_key,
        LegacyPreferenceDisposition.MIGRATED,
        owner,
        modern_field,
        "Persisted in the strict modern preference schema with a 9.x mirror.",
    )


def _replaced(legacy_key: str, owner: str, rationale: str) -> LegacyPreferencePolicy:
    return LegacyPreferencePolicy(
        legacy_key,
        LegacyPreferenceDisposition.REPLACED,
        owner,
        None,
        rationale,
    )


def _enforced(legacy_key: str, owner: str, rationale: str) -> LegacyPreferencePolicy:
    return LegacyPreferencePolicy(
        legacy_key,
        LegacyPreferenceDisposition.ENFORCED,
        owner,
        None,
        rationale,
    )


_POLICIES = (
    _migrated("advanced_options", "expertMode", "settings.application"),
    _migrated("check_for_bootloader_unlocked", "checkBootloaderUnlocked", "settings.application"),
    _migrated("check_for_disk_space", "checkDiskSpace", "settings.application"),
    _migrated("check_for_firmware_hash_validity", "checkFirmwareHash", "settings.application"),
    _migrated("check_module_updates", "checkModuleUpdates", "settings.application"),
    _migrated("create_boot_tar", "createBootTar", "boot.patch"),
    _migrated("customize_font", "customizeFont", "settings.application"),
    _migrated("extra_img_extracts", "extraImageExtracts", "settings.application"),
    _migrated("kb_index", "keyboxIndex", "settings.application"),
    _migrated("keep_patch_temporary_files", "keepPatchTemporaryFiles", "settings.application"),
    _migrated("low_mem", "lowMemoryMode", "settings.application"),
    _migrated("offer_patch_methods", "offerPatchMethods", "settings.application"),
    _migrated("pf_font_face", "fontFace", "settings.application"),
    _migrated("pf_font_size", "fontSize", "settings.application"),
    _migrated("reboot_to_system_timeout", "rebootTimeoutSeconds", "settings.application"),
    _migrated("show_custom_rom_options", "showCustomRomOptions", "settings.application"),
    _migrated("show_notifications", "showNotifications", "settings.application"),
    _migrated("show_recovery_patching_option", "showRecoveryPatching", "settings.application"),
    _migrated("update_check", "automaticUpdateCheck", "support.updates_help"),
    _migrated("use_busybox_shell", "useBusyboxShell", "boot.patch"),
    _replaced(
        "linux_file_explorer",
        "app.preferences_shell",
        "Folder actions use the operating system's native default opener.",
    ),
    _replaced(
        "linux_shell",
        "device.adb_shell",
        "Interactive ADB uses a fixed PTY adapter; custom host shells belong to permissioned My Tools.",
    ),
    _replaced(
        "magisk",
        "root.apps",
        "Root managers are selected by verified backend artifact identity instead of a mutable package string.",
    ),
    _replaced(
        "scrcpy",
        "device.scrcpy",
        "Scrcpy uses a verified installation and typed options; free-form path and flag state is not accepted.",
    ),
    _replaced(
        "spoofed_apps",
        "root.apps",
        "Official catalogs select non-spoofed assets; user-supplied APKs follow explicit signature policy.",
    ),
    _enforced(
        "custom_codepage",
        "app.preferences_shell",
        "Modern process transports decode bounded output with deterministic Unicode handling.",
    ),
    _enforced(
        "delete_bundled_libs",
        "settings.application",
        "Hash-bound packaged resources are immutable and cannot be deleted from Settings.",
    ),
    _enforced(
        "force_codepage",
        "app.preferences_shell",
        "Modern process transports do not permit a global host codepage override.",
    ),
    _enforced(
        "keep_temporary_support_files",
        "support.package",
        "Support-package staging is private and must be cleaned after atomic publication.",
    ),
    _enforced(
        "override_kmi",
        "boot.patch",
        "KMI is observed from the selected device and revalidated by SafetyPolicy; manual override is forbidden.",
    ),
    _enforced(
        "sanitize_support_files",
        "support.package",
        "Support Package v2 always applies mandatory allow-list redaction.",
    ),
)

LEGACY_PREFERENCE_POLICIES: Mapping[str, LegacyPreferencePolicy] = MappingProxyType(
    {policy.legacy_key: policy for policy in _POLICIES}
)
if len(LEGACY_PREFERENCE_POLICIES) != len(_POLICIES):
    raise RuntimeError("legacy preference policy contains duplicate keys")


__all__ = [
    "LEGACY_PREFERENCE_POLICIES",
    "LegacyPreferenceDisposition",
    "LegacyPreferencePolicy",
]
