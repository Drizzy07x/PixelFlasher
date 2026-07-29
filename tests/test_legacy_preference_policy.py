from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from pixelflasher_core.config_store import ConfigDocument
from pixelflasher_core.contracts import ModernPreferences
from pixelflasher_core.legacy_preference_policy import (
    LEGACY_PREFERENCE_POLICIES,
    LegacyPreferenceDisposition,
    LegacyPreferencePolicy,
)
from pixelflasher_core.preferences import document_with_preferences

ROOT = Path(__file__).resolve().parents[1]


def _classic_advanced_setting_keys() -> set[str]:
    tree = ast.parse(
        (ROOT / "advanced_settings.py").read_text(encoding="utf-8"),
        filename="advanced_settings.py",
    )
    keys: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Attribute) and node.value.attr == "config":
            keys.add(node.attr)
    return keys


def test_every_classic_advanced_setting_has_one_explicit_modern_policy() -> None:
    assert set(LEGACY_PREFERENCE_POLICIES) == _classic_advanced_setting_keys()
    assert len(LEGACY_PREFERENCE_POLICIES) == 31


def test_migrated_settings_name_real_public_fields_and_no_feature_is_silently_retired() -> None:
    public_fields = set(ModernPreferences().to_dict())
    for key, policy in LEGACY_PREFERENCE_POLICIES.items():
        assert policy.legacy_key == key
        assert policy.rationale
        assert policy.owner
        if policy.disposition is LegacyPreferenceDisposition.MIGRATED:
            assert policy.modern_field in public_fields
        else:
            assert policy.modern_field is None

    assert {policy.disposition for policy in LEGACY_PREFERENCE_POLICIES.values()} == {
        LegacyPreferenceDisposition.MIGRATED,
        LegacyPreferenceDisposition.REPLACED,
        LegacyPreferenceDisposition.ENFORCED,
    }


def test_replaced_and_enforced_settings_are_never_written_back_to_the_9x_config() -> None:
    """The disposition of the eleven non-migrated keys must be executable.

    Their rationale is prose inside a Python literal, so on its own it proves
    nothing. What is checkable is the consequence: saving preferences must never
    reintroduce a key the policy says is replaced or enforced.
    """

    retired = {
        key
        for key, policy in LEGACY_PREFERENCE_POLICIES.items()
        if policy.disposition is not LegacyPreferenceDisposition.MIGRATED
    }
    assert len(retired) == 11

    document = ConfigDocument(values={})
    written = set(document_with_preferences(document, ModernPreferences()).values)

    assert not (written & retired), "a retired 9.x setting was mirrored back into the config"

    migrated = {
        key
        for key, policy in LEGACY_PREFERENCE_POLICIES.items()
        if policy.disposition is LegacyPreferenceDisposition.MIGRATED
    }
    # Toolbar layout has no 9.x advanced-settings key, so the mirror is a
    # superset of the migrated keys rather than an exact match.
    assert migrated <= written


def test_every_policy_owner_names_a_real_parity_capability() -> None:
    inventory = json.loads((ROOT / "docs" / "modern-ui-parity.json").read_text(encoding="utf-8"))
    capabilities = {row["id"] for row in inventory["capabilities"]}

    for key, policy in LEGACY_PREFERENCE_POLICIES.items():
        assert policy.owner in capabilities, f"{key} names an owner that does not exist: {policy.owner}"


@pytest.mark.parametrize("empty_field", ("legacy_key", "owner", "rationale"))
def test_policy_rejects_empty_audit_text(empty_field: str) -> None:
    values = {
        "legacy_key": "legacy_key",
        "owner": "settings.application",
        "rationale": "Explicit migration.",
    }
    values[empty_field] = ""
    with pytest.raises(ValueError, match="must not be empty"):
        LegacyPreferencePolicy(
            values["legacy_key"],
            LegacyPreferenceDisposition.MIGRATED,
            values["owner"],
            "expertMode",
            values["rationale"],
        )


def test_policy_rejects_inconsistent_disposition_and_modern_field() -> None:
    with pytest.raises(ValueError, match="require a modern field"):
        LegacyPreferencePolicy(
            "advanced_options",
            LegacyPreferenceDisposition.MIGRATED,
            "settings.application",
            None,
            "Explicit migration.",
        )
    with pytest.raises(ValueError, match="cannot claim a modern field"):
        LegacyPreferencePolicy(
            "linux_shell",
            LegacyPreferenceDisposition.REPLACED,
            "device.adb_shell",
            "shell",
            "Typed PTY replacement.",
        )
