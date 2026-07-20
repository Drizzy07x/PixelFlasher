from __future__ import annotations

import ast
from pathlib import Path

from pixelflasher_core.contracts import ModernPreferences
from pixelflasher_core.legacy_preference_policy import (
    LEGACY_PREFERENCE_POLICIES,
    LegacyPreferenceDisposition,
)

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
