"""Typed persistence for modern, UI-independent presentation preferences.

The current ``ConfigStore`` intentionally preserves the flat 9.x configuration
shape.  Modern preferences therefore live in one strictly validated nested
object while unrelated legacy keys remain untouched.  All filesystem writes,
atomic replacement and backup behavior are delegated to ``ConfigStore``.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from .config_store import ConfigDocument, ConfigStore
from .contracts import (
    MAX_ZOOM,
    MIN_ZOOM,
    PREFERENCES_SCHEMA_KEY,
    PREFERENCES_SCHEMA_VERSION,
    SUPPORTED_LOCALES,
    SUPPORTED_THEMES,
    ModernPreferences,
    PreferencesError,
)

PREFERENCES_KEY = "_pixelflasher_modern_preferences"
_LEGACY_ALIASES: Mapping[str, tuple[str, ...]] = {
    "theme": ("theme", "ui_theme", "uiTheme"),
    "locale": ("locale", "language"),
    "highContrast": ("highContrast", "high_contrast"),
    "reducedMotion": ("reducedMotion", "reduced_motion"),
    "zoom": ("zoom", "ui_zoom", "uiZoom"),
    "expertMode": ("expertMode", "expert_mode", "advanced_options"),
}

type StoreLike = ConfigStore | str | os.PathLike[str]


def load_preferences(store: StoreLike) -> ModernPreferences:
    """Load canonical preferences or migrate recognized flat 9.x values.

    The function has no UI side effects. ConfigStore performs its idempotent
    schema-v2 migration only after durable legacy backups exist.
    """

    config_store = _config_store(store)
    document = config_store.load()
    return preferences_from_document(document)


def preferences_from_document(document: ConfigDocument) -> ModernPreferences:
    """Decode canonical preferences from an already loaded document.

    Runtime composition uses this form so one immutable configuration read is
    the source for both the initial :class:`AppSnapshot` and backend services.
    """

    if not isinstance(document, ConfigDocument):
        raise TypeError("document must be a ConfigDocument")
    values = document.values
    if PREFERENCES_KEY in values:
        return _modern_preferences(values[PREFERENCES_KEY])
    return ModernPreferences.from_mapping(_legacy_preferences(values))


def save_preferences(
    store: StoreLike,
    preferences: ModernPreferences | Mapping[str, Any],
) -> ModernPreferences:
    """Validate and atomically persist modern preferences.

    Existing configuration values are preserved. Every recognized 9.x field is
    mirrored at the top level for one-major compatibility;
    the nested versioned object remains canonical for the modern application.
    """

    canonical = (
        preferences
        if isinstance(preferences, ModernPreferences)
        else ModernPreferences.from_mapping(preferences)
    )
    config_store = _config_store(store)
    document = config_store.load()
    updated = document_with_preferences(document, canonical)
    config_store.save(updated)
    return canonical


def document_with_preferences(
    document: ConfigDocument,
    preferences: ModernPreferences | Mapping[str, Any],
) -> ConfigDocument:
    """Return a validated document with canonical and 9.x mirror values.

    This pure preparation step lets a caller construct the exact durable
    document before entering a fail-closed state-store transaction.
    """

    if not isinstance(document, ConfigDocument):
        raise TypeError("document must be a ConfigDocument")
    canonical = (
        preferences
        if isinstance(preferences, ModernPreferences)
        else ModernPreferences.from_mapping(preferences)
    )
    if PREFERENCES_KEY in document.values:
        # Never erase fields from a newer or malformed persisted preference
        # object merely because the caller supplied a valid replacement.
        _modern_preferences(document.values[PREFERENCES_KEY])
    mirrors = _legacy_mirrors(document.values, canonical)
    mirrors[PREFERENCES_KEY] = canonical.to_dict()
    return document.with_values(**mirrors)


def _modern_preferences(raw: object) -> ModernPreferences:
    if not isinstance(raw, Mapping):
        raise PreferencesError(
            "preferences_not_object",
            f"{PREFERENCES_KEY} must be an object",
        )
    values = cast(Mapping[object, object], raw)
    if any(not isinstance(key, str) for key in values):
        raise PreferencesError(
            "preferences_key_invalid",
            f"{PREFERENCES_KEY} keys must be strings",
        )
    return ModernPreferences.from_mapping(
        cast(Mapping[str, Any], values),
        require_schema=True,
    )


def _legacy_preferences(values: Mapping[str, Any]) -> dict[str, Any]:
    migrated: dict[str, Any] = {}
    for field, aliases in _LEGACY_ALIASES.items():
        present = [(key, values[key]) for key in aliases if key in values]
        if not present:
            continue
        first_key, first_value = present[0]
        for key, value in present[1:]:
            if type(value) is not type(first_value) or value != first_value:
                raise PreferencesError(
                    "legacy_preference_ambiguous",
                    f"legacy preference aliases {first_key} and {key} disagree",
                )
        migrated[field] = first_value
    return migrated


def _legacy_mirrors(
    values: Mapping[str, object],
    preferences: ModernPreferences,
) -> dict[str, object]:
    field_values: Mapping[str, object] = {
        "theme": preferences.theme,
        "locale": preferences.locale,
        "highContrast": preferences.high_contrast,
        "reducedMotion": preferences.reduced_motion,
        "zoom": preferences.zoom,
        "expertMode": preferences.expert_mode,
    }
    preferred_keys = {
        "theme": "theme",
        "locale": "language",
        "highContrast": "high_contrast",
        "reducedMotion": "reduced_motion",
        "zoom": "ui_zoom",
        "expertMode": "advanced_options",
    }
    mirrors: dict[str, object] = {}
    for field, aliases in _LEGACY_ALIASES.items():
        value = field_values[field]
        mirrors[preferred_keys[field]] = value
        for alias in aliases:
            if alias in values:
                mirrors[alias] = value
    return mirrors


def _config_store(store: StoreLike) -> ConfigStore:
    return store if isinstance(store, ConfigStore) else ConfigStore(Path(store))


__all__ = [
    "MAX_ZOOM",
    "MIN_ZOOM",
    "PREFERENCES_KEY",
    "PREFERENCES_SCHEMA_KEY",
    "PREFERENCES_SCHEMA_VERSION",
    "SUPPORTED_LOCALES",
    "SUPPORTED_THEMES",
    "ModernPreferences",
    "PreferencesError",
    "document_with_preferences",
    "load_preferences",
    "preferences_from_document",
    "save_preferences",
]
