"""Typed persistence for modern, UI-independent presentation preferences.

The current ``ConfigStore`` intentionally preserves the flat 9.x configuration
shape.  Modern preferences therefore live in one strictly validated nested
object while unrelated legacy keys remain untouched.  All filesystem writes,
atomic replacement and backup behavior are delegated to ``ConfigStore``.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeAlias

from .config_store import ConfigError, ConfigStore


PREFERENCES_KEY = "_pixelflasher_modern_preferences"
PREFERENCES_SCHEMA_KEY = "schemaVersion"
PREFERENCES_SCHEMA_VERSION = 1

SUPPORTED_THEMES = ("dark", "light")
SUPPORTED_LOCALES = ("en", "es", "fr", "it", "zh_CN", "zh_TW")
_SUPPORTED_THEME_SET = frozenset(SUPPORTED_THEMES)
_SUPPORTED_LOCALE_SET = frozenset(SUPPORTED_LOCALES)
MIN_ZOOM = 80
MAX_ZOOM = 200

_PREFERENCE_FIELDS = frozenset(
    {
        PREFERENCES_SCHEMA_KEY,
        "theme",
        "locale",
        "highContrast",
        "reducedMotion",
        "zoom",
    }
)
_LEGACY_ALIASES: Mapping[str, tuple[str, ...]] = {
    "theme": ("theme", "ui_theme", "uiTheme"),
    "locale": ("locale", "language"),
    "highContrast": ("highContrast", "high_contrast"),
    "reducedMotion": ("reducedMotion", "reduced_motion"),
    "zoom": ("zoom", "ui_zoom", "uiZoom"),
}

StoreLike: TypeAlias = ConfigStore | str | os.PathLike[str]


class PreferencesError(ConfigError):
    """Stable validation error for persisted or proposed preferences."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class ModernPreferences:
    """Canonical modern preferences with fail-safe defaults."""

    theme: str = "dark"
    locale: str = "en"
    high_contrast: bool = False
    reduced_motion: bool = False
    zoom: int = 100

    def __post_init__(self) -> None:
        if not isinstance(self.theme, str) or self.theme not in _SUPPORTED_THEME_SET:
            raise PreferencesError(
                "theme_invalid",
                "theme must be exactly dark or light",
            )
        if not isinstance(self.locale, str) or self.locale not in _SUPPORTED_LOCALE_SET:
            raise PreferencesError(
                "locale_invalid",
                "locale must be one of en, es, fr, it, zh_CN, or zh_TW",
            )
        if not isinstance(self.high_contrast, bool):
            raise PreferencesError(
                "high_contrast_invalid",
                "highContrast must be a boolean",
            )
        if not isinstance(self.reduced_motion, bool):
            raise PreferencesError(
                "reduced_motion_invalid",
                "reducedMotion must be a boolean",
            )
        if not isinstance(self.zoom, int) or isinstance(self.zoom, bool):
            raise PreferencesError(
                "zoom_invalid",
                "zoom must be an integer",
            )
        if not MIN_ZOOM <= self.zoom <= MAX_ZOOM:
            raise PreferencesError(
                "zoom_invalid",
                f"zoom must be between {MIN_ZOOM} and {MAX_ZOOM}",
            )

    @classmethod
    def from_mapping(
        cls,
        raw: Mapping[str, Any],
        *,
        require_schema: bool = False,
    ) -> "ModernPreferences":
        if not isinstance(raw, Mapping):
            raise PreferencesError(
                "preferences_not_object",
                "modern preferences must be an object",
            )
        unknown = set(raw) - _PREFERENCE_FIELDS
        if unknown:
            field = min((repr(value) for value in unknown), default="<unknown>")
            raise PreferencesError(
                "unknown_preference_field",
                f"unsupported preference field: {field}",
            )
        if require_schema and PREFERENCES_SCHEMA_KEY not in raw:
            raise PreferencesError(
                "preferences_schema_invalid",
                "persisted modern preferences require schemaVersion",
            )
        schema = raw.get(PREFERENCES_SCHEMA_KEY, PREFERENCES_SCHEMA_VERSION)
        if not isinstance(schema, int) or isinstance(schema, bool):
            raise PreferencesError(
                "preferences_schema_invalid",
                "preference schema version must be an integer",
            )
        if schema != PREFERENCES_SCHEMA_VERSION:
            raise PreferencesError(
                "preferences_schema_unsupported",
                (
                    f"unsupported preference schema {schema}; "
                    f"expected {PREFERENCES_SCHEMA_VERSION}"
                ),
            )
        defaults = cls()
        return cls(
            theme=raw.get("theme", defaults.theme),
            locale=raw.get("locale", defaults.locale),
            high_contrast=raw.get("highContrast", defaults.high_contrast),
            reduced_motion=raw.get("reducedMotion", defaults.reduced_motion),
            zoom=raw.get("zoom", defaults.zoom),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            PREFERENCES_SCHEMA_KEY: PREFERENCES_SCHEMA_VERSION,
            "theme": self.theme,
            "locale": self.locale,
            "highContrast": self.high_contrast,
            "reducedMotion": self.reduced_motion,
            "zoom": self.zoom,
        }


def load_preferences(store: StoreLike) -> ModernPreferences:
    """Load canonical preferences or migrate recognized flat 9.x values.

    The function has no UI side effects and does not write during a successful
    load.  ``ConfigStore`` may still create its one-time legacy backup while it
    opens a schema-0 file, as required by its migration contract.
    """

    config_store = _config_store(store)
    document = config_store.load()
    values = document.values
    if PREFERENCES_KEY in values:
        return _modern_preferences(values[PREFERENCES_KEY])
    return ModernPreferences.from_mapping(_legacy_preferences(values))


def save_preferences(
    store: StoreLike,
    preferences: ModernPreferences | Mapping[str, Any],
) -> ModernPreferences:
    """Validate and atomically persist modern preferences.

    Existing configuration values are preserved.  The two fields understood by
    the 9.x host are mirrored at the top level for one-major compatibility;
    the nested versioned object remains canonical for the modern application.
    """

    canonical = (
        preferences
        if isinstance(preferences, ModernPreferences)
        else ModernPreferences.from_mapping(preferences)
    )
    config_store = _config_store(store)
    document = config_store.load()
    if PREFERENCES_KEY in document.values:
        # Never erase fields from a newer or malformed persisted preference
        # object merely because the caller supplied a valid replacement.
        _modern_preferences(document.values[PREFERENCES_KEY])
    updated = document.with_values(
        **{
            PREFERENCES_KEY: canonical.to_dict(),
            "theme": canonical.theme,
            "language": canonical.locale,
        }
    )
    config_store.save(updated)
    return canonical


def _modern_preferences(raw: object) -> ModernPreferences:
    if not isinstance(raw, Mapping):
        raise PreferencesError(
            "preferences_not_object",
            f"{PREFERENCES_KEY} must be an object",
        )
    return ModernPreferences.from_mapping(raw, require_schema=True)


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
    "load_preferences",
    "save_preferences",
]
