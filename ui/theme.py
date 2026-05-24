"""Design tokens for the modernized PixelFlasher UI."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

ThemeName = Literal["light", "dark"]


@dataclass(frozen=True)
class Palette:
    background: str
    surface: str
    surface_raised: str
    border: str
    text: str
    text_muted: str
    accent: str
    accent_hover: str
    success: str
    warning: str
    danger: str
    info: str


@dataclass(frozen=True)
class Typography:
    family: str = "system-ui"
    mono_family: str = "ui-monospace"
    size_xs: int = 11
    size_sm: int = 12
    size_md: int = 14
    size_lg: int = 18
    size_xl: int = 24


@dataclass(frozen=True)
class Spacing:
    xxs: int = 4
    xs: int = 8
    sm: int = 12
    md: int = 16
    lg: int = 24
    xl: int = 32


@dataclass(frozen=True)
class Radius:
    sm: int = 6
    md: int = 10
    lg: int = 14
    xl: int = 20


@dataclass(frozen=True)
class Theme:
    name: ThemeName
    palette: Palette
    typography: Typography
    spacing: Spacing
    radius: Radius

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


_LIGHT = Theme(
    name="light",
    palette=Palette(
        background="#F6F8FC",
        surface="#FFFFFF",
        surface_raised="#FDFEFF",
        border="#DDE3EE",
        text="#101828",
        text_muted="#667085",
        accent="#2563EB",
        accent_hover="#1D4ED8",
        success="#16A34A",
        warning="#F59E0B",
        danger="#DC2626",
        info="#0284C7",
    ),
    typography=Typography(),
    spacing=Spacing(),
    radius=Radius(),
)

_DARK = Theme(
    name="dark",
    palette=Palette(
        background="#0B1220",
        surface="#101827",
        surface_raised="#162033",
        border="#263247",
        text="#F8FAFC",
        text_muted="#AAB4C5",
        accent="#7C3AED",
        accent_hover="#6D28D9",
        success="#22C55E",
        warning="#FBBF24",
        danger="#F87171",
        info="#38BDF8",
    ),
    typography=Typography(),
    spacing=Spacing(),
    radius=Radius(),
)

_THEMES: dict[ThemeName, Theme] = {"light": _LIGHT, "dark": _DARK}


def get_theme(name: ThemeName | str = "light") -> Theme:
    normalized = str(name).lower()
    if normalized not in _THEMES:
        raise ValueError(f"Unknown theme: {name!r}. Expected one of: {', '.join(_THEMES)}")
    return _THEMES[normalized]  # type: ignore[index]


def status_color(status: str, theme_name: ThemeName | str = "light") -> str:
    theme = get_theme(theme_name)
    normalized = status.lower().strip()
    if normalized in {"ok", "ready", "connected", "success", "pass"}:
        return theme.palette.success
    if normalized in {"warn", "warning", "pending"}:
        return theme.palette.warning
    if normalized in {"error", "fail", "failed", "danger"}:
        return theme.palette.danger
    return theme.palette.info
