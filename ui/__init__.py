"""Modern UI foundation for the PixelFlasher wxPython refresh.

This package intentionally contains wx-free primitives first. The main UI can
adopt these tokens incrementally without coupling tests to a desktop display.
"""

from .theme import ThemeName, get_theme

__all__ = ["ThemeName", "get_theme"]
