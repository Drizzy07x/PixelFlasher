"""Cross-version path checks used by security-sensitive file boundaries."""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import cast

_DOS_DEVICE_NAMES = frozenset(
    {
        "AUX",
        "CLOCK$",
        "CON",
        "CONIN$",
        "CONOUT$",
        "NUL",
        "PRN",
    }
)
_DOS_DEVICE_DIGITS = frozenset("123456789\u00b9\u00b2\u00b3")
_RESERVED_CHARACTERS = frozenset('"*?<>|:')


def is_reserved_path(path: os.PathLike[str] | str) -> bool:
    """Return whether *path* uses an OS-reserved name.

    Python 3.13 exposes :func:`os.path.isreserved`; the compatibility branch
    preserves the same fail-closed Windows checks while PixelFlasher's 9.x
    development environment still supports Python 3.12.
    """

    checker = getattr(os.path, "isreserved", None)
    if checker is not None:
        typed_checker = cast(Callable[[os.PathLike[str] | str], bool], checker)
        return typed_checker(path)
    if os.name != "nt":
        return False

    raw = os.fspath(path)
    name = raw.replace("/", "\\").rsplit("\\", maxsplit=1)[-1]
    if not name:
        return False
    if name.endswith((".", " ")):
        return True
    if any(ord(character) < 32 or character in _RESERVED_CHARACTERS for character in name):
        return True

    stem = name.split(".", maxsplit=1)[0].rstrip().upper()
    if stem in _DOS_DEVICE_NAMES:
        return True
    return len(stem) == 4 and stem[:3] in {"COM", "LPT"} and stem[3] in _DOS_DEVICE_DIGITS
