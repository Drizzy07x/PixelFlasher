"""Read a device shell request without pinning how its script is quoted.

A root request carries its whole program in one argument, because `adb shell`
concatenates its arguments without re-quoting them and would otherwise hand
`su` only the text up to the first separator. Requests that pass a plain
`sh -c` still use separate elements, so these helpers accept both and let a
test assert what the device runs rather than how it was packed.
"""

from __future__ import annotations

import shlex

_SEPARATE = ("su", "sh")


def shell_prefix(argv: tuple[str, ...]) -> tuple[str, ...]:
    """The adb invocation up to and including `shell`."""

    return tuple(argv[:4])


def shell_script(argv: tuple[str, ...]) -> str:
    """The script the device shell will run, whichever shape carries it."""

    if len(argv) >= 7 and argv[4] in _SEPARATE and argv[5] == "-c":
        return argv[6]
    if len(argv) == 5:
        parsed = shlex.split(argv[4])
        if len(parsed) == 3 and parsed[0] in _SEPARATE and parsed[1] == "-c":
            return parsed[2]
    raise AssertionError(f"not a device shell script request: {argv!r}")


def readable_command(argv: tuple[str, ...]) -> str:
    """The request as text a matcher can scan.

    A root request carries its script quoted inside one argument, so joining the
    raw argv hides the program behind shell escaping. This unwraps the script
    when there is one and otherwise joins the elements unchanged.
    """

    try:
        return shell_script(argv)
    except AssertionError:
        return " ".join(argv)


def root_command(argv: tuple[str, ...]) -> str | None:
    """The script a root request runs, or None when this argv is something else.

    Fakes match on argv, so they need a probe that answers rather than raises.
    """

    try:
        if root_interpreter(argv) != "su":
            return None
        return shell_script(argv)
    except AssertionError:
        return None


def root_interpreter(argv: tuple[str, ...]) -> str:
    """The interpreter the request asks for, `su` or `sh`."""

    if len(argv) >= 7 and argv[4] in _SEPARATE and argv[5] == "-c":
        return argv[4]
    if len(argv) == 5:
        parsed = shlex.split(argv[4])
        if len(parsed) == 3 and parsed[0] in _SEPARATE and parsed[1] == "-c":
            return parsed[0]
    raise AssertionError(f"not a device shell script request: {argv!r}")
